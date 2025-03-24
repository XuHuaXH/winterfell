use alloc::vec::Vec;
use core::marker::PhantomData;

use crypto::{ElementHasher, VectorCommitment};
use math::FieldElement;
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{
    flatten_vector_elements, transpose_slice,
};

use crate::{
    build_layer_commitment, fold_and_batch_proof::FoldingProof, folding::{apply_drp, fold_positions}, prover::query_layer, FriLayer, ProverChannel
};

mod options;
pub(crate) use options::FoldingOptions;


#[cfg(test)]
mod tests;



pub struct FoldingProver<E, C, H, V>
where
    E: FieldElement,
    C: ProverChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    domain_size: usize,
    options: FoldingOptions,
    layers: Vec<FriLayer<E, H, V>>,
    _channel: PhantomData<C>,
}

// PROVER IMPLEMENTATION
// ================================================================================================

impl<E, C, H, V> FoldingProver<E, C, H, V>
where
    E: FieldElement,
    C: ProverChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new FoldingProver instantiated with the provided `domain_size` and `options`.
    pub fn new(domain_size: usize, options: FoldingOptions) -> Self {
        FoldingProver {
            domain_size,
            options,
            layers: Vec::new(),
            _channel: PhantomData,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the domain size for this prover.
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Returns folding factor for this prover.
    pub fn folding_factor(&self) -> usize {
        self.options.folding_factor()
    }

    /// Returns offset of the domain over which FRI protocol is executed by this prover.
    pub fn domain_offset(&self) -> E::BaseField {
        self.options.domain_offset()
    }

    /// Returns the number of FRI layers this prover should build. 
    fn num_fri_layers_to_build(&self) -> usize {
        self.options.num_fri_layers()
    }

    /// Returns number of FRI layers computed during the last execution of the
    /// [build_layers()](FoldingProver::build_layers()) method.
    pub fn num_layers(&self) -> usize {
        assert!(self.layers.len() > 0, "FRI layers have not been built yet");
        self.layers.len()
    }



    // COMMIT PHASE
    // --------------------------------------------------------------------------------------------
    /// Executes the commit phase of the FRI protocol.
    ///
    /// During this phase we repeatedly apply a degree-respecting projection (DRP) to
    /// `evaluations` which contain evaluations of some function *f* over domain *D*. With every
    /// application of the DRP the degree of the function (and size of the domain) is reduced by
    /// `folding_factor` until the remaining evaluations can be represented by a remainder
    /// polynomial with at most `remainder_max_degree_plus_1` number of coefficients.
    /// At each layer of reduction the current evaluations are committed to using a vector
    /// commitment scheme, and the commitment string of this vector commitment is written into
    /// the channel. After this the prover draws a random field element α from the channel, and
    /// uses it in the next application of the DRP.
    ///
    /// # Panics
    /// Panics if the prover state is dirty (the vector of layers is not empty).
    pub fn build_layers(&mut self, channel: &mut C, mut evaluations: Vec<E>) -> Vec<E> {
        assert!(
            self.layers.is_empty(),
            "a prior proof generation request has not been completed yet"
        );

        let mut last_eval_vector = Vec::new();

        // reduce the degree by folding_factor at each iteration until the remaining polynomial
        // has small enough degree
        for i in 0..self.num_fri_layers_to_build() {

            // Record the last evaluation vector.
            if i == self.num_fri_layers_to_build() - 1 {
                last_eval_vector = evaluations.clone();
            }

            match self.folding_factor() {
                2 => self.build_layer::<2>(channel, &mut evaluations),
                4 => self.build_layer::<4>(channel, &mut evaluations),
                8 => self.build_layer::<8>(channel, &mut evaluations),
                16 => self.build_layer::<16>(channel, &mut evaluations),
                _ => unimplemented!("folding factor {} is not supported", self.folding_factor()),
            }
        }

        last_eval_vector
    }

    

    /// Builds a single FRI layer by first committing to the `evaluations`, then drawing a random
    /// alpha from the channel and use it to perform degree-respecting projection.
    fn build_layer<const N: usize>(&mut self, channel: &mut C, evaluations: &mut Vec<E>) {
        // commit to the evaluations at the current layer; we do this by first transposing the
        // evaluations into a matrix of N columns, then hashing each row into a digest, and finally
        // commiting to vector of these digests; we do this so that we could de-commit to N values
        // with a single opening proof.
        let transposed_evaluations = transpose_slice(evaluations);
        let evaluation_vector_commitment =
            build_layer_commitment::<_, _, V, N>(&transposed_evaluations)
                .expect("failed to construct FRI layer commitment");
        channel.commit_fri_layer(evaluation_vector_commitment.commitment());

        // draw a pseudo-random coefficient from the channel, and use it in degree-respecting
        // projection to reduce the degree of evaluations by N
        let alpha = channel.draw_fri_alpha();
        *evaluations = apply_drp(&transposed_evaluations, self.domain_offset(), alpha);
        self.layers.push(
            FriLayer::new(
                evaluation_vector_commitment, 
                // flatten_vector_elements(transposed_evaluations)
                flatten_vector_elements(transposed_evaluations.clone())
            ));
    }


    // QUERY PHASE
    // --------------------------------------------------------------------------------------------
    /// Executes query phase of FRI protocol.
    ///
    /// For each of the provided `positions`, corresponding evaluations from each of the layers
    /// (excluding the remainder layer) are recorded into the proof together with a batch opening
    /// proof against the sent vector commitment. The difference between the query phases of a 
    /// [crate::FriProver] and a [FoldingProver] is that a [FoldingProver] does not need to deal
    /// with the remainder.
    ///
    /// # Panics
    /// Panics is the prover state is clean (no FRI layers have been build yet).
    pub fn build_proof(&mut self, input: &[E], positions: &[usize]) -> (FoldingProof, Vec<E>) {

        let mut layers = Vec::with_capacity(self.layers.len());

        if !self.layers.is_empty() {
            let mut positions = positions.to_vec();
            let mut domain_size = self.layers[0].evaluations().len();
            let folding_factor = self.options.folding_factor();

            // for all FRI layers, except the last one, record tree root, determine a set of query
            // positions, and query the layer at these positions.
            for i in 0..self.layers.len() {
                positions = fold_positions(&positions, domain_size, folding_factor);

                // sort of a static dispatch for folding_factor parameter
                let proof_layer = match folding_factor {
                    2 => query_layer::<E, H, V, 2>(&self.layers[i], &positions),
                    4 => query_layer::<E, H, V, 4>(&self.layers[i], &positions),
                    8 => query_layer::<E, H, V, 8>(&self.layers[i], &positions),
                    16 => query_layer::<E, H, V, 16>(&self.layers[i], &positions),
                    _ => unimplemented!("folding factor {} is not supported", folding_factor),
                };

                layers.push(proof_layer);
                domain_size /= folding_factor;
            }
        }

        // Comptute the evaluations of this prover's local polynomial at all the query positions.
        let evaluation_vector = positions.iter().map(|&p| input[p]).collect::<Vec<_>>();

        (FoldingProof::new(layers), evaluation_vector)
    } 
}
