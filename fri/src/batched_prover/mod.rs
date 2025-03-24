use alloc::vec::Vec;
use math::StarkField;
use utils::{
    flatten_vector_elements, group_slice_elements, transpose_slice};
use crypto::{Hasher, RandomCoin};
use crypto::{ElementHasher, VectorCommitment};
use math::FieldElement;
#[cfg(feature = "concurrent")]
use utils::iterators::*;

pub(crate) mod channel;
use channel::BatchedFriProverChannel;

use crate::folding::fold_positions;
use crate::{build_layer_commitment, BatchedFriProof, DefaultProverChannel, FoldAndBatchProof, FoldingProver, FriLayer, FriOptions, FriProofLayer, FriProver};

#[cfg(test)]
mod tests;

pub struct BatchedFriProver<E, H, V, R>
where
    E: FieldElement + StarkField,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>
{
    fri_prover: FriProver<E, BatchedFriProverChannel<E, H, R>, H, V>,
    function_layers: Vec<FriLayer<E, H, V>>,
    channel: BatchedFriProverChannel<E, H, R>,
}

impl<E, H, V, R> BatchedFriProver<E, H, V, R>
where
    E: FieldElement + StarkField,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new Batched FRI prover instantiated with the provided `options`.
    pub fn new(options: FriOptions) -> Self {
        BatchedFriProver {
            fri_prover: FriProver::new(options),
            function_layers: Vec::new(),
            channel: BatchedFriProverChannel::new(),
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the folding factor for this prover.
    pub fn folding_factor(&self) -> usize {
        self.fri_prover.folding_factor()
    }

    /// Returns the offset of the domain over which FRI protocol is executed by this prover.
    pub fn domain_offset(&self) -> E::BaseField {
        self.fri_prover.domain_offset()
    }

    /// Returns number of FRI layers computed during the last execution of the
    /// [build_layers()](FriProver::build_layers()) method.
    pub fn num_layers(&self) -> usize {
        self.fri_prover.num_layers()
    }
    

    /// Takes the evaluation vector of a single polynomial and builds the FriLayer for that polynomial.
    /// This method performs two operations:
    /// 1. Compute the commitment to the evaluation vector `evaluations` and push it into the prover channel.
    /// 2. Constructs a FriLayer storing the evaluations and the commitment, then store that FriLayer
    /// in the prover's `function_layers` field.
    fn build_function_layer<const N: usize>(channel: &mut BatchedFriProverChannel<E, H, R>, evaluations: &[E]) -> FriLayer<E, H, V> {
        
        // Commit to the function evaluations. We do this by first transposing the
        // evaluations into a matrix of N columns, then hashing each row into a digest, and finally, 
        // commiting to vector of these digests. We do this so that we could de-commit to N values
        // with a single opening proof.
        let transposed_evaluations = transpose_slice(evaluations);
        let evaluation_vector_commitment =
            build_layer_commitment::<_, _, V, N>(&transposed_evaluations)
                .expect("failed to construct batched FRI function layer commitment");
        channel.push_function_commitment(evaluation_vector_commitment.commitment());

        FriLayer::new(evaluation_vector_commitment, flatten_vector_elements(transposed_evaluations))
    }


    /// For each function layer, create its corresponding proof layer consisting of the evaluations 
    /// of that function at the queried positions(`positions`) and the opening proofs of those evaluations 
    /// against the vector commitment of that function.
    ///
    /// # Panics
    /// Panics if no batched FRI function layers have been build yet.
    fn compute_batching_proofs(&mut self, positions: &[usize], domain_size: usize) -> Vec<FriProofLayer> {
        assert!(!self.function_layers.is_empty(), "Batched FRI function layers have not been built yet");

        let mut proof_layers = Vec::with_capacity(self.function_layers.len());
        let folding_factor = self.folding_factor();

        // For all batched FRI function layers, record tree root and query the layer at 
        // the query positions.
        for i in 0..self.function_layers.len() {

            // static dispatch for folding_factor parameter
            let proof_layer = match folding_factor {
                2 => query_layer::<E, H, V, 2>(&self.function_layers[i], &positions, domain_size),
                4 => query_layer::<E, H, V, 4>(&self.function_layers[i], &positions, domain_size),
                8 => query_layer::<E, H, V, 8>(&self.function_layers[i], &positions, domain_size),
                16 => query_layer::<E, H, V, 16>(&self.function_layers[i], &positions, domain_size),
                _ => unimplemented!("folding factor {} is not supported", folding_factor),
            };

            proof_layers.push(proof_layer);
        }

        proof_layers
    }

    
    /// This is the main function used to compute a batched FRI proof. The variable `inputs` 
    /// contains all the input polynomials to be batched in evaluation form. Namely, each vector
    /// in `inputs` is the evaluation vector of a polynomial to be batched in batched FRI 
    /// evaluated at all the points in the FRI evaluation domain.
    /// 
    /// Returns a batched FRI proof for the polynomials represented by the input evaluation vectors.
    pub fn build_proof(&mut self, inputs: &Vec<Vec<E>>, domain_size: usize, num_queries: usize) -> BatchedFriProof<H> {
        
        // -------------------------------- Step 1 ---------------------------------------------
        // Build the function layers. Each function layer corresponds to one input polynomial.
        for i in 0..inputs.len() {
            let function_layer = match self.folding_factor() {

                // static dispatch for folding_factor parameter
                2 => Self::build_function_layer::<2>(&mut self.channel, &inputs[i]),
                4 => Self::build_function_layer::<4>(&mut self.channel, &inputs[i]),
                8 => Self::build_function_layer::<8>(&mut self.channel, &inputs[i]),
                16 =>Self::build_function_layer::<16>(&mut self.channel, &inputs[i]),
                _ => unimplemented!("folding factor {} is not supported", self.folding_factor()),
            };

            self.function_layers.push(function_layer);
        }


        // -------------------------------- Step 2 ---------------------------------------------
        // Batch the input polynomial evaluations into a single evaluation vector
        // using the batched FRI challenge obtained from Fiat-Shamir.
        let challenge = self.channel.draw_batched_fri_challange();
        let batched_evaluations = combine_poly_evaluations(&inputs, challenge);


        // -------------------------------- Step 3 ---------------------------------------------
        // Perform the FRI folding phase.
        self.fri_prover.build_layers(&mut self.channel, batched_evaluations.clone());


        // -------------------------------- Step 4 ---------------------------------------------
        // Sample the query positions using Fiat-Shamir.
        // TODO: consider using grinding?
        let mut query_positions = self.channel.draw_query_positions(domain_size, num_queries, 0);

        // Remove any potential duplicates from the positions as the prover will send openings only
        // for unique queries.
        query_positions.sort_unstable();
        query_positions.dedup();


        // -------------------------------- Step 5 ---------------------------------------------
        // Build the batched FRI proof.
        let fri_proof = self.fri_prover.build_proof(&query_positions);
        let batching_proofs = self.compute_batching_proofs(&query_positions, domain_size);
        let layer_commitments = self.channel.layer_commitments().to_vec();
        let function_commitments = self.channel.function_commitments().to_vec();
        let evaluations = query_positions.iter().map(|&p| batched_evaluations[p]).collect::<Vec<_>>();
        
        BatchedFriProof::new::<E>(fri_proof, evaluations, batching_proofs, layer_commitments, function_commitments)
    }


    /// This is the main function used to compute a Fold-and-Batch proof. The variable `inputs` 
    /// contains all the input evaluation vectors. 
    /// 
    /// Returns a Fold-and-Batch proof for the polynomials represented by the input evaluation vectors.
    pub fn prove_fold_and_batch(
        &mut self,
        inputs: &Vec<Vec<E>>, 
        worker_domain_size: usize, 
        master_domain_size: usize, 
        num_queries: usize, 
        worker_nodes: &mut Vec<FoldingProver::<E, DefaultProverChannel<E, H, R>, H, V>>,
    ) -> FoldAndBatchProof<H>
    {
        // -------------------------------- Step 1 ---------------------------------------------
        // Each worker node executes the FRI commit phase on their local input polynomial.
        let num_worker = worker_nodes.len();
        let mut worker_layer_commitments = Vec::with_capacity(num_worker);
        let mut batched_fri_inputs = Vec::with_capacity(num_worker);
        for (i, node) in worker_nodes.iter_mut().enumerate() {

            // Prepare a ProverChannel for the worker node
            let mut worker_channel = DefaultProverChannel::<E, H, R>::new(worker_domain_size, num_queries);
            
            // Execute the commit phase for the worker node.
            let last_eval_vector = node.build_layers(&mut worker_channel, inputs[i].clone());
            batched_fri_inputs.push(last_eval_vector);
            worker_layer_commitments.push(worker_channel.layer_commitments().to_vec());
        }


        // -------------------------------- Step 2 ---------------------------------------------
        // The master prover reads the last layer commitments of each worker node into its channel.
        // These layer commitments correspond to the function commitments in batched FRI.
        for layer_commitments in worker_layer_commitments.iter() {
            self.channel.push_function_commitment(layer_commitments.last().unwrap().clone());
        }


        // -------------------------------- Step 3 ---------------------------------------------
        // Batch the input evaluation vectors into a single evaluation vector using the batched 
        // FRI challenge obtained from Fiat-Shamir.
        let challenge = self.channel.draw_batched_fri_challange();
        let batched_evaluations = combine_poly_evaluations(&batched_fri_inputs, challenge);


        // -------------------------------- Step 4 ---------------------------------------------
        // The master node performs the FRI folding phase on the batched polynomial.
        self.fri_prover.build_layers(&mut self.channel, batched_evaluations.clone());


        // -------------------------------- Step 5 ---------------------------------------------
        // Sample the query positions using Fiat-Shamir.
        // TODO: consider using grinding?
        let mut query_positions = self.channel.draw_query_positions(worker_domain_size, num_queries, 0);

        // Remove any potential duplicates from the positions as the prover will send openings only
        // for unique queries.
        query_positions.sort_unstable();
        query_positions.dedup();


        // -------------------------------- Step 6 ---------------------------------------------
        // Each worker node generates the FRI folding proof proving that the folding of its local 
        // polynomial was done correctly.
        let mut folding_proofs = Vec::with_capacity(num_worker);
        let mut worker_evaluations = Vec::with_capacity(num_worker);
        for i in 0..num_worker {
            let (folding_proof, evaluation_vector) = worker_nodes[i].build_proof(&inputs[i], &query_positions);
            folding_proofs.push(folding_proof);
            worker_evaluations.push(evaluation_vector);
        }


        // -------------------------------- Step 7 ---------------------------------------------
        // Fold the initial query positions to the folded positions at the last FRI layer
        // of a worker node.
        let folding_factor = self.folding_factor();
        let mut current_domain_size = worker_domain_size;
        while current_domain_size > master_domain_size {
            query_positions = fold_positions(&query_positions, current_domain_size, folding_factor);
            current_domain_size /= folding_factor;
        }


        // -------------------------------- Step 8 ---------------------------------------------
        // Build the Fold-and-Batch proof.

        let fri_proof = self.fri_prover.build_proof(&query_positions);
        let master_evaluations = query_positions.iter().map(|&p| batched_evaluations[p]).collect::<Vec<_>>();

        // Extract the layer commitments for the master prover. 
        let master_layer_commitments = self.channel.layer_commitments().to_vec();

        FoldAndBatchProof::new::<E>(
            folding_proofs, 
            fri_proof, 
            worker_evaluations,
            master_evaluations, 
            worker_layer_commitments,
            master_layer_commitments
            )
    }
}



/// Takes a vector of evaluation vectors, return their linear combination using the 
/// batched FRI challenge. If `evaluations` contains vectors `v_0, ..., v_l`, and the 
/// `batched_fri_challenge` is `a`, then the returned vector is
/// `v_0 + a * v_1 + a^2 * v_2 + ... + a^l * v_l`.
pub fn combine_poly_evaluations<E: FieldElement>(evaluations: &Vec<Vec<E>>, batched_fri_challenge: E) -> Vec<E> {
    
    assert!(evaluations.len() > 0, "Number of evaluation vectors must be at least 1");

    let eval_vec_size = evaluations[0].len();
    let num_poly = evaluations.len();
    let mut combined_evaluations = Vec::with_capacity(eval_vec_size);
    for j in 0..eval_vec_size {
        let mut combined_entry = E::ZERO;
        let mut multiplier = E::ONE;
        for i in 0..num_poly {
            combined_entry += multiplier * evaluations[i][j];
            multiplier *= batched_fri_challenge;
        }
        combined_evaluations.push(combined_entry);
    }

    combined_evaluations
}


/// Builds a single proof layer by querying the evaluations of the passed in FRI layer at the
/// specified positions.
fn query_layer<E: FieldElement, H: Hasher, V: VectorCommitment<H>, const N: usize>(
    layer: &FriLayer<E, H, V>,
    positions: &[usize],
    domain_size: usize
) -> FriProofLayer {

    // We need to fold once here because the number of leaves in the Merkle tree 
    // is the number of evaluations divided by the folding factor, since we batch
    // multiple evaluations into one leaf.
    let folded_positions = fold_positions(&positions, domain_size, N);

    // build a batch opening proof for all query positions
    let opening_proof = layer
        .commitment()
        .open_many(&folded_positions)
        .expect("failed to generate a batch opening proof for FRI layer queries");

    // build a list of polynomial evaluations at each position; since evaluations in FRI layers
    // are stored in transposed form, a position refers to N evaluations which are committed
    // in a single leaf
    let evaluations: &[[E; N]] = group_slice_elements(layer.evaluations());
    let mut queried_values: Vec<[E; N]> = Vec::with_capacity(folded_positions.len());
    for &folded_position in folded_positions.iter() {
        queried_values.push(evaluations[folded_position]);
    }

    FriProofLayer::new::<_, _, V, N>(queried_values, opening_proof.1)
}