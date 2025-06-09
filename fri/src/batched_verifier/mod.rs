use core::marker::PhantomData;

use alloc::string::ToString;
use alloc::vec::Vec;
use crypto::{ElementHasher, RandomCoin, VectorCommitment};
use math::FieldElement;
use utils::group_slice_elements;

use crate::folding::fold_positions;
use crate::{BatchedFriProof, DefaultVerifierChannel, FriOptions, FriProofLayer, FriVerifier, VerifierChannel, VerifierError};
use super::batched_prover::combine_poly_evaluations;

#[cfg(test)]
mod tests;

pub struct BatchedFriVerifier<E, C, H, R, V>
where
    E: FieldElement,
    C: VerifierChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    public_coin: R,
    degree_bound: usize,
    domain_size: usize,
    num_queries: usize,
    options: FriOptions,
    _channel: PhantomData<C>,
    _vector_com: PhantomData<V>,
    _field_element: PhantomData<E>
}

impl<E, C, H, R, V> BatchedFriVerifier<E, C, H, R, V>
where
    E: FieldElement,
    C: VerifierChannel<E, Hasher = H, VectorCommitment = V>,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    pub fn new(
        public_coin: R,
        num_queries: usize,
        options: FriOptions,
        degree_bound: usize,
    ) -> Result<Self, VerifierError> {
        Ok(BatchedFriVerifier {
            public_coin,
            degree_bound,
            domain_size: options.blowup_factor() * degree_bound.next_power_of_two(),
            num_queries,
            options,
            _channel: PhantomData,
            _vector_com: PhantomData,
            _field_element: PhantomData
        })

    }

    fn folding_factor(&self) -> usize {
        self.options.folding_factor()
    }

    pub fn verify(&mut self, proof: &BatchedFriProof<H>) -> Result<(), VerifierError> {

        // Read the function commitments and reseed the random coin.
        let function_commitments = proof.function_commitments();
        for commitment in function_commitments.iter() {
            self.public_coin.reseed(*commitment);
        }

        // Draw the batched FRI challenge.
        let batched_fri_challenge: E = self.public_coin.draw().expect("Batched FRI verifier failed to draw batched FRI challenge.");

        // Prepare the verifier channel for the FRI verifier.
        let mut channel = DefaultVerifierChannel::<E, H, V>::new(
            proof.fri_proof().clone(),
            proof.layer_commitments().to_vec(),
            self.domain_size,
            self.options.folding_factor(),
        ).unwrap();

        let fri_verifier = FriVerifier::new(
            &mut channel, 
            &mut self.public_coin, 
            self.options.clone(), 
            self.degree_bound - 1
        )?;

        // Sample the query positions using Fiat-Shamir.
        // TODO: consider using grinding?
        let mut query_positions = self.public_coin
            .draw_integers(self.num_queries, self.domain_size, 0)
            .expect("Failed to draw batched FRI query positions");

        // Remove any potential duplicates from the positions as the prover will send openings only
        // for unique queries.
        query_positions.sort_unstable();
        query_positions.dedup();

        // Read the evaluations of the batched polynomial at the query positions.
        let batched_evaluations = proof.parse_evaluations()?;

        // Verifies the FRI proof.
        fri_verifier.verify(&mut channel, &batched_evaluations, &query_positions)?;

        let batching_proofs = proof.batching_proofs().to_vec();
        let folding_factor = self.folding_factor();
        let (queried_values, opening_proofs) = self.parse_batching_proofs(batching_proofs)?;

        // Verify that the opening proofs for the batched polynomials are valid against their commitments.
        match folding_factor {
            2 => self.verify_opening_proofs::<2>(&function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            4 => self.verify_opening_proofs::<4>(&function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            8 => self.verify_opening_proofs::<8>(&function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            16 => self.verify_opening_proofs::<16>(&function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            _ => unimplemented!("folding factor {} is not supported", folding_factor),
        }
        
        // Verify that the random linear combination using batched_fri_challenge was computed correctly.
        verify_batching(
            &query_positions, 
            &batched_evaluations, 
            &queried_values, 
            batched_fri_challenge, 
            self.domain_size, 
            folding_factor)?;
            
        Ok(())
    }


    /// Helper function to extract the queried values and opening proofs from the `batching_proofs` of
    /// a [BatchedFriProof].
    fn parse_batching_proofs(&self, batching_proofs: Vec<FriProofLayer>) -> Result<(Vec<Vec<E>>, Vec<V::MultiProof>), VerifierError>  {
        
        let num_poly = batching_proofs.len();
        let mut queried_values : Vec<Vec<E>> = Vec::with_capacity(num_poly);
        let mut opening_proofs : Vec<V::MultiProof> = Vec::with_capacity(num_poly);

        for layer in batching_proofs {
            let (values, opening_proof) = layer.parse::<E, H, V>(self.options.folding_factor()).map_err(|err| VerifierError::FunctionOpeningsDeserializationError(err.to_string()))?;
            queried_values.push(values);
            opening_proofs.push(opening_proof);
        }
        Ok((queried_values, opening_proofs))
    }


    fn verify_opening_proofs<const N: usize>(&self, function_commitments: &[H::Digest], queried_values: &Vec<Vec<E>>, opening_proofs: &Vec<V::MultiProof>, query_positions: &[usize]) -> Result<(), VerifierError> {

        assert_eq!(function_commitments.len(), queried_values.len(), "The number of function commitments does not match the number of queried evaluation vectors.");
        assert_eq!(queried_values.len(), opening_proofs.len(), "The number of queried evaluation vectors does not match the number of opening proofs.");

        let query_positions = fold_positions(query_positions, self.domain_size, self.folding_factor());

        for i in 0..function_commitments.len() {

            // build the values (i.e., polynomial evaluations over a coset of a multiplicative subgroup
            // of the current evaluation domain) corresponding to each leaf of the layer commitment
            let leaf_values : &[[E; N]] = group_slice_elements(&queried_values[i]);

            // hash the aforementioned values to get the leaves to be verified against the previously
            // received commitment
            let hashed_values: Vec<H::Digest> = leaf_values
                .iter()
                .map(|seg| H::hash_elements(seg))
                .collect();

            V::verify_many(
                function_commitments[i],
                &query_positions,
                &hashed_values,
                &opening_proofs[i],
            )
            .map_err(|_| VerifierError::LayerCommitmentMismatch)?;
        }
        
        Ok(())
    }
}


// HELPER FUNCTIONS
// ================================================================================================

pub(crate) fn verify_batching<E: FieldElement>(query_positions: &[usize], batched_evaluations: &[E], queried_values: &Vec<Vec<E>>, batched_fri_challenge: E, domain_size: usize, folding_factor: usize) -> Result<(), VerifierError> {

    // Extract from queried_values which is in transposed form the evaluations of each polynomial 
    // at query_positions.
    let unbatched_evaluations = extract_evaluations(&query_positions, queried_values, domain_size, folding_factor);

    let expected_batched_evaluations = combine_poly_evaluations(&unbatched_evaluations, batched_fri_challenge);

    if expected_batched_evaluations != batched_evaluations {
        return Err(VerifierError::InvalidPolynomialBatching)
    }
    Ok(())
}


pub fn extract_evaluations<E: FieldElement>(query_positions: &[usize], queried_values: &Vec<Vec<E>>, domain_size: usize, folding_factor: usize) -> Vec<Vec<E>> {
    let mut unbatched_evaluations = Vec::with_capacity(queried_values.len());

    let folded_domain_size = domain_size / folding_factor;
    let folded_positions = fold_positions(query_positions, domain_size, folding_factor);
    let mut indices = Vec::new();

    for position in query_positions {
        let folded_position = position % folded_domain_size;

        // Find the index of folded_position in folded_positions
        if let Some(index) = folded_positions.iter().position(|&x| x == folded_position) {
            indices.push(index * folding_factor + position / folded_domain_size);
        } else {
            panic!("The folded position {} cannot be found in the folded_positions vector: {:?}", folded_position, folded_positions);
        }
    }

    for eval_vector in queried_values {
        let mut evaluation_vector = Vec::with_capacity(query_positions.len());
        for index in indices.iter() {
            evaluation_vector.push(eval_vector[*index]);
        }
        unbatched_evaluations.push(evaluation_vector);
    }

    unbatched_evaluations
}