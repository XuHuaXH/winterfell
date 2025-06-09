use core::marker::PhantomData;

use alloc::string::ToString;
use alloc::vec::Vec;
use crypto::{ElementHasher, RandomCoin, VectorCommitment};
use math::FieldElement;
use utils::group_slice_elements;

use crate::fold_and_batch_prover::FoldingOptions;
use crate::folding::fold_positions;
use crate::{BatchedFriProof, DefaultVerifierChannel, FoldAndBatchProof, FoldingVerifierChannel, FriOptions, FriProofLayer, FriVerifier, VerifierChannel, VerifierError, batched_verifier::verify_batching};

mod folding_verifier;
pub(crate) use folding_verifier::FoldingVerifier;

pub struct FoldAndBatchVerifier<E, C, H, R, V>
where
    E: FieldElement,
    C: VerifierChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    public_coin: R,
    worker_degree_bound: usize,
    master_degree_bound: usize,
    worker_domain_size: usize,
    master_domain_size: usize,
    num_queries: usize,
    options: FriOptions,
    _channel: PhantomData<C>,
    _vector_com: PhantomData<V>,
    _field_element: PhantomData<E>
}

impl<E, C, H, R, V> FoldAndBatchVerifier<E, C, H, R, V>
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
        worker_degree_bound: usize,
        master_degree_bound: usize,
    ) -> Result<Self, VerifierError> {
        assert!(worker_degree_bound >= master_degree_bound, "The degree bound for worker nodes must be greater than or equal to the degree bound for the master node");
        
        Ok(FoldAndBatchVerifier {
            public_coin,
            worker_degree_bound,
            master_degree_bound,
            worker_domain_size: options.blowup_factor() * worker_degree_bound.next_power_of_two(),
            master_domain_size: options.blowup_factor() * master_degree_bound.next_power_of_two(),
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

    /// Return the number of times the worker nodes fold their local polynomials. This
    /// number is determined by the ratio worker_domain_size / master_domain_size and the
    /// folding_factor.
    fn num_worker_folding(&self) -> usize {
        let mut result = 0;
        let mut current_domain_size = self.worker_domain_size;
        while current_domain_size > self.master_domain_size {
            current_domain_size /= self.folding_factor();
            result += 1;
        }
        result
    }

    /// This method is used to verify the batched FRI proof in a FoldAndBatchedProof. The verification 
    /// procedure is different from the verification of a standalone batched FRI proof in that the 
    /// verifier must first read all the layer commitments from the worker nodes before deriving the
    /// batched FRI challenge.
    pub fn verify_batched_fri(&mut self, proof: BatchedFriProof<H>, worker_layer_commitments: Vec<Vec<H::Digest>>) -> Result<Vec<usize>, VerifierError> {

        // Read the worker layer commitments and reseed the random coin.
        for commitments_vec in worker_layer_commitments {
            for commitment in commitments_vec {
                self.public_coin.reseed(commitment);
            }
        }

        // Draw the batched FRI challenge.
        let batched_fri_challenge: E = self.public_coin.draw().expect("The Fold and Batch verifier failed to draw the batched FRI challenge.");

        // Prepare the verifier channel for the FRI verifier.
        let mut fri_verifier_channel = DefaultVerifierChannel::<E, H, V>::new(
            proof.fri_proof().clone(),
            proof.layer_commitments().to_vec(),
            self.master_domain_size,
            self.options.folding_factor(),
        ).unwrap();

        let fri_verifier = FriVerifier::new(
            &mut fri_verifier_channel, 
            &mut self.public_coin, 
            self.options.clone(), 
            self.master_degree_bound - 1
        )?;


        // Sample the query positions using Fiat-Shamir. Since these are the query positions
        // used for Fold-and-Batch, we draw the queries from the range [0, worker_domain_size). 
        // TODO: consider using grinding?
        let mut query_positions = self.public_coin
            .draw_integers(self.num_queries, self.worker_domain_size, 0)
            .expect("Failed to draw Fold-and-Batch query positions");

        // Remove any potential duplicates from the positions as the prover will send openings only
        // for unique queries.
        query_positions.sort_unstable();
        query_positions.dedup();

        // Record the query positions used by the worker nodes for the verification of folding 
        // proofs later.
        let worker_query_positions = query_positions.to_vec();

        // Fold the query positions for Fold-and-Batch N times where N is how many times the worker 
        // nodes fold their local polynomials. This is to obtain the query positions for batched FRI.
        let mut current_domain_size = self.worker_domain_size;
        for _ in 0..self.num_worker_folding() {
            query_positions = fold_positions(&query_positions, current_domain_size, self.folding_factor());
            current_domain_size /= self.folding_factor();
        }

        // Read the evaluations of the batched polynomial at the query positions.
        let queried_evaluations = proof.parse_evaluations()?;

        // Verify the FRI proof.
        fri_verifier.verify(&mut fri_verifier_channel, &queried_evaluations, &query_positions)?; 

        let batching_proofs = proof.batching_proofs().to_vec();
        let folding_factor = self.folding_factor();
        let (queried_values, opening_proofs) = self.parse_batching_proofs(batching_proofs)?;

        // Verify that the opening proofs for the worker witness polynomials are valid against their commitments.
        let function_commitments = proof.function_commitments();
        match folding_factor {
            2 => self.verify_opening_proofs::<2>(function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            4 => self.verify_opening_proofs::<4>(function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            8 => self.verify_opening_proofs::<8>(function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            16 => self.verify_opening_proofs::<16>(function_commitments, &queried_values, &opening_proofs, &query_positions)?,
            _ => unimplemented!("folding factor {} is not supported", folding_factor),
        }
        
        // Verify that the random linear combination using batched fri challenge was computed correctly.
        verify_batching(
            &query_positions, 
            &queried_evaluations, 
            &queried_values, 
            batched_fri_challenge, 
            self.master_domain_size, 
            folding_factor)?;
            
        Ok(worker_query_positions)
    }


    pub fn verify_fold_and_batch(&mut self, proof: &FoldAndBatchProof<E, H>) -> Result<(), VerifierError> {
        
        // ------------------- Step 1: Prepare the folding verifiers ----------------------------------------
        
        let folding_proofs = proof.folding_proofs();
        let num_worker = folding_proofs.len();

        let mut folding_verifiers : Vec<FoldingVerifier<E, FoldingVerifierChannel<E, H, V>, H, R, V>> = Vec::with_capacity(num_worker);
        let mut folding_verifier_channels = Vec::with_capacity(num_worker);

        // For each folding proof, instantiate a FoldingVerifier to verify it.
        let worker_layer_commitments = proof.worker_layer_commitments().to_vec();
        for (folding_proof, layer_commitments) in folding_proofs.iter().zip(worker_layer_commitments.into_iter()) {
            // Prepare a verifier channal for the FoldingVerifier
            let mut channel = FoldingVerifierChannel::<E, H, V>::new(
                folding_proof,
                layer_commitments,
                self.worker_domain_size,
                self.folding_factor(),
            )
            .unwrap();

            // Instantiate the folding verifier
            let last_poly_max_degree = self.master_degree_bound - 1;
            let options = FoldingOptions::new(
                self.options.blowup_factor(), 
                self.folding_factor(), 
                self.worker_domain_size, 
                last_poly_max_degree);
            let mut public_coin = RandomCoin::new(&[]);
            let verifier = FoldingVerifier::new(&mut channel, &mut public_coin, options, self.worker_degree_bound - 1)?;
            
            folding_verifiers.push(verifier);
            folding_verifier_channels.push(channel);
        }

        
        
        // ------------------- Step 2: Verify the batched FRI proof ----------------------------------------

        // Extracts the function commitments for the reconstruction of the batched FRI proof later on. 
        // The function commitments are the commitments of the evaluation vectors at the worker nodes'
        // last FRI layers.
        let mut function_commitments : Vec<H::Digest> = Vec::with_capacity(num_worker);
        for commitments_vec in proof.worker_layer_commitments() {

            // The function commitment of each worker node is the layer commitment of its last FRI layer.
            function_commitments.push(*commitments_vec.last().expect("Failed to extract the last layer commitment."));
        }

        // Reconstruct a batched FRI proof from the FoldAndBatchProof
        let batching_proofs : Vec<FriProofLayer> = folding_proofs.iter().map(|folding_proof| folding_proof.batching_proof().clone()).collect();
        let batched_fri_proof : BatchedFriProof<H> = BatchedFriProof::new(
            proof.fri_proof().clone(), 
            proof.master_evaluations().to_vec(), 
            batching_proofs, 
            proof.master_layer_commitments().to_vec(), 
            function_commitments);


        // Verify the batched FRI proof
        let worker_query_positions = self.verify_batched_fri(batched_fri_proof, proof.worker_layer_commitments().to_vec())?;
        
            
        // ------------------- Step 3: Verify the folding proofs ----------------------------------------

        for i in 0..num_worker {
            folding_verifiers[i].verify(&mut folding_verifier_channels[i], &proof.worker_evaluations()[i], &worker_query_positions)?
        }

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

        let query_positions = fold_positions(query_positions, self.master_domain_size, self.folding_factor());

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
