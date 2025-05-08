use alloc::vec::Vec;

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::{fft, fields::f128::BaseElement, FieldElement, StarkField};
use rand_utils::rand_vector;
use utils::{Deserializable, Serializable, SliceReader};

use crate::{
    fold_and_batch_prover::fold_and_batch_prove, verifier::DefaultVerifierChannel, DefaultProverChannel, FoldAndBatchProof, FoldAndBatchVerifier, FriOptions, VerifierError
};

use super::{FoldingOptions, FoldingProver};

type Blake3 = Blake3_256<BaseElement>;

// PROVE/VERIFY TEST
// ================================================================================================


#[test]
fn test_fold_and_batch_single_poly() {
    let degree_bound_e = 12;
    let lde_blowup_e = 2;
    let folding_factor_e = 1;
    let worker_last_poly_max_degree = 15;
    let master_max_remainder_degree = 7;
    let num_polys = 1;
    let num_queries = 50;

    let result = fold_and_batch_prove_verify_random(
        degree_bound_e, 
        lde_blowup_e, 
        folding_factor_e, 
        worker_last_poly_max_degree, 
        master_max_remainder_degree,
        num_polys, 
        num_queries);
    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}

#[test]
fn test_fold_and_batch_multiple_poly() {
    let degree_bound_e = 12;
    let lde_blowup_e = 3;
    let folding_factor_e = 2;
    let worker_last_poly_max_degree = 15;
    let master_max_remainder_degree = 7;
    let num_polys = 10;
    let num_queries = 50;

    let result = fold_and_batch_prove_verify_random(
        degree_bound_e, 
        lde_blowup_e, 
        folding_factor_e, 
        worker_last_poly_max_degree, 
        master_max_remainder_degree,
        num_polys, 
        num_queries);
    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}

#[test]
fn test_fold_and_batch_master_complete_folding() {
    let degree_bound_e = 12;
    let lde_blowup_e = 2;
    let folding_factor_e = 1;
    let worker_last_poly_max_degree = 15;
    let master_max_remainder_degree = 0;
    let num_polys = 10;
    let num_queries = 50;

    let result = fold_and_batch_prove_verify_random(
        degree_bound_e, 
        lde_blowup_e, 
        folding_factor_e, 
        worker_last_poly_max_degree, 
        master_max_remainder_degree,
        num_polys, 
        num_queries);
    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}


#[test]
fn test_fold_and_batch_worker_complete_folding() {
    let degree_bound_e = 12;
    let lde_blowup_e = 3;
    let folding_factor_e = 1;
    let worker_last_poly_max_degree = 0;
    let num_queries = 50;

    let result = fold_and_batch_worker_prove(
        degree_bound_e, 
        lde_blowup_e, 
        folding_factor_e, 
        worker_last_poly_max_degree, 
        num_queries);

    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}


#[test]
fn test_fold_and_batch_worker_folds_twice() {
    let degree_bound_e = 12;
    let lde_blowup_e = 2;
    let folding_factor_e = 1;
    let worker_last_poly_max_degree = ((1 << degree_bound_e) / 4) - 1;
    let master_max_remainder_degree = 0;
    let num_polys = 1;
    let num_queries = 50;

    let result = fold_and_batch_prove_verify_random(
        degree_bound_e, 
        lde_blowup_e, 
        folding_factor_e, 
        worker_last_poly_max_degree, 
        master_max_remainder_degree,
        num_polys, 
        num_queries);
    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}


// TEST UTILS
// ================================================================================================


fn build_evaluations_from_random_poly<E>(degree_bound: usize, lde_blowup: usize) -> Vec<E> 
where 
    E: FieldElement + StarkField
{
    // Generates a random vector which represents the coefficients of a random polynomial 
    // with degree < degree_bound
    let mut p = rand_vector::<E>(degree_bound);

    // allocating space for the evaluation form of the polynomial p
    let domain_size = degree_bound * lde_blowup;
    p.resize(domain_size, E::ZERO);

    // transforms the polynomial from coefficient form to evaluation form in place
    let twiddles = fft::get_twiddles::<E>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);

    p
}


fn fold_and_batch_worker_prove(
    worker_degree_bound_e: usize,
    lde_blowup_e: usize,
    folding_factor_e: usize,
    worker_last_poly_max_degree: usize,
    num_queries: usize
) -> Result<(), VerifierError> {

    let worker_degree_bound = 1 << worker_degree_bound_e;
    let lde_blowup = 1 << lde_blowup_e;
    let folding_factor = 1 << folding_factor_e;
    let worker_domain_size = lde_blowup * worker_degree_bound;

    // Generates a random input evaluation vector.
    let inputs = build_evaluations_from_random_poly(worker_degree_bound, lde_blowup);

    // Prepare the query positions. For simplicity, we draw some random integers 
    // instead of using Fiat-Shamir.
    let mut public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
    let query_positions = public_coin
        .draw_integers(num_queries, worker_domain_size, 0)
        .expect("failed to draw query positions");


    // ------------------------ Step 1: worker commit phase --------------------------
    // Each worker node executes the FRI commit phase on their local input polynomial.

    // Instantiate a worker node.
    let worker_options = FoldingOptions::new(lde_blowup, folding_factor, worker_domain_size, worker_last_poly_max_degree);
    let mut worker_node = FoldingProver::<BaseElement, DefaultProverChannel<_, _, _>, Blake3, MerkleTree<_>>::new(worker_options);

    // Prepare a ProverChannel for the worker node
    let mut worker_channel = DefaultProverChannel::<BaseElement, Blake3, DefaultRandomCoin<_>>::new(worker_domain_size, num_queries);
       
    // Execute the commit phase for the worker node.
    let _ = worker_node.build_layers(&mut worker_channel, inputs.clone());

    // -------------------------- Step 3: worker query phase --------------------------------
    // Each worker node generates the FRI folding proof proving that the folding of its local 
    // polynomial was done correctly.
    let (_, _) = worker_node.build_proof(&inputs, &query_positions);

    Ok(())
}




/// Generates a random Fold-and-Batch instance and test the prove/verify functionality.
/// 
/// `num_polys` is the number of polynomials to be batched in batched FRI. It is equal to 
/// the number of worker nodes.
/// `worker_last_poly_max_degree` is the maximum degree of the polynomial in the last layer 
/// of a worker node's FRI layers. In other words, each worker node will fold their local 
/// polynomial to a polynomial of degree <= `worker_last_poly_max_degree`.
fn fold_and_batch_prove_verify_random(
    worker_degree_bound_e: usize,
    lde_blowup_e: usize,
    folding_factor_e: usize,
    worker_last_poly_max_degree: usize,
    master_remainder_max_degree: usize,
    num_poly: usize,
    num_queries: usize
) -> Result<(), VerifierError> {

    let worker_degree_bound = 1 << worker_degree_bound_e;
    let lde_blowup = 1 << lde_blowup_e;
    let folding_factor = 1 << folding_factor_e;
    let worker_domain_size = lde_blowup * worker_degree_bound;
    let master_degree_bound = worker_last_poly_max_degree + 1;
    let master_domain_size = lde_blowup * master_degree_bound.next_power_of_two();
    let master_options = FriOptions::new(lde_blowup, folding_factor, master_remainder_max_degree);

    assert!(worker_last_poly_max_degree >= master_remainder_max_degree, "The maximum degree for the worker node's last polynomial must be greater than or equal to the max remainder degree of the master node");

    // Generate some random input evaluation vectors.
    let mut inputs = Vec::with_capacity(num_poly);
    for _ in 0..num_poly {
        inputs.push(build_evaluations_from_random_poly(worker_degree_bound, lde_blowup));
    }

    let fold_and_batch_proof = fold_and_batch_prove::<BaseElement, Blake3, DefaultRandomCoin<_>, MerkleTree<_>>(
        inputs,
        num_poly, 
        lde_blowup, 
        folding_factor, 
        worker_domain_size, 
        worker_last_poly_max_degree, 
        master_domain_size, 
        master_options.clone(),
        num_queries
    );


    // Test proof serialization / deserialization.
    let mut proof_bytes = Vec::new();
    fold_and_batch_proof.write_into(&mut proof_bytes);

    let mut reader = SliceReader::new(&proof_bytes);
    let fold_and_batch_proof = FoldAndBatchProof::read_from(&mut reader).unwrap();

    // Instantiate the Fold-and-Batch verifier.
    let public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
    let mut verifier = FoldAndBatchVerifier::<BaseElement, DefaultVerifierChannel<BaseElement, _, MerkleTree<Blake3>>, _, DefaultRandomCoin<_>, _>::new(public_coin, num_queries, master_options, worker_degree_bound, master_degree_bound)?;
    
    // Verify the Fold-and-Batch proof.
    verifier.verify_fold_and_batch(&fold_and_batch_proof)?;
    
    Ok(())
}
