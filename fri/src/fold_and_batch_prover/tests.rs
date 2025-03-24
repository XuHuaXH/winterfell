use alloc::vec::Vec;

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::{fft, fields::f128::BaseElement, FieldElement};
use rand_utils::rand_vector;
use utils::{Deserializable, Serializable, SliceReader};

use crate::{
    batched_prover::BatchedFriProver, fold_and_batch_prover::FoldingOptions, verifier::DefaultVerifierChannel, DefaultProverChannel, FoldAndBatchProof, FoldAndBatchVerifier, FoldingProver, FriOptions, VerifierError
};

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



// TEST UTILS
// ================================================================================================

fn build_evaluations_from_random_poly(degree_bound: usize, lde_blowup: usize) -> Vec<BaseElement> {
    // Generates a random vector which represents the coefficients of a random polynomial 
    // with degree < degree_bound
    let mut p = rand_vector::<BaseElement>(degree_bound);

    // allocating space for the evaluation form of the polynomial p
    let domain_size = degree_bound * lde_blowup;
    p.resize(domain_size, BaseElement::ZERO);

    // transforms the polynomial from coefficient form to evaluation form in place
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);

    p
}



/// Generates a random Fold-and-Batch instance and test the prove/verify functionality 
/// for Fold-and-Batch.
/// 
/// `num_polys` is the number of polynomials to be batched in batched FRI.
/// `worker_last_poly_max_degree` is the maximum degree of the polynomial in the last layer 
/// of a worker node's FRI layers. In other words, each worker node will fold their local 
/// polynomial to a polynomial of degree <= `worker_last_poly_max_degree`.
fn fold_and_batch_prove_verify_random(
    worker_degree_bound_e: usize,
    lde_blowup_e: usize,
    folding_factor_e: usize,
    worker_last_poly_max_degree: usize,
    master_max_remainder_degree: usize,
    num_poly: usize,
    num_queries: usize
) -> Result<(), VerifierError> {

    let worker_degree_bound = 1 << worker_degree_bound_e;
    let lde_blowup = 1 << lde_blowup_e;
    let folding_factor = 1 << folding_factor_e;
    let worker_domain_size = lde_blowup * worker_degree_bound;
    let master_degree_bound = worker_last_poly_max_degree + 1;
    let master_domain_size = master_degree_bound * lde_blowup;

    // The remainder polynomial is obtained by folding the polynomial in the worker's last FRI layer
    // one more time.
    assert!(worker_last_poly_max_degree >= master_max_remainder_degree, "The maximum degree for the worker node's last polynomial must be greater than or equal to the max remainder degree of the master node");
    let worker_options = FoldingOptions::new(lde_blowup, folding_factor, worker_domain_size, worker_last_poly_max_degree);
    let master_options = FriOptions::new(lde_blowup, folding_factor, master_max_remainder_degree);

    // Generates evaluation vectors of random polynomials with degree < worker_degree_bound.
    let mut inputs = Vec::with_capacity(num_poly);
    for _ in 0..num_poly {
        inputs.push(build_evaluations_from_random_poly(worker_degree_bound, lde_blowup));
    }

    // Instantiate the worker nodes.
    let mut worker_nodes = Vec::with_capacity(num_poly);
    for _ in 0..num_poly {
        worker_nodes.push(FoldingProver::<BaseElement, DefaultProverChannel<BaseElement, Blake3, DefaultRandomCoin<Blake3>>, Blake3, MerkleTree<Blake3>>::new(worker_domain_size, worker_options.clone()));
    }
  
    // Instantiate the master prover.
    let mut master_prover = BatchedFriProver::<BaseElement, Blake3, MerkleTree<Blake3>, DefaultRandomCoin<Blake3>>::new(master_options.clone());

    // Generates the Fold-and-Batch proof.
    let fold_and_batch_proof = master_prover.prove_fold_and_batch(&inputs, worker_domain_size, master_domain_size, num_queries, &mut worker_nodes);

    // Test proof serialization / deserialization.
    let mut proof_bytes = Vec::new();
    fold_and_batch_proof.write_into(&mut proof_bytes);

    let mut reader = SliceReader::new(&proof_bytes);
    let fold_and_batch_proof = FoldAndBatchProof::read_from(&mut reader).unwrap();


    // ----------------- End of Proof Generation --------------------------------------

    // Instantiate the Fold-and-Batch verifier.
    let public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
    let mut verifier = FoldAndBatchVerifier::<BaseElement, DefaultVerifierChannel<BaseElement, _, MerkleTree<Blake3>>, _, DefaultRandomCoin<_>, _>::new(public_coin, num_queries, master_options, worker_degree_bound, master_degree_bound)?;
    
    // Verify the Fold-and-Batch proof.
    verifier.verify_fold_and_batch(&fold_and_batch_proof)?;
    
    Ok(())
}
