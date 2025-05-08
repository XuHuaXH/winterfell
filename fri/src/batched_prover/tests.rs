use alloc::vec::Vec;

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::{fft, fields::f128::BaseElement, FieldElement};
use rand_utils::rand_vector;
use utils::{Deserializable, Serializable, SliceReader};
use super::{BatchedFriProver, combine_poly_evaluations};

use crate::{
    verifier::DefaultVerifierChannel, BatchedFriProof, BatchedFriVerifier, FriOptions, VerifierError
};

type Blake3 = Blake3_256<BaseElement>;

// PROVE/VERIFY TEST
// ================================================================================================

#[test]
fn test_batched_fri_single_polynomial() {
    let trace_length_e = 12;
    let lde_blowup_e = 3;
    let folding_factor_e = 2;
    let max_remainder_degree = 7;
    let num_polys = 1;
    let num_queries = 50;

    let result = fri_prove_verify_random(trace_length_e, lde_blowup_e, folding_factor_e, max_remainder_degree, num_polys ,num_queries);
    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}

#[test]
fn test_batched_fri_multiple_polynomials() {
    let trace_length_e = 12;
    let lde_blowup_e = 3;
    let folding_factor_e = 2;
    let max_remainder_degree = 7;
    let num_polys = 10;
    let num_queries = 50;

    let result = fri_prove_verify_random(trace_length_e, lde_blowup_e, folding_factor_e, max_remainder_degree, num_polys ,num_queries);
    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}

#[test]
fn test_batched_fri_complete_folding() {
    let trace_length_e = 12;
    let lde_blowup_e = 2;
    let folding_factor_e = 4;
    let max_remainder_degree = 0;
    let num_polys = 10;
    let num_queries = 50;

    let result = fri_prove_verify_random(trace_length_e, lde_blowup_e, folding_factor_e, max_remainder_degree, num_polys ,num_queries);
    assert!(result.is_ok(), "{:}", result.err().unwrap()); 
}

#[test]
fn test_combine_poly_evaluations() {

    // Construct the test evaluations vector:
    // [[0, 1, 2],
    //  [3, 4, 5],
    //  [6, 7, 8]]
    let mut evaluations = Vec::new();
    let eval_vec1 = Vec::from([0, 1, 2].map(BaseElement::new));
    let eval_vec2 = Vec::from([3, 4, 5].map(BaseElement::new));
    let eval_vec3 = Vec::from([6, 7, 8].map(BaseElement::new));
    evaluations.push(eval_vec1);
    evaluations.push(eval_vec2);
    evaluations.push(eval_vec3);

    let batched_fri_challenge = BaseElement::new(5);

    // The expected combined evaluations vector is:
    // 5^0 * [0, 1, 2] + 5^1 * [3, 4, 5] + 5^2 * [6, 7, 8] = [165, 196, 227]
    let expected_combined_evaluations = Vec::from([165, 196, 227].map(BaseElement::new));
    let actual_combined_evaluations = combine_poly_evaluations::<BaseElement>(&evaluations, batched_fri_challenge);
    assert_eq!(
        actual_combined_evaluations,
        expected_combined_evaluations, 
        "Combined polynomial evaluations are different from expected"
    );

    let batched_fri_challenge = BaseElement::new(10);

    // The expected combined evaluations vector is:
    // 10^0 * [0, 1, 2] + 10^1 * [3, 4, 5] + 10^2 * [6, 7, 8] = [630, 741, 852]
    let expected_combined_evaluations = Vec::from([630, 741, 852].map(BaseElement::new));
    let actual_combined_evaluations = combine_poly_evaluations::<BaseElement>(&evaluations, batched_fri_challenge);
    assert_eq!(
        actual_combined_evaluations,
        expected_combined_evaluations, 
        "Combined polynomial evaluations are different from expected"
    );
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


/// Generates a random instance to test the prove/verify functionality for batched FRI.
/// `num_polys` is the number of polynomials to be batched in batched FRI.
fn fri_prove_verify_random(
    degree_bound_e: usize,
    lde_blowup_e: usize,
    folding_factor_e: usize,
    max_remainder_degree: usize,
    num_poly: usize,
    num_queries: usize
) -> Result<(), VerifierError> {
    let degree_bound = 1 << degree_bound_e;
    let lde_blowup = 1 << lde_blowup_e;
    let folding_factor = 1 << folding_factor_e;
    let domain_size = lde_blowup * degree_bound;
    let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);

    // Generates a vector of random polynomials with degree < degree_bound
    let mut inputs = Vec::with_capacity(num_poly);
    for _ in 0..num_poly {
        inputs.push(build_evaluations_from_random_poly(degree_bound, lde_blowup));
    }

    // instantiate the prover and generate the proof
    let mut prover = BatchedFriProver::<BaseElement, Blake3, MerkleTree<Blake3>, DefaultRandomCoin<Blake3>>::new(options.clone());
    let batched_fri_proof = prover.build_proof(&mut inputs, domain_size, num_queries);

    // test proof serialization / deserialization
    let mut proof_bytes = Vec::new();
    batched_fri_proof.write_into(&mut proof_bytes);

    let mut reader = SliceReader::new(&proof_bytes);
    let batched_fri_proof = BatchedFriProof::read_from(&mut reader).unwrap();

    // make sure the proof can be verified
    let public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
    let mut verifier = BatchedFriVerifier::<BaseElement, DefaultVerifierChannel<BaseElement, _, MerkleTree<Blake3>>, _, DefaultRandomCoin<_>, _>::new(public_coin, num_queries, options, degree_bound)?;
    verifier.verify(&batched_fri_proof)
}
