use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::{fft, fields::f128::BaseElement, FieldElement};
use rand_utils::rand_vector;
use winter_fri::{BatchedFriProver, DefaultProverChannel, DefaultVerifierChannel, FoldAndBatchVerifier, FoldingOptions, FoldingProver, FriOptions};
use std::hint::black_box;


static WORKER_DOMAIN_SIZES_E: [usize; 1] = [25];
static NUM_POLY: usize = 1;
static BLOWUP_FACTOR: usize = 8;
static FOLDING_FACTOR: usize = 2;
static NUM_QUERIES: usize = 50;
static WORKER_LAST_POLY_MAX_DEGREE: usize = 2000;
static MASTER_MAX_REMAINDER_DEGREE: usize = 0;

pub fn fold_and_batch_verifier(c: &mut Criterion) {
    let mut verifier_group = c.benchmark_group("verifier");
    verifier_group.sample_size(10);

    for &worker_domain_size_e in &WORKER_DOMAIN_SIZES_E {

        let worker_degree_bound = 1 << worker_domain_size_e;
        let worker_domain_size = BLOWUP_FACTOR * worker_degree_bound;
        let master_degree_bound = WORKER_LAST_POLY_MAX_DEGREE + 1;
        let master_domain_size = master_degree_bound * BLOWUP_FACTOR;
    
        // The remainder polynomial is obtained by folding the polynomial in the worker's last FRI layer
        // one more time.
        let worker_options = FoldingOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, worker_domain_size, WORKER_LAST_POLY_MAX_DEGREE);
        let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);
    

        verifier_group.bench_function(
            BenchmarkId::new("fold_and_batch_worker", worker_domain_size_e),
            |b| {
                b.iter_batched(
                    || {
                        // Generates evaluation vectors of random polynomials with degree < worker_degree_bound.
                        let mut inputs = Vec::with_capacity(NUM_POLY);
                        for _ in 0..NUM_POLY {
                            inputs.push(build_evaluations_from_random_poly(worker_degree_bound, BLOWUP_FACTOR));
                        }
                    
                        // Instantiate the worker nodes.
                        let mut worker_nodes = Vec::with_capacity(NUM_POLY);
                        for _ in 0..NUM_POLY {
                            worker_nodes.push(FoldingProver::<BaseElement, DefaultProverChannel<BaseElement, Blake3_256<_>, DefaultRandomCoin<Blake3_256<_>>>, Blake3_256<_>, MerkleTree<Blake3_256<_>>>::new(worker_domain_size, worker_options.clone()));
                        }
                    
                        // Instantiate the master prover.
                        let mut master_prover = BatchedFriProver::<BaseElement, Blake3_256<_>, MerkleTree<Blake3_256<_>>, DefaultRandomCoin<Blake3_256<_>>>::new(master_options.clone());
                    
                        // Generates the Fold-and-Batch proof.
                        master_prover.prove_fold_and_batch(&inputs, worker_domain_size, master_domain_size, NUM_QUERIES, &mut worker_nodes)
                    },
                    |proof| {
                        let public_coin = DefaultRandomCoin::<Blake3_256<_>>::new(&[]);
                        let mut verifier = black_box(FoldAndBatchVerifier::<BaseElement, DefaultVerifierChannel<BaseElement, _, MerkleTree<Blake3_256<_>>>, _, DefaultRandomCoin<_>, _>::new(public_coin, NUM_QUERIES, master_options.clone(), worker_degree_bound, master_degree_bound).unwrap());
    
                        // Verify the Fold-and-Batch proof.
                        let _ = black_box(verifier.verify_fold_and_batch(black_box(&proof)));

                        println!("The size of the Fold-and-Batch proof is {} bytes", proof.size());
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

criterion_group!(folding_prover_group, fold_and_batch_verifier);
criterion_main!(folding_prover_group);

// HELPER FUNCTIONS
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
