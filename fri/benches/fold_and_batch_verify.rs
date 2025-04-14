use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::f128::BaseElement;
use winter_fri::{fold_and_batch_prove, DefaultVerifierChannel, FoldAndBatchVerifier, FriOptions};
use std::{fs::File, hint::black_box, io::Write};

type Blake3 = Blake3_256<BaseElement>;

mod config;
use config::{BLOWUP_FACTOR, CIRCUIT_SIZES_E, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE, NUM_POLY_E, NUM_QUERIES};

mod utils;
use utils::build_evaluations_from_random_poly;


pub fn fold_and_batch_verifier(c: &mut Criterion) {
    let mut verifier_group = c.benchmark_group("verifier");
    verifier_group.sample_size(10);

    let mut file = File::create("./benches/bench_data/fold_and_batch_proof_size").unwrap();

    for &circuit_size_e in &CIRCUIT_SIZES_E {
        for &num_poly_e in &NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;

            // let worker_last_poly_max_degree = 0;
            let worker_last_poly_max_degree = worker_degree_bound / 4;
            // let worker_last_poly_max_degree = worker_degree_bound - 1;

            let master_degree_bound : usize = worker_last_poly_max_degree + 1;
            println!("worker degree bound: {}", worker_degree_bound);
            println!("worker_last_poly_max_degree: {}", worker_last_poly_max_degree);
            println!("master degree bound: {}", master_degree_bound);
            let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
            let num_poly = 1 << num_poly_e;
            let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);
            
            
            // Generates evaluation vectors of random polynomials with degree < worker_degree_bound.
            let mut inputs = Vec::with_capacity(num_poly);
            for _ in 0..num_poly {
                inputs.push(build_evaluations_from_random_poly(worker_degree_bound, BLOWUP_FACTOR));
            }

            let proof = fold_and_batch_prove::<BaseElement, Blake3, DefaultRandomCoin<_>, MerkleTree<_>>(
                inputs.clone(),
                num_poly, 
                BLOWUP_FACTOR,
                FOLDING_FACTOR,
                worker_domain_size,
                worker_last_poly_max_degree,
                master_domain_size,
                master_options.clone(),
                NUM_QUERIES
            );

            // Record the proof size to the file.
            let proof_size = format!("{}\n", proof.size());
            let _ = file.write_all(proof_size.as_bytes());

            verifier_group.bench_function(
                BenchmarkId::new("fold_and_batch_verifier", format!("circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)),
                |b| {
                    b.iter_batched(
                        || {
                            DefaultRandomCoin::<Blake3_256<_>>::new(&[])
                        },
                        |public_coin| {
                            let mut verifier = black_box(FoldAndBatchVerifier::<BaseElement, DefaultVerifierChannel<BaseElement, _, MerkleTree<Blake3_256<_>>>, _, DefaultRandomCoin<_>, _>::new(public_coin, NUM_QUERIES, master_options.clone(), worker_degree_bound, master_degree_bound).unwrap());
        
                            // Verify the Fold-and-Batch proof.
                            let _ = black_box(verifier.verify_fold_and_batch(black_box(&proof)));
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }
}

criterion_group!(folding_prover_group, fold_and_batch_verifier);
criterion_main!(folding_prover_group);

