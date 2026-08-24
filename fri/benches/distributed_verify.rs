use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::{f128::BaseElement, QuadExtension};
use winter_fri::{fold_and_batch_prove, DefaultVerifierChannel, FoldAndBatchVerifier, FriOptions};
use std::{fs::File, hint::black_box, io::Write};

type Blake3 = Blake3_256<BaseElement>;

mod config;
use config::{BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE, NUM_QUERIES, FriMode, parse_fri_mode, parse_circuit_size_e, parse_num_poly_e};

mod utils;
use utils::build_evaluations_from_random_poly;


pub fn distributed_verify(c: &mut Criterion) {

    let mut verifier_group = c.benchmark_group("distributed verify");
    verifier_group.sample_size(10);
    let fri_mode = parse_fri_mode();

    std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/benches/bench_data")).unwrap();
    let mut file = match fri_mode {
        FriMode::DistributedBatchedFri => File::create(concat!(env!("CARGO_MANIFEST_DIR"), "/benches/bench_data/distributed_batched_fri_proof_size")).unwrap(),
        FriMode::FoldAndBatch => File::create(concat!(env!("CARGO_MANIFEST_DIR"), "/benches/bench_data/fold_and_batch_proof_size")).unwrap(),
    };

    for circuit_size_e in parse_circuit_size_e() {
        for num_poly_e in parse_num_poly_e() {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;

            let worker_last_poly_max_degree = match fri_mode {
                FriMode::FoldAndBatch => worker_degree_bound / 4 - 1,
                FriMode::DistributedBatchedFri => worker_degree_bound - 1,
            };

            let master_degree_bound : usize = worker_last_poly_max_degree + 1;
            let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
            let num_poly = 1 << num_poly_e;
            let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);


            // Generates evaluation vectors of random polynomials with degree < worker_degree_bound.
            let mut inputs = Vec::with_capacity(num_poly);
            for _ in 0..num_poly {
                inputs.push(build_evaluations_from_random_poly(worker_degree_bound, BLOWUP_FACTOR));
            }

            let proof = fold_and_batch_prove::<QuadExtension<BaseElement>, Blake3, DefaultRandomCoin<_>, MerkleTree<_>>(
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
                BenchmarkId::new(
                    match fri_mode {
                    FriMode::FoldAndBatch => "fold_and_batch_verifier",
                    FriMode::DistributedBatchedFri => "distributed_batched_fri_verifier",
                }, format!("circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)),
                |b| {
                    b.iter_batched(
                        || {
                            DefaultRandomCoin::<Blake3_256<_>>::new(&[])
                        },
                        |public_coin| {
                            let mut verifier = black_box(FoldAndBatchVerifier::<QuadExtension<BaseElement>, DefaultVerifierChannel<QuadExtension<BaseElement>, _, MerkleTree<Blake3>>, _, DefaultRandomCoin<_>, _>::new(public_coin, NUM_QUERIES, master_options.clone(), worker_degree_bound, master_degree_bound).unwrap());

                            // Verify the Fold-and-Batch proof.
                            let result = verifier.verify_fold_and_batch(black_box(&proof));
                            let _ = black_box(result);
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }
}

criterion_group!(bench_verify, distributed_verify);
criterion_main!(bench_verify);

