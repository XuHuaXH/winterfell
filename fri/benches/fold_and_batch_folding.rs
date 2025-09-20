use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::{f128::BaseElement, QuadExtension};

use winter_fri::{DefaultProverChannel, FoldingOptions, FoldingProver};
use std::{hint::black_box};

mod config;
use config::{BLOWUP_FACTOR, CIRCUIT_SIZES_E, FOLDING_FACTOR, NUM_POLY_E, NUM_QUERIES};

mod utils;
use utils::build_evaluations;

type Blake3 = Blake3_256<BaseElement>;


pub fn fold_and_batch_worker(c: &mut Criterion) {

    let mut folding_group = c.benchmark_group("folding prover");
    folding_group.sample_size(10);

    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);

            // let last_poly_max_degree = worker_degree_bound - 1;       // parameter for Distributed Batched FRI
            let last_poly_max_degree = worker_degree_bound / 4 - 1;   // parameter for Fold-and-Batch

            let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;
            let options = FoldingOptions::new(
                BLOWUP_FACTOR, 
                FOLDING_FACTOR, 
                worker_domain_size, 
                last_poly_max_degree);

            // Prepare the query positions. For simplicity, we draw some random integers 
            // instead of using Fiat-Shamir.
            let mut public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
            let query_positions = public_coin
                .draw_integers(NUM_QUERIES, worker_domain_size, 0)
                .expect("failed to draw query positions");

            // generate a random input for the benchmark
            let evaluations = build_evaluations(worker_domain_size, BLOWUP_FACTOR);

            folding_group.bench_function(
                BenchmarkId::new("fold_and_batch_worker", format!("circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)),
                |b| {
                    b.iter_batched(
                        || {
                            let prover =
                                FoldingProver::<QuadExtension<BaseElement>, _, _, MerkleTree<Blake3>>::new(options.clone());
                            let channel = DefaultProverChannel::<QuadExtension<BaseElement>, Blake3, DefaultRandomCoin<_>>::new(worker_domain_size, NUM_QUERIES);
                            (prover, channel)
                        },
                        |(mut prover, mut channel)| {
                            let _ = black_box(prover.build_layers(black_box(&mut channel), black_box(evaluations.clone())));
                            let _ = black_box(prover.build_proof(black_box(&evaluations), black_box(&query_positions)));
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }   
    }
}

criterion_group!(folding_prover_group, fold_and_batch_worker);
criterion_main!(folding_prover_group);

