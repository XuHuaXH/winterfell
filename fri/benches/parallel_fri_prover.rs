use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use math::fields::f128::BaseElement;
use winter_fri::{DefaultProverChannel, FriOptions, FriProver};
use std::hint::black_box;

mod config;
use config::{BLOWUP_FACTOR, CIRCUIT_SIZES_E, FOLDING_FACTOR, NUM_POLY_E, NUM_QUERIES};

mod utils;
use utils::build_evaluations;

type Blake3 = Blake3_256<BaseElement>;


pub fn parallel_fri_prover(c: &mut Criterion) {
    let mut folding_group = c.benchmark_group("parallel fri prover");
    folding_group.sample_size(10);

    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let max_remainder_degree = 0;
            let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;
            let options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, max_remainder_degree);

            // generate a random input for the benchmark
            let evaluations = build_evaluations(worker_domain_size, BLOWUP_FACTOR);


            folding_group.bench_function(
                BenchmarkId::new("parallel_fri_worker", format!("circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)),
                |b| {
                    b.iter_batched(
                        || {
                            // instantiate the prover and the prover channel
                            let channel = DefaultProverChannel::<BaseElement, Blake3, DefaultRandomCoin<_>>::new(worker_domain_size, NUM_QUERIES);
                            let prover = FriProver::<_, _, _, MerkleTree<Blake3>>::new(options.clone());
                            (channel, prover)
                        },
                        |(mut channel, mut prover)| {
                            prover.build_layers(&mut channel, black_box(evaluations.clone()));
                            let positions = channel.draw_query_positions(black_box(0));
                            let proof = prover.build_proof(&positions);
                            black_box(proof);
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }   
    }
}

criterion_group!(parallel_fri_prover_group, parallel_fri_prover);
criterion_main!(parallel_fri_prover_group);

