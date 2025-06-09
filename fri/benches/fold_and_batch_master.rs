use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::{fields::f128::BaseElement, FieldElement};
use winter_fri::{fold_and_batch_master_commit, fold_and_batch_master_query, fold_and_batch_worker_commit, fold_and_batch_worker_query, DefaultProverChannel, FriOptions, FriProver};
use std::io::Write;
use std::{fs::File, hint::black_box};
use std::mem::size_of;

mod config;
use config::{BLOWUP_FACTOR, CIRCUIT_SIZES_E, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE, NUM_POLY_E, NUM_QUERIES};

mod utils;
use utils::build_evaluations_from_random_poly;

type Blake3 = Blake3_256<BaseElement>;



pub fn fold_and_batch_master(c: &mut Criterion) {
    let mut folding_group = c.benchmark_group("master prover");
    folding_group.sample_size(10);

    let mut file = File::create("./benches/bench_data/fold_and_batch_comm_cost").unwrap();

    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;

            let worker_last_poly_max_degree = worker_degree_bound / 4 - 1;  // parameter for Fold-and-Batch
            // let worker_last_poly_max_degree = worker_degree_bound - 1;   // parameter for Distributed Batched FRI

            let master_degree_bound : usize = worker_last_poly_max_degree + 1;
            let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
            let num_poly = 1 << num_poly_e;
            let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);

            // Generates evaluation vectors of random polynomials with degree < worker_degree_bound.
            let mut inputs = Vec::with_capacity(num_poly);
            for _ in 0..num_poly {
                inputs.push(build_evaluations_from_random_poly(worker_degree_bound, BLOWUP_FACTOR));
            }

            // Prepare the query positions. For simplicity, we draw some random integers 
            // instead of using Fiat-Shamir.
            let mut public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
            let query_positions = public_coin
                .draw_integers(NUM_QUERIES, worker_domain_size, 0)
                .expect("failed to draw query positions");


            // ------------------------ Step 1: worker commit phase --------------------------
            // Each worker node executes the FRI commit phase on their local input polynomial.
            let (mut worker_nodes, worker_layer_commitments, batched_fri_inputs) = 
            fold_and_batch_worker_commit(
                &inputs, 
                num_poly, 
                BLOWUP_FACTOR, 
                FOLDING_FACTOR, 
                worker_domain_size, 
                worker_last_poly_max_degree, 
                NUM_QUERIES
            );
            

            // -------------------------- Step 3: worker query phase --------------------------------
            // Each worker node generates the FRI folding proof proving that the folding of its local 
            // polynomial was done correctly.
            let (folding_proofs, worker_evaluations) = 
            fold_and_batch_worker_query::<BaseElement, Blake3, MerkleTree<_>, DefaultRandomCoin<_>>(&inputs, &mut worker_nodes, &query_positions);


            // Compute the total amount of communication in bytes between the workers and the master.
            let worker_layer_commitment_size = {
                let num_vec = worker_layer_commitments.len();
                num_vec * worker_layer_commitments[0].len() * 32 // 32 bytes per digest
            };
            let batched_fri_inputs_size = {
                let num_vec = batched_fri_inputs.len();
                num_vec * batched_fri_inputs[0].len() * BaseElement::ELEMENT_BYTES
            };
            let folding_proofs_size = folding_proofs.iter().fold(0, |acc, proof| acc + proof.size()); 
            let worker_evaluations_size = {
                let num_vec = worker_evaluations.len();
                num_vec * worker_evaluations[0].len() * BaseElement::ELEMENT_BYTES
            };
            let query_positions_size = num_poly * query_positions.len() * size_of::<usize>();
            let total_communication_bytes = 
                worker_layer_commitment_size + 
                batched_fri_inputs_size +
                folding_proofs_size + 
                worker_evaluations_size +
                query_positions_size;

            // Record the communication cost to the file.
            let communication_cost = format!("{}\n", total_communication_bytes);
            let _ = file.write_all(communication_cost.as_bytes());

            folding_group.bench_function(
                BenchmarkId::new("fold_and_batch_worker", format!("circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)),
                |b| {
                    b.iter_batched(
                        || {
                            // Instantiate the master prover and its prover channel.
                            let master_prover = FriProver::<BaseElement, DefaultProverChannel<BaseElement, Blake3, DefaultRandomCoin<_>>, Blake3, MerkleTree<_>>::new(master_options.clone());
                            let master_prover_channel = DefaultProverChannel::new(master_domain_size, NUM_QUERIES);
                            (master_prover, master_prover_channel)
                        },
                        |(mut master_prover, mut master_prover_channel)| {

                            // In the actual Fold-and-Batch protocol, the worker nodes execute 
                            // the query phase in between the commit and query phase of the master prover. 
                            // Here, we combine the commit phase and query phase of the master prover to make
                            // benchmarking easier, and use artificially generated query positions instead of
                            // getting them from Fiat-Shamir. The FoldAndBatchProof produced this way will be 
                            // incorrect, but the computations performed will be similar to those in realistic 
                            // scenarios.
                            let (batched_evaluations, _) = black_box(fold_and_batch_master_commit(
                                &mut master_prover,
                                &mut master_prover_channel,
                                &worker_layer_commitments,
                                batched_fri_inputs.clone(),
                                NUM_QUERIES,
                                worker_domain_size));

                            let _ = black_box(fold_and_batch_master_query(
                                &mut master_prover, 
                                &master_prover_channel,
                                worker_domain_size, 
                                master_domain_size, 
                                worker_layer_commitments.clone(),
                                query_positions.clone(),
                                folding_proofs.clone(), 
                                worker_evaluations.clone(),
                                batched_evaluations));
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }   
    }
}

criterion_group!(folding_prover_group, fold_and_batch_master);
criterion_main!(folding_prover_group);
