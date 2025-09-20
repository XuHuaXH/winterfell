use std::fs::File;

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::{f128::BaseElement, QuadExtension};
use ::utils::{ByteWriter, Serializable};

mod config;
use config::{BLOWUP_FACTOR, NUM_QUERIES, FOLDING_FACTOR, CIRCUIT_SIZES_E, NUM_POLY_E};

mod utils;
use utils::build_evaluations;
use winter_fri::{fold_and_batch_worker_commit, fold_and_batch_worker_query};

type Blake3 = Blake3_256<BaseElement>;


#[test]
fn generate_fri_inputs() {
    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let worker_domain_size = worker_degree_bound.next_power_of_two() * BLOWUP_FACTOR;

            // generate a random input for the benchmark
            let evaluations = build_evaluations(worker_domain_size, BLOWUP_FACTOR);

            // write the input to file
            let mut file = File::create(format!("./benches/input_data/fri_prover/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap();
            for element in evaluations {
                element.write_into(&mut file);
            }

        }
    }
}

enum Mode {
    FoldAndBatch,
    DistributedBatchedFri,
}

#[test]
fn generate_fold_and_batch_inputs() {
    generate_batched_fri_inputs(Mode::FoldAndBatch);
}

#[test]
fn generate_distributed_batched_fri_inputs() {
    generate_batched_fri_inputs(Mode::DistributedBatchedFri);
}


fn generate_batched_fri_inputs(mode: Mode) {
    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let worker_domain_size = worker_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
            let num_poly = 1 << num_poly_e;

            // Set worker_last_poly_max_degree depending on which batched FRI mode we're in.
            let worker_last_poly_max_degree = match mode {
                Mode::FoldAndBatch => worker_degree_bound / 4 - 1,
                Mode::DistributedBatchedFri => worker_degree_bound - 1
            };
    
            // Prepare the query positions. For simplicity, we draw some random integers 
            // instead of using Fiat-Shamir.
            let mut public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
            let query_positions = public_coin
                .draw_integers(NUM_QUERIES, worker_domain_size, 0)
                .expect("failed to draw query positions");

            // Generate random inputs for the worker nodes.
            let mut inputs = Vec::with_capacity(num_poly);
            for _ in 0..num_poly {
                inputs.push(build_evaluations(worker_domain_size, BLOWUP_FACTOR));
            }

            // ------------------------ Step 1: worker commit phase --------------------------
            // Each worker node executes the FRI commit phase on their local input polynomial.
            let (mut worker_nodes, worker_layer_commitments, batched_fri_inputs) = 
            fold_and_batch_worker_commit::<QuadExtension<BaseElement>, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
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
            let (folding_proofs, worker_queried_evaluations) = 
            fold_and_batch_worker_query::<QuadExtension<BaseElement>, Blake3, MerkleTree<_>, DefaultRandomCoin<_>>(
                &inputs, 
                &mut worker_nodes, 
                &query_positions
            );
            

            // Write the inputs for the master node to file.
            let mut file = match mode {
                Mode::DistributedBatchedFri => 
                    // File::create(format!("/dev/shm/frittata/benches/input_data/distributed_batched_fri_master/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap(),
                    File::create(format!("./benches/input_data/distributed_batched_fri_master/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap(),
                Mode::FoldAndBatch => 
                    // File::create(format!("/dev/shm/frittata/benches/input_data/fold_and_batch_master/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap()
                    File::create(format!("./benches/input_data/fold_and_batch_master/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap()
            };
            
            // Write the batched fri inputs.
            for eval_vec in batched_fri_inputs {
                for element in eval_vec {
                    element.write_into(&mut file);
                }
            }

            // Write the worker layer commitments.
            file.write_many(worker_layer_commitments);

            // Write the folding proofs
            file.write_many(folding_proofs);

            // write the worker queried evaluations.
            file.write_many(worker_queried_evaluations);
        }
    }
}

