use std::fs::File;

use ::utils::{ByteWriter, Serializable};

mod config;
use config::{BLOWUP_FACTOR, CIRCUIT_SIZES_E, FOLDING_FACTOR, NUM_POLY_E, NUM_QUERIES};

mod utils;
use utils::build_evaluations;


#[test]
fn generate_fri_inputs() {
    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;

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


#[test]
fn generate_batched_fri_inputs() {
    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            // let worker_last_poly_max_degree = worker_degree_bound / 4;
            let worker_last_poly_max_degree = worker_degree_bound - 1;


            let master_degree_bound : usize = worker_last_poly_max_degree + 1;
            let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
            let num_poly = 1 << num_poly_e;

            // generate random inputs for the batched FRI prover
            let mut inputs = Vec::with_capacity(num_poly);
            for _ in 0..num_poly {
                let evaluations = build_evaluations(master_domain_size, BLOWUP_FACTOR);
                inputs.push(evaluations);
            }
            
            // write the inputs to file
            let mut file = File::create(format!("./benches/input_data/fold_and_batch_master/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap();
            for eval_vec in inputs {
                for element in eval_vec {
                    element.write_into(&mut file);
                }
            }
        }
    }
}

