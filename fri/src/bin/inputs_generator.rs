use std::env;

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::{f128::BaseElement, QuadExtension};
use ::utils::Serializable;
use math::{fft, FieldElement};
use rand_utils::rand_vector;

use winter_fri::{fold_and_batch_worker_commit, fold_and_batch_worker_query};

type Blake3 = Blake3_256<BaseElement>;


// Parameters for distributed FRI benchmarks
pub static BLOWUP_FACTOR: usize = 4;
pub static FOLDING_FACTOR: usize = 2;
pub static NUM_QUERIES: usize = 282;


fn generate_fri_inputs(circuit_size_e: usize, num_poly_e: usize) {
    let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
    let worker_domain_size = worker_degree_bound.next_power_of_two() * BLOWUP_FACTOR;

    // generate a random input for the benchmark
    let evaluations = build_evaluations(worker_domain_size, BLOWUP_FACTOR);

    // write to stdout for piping into the reader program
    let mut file = std::io::stdout();

    for element in evaluations {
        element.write_into(&mut file);
    }
}

enum Mode {
    FoldAndBatch,
    DistributedBatchedFri,
}


fn generate_fold_and_batch_inputs(circuit_size_e: usize, num_poly_e: usize) {
    generate_batched_fri_inputs(circuit_size_e, num_poly_e, Mode::FoldAndBatch);
}


fn generate_distributed_batched_fri_inputs(circuit_size_e: usize, num_poly_e: usize) {
    generate_batched_fri_inputs(circuit_size_e, num_poly_e, Mode::DistributedBatchedFri);
}


fn generate_batched_fri_inputs(circuit_size_e: usize, num_poly_e: usize, mode: Mode) {
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
    

    // write to stdout for piping into the reader program
    let mut file = std::io::stdout();

        // Write the batched fri inputs.
    for eval_vec in batched_fri_inputs {
        for element in eval_vec {
            element.write_into(&mut file);
        }
    }

    // Write the worker layer commitments.
    for layer_commitment_vec in &worker_layer_commitments {
        for element in layer_commitment_vec {
            element.write_into(&mut file);
        }
    }

    // write the worker queried evaluations.
    for queried_eval_vec in &worker_queried_evaluations {
        for i in 0..queried_eval_vec.len() {
            queried_eval_vec[i].write_into(&mut file);
        }
    }

    // Write the folding proofs
    {
        for folding_proof in &folding_proofs {
            folding_proof.write_into(&mut file);
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn build_evaluations(domain_size: usize, lde_blowup: usize) -> Vec<QuadExtension<BaseElement>> {
    let mut p: Vec<QuadExtension<BaseElement>> = rand_vector(domain_size / lde_blowup);
    p.resize(domain_size, <QuadExtension<BaseElement>>::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let circuit_size_e = args[1].parse::<usize>().unwrap();
    let num_poly_e = args[2].parse::<usize>().unwrap();
    let mode = &args[3];

    match mode.as_str() {
        "distributed_batched_fri" => generate_distributed_batched_fri_inputs(circuit_size_e, num_poly_e),
        "fold_and_batch" => generate_fold_and_batch_inputs(circuit_size_e, num_poly_e),
        "parallel_fri" => generate_fri_inputs(circuit_size_e, num_poly_e),
        _ => unimplemented!("mode {} is not supported", mode),
    }

}

