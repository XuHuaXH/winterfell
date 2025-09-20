use std::{env, fs::File};

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::{f128::BaseElement, QuadExtension};
use utils::{Deserializable, ReadAdapter};
use winter_fri::{DefaultProverChannel, FoldingOptions, FoldingProver};

type Blake3 = Blake3_256<BaseElement>;

static BLOWUP_FACTOR: usize = 4;
static FOLDING_FACTOR: usize = 2;
static NUM_QUERIES: usize = 282;

enum Mode {
    DistributedBatchedFri,
    FoldAndBatch
}

fn run_single_distributed_fri_worker(circuit_size_e: usize, num_poly_e: usize, mode: Mode) {
    let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);

    let last_poly_max_degree = match mode {
        Mode::DistributedBatchedFri => worker_degree_bound - 1,
        Mode::FoldAndBatch => worker_degree_bound / 4 - 1
    };

    let worker_domain_size = worker_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
    
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

    let mut prover = FoldingProver::<_, _, _, MerkleTree<Blake3>>::new(options.clone());
    let mut channel = DefaultProverChannel::<QuadExtension<BaseElement>, Blake3, DefaultRandomCoin<_>>::new(worker_domain_size, NUM_QUERIES);

    // read the input evaluation vector from file
    let mut file = File::open(format!("./benches/input_data/fri_prover/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap();
    let mut reader = ReadAdapter::new(&mut file);
    let evaluations_size = worker_domain_size;
    let mut evaluations = Vec::with_capacity(evaluations_size);

    for _ in 0..evaluations_size {
        let element = QuadExtension::<BaseElement>::read_from(&mut reader).unwrap();
        evaluations.push(element);
    }

    let _ = prover.build_layers(&mut channel, evaluations.clone());
    let _ = prover.build_proof(&evaluations, &query_positions);
    
}



fn main() {
    let args: Vec<String> = env::args().collect();
    let circuit_size_e = args[1].parse::<usize>().unwrap();
    let num_poly_e = args[2].parse::<usize>().unwrap();
    let mode = &args[3];

    match mode.as_str() {
        "distributed_batched_fri" => run_single_distributed_fri_worker(circuit_size_e, num_poly_e, Mode::DistributedBatchedFri),
        "fold_and_batch" => run_single_distributed_fri_worker(circuit_size_e, num_poly_e, Mode::FoldAndBatch),
        _ => unimplemented!("mode {} is not supported", mode)
    }
}