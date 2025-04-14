use std::{env, fs::File};

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::fields::f128::BaseElement;
use utils::{ByteReader, Deserializable, ReadAdapter};
use winter_fri::{fold_and_batch_prove, BatchedFriProver, DefaultProverChannel, FoldingOptions, FoldingProver, FriOptions, FriProver};

type Blake3 = Blake3_256<BaseElement>;

static BLOWUP_FACTOR: usize = 8;
static FOLDING_FACTOR: usize = 2;
static NUM_QUERIES: usize = 50;
static MASTER_MAX_REMAINDER_DEGREE: usize = 0;


fn run_fold_and_batch_master(circuit_size_e: usize, num_poly_e: usize) {
    let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
    // let worker_last_poly_max_degree = worker_degree_bound / 4;
    let worker_last_poly_max_degree = worker_degree_bound - 1;


    let master_degree_bound : usize = worker_last_poly_max_degree + 1;
    let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
    let num_poly = 1 << num_poly_e;
    let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);

    // Read inputs from file
    let mut file = File::open(format!("./benches/input_data/fold_and_batch_master/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap();
    let mut reader = ReadAdapter::new(&mut file);
    let evaluations_size = master_domain_size;
    let mut inputs = Vec::with_capacity(num_poly);

    for _ in 0..num_poly {
        let mut eval_vec = Vec::with_capacity(evaluations_size);
        for _ in 0..evaluations_size {
            let element = BaseElement::read_from(&mut reader).unwrap();
            eval_vec.push(element);
        }
        inputs.push(eval_vec);
    }

    // instantiate the prover and generate the proof
    let mut prover = BatchedFriProver::<BaseElement, Blake3, MerkleTree<Blake3>, DefaultRandomCoin<Blake3>>::new(master_options);
    let _ = prover.build_proof(&mut inputs, master_domain_size, NUM_QUERIES);
}



fn main() {
    let args: Vec<String> = env::args().collect();
    let circuit_size_e = args[1].parse::<usize>().unwrap();
    let num_poly_e = args[2].parse::<usize>().unwrap();

    run_fold_and_batch_master(circuit_size_e, num_poly_e);
}