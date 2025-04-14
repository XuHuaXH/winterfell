use std::{env, fs::File};

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use math::fields::f128::BaseElement;
use utils::{ByteReader, Deserializable, ReadAdapter};
use winter_fri::{DefaultProverChannel, FriOptions, FriProver};

type Blake3 = Blake3_256<BaseElement>;

static BLOWUP_FACTOR: usize = 8;
static FOLDING_FACTOR: usize = 2;
static NUM_QUERIES: usize = 50;


fn run_single_fri_prover(circuit_size_e: usize, num_poly_e: usize) {
    let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
    let max_remainder_degree = 0;
    let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;
    let options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, max_remainder_degree);

    // read the input evaluation vector from file
    let mut file = File::open(format!("./benches/input_data/fri_prover/circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)).unwrap();
    let mut reader = ReadAdapter::new(&mut file);
    // let evaluation_size = reader.read_u64().unwrap() as usize;
    let evaluations_size = worker_domain_size;
    let mut evaluations = Vec::with_capacity(evaluations_size);

    for _ in 0..evaluations_size {
        let element = BaseElement::read_from(&mut reader).unwrap();
        evaluations.push(element);
    }

    // instantiate the prover and the prover channel
    let mut channel = DefaultProverChannel::<BaseElement, Blake3, DefaultRandomCoin<_>>::new(worker_domain_size, NUM_QUERIES);
    let mut prover = FriProver::<_, _, _, MerkleTree<Blake3>>::new(options.clone());

    prover.build_layers(&mut channel, evaluations.clone());
    let positions = channel.draw_query_positions(0);
    let _ = prover.build_proof(&positions);
    
    // Comptute the evaluations of this prover's local polynomial at all the query positions.
    let _ = positions.iter().map(|&p| evaluations[p]).collect::<Vec<_>>();

}



fn main() {
    let args: Vec<String> = env::args().collect();
    let circuit_size_e = args[1].parse::<usize>().unwrap();
    let num_poly_e = args[2].parse::<usize>().unwrap();

    run_single_fri_prover(circuit_size_e, num_poly_e);
}