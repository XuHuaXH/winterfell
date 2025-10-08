use std::{env, io::Read};

use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use math::fields::{f128::BaseElement, QuadExtension};
use utils::{Deserializable, SliceReader};
use winter_fri::{DefaultProverChannel, FriOptions, FriProver};

type Blake3 = Blake3_256<BaseElement>;

static BLOWUP_FACTOR: usize = 4;
static FOLDING_FACTOR: usize = 2;
static NUM_QUERIES: usize = 282;


fn run_single_fri_prover(circuit_size_e: usize, num_poly_e: usize) {
    let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
    let max_remainder_degree = 0;
    let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;
    let options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, max_remainder_degree);

    // Read the input evaluation vector from stdin
    let mut file = std::io::stdin();

    let evaluations_size = worker_domain_size;
    let mut evaluations = Vec::with_capacity(evaluations_size);

    for _ in 0..evaluations_size {
        let mut buf = [0u8; 32]; 
        file.read_exact(&mut buf).unwrap();
        let mut reader = SliceReader::new(&buf);
        let element = QuadExtension::<BaseElement>::read_from(&mut reader).unwrap();
        evaluations.push(element);
    }

    // check if we've read all the bytes
    if file.bytes().next().is_some() {
        panic!("Uncomsumed bytes in the batched fri input file");
    }

    // instantiate the prover and the prover channel
    let mut channel = DefaultProverChannel::<QuadExtension<BaseElement>, Blake3, DefaultRandomCoin<_>>::new(worker_domain_size, NUM_QUERIES);
    let mut prover = FriProver::<QuadExtension<BaseElement>, _, Blake3, MerkleTree<Blake3>>::new(options.clone());

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