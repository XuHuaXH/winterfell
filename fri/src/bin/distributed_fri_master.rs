use std::{env, io::Read};

use crypto::{hashers::Blake3_256, DefaultRandomCoin, Hasher, MerkleTree, RandomCoin};
use math::fields::{f128::BaseElement, QuadExtension};
use utils::{Deserializable, SliceReader};
use winter_fri::{fold_and_batch_master_commit, fold_and_batch_master_query, DefaultProverChannel, FoldingProof, FriOptions, FriProver};

type Blake3 = Blake3_256<BaseElement>;
type Blake3Digest = <Blake3 as Hasher>::Digest;

static BLOWUP_FACTOR: usize = 4;
static FOLDING_FACTOR: usize = 2;
static NUM_QUERIES: usize = 282;
static MASTER_MAX_REMAINDER_DEGREE: usize = 0;

enum Mode {
    DistributedBatchedFri,
    FoldAndBatch
}

fn run_distributed_fri_master(circuit_size_e: usize, num_poly_e: usize, mode: Mode) {
    let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
    let worker_domain_size = worker_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
    let worker_last_poly_max_degree = match mode {
        Mode::DistributedBatchedFri => worker_degree_bound - 1,
        Mode::FoldAndBatch => worker_degree_bound / 4 - 1
    };

    let master_degree_bound : usize = worker_last_poly_max_degree + 1;
    let master_domain_size = master_degree_bound.next_power_of_two() * BLOWUP_FACTOR;
    let num_poly = 1 << num_poly_e;
    let master_options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, MASTER_MAX_REMAINDER_DEGREE);

    // Prepare the query positions. For simplicity, we draw some random integers 
    // instead of using Fiat-Shamir.
    let mut public_coin = DefaultRandomCoin::<Blake3>::new(&[]);
    let query_positions = public_coin
        .draw_integers(NUM_QUERIES, worker_domain_size, 0)
        .expect("failed to draw query positions");

    let evaluations_size = master_domain_size;
    let mut batched_fri_inputs = Vec::with_capacity(num_poly);
    let mut worker_layer_commitments : Vec<Vec<Blake3Digest>> = Vec::with_capacity(num_poly);
    let mut folding_proofs: Vec<FoldingProof> = Vec::with_capacity(num_poly);
    let mut worker_queried_evaluations : Vec<Vec<QuadExtension<BaseElement>>> = Vec::with_capacity(num_poly);

    // Read the master prover inputs from stdin
    let mut file = std::io::stdin();

    // Read the batched fri inputs.
    for _ in 0..num_poly {
        let mut eval_vec = Vec::with_capacity(evaluations_size);
        for _ in 0..evaluations_size {
            let mut buf = [0u8; 32]; 
            file.read_exact(&mut buf).unwrap();
            let mut reader = SliceReader::new(&buf);
            let element = QuadExtension::<BaseElement>::read_from(&mut reader).unwrap();
            eval_vec.push(element);
        }
        batched_fri_inputs.push(eval_vec);
    }

    // Read the worker layer commitments.
    let num_worker_layers = (worker_degree_bound / master_degree_bound) / FOLDING_FACTOR + 1;
    for _ in 0..num_poly {
        let mut layer_commitment_vec = Vec::with_capacity(num_worker_layers);
        for _ in 0..num_worker_layers {
            let mut buf = [0u8; 32]; 
            file.read_exact(&mut buf).unwrap();
            let mut reader = SliceReader::new(&buf);
            layer_commitment_vec.push(Blake3Digest::read_from(&mut reader).unwrap());
        }
        worker_layer_commitments.push(layer_commitment_vec);
    }

    // Read the worker queried evaluations.
    for _ in 0..num_poly {
        let mut queried_eval_vec = Vec::with_capacity(NUM_QUERIES);
        for _ in 0..NUM_QUERIES {
            let mut buf = [0u8; 32]; 
            file.read_exact(&mut buf).unwrap();
            let mut reader = SliceReader::new(&buf);
            let element = QuadExtension::<BaseElement>::read_from(&mut reader).unwrap();
            queried_eval_vec.push(element);
        }
        worker_queried_evaluations.push(queried_eval_vec);
    }

    // Read the folding proofs.
    let mut buf = Vec::<u8>::new(); 
    file.read_to_end(&mut buf).unwrap();
    let mut reader = SliceReader::new(&buf);
    for _ in 0..num_poly {
        folding_proofs.push(FoldingProof::read_from(&mut reader).unwrap());
    }

    // check if we've read all the bytes
    if file.bytes().next().is_some() {
        panic!("Uncomsumed bytes in the batched fri input file");
    }


    // Instantiate the master prover and its prover channel.
    let mut master_prover = FriProver::<QuadExtension<BaseElement>, DefaultProverChannel<QuadExtension<BaseElement>, Blake3, DefaultRandomCoin<_>>, Blake3, MerkleTree<_>>::new(master_options.clone());
    let mut master_prover_channel = DefaultProverChannel::new(master_domain_size, NUM_QUERIES);

    let (batched_evaluations, _) = fold_and_batch_master_commit(
        &mut master_prover,
        &mut master_prover_channel,
        &worker_layer_commitments,
        batched_fri_inputs,
        NUM_QUERIES,
        worker_domain_size);

    let _ = fold_and_batch_master_query(
        &mut master_prover, 
        &master_prover_channel,
        worker_domain_size, 
        master_domain_size, 
        worker_layer_commitments,
        query_positions,
        folding_proofs, 
        worker_queried_evaluations,
        batched_evaluations);

}



fn main() {
    let args: Vec<String> = env::args().collect();
    let circuit_size_e = args[1].parse::<usize>().unwrap();
    let num_poly_e = args[2].parse::<usize>().unwrap();
    let mode = &args[3];

    match mode.as_str() {
        "distributed_batched_fri" => run_distributed_fri_master(circuit_size_e, num_poly_e, Mode::DistributedBatchedFri),
        "fold_and_batch" => run_distributed_fri_master(circuit_size_e, num_poly_e, Mode::FoldAndBatch),
        _ => unimplemented!("mode {} is not supported", mode),
    }
}