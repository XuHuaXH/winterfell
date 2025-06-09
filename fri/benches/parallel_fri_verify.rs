use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, Hasher, MerkleTree, RandomCoin};
use math::fields::f128::BaseElement;
use winter_fri::{DefaultProverChannel, DefaultVerifierChannel, FriOptions, FriProof, FriProver, FriVerifier};
use std::{fs::File, hint::black_box, io::Write};

mod config;
use config::{BLOWUP_FACTOR, CIRCUIT_SIZES_E, FOLDING_FACTOR, NUM_POLY_E, NUM_QUERIES};

mod utils;
use utils::build_evaluations;

type Blake3 = Blake3_256<BaseElement>;


pub fn parallel_fri_verify(c: &mut Criterion) {
    let mut folding_group = c.benchmark_group("parallel fri verifier");
    folding_group.sample_size(10);

    let mut file = File::create("./benches/bench_data/parallel_fri_proof_size").unwrap();

    for circuit_size_e in CIRCUIT_SIZES_E {
        for num_poly_e in NUM_POLY_E {

            let worker_degree_bound : usize = 1 << (circuit_size_e - num_poly_e);
            let max_remainder_degree = 0;
            let worker_domain_size = worker_degree_bound * BLOWUP_FACTOR;
            let num_poly = 1 << num_poly_e;
            let options = FriOptions::new(BLOWUP_FACTOR, FOLDING_FACTOR, max_remainder_degree);

            // generate random inputs for the provers
            let mut inputs = Vec::with_capacity(num_poly);
            for _ in 0..num_poly {
                inputs.push(build_evaluations(worker_domain_size, BLOWUP_FACTOR));
            }

            let (proofs, commitments, queried_evaluations) = generate_fri_proofs(inputs, worker_domain_size, &options);

            // Record the proof size to the file.
            let proof_size = format!("{}\n", proofs.iter().fold(0, |acc, proof| acc + proof.size()));
            let _ = file.write_all(proof_size.as_bytes());

            folding_group.bench_function(
                BenchmarkId::new("parallel_fri_verifier", format!("circuit_e_{}_machine_e_{}", circuit_size_e, num_poly_e)),
                |b| {
                    b.iter(
                        || {
                            for i in 0..num_poly {
                                // Prepare the channel and public coin for the verifier.
                                let mut channel = black_box(DefaultVerifierChannel::<BaseElement, Blake3, MerkleTree<Blake3>>::new(
                                    proofs[i].clone(),
                                    commitments[i].clone(),
                                    worker_domain_size,
                                    FOLDING_FACTOR,
                                )
                                .unwrap());
                                let mut coin = crypto::DefaultRandomCoin::<Blake3>::new(black_box(&[]));

                                // Instantiate the FRI verifier and verify the proof.
                                let verifier = FriVerifier::new(&mut channel, &mut coin, options.clone(), worker_degree_bound - 1).unwrap();
                                let positions = coin.draw_integers(NUM_QUERIES, worker_domain_size, 0).unwrap();
                                let result = verifier.verify(&mut channel, &queried_evaluations[i], &positions);
                                let _ = black_box(result);
                            }
                        }
                    );
                },
            );
        }   
    }
}

criterion_group!(parallel_fri_verifier_group, parallel_fri_verify);
criterion_main!(parallel_fri_verifier_group);

// HELPER FUNCTIONS
// ================================================================================================

/// Generate a FRI proof for each one of the input evaluation vectors in `inputs`.
fn generate_fri_proofs(inputs: Vec<Vec<BaseElement>>, domain_size: usize, options: &FriOptions) 
-> (Vec<FriProof>, 
    Vec<Vec<<Blake3_256<BaseElement> as Hasher>::Digest>>,
    Vec<Vec<BaseElement>>
) {
    let num_poly = inputs.len();
    let mut proofs = Vec::with_capacity(num_poly);
    let mut commitments = Vec::with_capacity(num_poly);
    let mut queried_evaluations = Vec::with_capacity(num_poly);

    for input in inputs {
        // instantiate the prover and the prover channel
        let mut channel = DefaultProverChannel::<BaseElement, Blake3, DefaultRandomCoin<_>>::new(domain_size, NUM_QUERIES);
        let mut prover = FriProver::<_, _, _, MerkleTree<Blake3>>::new(options.clone());

        prover.build_layers(&mut channel, input.clone());
        let positions = channel.draw_query_positions(0);
        let proof = prover.build_proof(&positions);
        proofs.push(proof);
        commitments.push(channel.layer_commitments().to_vec());
        queried_evaluations.push(positions.iter().map(|&p| input[p]).collect::<Vec<_>>());
    }
    (proofs, commitments, queried_evaluations)
}