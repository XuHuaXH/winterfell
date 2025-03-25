use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree, RandomCoin};
use math::{fft, fields::f128::BaseElement, FieldElement};
use rand_utils::rand_vector;
use winter_fri::{DefaultProverChannel, FoldingOptions, FoldingProver};
use std::hint::black_box;

static DOMAIN_SIZES_E: [usize; 5] = [14, 15, 16, 17, 18];
static BLOWUP_FACTOR: usize = 8;
static FOLDING_FACTOR: usize = 2;
static NUM_QUERIES: usize = 50;
static LAST_POLY_MAX_DEGREE: usize = 7;

pub fn fold_and_batch_worker(c: &mut Criterion) {
    let mut folding_group = c.benchmark_group("folding prover");
    folding_group.sample_size(10);

    for &domain_size_e in &DOMAIN_SIZES_E {

        let domain_size = 1 << domain_size_e;
        let options = FoldingOptions::new(
            BLOWUP_FACTOR, 
            FOLDING_FACTOR, 
            domain_size, 
            LAST_POLY_MAX_DEGREE);

        // Prepare the query positions. For simplicity, we simply draw some random 
        // integer instead of using Fiat-Shamir.
        let mut public_coin = DefaultRandomCoin::<Blake3_256<BaseElement>>::new(&[]);
        let query_positions = public_coin
            .draw_integers(NUM_QUERIES, domain_size, 0)
            .expect("failed to draw query positions");


        folding_group.bench_function(
            BenchmarkId::new("fold_and_batch_worker", domain_size_e),
            |b| {
                b.iter_batched(
                    || {
                        // generate a random input for each iteration of the benchmark
                        build_evaluations(domain_size)
                    },
                    |evaluations| {
                        let mut prover =
                            FoldingProver::<_, _, _, MerkleTree<Blake3_256<BaseElement>>>::new(
                                domain_size, 
                                options.clone());
                        let mut channel = DefaultProverChannel::<BaseElement, Blake3_256<BaseElement>, DefaultRandomCoin<_>>::new(domain_size, NUM_QUERIES);
                        let _ = black_box(prover.build_layers(black_box(&mut channel), black_box(evaluations.clone())));
                        let _ = black_box(prover.build_proof(black_box(&evaluations), black_box(&query_positions)));
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }
}

criterion_group!(folding_prover_group, fold_and_batch_worker);
criterion_main!(folding_prover_group);

// HELPER FUNCTIONS
// ================================================================================================

fn build_evaluations(domain_size: usize) -> Vec<BaseElement> {
    let mut p: Vec<BaseElement> = rand_vector(domain_size / BLOWUP_FACTOR);
    p.resize(domain_size, BaseElement::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}
