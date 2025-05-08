
use alloc::vec::Vec;
use crate::ProverChannel;
use core::marker::PhantomData;

use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;


pub struct BatchedFriProverChannel<E, H, R>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
{
    public_coin: R,
    function_commitments: Vec<H::Digest>,
    layer_commitments: Vec<H::Digest>,
    _field_element: PhantomData<E>,
}


impl<E, H, R> BatchedFriProverChannel<E, H, R>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
{

    pub fn new() -> Self {
        BatchedFriProverChannel {
            public_coin: RandomCoin::new(&[]),
            function_commitments: Vec::new(),
            layer_commitments: Vec::new(),
            _field_element: PhantomData,
        }
    }

    pub fn function_commitments(&self) -> &[H::Digest] {
        &self.function_commitments
    }

    pub fn layer_commitments(&self) -> &[H::Digest] {
        &self.layer_commitments
    }

    pub fn push_function_commitment(&mut self, function_root: H::Digest) {
        self.function_commitments.push(function_root);
        self.public_coin.reseed(function_root);
    }

    pub fn draw_batched_fri_challange(&mut self) -> E {
        self.public_coin.draw().expect("failed to draw batched FRI challenge")
    }

    pub fn draw_query_positions(&mut self, domain_size: usize, num_queries: usize, nonce: u64) -> Vec<usize> {
        
        assert!(domain_size >= 8, "domain size must be at least 8, but was {domain_size}");
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two, but was {domain_size}"
        );
        assert!(num_queries > 0, "number of queries must be greater than zero");

        self.public_coin
            .draw_integers(num_queries, domain_size, nonce)
            .expect("failed to draw query positions")
    }
}

impl<E, H, R> ProverChannel<E> for BatchedFriProverChannel<E, H, R>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
{
    type Hasher = H;

    fn commit_fri_layer(&mut self, layer_root: H::Digest) {
        self.layer_commitments.push(layer_root);
        self.public_coin.reseed(layer_root);
    }

    fn draw_fri_alpha(&mut self) -> E {
        self.public_coin.draw().expect("failed to draw FRI alpha")
    }
}

