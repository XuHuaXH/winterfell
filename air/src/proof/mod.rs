// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains STARK proof struct and associated components.

use alloc::vec::Vec;

use crypto::{Hasher, MerkleTree};
use fri::FriProof;
use math::FieldElement;
use security::{ConjecturedSecurity, ProvenSecurity};
use utils::{ByteReader, Deserializable, DeserializationError, Serializable, SliceReader};

use crate::{options::BatchingMethod, ProofOptions, TraceInfo};

mod context;
pub use context::Context;

mod commitments;
pub use commitments::Commitments;

mod queries;
pub use queries::Queries;

mod ood_frame;
pub use ood_frame::{OodFrame, TraceOodFrame};

mod security;

mod table;
pub use table::Table;

#[cfg(test)]
mod tests;

// PROOF
// ================================================================================================
/// A proof generated by Winterfell prover.
///
/// A STARK proof contains information proving that a computation was executed correctly. A proof
/// also contains basic metadata for the computation, but neither the definition of the computation
/// itself, nor public inputs consumed by the computation are contained in a proof.
///
/// A proof can be serialized into a sequence of bytes using [to_bytes()](Proof::to_bytes) function,
/// and deserialized from a sequence of bytes using [from_bytes()](Proof::from_bytes) function.
///
/// To estimate soundness of a proof (in bits), [security_level()](Proof::security_level) function
/// can be used.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Proof {
    /// Basic metadata about the execution of the computation described by this proof.
    pub context: Context,
    /// Number of unique queries made by the verifier. This will be different from the
    /// context.options.num_queries if the same position in the domain was queried more than once.
    pub num_unique_queries: u8,
    /// Commitments made by the prover during the commit phase of the protocol.
    pub commitments: Commitments,
    /// Decommitments of extended execution trace values (for all trace segments) at position
    ///  queried by the verifier.
    pub trace_queries: Vec<Queries>,
    /// Decommitments of constraint composition polynomial evaluations at positions queried by
    /// the verifier.
    pub constraint_queries: Queries,
    /// Trace and constraint polynomial evaluations at an out-of-domain point.
    pub ood_frame: OodFrame,
    /// Low-degree proof for a DEEP composition polynomial.
    pub fri_proof: FriProof,
    /// Proof-of-work nonce for query seed grinding.
    pub pow_nonce: u64,
}

impl Proof {
    /// Returns STARK protocol parameters used to generate this proof.
    pub fn options(&self) -> &ProofOptions {
        self.context.options()
    }

    /// Returns trace info for the computation described by this proof.
    pub fn trace_info(&self) -> &TraceInfo {
        self.context.trace_info()
    }

    /// Returns the size of the LDE domain for the computation described by this proof.
    pub fn lde_domain_size(&self) -> usize {
        self.context.lde_domain_size()
    }

    // SECURITY LEVEL
    // --------------------------------------------------------------------------------------------
    /// Returns security level of this proof (in bits) using conjectured security.
    ///
    /// This is the conjecture on the security of the Toy problem (Conjecture 1)
    /// in https://eprint.iacr.org/2021/582.
    pub fn conjectured_security<H: Hasher>(&self) -> ConjecturedSecurity {
        ConjecturedSecurity::compute(
            self.context.options(),
            self.context.num_modulus_bits(),
            H::COLLISION_RESISTANCE,
        )
    }
    /// Returns security level of this proof (in bits) using proven security.
    ///
    /// Usually, the number of queries needed for provable security is 2x - 3x higher than
    /// the number of queries needed for conjectured security at the same security level.
    pub fn proven_security<H: Hasher>(&self) -> ProvenSecurity {
        // we need to count the number of code words appearing in the protocol as the soundness
        // error, in the case of algebraic batching, depends on the this number.
        // we use the blowup factor as an upper bound on the number of constraint composition
        // polynomials.
        let num_trace_polys = self.context.trace_info().width();
        let num_constraint_composition_polys = self.options().blowup_factor();
        let total_number_of_polys = num_trace_polys + num_constraint_composition_polys;
        ProvenSecurity::compute(
            self.context.options(),
            self.context.num_modulus_bits(),
            self.trace_info().length(),
            H::COLLISION_RESISTANCE,
            total_number_of_polys,
        )
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this proof into a vector of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        Serializable::to_bytes(self)
    }

    /// Returns a STARK proof read from the specified `source`.
    ///
    /// # Errors
    /// Returns an error of a valid STARK proof could not be read from the specified `source`.
    pub fn from_bytes(source: &[u8]) -> Result<Self, DeserializationError> {
        Deserializable::read_from_bytes(source)
    }

    /// Creates a dummy `Proof` for use in tests.
    pub fn new_dummy() -> Self {
        use crypto::{hashers::Blake3_192 as DummyHasher, BatchMerkleProof};
        use math::fields::f64::BaseElement as DummyField;

        use crate::FieldExtension;

        Self {
            context: Context::new::<DummyField>(
                TraceInfo::new(1, 8),
                ProofOptions::new(1, 2, 2, FieldExtension::None, 8, 1, BatchingMethod::Linear),
            ),
            num_unique_queries: 0,
            commitments: Commitments::default(),
            trace_queries: Vec::new(),
            constraint_queries: Queries::new::<DummyHasher<DummyField>, DummyField, MerkleTree<_>>(
                BatchMerkleProof::<DummyHasher<DummyField>> { nodes: Vec::new(), depth: 0 },
                vec![vec![DummyField::ONE]],
            ),
            ood_frame: OodFrame::default(),
            fri_proof: FriProof::new_dummy(),
            pow_nonce: 0,
        }
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Proof {
    fn write_into<W: utils::ByteWriter>(&self, target: &mut W) {
        self.context.write_into(target);
        target.write_u8(self.num_unique_queries);
        self.commitments.write_into(target);
        target.write_many(&self.trace_queries);
        self.constraint_queries.write_into(target);
        self.ood_frame.write_into(target);
        self.fri_proof.write_into(target);
        self.pow_nonce.write_into(target);
    }
}

impl Deserializable for Proof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let context = Context::read_from(source)?;
        let num_unique_queries = source.read_u8()?;
        let commitments = Commitments::read_from(source)?;
        let num_trace_segments = context.trace_info().num_segments();
        let mut trace_queries = Vec::with_capacity(num_trace_segments);
        for _ in 0..num_trace_segments {
            trace_queries.push(Queries::read_from(source)?);
        }

        let proof = Proof {
            context,
            num_unique_queries,
            commitments,
            trace_queries,
            constraint_queries: Queries::read_from(source)?,
            ood_frame: OodFrame::read_from(source)?,
            fri_proof: FriProof::read_from(source)?,
            pow_nonce: source.read_u64()?,
        };
        Ok(proof)
    }
}
