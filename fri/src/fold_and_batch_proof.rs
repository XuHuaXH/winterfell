use alloc::{string::ToString, vec::Vec};
use crypto::ElementHasher;
use math::FieldElement;
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader};
use crate::{FriProof, FriProofLayer, VerifierError};

#[derive(Clone)]
pub struct FoldingProof
{
    folding_proof: Vec<FriProofLayer>
}

impl FoldingProof
{
    pub fn new(folding_proof: Vec<FriProofLayer>) -> Self {
        assert!(!folding_proof.is_empty(), "The folding proof must contain at least one FriProofLayer");
        FoldingProof { folding_proof }
    }

    pub fn folding_proof(&self) -> &Vec<FriProofLayer> {
        &self.folding_proof
    }

    pub fn batching_proof(&self) -> &FriProofLayer {
        self.folding_proof.last().unwrap()
    }

    // Returns the number of bytes in this folding proof.
    pub fn size(&self) -> usize {
        // + 1 for the length of the folding_proof vector
        self.folding_proof.iter().fold(1, |acc, layer| acc + layer.size())
    }
}

pub struct FoldAndBatchProof<H>
where 
    H: ElementHasher,
{
    folding_proofs: Vec<FoldingProof>,
    fri_proof: FriProof,
    worker_evaluations: Vec<Vec<u8>>,
    master_evaluations: Vec<u8>,
    worker_layer_commitments: Vec<Vec<H::Digest>>,
    master_layer_commitments: Vec<H::Digest>,
} 

impl<H> FoldAndBatchProof<H>
where
    H: ElementHasher,
{
    pub(crate) fn new<E: FieldElement>(
        folding_proofs: Vec<FoldingProof>,
        fri_proof: FriProof,
        worker_evaluations: Vec<Vec<E>>,
        master_evaluations: Vec<E>,
        worker_layer_commitments: Vec<Vec<H::Digest>>,
        master_layer_commitments: Vec<H::Digest>,
    ) -> Self {
        assert_eq!(folding_proofs.len(), worker_layer_commitments.len(), "The number of folding proofs should match the number of layer commitment vectors");
        
        // Convert master evaluations into a vector of bytes
        let mut master_evaluations_bytes = Vec::with_capacity(E::ELEMENT_BYTES * master_evaluations.len());
        master_evaluations_bytes.write_many(master_evaluations);

        // Convert worker evaluations into a vector of vector of bytes
        let worker_evaluations = worker_evaluations.iter().map(|eval_vector| {
            let mut worker_evaluation_bytes = Vec::with_capacity(E::ELEMENT_BYTES * eval_vector.len());
            worker_evaluation_bytes.write_many(eval_vector);
            worker_evaluation_bytes
        }).collect();

        FoldAndBatchProof {
            folding_proofs,
            fri_proof,
            worker_evaluations,
            master_evaluations: master_evaluations_bytes,
            worker_layer_commitments,
            master_layer_commitments,    
        }
    }

    pub(crate) fn folding_proofs(&self) -> &Vec<FoldingProof> {
        &self.folding_proofs
    }

    pub(crate) fn fri_proof(&self) -> &FriProof {
        &self.fri_proof
    }

    pub(crate) fn master_layer_commitments(&self) -> &Vec<H::Digest> {
        &self.master_layer_commitments
    }


    pub(crate) fn worker_layer_commitments(&self) -> &Vec<Vec<H::Digest>> {
        &self.worker_layer_commitments
    }


    /// Returns the number of the evaluation values in this proof.
    ///
    /// The number of evaluation values is computed by dividing the number of bytes 
    /// in `evaluations` by the size of the field element specified by `E` type parameter.
    pub fn num_master_evaluations<E: FieldElement>(&self) -> usize {
        self.master_evaluations.len() / E::ELEMENT_BYTES
    }

    // Returns the number of bytes in this proof.
    pub fn size(&self) -> usize {

        // +4 for the length of the folding_proofs vector
        let folding_proofs_size = self.folding_proofs.iter().fold(4, |acc, folding_proof| acc + folding_proof.size());
    
        let fri_proof_size = self.fri_proof.size();

        // +4 for the length of the worker_evaluations vector.
        // +2 for the length of each vector in worker_evaluations.
        let worker_evaluations_size = self.worker_evaluations.iter().fold(4, |acc, byte_vec| acc + byte_vec.len() + 2);

        // +2 for the length of the master_evaluations vector.
        let master_evaluations_size = self.master_evaluations.len() + 2;

        // +4 for the length of worker_layer_commitments
        // +2 for the length of each vector in worker_layer_commitments
        let worker_layer_commitments_size = self.worker_layer_commitments.iter().fold(4, |acc, commitment_vec| {
            if commitment_vec.len() == 0 {
                panic!("The length of a worker layer commitments vector is 0");
            }
            let commitment_size = commitment_vec[0].get_size_hint();
            if commitment_size == 0 {
                panic!("The size of a worker layer commitment is 0");
            }
            acc + commitment_size * commitment_vec.len() + 2
            }
        );

        // +2 for the length of master_layer_commitments
        if self.master_layer_commitments().len() == 0 {
            panic!("The length of master layer commitments vector is 0");
        }
        let commitment_size = self.master_layer_commitments()[0].get_size_hint();
        if commitment_size == 0 {
            panic!("The size of a master layer commitment is 0");
        }
        let master_layer_commitments_size = self.master_layer_commitments().len() * commitment_size + 2;

        folding_proofs_size + 
        fri_proof_size + 
        worker_evaluations_size +
        master_evaluations_size +
        worker_layer_commitments_size + 
        master_layer_commitments_size
    }


    // PARSING
    // --------------------------------------------------------------------------------------------

    /// Returns a vector of evaluations at the queried positions parsed from this proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// * Any of the remainder values could not be parsed correctly.
    /// * Not all bytes have been consumed while parsing remainder values.
    pub fn parse_master_evaluations<E: FieldElement>(&self) -> Result<Vec<E>, VerifierError> {
        let num_elements = self.num_master_evaluations::<E>();
        
        let mut reader = SliceReader::new(&self.master_evaluations);
        let master_evaluations = reader.read_many(num_elements).map_err(|err| {
            VerifierError::InvalidValueInEvaluationsVector(err.to_string())
        })?;
        if reader.has_more_bytes() {
            return Err(VerifierError::UnconsumedBytesInEvaluationsVector);
        }
        Ok(master_evaluations)
    }


    pub fn parse_worker_evaluations<E: FieldElement>(&self) -> Result<Vec<Vec<E>>, VerifierError> {
        let mut worker_evaluations = Vec::with_capacity(self.folding_proofs.len());
        
        for byte_vec in self.worker_evaluations.iter() {
            let mut reader = SliceReader::new(byte_vec);
            let num_elements = byte_vec.len() / E::ELEMENT_BYTES;
            let eval_vec : Vec<E> = reader.read_many(num_elements).map_err(|err| {
                VerifierError::InvalidValueInEvaluationsVector(err.to_string())
            })?;
            if reader.has_more_bytes() {
                return Err(VerifierError::UnconsumedBytesInEvaluationsVector);
            }
            worker_evaluations.push(eval_vec);
        }
        Ok(worker_evaluations)
    }
}

// SERIALIZATION / DESERIALIZATION
// ------------------------------------------------------------------------------------------------

impl Serializable for FoldingProof {
    /// Serializes this folding proof and writes the resulting bytes to the specified `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write the number of layers into the target
        target.write_u8(self.folding_proof.len() as u8);

        // write each layer into the target
        for layer in self.folding_proof.iter() {
            layer.write_into(target);
        }
    }
}

impl Deserializable for FoldingProof {
    /// Reads a folding proof from the `source` and returns it.
    ///
    /// # Errors
    /// Returns an error if a valid [FriProofLayer] could not be read from the specified source.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {

        // read the number of layers in this FoldingProof
        let num_layers = source.read_u8()?;
        if num_layers == 0 {
            return Err(DeserializationError::InvalidValue(
                "a FoldingProof must contain at least one FriProofLayer".to_string(),
            ));
        }

        // read the layers
        let mut folding_proof = Vec::with_capacity(num_layers.into());
        for _ in 0..num_layers {
            let layer = FriProofLayer::read_from(source)?;
            folding_proof.push(layer);
        }

        Ok(FoldingProof { folding_proof })
    }
}

impl<H> Serializable for FoldAndBatchProof<H>
where 
    H: ElementHasher
{
    /// Serializes `self` and writes the resulting bytes into the `target` writer.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {

        // write folding proofs
        target.write_u32(self.folding_proofs.len() as u32);
        for folding_proof in self.folding_proofs.iter() {
            folding_proof.write_into(target);
        }

        // write FRI proof
        self.fri_proof.write_into(target);

        // write worker evaluations
        target.write_u32(self.worker_evaluations.len() as u32);
        for eval_vec in self.worker_evaluations.iter() {
            target.write_u16(eval_vec.len() as u16);
            target.write_bytes(&eval_vec);
        }

        // write master evaluations
        target.write_u16(self.master_evaluations.len() as u16);
        target.write_bytes(&self.master_evaluations);

        // write worker layer commitments
        target.write_u32(self.worker_layer_commitments.len() as u32);
        for layer_commitments in self.worker_layer_commitments.iter() {
            target.write_u8(layer_commitments.len() as u8);
            for commitment in layer_commitments.iter() {
                commitment.write_into(target);
            }
        }

        // write master layer commitments
        target.write_u8(self.master_layer_commitments.len() as u8);
        for commitment in self.master_layer_commitments.iter() {
            commitment.write_into(target);
        }
    }
}

impl<H> Deserializable for FoldAndBatchProof<H>
where 
    H: ElementHasher
{
    /// Reads a Fold-and-Batch proof from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error if a valid proof could not be read from the source.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {

        // read folding proofs
        let num_layers = source.read_u32()? as usize;
        let folding_proofs = source.read_many(num_layers)?;
        
        // read FRI proof
        let fri_proof = FriProof::read_from(source)?;

        // read worker evaluations
        let num_workers = source.read_u32()? as usize;
        let mut worker_evaluations = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let num_evaluations_bytes = source.read_u16()? as usize;
            let eval_vec = source.read_vec(num_evaluations_bytes)?;
            worker_evaluations.push(eval_vec);
        }

        // read master evaluations
        let num_evaluations_bytes = source.read_u16()? as usize;
        let master_evaluations = source.read_vec(num_evaluations_bytes)?;


        // read worker layer commitments
        let num_workers = source.read_u32()? as usize;
        let mut worker_layer_commitments = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let num_commitments = source.read_u8()? as usize;
            let layer_commitments = source.read_many(num_commitments)?;
            worker_layer_commitments.push(layer_commitments);
        }

        // read master layer commitments
        let num_commitments = source.read_u8()? as usize;
        let master_layer_commitments = source.read_many(num_commitments)?;
        

        Ok(FoldAndBatchProof { 
            folding_proofs,
            fri_proof, 
            worker_evaluations,
            master_evaluations,
            worker_layer_commitments,
            master_layer_commitments
         })

    }
}

