use math::StarkField;

// FOLDING OPTIONS 
// ================================================================================================

/// FRI protocol config options for folding proof generation and verification. This struct is
/// used by the [crate::FoldingProver] and [crate::fold_and_batch_verifier::FoldingVerifier].
#[derive(Clone, PartialEq, Eq)]
pub struct FoldingOptions {
    folding_factor: usize,
    blowup_factor: usize,
    domain_size: usize,
    last_poly_max_degree: usize,
}

impl FoldingOptions {
    /// Returns a new [FoldingOptions] struct instantiated with the specified parameters.
    /// `last_poly_max_degree` is the maximum degree of the polynomial at the last FRI layer 
    /// of a [FoldingProver](crate::FoldingProver) using this [FoldingOptions].
    ///
    /// # Panics
    /// Panics if:
    /// - `blowup_factor` is not a power of two.
    /// - `folding_factor` is not 2, 4, 8, or 16.
    pub fn new(blowup_factor: usize, folding_factor: usize, domain_size: usize, last_poly_max_degree: usize) -> Self {
        // TODO: change panics to errors
        assert!(
            blowup_factor.is_power_of_two(),
            "blowup factor must be a power of two, but was {blowup_factor}"
        );
        assert!(
            folding_factor == 2
                || folding_factor == 4
                || folding_factor == 8
                || folding_factor == 16,
            "folding factor {folding_factor} is not supported"
        );
        FoldingOptions {
            folding_factor,
            blowup_factor,
            domain_size,
            last_poly_max_degree
        }
    }

    /// Returns the offset by which the evaluation domain is shifted.
    ///
    /// The domain is shifted by multiplying every element in the domain by this offset.
    ///
    /// Currently, the offset is hard-coded to be the primitive element in the field specified by
    /// type parameter `B`.
    pub fn domain_offset<B: StarkField>(&self) -> B {
        B::GENERATOR
    }

    /// Returns the factor by which the degree of a polynomial is reduced with each FRI layer.
    pub fn folding_factor(&self) -> usize {
        self.folding_factor
    }

    /// Returns maximum allowed degree of the polynomial in the last FRI layer of this worker.
    ///
    /// In combination with `folding_factor` and `domain_size`, this property defines how many
    /// FRI layers are needed for a FoldingProver using this FoldingOptions.
    pub fn last_poly_max_degree(&self) -> usize {
        self.last_poly_max_degree
    }

    /// Returns a blowup factor of the evaluation domain.
    ///
    /// Specifically, if the polynomial for which the FRI protocol is executed is of degree `d`
    /// where `d` is one less than a power of two, then the evaluation domain size will be
    /// equal to `(d + 1) * blowup_factor`.
    pub fn blowup_factor(&self) -> usize {
        self.blowup_factor
    }

    pub fn domain_size(&self) -> usize {
        self.domain_size
    }


    /// Computes the number of FRI layers a [FoldingProver](crate::FoldingProver) using this [FoldingOptions]
    /// should build.
    pub fn num_fri_layers(&self) -> usize {
        let mut result = 0;
        let max_last_eval_vector_size = (self.last_poly_max_degree + 1).next_power_of_two() * self.blowup_factor;
        let mut current_domain_size = self.domain_size;

        while current_domain_size > max_last_eval_vector_size {
            current_domain_size /= self.folding_factor;
            result += 1;
        }

        result + 1 // The number of FRI layers is the number of foldings needed + 1
    }
}
