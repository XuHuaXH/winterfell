use math::{fft, fields::{f128::BaseElement, QuadExtension}, FieldElement};
use rand_utils::rand_vector;



// HELPER FUNCTIONS
// ================================================================================================

pub fn build_evaluations(domain_size: usize, lde_blowup: usize) -> Vec<QuadExtension<BaseElement>> {
    let mut p: Vec<QuadExtension<BaseElement>> = rand_vector(domain_size / lde_blowup);
    p.resize(domain_size, <QuadExtension<BaseElement>>::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}


pub fn build_evaluations_from_random_poly(degree_bound: usize, lde_blowup: usize) -> Vec<QuadExtension<BaseElement>> {
    // Generates a random vector which represents the coefficients of a random polynomial 
    // with degree < degree_bound
    let mut p = rand_vector::<QuadExtension<BaseElement>>(degree_bound);

    // allocating space for the evaluation form of the polynomial p
    let domain_size = degree_bound * lde_blowup;
    p.resize(domain_size, <QuadExtension<BaseElement>>::ZERO);

    // transforms the polynomial from coefficient form to evaluation form in place
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);

    p
}