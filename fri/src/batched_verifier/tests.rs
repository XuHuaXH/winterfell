use alloc::vec::Vec;
use math::fields::f128::BaseElement;

use super::extract_evaluations;


#[test]
fn test_extract_evaluations() {
    let domain_size = 8;
    let folding_factor = 2;

    // The original full evaluation vector is: [8, 7, 6, 5, 4, 3, 2, 1]
    // The evaluations at the query_positions are: [8, 6, 4, 3, 2]
    let query_positions = Vec::from([0, 2, 4, 5, 6 ]);

    // The queried_values vector is obtained as follows:
    // 1. Start with the full evaluations vector: [8, 7, 6, 5, 4, 3, 2, 1].
    // 2. Transform it by grouping the elements that should be hashed into 
    // a single Merkle tree leaf together. Since the folding factor is 2,
    // the transformed vector is: [[8, 4], [7, 3], [6, 2], [5, 1]].
    // 3. Obtain the corresponding folded positions from query_positions. This 
    // step takes all the positions in query_positions, modulo them by the folded
    // domain size which is domain_size / folding_factor = 8 / 2 = 4, then remove 
    // the duplicates. The folded positions vector is: [0, 2, 1].
    // 4. The queried_values vector is obtained by collecting entries in the 
    // transformed evaluation vector [[8, 4], [7, 3], [6, 2], [5, 1]] at the 
    // folded positions which gives us [[8, 4], [6, 2], [7, 3]], and flatten it 
    // to get [8, 4, 6, 2, 7, 3].
    // Note: In this example, there is a single evaluation vector. In general,
    // there are multiple evaluations vectors and the above procedure is applied
    // to each one of them.
    let mut queried_values = Vec::new();
    queried_values.push(Vec::from([8, 4, 6, 2, 7, 3].map(BaseElement::new)));

    let expected_extracted_evaluations = Vec::from([8, 6, 4, 3, 2].map(BaseElement::new));
    let actual_extracted_evaluations = extract_evaluations(&query_positions, &queried_values, domain_size, folding_factor);
    assert_eq!(
        expected_extracted_evaluations, 
        actual_extracted_evaluations[0],
        "The extracted evaluations vector is different from expected"
    )
}