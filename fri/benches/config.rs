#![allow(dead_code)]

use std::env;

// Default parameters for benchmarks. The default values of CIRCUIT_SIZES_E and NUM_POLY_E are overridden by
// their corresponding environment variables if set.
pub static CIRCUIT_SIZES_E: [usize; 1] = [15];
pub static NUM_POLY_E: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
pub static BLOWUP_FACTOR: usize = 4;
pub static FOLDING_FACTOR: usize = 2;
pub static NUM_QUERIES: usize = 282;
pub static MASTER_MAX_REMAINDER_DEGREE: usize = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriMode {
    FoldAndBatch,
    DistributedBatchedFri,
}

pub fn parse_fri_mode() -> FriMode {
    let mode = env::var("FRI_MODE").unwrap_or_else(
        |err| {
            eprintln!("[BENCH] FRI_MODE not set ({err}); defaulting to 'fold_and_batch'");
            "fold_and_batch".to_string()  // Use the default FRI_MODE "fold_and_batch" when the environment variable is not set
        });
    match mode.as_str() {
        "fold_and_batch" => FriMode::FoldAndBatch,
        "distributed_batched_fri" => FriMode::DistributedBatchedFri,
        _ => panic!("Invalid FRI_MODE: {}. Valid options are 'fold_and_batch' or 'distributed_batched_fri'.", mode),
    }
}

pub fn parse_circuit_size_e() -> Vec<usize> {
    let circuit_size_e = env::var("CIRCUIT_SIZE_E").unwrap_or_else(
        |err| {
            eprintln!("[BENCH] CIRCUIT_SIZE_E not set ({err}); defaulting to [15]");
            CIRCUIT_SIZES_E.iter().map(|&x| x.to_string()).collect::<Vec<String>>().join(",")  // Use the default CIRCUIT_SIZES_E when the environment variable is not set
        });
    circuit_size_e.split(',').map(|s| s.trim().parse().unwrap_or_else(|_| panic!("Invalid CIRCUIT_SIZE_E: {}. Use numbers separated by commas, e.g., 15, 20, 25", circuit_size_e))).collect()
}

pub fn parse_num_poly_e() -> Vec<usize> {
    let num_poly_e = env::var("NUM_POLY_E").unwrap_or_else(
        |err| {
            eprintln!("[BENCH] NUM_POLY_E not set ({err}); defaulting to [0, 1, 2, 3, 4, 5, 6, 7]");
            NUM_POLY_E.iter().map(|&x| x.to_string()).collect::<Vec<String>>().join(",")   // Use the default NUM_POLY_E when the environment variable is not set
        });
    num_poly_e.split(',').map(|s| s.trim().parse().unwrap_or_else(|_| panic!("Invalid NUM_POLY_E: {}. Use numbers separated by commas, e.g., 0, 1, 2, 3, 4, 5, 6, 7", num_poly_e))).collect()
}
