#!/usr/bin/env bash
# Runs all benchmarks including
# (1) prover/verifier runtimes,
# (2) proof sizes,
# (3) communication costs,
# (4) prover memory usage
# for the three distributed FRI variants. Stores the results in fri/benches/bench_data/
# with filenames expected by plot.py. Finally, generates the graphs for all benchmarks.
#
# Usage: fri/scripts/bench.sh <circuit_size_e_list> <num_poly_e_list>
# e.g., fri/scripts/bench.sh 12 0,1,2
set -euo pipefail
cd "$(dirname "$0")/../.."   # Switch the current working directory to the root of the repository

export CIRCUIT_SIZE_E=$1
export NUM_POLY_E=$2

# Run memory usage benchmarks
fri/scripts/bench_memory_usage.sh $CIRCUIT_SIZE_E $NUM_POLY_E

# Run criterion benchmarks
fri/scripts/run_criterion_benches.sh $CIRCUIT_SIZE_E $NUM_POLY_E

# Plot the results
python3 fri/scripts/plot.py
