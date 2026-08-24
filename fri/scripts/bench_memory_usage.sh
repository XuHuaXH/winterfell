#!/usr/bin/env bash
# Runs memory usage benchmarks for all three distributed FRI variants.
# Stores the results in fri/benches/bench_data/ with filenames expected by plot.py.
#
# Usage: fri/scripts/bench_memory_usage.sh <circuit_size_e_list> <num_poly_e_list>
# e.g., fri/scripts/bench_memory_usage.sh 12 0,1,2
set -euo pipefail
cd "$(dirname "$0")/../.."   # Switch the current working directory to the root of the repository

CIRCUIT_SIZE_E=$1
NUM_POLY_E=$2
cargo build --release --package winter-fri

OUT_DIR=fri/benches/bench_data
mkdir -p "$OUT_DIR"

# Clears all output files.
rm -f "$OUT_DIR"/*_memory


# Detect which /usr/bin/time the system has by probing for the output line we want to parse.
# GNU time (-v) reports kilobytes; BSD/macOS time (-l) reports bytes. We normalize to kilobytes.
if [ ! -x /usr/bin/time ]; then
    echo "error: /usr/bin/time not found (on RHEL/Rocky: sudo dnf install time)" >&2
    exit 1
fi
if /usr/bin/time -v true 2>&1 | grep 'Maximum resident set size' > /dev/null; then
    TIME_CMD="/usr/bin/time -v"
    extract_kb() { grep 'Maximum resident set size' | awk '{print $NF}'; }
elif /usr/bin/time -l true 2>&1 | grep 'maximum resident set size' > /dev/null; then
    TIME_CMD="/usr/bin/time -l"
    extract_kb() { grep 'maximum resident set size' | awk '{printf "%d\n", $1 / 1024}'; } # converts to kB
else
    echo "error: unrecognized /usr/bin/time implementation on this system" >&2
    exit 1
fi

# Run all memory usage benchmarks for the specified range of circuit sizes and numbers of polynomials.
for circuit_size_e in ${CIRCUIT_SIZE_E//,/ }; do
    for num_poly_e in ${NUM_POLY_E//,/ }; do
        ./target/release/inputs_generator $circuit_size_e $num_poly_e parallel_fri | $TIME_CMD ./target/release/parallel_fri_prover $circuit_size_e $num_poly_e 2>&1 | extract_kb >> "$OUT_DIR"/parallel_fri_prover_memory

        ./target/release/inputs_generator $circuit_size_e $num_poly_e fold_and_batch_worker | $TIME_CMD ./target/release/distributed_fri_worker $circuit_size_e $num_poly_e fold_and_batch 2>&1 | extract_kb >> "$OUT_DIR"/fold_and_batch_worker_memory
        ./target/release/inputs_generator $circuit_size_e $num_poly_e fold_and_batch_master | $TIME_CMD ./target/release/distributed_fri_master $circuit_size_e $num_poly_e fold_and_batch 2>&1 | extract_kb >> "$OUT_DIR"/fold_and_batch_master_memory

        ./target/release/inputs_generator $circuit_size_e $num_poly_e distributed_batched_fri_worker | $TIME_CMD ./target/release/distributed_fri_worker $circuit_size_e $num_poly_e distributed_batched_fri 2>&1 | extract_kb >> "$OUT_DIR"/distributed_batched_fri_worker_memory
        ./target/release/inputs_generator $circuit_size_e $num_poly_e distributed_batched_fri_master | $TIME_CMD ./target/release/distributed_fri_master $circuit_size_e $num_poly_e distributed_batched_fri 2>&1 | extract_kb >> "$OUT_DIR"/distributed_batched_fri_master_memory
    done
done
