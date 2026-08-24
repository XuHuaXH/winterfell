#!/usr/bin/env bash
# Runs criterion benchmarks for:
#   (1) prover/verifier runtimes,
#   (2) proof sizes,
#   (3) communication costs
# for the three distributed FRI variants. Stores the results in
# fri/benches/bench_data/ with filenames expected by plot.py.
#
# Usage: fri/scripts/run_criterion_benches.sh <circuit_size_e_list> <num_poly_e_list>
# e.g., fri/scripts/run_criterion_benches.sh 12 0,1,2
set -euo pipefail
cd "$(dirname "$0")/../.."   # Switch the current working directory to the root of the repository

export CIRCUIT_SIZE_E=$1
export NUM_POLY_E=$2

if ! cargo criterion --version > /dev/null 2>&1; then
    echo "error: cargo-criterion is not installed; run: cargo install cargo-criterion" >&2
    exit 1
fi

OUT_DIR=fri/benches/bench_data
mkdir -p "$OUT_DIR"


# Clears the results from the last run
rm -f "$OUT_DIR"/*.json

# Fold-and-Batch and distributed batched FRI benchmarks. Both modes share the
# same three benchmarks. The benchmark code determines which mode is used by
# reading FRI_MODE from environmental variables. The output JSON is named
# according to the value of FRI_MODE. The benchmarks themselves write their
# comm cost and proof size files with mode-specific names into fri/benches/bench_data/.
for mode in fold_and_batch distributed_batched_fri; do
    for bench in distributed_worker distributed_master distributed_verify; do
        out_name="${mode}${bench#distributed}"
        echo "== Benchmarking $bench (FRI_MODE=$mode) =="
        FRI_MODE=$mode cargo criterion --package winter-fri --bench "$bench" \
            --message-format=json > "$OUT_DIR/${out_name}.json"
    done
done

# Parallel FRI benchmarks
for bench in parallel_fri_prover parallel_fri_verify; do
    echo "== Benchmarking $bench =="
    cargo criterion --package winter-fri --bench "$bench" \
        --message-format=json > "$OUT_DIR/${bench}.json"
done

echo "All benchmarks finished. See results in $OUT_DIR."
