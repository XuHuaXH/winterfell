
# clears the output files 
# > ./benches/bench_data/parallel_fri_prover_memory
# > ./benches/bench_data/fold_and_batch_worker_memory
> ./benches/bench_data/fold_and_batch_master_memory

for circuit_size_e in {24..24}; do
    for num_poly_e in {0..5}; do
        # /usr/bin/time -al cargo run --package winter-fri --bin parallel_fri_prover $circuit_size_e $num_poly_e 2>&1 | grep 'maximum resident set size' | awk '{print $1}' 
        # /usr/bin/time -al cargo run --package winter-fri --bin fold_and_batch_worker $circuit_size_e $num_poly_e 2>&1 | grep 'maximum resident set size' | awk '{print $1}' 
        /usr/bin/time -al cargo run --package winter-fri --bin fold_and_batch_master $circuit_size_e $num_poly_e 2>&1 | grep 'maximum resident set size' | awk '{print $1}' >> ./benches/bench_data/fold_and_batch_master_memory
    done
done
