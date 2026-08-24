# FRIttata: a distributed polynomial commitment scheme based on FRI

This repository contains the implementation and benchmarks for the paper

> [FRIttata: A FRI-based Polynomial Commitment Scheme for Distributed Proof Generation](https://doi.org/10.62056/akjby76bm)
> Hua Xu, Mariana Gama, Emad Heydari Beni, Jiayi Kang.
> IACR Communications in Cryptology, 2(4), 2026.

The implementation is built on a fork of [facebook/winterfell](https://github.com/facebook/winterfell). Almost all of our additions live in the [`fri`](fri) crate. See [here](https://github.com/XuHuaXH/winterfell/commits/main/?author=XuHuaXH) for a full list of commits we made for FRIttata.

## What is implemented

The paper evaluates three methods of running FRI on polynomials that are distributed across many prover machines. All of the following three variants are implemented:

- **Parallel FRI.** Each worker runs plain FRI on its own local polynomial. There is no communication among the workers.
- **Distributed batched FRI.** Workers send their evaluation vectors to a master node, and the master node batches them into a single FRI instance. This method was proposed in [*On Distributed FRI-based Proof Generation*](https://hackmd.io/@nil-research/rJ_NVyiRA) by Alisa Cherniaeva.
- **Fold-and-Batch.** Each worker folds its polynomial locally for some number of rounds and proves that the folding was done correctly. The master node then batches the folded polynomials. The number of local folding rounds controls the tradeoff between communication cost and verifier cost.

## Where the implementation is

For each piece of code added by the FRIttata implementation, the following table shows the mapping between the file paths and their contents:

| Path | Contents |
| --- | --- |
| [`fri/src/batched_prover/`](fri/src/batched_prover), [`fri/src/batched_verifier/`](fri/src/batched_verifier), [`fri/src/batched_proof.rs`](fri/src/batched_proof.rs), [`fri/src/fold_and_batch_proof.rs`](fri/src/fold_and_batch_proof.rs), [`fri/src/fold_and_batch_prover/`](fri/src/fold_and_batch_prover), [`fri/src/fold_and_batch_verifier/`](fri/src/fold_and_batch_verifier) | Implementation of all three variants of FRIttata's distributed provers and verifiers. |
| [`fri/src/bin/`](fri/src/bin) | Binaries that run each protocol with a specified role (worker/master) as a separate process, used for measuring memory usage. |
| [`fri/benches/`](fri/benches) | Criterion benchmarks for the FRIttata implementation. |
| [`fri/scripts/`](fri/scripts) | Scripts for reproducing the paper's measurements and plotting (see below for instructions). |

## Building and testing

```bash
cargo build --release
cargo test -p winter-fri
```

## Benchmarks

Install the benchmarking and plotting dependencies:

```bash
cargo install cargo-criterion     # for benchmarking
pip install plotly                # for plotting
```

**Example Usage:** To run all benchmarks for the three distributed FRI methods, with circuit sizes $2^{15}, 2^{20}$ and $1, 2, 4, 8$ prover machines, run the following commands from the project root:

```bash
chmod +x fri/scripts/*.sh
fri/scripts/bench.sh 15,20 0,1,2,3
```

The first argument lists the circuit size exponents, the second the prover machine count exponents. This collects all timing, proof size, communication cost and memory measurements, then generates and saves the plots.

## Citing

If you would like to use this code in your research, please cite the paper:

```bibtex
@article{frittata,
      author = {Hua Xu and Mariana Gama and Emad Heydari Beni and Jiayi Kang},
      title = {{FRIttata}: A {FRI}-based Polynomial Commitment Scheme for Distributed Proof Generation},
      journal = {IACR Communications in Cryptology},
      volume = {2},
      number = {4},
      year = {2026},
      doi = {10.62056/akjby76bm}
}
```

## License

This project is [MIT licensed](./LICENSE).
