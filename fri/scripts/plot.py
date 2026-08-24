import json
import os
import shutil
import sys

import plotly.graph_objects as go

BENCH_DATA_DIR = "fri/benches/bench_data/"


def parse_env_var_as_int_list(name, default):
    """
    Parse an environment variable as a list of integers.
    If the variable is not set, return the default value.

    name: the name of the environment variable
    default: the default value to return if the variable is not set
    """
    value = os.environ.get(name)
    if value is None:
        print(f"[PLOTTING] environment variable {name} not set; defaulting to {default}")
        return default
    try:
        return [int(s.strip()) for s in value.split(",")]
    except ValueError:
        sys.exit(f"Invalid {name}: {value}. Use numbers separated by commas, e.g., 15,20,25")


CIRCUIT_SIZES_E = parse_env_var_as_int_list("CIRCUIT_SIZE_E", [15])
NUM_POLY_E = parse_env_var_as_int_list("NUM_POLY_E", [0, 1, 2, 3, 4, 5, 6, 7])

# Directory where the graphs are saved as HTML files.
GRAPHS_DIR = "fri/benches/bench_data/graphs/"


def output_figure(fig, name):
    """
    Save the figure as an HTML file under GRAPHS_DIR.
    """
    os.makedirs(GRAPHS_DIR, exist_ok=True)
    filename = name.lower().replace(" ", "_").replace("-", "_") + ".html"
    path = os.path.join(GRAPHS_DIR, filename)
    fig.write_html(path)
    print(f"[PLOTTING] saved {path}")


def plot_worker_prover_time(running_times, protocol):
    fig = go.Figure()
    fig.update_layout(
        title=f"Worker prover time for {protocol}",
        legend_title_text="Instance size",
        xaxis_type="log",  # Set x-axis to log scale
        yaxis_type="log",  # Set y-axis to log scale
    )
    fig.update_xaxes(title_text="Number of machines")
    fig.update_yaxes(title_text="Prover time in seconds")

    for i, instance_size_e in enumerate(CIRCUIT_SIZES_E):
        x = []
        y = []
        for j, num_machines_e in enumerate(NUM_POLY_E):
            x.append(2**num_machines_e)
            y.append(running_times[i][j])
        fig.add_trace(go.Scatter(x=x, y=y, mode="markers+lines", name=f"2^{instance_size_e}"))

    output_figure(fig, f"worker_prover_time_{protocol}")


def plot_master_prover_time(running_times, protocol):
    fig = go.Figure()
    fig.update_layout(
        title=f"Master prover time for {protocol}",
        legend_title_text="Instance size",
        xaxis_type="log",  # Set x-axis to log scale
        yaxis_type="log",  # Set y-axis to log scale
    )
    fig.update_xaxes(title_text="Number of machines")
    fig.update_yaxes(title_text="Prover time in seconds")

    for i, instance_size_e in enumerate(CIRCUIT_SIZES_E):
        x = []
        y = []
        for j, num_machines_e in enumerate(NUM_POLY_E):
            x.append(2**num_machines_e)
            y.append(running_times[i][j])
        fig.add_trace(go.Scatter(x=x, y=y, mode="markers+lines", name=f"2^{instance_size_e}"))

    output_figure(fig, f"master_prover_time_{protocol}")


def plot_verification_time(running_times, protocol):
    fig = go.Figure()
    fig.update_layout(
        title=f"Verification time for {protocol}",
        legend_title_text="Instance size",
        xaxis_type="log",  # Set x-axis to log scale
        yaxis_type="log",  # Set y-axis to log scale
    )
    fig.update_xaxes(title_text="Number of machines")
    fig.update_yaxes(title_text="Verification time in seconds")

    for i, instance_size_e in enumerate(CIRCUIT_SIZES_E):
        x = []
        y = []
        for j, num_machines_e in enumerate(NUM_POLY_E):
            x.append(2**num_machines_e)
            y.append(running_times[i][j])
        fig.add_trace(go.Scatter(x=x, y=y, mode="markers+lines", name=f"2^{instance_size_e}"))

    output_figure(fig, f"verification_time_{protocol}")


def read_runtime_data(filepath):
    data = []
    try:
        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    data.append(json.loads(line))

        # discard the group info
        data = data[:-1]
    except FileNotFoundError:
        sys.exit(f"{filepath} not found. Run the benchmarks first.")
    except json.JSONDecodeError as e:
        sys.exit(f"Error decoding JSON in {filepath}: {e}")

    expected = len(CIRCUIT_SIZES_E) * len(NUM_POLY_E)
    if len(data) != expected:
        sys.exit(
            f"{filepath}: found {len(data)} entries, expected {expected} (CIRCUIT_SIZE_E x NUM_POLY_E). "
            "Interrupted benchmark run, or mismatched environment variables?"
        )
    return data


# Each entry in data is a json object describing a benchmark
def process_runtime_data(data):
    i = 0
    running_times = []
    for _ in CIRCUIT_SIZES_E:
        runtime = []
        for _ in NUM_POLY_E:
            prover_time_in_ns = float(data[i]["typical"]["estimate"])
            prover_time_in_seconds = prover_time_in_ns / 10**9
            runtime.append(prover_time_in_seconds)
            i += 1
        running_times.append(runtime)
    return running_times


def read_and_process_proof_size_data(filepath):
    data = []
    try:
        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    size = int(line)
                    data.append(size)
    except FileNotFoundError:
        sys.exit(f"{filepath} not found. Run the benchmarks first.")

    expected = len(CIRCUIT_SIZES_E) * len(NUM_POLY_E)
    if len(data) != expected:
        sys.exit(
            f"{filepath}: found {len(data)} values, expected {expected} (CIRCUIT_SIZE_E x NUM_POLY_E). "
            "Interrupted benchmark run, or mismatched environment variables?"
        )

    proof_sizes = []
    i = 0
    for _ in CIRCUIT_SIZES_E:
        size_vec = []
        for _ in NUM_POLY_E:
            proof_size_in_bytes = data[i]
            proof_size_in_MB = proof_size_in_bytes / 10**6
            size_vec.append(proof_size_in_MB)
            i += 1
        proof_sizes.append(size_vec)
    return proof_sizes


def plot_proof_size(proof_sizes, protocol):
    fig = go.Figure()
    fig.update_layout(
        title=f"Proof Size for {protocol}",
        legend_title_text="Instance size",
        xaxis_type="log",  # Set x-axis to log scale
        yaxis_type="log",  # Set y-axis to log scale
    )
    fig.update_xaxes(title_text="Number of machines")
    fig.update_yaxes(title_text="Proof Size in MB")

    for i, instance_size_e in enumerate(CIRCUIT_SIZES_E):
        x = []
        y = []
        for j, num_machines_e in enumerate(NUM_POLY_E):
            x.append(2**num_machines_e)
            y.append(proof_sizes[i][j])
        fig.add_trace(go.Scatter(x=x, y=y, mode="markers+lines", name=f"2^{instance_size_e}"))

    output_figure(fig, f"proof_size_{protocol}")


def read_and_process_comm_cost_data(filepath):
    data = []
    try:
        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    size = int(line)
                    data.append(size)
    except FileNotFoundError:
        sys.exit(f"{filepath} not found. Run the benchmarks first.")

    expected = len(CIRCUIT_SIZES_E) * len(NUM_POLY_E)
    if len(data) != expected:
        sys.exit(
            f"{filepath}: found {len(data)} values, expected {expected} (CIRCUIT_SIZE_E x NUM_POLY_E). "
            "Interrupted benchmark run, or mismatched environment variables?"
        )

    comm_costs = []
    i = 0
    for _ in CIRCUIT_SIZES_E:
        cost_vec = []
        for _ in NUM_POLY_E:
            comm_cost_in_bytes = data[i]
            comm_cost_in_MB = comm_cost_in_bytes / 10**6
            cost_vec.append(comm_cost_in_MB)
            i += 1
        comm_costs.append(cost_vec)

    return comm_costs


def plot_comm_cost(comm_costs, protocol):
    fig = go.Figure()
    fig.update_layout(
        title=f"Communication Costs for {protocol}",
        legend_title_text="Instance size",
        xaxis_type="log",  # Set x-axis to log scale
        yaxis_type="log",  # Set y-axis to log scale
    )
    fig.update_xaxes(title_text="Number of machines")
    fig.update_yaxes(title_text="Comm. Cost in MB")

    for i, instance_size_e in enumerate(CIRCUIT_SIZES_E):
        x = []
        y = []
        for j, num_machines_e in enumerate(NUM_POLY_E):
            if num_machines_e > 0:
                x.append(2**num_machines_e)
                y.append(comm_costs[i][j])
        fig.add_trace(go.Scatter(x=x, y=y, mode="markers+lines", name=f"2^{instance_size_e}"))

    output_figure(fig, f"comm_cost_{protocol}")


def read_and_process_memory_usage(filepath):
    data = []
    try:
        with open(filepath, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    data.append(int(line))
    except FileNotFoundError:
        sys.exit(f"{filepath} not found. Run the benchmarks first.")

    expected = len(CIRCUIT_SIZES_E) * len(NUM_POLY_E)
    if len(data) != expected:
        sys.exit(
            f"{filepath}: found {len(data)} values, expected {expected} (CIRCUIT_SIZE_E x NUM_POLY_E). "
            "Interrupted benchmark run, or mismatched environment variables?"
        )

    memory_usage = []
    i = 0
    for _ in CIRCUIT_SIZES_E:
        instance_usage = []
        for _ in NUM_POLY_E:
            memory_usage_in_kB = data[i]
            memory_usage_in_GB = memory_usage_in_kB / 10**6
            instance_usage.append(memory_usage_in_GB)
            i += 1
        memory_usage.append(instance_usage)

    return memory_usage


def plot_memory_usage(memory_usage, protocol_and_node_type):
    fig = go.Figure()
    fig.update_layout(
        title=f"Memory Usage for {protocol_and_node_type}",
        legend_title_text="Instance size",
        xaxis_type="log",  # Set x-axis to log scale
        yaxis_type="log",  # Set y-axis to log scale
    )
    fig.update_xaxes(title_text="Number of machines")
    fig.update_yaxes(title_text="Memory Usage in GB")

    for i, instance_size_e in enumerate(CIRCUIT_SIZES_E):
        x = []
        y = []
        for j, num_machines_e in enumerate(NUM_POLY_E):
            x.append(2**num_machines_e)
            y.append(memory_usage[i][j])
        fig.add_trace(go.Scatter(x=x, y=y, mode="markers+lines", name=f"2^{instance_size_e}"))

    output_figure(fig, f"memory_usage_{protocol_and_node_type}")


def show_parallel_fri_worker_time():
    data = read_runtime_data(f"{BENCH_DATA_DIR}parallel_fri_prover.json")
    running_times = process_runtime_data(data)
    plot_worker_prover_time(running_times, "Parallel FRI")


def show_fold_and_batch_worker_time():
    data = read_runtime_data(f"{BENCH_DATA_DIR}fold_and_batch_worker.json")
    running_times = process_runtime_data(data)
    plot_worker_prover_time(running_times, "Fold-and-Batch")


def show_fold_and_batch_master_time():
    worker_data = read_runtime_data(f"{BENCH_DATA_DIR}fold_and_batch_worker.json")
    master_data = read_runtime_data(f"{BENCH_DATA_DIR}fold_and_batch_master.json")
    worker_running_times = process_runtime_data(worker_data)
    master_running_times = process_runtime_data(master_data)
    for i in range(len(CIRCUIT_SIZES_E)):
        for j in range(len(NUM_POLY_E)):
            master_running_times[i][j] += worker_running_times[i][j]
    plot_master_prover_time(master_running_times, "Fold-and-Batch")


def show_distributed_batched_fri_worker_time():
    data = read_runtime_data(f"{BENCH_DATA_DIR}distributed_batched_fri_worker.json")
    running_times = process_runtime_data(data)
    plot_worker_prover_time(running_times, "Distributed Batched FRI")


def show_distributed_batched_fri_master_time():
    worker_data = read_runtime_data(f"{BENCH_DATA_DIR}distributed_batched_fri_worker.json")
    master_data = read_runtime_data(f"{BENCH_DATA_DIR}distributed_batched_fri_master.json")
    worker_running_times = process_runtime_data(worker_data)
    master_running_times = process_runtime_data(master_data)
    for i in range(len(CIRCUIT_SIZES_E)):
        for j in range(len(NUM_POLY_E)):
            master_running_times[i][j] += worker_running_times[i][j]
    plot_master_prover_time(master_running_times, "Distributed Batched FRI")


def show_fold_and_batch_comm_cost():
    filename = f"{BENCH_DATA_DIR}fold_and_batch_comm_cost"
    comm_costs = read_and_process_comm_cost_data(filename)
    plot_comm_cost(comm_costs, "Fold-and-Batch")


def show_distributed_batched_fri_comm_cost():
    filename = f"{BENCH_DATA_DIR}distributed_batched_fri_comm_cost"
    comm_costs = read_and_process_comm_cost_data(filename)
    plot_comm_cost(comm_costs, "Distributed Batched FRI")


def show_fold_and_batch_verification_time():
    data = read_runtime_data(f"{BENCH_DATA_DIR}fold_and_batch_verify.json")
    running_times = process_runtime_data(data)
    plot_verification_time(running_times, "Fold-and-Batch")


def show_parallel_fri_verification_time():
    data = read_runtime_data(f"{BENCH_DATA_DIR}parallel_fri_verify.json")
    running_times = process_runtime_data(data)
    plot_verification_time(running_times, "Parallel FRI")


def show_distributed_batched_fri_verification_time():
    data = read_runtime_data(f"{BENCH_DATA_DIR}distributed_batched_fri_verify.json")
    running_times = process_runtime_data(data)
    plot_verification_time(running_times, "Distributed Batched FRI")


def show_fold_and_batch_proof_size():
    filename = f"{BENCH_DATA_DIR}fold_and_batch_proof_size"
    proof_sizes = read_and_process_proof_size_data(filename)
    plot_proof_size(proof_sizes, "Fold-and-Batch")


def show_distributed_batched_fri_proof_size():
    filename = f"{BENCH_DATA_DIR}distributed_batched_fri_proof_size"
    proof_sizes = read_and_process_proof_size_data(filename)
    plot_proof_size(proof_sizes, "Distributed Batched FRI")


def show_parallel_fri_proof_size():
    filename = f"{BENCH_DATA_DIR}parallel_fri_proof_size"
    proof_sizes = read_and_process_proof_size_data(filename)
    plot_proof_size(proof_sizes, "Parallel FRI")


def show_distributed_batched_fri_worker_memory_usage():
    filename = f"{BENCH_DATA_DIR}distributed_batched_fri_worker_memory"
    memory_usage = read_and_process_memory_usage(filename)
    plot_memory_usage(memory_usage, "Distributed Batched FRI worker")


def show_distributed_batched_fri_master_memory_usage():
    worker_filename = f"{BENCH_DATA_DIR}distributed_batched_fri_worker_memory"
    master_filename = f"{BENCH_DATA_DIR}distributed_batched_fri_master_memory"
    worker_memory_usage = read_and_process_memory_usage(worker_filename)
    master_memory_usage = read_and_process_memory_usage(master_filename)
    for i in range(len(CIRCUIT_SIZES_E)):
        for j in range(len(NUM_POLY_E)):
            master_memory_usage[i][j] = max(master_memory_usage[i][j], worker_memory_usage[i][j])
    plot_memory_usage(master_memory_usage, "Distributed Batched FRI master")


def show_fold_and_batch_worker_memory_usage():
    filename = f"{BENCH_DATA_DIR}fold_and_batch_worker_memory"
    memory_usage = read_and_process_memory_usage(filename)
    plot_memory_usage(memory_usage, "Fold-and-Batch worker")


def show_fold_and_batch_master_memory_usage():
    worker_filename = f"{BENCH_DATA_DIR}fold_and_batch_worker_memory"
    master_filename = f"{BENCH_DATA_DIR}fold_and_batch_master_memory"
    worker_memory_usage = read_and_process_memory_usage(worker_filename)
    master_memory_usage = read_and_process_memory_usage(master_filename)
    for i in range(len(CIRCUIT_SIZES_E)):
        for j in range(len(NUM_POLY_E)):
            master_memory_usage[i][j] = max(master_memory_usage[i][j], worker_memory_usage[i][j])
    plot_memory_usage(master_memory_usage, "Fold-and-Batch master")


def show_parallel_fri_memory_usage():
    filename = f"{BENCH_DATA_DIR}parallel_fri_prover_memory"
    memory_usage = read_and_process_memory_usage(filename)
    plot_memory_usage(memory_usage, "Parallel FRI")


if __name__ == "__main__":
    print("Generating plots for the following circuit sizes (2^e):", CIRCUIT_SIZES_E)
    print("Generating plots for the following number of machines (2^e):", NUM_POLY_E)

    # Switch the current working directory to the root of the repository.
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    # Clear the graphs from previous runs.
    shutil.rmtree(GRAPHS_DIR, ignore_errors=True)

    # Prover time
    show_distributed_batched_fri_worker_time()
    show_distributed_batched_fri_master_time()
    show_fold_and_batch_worker_time()
    show_fold_and_batch_master_time()
    show_parallel_fri_worker_time()

    # Communication cost
    show_distributed_batched_fri_comm_cost()
    show_fold_and_batch_comm_cost()

    # Verification time
    show_distributed_batched_fri_verification_time()
    show_fold_and_batch_verification_time()
    show_parallel_fri_verification_time()

    # Proof size
    show_distributed_batched_fri_proof_size()
    show_fold_and_batch_proof_size()
    show_parallel_fri_proof_size()

    # Memory Usage
    show_distributed_batched_fri_worker_memory_usage()
    show_distributed_batched_fri_master_memory_usage()
    show_fold_and_batch_worker_memory_usage()
    show_fold_and_batch_master_memory_usage()
    show_parallel_fri_memory_usage()
