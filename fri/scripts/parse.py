import json
import plotly.graph_objects as go

INSTANCE_SIZE_E_LOWER_BOUND = 21
INSTANCE_SIZE_E_UPPER_BOUND = 26
INSTANCE_SIZE_E_RANGE = range(INSTANCE_SIZE_E_LOWER_BOUND, INSTANCE_SIZE_E_UPPER_BOUND)

NUM_MACHINES_E_LOWER_BOUND = 0
NUM_MACHINES_E_UPPER_BOUND = 8
NUM_MACHINES_E_RANGE = range(NUM_MACHINES_E_LOWER_BOUND, NUM_MACHINES_E_UPPER_BOUND)


def plot_worker_prover_time(running_times, protocol):
        fig = go.Figure()
        fig.update_layout(
            title=f"Worker prover time for {protocol}", 
            legend_title_text = "Instance size",
            xaxis_type = "log",  # Set x-axis to log scale
            yaxis_type = "log",  # Set y-axis to log scale
        )
        fig.update_xaxes(title_text="Number of machines")
        fig.update_yaxes(title_text="Prover time in seconds")

        for instance_size_e in INSTANCE_SIZE_E_RANGE:
            x = []
            y = []
            for num_machines_e in NUM_MACHINES_E_RANGE:
                x.append(2 ** num_machines_e)
                y.append(running_times[instance_size_e - INSTANCE_SIZE_E_LOWER_BOUND][num_machines_e - NUM_MACHINES_E_LOWER_BOUND])
            fig.add_trace(go.Scatter(x=x, y=y, mode='markers+lines', name=f'2^{instance_size_e}' ))

        fig.show(config={'scrollZoom': True})


def plot_master_prover_time(running_times, protocol):
        fig = go.Figure()
        fig.update_layout(
            title=f"Master prover time for {protocol}", 
            legend_title_text = "Instance size",
            xaxis_type = "log",  # Set x-axis to log scale
            yaxis_type = "log",  # Set y-axis to log scale
        )
        fig.update_xaxes(title_text="Number of machines")
        fig.update_yaxes(title_text="Prover time in seconds")

        for instance_size_e in INSTANCE_SIZE_E_RANGE:
            x = []
            y = []
            for num_machines_e in NUM_MACHINES_E_RANGE:
                x.append(2 ** num_machines_e)
                y.append(
                    running_times[instance_size_e - INSTANCE_SIZE_E_LOWER_BOUND][num_machines_e - NUM_MACHINES_E_LOWER_BOUND])
            fig.add_trace(go.Scatter(x=x, y=y, mode='markers+lines', name=f'2^{instance_size_e}' ))

        fig.show(config={'scrollZoom': True})


def plot_verification_time(running_times, protocol):
        fig = go.Figure()
        fig.update_layout(
            title=f"Verification time for {protocol}", 
            legend_title_text = "Instance size",
            xaxis_type = "log",  # Set x-axis to log scale
            yaxis_type = "log",  # Set y-axis to log scale
        )
        fig.update_xaxes(title_text="Number of machines")
        fig.update_yaxes(title_text="Verification time in seconds")

        for instance_size_e in INSTANCE_SIZE_E_RANGE:
            x = []
            y = []
            for num_machines_e in NUM_MACHINES_E_RANGE:
                x.append(2 ** num_machines_e)
                y.append(running_times[instance_size_e - INSTANCE_SIZE_E_LOWER_BOUND][num_machines_e - NUM_MACHINES_E_LOWER_BOUND])
            fig.add_trace(go.Scatter(x=x, y=y, mode='markers+lines', name=f'2^{instance_size_e}' ))

        fig.show(config={'scrollZoom': True})



def read_runtime_data(filepath):
    data = []
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    data.append(json.loads(line))

        # discard the group info 
        data = data[:-1]
        return data
    except FileNotFoundError:
        print("File not found.")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")


# Each entry in data is a json object describing a benchmark
def process_runtime_data(data):
    i = 0
    running_times = []
    for _ in INSTANCE_SIZE_E_RANGE:
        runtime = []
        for _ in NUM_MACHINES_E_RANGE:
            prover_time_in_ns = float(data[i]['typical']['estimate'])
            prover_time_in_seconds = prover_time_in_ns / 10 ** 9
            runtime.append(prover_time_in_seconds)
            i += 1
        running_times.append(runtime)
    return running_times


def read_and_process_proof_size_data(filepath):
    data = []
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    size = int(line)
                    data.append(size)
    except FileNotFoundError:
        print("File not found.")
    
    proof_sizes = []
    i = 0
    for _ in INSTANCE_SIZE_E_RANGE:
        size_vec = []
        for _ in NUM_MACHINES_E_RANGE:
            proof_size_in_bytes = data[i]
            proof_size_in_MB = proof_size_in_bytes / 10 ** 6
            size_vec.append(proof_size_in_MB)
            i += 1
        proof_sizes.append(size_vec)
    return proof_sizes


def plot_proof_size(proof_sizes, protocol):
        fig = go.Figure()
        fig.update_layout(
            title=f"Proof Size for {protocol}", 
            legend_title_text = "Instance size",
            xaxis_type = "log",  # Set x-axis to log scale
            yaxis_type = "log",  # Set y-axis to log scale
        )
        fig.update_xaxes(title_text="Number of machines")
        fig.update_yaxes(title_text="Proof Size in MB")

        for instance_size_e in INSTANCE_SIZE_E_RANGE:
            x = []
            y = []
            for num_machines_e in NUM_MACHINES_E_RANGE:
                x.append(2 ** num_machines_e)
                y.append(proof_sizes[instance_size_e - INSTANCE_SIZE_E_LOWER_BOUND][num_machines_e - NUM_MACHINES_E_LOWER_BOUND])
            fig.add_trace(go.Scatter(x=x, y=y, mode='markers+lines', name=f'2^{instance_size_e}' ))

        fig.show(config={'scrollZoom': True})
    

def read_and_process_comm_cost_data(filepath):
    data = []
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    size = int(line)
                    data.append(size)
    except FileNotFoundError:
        print("File not found.")
    
    comm_costs = []
    i = 0
    for _ in INSTANCE_SIZE_E_RANGE:
        cost_vec = []
        for _ in NUM_MACHINES_E_RANGE:
            comm_cost_in_bytes = data[i]
            comm_cost_in_MB = comm_cost_in_bytes / 10 ** 6
            cost_vec.append(comm_cost_in_MB)
            i += 1
        comm_costs.append(cost_vec)

    return comm_costs


def plot_comm_cost(comm_costs, protocol):
        fig = go.Figure()
        fig.update_layout(
            title=f"Communication Costs for {protocol}", 
            legend_title_text = "Instance size",
            xaxis_type = "log",  # Set x-axis to log scale
            yaxis_type = "log",  # Set y-axis to log scale
        )
        fig.update_xaxes(title_text="Number of machines")
        fig.update_yaxes(title_text="Comm. Cost in MB")

        for instance_size_e in INSTANCE_SIZE_E_RANGE:
            x = []
            y = []
            for num_machines_e in NUM_MACHINES_E_RANGE:
                if num_machines_e > 0:
                    x.append(2 ** num_machines_e)
                    y.append(comm_costs[instance_size_e - INSTANCE_SIZE_E_LOWER_BOUND][num_machines_e - NUM_MACHINES_E_LOWER_BOUND])
            fig.add_trace(go.Scatter(x=x, y=y, mode='markers+lines', name=f'2^{instance_size_e}' ))

        fig.show(config={'scrollZoom': True})


def read_and_process_memory_usage(filepath):
    data = []
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    data.append(int(line))
    except FileNotFoundError:
        print("File not found.")
    
    memory_usage = []
    i = 0
    for _ in INSTANCE_SIZE_E_RANGE:
        instance_usage = []
        for _ in NUM_MACHINES_E_RANGE:
            memory_usage_in_kB = data[i]
            memory_usage_in_GB = memory_usage_in_kB / 10 ** 6
            instance_usage.append(memory_usage_in_GB)
            i += 1
        memory_usage.append(instance_usage)

    return memory_usage


def plot_memory_usage(memory_usage, protocol_and_node_type):
        fig = go.Figure()
        fig.update_layout(
            title=f"Memory Usage for {protocol_and_node_type}", 
            legend_title_text = "Instance size",
            xaxis_type = "log",  # Set x-axis to log scale
            yaxis_type = "log",  # Set y-axis to log scale
        )
        fig.update_xaxes(title_text="Number of machines")
        fig.update_yaxes(title_text="Memory Usage in GB")

        for instance_size_e in INSTANCE_SIZE_E_RANGE:
            x = []
            y = []
            for num_machines_e in NUM_MACHINES_E_RANGE:
                x.append(2 ** num_machines_e)
                y.append(memory_usage[instance_size_e - INSTANCE_SIZE_E_LOWER_BOUND][num_machines_e - NUM_MACHINES_E_LOWER_BOUND])
            fig.add_trace(go.Scatter(x=x, y=y, mode='markers+lines', name=f'2^{instance_size_e}' ))

        fig.show(config={'scrollZoom': True})


def show_parallel_fri_worker_time(prefixes):
    for prefix in prefixes:
        data = read_runtime_data(f'{prefix}parallel_fri_prover.json')
        running_times = process_runtime_data(data)
        plot_worker_prover_time(running_times, "Parallel FRI")


def show_fold_and_batch_worker_time(prefixes):
    for prefix in prefixes:
        data = read_runtime_data(f'{prefix}fold_and_batch_folding.json')
        running_times = process_runtime_data(data)
        plot_worker_prover_time(running_times, "Fold-and-Batch")


def show_fold_and_batch_master_time(prefixes):
    for prefix in prefixes:
        worker_data = read_runtime_data(f'{prefix}fold_and_batch_folding.json')
        master_data = read_runtime_data(f'{prefix}fold_and_batch_master.json')
        worker_running_times = process_runtime_data(worker_data)
        master_running_times = process_runtime_data(master_data)
        for i in range(len(INSTANCE_SIZE_E_RANGE)):
            for j in range(len(NUM_MACHINES_E_RANGE)):
                master_running_times[i][j] += worker_running_times[i][j]
        plot_master_prover_time(master_running_times, "Fold-and-Batch")


def show_distributed_batched_fri_worker_time(prefixes):
    for prefix in prefixes:
        data = read_runtime_data(f'{prefix}distributed_batched_fri_folding.json')
        running_times = process_runtime_data(data)
        plot_worker_prover_time(running_times, "Distributed Batched FRI")


def show_distributed_batched_fri_master_time(prefixes):
    for prefix in prefixes:
        worker_data = read_runtime_data(f'{prefix}distributed_batched_fri_folding.json')
        master_data = read_runtime_data(f'{prefix}distributed_batched_fri_master.json')
        worker_running_times = process_runtime_data(worker_data)
        master_running_times = process_runtime_data(master_data)
        for i in range(len(INSTANCE_SIZE_E_RANGE)):
            for j in range(len(NUM_MACHINES_E_RANGE)):
                master_running_times[i][j] += worker_running_times[i][j]
        plot_master_prover_time(master_running_times, "Distributed Batched FRI")


def show_fold_and_batch_comm_cost(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}fold_and_batch_comm_cost'
        comm_costs = read_and_process_comm_cost_data(filename)
        plot_comm_cost(comm_costs, "Fold-and-Batch")

def show_distributed_batched_fri_comm_cost(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}distributed_batched_fri_comm_cost'
        comm_costs = read_and_process_comm_cost_data(filename)
        plot_comm_cost(comm_costs, "Distributed Batched FRI")

def show_fold_and_batch_verification_time(prefixes):
    for prefix in prefixes:
        data = read_runtime_data(f'{prefix}fold_and_batch_verify.json')
        running_times = process_runtime_data(data)
        plot_verification_time(running_times, "Fold-and-Batch")


def show_parallel_fri_verification_time(prefixes):
    for prefix in prefixes:
        data = read_runtime_data(f'{prefix}parallel_fri_verify.json')
        running_times = process_runtime_data(data)
        plot_verification_time(running_times, "Parallel FRI")


def show_distributed_batched_fri_verification_time(prefixes):
    for prefix in prefixes:
        data = read_runtime_data(f'{prefix}distributed_batched_fri_verify.json')
        running_times = process_runtime_data(data)
        plot_verification_time(running_times, "Distributed Batched FRI")

def show_fold_and_batch_proof_size(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}fold_and_batch_proof_size'
        proof_sizes = read_and_process_proof_size_data(filename)
        plot_proof_size(proof_sizes, "Fold-and-Batch")


def show_distributed_batched_fri_proof_size(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}distributed_batched_fri_proof_size'
        proof_sizes = read_and_process_proof_size_data(filename)
        plot_proof_size(proof_sizes, "Distributed Batched FRI")


def show_distributed_batched_fri_worker_memory_usage(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}distributed_batched_fri_worker_memory'
        memory_usage = read_and_process_memory_usage(filename)
        plot_memory_usage(memory_usage, "Distributed Batched FRI worker")


def show_distributed_batched_fri_master_memory_usage(prefixes):
    for prefix in prefixes:
        worker_filename = f'{prefix}distributed_batched_fri_worker_memory'
        master_filename = f'{prefix}distributed_batched_fri_master_memory'
        worker_memory_usage = read_and_process_memory_usage(worker_filename)
        master_memory_usage = read_and_process_memory_usage(master_filename)
        for i in range(len(INSTANCE_SIZE_E_RANGE)):
            for j in range(len(NUM_MACHINES_E_RANGE)):
                master_memory_usage[i][j] = max(master_memory_usage[i][j], worker_memory_usage[i][j])
        plot_memory_usage(master_memory_usage, "Distributed Batched FRI master")


def show_fold_and_batch_worker_memory_usage(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}fold_and_batch_worker_memory'
        memory_usage = read_and_process_memory_usage(filename)
        plot_memory_usage(memory_usage, "Fold-and-Batch worker")


def show_fold_and_batch_master_memory_usage(prefixes):
    for prefix in prefixes:
        worker_filename = f'{prefix}fold_and_batch_worker_memory'
        master_filename = f'{prefix}fold_and_batch_master_memory'
        worker_memory_usage = read_and_process_memory_usage(worker_filename)
        master_memory_usage = read_and_process_memory_usage(master_filename)
        for i in range(len(INSTANCE_SIZE_E_RANGE)):
            for j in range(len(NUM_MACHINES_E_RANGE)):
                master_memory_usage[i][j] = max(master_memory_usage[i][j], worker_memory_usage[i][j])
        plot_memory_usage(master_memory_usage, "Fold-and-Batch master")


def show_parallel_fri_memory_usage(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}parallel_fri_prover_memory'
        memory_usage = read_and_process_memory_usage(filename)
        plot_memory_usage(memory_usage, "Parallel FRI")

def show_parallel_fri_proof_size(prefixes):
    for prefix in prefixes:
        filename = f'{prefix}parallel_fri_proof_size'
        proof_sizes = read_and_process_proof_size_data(filename)
        plot_proof_size(proof_sizes, "Parallel FRI")


if __name__ == "__main__":

    prefixes = [
        # "./benches/bench_data/15_21_0_7_small_K/",
        # "./benches/bench_data/15_21_0_7_medium_K/",
        # "./benches/bench_data/15_21_0_7_large_K/",
        # "./benches/bench_data/21_25_0_7_small_K/",
        # "./benches/bench_data/21_25_0_7_medium_K/",
        # "./benches/bench_data/21_25_0_7_256_K/",
        # "./benches/bench_data/21_25_0_7_large_K/",
        # "./benches/bench_data/21_25_0_7_T_divided_by_4_K/",
        "./benches/bench_data/21_26_0_8_T_divided_by_4_K/",
        # "./benches/bench_data/15_21_0_8_T_divided_by_4_K/",
        # "./benches/bench_data/",
    ]

    parallel_fri_prefix = [
        # "./benches/bench_data/21_25_0_7_parallel_fri/",
        "./benches/bench_data/21_26_0_8_parallel_fri/",
    ]

    distributed_batched_fri_prefixes = [
        "./benches/bench_data/21_26_0_8_distributed_batched_fri/",
    ]

    # # Prover time
    show_distributed_batched_fri_worker_time(distributed_batched_fri_prefixes)
    show_distributed_batched_fri_master_time(distributed_batched_fri_prefixes)
    show_fold_and_batch_worker_time(prefixes)
    show_fold_and_batch_master_time(prefixes)
    show_parallel_fri_worker_time(parallel_fri_prefix)

    # Communication cost
    show_distributed_batched_fri_comm_cost(distributed_batched_fri_prefixes)
    show_fold_and_batch_comm_cost(prefixes)

    # Verification time
    show_distributed_batched_fri_verification_time(distributed_batched_fri_prefixes)
    show_fold_and_batch_verification_time(prefixes)
    show_parallel_fri_verification_time(parallel_fri_prefix)

    # # Proof size
    show_distributed_batched_fri_proof_size(distributed_batched_fri_prefixes)
    show_fold_and_batch_proof_size(prefixes)
    show_parallel_fri_proof_size(parallel_fri_prefix)

    # Memory Usage
    show_distributed_batched_fri_worker_memory_usage(distributed_batched_fri_prefixes)
    show_distributed_batched_fri_master_memory_usage(distributed_batched_fri_prefixes)
    show_fold_and_batch_worker_memory_usage(prefixes)
    show_fold_and_batch_master_memory_usage(prefixes)
    show_parallel_fri_memory_usage(parallel_fri_prefix)

        
