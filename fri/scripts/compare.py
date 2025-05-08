import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from parse import *

PARA_PREFIX = "./benches/bench_data/21_26_0_8_parallel_fri/"
FAB_PREFIX =  "./benches/bench_data/21_26_0_8_T_divided_by_4_K/"
DBF_PREFIX = "./benches/bench_data/21_26_0_8_distributed_batched_fri/"

def plot3(y_DBF, y_FAB, y_para, yticks, ylabel, title, worker_data):
    if worker_data:
        # For worker data, we don't need to plot the data point for a single prover
        x_para = [2**i for i in range(1, 8)]
        x_DBF = x_para
        x_FAB = x_para
        y_para = y_para[1:]
    else:
        # For overall data, we keep the single prover data point for paralel FRI 
        # to compare with monolithic proving. 
        x_para = [2**i for i in range(8)]
        x_DBF = [2**i for i in range(1, 8)]
        x_FAB = x_DBF

    # For a single prover, it does not make sense to use a distributed algorithm as 
    # there will be overheads. Therefore, we remove the data point for a single prover.
    y_DBF = y_DBF[1:]
    y_FAB = y_FAB[1:]

    plt.loglog(x_DBF, y_DBF, 'ro-', label="Distributed Batched FRI")
    plt.loglog(x_FAB, y_FAB, 'b^-',  label="Fold-and-Batch (K = T / 4)")
    plt.loglog(x_para, y_para, 'gs-',  label="Parallel FRI")

    plt.xlabel('Number of Machines')
    plt.ylabel(ylabel)

    plt.xticks(x_para)
    plt.gca().xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x)}'))
    plt.gca().xaxis.set_minor_locator(mticker.NullLocator())
    
    plt.yticks(yticks)
    plt.gca().yaxis.set_major_formatter(mticker.ScalarFormatter()) 
    plt.gca().yaxis.set_minor_locator(mticker.NullLocator()) 

    plt.title(title)
    plt.grid(True, which="both", linestyle='--', linewidth=0.5)
    plt.legend()
    plt.show()

def plot2(y_DBF, y_FAB, yticks, ylabel, title):
    x = [2**i for i in range(1, 8)]
    y_DBF = y_DBF[1:]
    y_FAB = y_FAB[1:]

    plt.loglog(x, y_DBF, 'ro-', label="Distributed Batched FRI")
    plt.loglog(x, y_FAB, 'b^-',  label="Fold-and-Batch (K = T / 4)")

    plt.xlabel('Number of Machines')
    plt.ylabel(ylabel)

    plt.xticks(x)
    plt.gca().xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x)}'))
    plt.gca().xaxis.set_minor_locator(mticker.NullLocator())

    plt.yticks(yticks)
    plt.gca().yaxis.set_major_formatter(mticker.ScalarFormatter())
    plt.gca().yaxis.set_minor_locator(mticker.NullLocator())

    plt.title(title)
    plt.grid(True, which="both", linestyle='--', linewidth=0.5)
    plt.legend()
    plt.show()



def plot_master_running_time():
    worker_data = read_runtime_data(f'{FAB_PREFIX}fold_and_batch_folding.json')
    master_data = read_runtime_data(f'{FAB_PREFIX}fold_and_batch_master.json')
    worker_running_times = process_runtime_data(worker_data)
    master_running_times = process_runtime_data(master_data)
    for i in range(len(INSTANCE_SIZE_E_RANGE)):
        for j in range(len(NUM_MACHINES_E_RANGE)):
            master_running_times[i][j] += worker_running_times[i][j]
    y_FAB = master_running_times[-1]

    worker_data = read_runtime_data(f'{DBF_PREFIX}distributed_batched_fri_folding.json')
    master_data = read_runtime_data(f'{DBF_PREFIX}distributed_batched_fri_master.json')
    worker_running_times = process_runtime_data(worker_data)
    master_running_times = process_runtime_data(master_data)
    
    for i in range(len(INSTANCE_SIZE_E_RANGE)):
        for j in range(len(NUM_MACHINES_E_RANGE)):
            master_running_times[i][j] += worker_running_times[i][j]
    y_DBF = master_running_times[-1]

    data = read_runtime_data(f'{PARA_PREFIX}parallel_fri_prover.json')
    running_times = process_runtime_data(data)
    y_para = running_times[-1] 

    yticks = [0.65, 5, 10, 20, 50, 85]
    plot3(y_DBF, y_FAB, y_para, yticks, "Time (s)", "Overall Prover Runtimes", worker_data=False)

def plot_worker_running_time():
    data = read_runtime_data(f'{PARA_PREFIX}parallel_fri_prover.json')
    running_times = process_runtime_data(data)
    y_para = running_times[-1] 

    data = read_runtime_data(f'{DBF_PREFIX}distributed_batched_fri_folding.json')
    running_times = process_runtime_data(data)
    y_DBF = running_times[-1] 

    data = read_runtime_data(f'{FAB_PREFIX}fold_and_batch_folding.json')
    running_times = process_runtime_data(data)
    y_FAB = running_times[-1]

    yticks = [0.4, 1, 10, 20, 50]
    plot3(y_DBF, y_FAB, y_para, yticks, "Time (s)", "Worker Runtimes", worker_data=True)

def plot_comm_cost():
    filename = f'{FAB_PREFIX}fold_and_batch_comm_cost'
    comm_costs = read_and_process_comm_cost_data(filename)
    y_FAB = comm_costs[-1]

    filename = f'{DBF_PREFIX}distributed_batched_fri_comm_cost'
    comm_costs = read_and_process_comm_cost_data(filename)
    y_DBF = comm_costs[-1]

    yticks = [1000, 2000, 3000, 4000]
    plot2(y_DBF, y_FAB, yticks, "Communication (MB)", "Communication Costs")

def plot_verification_time():
    data = read_runtime_data(f'{PARA_PREFIX}parallel_fri_verify.json')
    running_times = process_runtime_data(data)
    y_para = running_times[-1]

    data = read_runtime_data(f'{FAB_PREFIX}fold_and_batch_verify.json')
    running_times = process_runtime_data(data)
    y_FAB = running_times[-1]

    data = read_runtime_data(f'{DBF_PREFIX}distributed_batched_fri_verify.json')
    running_times = process_runtime_data(data)
    y_DBF = running_times[-1]

    yticks = [0.003, 0.005, 0.05, 0.1, 0.2, 0.3]
    plot3(y_DBF, y_FAB, y_para, yticks, "Time (s)", "Verification Time", worker_data=False)

def plot_proof_size():
    filename = f'{DBF_PREFIX}distributed_batched_fri_proof_size'
    proof_sizes = read_and_process_proof_size_data(filename)
    y_DBF = proof_sizes[-1]
    
    filename = f'{FAB_PREFIX}fold_and_batch_proof_size'
    proof_sizes = read_and_process_proof_size_data(filename)
    y_FAB = proof_sizes[-1]

    filename = f'{PARA_PREFIX}parallel_fri_proof_size'
    proof_sizes = read_and_process_proof_size_data(filename)
    y_para = proof_sizes[-1]

    yticks = [0.3, 1, 3, 10, 23]
    plot3(y_DBF, y_FAB, y_para, yticks, "Proof Size (MB)", "Proof Size", worker_data=False)

def plot_worker_memory():
    filename = f'{DBF_PREFIX}distributed_batched_fri_worker_memory'
    memory_usage = read_and_process_memory_usage(filename)
    y_DBF = memory_usage[-1]

    filename = f'{FAB_PREFIX}fold_and_batch_worker_memory'
    memory_usage = read_and_process_memory_usage(filename)
    y_FAB = memory_usage[-1]

    filename = f'{PARA_PREFIX}parallel_fri_prover_memory'
    memory_usage = read_and_process_memory_usage(filename)
    y_para = memory_usage[-1]

    yticks = [0.23, 1, 5, 10, 15]
    plot3(y_DBF, y_FAB, y_para, yticks, "Memory (GB)", "Worker Memory Costs", worker_data = True)


def plot_master_memory():
    worker_filename = f'{DBF_PREFIX}distributed_batched_fri_worker_memory'
    master_filename = f'{DBF_PREFIX}distributed_batched_fri_master_memory'
    worker_memory_usage = read_and_process_memory_usage(worker_filename)
    master_memory_usage = read_and_process_memory_usage(master_filename)
    for i in range(len(INSTANCE_SIZE_E_RANGE)):
        for j in range(len(NUM_MACHINES_E_RANGE)):
            master_memory_usage[i][j] = max(master_memory_usage[i][j], worker_memory_usage[i][j])
    y_DBF = master_memory_usage[-1]

    worker_filename = f'{FAB_PREFIX}fold_and_batch_worker_memory'
    master_filename = f'{FAB_PREFIX}fold_and_batch_master_memory'
    worker_memory_usage = read_and_process_memory_usage(worker_filename)
    master_memory_usage = read_and_process_memory_usage(master_filename)
    for i in range(len(INSTANCE_SIZE_E_RANGE)):
        for j in range(len(NUM_MACHINES_E_RANGE)):
            master_memory_usage[i][j] = max(master_memory_usage[i][j], worker_memory_usage[i][j])
    y_FAB = master_memory_usage[-1]

    filename = f'{PARA_PREFIX}parallel_fri_prover_memory'
    memory_usage = read_and_process_memory_usage(filename)
    y_para = memory_usage[-1]

    yticks = [0.23, 4, 10, 20, 30]
    plot3(y_DBF, y_FAB, y_para, yticks, "Memory (GB)", "Overall Memory Costs", worker_data=False)

# plot_master_running_time()
# plot_worker_running_time()
# plot_comm_cost()
plot_verification_time()
plot_proof_size()
# plot_worker_memory()
# plot_master_memory()