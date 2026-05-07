// perf_branch_miss.ks
// Demonstrates @perf_event program type in KernelScript.
// The eBPF program runs on every hardware branch-miss event.
// The userspace side opens the perf event and attaches the BPF program.

@perf_event
fn on_branch_miss(ctx: *bpf_perf_event_data) -> i32 {
    return 0
}

fn main() -> i32 {
    var prog = load(on_branch_miss)

    // Only perf_type + perf_config are required; pid, cpu, period, wakeup and flag fields
    // default to: pid=-1 (all procs), cpu=0, period=1_000_000, wakeup=1,
    // inherit/exclude_kernel/exclude_user=false.
    attach(prog, perf_options { perf_type: perf_type_hardware, perf_config: branch_misses }, 0)
    print("Branch-miss perf_event demo attached")

    detach(prog)
    print("Branch-miss perf_event demo detached")
    return 0
}
