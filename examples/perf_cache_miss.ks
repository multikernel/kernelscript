// perf_cache_miss.ks
// Demonstrates @perf_event program type in KernelScript.
// The eBPF program runs on every hardware cache-miss event.
// The userspace side opens the perf event and attaches the BPF program.

@perf_event
fn on_cache_miss(ctx: *bpf_perf_event_data) -> i32 {
    return 0
}

fn main() -> i32 {
    var prog = load(on_cache_miss)

    // Only perf_type + perf_config are required; pid, cpu, period, wakeup and flag fields
    // default to: pid=-1 (all procs), cpu=0, period=1_000_000, wakeup=1,
    // inherit/exclude_kernel/exclude_user=false.
    var cache = attach(prog, perf_options { perf_type: perf_type_hardware, perf_config: cache_misses, period: 10000000, inherit: true }, 0)
    var branch = attach(prog, perf_options { perf_type: perf_type_hardware, perf_config: branch_misses, period: 10000000, inherit: true }, 0)
    print("Cache-miss and branch-miss perf_event demo attached")
    var cache_count = read(cache)
    print("Cache-miss count: %lld", cache_count)
    var branch_count = read(branch)
    print("Branch-miss count: %lld", branch_count)

    detach(cache)
    detach(branch)
    detach(prog)
    print("Cache-miss and branch-miss perf_event demo detached")
    return 0
}
