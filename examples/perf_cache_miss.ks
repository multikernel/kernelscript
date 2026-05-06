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

    // Only counter is required; pid, cpu, period, wakeup and flag fields
    // default to: pid=-1 (all procs), cpu=0, period=1_000_000, wakeup=1,
    // inherit/exclude_kernel/exclude_user=false.
    attach(prog, perf_options { counter: cache_misses,period: 10000000, inherit: true }, 0)

    perf_print(prog, "cache_misses")

    detach(prog)
    return 0
}
