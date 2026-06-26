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

    // Only event is required; pid, cpu, group/group_fd, period, wakeup and flag fields
    // default to: pid=-1 (all procs), cpu=0, period=1_000_000, wakeup=1,
    // no group, inherit/exclude_kernel/exclude_user=false.
    var cache = attach(prog, perf_options { event: cache_misses, period: 10000000, inherit: true }, 0)
    // branch joins cache's perf event group. Adding a member restarts the whole group from zero.
    var branch = attach(prog, perf_options { event: branch_misses, period: 10000000, inherit: true, group: cache }, 0)
    print("Cache-miss and branch-miss perf_event demo attached")
    var cache_count = read(cache).scaled
    print("Cache-miss count: %lld", cache_count)
    var branch_count = read(branch).scaled
    print("Branch-miss count: %lld", branch_count)
    
    var prev = read(cache)
    // Simulate workload with cache misses and branch misses.
    var x = 0
    var i = 0
    for (i in 0..10000000) {
        if (i % 100 == 0) {
            x = x + 1
        } else {
            x = x * 2
        }
    }
    var cur = read(cache)
    var delta = cur.scaled - prev.scaled
    var dt_ns = cur.time_enabled - prev.time_enabled
    if (dt_ns > 0) {
        var per_sec = (delta * 1000000000) / dt_ns
        print("Cache misses/sec: %lld", per_sec)
    }

    var snapshot = read(cache)
    print("Grouped snapshot entries: %u", snapshot.count)

    var snapshot_index = 0
    while (snapshot_index < snapshot.count) {
        print("id=%llu value=%lld", snapshot.ids[snapshot_index], snapshot.values[snapshot_index])
        snapshot_index = snapshot_index + 1
    }

    detach(branch)
    detach(cache)
    detach(prog)
    print("Cache-miss and branch-miss perf_event demo detached")
    return 0
}
