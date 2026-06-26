// perf_page_fault.ks
// Demonstrates @perf_event program type in KernelScript.
// The eBPF program runs on every software page-fault event.
// The userspace side opens the perf event and attaches the BPF program.

@perf_event
fn on_page_fault(ctx: *bpf_perf_event_data) -> i32 {
    return 0
}

fn main() -> i32 {
    var prog = load(on_page_fault)

    // pid: 0 = current process, cpu: -1 = any CPU (standard per-process monitoring).
    // page_faults (PERF_COUNT_SW_PAGE_FAULTS) is the most reliable software event:
    // every heap/stack allocation triggers minor page faults, no scheduler dependency.
    var page = attach(prog, perf_options { event: page_faults, pid: 0, cpu: -1, period: 1 }, 0)
    // branch is a standalone hardware event; page_faults remains a separate software event.
    var branch = attach(prog, perf_options { event: branch_misses, period: 10000000, inherit: true}, 0)
    
    print("perf_event demo attached")

    // Repeatedly increment a counter; stack/heap activity will generate page faults.
    var x: i64 = 0
    for (i in 0..10000000) {
        x = x + 1
    }

    var page_fault_count = read(page).scaled
    print("Page-fault count: %lld", page_fault_count)
    var branch_count = read(branch).scaled
    print("Branch-miss count: %lld", branch_count)

    detach(page)
    detach(branch)
    print("perf_event demo detached")
    detach(prog)
    return 0
}
