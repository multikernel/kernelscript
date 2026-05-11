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
    var att = attach(prog, perf_options { perf_type: perf_type_software, perf_config: page_faults, pid: 0, cpu: -1, period: 1 }, 0)
    print("Page-fault perf_event demo attached")

    // Repeatedly increment a counter; stack/heap activity will generate page faults.
    var x: i64 = 0
    for (i in 0..10000000) {
        x = x + 1
    }

    var count = read(att)
    print("Page-fault count: %lld", count)

    detach(att)
    print("Page-fault perf_event demo detached")
    detach(prog)
    return 0
}
