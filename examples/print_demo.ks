// This shows the same print() function working in both eBPF and userspace contexts

config demo {
    enable_logging: bool = true,
    message_count: u32 = 0,
}

// eBPF program that uses print()
@xdp fn simple_logger(ctx: xdp_md) -> xdp_action {
    if (demo.enable_logging) {
        print("eBPF: Processing packet")
    }
    return XDP_PASS
}

// Userspace coordinator that also uses print() (no wrapper)
fn main() -> i32 {
    print("Userspace: Starting packet logger")
    print("Userspace: Logger initialized successfully")
    var prog = load(simple_logger)
    attach(prog, "lo", 0)
    return 0
} 