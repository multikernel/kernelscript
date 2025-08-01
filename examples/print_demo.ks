// XDP context struct (from BTF)
struct xdp_md {
  data: u64,
  data_end: u64,
  data_meta: u64,
  ingress_ifindex: u32,
  rx_queue_index: u32,
  egress_ifindex: u32,
}

// XDP action enum (from BTF)
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP = 1,
  XDP_PASS = 2,
  XDP_REDIRECT = 3,
  XDP_TX = 4,
}

// This shows the same print() function working in both eBPF and userspace contexts

config demo {
    enable_logging: bool = true,
    message_count: u32 = 0,
}

// eBPF program that uses print()
@xdp fn simple_logger(ctx: *xdp_md) -> xdp_action {
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
    
    print("Userspace: Print demo program attached")
    print("Userspace: Demonstrating kernel/userspace print coordination...")
    
    // Show print functionality working
    detach(prog)
    print("Userspace: Print demo program detached")
    
    return 0
} 