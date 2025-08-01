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

@xdp fn simple_xdp(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  var prog = load(simple_xdp)
  attach(prog, "eth0", 0)
  
  print("XDP program attached to eth0")
  print("Letting it run for demonstration...")
  
  // In a real application, the program would run here
  // For demonstration, we immediately detach
  detach(prog)
  print("XDP program detached from eth0")
  
  return 0
} 
