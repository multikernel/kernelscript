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

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  var packet_size = ctx->data_end - ctx->data
  if (packet_size > 1500) {
    return XDP_DROP
  }
  return XDP_PASS
}

fn main() -> i32 {
  var prog = load(packet_filter)
  attach(prog, "eth0", 0)
  
  print("Packet filter attached to eth0")
  print("Filtering incoming packets...")
  
  // In a real application, this would run indefinitely
  // For demonstration, we detach after setup
  detach(prog)
  print("Packet filter detached")
  
  return 0
} 