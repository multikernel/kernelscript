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

// Pattern Test Example - tests struct initialization (IRStructLiteral pattern)

struct PacketInfo {
    size: u64,
    action: u32,
}

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  // Context access - tests IRContextAccess pattern
  var packet_size = ctx->data_end - ctx->data
  
  // Struct literal initialization - tests IRStructLiteral pattern
  var info = PacketInfo {
      size: packet_size,
      action: 2,
  }
  
  // Use the struct values
  if (info.size > 1500) {
    return XDP_DROP
  }
  
  return XDP_PASS
}

fn main() -> i32 {
  var prog = load(packet_filter)
  attach(prog, "lo", 0)
  
  print("Pattern-based packet filter attached to loopback")
  print("Testing pattern matching capabilities...")
  
  // Demonstrate pattern matching functionality
  detach(prog)
  print("Pattern filter detached")
  
  return 0
} 