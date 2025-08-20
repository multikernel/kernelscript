include "xdp.kh"

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