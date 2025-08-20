// Pattern Test Example - tests struct initialization (IRStructLiteral pattern)

include "xdp.kh"

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