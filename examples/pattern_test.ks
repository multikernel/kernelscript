// Pattern Test Example - tests struct initialization (IRStructLiteral pattern)

struct PacketInfo {
    size: u64,
    action: u32,
}

@xdp fn packet_filter(ctx: XdpContext) -> XdpAction {
  // Context access - tests IRContextAccess pattern
  let packet_size = ctx.data_end - ctx.data
  
  // Struct literal initialization - tests IRStructLiteral pattern
  let info = PacketInfo {
      size: packet_size,
      action: 2,
  }
  
  // Use the struct values
  if (info.size > 1500) {
    return 1
  }
  
  return info.action
}

fn main() -> i32 {
  let prog = load(packet_filter)
  attach(prog, "lo", 0)
  return 0
} 