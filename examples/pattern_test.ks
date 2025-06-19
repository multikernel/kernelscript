// Pattern Test Example - tests struct initialization (IRStructLiteral pattern)

struct PacketInfo {
    size: u64,
    action: u32,
}

program packet_filter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
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
}

fn main() -> i32 {
    let prog = load_program(packet_filter)
    attach_program(prog, "lo", 0)
    return 0
} 