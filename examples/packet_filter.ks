program packet_filter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let packet_size = ctx.data_end - ctx.data
    if (packet_size > 1500) {
      return 1
    }
    return 2
  }
} 