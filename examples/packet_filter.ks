@xdp fn packet_filter(ctx: xdp_md) -> xdp_action {
  let packet_size = ctx.data_end - ctx.data
  if (packet_size > 1500) {
    return 1
  }
  return 2
}

fn main() -> i32 {
  let prog = load(packet_filter)
  attach(prog, "eth0", 0)
  return 0
} 