map<u32, u32> shared_counter : HashMap(1024) {
  pinned: "/sys/fs/bpf/shared_counter"
}

// First eBPF program - packet counter
@xdp fn packet_counter(ctx: xdp_md) -> xdp_action {
  shared_counter[1] = 100
  return XDP_PASS
}

@tc fn packet_filter(ctx: TcContext) -> TcAction {
  shared_counter[2] = 200
  return TC_ACT_OK
}

// Userspace coordination (outside program blocks)
fn main() -> i32 {
  shared_counter[1] = 0
  shared_counter[2] = 0
  
  let prog1 = load(packet_counter)
  let prog2 = load(packet_filter)
  attach(prog1, "eth0", 0)
  attach(prog2, "eth0", 0)
  
  return 0
} 