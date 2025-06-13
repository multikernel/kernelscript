map<u32, u32> shared_counter : HashMap(1024) {
  pinned: "/sys/fs/bpf/shared_counter"
};

// First eBPF program - packet counter
program packet_counter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    shared_counter[1] = 100;
    return 2;
  }
}

program packet_filter : tc {
  fn main(ctx: TcContext) -> TcAction {
    shared_counter[2] = 200;
    return 0;
  }
}

userspace {
  fn main() -> i32 {
    shared_counter[1] = 0;
    shared_counter[2] = 0;
    return 0;
  }
} 