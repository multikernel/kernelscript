// Global map accessible by both eBPF programs and userspace
map<u32, u64> shared_counter : HashMap(1024) {
  pinned: "/sys/fs/bpf/shared_counter"
};

// First eBPF program - packet counter
program packet_counter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let key = 1;
    let current = shared_counter[key];
    shared_counter[key] = current + 1;
    return 2;  // XDP_PASS
  }
}

// Second eBPF program - packet filter
program packet_filter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let key = 2;
    let filter_count = shared_counter[key];
    shared_counter[key] = filter_count + 1;
    
    // Simple filtering logic
    if filter_count > 100 {
      return 1;  // XDP_DROP
    }
    return 2;  // XDP_PASS
  }
}

userspace {
  struct Config {
    debug_level: u32;
    max_packets: u64;
  }

  fn main(argc: u32, argv: u64) -> i32 {
    // Monitor shared map from userspace
    let counter_key = 1;
    let filter_key = 2;
    
    // Read counters (simplified for testing)
    let packet_count = shared_counter[counter_key];
    let filter_count = shared_counter[filter_key];
    
    // Reset if too high
    if packet_count > 1000000 {
      shared_counter[counter_key] = 0;
    }
    
    if filter_count > 1000000 {
      shared_counter[filter_key] = 0;
    }
    
    return 0;
  }

  targets = ["c"];
} 