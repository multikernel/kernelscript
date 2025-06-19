// This example demonstrates the complete eBPF map type system

// Type aliases for clarity
type IpAddress = u32
type Counter = u64
type PacketSize = u16

// Struct for packet statistics
struct PacketStats {
  count: Counter,
  total_bytes: u64,
  last_seen: u64
}

// Global maps with different configurations

// 1. Simple array map for per-CPU counters
map<u32, Counter> cpu_counters : Array(256) {
  pinned: "/sys/fs/bpf/cpu_counters"
}

// 2. Hash map for IP address tracking with attributes
map<IpAddress, PacketStats> ip_stats : HashMap(10000) {
  pinned: "/sys/fs/bpf/ip_tracking"
}

// 3. LRU hash map for recent connections
map<IpAddress, u64> recent_connections : LruHash(1000)

// 4. Ring buffer for event logging
map<u32, u8> event_log : RingBuffer(65536) {
  pinned: "/sys/fs/bpf/events"
}

// XDP program demonstrating map usage
program packet_analyzer : xdp {
  // Helper functions (would be implemented in stdlib)
  fn get_src_ip(ctx: XdpContext) -> IpAddress {
    return 0x7f000001 // 127.0.0.1 for demo
  }
  
  fn get_packet_len(ctx: XdpContext) -> PacketSize {
    return 64 // Demo packet size
  }
  
  fn get_cpu_id() -> u32 {
    return 0 // Demo CPU ID
  }
  
  fn get_timestamp() -> u64 {
    return 1234567890 // Demo timestamp
  }

  // Local map for program-specific data
  map<u32, u32> local_state : HashMap(100)
  
  fn main(ctx: XdpContext) -> XdpAction {
    // Get packet information
    let src_ip: IpAddress = get_src_ip(ctx)
    let packet_len: PacketSize = get_packet_len(ctx)
    
    // Update CPU counter
    let cpu_id = get_cpu_id()
    cpu_counters[cpu_id] = cpu_counters[cpu_id] + 1
    
    // Update IP statistics
    let stats = ip_stats[src_ip]
    if (stats != null) {
      stats.count = stats.count + 1
      stats.total_bytes = stats.total_bytes + packet_len
      stats.last_seen = get_timestamp()
      ip_stats[src_ip] = stats
    } else {
      let new_stats = PacketStats {
        count: 1,
        total_bytes: packet_len,
        last_seen: get_timestamp()
      }
      ip_stats[src_ip] = new_stats
    }
    
    // Check recent connections
    let recent = recent_connections[src_ip]
    if (recent != null) {
      // Log repeated connection
      event_log[0] = 1
    }
    
    // Update local state
    local_state[0] = local_state[0] + 1
    
    return XDP_PASS
  }
}

// TC program demonstrating different map usage patterns
program traffic_shaper : tc {
  
  // Per-CPU array for bandwidth tracking
  map<u32, u64> bandwidth_usage : PercpuArray(256) {
    pinned: "/sys/fs/bpf/bandwidth"
  }
  
  fn main(ctx: TcContext) -> TcAction {
    let cpu = get_cpu_id()
    let bytes = get_packet_len(ctx)
    
    // Update bandwidth usage
    bandwidth_usage[cpu] = bandwidth_usage[cpu] + bytes
    
    // Simple rate limiting logic
    if (bandwidth_usage[cpu] > 1000000) {
      return TC_ACT_SHOT
    }
    
    return TC_ACT_OK
  }
  
  fn get_packet_len(ctx: TcContext) -> u64 {
    return 128 // Demo packet size
  }
}

fn main() -> i32 {
  let prog1 = load_program(traffic_shaper)
  let prog2 = load_program(packet_analyzer)
  attach_program(prog1, "lo", 0)
  attach_program(prog2, "lo", 0)
}