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

// 1. Simple array map for per-CPU counters (pinned to filesystem)
pin map<u32, Counter> cpu_counters : Array(256)

// 2. Hash map for IP address tracking (pinned to filesystem)
pin map<IpAddress, PacketStats> ip_stats : HashMap(10000)

// 3. LRU hash map for recent connections (local to program)
map<IpAddress, u64> recent_connections : LruHash(1000)

// 4. Ring buffer for event logging (pinned to filesystem)
pin map<u32, u8> event_log : RingBuffer(65536)

// 5. Local state map (not pinned)
map<u32, u32> local_state : HashMap(100)

// 6. Per-CPU bandwidth tracking (pinned to filesystem)
pin map<u32, u64> bandwidth_usage : PercpuArray(256)

@helper
fn get_cpu_id() -> u32 {
    return 0 // Demo CPU ID
}

@helper
fn get_src_ip(ctx: xdp_md) -> IpAddress {
  return 0x7f000001 // 127.0.0.1 for demo
}

@helper
fn get_packet_len_xdp(ctx: xdp_md) -> PacketSize {
  return 64 // Demo packet size
}

@helper
fn get_packet_len_tc(ctx: TcContext) -> u64 {
  return 128 // Demo packet size
}

@helper
fn get_timestamp() -> u64 {
  return 1234567890 // Demo timestamp
}

// XDP program demonstrating map usage
@xdp fn packet_analyzer(ctx: xdp_md) -> xdp_action {
  // Get packet information
  var src_ip: IpAddress = get_src_ip(ctx)
  var packet_len: PacketSize = get_packet_len_xdp(ctx)
  
  // Update CPU counter
  var cpu_id = get_cpu_id()
  cpu_counters[cpu_id] = cpu_counters[cpu_id] + 1
  
  // Update IP statistics
  var stats = ip_stats[src_ip]
  if (stats != null) {
    stats.count = stats.count + 1
    stats.total_bytes = stats.total_bytes + packet_len
    stats.last_seen = get_timestamp()
    ip_stats[src_ip] = stats
  } else {
    var new_stats = PacketStats {
      count: 1,
      total_bytes: packet_len,
      last_seen: get_timestamp()
    }
    ip_stats[src_ip] = new_stats
  }
  
  // Check recent connections
  var recent = recent_connections[src_ip]
  if (recent != null) {
    // Log repeated connection
    event_log[0] = 1
  }
  
  // Update local state
  local_state[0] = local_state[0] + 1
  
  return XDP_PASS
}

// TC program demonstrating different map usage patterns
@tc fn traffic_shaper(ctx: TcContext) -> TcAction {
  var cpu = get_cpu_id()
  var bytes = get_packet_len_tc(ctx)
  
  // Update bandwidth usage
  bandwidth_usage[cpu] = bandwidth_usage[cpu] + bytes
  
  // Simple rate limiting logic
  if (bandwidth_usage[cpu] > 1000000) {
    return TC_ACT_SHOT
  }
  
  return TC_ACT_OK
}

fn main() -> i32 {
  var prog1 = load(traffic_shaper)
  var prog2 = load(packet_analyzer)
  attach(prog1, "lo", 0)
  attach(prog2, "lo", 0)
  return 0
}