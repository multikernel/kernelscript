// This example demonstrates the complete eBPF map type system

// XDP context struct (from BTF)
struct xdp_md {
  data: u64,
  data_end: u64,
  data_meta: u64,
  ingress_ifindex: u32,
  rx_queue_index: u32,
  egress_ifindex: u32,
}

// XDP action enum (from BTF)
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP = 1,
  XDP_PASS = 2,
  XDP_REDIRECT = 3,
  XDP_TX = 4,
}

// TC context struct (from BTF)
struct __sk_buff {
  data: u64,
  data_end: u64,
  len: u32,
  ifindex: u32,
  protocol: u32,
  mark: u32,
}

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
fn get_src_ip(ctx: *xdp_md) -> IpAddress {
  return 0x7f000001 // 127.0.0.1 for demo
}

@helper
fn get_packet_len_xdp(ctx: *xdp_md) -> PacketSize {
  return 64 // Demo packet size
}

@helper
fn get_packet_len_tc(ctx: *__sk_buff) -> u64 {
  return 128 // Demo packet size
}

@helper
fn get_timestamp() -> u64 {
  return 1234567890 // Demo timestamp
}

// XDP program demonstrating map usage
@xdp fn packet_analyzer(ctx: *xdp_md) -> xdp_action {
  // Get packet information
  var src_ip: IpAddress = get_src_ip(ctx)
  var packet_len: PacketSize = get_packet_len_xdp(ctx)
  
  // Update CPU counter
  var cpu_id = get_cpu_id()
  cpu_counters[cpu_id] = cpu_counters[cpu_id] + 1
  
  // Update IP statistics - elegant truthy/falsy pattern
  var stats = ip_stats[src_ip]
  if (stats != none) {
    // stats is truthy - entry exists, update it
    stats.count = stats.count + 1
    stats.total_bytes = stats.total_bytes + packet_len
    stats.last_seen = get_timestamp()
    ip_stats[src_ip] = stats
  } else {
    // stats is falsy - no entry, create new one
    var new_stats = PacketStats {
      count: 1,
      total_bytes: packet_len,
      last_seen: get_timestamp()
    }
    ip_stats[src_ip] = new_stats
  }
  
  // Check recent connections
  var recent = recent_connections[src_ip]
  if (recent != none) {
    // Log repeated connection
    event_log[0] = 1
  }
  
  // Update local state
  local_state[0] = local_state[0] + 1
  
  return XDP_PASS
}

// TC program demonstrating different map usage patterns
@tc fn traffic_shaper(ctx: *__sk_buff) -> int {
  var cpu = get_cpu_id()
  var bytes = get_packet_len_tc(ctx)
  
  // Update bandwidth usage
  bandwidth_usage[cpu] = bandwidth_usage[cpu] + bytes
  
  // Simple rate limiting logic
  if (bandwidth_usage[cpu] > 1000000) {
    return 2  // TC_ACT_SHOT
  }
  
  return 0  // TC_ACT_OK
}

fn main() -> i32 {
  var prog1 = load(traffic_shaper)
  var prog2 = load(packet_analyzer)
  attach(prog1, "lo", 0)
  attach(prog2, "lo", 0)
  return 0
}