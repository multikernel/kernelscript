// Simple XDP packet inspector with object allocation
// Demonstrates new/delete for connection tracking

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

struct ConnStats {
    packet_count: u64,
    byte_count: u64,
    first_seen: u64,
    last_seen: u64,
}

// Map to store connection statistics
var conn_tracker : hash<u32, *ConnStats>(1024)

@xdp fn packet_inspector(ctx: *xdp_md) -> xdp_action {
    // Simple source IP extraction (in real code, would parse ethernet/IP headers)
    var src_ip: u32 = 0x08080808  // Simulated source IP
    var packet_size: u32 = 64     // Simulated packet size
    
    // Look up existing connection stats
    var stats = conn_tracker[src_ip]
    
    if (stats == none) {
        // First packet from this IP - allocate new stats object
        stats = new ConnStats()
        if (stats == null) {
            return XDP_DROP  // Allocation failed
        }
        
        // Initialize new connection stats
        stats->packet_count = 1
        stats->byte_count = packet_size
        stats->first_seen = 12345  // Fake timestamp
        stats->last_seen = 12345
        
        // Store in map
        conn_tracker[src_ip] = stats
    } else {
        // Update existing stats
        stats->packet_count = stats->packet_count + 1
        stats->byte_count = stats->byte_count + packet_size
        stats->last_seen = 12346  // Updated timestamp
    }
    
    // Simple rate limiting: drop if too many packets
    if (stats->packet_count > 100) {
        return XDP_DROP
    }
    
    return XDP_PASS
}

fn main() -> i32 {
    // Test userspace allocation
    var test_stats = new ConnStats()
    if (test_stats == null) {
        return 1
    }
    
    test_stats->packet_count = 42
    test_stats->byte_count = 2048
    
    // Clean up
    delete test_stats
    
    // Load and attach the XDP program
    var prog = load(packet_inspector)
    attach(prog, "eth0", 0)
    
    return 0
} 