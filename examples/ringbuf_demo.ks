// Ring Buffer Demonstration for KernelScript
// Shows complete ring buffer API usage from eBPF to userspace

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

// Event structures for different types of events
struct NetworkEvent {
  timestamp: u64,
  event_type: u32,
  src_ip: u32,
  dst_ip: u32,
  port: u16,
  protocol: u8,
  packet_size: u16,
}

struct SecurityEvent {
  timestamp: u64,
  severity: u32,
  event_id: u32,
  pid: u32,
  message: u8[64],
}

// Ring buffer declarations
var network_events : ringbuf<NetworkEvent>(8192)     // 8KB ring buffer
pin var security_events : ringbuf<SecurityEvent>(16384)  // 16KB pinned ring buffer

// Stats for monitoring
struct Stats {
  events_submitted: u64,
  events_dropped: u64,
  buffer_full_count: u64,
}

var stats : hash<u32, Stats>(1)

@helper
fn get_timestamp() -> u64 {
  return 1234567890  // Demo timestamp - would be bpf_ktime_get_ns() in real code
}

@helper  
fn get_packet_info(ctx: *xdp_md) -> NetworkEvent {
  var event = NetworkEvent {
    timestamp: get_timestamp(),
    event_type: 1,  // PACKET_RECEIVED
    src_ip: 0x7f000001,  // 127.0.0.1
    dst_ip: 0x7f000002,  // 127.0.0.2  
    port: 80,
    protocol: 6,  // TCP
    packet_size: 64,
  }
  return event
}

// XDP program that generates network events
@xdp fn network_monitor(ctx: *xdp_md) -> xdp_action {
  var key: u32 = 0
  var stat = stats[key]
  if (stat == none) {
    var init_stat = Stats { events_submitted: 0, events_dropped: 0, buffer_full_count: 0 }
    stats[key] = init_stat
    stat = stats[key]
  }
  
  // Try to reserve space in ring buffer
  var reserved = network_events.reserve()
  if (reserved != null) {
    // Successfully reserved space - build event and submit
    // For now, just submit the reserved space
    network_events.submit(reserved)
    stat.events_submitted = stat.events_submitted + 1
  } else {
    // Ring buffer is full - increment drop counter
    stat.events_dropped = stat.events_dropped + 1
    stat.buffer_full_count = stat.buffer_full_count + 1
  }
  
  return XDP_PASS
}

// Security monitoring program
@kprobe("sys_openat") fn security_monitor(dfd: i32, filename: *u8, flags: i32, mode: u16) -> i32 {
  var reserved = security_events.reserve()
  if (reserved != null) {
    // Successfully reserved space - submit the event
    security_events.submit(reserved)
  } else {
    // Handle full buffer - could discard or try alternative logging
    // Note: discard not needed for failed reserve
  }
  
  return 0
}

// Userspace event handling

// Event handler for network events
fn network_event_handler(event: *NetworkEvent) -> i32 {
  print("Network Event:")
  print("  Timestamp: ", event->timestamp)
  print("  Type: ", event->event_type)
  print("  Source IP: ", event->src_ip)
  print("  Destination IP: ", event->dst_ip)
  print("  Port: ", event->port)
  print("  Protocol: ", event->protocol)
  print("  Packet Size: ", event->packet_size)
  return 0
}

// Event handler for security events  
fn security_event_handler(event: *SecurityEvent) -> i32 {
  print("Security Event:")
  print("  Timestamp: ", event->timestamp)
  print("  Severity: ", event->severity)
  print("  Event ID: ", event->event_id)
  print("  PID: ", event->pid)
  print("  Message: [security event]")
  return 0
}

// Custom callback functions (override weak symbols)
fn network_events_callback(event: *NetworkEvent) -> i32 {
  return network_event_handler(event)
}

fn security_events_callback(event: *SecurityEvent) -> i32 {
  return security_event_handler(event)
}

// Main userspace program
fn main() -> i32 {
  print("Starting ring buffer demonstration...")
  
  // Load and attach eBPF programs
  var network_prog = load(network_monitor)
  var security_prog = load(security_monitor)
  
  if (network_prog == null || security_prog == null) {
    print("Failed to load eBPF programs")
    return 1
  }
  
  // Attach programs
  var net_result = attach(network_prog, "eth0", 0)  // Attach XDP to eth0
  var sec_result = attach(security_prog, "sys_openat", 0)  // Attach kprobe to sys_openat
  
  if (net_result != 0 || sec_result != 0) {
    print("Failed to attach eBPF programs")
    return 1
  }
  
  print("eBPF programs loaded and attached successfully")
  print("Starting event processing...")
  print("Press Ctrl+C to stop")
  
  // Start processing ring buffer events using the builtin dispatch() function
  dispatch(network_events, security_events)
  
  return 0
}

// Utility function to get statistics
fn print_stats() -> i32 {
  print("=== Ring Buffer Statistics ===")
  // In a real implementation, would read from stats map
  print("Network events processed: [would read from eBPF map]")
  print("Security events processed: [would read from eBPF map]")
  print("Buffer full events: [would read from eBPF map]")
  return 0
} 