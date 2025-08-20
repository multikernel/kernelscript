// Ring Buffer on_event() Demo
// Shows how to register event handlers for ring buffers

include "xdp.kh"

struct NetworkEvent {
  src_ip: u32,
  dst_ip: u32,
  packet_size: u16,
  protocol: u8,
}

struct SecurityEvent {
  event_type: u32,
  severity: u8,
  timestamp: u64,
}

// Ring buffer declarations
var network_events : ringbuf<NetworkEvent>(4096)
var security_events : ringbuf<SecurityEvent>(8192)

@xdp fn network_monitor(ctx: *xdp_md) -> xdp_action {
  var reserved = network_events.reserve()
  network_events.submit(reserved)
  return XDP_PASS
}

@probe("sys_openat")
fn security_monitor(dfd: i32, filename: *u8, flags: i32, mode: u16) -> i32 {
  var reserved = security_events.reserve()
  security_events.submit(reserved)
  return 0
}

// Event handler functions
fn handle_network_event(event: *NetworkEvent) -> i32 {
  print("Network event received")
  return 0
}

fn handle_security_event(event: *SecurityEvent) -> i32 {
  print("Security event received")
  return 0
}

fn main() -> i32 {
  print("Starting ring buffer on_event demo")
  
  // Register event handlers with ring buffers
  network_events.on_event(handle_network_event)
  security_events.on_event(handle_security_event)
  
  // Load and attach programs
  var net_prog = load(network_monitor)
  var sec_prog = load(security_monitor)
  
  // Start event processing for both ring buffers
  dispatch(network_events, security_events)
  
  return 0
} 