// Example demonstrating @test functions for eBPF program testing

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

// Test context structures for different program types
struct XdpTestContext {
  packet_size: u32,
  interface_id: u32,
  expected_action: u32,
}

// Simple packet filter to test
@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
  var packet_size = ctx->data_end - ctx->data
  
  // Drop packets larger than 1000 bytes
  if (packet_size > 1000) {
    return XDP_DROP
  }
  
  // Pass smaller packets
  return XDP_PASS
}

// Test functions using @test attribute
@test
fn test_small_packet() -> i32 {
  // Create test context for small packet
  var test_ctx = XdpTestContext {
    packet_size: 500,        // Small packet
    interface_id: 1,
    expected_action: 2,      // XDP_PASS
  }
  
  // Test the packet filter with small packet
  var result = test(packet_filter, test_ctx)
  
  if (result == 2) {  // XDP_PASS
    print("✅ Small packet test passed")
    return 0
  } else {
    print("❌ Small packet test failed: expected %d, got %d", 2, result)
    return 1
  }
}

@test
fn test_large_packet() -> i32 {
  // Create test context for large packet  
  var test_ctx = XdpTestContext {
    packet_size: 1200,        // Large packet
    interface_id: 1,
    expected_action: 1,       // XDP_DROP
  }
  
  // Test the packet filter with large packet
  var result = test(packet_filter, test_ctx)
  
  if (result == 1) {  // XDP_DROP
    print("✅ Large packet test passed")
    return 0
  } else {
    print("❌ Large packet test failed: expected %d, got %d", 1, result)
    return 1
  }
}

// This main function will be ignored in test mode
fn main() -> i32 {
  var prog = load(packet_filter)
  attach(prog, "eth0", 0)
  return 0
} 