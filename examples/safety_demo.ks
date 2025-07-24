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

// This file demonstrates the memory safety analysis capabilities

// Type aliases for clarity
type PacketSize = u16
type Counter = u64

// Struct with reasonable size
struct PacketInfo {
  src_ip: u32,
  dst_ip: u32,
  protocol: u8,
  size: PacketSize,
}

// Global map for statistics
pin var packet_stats : HashMap<u32, Counter>(1024)

// Kernel-shared functions accessible by all eBPF programs
@helper
fn safe_function(ctx: *xdp_md) -> xdp_action {
  // Small local variables - safe stack usage
  var counter: u64 = 0
  var packet_size: u16 = 1500
  var protocol: u8 = 6 // TCP
  
  // Safe array access
  var small_buffer: u8[64] = [0]
  small_buffer[10] = protocol // Safe: index 10 < 64
  
  // Safe map operations
  packet_stats[1] = counter
  
  return XDP_PASS
}

// Function demonstrating bounds checking
@helper
fn bounds_demo(ctx: *xdp_md) -> xdp_action {
  var data_array: u32[10] = [0]
  
  // Safe accesses
  data_array[0] = 42   // OK: index 0
  data_array[9] = 100  // OK: index 9 (last valid)
  
  // The following would be caught by bounds checking:
  // data_array[10] = 200 // ERROR: index 10 >= size 10
  // data_array[-1] = 300 // ERROR: negative index
  
  return XDP_PASS
}

// Function with moderate stack usage
@helper
fn moderate_stack_usage(ctx: *xdp_md) -> xdp_action {
  // Moderate buffer size - should be within eBPF limits
  var buffer: u8[256] = [0]
  var info: PacketInfo = PacketInfo {
    src_ip: 0,
    dst_ip: 0,
    protocol: 0,
    size: 0
  }
  
  // Process data
  buffer[0] = info.protocol
  
  return XDP_PASS
}

// Function that would trigger stack overflow warning
@helper
fn large_stack_usage(ctx: *xdp_md) -> xdp_action {
  // Large buffer - would exceed eBPF 512-byte stack limit
  // This would be flagged by the safety analyzer
  var large_buffer: u8[600] = [0] // WARNING: Stack overflow
  
  large_buffer[0] = 1
  
  return XDP_PASS
}

// Function demonstrating array size validation
@helper
fn array_validation_demo(ctx: *xdp_md) -> xdp_action {
  // Valid array sizes
  var valid_small: u32[10] = [0]     // OK
  var valid_medium: u8[100] = [0]   // OK
  
  valid_small[5] = 42
  valid_medium[50] = 255
  
  return XDP_PASS
}

// Program with various safety scenarios
@xdp fn safety_demo(ctx: *xdp_md) -> xdp_action {
  // Stack usage: minimal for main function
  var result: xdp_action = XDP_PASS
  
  // Call safe functions
  safe_function(ctx)
  bounds_demo(ctx)
  moderate_stack_usage(ctx)
  
  // The following call would trigger warnings:
  // let _ = large_stack_usage(ctx) // Stack overflow warning
  
  // Safe map access
  var key: u32 = 1
  var count = packet_stats[key]
  if (count != none) {
    packet_stats[key] = count + 1
  } else {
    packet_stats[key] = 1
  }
  
  return result
}

// Safety Analysis Summary:
// 
// Stack Usage Analysis:
// - safe_function: ~80 bytes (safe)
// - bounds_demo: ~40 bytes (safe) 
// - moderate_stack_usage: ~280 bytes (safe)
// - large_stack_usage: ~600 bytes (WARNING: exceeds 512-byte limit)
// - main: ~20 bytes (safe)
//
// Bounds Checking:
// - All array accesses are validated at compile time
// - Out-of-bounds accesses are detected and reported
// - Array size validation prevents invalid declarations
//
// Memory Safety:
// - No pointer arithmetic (inherently safe)
// - Automatic bounds checking for all array operations
// - Stack overflow detection for large local variables
// - Map access validation ensures type safety
//
// eBPF Compliance:
// - Stack usage tracking ensures eBPF 512-byte limit compliance
// - Array sizes are validated against practical limits
// - Map operations follow eBPF semantics and constraints 