// This file demonstrates the memory safety analysis capabilities

// Type aliases for clarity
type PacketSize = u16;
type Counter = u64;

// Struct with reasonable size
struct PacketInfo {
  src_ip: u32;
  dst_ip: u32;
  protocol: u8;
  size: PacketSize;
}

// Global map for statistics
map<u32, Counter> packet_stats : HashMap(1024) {
  pinned: "/sys/fs/bpf/packet_stats",
}

// Program with various safety scenarios
program safety_demo : xdp {
  
  // Function with safe stack usage
  fn safe_function(ctx: XdpContext) -> XdpAction {
    // Small local variables - safe stack usage
    let counter: u64 = 0;
    let packet_size: u16 = 1500;
    let protocol: u8 = 6; // TCP
    
    // Safe array access
    let small_buffer: [u8; 64] = [0; 64];
    small_buffer[10] = protocol; // Safe: index 10 < 64
    
    // Safe map operations
    packet_stats[1] = counter;
    
    return XDP_PASS;
  }
  
  // Function demonstrating bounds checking
  fn bounds_demo(ctx: XdpContext) -> XdpAction {
    let data_array: [u32; 10] = [0; 10];
    
    // Safe accesses
    data_array[0] = 42;   // OK: index 0
    data_array[9] = 100;  // OK: index 9 (last valid)
    
    // The following would be caught by bounds checking:
    // data_array[10] = 200; // ERROR: index 10 >= size 10
    // data_array[-1] = 300; // ERROR: negative index
    
    return XDP_PASS;
  }
  
  // Function with moderate stack usage
  fn moderate_stack_usage(ctx: XdpContext) -> XdpAction {
    // Moderate buffer size - should be within eBPF limits
    let buffer: [u8; 256] = [0; 256];
    let info: PacketInfo = PacketInfo {
      src_ip: 0,
      dst_ip: 0,
      protocol: 0,
      size: 0
    };
    
    // Process data
    buffer[0] = info.protocol;
    
    return XDP_PASS;
  }
  
  // Function that would trigger stack overflow warning
  fn large_stack_usage(ctx: XdpContext) -> XdpAction {
    // Large buffer - would exceed eBPF 512-byte stack limit
    // This would be flagged by the safety analyzer
    let large_buffer: [u8; 600] = [0; 600]; // WARNING: Stack overflow
    
    large_buffer[0] = 1;
    
    return XDP_PASS;
  }
  
  // Function demonstrating array size validation
  fn array_validation_demo(ctx: XdpContext) -> XdpAction {
    // Valid array sizes
    let valid_small: [u32; 10] = [0; 10];     // OK
    let valid_medium: [u8; 100] = [0; 100];   // OK
    
    // The following would be caught by validation:
    // let invalid_negative: [u32; -1] = [0; -1];  // ERROR: Negative size
    // let invalid_zero: [u32; 0] = [0; 0];        // ERROR: Zero size
    // let too_large: [u8; 2000] = [0; 2000];      // WARNING: Too large for stack
    
    valid_small[5] = 42;
    valid_medium[50] = 255;
    
    return XDP_PASS;
  }
  
  // Main function with comprehensive safety checks
  fn main(ctx: XdpContext) -> XdpAction {
    // Stack usage: minimal for main function
    let result: XdpAction = XDP_PASS;
    
    // Call safe functions
    let _ = safe_function(ctx);
    let _ = bounds_demo(ctx);
    let _ = moderate_stack_usage(ctx);
    
    // The following call would trigger warnings:
    // let _ = large_stack_usage(ctx); // Stack overflow warning
    
    // Safe map access
    let key: u32 = 1;
    let count = packet_stats[key];
    if count != null {
      packet_stats[key] = count + 1;
    } else {
      packet_stats[key] = 1;
    }
    
    return result;
  }
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