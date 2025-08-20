// Example demonstrating local vs shared global variables
//
// This example shows the difference between:
// - Regular global variables (shared with userspace via skeleton)
// - Local global variables (kernel-only, not accessible from userspace)

// Shared global variables - accessible from userspace via skeleton
include "xdp.kh"

var packet_count: u64 = 0
var debug_enabled: bool = true

// Local global variables - kernel-only, not accessible from userspace
local var internal_counter: u32 = 0
local var secret_key: u64 = 0xdeadbeef

@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    // Increment both shared and local counters
    packet_count = packet_count + 1
    internal_counter = internal_counter + 1
    
    // Use secret key for internal processing
    var hash: u64 = secret_key + packet_count
    
    // Debug output (only if enabled from userspace)
    if (debug_enabled) {
        print("Packet processed: %u", packet_count)
    }
    
    return 2  // XDP_PASS
}

fn main() -> i32 {
    var prog = load(packet_filter)
    print("Initial packet_count = %u", packet_count)
    packet_count = 666
    print("After assignment packet_count = %u", packet_count)
    attach(prog, "lo", 0)
    
    print("Local/global vars demo program attached to loopback")
    print("Demonstrating local and global variable scoping...")
    
    // Show variable scoping working
    detach(prog)
    print("Local/global vars demo program detached")
    
    return 0
}