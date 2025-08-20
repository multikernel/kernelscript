// Test file with impl block struct_ops declarations using the new syntax
// This demonstrates the clean, intuitive impl block approach (Option 1)

include "tcp_congestion_ops.kh"

@struct_ops("tcp_congestion_ops")
impl minimal_congestion_control {
    // Function implementations are directly defined in the impl block
    // These automatically become eBPF functions with SEC("struct_ops/function_name")
    
    fn ssthresh(sk: *u8) -> u32 {
        return 16
    }

    fn cong_avoid(sk: *u8, ack: u32, acked: u32) -> void {
        // Minimal TCP congestion avoidance implementation
        // In a real implementation, this would adjust the congestion window
    }

    fn set_state(sk: *u8, new_state: u8) -> void {
        // Minimal state change handler
        // In a real implementation, this would handle TCP state transitions
    }

    fn cwnd_event(sk: *u8, ev: u32) -> void {
        // Minimal congestion window event handler
        // In a real implementation, this would handle events like slow start, recovery, etc.
    }

    // Optional function implementations (can be omitted for minimal testing)
    // These would be null in the generated struct_ops map
}

// Userspace main function
fn main() -> i32 {
    // Register the impl block directly - much cleaner than struct initialization!
    var result = register(minimal_congestion_control)
    
    return result
} 