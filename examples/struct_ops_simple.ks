// Test file with impl block struct_ops declarations using the new syntax
// This demonstrates the clean, intuitive impl block approach (Option 1)

// Extracted from BTF
struct tcp_congestion_ops {
    ssthresh: fn(arg: *u8) -> u32,
    cong_avoid: fn(arg: *u8, arg: u32, arg: u32) -> void,
    set_state: fn(arg: *u8, arg: u8) -> void,
    cwnd_event: fn(arg: *u8, arg: u32) -> void,
    in_ack_event: fn(arg: *u8, arg: u32) -> void,
    pkts_acked: fn(arg: *u8, arg: *u8) -> void,
    min_tso_segs: fn(arg: *u8) -> u32,
    cong_control: fn(arg: *u8, arg: u32, arg: u32, arg: *u8) -> void,
    undo_cwnd: fn(arg: *u8) -> u32,
    sndbuf_expand: fn(arg: *u8) -> u32,
    get_info: fn(arg: *u8, arg: u32, arg: *u8, arg: *u8) -> u64,
    name: u8[16],
    owner: *u8,
}

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
    
    // Static metadata fields - these become static data in the struct_ops
    name: "minimal_cc",
    owner: null,
}

// Userspace main function
fn main() -> i32 {
    // Register the impl block directly - much cleaner than struct initialization!
    var result = register(minimal_congestion_control)
    
    return result
} 