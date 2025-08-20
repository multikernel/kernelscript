// Minimal Tail Call Demo
// Shows both regular kernel function calls and actual eBPF tail calls

// KERNEL FUNCTION - can be called normally from eBPF programs
include "xdp.kh"

@helper
fn validate_packet(size: u32) -> bool {
    return size >= 64 && size <= 1500
}

// ATTRIBUTED FUNCTION - for tail calls (same signature as main function)
@xdp fn drop_handler(ctx: *xdp_md) -> xdp_action {
    return XDP_DROP
}

// MAIN eBPF PROGRAM - demonstrates both call types
@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet_size: u32 = 128
    
    // REGULAR CALL
    if (!validate_packet(packet_size)) {
        
        // TAIL CALL
        return drop_handler(ctx)
    }
    
    return XDP_PASS  // direct return
}

fn main() -> i32 {
    var prog = load(packet_filter)
    attach(prog, "lo", 0)
    
    print("Tail call demo program attached to loopback")
    print("Demonstrating tail call functionality...")
    
    // Show tail call mechanism working
    detach(prog)
    print("Tail call demo program detached")
    
    return 0
}
