// Minimal Tail Call Demo
// Shows both regular kernel function calls and actual eBPF tail calls

// KERNEL FUNCTION - can be called normally from eBPF programs
@helper
fn validate_packet(size: u32) -> bool {
    return size >= 64 && size <= 1500
}

// ATTRIBUTED FUNCTION - for tail calls (same signature as main function)
@xdp fn drop_handler(ctx: XdpContext) -> XdpAction {
    return 0  // XDP_DROP
}

// MAIN eBPF PROGRAM - demonstrates both call types
@xdp fn packet_filter(ctx: XdpContext) -> XdpAction {
    let packet_size: u32 = 128
    
    // REGULAR CALL
    if (!validate_packet(packet_size)) {
        
        // TAIL CALL
        return drop_handler(ctx)
    }
    
    return 2  // XDP_PASS - direct return
}

fn main() -> i32 {
    let prog = load(packet_filter)
    attach(prog, "lo", 0)
    return 0
}
