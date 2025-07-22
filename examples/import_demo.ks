// Working demo of unified import syntax

// Import KernelScript module (compiled to .so)
import utils from "./import/simple_utils.ks"

// Import Python module (uses Python bridge)
import network_utils from "./import/network_utils.py"

config network {
    enable_filtering: bool = false,
    status_code: u32 = 0,
    packet_count: u32 = 5000,
}

@xdp 
fn intelligent_filter(ctx: *xdp_md) -> xdp_action {
    if (network.enable_filtering) {
        return XDP_DROP
    }
    return XDP_PASS
}

fn main() -> i32 {
    // Use KernelScript imported functions (compiled C binding)
    var is_valid = utils.validate_config()
    var status = utils.get_status()
    
    // Use Python imported functions (Python bridge) - simplified calls
    var mtu = network_utils.get_default_mtu()
    
    print("=== Import Demo Results ===")
    print("KernelScript utils - Config valid: %d, Status: %d", is_valid, status)
    print("Python network_utils - MTU: %d", mtu)
    
    var prog = load(intelligent_filter)
    attach(prog, "eth0", 0)
    return 0
} 
