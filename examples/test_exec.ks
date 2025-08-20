// Test exec() builtin with Python integration

// Global maps for sharing with Python
include "xdp.kh"

var packet_stats : array<u32, u64>(256)
var bandwidth_usage : hash<u32, u64>(1024)
var test_map : hash<u32, u32>(100)

@helper
fn get_packet_size() -> u32 {
    return 64 // Demo packet size
}

@xdp fn packet_monitor(ctx: *xdp_md) -> xdp_action {
    var size = get_packet_size()
    var bucket = size / 64
    if (bucket < 256) {
        packet_stats[bucket] += 1
    }
    
    var interface = ctx->ingress_ifindex
    var size_u64: u64 = size
    bandwidth_usage[interface] += size_u64
    
    return XDP_PASS
}

fn main() -> i32 {
    var prog = load(packet_monitor)
    var result = attach(prog, "lo", 0)
    
    if (result == 0) {
        print("eBPF program attached successfully")
        print("Switching to Python for data analysis...")
        
        // Replace current process with Python - never returns
        exec("./python_demo.py")
    } else {
        print("Failed to attach eBPF program")
        return 1
    }
    
    return 0
}
