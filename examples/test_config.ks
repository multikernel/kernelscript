// Test KernelScript file demonstrating config system

config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
    blocked_ports: u16[4] = [22, 23, 135, 445],
}

map<u32, u64> packet_stats : HashMap(1024)

@xdp fn packet_filter(ctx: xdp_md) -> xdp_action {
    // Use network config
    if (network.max_packet_size > 1000) {
        if (network.enable_logging) {
            print("Dropping big packets")
            return XDP_DROP
        }
    }
    
    // Update stats
    packet_stats[0] = 1
    
    return XDP_PASS
}

// Userspace coordination (no wrapper)
struct Args {
    enable_debug: u32,
    interface: str<16>
}

fn main(args: Args) -> i32 {
    // Enable logging if debug mode is enabled
    if (args.enable_debug > 0) {
        network.enable_logging = true
    }
    let prog = load(packet_filter)
    attach(prog, args.interface, 0)
    return 0
} 
