// Test KernelScript file demonstrating config system

config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
    blocked_ports: [u16; 4] = [22, 23, 135, 445],
}

config security {
    threat_level: u32 = 1,
    enable_strict_mode: bool = false,
    max_connections: u64 = 1000,
}

map<u32, u64> packet_stats : HashMap(1024);

program packet_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        // Use network config
        if network.max_packet_size > 1000 {
            if network.enable_logging {
                return 1;  // XDP_DROP
            }
        }
        
        // Use security config  
        if security.threat_level > 2 {
            return 1;  // XDP_DROP
        }
        
        // Update stats
        packet_stats[0] = 1;
        
        return 2;  // XDP_PASS
    }
}

userspace {
    fn main(argc: u32, argv: u64) -> i32 {
        return 0;
    }
} 