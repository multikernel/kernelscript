// Basic Match Construct Demo for KernelScript
// Demonstrates packet matching with the new match construct

// Protocol constants
enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17
}

// Helper functions for packet processing (declared first)
@helper
fn get_ip_protocol(ctx: xdp_md) -> u32 {
    // In a real implementation, this would extract the protocol field
    // from the IP header. For demo purposes, we return TCP.
    return 6 // IPPROTO_TCP
}

@helper  
fn get_tcp_dest_port(ctx: xdp_md) -> u32 {
    // In a real implementation, this would extract the destination port
    // from the TCP header. For demo purposes, we return HTTP.
    return 80 // HTTP port
}

@helper
fn get_udp_dest_port(ctx: xdp_md) -> u32 {
    // In a real implementation, this would extract the destination port
    // from the UDP header. For demo purposes, we return DNS.
    return 53 // DNS port
}

// Basic packet classifier using match construct
@xdp
fn packet_classifier(ctx: xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    
    // Match construct provides clean packet classification
    return match (protocol) {
        TCP: XDP_PASS,          // Allow TCP traffic
        UDP: XDP_PASS,          // Allow UDP traffic  
        ICMP: XDP_DROP,         // Drop ICMP for security
        default: XDP_ABORTED    // Abort unknown protocols
    }
}

// TCP port-based classifier  
@xdp
fn tcp_port_classifier(ctx: xdp_md) -> xdp_action {
    var port = get_tcp_dest_port(ctx)
    
    return match (port) {
        80: XDP_PASS,       // Allow HTTP
        443: XDP_PASS,      // Allow HTTPS  
        22: XDP_PASS,       // Allow SSH
        21: XDP_DROP,       // Block FTP
        default: XDP_PASS   // Allow other TCP ports
    }
}

// UDP port-based classifier
@xdp  
fn udp_port_classifier(ctx: xdp_md) -> xdp_action {
    var port = get_udp_dest_port(ctx)
    
    return match (port) {
        53: XDP_PASS,       // Allow DNS
        123: XDP_PASS,      // Allow NTP
        161: XDP_DROP,      // Block SNMP
        default: XDP_PASS   // Allow other UDP ports
    }
}

 