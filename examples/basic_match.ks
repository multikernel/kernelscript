// Basic Match Construct Demo for KernelScript
// Demonstrates packet matching with the new match construct

// XDP context struct (from BTF)
struct xdp_md {
  data: u64,
  data_end: u64,
  data_meta: u64,
  ingress_ifindex: u32,
  rx_queue_index: u32,
  egress_ifindex: u32,
}

// XDP action enum (from BTF)
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP = 1,
  XDP_PASS = 2,
  XDP_REDIRECT = 3,
  XDP_TX = 4,
}

// Protocol constants
enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17
}

// Helper functions for packet processing (declared first)
@helper
fn get_ip_protocol(ctx: *xdp_md) -> u32 {
    // In a real implementation, this would extract the protocol field
    // from the IP header. For demo purposes, we return TCP.
    return 6 // IPPROTO_TCP
}

@helper  
fn get_tcp_dest_port(ctx: *xdp_md) -> u32 {
    // In a real implementation, this would extract the destination port
    // from the TCP header. For demo purposes, we return HTTP.
    return 80 // HTTP port
}

@helper
fn get_udp_dest_port(ctx: *xdp_md) -> u32 {
    // In a real implementation, this would extract the destination port
    // from the UDP header. For demo purposes, we return DNS.
    return 53 // DNS port
}

// Specialized TCP port-based classifier (tail-callable)
@xdp
fn tcp_port_classifier(ctx: *xdp_md) -> xdp_action {
    var port = get_tcp_dest_port(ctx)
    
    return match (port) {
        80: XDP_PASS,       // Allow HTTP
        443: XDP_PASS,      // Allow HTTPS  
        22: XDP_PASS,       // Allow SSH
        21: XDP_DROP,       // Block FTP for security
        23: XDP_DROP,       // Block Telnet (insecure)
        default: XDP_PASS   // Allow other TCP ports by default
    }
}

// Specialized UDP port-based classifier (tail-callable)
@xdp  
fn udp_port_classifier(ctx: *xdp_md) -> xdp_action {
    var port = get_udp_dest_port(ctx)
    
    return match (port) {
        53: XDP_PASS,       // Allow DNS
        123: XDP_PASS,      // Allow NTP
        161: XDP_DROP,      // Block SNMP (security risk)
        69: XDP_DROP,       // Block TFTP (insecure)
        default: XDP_PASS   // Allow other UDP ports by default
    }
}

// Main packet classifier using match construct with tail call delegation
@xdp
fn packet_classifier(ctx: *xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    
    // Match construct provides clean protocol-based delegation
    return match (protocol) {
        TCP: tcp_port_classifier(ctx),    // Tail call to TCP specialist 
        UDP: udp_port_classifier(ctx),    // Tail call to UDP specialist
        ICMP: XDP_DROP,                   // Drop ICMP for security  
        default: XDP_ABORTED              // Abort unknown protocols
    }
}

fn main() -> i32 {
    var prog = load(packet_classifier)
    attach(prog, "lo", 0)
    
    print("Packet classifier attached to loopback interface")
    print("Processing packets with pattern matching...")
    
    // In a real application, the program would run here
    // For demonstration, we detach after showing the lifecycle
    detach(prog)
    print("Packet classifier detached")
    
    return 0
}

 