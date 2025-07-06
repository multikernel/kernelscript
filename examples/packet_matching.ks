// Packet Matching Demo - KernelScript Match Construct
//
// This example demonstrates the powerful match construct for packet processing,
// which is a killer feature for eBPF programming. The match construct provides
// clean, efficient, and readable packet classification.
//

// Protocol constants for packet classification
enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    GRE = 47,
    ESP = 50,
    AH = 51,
    SCTP = 132
}

// XDP action constants for packet disposition
enum PacketAction {
    PASS = 2,
    DROP = 1,
    REDIRECT = 4,
    ABORTED = 0
}

// TCP port classification
enum WellKnownPorts {
    HTTP = 80,
    HTTPS = 443,
    SSH = 22,
    FTP = 21,
    SMTP = 25,
    DNS = 53
}

// Basic packet classifier using match construct
// This demonstrates the clean syntax for protocol-based decisions
@xdp
fn basic_packet_classifier(ctx: xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    
    // Match construct provides clean packet classification
    return match (protocol) {
        TCP: XDP_PASS,          // Allow TCP traffic
        UDP: XDP_PASS,          // Allow UDP traffic  
        ICMP: XDP_DROP,         // Drop ICMP for security
        SCTP: XDP_PASS,         // Allow SCTP
        default: XDP_ABORTED    // Abort unknown protocols
    }
}

// Advanced packet classifier with port-based filtering
// Demonstrates nested decision making with match constructs
@xdp
fn advanced_packet_classifier(ctx: xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    
    return match (protocol) {
        TCP: {
            var port = get_tcp_dest_port(ctx)
            return match (port) {
                HTTP: XDP_PASS,     // Allow HTTP
                HTTPS: XDP_PASS,    // Allow HTTPS  
                SSH: XDP_PASS,      // Allow SSH
                FTP: XDP_DROP,      // Block FTP (legacy)
                default: XDP_PASS   // Allow other TCP
            }
        },
        
        UDP: {
            var port = get_udp_dest_port(ctx);
            return match (port) {
                DNS: XDP_PASS,      // Allow DNS
                53: XDP_PASS,       // Allow DNS (alternative)
                default: XDP_PASS   // Allow other UDP
            }
        },
        
        ICMP: XDP_DROP,         // Security: drop ICMP
        default: XDP_ABORTED    // Unknown protocols
    }
}

// DDoS protection using match construct
// Shows how match simplifies complex security logic
@xdp
fn ddos_protection(ctx: xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    var src_ip = get_src_ip(ctx)
    
    // First level: protocol-based filtering
    var protocol_action = match (protocol) {
        TCP: {
            var flags = get_tcp_flags(ctx);
            // TCP SYN flood protection
            return match (flags) {
                0x02: rate_limit_syn(src_ip),  // SYN only
                default: XDP_PASS
            }
        },
        
        UDP: {
            var port = get_udp_dest_port(ctx)
            // UDP flood protection for specific ports
            return match (port) {
                DNS: rate_limit_dns(src_ip),
                default: XDP_PASS
            }
        },
        
        ICMP: {
            var icmp_type = get_icmp_type(ctx)
            // ICMP flood protection
            return match (icmp_type) {
                8: rate_limit_ping(src_ip),    // Echo request
                default: XDP_DROP              // Other ICMP
            }
        },
        
        default: XDP_PASS
    }
    
    return protocol_action
}

// Load balancer using match for backend selection
// Demonstrates match for algorithmic packet distribution
@xdp
fn load_balancer(ctx: xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    
    // Only load balance specific protocols
    return match (protocol) {
        TCP: {
            var port = get_tcp_dest_port(ctx)
            return match (port) {
                HTTP: distribute_http(ctx),
                HTTPS: distribute_https(ctx),
                default: XDP_PASS
            }
        },
        
        UDP: {
            var port = get_udp_dest_port(ctx)
            return match (port) {
                DNS: distribute_dns(ctx),
                default: XDP_PASS
            }
        },
        
        default: XDP_PASS
    }
}

// Packet logging and monitoring
// Shows match for categorizing packets for observability
@xdp  
fn packet_monitor(ctx: xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    var src_ip = get_src_ip(ctx)
    var dst_ip = get_dst_ip(ctx)
    
    // Categorize and log based on protocol
    var log_category = match (protocol) {
        TCP: {
            var port = get_tcp_dest_port(ctx);
            return match (port) {
                HTTP: "web_traffic",
                HTTPS: "secure_web", 
                SSH: "admin_access",
                default: "tcp_other"
            }
        },
        
        UDP: {
            var port = get_udp_dest_port(ctx);
            return match (port) {
                DNS: "dns_query",
                default: "udp_other"
            }
        },
        
        ICMP: "icmp_traffic",
        default: "unknown_protocol"
    }
    
    // Log the packet with category
    print("PKT: %s %u->%u\n", log_category, src_ip, dst_ip)
    
    return XDP_PASS
}

// Quality of Service (QoS) packet marking
// Demonstrates match for traffic prioritization
@tc
fn qos_packet_marker(ctx: TcContext) -> TcAction {
    var protocol = get_ip_protocol_tc(ctx)
    
    // Set QoS markings based on traffic type
    var qos_class = match (protocol) {
        TCP: {
            var port = get_tcp_dest_port_tc(ctx)
            return match (port) {
                SSH: "high_priority",      // Admin traffic
                HTTPS: "medium_priority",  // Web traffic
                HTTP: "medium_priority",   // Web traffic
                default: "low_priority"
            }
        },
        
        UDP: {
            var port = get_udp_dest_port_tc(ctx)
            return match (port) {
                DNS: "high_priority",      // DNS is critical
                default: "low_priority"
            }
        },
        
        ICMP: "low_priority",      // ICMP is low priority
        default: "default_priority"
    }
    
    // Apply QoS marking (implementation depends on system)
    set_qos_mark(ctx, qos_class)
    
    return TC_ACT_OK
}

// Firewall rule engine using match construct
// Shows complex security policy implementation
@xdp
fn firewall_engine(ctx: xdp_md) -> xdp_action {
    var src_ip = get_src_ip(ctx)
    var protocol = get_ip_protocol(ctx)
    
    // Check if source is in blocklist
    if (is_blocked_ip(src_ip)) {
        return XDP_DROP
    }
    
    // Protocol-based firewall rules
    return match (protocol) {
        TCP: {
            var port = get_tcp_dest_port(ctx)
            var flags = get_tcp_flags(ctx)
            
            return match (port) {
                22: {  // SSH port
                    // Allow SSH but check source
                    return match (is_admin_network(src_ip)) {
                        true: XDP_PASS,
                        false: XDP_DROP
                    }
                },
                
                80: XDP_PASS,           // Allow HTTP
                443: XDP_PASS,          // Allow HTTPS
                25: XDP_DROP,           // Block SMTP
                23: XDP_DROP,           // Block Telnet
                default: {
                    // For unknown ports, check if it's a SYN flood
                    return match (flags) {
                        0x02: rate_limit_unknown_syn(src_ip),
                        default: XDP_PASS
                    }
                }
            }
        },
        
        UDP: {
            var port = get_udp_dest_port(ctx);
            return match (port) {
                53: XDP_PASS,           // Allow DNS
                123: XDP_PASS,          // Allow NTP
                161: XDP_DROP,          // Block SNMP
                default: XDP_PASS
            }
        },
        
        ICMP: {
            var icmp_type = get_icmp_type(ctx);
            return match (icmp_type) {
                8: rate_limit_ping(src_ip),     // Rate limit ping
                default: XDP_DROP               // Drop other ICMP
            }
        },
        
        default: XDP_DROP  // Deny unknown protocols
    }
}

// Helper functions (would be implemented separately)
// These demonstrate the ecosystem around match-based packet processing

@helper
fn get_ip_protocol(ctx: xdp_md) -> u32 {
    // Extract IP protocol field from packet
    return 6 // Mock: return TCP
}

@helper  
fn get_tcp_dest_port(ctx: xdp_md) -> u32 {
    // Extract TCP destination port
    return 80 // Mock: return HTTP port
}

@helper
fn get_udp_dest_port(ctx: xdp_md) -> u32 {
    // Extract UDP destination port  
    return 53 // Mock: return DNS port
}

@helper
fn get_tcp_flags(ctx: xdp_md) -> u32 {
    // Extract TCP flags
    return 0x02 // Mock: return SYN flag
}

@helper
fn get_icmp_type(ctx: xdp_md) -> u32 {
    // Extract ICMP type
    return 8 // Mock: return echo request
}

@helper
fn get_src_ip(ctx: xdp_md) -> u32 {
    // Extract source IP address
    return 0xc0a80101 // Mock: return 192.168.1.1
}

@helper
fn get_dst_ip(ctx: xdp_md) -> u32 {
    // Extract destination IP address  
    return 0xc0a80102 // Mock: return 192.168.1.2
}

// Rate limiting functions
@helper fn rate_limit_syn(ip: u32) -> xdp_action { return XDP_PASS }
@helper fn rate_limit_dns(ip: u32) -> xdp_action { return XDP_PASS }  
@helper fn rate_limit_ping(ip: u32) -> xdp_action { return XDP_PASS }
@helper fn rate_limit_unknown_syn(ip: u32) -> xdp_action { return XDP_PASS }

// Load balancing functions
@helper fn distribute_http(ctx: xdp_md) -> xdp_action { return XDP_PASS }
@helper fn distribute_https(ctx: xdp_md) -> xdp_action { return XDP_PASS }
@helper fn distribute_dns(ctx: xdp_md) -> xdp_action { return XDP_PASS }

// Security check functions  
@helper fn is_blocked_ip(ip: u32) -> bool { return false }
@helper fn is_admin_network(ip: u32) -> bool { return true }

// TC-specific helper functions
@helper fn get_ip_protocol_tc(ctx: TcContext) -> u32 { return 6 }
@helper fn get_tcp_dest_port_tc(ctx: TcContext) -> u32 { return 80 }
@helper fn get_udp_dest_port_tc(ctx: TcContext) -> u32 { return 53 }
@helper fn set_qos_mark(ctx: TcContext, class: str<16>) -> void { }

// Summary:
// 
// This example demonstrates why match constructs are a killer feature
// for eBPF packet processing:
// 
// 1. **Readability**: Clean, structured code that's easy to understand
// 2. **Performance**: Compiles to efficient if-else chains (eBPF) or switch statements (userspace)
// 3. **Maintainability**: Easy to add new protocols and ports
// 4. **Type Safety**: Ensures all cases return compatible types
// 5. **Expressiveness**: Natural way to express packet classification logic
// 
// The match construct makes KernelScript ideal for:
// - Firewalls and security appliances
// - Load balancers and traffic distributors  
// - DDoS protection systems
// - Network monitoring and analytics
// - Quality of Service (QoS) engines
// - Protocol analyzers and packet classifiers 