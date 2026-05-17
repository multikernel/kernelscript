// Packet Matching Demo - KernelScript Match Construct
//
// This example demonstrates the powerful match construct for packet processing,
// which is a killer feature for eBPF programming. The match construct provides
// clean, efficient, and readable packet classification.
//

// TC context struct (from BTF)
include "xdp.kh"
include "tc.kh"

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

// TCP port classification
enum WellKnownPorts {
    HTTP = 80,
    HTTPS = 443,
    SSH = 22,
    FTP = 21,
    SMTP = 25,
    DNS = 53
}

// Helper functions - defined first to be available to all main functions
// These demonstrate the ecosystem around match-based packet processing

@helper
fn get_ip_protocol(ctx: *xdp_md) -> u32 {
    // Extract IP protocol field from packet
    return 6 // Mock: return TCP
}

@helper  
fn get_tcp_dest_port(ctx: *xdp_md) -> u32 {
    // Extract TCP destination port
    return 80 // Mock: return HTTP port
}

@helper
fn get_udp_dest_port(ctx: *xdp_md) -> u32 {
    // Extract UDP destination port  
    return 53 // Mock: return DNS port
}

@helper
fn get_tcp_flags(ctx: *xdp_md) -> u32 {
    // Extract TCP flags
    return 0x02 // Mock: return SYN flag
}

@helper
fn get_icmp_type(ctx: *xdp_md) -> u32 {
    // Extract ICMP type
    return 8 // Mock: return echo request
}

@helper
fn get_src_ip(ctx: *xdp_md) -> u32 {
    // Extract source IP address
    return 0xc0a80101 // Mock: return 192.168.1.1
}

@helper
fn get_dst_ip(ctx: *xdp_md) -> u32 {
    // Extract destination IP address  
    return 0xc0a80102 // Mock: return 192.168.1.2
}

// Rate limiting functions
@helper fn rate_limit_syn(ip: u32) -> xdp_action { return XDP_PASS }
@helper fn rate_limit_dns(ip: u32) -> xdp_action { return XDP_PASS }  
@helper fn rate_limit_ping(ip: u32) -> xdp_action { return XDP_PASS }
@helper fn rate_limit_unknown_syn(ip: u32) -> xdp_action { return XDP_PASS }

// Load balancing functions
@helper fn distribute_http(ctx: *xdp_md) -> xdp_action { return XDP_PASS }
@helper fn distribute_https(ctx: *xdp_md) -> xdp_action { return XDP_PASS }
@helper fn distribute_dns(ctx: *xdp_md) -> xdp_action { return XDP_PASS }

// Security check functions  
@helper fn is_blocked_ip(ip: u32) -> bool { return false }
@helper fn is_admin_network(ip: u32) -> bool { return true }

// TC-specific helper functions
@helper fn get_ip_protocol_tc(ctx: *__sk_buff) -> u32 { return 6 }
@helper fn get_tcp_dest_port_tc(ctx: *__sk_buff) -> u32 { return 80 }
@helper fn get_udp_dest_port_tc(ctx: *__sk_buff) -> u32 { return 53 }
@helper fn set_qos_mark(ctx: *__sk_buff, class: str(16)) -> void { }

// Main packet processing functions using match constructs

// Basic packet classifier using match construct
// This demonstrates the clean syntax for protocol-based decisions
@xdp
fn basic_packet_classifier(ctx: *xdp_md) -> xdp_action {
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
// Demonstrates nested decision making with match constructs.
//
// Note on outer dispatch: protocol dispatch is written as `if (protocol == X)`
// rather than `match (protocol) { X: { var p = ...; match (p) {...} } }` because
// the codegen doesn't yet support `var` declarations inside match arm blocks -
// the initializer is silently dropped during IR lowering, leaving the variable
// uninitialized at use sites. The same workaround is applied throughout this
// file; inner matches operating on the now-enclosing-scope variable work fine.
@xdp
fn advanced_packet_classifier(ctx: *xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)

    if (protocol == TCP) {
        var tcp_port = get_tcp_dest_port(ctx)
        return match (tcp_port) {
            HTTP: XDP_PASS,
            HTTPS: XDP_PASS,
            SSH: XDP_PASS,
            FTP: XDP_DROP,      // Block FTP (legacy)
            default: XDP_PASS
        }
    } else if (protocol == UDP) {
        var udp_port = get_udp_dest_port(ctx)
        return match (udp_port) {
            DNS: XDP_PASS,
            53: XDP_PASS,       // Alternative DNS spelling
            default: XDP_PASS
        }
    } else if (protocol == ICMP) {
        return XDP_DROP         // Security: drop ICMP
    } else {
        return XDP_ABORTED      // Unknown protocols
    }
}

// DDoS protection using match construct
// Shows how match simplifies complex security logic
@xdp
fn ddos_protection(ctx: *xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    var src_ip = get_src_ip(ctx)

    if (protocol == TCP) {
        var flags = get_tcp_flags(ctx)
        // TCP SYN flood protection
        return match (flags) {
            0x02: rate_limit_syn(src_ip),  // SYN only
            default: XDP_PASS
        }
    } else if (protocol == UDP) {
        var udp_port = get_udp_dest_port(ctx)
        // UDP flood protection for specific ports
        return match (udp_port) {
            DNS: rate_limit_dns(src_ip),
            default: XDP_PASS
        }
    } else if (protocol == ICMP) {
        var icmp_type = get_icmp_type(ctx)
        // ICMP flood protection
        return match (icmp_type) {
            8: rate_limit_ping(src_ip),    // Echo request
            default: XDP_DROP              // Other ICMP
        }
    } else {
        return XDP_PASS
    }
}

// Load balancer using match for backend selection
// Demonstrates match for algorithmic packet distribution
@xdp
fn load_balancer(ctx: *xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)

    if (protocol == TCP) {
        var tcp_port = get_tcp_dest_port(ctx)
        return match (tcp_port) {
            HTTP: distribute_http(ctx),
            HTTPS: distribute_https(ctx),
            default: XDP_PASS
        }
    } else if (protocol == UDP) {
        var udp_port = get_udp_dest_port(ctx)
        return match (udp_port) {
            DNS: distribute_dns(ctx),
            default: XDP_PASS
        }
    } else {
        return XDP_PASS
    }
}

// Packet logging and monitoring
// Shows match for categorizing packets for observability
@xdp
fn packet_monitor(ctx: *xdp_md) -> xdp_action {
    var protocol = get_ip_protocol(ctx)
    var src_ip = get_src_ip(ctx)
    var dst_ip = get_dst_ip(ctx)

    if (protocol == TCP) {
        var tcp_port = get_tcp_dest_port(ctx)
        match (tcp_port) {
            HTTP: {
                print("PKT: web_traffic %u->%u\n", src_ip, dst_ip)
            },
            HTTPS: {
                print("PKT: secure_web %u->%u\n", src_ip, dst_ip)
            },
            SSH: {
                print("PKT: admin_access %u->%u\n", src_ip, dst_ip)
            },
            default: {
                print("PKT: tcp_other %u->%u\n", src_ip, dst_ip)
            }
        }
    } else if (protocol == UDP) {
        var udp_port = get_udp_dest_port(ctx)
        match (udp_port) {
            DNS: {
                print("PKT: dns_query %u->%u\n", src_ip, dst_ip)
            },
            default: {
                print("PKT: udp_other %u->%u\n", src_ip, dst_ip)
            }
        }
    } else if (protocol == ICMP) {
        print("PKT: icmp_traffic %u->%u\n", src_ip, dst_ip)
    } else {
        print("PKT: unknown_protocol %u->%u\n", src_ip, dst_ip)
    }

    return XDP_PASS
}

// Quality of Service (QoS) packet marking
// Demonstrates match for traffic prioritization
@tc("ingress")
fn qos_packet_marker(ctx: *__sk_buff) -> i32 {
    var protocol = get_ip_protocol_tc(ctx)

    // Bind to a typed `str(16)` so each arm's narrower literal widens to
    // match set_qos_mark's parameter type. Without the annotation, the match's
    // result type would be the LUB of arm types (e.g. str(15) for the TCP
    // branch) and the function-call site has no width-coercion path.
    if (protocol == TCP) {
        var tcp_port = get_tcp_dest_port_tc(ctx)
        var qos_class: str(16) = match (tcp_port) {
            SSH: "high_priority",      // Admin traffic
            HTTPS: "medium_priority",  // Web traffic
            HTTP: "medium_priority",   // Web traffic
            default: "low_priority"
        }
        set_qos_mark(ctx, qos_class)
    } else if (protocol == UDP) {
        var udp_port = get_udp_dest_port_tc(ctx)
        var qos_class: str(16) = match (udp_port) {
            DNS: "high_priority",      // DNS is critical
            default: "low_priority"
        }
        set_qos_mark(ctx, qos_class)
    } else if (protocol == ICMP) {
        var qos_class: str(16) = "low_priority"
        set_qos_mark(ctx, qos_class)
    } else {
        set_qos_mark(ctx, "default_priority")
    }

    return 0  // TC_ACT_OK
}

// Firewall rule engine using match construct
// Shows complex security policy implementation
@xdp
fn firewall_engine(ctx: *xdp_md) -> xdp_action {
    var src_ip = get_src_ip(ctx)
    var protocol = get_ip_protocol(ctx)
    
    // Check if source is in blocklist
    if (is_blocked_ip(src_ip)) {
        return XDP_DROP
    }
    
    if (protocol == TCP) {
        var tcp_port = get_tcp_dest_port(ctx)
        var tcp_flags = get_tcp_flags(ctx)

        // Match arms with block bodies (containing if/else or nested matches that
        // need to gate on outer-arm-locals) hit the codegen limitation noted on
        // advanced_packet_classifier above - the inner control flow gets lifted
        // out of its arm. Fan the port dispatch out into if/else here too, so
        // each branch's body sits in an `if` block (where local control flow
        // works) instead of a match arm block.
        if (tcp_port == 22) {
            // Allow SSH but check source. is_admin_network is a function call,
            // so this inner match has no block arms and lowers cleanly.
            return match (is_admin_network(src_ip)) {
                true: XDP_PASS,
                false: XDP_DROP
            }
        } else if (tcp_port == 80) {
            return XDP_PASS         // Allow HTTP
        } else if (tcp_port == 443) {
            return XDP_PASS         // Allow HTTPS
        } else if (tcp_port == 25) {
            return XDP_DROP         // Block SMTP
        } else if (tcp_port == 23) {
            return XDP_DROP         // Block Telnet
        } else {
            // For unknown ports, check if it's a SYN flood.
            if (tcp_flags == 0x02) {
                return rate_limit_unknown_syn(src_ip)
            } else {
                return XDP_PASS
            }
        }
    } else if (protocol == UDP) {
        var udp_port = get_udp_dest_port(ctx)
        return match (udp_port) {
            53: XDP_PASS,           // Allow DNS
            123: XDP_PASS,          // Allow NTP
            161: XDP_DROP,          // Block SNMP
            default: XDP_PASS
        }
    } else if (protocol == ICMP) {
        var icmp_type_val = get_icmp_type(ctx)
        return match (icmp_type_val) {
            8: rate_limit_ping(src_ip),     // Rate limit ping
            default: XDP_DROP               // Drop other ICMP
        }
    } else {
        return XDP_DROP  // Deny unknown protocols
    }
}

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