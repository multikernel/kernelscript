// This file demonstrates all the new type system features

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

// Type alias for common types
type IpAddress = u32
type PacketSize = u16
type Counter = u64

// Struct definition for packet information
struct PacketInfo {
  src_ip: IpAddress,
  dst_ip: IpAddress,
  protocol: u8,
  src_port: u16,
  dst_port: u16,
  payload_size: PacketSize
}

// Enum for filtering actions
enum FilterAction {
  FILTER_ACTION_ALLOW = 0,
  FILTER_ACTION_BLOCK = 1,
  FILTER_ACTION_LOG = 2,
  FILTER_ACTION_REDIRECT = 3
}

// Enum for packet protocols
enum Protocol {
  TCP = 6,
  UDP = 17,
  ICMP = 1
}

// Global map declarations with different types
pin var connection_count : hash<IpAddress, Counter>(1024)

var packet_filter : lru_hash<PacketInfo, FilterAction>(512)

var recent_packets : array<u32, PacketInfo>(256)

// Result type for error handling
var packet_cache : percpu_hash<u32, PacketInfo>(128)

// Local maps for program-specific data
var protocol_stats : percpu_array<Protocol, Counter>(32)

@helper
fn extract_packet_info(ctx: *xdp_md) -> *PacketInfo {
  // This would contain actual packet parsing logic
  // For now, return a dummy PacketInfo
  var info: PacketInfo = PacketInfo {
    src_ip: 0xC0A80001,  // 192.168.0.1
    dst_ip: 0xC0A80002,  // 192.168.0.2
    protocol: 6,         // TCP
    src_port: 80,
    dst_port: 8080,
    payload_size: 1024
  }
  return &info
}

@helper
fn get_filter_action(info: PacketInfo) -> FilterAction {
  // Look up in the filter map
  var action = packet_filter[info]
  if (action != none) {
    return action
  } else {
    return FILTER_ACTION_ALLOW
  }
}

@helper
fn protocol_from_u8(proto_num: u8) -> Protocol {
  // Convert u8 protocol number to Protocol enum
  match (proto_num) {
    1: ICMP,
    6: TCP,
    17: UDP,
    default: TCP  // Default to TCP for unknown protocols
  }
}

@helper
fn update_stats(info: PacketInfo) {
  // Update connection count
  var current_count = connection_count[info.src_ip]
  if (current_count != none) {
    connection_count[info.src_ip] = current_count + 1
  } else {
    connection_count[info.src_ip] = 1
  }
  
  // Update protocol stats
  var proto = protocol_from_u8(info.protocol)
  var stats = protocol_stats[proto]
  if (stats != none) {
    protocol_stats[proto] = stats + 1
  } else {
    protocol_stats[proto] = 1
  }
}

// Program using all the new types
@xdp fn packet_inspector(ctx: *xdp_md) -> xdp_action {
  // Extract packet information
  var packet_info = extract_packet_info(ctx)
  
  if (packet_info != none) {
    // Update statistics
    update_stats(*packet_info)
    
    // Get filtering decision
    var action = get_filter_action(*packet_info)
    
    // Store in recent packets for userspace inspection
    var packet_id = ctx->ingress_ifindex
    recent_packets[packet_id] = *packet_info
    
    // Apply filtering action
    return match (action) {
      FILTER_ACTION_ALLOW: XDP_PASS,
      FILTER_ACTION_BLOCK: XDP_DROP,
      FILTER_ACTION_LOG: XDP_PASS,
      FILTER_ACTION_REDIRECT: XDP_REDIRECT
    }
  } else {
    // Failed to parse packet, drop it
    return XDP_DROP
  }
} 