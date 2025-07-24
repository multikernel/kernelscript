// This file demonstrates hierarchical symbol resolution,
// global scope management, map visibility rules,
// and function/type name resolution.

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

// TC context struct (from BTF)
struct __sk_buff {
  data: u64,
  data_end: u64,
  len: u32,
  ifindex: u32,
  protocol: u32,
  mark: u32,
}

// TC action constants
enum tc_action {
  TC_ACT_UNSPEC = 255,
  TC_ACT_OK = 0,
  TC_ACT_RECLASSIFY = 1,
  TC_ACT_SHOT = 2,
  TC_ACT_PIPE = 3,
  TC_ACT_STOLEN = 4,
  TC_ACT_QUEUED = 5,
  TC_ACT_REPEAT = 6,
  TC_ACT_REDIRECT = 7,
}

// Global type definitions (visible everywhere)
struct PacketInfo {
    size: u32,
    protocol: u16,
    src_ip: u32,
    dst_ip: u32,
}

// Global maps (accessible from all programs)
pin var global_stats : HashMap<u32, u64>(1024)

pin var packet_cache : LruHash<u32, PacketInfo>(256)

pin var traffic_data : Array<u32, u32>(128)

@helper
fn log_packet(info: PacketInfo) -> u32 {
    global_stats[info.protocol] = global_stats[info.protocol] + 1
    return info.size
}

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet_size = ctx->data_end - ctx->data
    var info = PacketInfo {
        size: packet_size,
        protocol: 6,  // Demo value
        src_ip: 0x7f000001,  // Demo IP
        dst_ip: 0x7f000002,  // Demo IP
    }
    
    // Access global maps (visible from all programs)
    global_stats[0] = global_stats[0] + 1
    
    // Store packet info in global cache
    packet_cache[info.src_ip] = info
    
    // Call global function
    var logged_size = log_packet(info)
    
    // Use global enum
    if (info.protocol == 6) {
        return XDP_PASS
    } else {
        return XDP_DROP
    }
}

@tc fn traffic_monitor(ctx: *__sk_buff) -> i32 {
    var packet_protocol = ctx->protocol
    
    // Access global map (visible from all programs)
    global_stats[packet_protocol] = global_stats[packet_protocol] + 1
    
    // Use global traffic data map
    traffic_data[0] = ctx->len
    
    // Can call global function
    var info = PacketInfo {
        size: ctx->len,
        protocol: packet_protocol,
        src_ip: 0x7f000001,  // Demo IP
        dst_ip: 0x7f000002,  // Demo IP
    }
    log_packet(info)
    
    return TC_ACT_OK
}

fn main() -> i32 {
    // Userspace function can also access global maps
    global_stats[999] = 0
    return 0
}

// Demonstration of symbol visibility rules:
//
// 1. Global symbols (types, functions, maps) are visible everywhere
// 2. All maps are global and shared across programs
// 3. Private functions are only visible within their scope
// 4. Function parameters are only visible within their function
// 5. Block-scoped variables are only visible within their block
// 6. Symbols in inner scopes can shadow outer scope symbols
// 7. Symbol lookup follows scope hierarchy (inner to outer)
//
// Symbol Table Structure:
// Global Scope:
//   - PacketInfo (struct)
//   - xdp_action (enum)
//   - global_stats (map)
//   - packet_cache (map)
//   - traffic_data (map)
//   - log_packet (function)
//   - packet_filter (attributed function)
//   - traffic_monitor (attributed function)
//   - main (function)
//
// Function Scopes:
//   - Parameters and local variables
//   - Block-scoped variables 