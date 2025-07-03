// This file demonstrates hierarchical symbol resolution,
// global scope management, map visibility rules,
// and function/type name resolution.

// Global type definitions (visible everywhere)
struct PacketInfo {
    size: u32,
    protocol: u16,
    src_ip: u32,
    dst_ip: u32,
}

enum xdp_action {
    Pass = 0,
    Drop = 1,
    Aborted = 2,
    Redirect = 3,
}

// Global maps (accessible from all programs)
map<u32, u64> global_stats : HashMap(1024) {
    pinned: "/sys/fs/bpf/global_stats",
}

map<u32, PacketInfo> packet_cache : LruHash(256) {
    pinned: "/sys/fs/bpf/packet_cache",
}

map<u32, u32> traffic_data : Array(128) {
    pinned: "/sys/fs/bpf/traffic_data",
}

// Global function (public visibility)
pub fn log_packet(info: PacketInfo) -> u32 {
    global_stats[info.protocol] = global_stats[info.protocol] + 1
    return info.size
}

@xdp fn packet_filter(ctx: xdp_md) -> xdp_action {
    var packet = ctx.packet()
    var info = PacketInfo {
        size: packet.len(),
        protocol: packet.protocol(),
        src_ip: packet.src_ip(),
        dst_ip: packet.dst_ip(),
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

@tc fn traffic_monitor(ctx: TcContext) -> TcAction {
    var packet = ctx.packet()
    
    // Access global map (visible from all programs)
    global_stats[packet.protocol()] = global_stats[packet.protocol()] + 1
    
    // Use global traffic data map
    traffic_data[0] = packet.len()
    
    // Can call global function
    var info = PacketInfo {
        size: packet.len(),
        protocol: packet.protocol(),
        src_ip: packet.src_ip(),
        dst_ip: packet.dst_ip(),
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