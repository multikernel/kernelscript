// This file demonstrates hierarchical symbol resolution,
// global vs local scope management, map visibility rules,
// and function/type name resolution.

// Global type definitions (visible everywhere)
struct PacketInfo {
    size: u32,
    protocol: u16,
    src_ip: u32,
    dst_ip: u32,
}

enum XdpAction {
    Pass = 0,
    Drop = 1,
    Aborted = 2,
    Redirect = 3,
}

// Global map (accessible from all programs)
map<u32, u64> global_stats : HashMap(1024) {
    pinned: "/sys/fs/bpf/global_stats",
}

// Global function (public visibility)
pub fn log_packet(info: PacketInfo) -> u32 {
    global_stats[info.protocol] = global_stats[info.protocol] + 1
    return info.size
}

// First program with local scope
program packet_filter : xdp {
    // Local map (only visible within this program)
    map<u32, PacketInfo> local_cache : LruHash(256)
    
    // Private function (only visible within this program)
    fn process_packet(ctx: XdpContext) -> XdpAction {
        let packet = ctx.packet()
        let info = PacketInfo {
            size: packet.len(),
            protocol: packet.protocol(),
            src_ip: packet.src_ip(),
            dst_ip: packet.dst_ip(),
        }
        
        // Access global map (visible from here)
        global_stats[0] = global_stats[0] + 1
        
        // Access local map (visible within this program)
        local_cache[info.src_ip] = info
        
        // Call global function (visible from here)
        let logged_size = log_packet(info)
        
        // Use global enum (visible from here)
        if (info.protocol == 6) {
            return XDP_PASS
        } else {
            return XDP_DROP
        }
    }
    
    // Main function with parameter scope
    fn main(ctx: XdpContext) -> XdpAction {
        // Function parameter 'ctx' is in scope here
        let result = process_packet(ctx)
        
        // Local variable scope
        let local_var: u32 = 42
        
        // Block scope demonstration
        if (result == XDP_PASS) {
            let block_var: u32 = local_var + 1
            global_stats[1] = block_var
        }
        // block_var is not accessible here
        
        return result
    }
}

// Second program with separate local scope
program traffic_monitor : tc {
    // Different local map with same name (no conflict due to scoping)
    map<u32, u32> local_cache : Array(128)
    
    fn analyze_traffic(ctx: TcContext) -> TcAction {
        let packet = ctx.packet()
        
        // Access global map (visible from here)
        global_stats[packet.protocol()] = global_stats[packet.protocol()] + 1
        
        // Access this program's local map
        local_cache[0] = packet.len()
        
        // Cannot access packet_filter's local_cache (different scope)
        // This would cause a symbol resolution error:
        // packet_filter::local_cache[0] = packet.len()  // ERROR
        
        // Can call global function
        let info = PacketInfo {
            size: packet.len(),
            protocol: packet.protocol(),
            src_ip: packet.src_ip(),
            dst_ip: packet.dst_ip(),
        }
        log_packet(info)
        
        return TC_ACT_OK
    }
    
    fn main(ctx: TcContext) -> TcAction {
        return analyze_traffic(ctx)
    }
}

// Demonstration of symbol visibility rules:
//
// 1. Global symbols (types, functions, maps) are visible everywhere
// 2. Program-local maps are only visible within their program
// 3. Private functions are only visible within their program
// 4. Function parameters are only visible within their function
// 5. Block-scoped variables are only visible within their block
// 6. Symbols in inner scopes can shadow outer scope symbols
// 7. Symbol lookup follows scope hierarchy (inner to outer)
//
// Symbol Table Structure:
// Global Scope:
//   - PacketInfo (struct)
//   - XdpAction (enum)
//   - global_stats (map)
//   - log_packet (function)
//
// packet_filter Scope:
//   - local_cache (map)
//   - process_packet (function)
//   - main (function)
//
// traffic_monitor Scope:
//   - local_cache (map, different from packet_filter's)
//   - analyze_traffic (function)
//   - main (function)
//
// Function Scopes:
//   - Parameters and local variables
//   - Block-scoped variables 