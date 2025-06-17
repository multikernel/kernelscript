// TC (Traffic Control) builtin definitions
// This file defines the standard TC action constants and types

enum TcAction {
    TC_ACT_UNSPEC = 255,  // Using 255 instead of -1 for parser compatibility
    TC_ACT_OK = 0,
    TC_ACT_RECLASSIFY = 1,
    TC_ACT_SHOT = 2,
    TC_ACT_PIPE = 3,
    TC_ACT_STOLEN = 4,
    TC_ACT_QUEUED = 5,
    TC_ACT_REPEAT = 6,
    TC_ACT_REDIRECT = 7
}

// TC context structure (read-only)
struct TcContext {
    data: u32,           // Pointer to packet data start
    data_end: u32,       // Pointer to packet data end
    len: u32,            // Packet length
    pkt_type: u32,       // Packet type
    mark: u32,           // Packet mark
    queue_mapping: u32,  // Queue mapping
    protocol: u32,       // Protocol
    vlan_present: u32,   // VLAN present flag
    vlan_tci: u32,       // VLAN TCI
    vlan_proto: u32,     // VLAN protocol
    priority: u32,       // Packet priority
    ingress_ifindex: u32, // Ingress interface index
    ifindex: u32,        // Interface index
    tc_index: u32,       // TC index
    cb: u32[5],          // Control buffer
    hash: u32,           // Packet hash
    tc_classid: u32      // TC class ID
} 