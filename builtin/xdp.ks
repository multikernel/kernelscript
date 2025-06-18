// XDP (eXpress Data Path) builtin definitions
// This file defines the standard XDP action constants and types

enum XdpAction {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XDP_REDIRECT = 4
}

// XDP context structure (read-only)
struct XdpContext {
    data: *u8,           // Pointer to packet data start
    data_end: *u8,       // Pointer to packet data end
    data_meta: *u8,      // Pointer to metadata
    ingress_ifindex: u32, // Ingress interface index
    rx_queue_index: u32,  // RX queue index
    egress_ifindex: u32   // Egress interface index (for redirect)
} 