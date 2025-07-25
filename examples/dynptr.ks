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

// Dynptr showcase - compiler should transparently use dynptr APIs for packet access
// Example to demonstrate bpf_dynptr_from_mem usage
// This would be for accessing memory buffers, not packet data

struct DataBuffer {
    data: u8[32],
    size: u32
}

var buffer_map : hash<u32, DataBuffer>(1024)

@helper
fn process_map_data(buffer_ptr: *DataBuffer) -> u32 {
    // This should use bpf_dynptr_from_mem for map value access!
    var size_value = buffer_ptr->size  // Map data field access
    return size_value
}

@xdp  
  fn test(ctx: *xdp_md) -> xdp_action {
    // Packet data access - should use bpf_dynptr_from_xdp
    var packet_byte = *ctx->data
    
    // Map lookup - this gives us a pointer to map value
    var key = 1
    var buffer_value = buffer_map[key]  // Get map value
    
    if (buffer_value.size > 0) {
        // Pass address of the struct to demonstrate map data pointer access
        var buffer_ptr = &buffer_value
        var map_size = process_map_data(buffer_ptr)
        
        if (packet_byte > 0 || map_size > 0) {
            return XDP_PASS
        }
    }
    
    return XDP_DROP
}