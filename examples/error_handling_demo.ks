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

// Minimal error handling demo
map<u32, u64> counters : HashMap(1024)

@xdp fn error_demo(ctx: *xdp_md) -> xdp_action {
    var key = 42
    
    try {
        // Try to get value from map
        var value = counters[key]
        if (value == 0) {
            throw 1  // Key not found
        }
        return 2  // XDP_PASS
        
    } catch 1 {
        // Handle missing key by initializing it
        counters[key] = 100
        return 1  // XDP_DROP
    }
}

fn main() -> i32 {
    try {
        // Simulate some operation that might fail
        var result = 42
        if (result > 40) {
            throw 2  // Throw error code 2
        }
        return 0  // Success
        
    } catch 2 {
        // Handle the error
        return 1  // Return error code 1
    }
} 