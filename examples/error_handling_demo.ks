// Minimal error handling demo
map<u32, u64> counters : HashMap(1024);

program error_demo : xdp {
    fn main(ctx: XdpContext) -> i32 {
        let key = 42;
        
        try {
            // Try to get value from map
            let value = counters[key];
            if value == 0 {
                throw 1;  // Key not found
            }
            return 2;  // XDP_PASS
            
        } catch 1 {
            // Handle missing key by initializing it
            counters[key] = 100;
            return 1;  // XDP_DROP
        }
    }
}

fn main() -> i32 {
    try {
        // Simulate some operation that might fail
        let result = 42;
        if result > 40 {
            throw 2;  // Throw error code 2
        }
        return 0;  // Success
        
    } catch 2 {
        // Handle the error
        return 1;  // Return error code 1
    }
} 