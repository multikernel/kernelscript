// Test catch/throw/defer functionality with integer-based error handling
map<u32, u64> test_map : HashMap(1024)

// Error codes:
// 1 = Key not found
// 2 = Overflow detected

program error_test : xdp {
    fn process_key(key: u32) -> u32 {
        // Example of defer for resource cleanup
        let lock_acquired = true
        defer cleanup_lock()
        
        try {
            // Simulate looking up a potentially non-existent key
            let value = test_map[key]
            if value == 0 {
                throw 1  // Key not found
            }
            
            // Process the value
            return value as u32
            
        } catch 1 {  // Key not found
            // Handle the case where key doesn't exist
            let default_value = 42
            test_map[key] = default_value;
            return default_value as u32
        }
    }
    
    fn cleanup_lock() {
        // Simulate cleanup operation
        let result = 0
    }
    
    fn main(ctx: XdpContext) -> i32 {
        let packet_len = 64  // Simulate packet length
        let key = packet_len % 100  // Use packet length as key
        
        try {
            let result = process_key(key)
            if result > 1000 {
                throw 2  // Overflow detected
            }
            
        } catch 1 {  // Key not found
            // Log and drop the packet
            return 1  // XDP_DROP
        } catch 2 {  // Overflow detected
            // Handle overflow by dropping packet
            return 1  // XDP_DROP
        }
        
        return 2  // XDP_PASS
    }
}

fn main() -> i32 {
    return 0
} 