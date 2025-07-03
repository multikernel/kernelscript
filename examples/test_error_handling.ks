// Test catch/throw/defer functionality with integer-based error handling
map<u32, u64> test_map : HashMap(1024)

// Error codes following "null for absence, throw for errors" pattern:
// 1 = Invalid data (error condition, not absence)
// 2 = Overflow detected (error condition)

@helper
fn process_key(key: u32) -> u32 {
    // Example of defer for resource cleanup
    var lock_acquired = true
    defer cleanup_lock()
    
    try {
        // Check if key exists (expected absence - use null)
        var value = test_map[key]
        if (value == null) {
            // Key doesn't exist - create default value (expected pattern)
            var default_value = 42
            test_map[key] = default_value
            return default_value as u32
        }
        
        // Key exists - validate the value (error condition - use throw)
        if (value == 0) {
            throw 1  // Invalid data - this is an error condition
        }
        
        // Process the valid value
        return value as u32
        
    } catch 1 {  // Invalid data
        // Handle invalid data by logging and returning error value
        return 0
    }
}

@helper
fn cleanup_lock() {
    // Simulate cleanup operation
    var result = 0
}

@xdp fn error_test(ctx: xdp_md) -> xdp_action {
    var packet_len = 64  // Simulate packet length
    var key = packet_len % 100  // Use packet length as key
    
    try {
        var result = process_key(key)
        if (result > 1000) {
            throw 2  // Overflow detected
        }
        
    } catch 1 {  // Invalid data
        // Log and drop the packet due to invalid data
        return 1  // XDP_DROP
    } catch 2 {  // Overflow detected
        // Handle overflow by dropping packet
        return 1  // XDP_DROP
    }
    
    return 2  // XDP_PASS
}

fn main() -> i32 {
    var prog = load(error_test)
    attach(prog, "eth0", 0)
    return 0
} 