// Test catch/throw/defer functionality with integer-based error handling
include "xdp.kh"

var test_map : hash<u32, u64>(1024)

// Error codes following "null for absence, throw for errors" pattern:
// 1 = Invalid data (error condition, not absence)
// 2 = Overflow detected (error condition)

@helper
fn cleanup_lock() {
    // Simulate cleanup operation
    var result = 0
}

@helper
fn process_key(key: u32) -> u32 {
    // Example of defer for resource cleanup
    var lock_acquired = true
    defer cleanup_lock()
    
    try {
        // Check if key exists (expected absence - use null)
        var value = test_map[key]
        if (value == none) {
            // Key doesn't exist - create default value (expected pattern)
            var default_value = 42
            test_map[key] = default_value
            return default_value
        }
        
        // Key exists - validate the value (error condition - use throw)
        if (value == 0) {
            throw 1  // Invalid data - this is an error condition
        }
        
        // Process the valid value
        return value
    } catch 1 {  // Invalid data
        // Handle invalid data by logging and returning error value
        return 0
    }
}

@xdp fn error_test(ctx: *xdp_md) -> xdp_action {
    var packet_len = 64  // Simulate packet length
    var key = packet_len % 100  // Use packet length as key
    
    try {
        var result = process_key(key)
        if (result > 1000) {
            throw 2  // Overflow detected
        }
        
    } catch 1 {  // Invalid data
          // Log and drop the packet due to invalid data
         return XDP_DROP
    } catch 2 {  // Overflow detected
          // Handle overflow by dropping packet
         return XDP_DROP
    }
      
    return XDP_PASS
}

fn main() -> i32 {
    var prog = load(error_test)
    attach(prog, "eth0", 0)
    
    print("Error handling demo program attached to eth0")
    print("Testing error handling capabilities...")
    
    // Demonstrate the error handling is working
    detach(prog)
    print("Error handling demo program detached")
    
    return 0
} 