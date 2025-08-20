// KernelScript String Type Demonstration
// Shows unified string syntax working in both eBPF and userspace contexts

include "xdp.kh"

@xdp fn string_demo(ctx: *xdp_md) -> xdp_action {
  // Test string declarations with different sizes
  var name: str(16) = "hello"
  var message: str(32) = "world"
  var large_buffer: str(128) = "large message buffer"
  
  // Test string indexing
  var first_char: char = name[0]
  var second_char: char = name[1]
  
  // Test string comparison
  if (name == "hello") {
    // String concatenation
    var result: str(48) = name + message
    
    // Test string inequality
    if (result != "helloworld") {
      return XDP_DROP
    }
  }
  
  // Test smaller strings
  var tiny: str(4) = "abc"
  var custom: str(10) = "custom"
  
  return XDP_PASS
}

// Userspace coordinator demonstrating the same string operations
fn main() -> i32 {
    // Same string syntax works in userspace
    var greeting: str(20) = "Hello"
    var target: str(20) = "World"
    var punctuation: str(5) = "!"
    
    // String concatenation in userspace
    var message: str(45) = greeting + target
    var final_message: str(50) = message + punctuation
    
    // String comparison in userspace
    if (greeting == "Hello") {
        // Character access
        var first: char = greeting[0]
        var last: char = target[4]
        
        // String inequality test
        if (final_message != "HelloWorld!") {
            return 1
        }
    }
    
    // Test string truncation behavior
    var short: str(6) = "toolong"  // Will be truncated to "toolo" + null
    var exact: str(6) = "exact"    // Fits perfectly: "exact" + null
    
    // Demonstrate different string sizes
    var tiny: str(3) = "hi"        // 2 chars + null
    var medium: str(32) = "medium length string"
    var large: str(128) = "this is a much longer string for testing"
    
    return 0
} 