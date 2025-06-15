// KernelScript String Type Demonstration
// Shows unified string syntax working in both eBPF and userspace contexts

program string_demo : xdp {
  fn main(ctx: XdpContext) -> i32 {
    // Test string declarations with different sizes
    let name: str<16> = "hello";
    let message: str<32> = "world";
    let large_buffer: str<128> = "large message buffer";
    
    // Test string indexing
    let first_char: char = name[0];
    let second_char: char = name[1];
    
    // Test string comparison
    if name == "hello" {
      // String concatenation
      let result: str<48> = name + message;
      
      // Test string inequality
      if result != "helloworld" {
        return 1;
      }
    }
    
    // Test smaller strings
    let tiny: str<4> = "abc";
    let custom: str<10> = "custom";
    
    return 0;
  }
}

// Userspace coordinator demonstrating the same string operations
fn main() -> i32 {
    // Same string syntax works in userspace
    let greeting: str<20> = "Hello";
    let target: str<20> = "World";
    let punctuation: str<5> = "!";
    
    // String concatenation in userspace
    let message: str<45> = greeting + target;
    let final_message: str<50> = message + punctuation;
    
    // String comparison in userspace
    if greeting == "Hello" {
        // Character access
        let first: char = greeting[0];
        let last: char = target[4];
        
        // String inequality test
        if final_message != "HelloWorld!" {
            return 1;
        }
    }
    
    // Test string truncation behavior
    let short: str<6> = "toolong";  // Will be truncated to "toolo" + null
    let exact: str<6> = "exact";    // Fits perfectly: "exact" + null
    
    // Demonstrate different string sizes
    let tiny: str<3> = "hi";        // 2 chars + null
    let medium: str<32> = "medium length string";
    let large: str<128> = "this is a much longer string for testing";
    
    return 0;
} 