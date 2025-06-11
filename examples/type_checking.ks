// This file demonstrates the type checking capabilities

// Type definitions for comprehensive type checking
type IpAddress = u32;
type PacketSize = u16;

struct PacketHeader {
  src_ip: IpAddress;
  dst_ip: IpAddress;
  protocol: u8;
  length: PacketSize;
}

enum ProtocolType {
  TCP = 6,
  UDP = 17,
  ICMP = 1
}

enum FilterDecision {
  Allow = 0,
  Block = 1,
  Log = 2
}

// Global map for demonstration
map<IpAddress, u64> connection_stats : hash_map(1024) {
  max_entries = 1024;
  pinned = "/sys/fs/bpf/stats";
}

program packet_analyzer : xdp {
  
  fn extract_header(ctx: xdp_context) -> option PacketHeader {
    // Type checker validates that ctx is xdp_context type
    let data = ctx.data;
    let data_end = ctx.data_end;
    
    // Type checker ensures arithmetic operations are on numeric types
    let packet_len = data_end - data;
    
    if packet_len < 20 {
      return none;
    }
    
    // Type checker validates struct field types
    let header: PacketHeader = PacketHeader {
      src_ip: 0xC0A80001,    // Type checked as u32 (IpAddress)
      dst_ip: 0xC0A80002,    // Type checked as u32 (IpAddress)
      protocol: 6,           // Type checked as u8
      length: packet_len     // Type promoted from arithmetic to u16
    };
    
    return some header;
  }
  
  fn classify_protocol(proto: u8) -> option ProtocolType {
    // Type checker validates enum constant access
    if proto == 6 {
      return some ProtocolType::TCP;
    } else if proto == 17 {
      return some ProtocolType::UDP;
    } else if proto == 1 {
      return some ProtocolType::ICMP;
    }
    return none;
  }
  
  fn update_statistics(header: PacketHeader) {
    // Type checker validates map operations and key/value types
    let current_count = connection_stats[header.src_ip];
    
    if current_count != null {
      // Type checker ensures arithmetic on compatible types
      connection_stats[header.src_ip] = current_count + 1;
    } else {
      // Type checker validates map insert operation
      connection_stats[header.src_ip] = 1;
    }
  }
  
  fn make_decision(header: PacketHeader) -> FilterDecision {
    // Type checker validates function call signatures
    let proto_type = classify_protocol(header.protocol);
    
    match proto_type {
      some ProtocolType::TCP -> {
        // Type checker validates field access on struct types
        if header.length > 1500 {
          return FilterDecision::Block;
        }
        return FilterDecision::Allow;
      },
      some ProtocolType::UDP -> return FilterDecision::Allow,
      some ProtocolType::ICMP -> return FilterDecision::Log,
      none -> return FilterDecision::Block
    }
  }
  
  fn main(ctx: xdp_context) -> xdp_action {
    // Type checker validates context parameter and return type
    let packet_header = extract_header(ctx);
    
    match packet_header {
      some header -> {
        // Type checker validates function calls with correct types
        update_statistics(header);
        let decision = make_decision(header);
        
        // Type checker validates match expressions and enum types
        match decision {
          FilterDecision::Allow -> return XdpAction::Pass,
          FilterDecision::Block -> return XdpAction::Drop,
          FilterDecision::Log -> {
            // Type checker validates built-in function signatures
            bpf_trace_printk("Logging packet", 14);
            return XdpAction::Pass;
          }
        }
      },
      none -> {
        // Type checker validates return type compatibility
        return XdpAction::Drop;
      }
    }
  }
}

// Additional function demonstrating type inference
fn calculate_bandwidth(packet_count: u64, packet_size: u16) -> u64 {
  // Type checker infers result type from operand types
  let total_bytes = packet_count * packet_size;  // u64 * u16 -> u64
  let bandwidth = total_bytes * 8;               // u64 * literal -> u64
  return bandwidth;
}

// Function demonstrating error detection
fn type_error_examples() {
  // The following would be caught by the type checker:
  
  // 1. Type mismatch in assignment
  // let x: u32 = true;  // ERROR: cannot assign bool to u32
  
  // 2. Invalid field access
  // let header: PacketHeader = get_header();
  // let invalid = header.nonexistent_field;  // ERROR: field not found
  
  // 3. Function call with wrong types
  // let result = calculate_bandwidth(true, "hello");  // ERROR: wrong argument types
  
  // 4. Arithmetic on incompatible types
  // let bad_math = 42 + true;  // ERROR: cannot add u32 and bool
  
  // 5. Missing return in non-void function
  // fn missing_return() -> u32 {
  //   let x = 42;
  //   // ERROR: missing return statement
  // }
} 