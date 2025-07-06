// This file demonstrates the type checking capabilities

// Type definitions for comprehensive type checking
type IpAddress = u32
type PacketSize = u16

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
pin map<IpAddress, u64> connection_stats : HashMap(1024)

@helper
fn extract_header(ctx: *xdp_md) -> xdp_action {
  // Type checker validates context parameter access
  var data = ctx->data
  var data_end = ctx->data_end
  
  // Type checker ensures arithmetic operations are on numeric types
  var packet_len = data_end - data
  
  if (packet_len < 20) {
    return 1
  }
  
  // Type checker validates struct field types
  var header: PacketHeader = PacketHeader {
    src_ip: 0xC0A80001,    // Type checked as u32 (IpAddress)
    dst_ip: 0xC0A80002,    // Type checked as u32 (IpAddress)
    protocol: 6,           // Type checked as u8
    length: packet_len     // Type promoted from arithmetic to u16
  }
  
  return 2
}

@helper
fn classify_protocol(proto: u8) -> ProtocolType {
  // Type checker validates enum constant access
  if (proto == 6) {
    return some PROTOCOL_TYPE_TCP
  } else if (proto == 17) {
    return some PROTOCOL_TYPE_UDP
  } else if (proto == 1) {
    return some PROTOCOL_TYPE_ICMP
  }
  return none
}

@helper
fn update_statistics(header: PacketHeader) {
  // Type checker validates map operations and key/value types
  var current_count = connection_stats[header.src_ip]
  
  if (current_count != null) {
    // Type checker ensures arithmetic on compatible types
    connection_stats[header.src_ip] = current_count + 1
  } else {
    // Type checker validates map insert operation
    connection_stats[header.src_ip] = 1
  }
}

@helper
fn make_decision(header: PacketHeader) -> FilterDecision {
  // Type checker validates function call signatures
  var proto_type = classify_protocol(header.protocol)
  
  match proto_type {
    some PROTOCOL_TYPE_TCP -> {
      // Type checker validates field access on struct types
      if (header.length > 1500) {
        return FILTER_DECISION_BLOCK
      }
      return FILTER_DECISION_ALLOW
    },
    some PROTOCOL_TYPE_UDP -> return FILTER_DECISION_ALLOW,
    some PROTOCOL_TYPE_ICMP -> return FILTER_DECISION_LOG,
    none -> return FILTER_DECISION_BLOCK
  }
}

@xdp fn packet_analyzer(ctx: *xdp_md) -> xdp_action {
  // Type checker validates context parameter and return type
  var packet_header = extract_header(ctx)
  
  match packet_header {
    some header -> {
      // Type checker validates function calls with correct types
      update_statistics(header)
      var decision = make_decision(header)
      
      // Type checker validates match expressions and enum types
      match decision {
        FILTER_DECISION_ALLOW -> return XDP_PASS,
        FILTER_DECISION_BLOCK -> return XDP_DROP,
        FILTER_DECISION_LOG -> {
          // Type checker validates built-in function signatures
          bpf_trace_printk("Logging packet", 14)
          return XDP_PASS
        }
      }
    },
    none -> {
      // Type checker validates return type compatibility
      return XDP_DROP
    }
  }
}

// Additional function demonstrating type inference
fn calculate_bandwidth(packet_count: u64, packet_size: u16) -> u64 {
  // Type checker infers result type from operand types
  var total_bytes = packet_count * packet_size  // u64 * u16 -> u64
  var bandwidth = total_bytes * 8               // u64 * literal -> u64
  return bandwidth
}

// Function demonstrating error detection
fn type_error_examples() {
  // The following would be caught by the type checker:
  
  // 1. Type mismatch in assignment
  // var x: u32 = true  // ERROR: cannot assign bool to u32
  
  // 2. Invalid field access
  // var header: PacketHeader = get_header()
  // var invalid = header.nonexistent_field  // ERROR: field not found
  
  // 3. Function call with wrong types
  // var result = calculate_bandwidth(true, "hello")  // ERROR: wrong argument types
  
  // 4. Arithmetic on incompatible types
  // var bad_math = 42 + true  // ERROR: cannot add u32 and bool
  
  // 5. Missing return in non-void function
  // fn missing_return() -> u32 {
  //   var x = 42
  //   // ERROR: missing return statement
  // }
}

fn main() -> i32 {
  var prog = load(packet_analyzer)
  attach(prog, "eth0", 0)
  return 0
} 