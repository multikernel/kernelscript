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

// Basic named return value - Go-style syntax
fn add_with_named_return(a: i32, b: i32) -> sum: i32 {
  sum = a + b      // 'sum' is automatically declared as a local variable
  return           // Naked return - returns current value of 'sum'
}

// Named return with complex logic
fn calculate_hash(value: u32, multiplier: u32) -> hash_value: u64 {
  hash_value = 0   // Named return variable is available immediately
  
  for (i in 0..multiplier) {
    hash_value = hash_value * 31 + value  // Modify throughout function
  }
  
  return           // Naked return with computed hash_value
}

// Mixing named variables with explicit returns
fn validate_length(len: u32, min_len: u32) -> is_valid: bool {
  is_valid = false  // Start with default value
  
  if (len == 0) {
    return        // Early naked return with is_valid = false
  }
  
  if (len < min_len) {
    return false  // Explicit return still works
  }
  
  is_valid = true   // Set to true if all checks pass
  return            // Final naked return
}

// eBPF helper functions with named returns
@helper
fn calculate_packet_size(ctx: *xdp_md) -> packet_size: u32 {
  var data = ctx->data
  var data_end = ctx->data_end
  
  if (data_end <= data) {
    packet_size = 0
    return  // Naked return with 0
  }
  
  packet_size = data_end - data  // Calculate size
  return                        // Naked return with size
}

// eBPF program functions with named returns
@xdp
fn advanced_packet_filter(ctx: *xdp_md) -> action: xdp_action {
  action = XDP_PASS  // Default action
  
  var size = ctx->data_end - ctx->data
  if (size < 64) {
    action = XDP_DROP
    return  // Naked return with XDP_DROP
  }
  
  var packet_size = calculate_packet_size(ctx)
  if (packet_size == 0) {
    action = XDP_ABORTED
    return  // Naked return with XDP_ABORTED
  }
  
  return  // Naked return with XDP_PASS
}

// Userspace functions with named returns
fn lookup_counter(ip: u32) -> counter_value: u64 {
  // This would normally access a map, simplified for example
  counter_value = ip * 1000  // Compute some value
  
  if (counter_value > 1000000) {
    counter_value = 0  // Reset if too high
  }
  
  return  // Naked return
}

type HashFunction = fn(*u8, u32) -> u64
type PacketProcessor = fn(*xdp_md) -> xdp_action

// Example with recursive named returns
fn fibonacci(n: u32) -> result: u64 {
  if (n <= 1) {
    result = n
    return
  }
  
  var a = fibonacci(n - 1)
  var b = fibonacci(n - 2)
  result = a + b
  return
}

// Named return with error handling
fn safe_divide(numerator: i32, denominator: i32) -> quotient: i32 {
  if (denominator == 0) {
    quotient = 0  // Safe default
    return
  }
  
  quotient = numerator / denominator
  return
}

// Complex example combining multiple features
fn process_data_with_validation(value: u32, len: u32) -> status: i32 {
  status = -1  // Error by default
  
  // Validate input
  if (value == 0 || len == 0) {
    return  // Early return with error status
  }
  
  // Calculate hash for validation
  var hash = calculate_hash(value, len)
  if (hash == 0) {
    status = -2  // Invalid hash
    return
  }
  
  // Process successful
  status = 0
  return
}

fn main() -> exit_code: i32 {
  print("=== Named Return Values Demo ===")
  
  // Demonstrate basic named return
  var sum = add_with_named_return(10, 20)
  print("Sum with named return: %d", sum)
  
  // Test validation function
  var validation_result = validate_length(25, 10)
  if (validation_result) {
    print("Validation result: valid")
  } else {
    print("Validation result: invalid")
  }
  
  // Test hash calculation
  var hash = calculate_hash(42, 5)
  print("Hash value: %llu", hash)
  
  // Test counter lookup
  var counter = lookup_counter(0x08080808)  // Google DNS
  print("Counter for 8.8.8.8: %llu", counter)
  
  // Test fibonacci
  var fib_result = fibonacci(10)
  print("Fibonacci(10) = %llu", fib_result)
  
  // Test safe division
  var quotient1 = safe_divide(10, 2)
  var quotient2 = safe_divide(10, 0)  // Safe division by zero
  print("10 / 2 = %d, 10 / 0 = %d", quotient1, quotient2)
  
  // Test complex processing
  var status = process_data_with_validation(123, 10)
  print("Processing status: %d", status)
  
  print("=== Demo Complete ===")
  
  exit_code = 0  // Set named return variable
  return         // Naked return with exit_code = 0
} 