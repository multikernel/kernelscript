// Example demonstrating break and continue in truly unbound loops
// This should force bpf_loop() usage

map<u32, u32> counter_map : HashMap(10)

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  var end_value = 1000 // Large value to make it unbound
  
  // This should be treated as unbound due to large range
  for (i in 0..end_value) {
    // Skip even numbers
    if (i % 2 == 0) {
      continue
    }
    
    // Stop processing at threshold
    if (i > 50) {
      break
    }
    
    // Count odd numbers up to threshold
    var key = 0
    var current = counter_map[key]
    counter_map[key] = current + 1
  }
  
  return XDP_PASS
}

// Userspace coordination (no wrapper)
fn main() -> i32 {
  var limit = 1000 // Runtime-determined limit
  var count = 0
  
  // This should also be unbound
  for (i in 0..limit) {
    if (i % 2 == 0) {
      continue
    }
    
    if (i > 50) {
      break
    }
    
    count = count + 1
  }
  
  var prog = load(packet_filter)
  attach(prog, "lo", 0)
  
  return 0
} 