// Example demonstrating break and continue in truly unbound loops
// This should force bpf_loop() usage

map<u32, u32> counter_map : HashMap(10)

@xdp fn packet_filter(ctx: XdpContext) -> XdpAction {
  let end_value = 1000 // Large value to make it unbound
  
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
    let key = 0
    let current = counter_map[key]
    counter_map[key] = current + 1
  }
  
  return XDP_PASS
}

// Userspace coordination (no wrapper)
fn main() -> i32 {
  let limit = 1000 // Runtime-determined limit
  let count = 0
  
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
  
  let prog = load(packet_filter)
  attach(prog, "eth0", 0)
  
  return 0
} 