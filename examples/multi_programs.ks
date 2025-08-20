// TC context struct (from BTF)
include "xdp.kh"
include "tc.kh"

// TC action constants
pin var shared_counter : hash<u32, u32>(1024)

// First eBPF program - packet counter
@xdp fn packet_counter(ctx: *xdp_md) -> xdp_action {
  shared_counter[1] = 100
  return XDP_PASS
}

@tc("ingress")
fn packet_filter(ctx: *__sk_buff) -> i32 {
  shared_counter[2] = 200
  return TC_ACT_OK
}

// Userspace coordination (outside program blocks)
fn main() -> i32 {
  shared_counter[1] = 0
  shared_counter[2] = 0
  
  var prog1 = load(packet_counter)
  var prog2 = load(packet_filter)
  attach(prog1, "eth0", 0)
  attach(prog2, "eth0", 0)
  
  print("Multiple XDP programs attached to eth0")
  print("Counter and filter working together...")
  
  // Detach in reverse order (good practice)
  detach(prog2)
  detach(prog1)
  print("All programs detached")
  
  return 0
} 