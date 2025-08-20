include "xdp.kh"

@xdp fn simple_xdp(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  var prog = load(simple_xdp)
  attach(prog, "eth0", 0)
  
  print("XDP program attached to eth0")
  print("Letting it run for demonstration...")
  
  // In a real application, the program would run here
  // For demonstration, we immediately detach
  detach(prog)
  print("XDP program detached from eth0")
  
  return 0
} 
