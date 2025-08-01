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

// Test file for type alias functionality
type IpAddress = u32
type Port = u16
type EthBuffer = u8[14]

@xdp fn test_type_aliases(ctx: *xdp_md) -> xdp_action {
    var port: Port = 8080
    var ip: IpAddress = 192168001001
    
    return XDP_PASS
}

fn main() -> i32 {
    var prog = load(test_type_aliases)
    attach(prog, "eth0", 0)
    
    print("Type alias demo program attached to eth0")
    print("Demonstrating type alias capabilities...")
    
    // Show type alias functionality
    detach(prog)
    print("Type alias demo program detached")
    
    return 0
} 
