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

var packet_counts : hash<u32, u64>(1024)

config network {
  limit : u32,
}

@xdp fn rate_limiter(ctx: *xdp_md) -> xdp_action {
  var packet_start = ctx->data
  var packet_end = ctx->data_end
  var packet_size = packet_end - packet_start
  
  // Basic packet size validation
  if (packet_size < 14) {
    return XDP_DROP // too small for Ethernet header
  }
  
  // For simplicity, assume IPv4 and extract source IP
  // In reality, we'd need to parse Ethernet header first
  var src_ip = 0x7F000001 // Placeholder IP (127.0.0.1)
    
  // Update the count
  if (packet_counts[src_ip] != none) {
    packet_counts[src_ip] += 1
  } else {
    packet_counts[src_ip] = 0
  }
  
  // Rate limiting: drop if too many packets
  if (packet_counts[src_ip] > network.limit) {
    return XDP_DROP
  }
  
  return XDP_PASS
}

struct Args {
  interface : str(20),
  limit : u32
}

fn main(args: Args) -> i32 {
  network.limit = args.limit
  var prog = load(rate_limiter)
  attach(prog, args.interface, 0)
  return 0
}
