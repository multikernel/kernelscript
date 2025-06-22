map<u32,u64>packet_counts : HashMap(1024)

config network {
  limit : u32,
}

@xdp fn rate_limiter(ctx: XdpContext) -> XdpAction {
  let packet_start = ctx.data
  let packet_end = ctx.data_end
  let packet_size = packet_end - packet_start
  
  // Basic packet size validation
  if (packet_size < 14) {
    return XDP_DROP // too small for Ethernet header
  }
  
  // For simplicity, assume IPv4 and extract source IP
  // In reality, we'd need to parse Ethernet header first
  let src_ip = 0x7F000001 // Placeholder IP (127.0.0.1)
  
  // Look up current packet count for this IP
  let current_count = packet_counts[src_ip]
  let new_count = current_count + 1
  
  // Update the count
  packet_counts[src_ip] = new_count
  
  // Rate limiting: drop if too many packets
  if (new_count > network.limit) {
    return XDP_DROP
  }
  
  return XDP_PASS
}

struct Args {
  interface : str<20>,
  limit : u32
}

fn main(args: Args) -> i32 {
  network.limit = args.limit
  let prog = load(rate_limiter)
  attach(prog, args.interface, 0)
  return 0
}
