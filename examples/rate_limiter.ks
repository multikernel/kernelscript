map packet_counts : HashMap<u32, u64> {
  max_entries: 1024;
}

program rate_limiter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let packet_start = ctx.data;
    let packet_end = ctx.data_end;
    let packet_size = packet_end - packet_start;
    
    // Basic packet size validation
    if (packet_size < 14) {
      return 1; // XDP_DROP - too small for Ethernet header
    }
    
    // For simplicity, assume IPv4 and extract source IP
    // In reality, we'd need to parse Ethernet header first
    let src_ip = 0x08080808; // Placeholder IP (8.8.8.8)
    
    // Look up current packet count for this IP
    let current_count = packet_counts[src_ip];
    let new_count = current_count + 1;
    
    // Update the count
    packet_counts[src_ip] = new_count;
    
    // Rate limiting: drop if too many packets
    if (new_count > 100) {
      return 1; // XDP_DROP
    }
    
    return 2; // XDP_PASS
  }
} 