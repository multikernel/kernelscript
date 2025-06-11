// This file demonstrates all the new type system features

// Type alias for common types
type IpAddress = u32;
type PacketSize = u16;
type Counter = u64;

// Struct definition for packet information
struct PacketInfo {
  src_ip: IpAddress;
  dst_ip: IpAddress;
  protocol: u8;
  src_port: u16;
  dst_port: u16;
  payload_size: PacketSize;
}

// Enum for filtering actions
enum FilterAction {
  Allow = 0,
  Block = 1,
  Log = 2,
  Redirect = 3
}

// Enum for packet protocols
enum Protocol {
  TCP = 6,
  UDP = 17,
  ICMP = 1
}

// Global map declarations with different types
map<IpAddress, Counter> connection_count : HashMap(1024) {
  pinned: "/sys/fs/bpf/connection_count"
};

map<PacketInfo, FilterAction> packet_filter : LruHash(512) {
};

map<u32, option PacketInfo> recent_packets : Array(256) {
};

// Result type for error handling
map<u32, result PacketInfo u8> packet_cache : PercpuHash(128) {
};

// Program using all the new types
program packet_inspector : xdp {
  
  // Local map within the program
  map<Protocol, Counter> protocol_stats : PercpuArray(32) {
  };
  
  fn extract_packet_info(ctx: XdpContext) -> option PacketInfo {
    // This would contain actual packet parsing logic
    // For now, return a dummy PacketInfo
    let info: PacketInfo = PacketInfo {
      src_ip: 0xC0A80001,  // 192.168.0.1
      dst_ip: 0xC0A80002,  // 192.168.0.2
      protocol: 6,         // TCP
      src_port: 80,
      dst_port: 8080,
      payload_size: 1024
    };
    return some info;
  }
  
  fn get_filter_action(info: PacketInfo) -> FilterAction {
    // Look up in the filter map
    let action = packet_filter[info];
    if action != null {
      return action;
    } else {
      return FilterAction::Allow;
    }
  }
  
  fn update_stats(info: PacketInfo) {
    // Update connection count
    let current_count = connection_count[info.src_ip];
    if current_count != null {
      connection_count[info.src_ip] = current_count + 1;
    } else {
      connection_count[info.src_ip] = 1;
    }
    
    // Update protocol stats
    let proto = Protocol::from_u8(info.protocol);
    if proto != null {
      let stats = protocol_stats[proto];
      if stats != null {
        protocol_stats[proto] = stats + 1;
      } else {
        protocol_stats[proto] = 1;
      }
    }
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    // Extract packet information
    let packet_info = extract_packet_info(ctx);
    
    match packet_info {
      some info -> {
        // Update statistics
        update_stats(info);
        
        // Get filtering decision
        let action = get_filter_action(info);
        
        // Store in recent packets for userspace inspection
        let packet_id = ctx.get_packet_id();
        recent_packets[packet_id] = info;
        
        // Apply filtering action
        match action {
          FilterAction::Allow -> return XdpAction::Pass,
          FilterAction::Block -> return XdpAction::Drop,
          FilterAction::Log -> {
            // Log packet and allow
            ctx.log_packet(info);
            return XdpAction::Pass;
          },
          FilterAction::Redirect -> return XdpAction::Redirect
        }
      },
      none -> {
        // Failed to parse packet, drop it
        return XdpAction::Drop;
      }
    }
  }
} 