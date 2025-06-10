# KernelScript Language Format Specification v1.0

## 1. Design Philosophy and Scope

### 1.1 Core Principles
- **Simplicity over generality**: Avoid complex template systems that burden the compiler
- **Explicit over implicit**: Clear, readable syntax with minimal magic
- **Safety by construction**: Type system prevents common eBPF errors
- **Seamless kernel-userspace integration**: First-class support for bidirectional communication

### 1.2 Simplified Type System
Instead of complex templates, KernelScript uses **simple type aliases** and **fixed-size types**:

```kernelscript
// Simple type aliases for common patterns
type IpAddress = u32;
type Port = u16;
type PacketBuffer = [u8; 1500];
type SmallBuffer = [u8; 256];

// Fixed-size arrays (no complex bounds)
[u8; 64]               // 64-byte buffer
[u32; 16]              // 16 u32 values

// Simple map declarations
map<u32, u64> counters : array(256);
map<IpAddress, PacketStats> flows : hash_map(1024);

// No complex template metaprogramming - just practical, concrete types
```

## 2. Lexical Structure

### 2.1 Keywords
```
program     fn          let         mut         const       config      userspace
map         type        struct      enum        match       if          else
for         while       loop        break       continue    return      import
export      pub         priv        static      unsafe      where       impl
true        false       null        and         or          not         in
as          is          try         catch       throw       defer       go
```

### 2.2 Identifiers
```ebnf
identifier = letter { letter | digit | "_" } ;
letter = "a"..."z" | "A"..."Z" ;
digit = "0"..."9" ;
```

### 2.3 Literals
```ebnf
integer_literal = decimal_literal | hex_literal | octal_literal | binary_literal ;
decimal_literal = digit { digit } ;
hex_literal = "0x" hex_digit { hex_digit } ;
octal_literal = "0o" octal_digit { octal_digit } ;
binary_literal = "0b" binary_digit { binary_digit } ;

string_literal = '"' { string_char } '"' ;
char_literal = "'" char "'" ;

boolean_literal = "true" | "false" ;
```

## 3. Program Structure

### 3.1 Basic Program Declaration
```ebnf
program = "program" identifier ":" program_type "{" program_body "}" ;

program_type = "xdp" | "tc" | "kprobe" | "uprobe" | "tracepoint" | 
               "lsm" | "cgroup_skb" | "socket_filter" | "sk_lookup" ;

program_body = { config_section | local_map_declaration | 
                 type_declaration | function_declaration | import_declaration } ;
```

### 3.2 Configuration Section
```kernelscript
program network_monitor : xdp {
    config {
        enable_logging: bool = true,
        max_packet_size: u32 = 1500,
        blocked_ports: [u16; 5] = [22, 23, 135, 445, 3389],
        rate_limit: u64 = 1000000,
    }
    
    fn main(ctx: XdpContext) -> XdpAction {
        let packet = ctx.packet();
        
        // Use configuration values directly
        if packet.size > config.max_packet_size {
            if config.enable_logging {
                bpf_printk("Packet too large: %d", packet.size);
            }
            return XdpAction::Drop;
        }
        
        // Check blocked ports
        if packet.is_tcp() {
            let tcp = packet.tcp_header();
            for i in 0..5 {
                if tcp.dst_port == config.blocked_ports[i] {
                    return XdpAction::Drop;
                }
            }
        }
        
        return XdpAction::Pass;
    }
}
```

### 3.3 User-Space Integration Section
```kernelscript
// Multiple eBPF programs working together
program packet_analyzer : xdp {
    config {
        enable_stats: bool = true,
    }
    
    fn main(ctx: XdpContext) -> XdpAction {
        if config.enable_stats {
            // Process packet and update statistics
        }
        return XdpAction::Pass;
    }
}

program flow_tracker : tc {
    fn main(ctx: TcContext) -> TcAction {
        // Track flow information
        return TcAction::Pass;
    }
}

// Top-level userspace coordinator - manages all programs
userspace {
    struct PacketStats {
        packets: u64,
        bytes: u64,
        drops: u64,
    }
    
    fn main(argc: u32, argv: &[&str]) -> i32 {
        // Parse command line arguments
        if argc < 2 {
            print("Usage: ", argv[0], " <interface>");
            return 1;
        }
        
        let interface = argv[1];
        
        // Load and coordinate multiple programs
        let analyzer = BpfProgram::load("packet_analyzer");
        let tracker = BpfProgram::load("flow_tracker");
        
        analyzer.attach_xdp(interface);
        tracker.attach_tc(interface, TcDirection::Ingress);
        
        print("Multi-program system started on interface: ", interface);
        
        while true {
            let stats = get_combined_stats();
            print("Total packets: ", stats.packets);
            print("Total bytes: ", stats.bytes);
            sleep(1000);
        }
        
        return 0;
    }
    
    // Helper functions for coordinating programs
    fn on_packet_event(event: PacketEvent) {
        print("Received packet from ", event.src_ip);
    }
    
    fn update_all_configs(new_config: GlobalConfig) -> bool {
        // Update configuration for all programs
        return update_program_configs(new_config);
    }
    
    fn get_combined_stats() -> PacketStats {
        // Aggregate statistics from all programs
        return PacketStats {
            packets: packet_stats_map.get(0),
            bytes: packet_stats_map.get(1),
            drops: packet_stats_map.get(2),
        };
    }
}
```

## 4. Type System

### 4.1 Primitive Types
```kernelscript
// Integer types with explicit bit widths
u8, u16, u32, u64      // Unsigned integers
i8, i16, i32, i64      // Signed integers
bool                   // Boolean
char                   // 8-bit character

// Pointer types (restricted usage in kernel context)
*u8, *u32, *void       // Pointers to specific types
```

### 4.2 Compound Types
```kernelscript
// Fixed-size arrays
[u8; 64]               // Array of 64 bytes
[u32; 16]              // Array of 16 u32 values

// Structures
struct PacketHeader {
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    flags: u16,
}

// Enumerations
enum XdpAction {
    Aborted = 0,
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
}

// Simple option type for null safety
Option_u32             // Can be Some(value) or None
Option_PacketHeader    // Option containing a PacketHeader

// Simple result type for error handling
Result_u32_ParseError  // Ok(u32) or Err(ParseError)
Result_void_Error      // Ok(()) or Err(Error)
```

### 4.3 Type Aliases for Common Patterns
```kernelscript
// Simple type aliases without complex constraints
type IpAddress = u32;
type Port = u16;
type PacketSize = u16;
type Timestamp = u64;

// Buffer types with fixed sizes (no templates needed)
type EthBuffer = [u8; 14];      // Ethernet header buffer
type IpBuffer = [u8; 20];       // IP header buffer
type SmallBuffer = [u8; 256];   // Small general buffer
type PacketBuffer = [u8; 1500]; // Maximum packet buffer
```

## 5. eBPF Maps and Global Sharing

### 5.1 Map Declaration Syntax
```ebnf
map_declaration = "map" "<" key_type "," value_type ">" identifier ":" map_type "(" map_config ")" 
                  [ map_attributes ] ";" ;

map_type = "hash_map" | "array" | "prog_array" | "percpu_hash" | "percpu_array" |
           "lru_hash" | "ring_buffer" | "perf_event" | "stack_trace" ;

map_config = max_entries [ "," additional_config ] ;
map_attributes = "{" { map_attribute "," } "}" ;
map_attribute = "pinned" | "read_only" | "write_only" | "userspace_writable" |
                "pin_path" "=" string_literal | "permissions" "=" string_literal ;
```

### 5.2 Global Maps (Shared Across Programs)

Global maps are declared outside any program block and are automatically shared:

```kernelscript
// Global maps - automatically shared between all programs
map<FlowKey, FlowStats> global_flows : hash_map(10000) {
    pinned: "/sys/fs/bpf/global_flows",
};

map<u32, InterfaceStats> interface_stats : array(256) {
    pinned: "/sys/fs/bpf/interface_stats",
};

map<SecurityEvent> security_events : ring_buffer(1024 * 1024) {
    pinned: "/sys/fs/bpf/security_events",
};

map<ConfigKey, ConfigValue> global_config : array(64) {
    pinned: "/sys/fs/bpf/global_config",
};

// Program 1: Can access all global maps
program ingress_monitor : xdp {
    // Local maps (only accessible within this program)
    map<u32, LocalStats> local_cache : hash_map(512);
    
    fn main(ctx: XdpContext) -> XdpAction {
        let flow_key = extract_flow_key(ctx)?;
        
        // Access global map directly
        let stats = global_flows.get_or_create(flow_key, FlowStats::new());
        stats.ingress_packets += 1;
        stats.ingress_bytes += ctx.packet_size();
        
        // Update interface stats
        interface_stats[ctx.ingress_ifindex()].packets += 1;
        
        return XdpAction::Pass;
    }
}

// Program 2: Automatically has access to the same global maps
program egress_monitor : tc {
    // Local maps
    map<FlowKey, EgressInfo> egress_cache : lru_hash(1000);
    
    fn main(ctx: TcContext) -> TcAction {
        let flow_key = extract_flow_key(ctx)?;
        
        // Same global map, no import needed
        if let Some(stats) = global_flows.get_mut(flow_key) {
            stats.egress_packets += 1;
            stats.egress_bytes += ctx.packet_size();
        }
        
        // Check global configuration
        let enable_filtering = global_config.get(ConfigKey::EnableFiltering)
            .unwrap_or(ConfigValue::Bool(false));
        
        if enable_filtering.as_bool() && should_drop(flow_key) {
            // Log to global security events
            security_events.submit(SecurityEvent {
                event_type: EventType::PacketDropped,
                flow_key: flow_key,
                timestamp: bpf_ktime_get_ns(),
            });
            return TcAction::Shot;
        }
        
        return TcAction::Pass;
    }
}

// Program 3: Security analyzer using the same global maps
program security_analyzer : lsm("socket_connect") {
    fn main(ctx: LsmContext) -> i32 {
        let flow_key = extract_flow_key_from_socket(ctx)?;
        
        // Check global flow statistics
        if let Some(flow_stats) = global_flows.get(flow_key) {
            if flow_stats.is_suspicious() {
                security_events.submit(SecurityEvent {
                    event_type: EventType::SuspiciousConnection,
                    flow_key: flow_key,
                    timestamp: bpf_ktime_get_ns(),
                });
                return -EPERM;  // Block connection
            }
        }
        
        return 0;  // Allow connection
    }
}
```

### 5.3 Local vs Global Map Scope

```kernelscript
// Global maps (outside any program)
map<u32, GlobalCounter> global_counters : array(256);
map<Event> event_stream : ring_buffer(1024 * 1024);

program producer : kprobe("sys_read") {
    // Local maps (only accessible within this program)
    map<u32, LocalState> producer_state : hash_map(1024);
    
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32;
        
        // Update local state
        producer_state.increment(pid, 1);
        
        // Update global counter (accessible by other programs)
        global_counters.increment(pid % 256, 1);
        
        // Send event to global stream
        let event = Event {
            pid: pid,
            syscall: "read",
            timestamp: bpf_ktime_get_ns(),
        };
        event_stream.submit(event);
        
        return 0;
    }
    
    userspace {
        fn main() {
            let program = BpfProgram::load("producer");
            program.attach_kprobe("sys_read");
            print("Producer attached to sys_read");
        }
    }
}

program consumer : kprobe("sys_write") {
    // Local maps
    map<u32, LocalState> consumer_state : hash_map(1024);
    
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32;
        
        // Access global counter (same map as producer program)
        let read_count = global_counters.get(pid % 256);
        
        // Update local state
        let local_state = LocalState {
            write_count: 1,
            corresponding_reads: read_count,
        };
        consumer_state.insert(pid, local_state);
        
        return 0;
    }
    
    userspace {
        fn main() {
            let program = BpfProgram::load("consumer");
            program.attach_kprobe("sys_write");
            print("Consumer attached to sys_write");
        }
    }
}
```

### 5.4 Namespace Organization (Optional)

For better organization, you can group related global maps in namespaces:

```kernelscript
// Namespace for network monitoring maps
namespace network {
    map<FlowKey, FlowStats> flows : hash_map(10000);
    map<u32, InterfaceStats> interfaces : array(256);
    map<PacketEvent> events : ring_buffer(1024 * 1024);
}

// Namespace for security monitoring maps
namespace security {
    map<u32, ThreatScore> threat_scores : hash_map(10000);
    map<SecurityEvent> alerts : ring_buffer(512 * 1024);
    map<ConfigKey, ConfigValue> policy : array(32);
}

program network_monitor : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let flow_key = extract_flow_key(ctx);
        
        // Access namespaced global maps
        network::flows.increment(flow_key);
        network::interfaces[ctx.ingress_ifindex()].packets = 
            network::interfaces[ctx.ingress_ifindex()].packets + 1;
        
        return XdpAction::Pass;
    }
    
    userspace {
        fn main() {
            let program = BpfProgram::load("network_monitor");
            program.attach_xdp("eth0");
            print("Network monitor started");
        }
    }
}

program security_monitor : lsm("socket_connect") {
    fn main(ctx: LsmContext) -> i32 {
        let flow_key = extract_flow_key_from_socket(ctx);
        
        // Check both network and security namespaces
        let flow_stats = network::flows.get(flow_key);
        if flow_stats != null {
            let threat_score = calculate_threat_score(flow_stats);
            security::threat_scores.insert(flow_key.src_ip, threat_score);
            
            let threshold = security::policy.get(ConfigKey::ThreatThreshold);
            if threat_score > threshold {
                let alert = SecurityEvent::HighThreatDetected {
                    flow_key: flow_key,
                    threat_score: threat_score,
                };
                security::alerts.submit(alert);
                return -EPERM;
            }
        }
        
        return 0;
    }
    
    userspace {
        fn main() {
            let program = BpfProgram::load("security_monitor");
            program.attach_lsm("socket_connect");
            print("Security monitor started");
        }
    }
}
```

### 5.5 Map Examples
```kernelscript
// Global maps accessible by all programs
map<u32, PacketStats> packet_stats : hash_map(1024) {
    pinned: "/sys/fs/bpf/packet_stats",
};

map<u32, u64> counters : percpu_array(256) {
    pinned: "/sys/fs/bpf/counters",
};

map<FlowKey, FlowInfo> active_flows : lru_hash(10000) {
    pinned: "/sys/fs/bpf/active_flows",
};

map<PacketEvent> events : ring_buffer(1024 * 1024) {
    pinned: "/sys/fs/bpf/events",
};

map<ConfigKey, ConfigValue> config_map : array(16) {
    pinned: "/sys/fs/bpf/config",
};

program simple_monitor : xdp {
    // Local map - only accessible within this program
    map<u32, LocalCache> cache : hash_map(256);
    
    fn main(ctx: XdpContext) -> XdpAction {
        // Access global maps directly
        packet_stats.increment(ctx.packet_type(), 1);
        counters.increment(0, 1);
        
        // Access local map
        cache.insert(ctx.hash(), LocalCache::new());
        
        return XdpAction::Pass;
    }
}
```

## 6. Functions and Control Flow

### 6.1 Function Declaration
```ebnf
function_declaration = [ visibility ] "fn" identifier "(" parameter_list ")" [ "->" return_type ] "{" statement_list "}" ;

visibility = "pub" | "priv" ;
parameter_list = [ parameter { "," parameter } ] ;
parameter = identifier ":" type_annotation ;
return_type = type_annotation ;
```

### 6.2 Main Program Function
```kernelscript
program simple_xdp : xdp {
    // Required main function - entry point
    fn main(ctx: XdpContext) -> XdpAction {
        let packet = ctx.packet()?;
        
        if packet.is_tcp() {
            return XdpAction::Pass;
        }
        
        return XdpAction::Drop;
    }
}
```

### 6.3 Helper Functions
```kernelscript
// Private helper function
priv fn validate_packet(packet: *PacketHeader) -> bool {
    packet.len >= 64 && packet.len <= 1500
}

// Public function (can be called from other programs)
pub fn calculate_checksum(data: *u8, len: u32) -> u16 {
    let mut sum: u32 = 0;
    for i in 0..(len / 2) {
        sum += data[i * 2] + (data[i * 2 + 1] << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return !(sum as u16);
}
```

### 6.4 Control Flow Statements
```kernelscript
// Conditional statements
if condition {
    // statements
} else if other_condition {
    // statements
} else {
    // statements
}

// Pattern matching (simplified)
let protocol = packet.protocol();
if protocol == Protocol::TCP {
    handle_tcp(packet);
} else if protocol == Protocol::UDP {
    handle_udp(packet);
} else if protocol == Protocol::ICMP {
    handle_icmp(packet);
} else {
    // default case
}

// Loops with automatic bounds checking
for i in 0..MAX_ITERATIONS {
    if should_break() {
        break;
    }
    process_item(i);
}

// While loops (compiler ensures termination)
let iterations = 0;
while condition && iterations < MAX_ITERATIONS {
    do_work();
    iterations = iterations + 1;
}
```

## 7. Error Handling

### 7.1 Simple Result Types
```kernelscript
// Functions that can fail return simple result types
fn parse_ip_header(packet: *u8, len: u32) -> Result_IpHeader_ParseError {
    if len < 20 {
        return Err_ParseError(ParseError::TooShort);
    }
    
    let header = cast_to_ip_header(packet);
    if header.version != 4 {
        return Err_ParseError(ParseError::InvalidVersion);
    }
    
    return Ok_IpHeader(header);
}

// Error propagation with simple syntax
fn process_packet(ctx: *XdpContext) -> Result_XdpAction_ProcessError {
    let packet = get_packet(ctx);
    if packet == null {
        return Err_ProcessError(ProcessError::InvalidContext);
    }
    
    let ip_result = parse_ip_header(packet.data, packet.len);
    if is_err(ip_result) {
        return Err_ProcessError(ProcessError::ParseFailed);
    }
    
    let ip_header = unwrap_ok(ip_result);
    // Process the packet
    return Ok_XdpAction(XdpAction::Pass);
}
```

### 7.2 Simple Option Types
```kernelscript
// Functions that might not return a value
fn find_tcp_header(packet: *u8, len: u32) -> Option_TcpHeader {
    let ip_header = cast_to_ip_header(packet);
    if ip_header.protocol != IPPROTO_TCP {
        return None_TcpHeader();
    }
    
    let tcp_offset = ip_header.header_length * 4;
    if len < tcp_offset + 20 {
        return None_TcpHeader();
    }
    
    let tcp_header = cast_to_tcp_header(packet + tcp_offset);
    return Some_TcpHeader(tcp_header);
}

// Using option values
fn handle_packet(packet: *u8, len: u32) {
    let tcp_opt = find_tcp_header(packet, len);
    if is_some(tcp_opt) {
        let tcp_header = unwrap_some(tcp_opt);
        process_tcp_packet(tcp_header);
    }
}
```

### 7.3 Simple Error Types
```kernelscript
enum ParseError {
    TooShort = 1,
    InvalidVersion = 2,
    BadChecksum = 3,
}

enum ProcessError {
    InvalidContext = 1,
    ParseFailed = 2,
    OutOfMemory = 3,
}

// Panic for unrecoverable errors
fn critical_operation() {
    if unsafe_condition() {
        panic("Critical system state violated");
    }
}

// Simple assertions
fn validate_state() {
    assert(map_size < MAX_ENTRIES, "Map overflow detected");
}
```

## 8. User-Space Integration

### 8.1 Top-Level Userspace Coordination with Global Maps
```kernelscript
// Global maps (accessible from all programs and userspace)
map<FlowKey, FlowStats> global_flows : hash_map(10000) {
    pinned: "/sys/fs/bpf/global_flows",
};

map<Event> global_events : ring_buffer(1024 * 1024) {
    pinned: "/sys/fs/bpf/global_events",
};

map<ConfigKey, ConfigValue> global_config : array(64) {
    pinned: "/sys/fs/bpf/global_config",
};

// Multiple eBPF programs working together
program network_monitor : xdp {
    // Local maps (only accessible within this program)
    map<u32, LocalStats> local_stats : hash_map(1024);
    
    config {
        enable_logging: bool = true,
        threshold: u64 = 1000,
    }
    
    fn main(ctx: XdpContext) -> XdpAction {
        // Access global maps directly
        let flow_key = extract_flow_key(ctx)?;
        global_flows.increment(flow_key);
        
        // Send event to global stream
        global_events.submit(Event::PacketProcessed { flow_key });
        
        return XdpAction::Pass;
    }
}

program security_filter : lsm("socket_connect") {
    fn main(ctx: LsmContext) -> i32 {
        let flow_key = extract_flow_key_from_socket(ctx)?;
        
        // Check global flow statistics for threat detection
        if let Some(flow_stats) = global_flows.get(flow_key) {
            if flow_stats.is_suspicious() {
                global_events.submit(Event::ThreatDetected { flow_key });
                return -EPERM;  // Block connection
            }
        }
        
        return 0;  // Allow connection
    }
}

// Top-level userspace coordinator - manages all eBPF programs
userspace {
    // Generated bindings automatically include global maps
    use std::collections::HashMap;
    
    pub struct SystemCoordinator {
        network_monitor: BpfProgram,
        security_filter: BpfProgram,
        
        // Global map access (shared across all programs)
        global_flows: &'static GlobalMap<FlowKey, FlowStats>,
        global_events: &'static GlobalRingBuffer<Event>,
        global_config: &'static GlobalMap<ConfigKey, ConfigValue>,
    }
    
    impl SystemCoordinator {
        pub fn new() -> Result<Self, Error> {
            Ok(Self {
                network_monitor: BpfProgram::load("network_monitor")?,
                security_filter: BpfProgram::load("security_filter")?,
                
                // Global maps are automatically accessible
                global_flows: GlobalMaps::flows(),
                global_events: GlobalMaps::events(),
                global_config: GlobalMaps::config(),
            })
        }
        
        pub fn start(&mut self) -> Result<(), Error> {
            // Coordinate multiple programs
            self.network_monitor.attach_xdp("eth0")?;
            self.security_filter.attach_lsm("socket_connect")?;
            Ok(())
        }
        
        pub fn process_events(&self) {
            // Process events from all programs
            while let Some(event) = self.global_events.read() {
                match event {
                    Event::PacketProcessed { flow_key } => {
                        println!("Processed packet for flow: {:?}", flow_key);
                    },
                    Event::ThreatDetected { flow_key } => {
                        println!("THREAT DETECTED: {:?}", flow_key);
                        self.handle_threat(flow_key);
                    },
                }
            }
        }
        
        fn handle_threat(&self, flow_key: FlowKey) {
            // Coordinated response across all programs
            self.global_config.update(ConfigKey::ThreatLevel, ConfigValue::High);
        }
    }
    
    fn main(argc: u32, argv: &[&str]) -> i32 {
        // Parse command line arguments for interface configuration
        let interface = if argc > 1 { argv[1] } else { "eth0" };
        
        let mut coordinator = SystemCoordinator::new().unwrap();
        coordinator.start_on_interface(interface).unwrap();
        
        println!("Multi-program eBPF system started on interface: ", interface);
        
        loop {
            coordinator.process_events();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        return 0;
    }
}
```

### 8.2 Cross-Language Bindings
```kernelscript
program network_monitor : xdp {
    config {
        enable_logging: bool = true,
    }
    
    fn main(ctx: XdpContext) -> XdpAction {
        return XdpAction::Pass;
    }
}

program flow_analyzer : tc {
    fn main(ctx: TcContext) -> TcAction {
        return TcAction::Pass;
    }
}

// Top-level userspace with cross-language binding generation
userspace {
    // Default: KernelScript userspace code
    fn main(argc: u32, argv: &[&str]) -> i32 {
        // Parse command line arguments
        let interface = if argc > 1 { argv[1] } else { "eth0" };
        let verbose = argc > 2 && argv[2] == "--verbose";
        
        let network_monitor = BpfProgram::load("network_monitor");
        let flow_analyzer = BpfProgram::load("flow_analyzer");
        
        network_monitor.attach_xdp(interface);
        flow_analyzer.attach_tc(interface, TcDirection::Ingress);
        
        if verbose {
            print("Multi-program system loaded on interface: ", interface);
            print("Verbose mode enabled");
        }
        
        // Coordinate both programs
        handle_system_events(verbose);
        
        return 0;
    }
    
    fn handle_system_events(verbose: bool) {
        while true {
            // Process events from all programs
            if verbose {
                print("Processing system events...");
            }
            sleep(1000);
        }
    }
    
    // Generate bindings for other languages

    
    // Language-specific configuration  
    rust {
        crate_name: "network_system",
    },
    
    go {
        package: "networksystem",
    },
    
    python {
        package: "network_system",
    },
}
```

## 9. Memory Management and Safety

### 9.1 Automatic Bounds Checking
```kernelscript
fn safe_packet_access(packet: &Packet, offset: usize, size: usize) -> Option<&[u8]> {
    // Compiler automatically inserts bounds checks
    if offset + size <= packet.len() {
        Some(&packet.data()[offset..offset + size])
    } else {
        None
    }
}

// Array access with compile-time and runtime checks
fn process_array(arr: &[u32; 256], index: usize) -> u32 {
    // Compile-time check if index is constant
    arr[index]  // Compiler generates bounds check if needed
}
```

### 9.2 Stack Management
```kernelscript
// Automatic stack usage tracking
fn large_function() {
    let buffer: [u8; 400] = [0; 400];  // Compiler tracks stack usage
    // Compiler will automatically spill to map if stack limit exceeded
    
    process_buffer(&buffer);
    
    // Automatic cleanup
}

// Explicit stack annotation for performance-critical code
#[stack_limit(256)]
fn performance_critical() {
    // Compiler ensures this function uses at most 256 bytes of stack
}
```

## 10. Compilation and Build System

### 10.1 Deployment Configuration (deploy.yaml)
```yaml
# Deployment configuration for KernelScript programs
apiVersion: kernelscript.dev/v1
kind: ProgramDeployment
metadata:
  name: network-monitoring
spec:
  programs:
    - name: packet_counter
      type: xdp
      attach:
        interfaces: ["eth0", "eth1"]
        mode: "native"  # or "generic"
      
    - name: security_monitor
      type: lsm
      attach:
        hooks: ["socket_connect"]
        
    - name: perf_tracer
      type: kprobe
      attach:
        functions: 
          - "sys_read"
          - "sys_write"
        auto_attach: true
        
  global_maps:
    pin_path: "/sys/fs/bpf/monitoring/"
    cleanup_on_exit: true
    
  userspace:
    auto_start: true
    restart_policy: "always"
```

### 10.3 Build Commands
```bash
# Compile KernelScript to eBPF bytecode
kernelscript build

# Generate userspace bindings
kernelscript generate --target=rust --output=bindings/

# Run tests
kernelscript test

# Deploy using configuration
kernelscript deploy --config=deploy.yaml

# Manual attachment (if auto_attach=false)
kernelscript attach perf_monitor --function=sys_read
```

## 11. Standard Library

### 11.1 Core Library Functions
```kernelscript
// Network utilities
mod net {
    pub fn parse_ethernet(data: &[u8]) -> Result<EthernetHeader, ParseError>;
    pub fn parse_ipv4(data: &[u8]) -> Result<Ipv4Header, ParseError>;
    pub fn parse_tcp(data: &[u8]) -> Result<TcpHeader, ParseError>;
    pub fn calculate_checksum(data: &[u8]) -> u16;
}

// String utilities (limited for eBPF)
mod str {
    pub fn compare(a: &[u8], b: &[u8]) -> i32;
    pub fn find_byte(haystack: &[u8], needle: u8) -> Option<usize>;
}

// Math utilities
mod math {
    pub fn min(a: u64, b: u64) -> u64;
    pub fn max(a: u64, b: u64) -> u64;
    pub fn clamp(value: u64, min: u64, max: u64) -> u64;
}
```

### 11.2 Context Helpers
```kernelscript
// XDP context helpers
impl XdpContext {
    pub fn packet(&self) -> Result<Packet, ContextError>;
    pub fn adjust_head(&mut self, delta: i32) -> Result<(), ContextError>;
    pub fn adjust_tail(&mut self, delta: i32) -> Result<(), ContextError>;
}

// Kprobe context helpers
impl KprobeContext {
    pub fn arg<T>(&self, index: usize) -> T;
    pub fn return_value<T>(&self) -> T;
    pub fn function_name(&self) -> &str;
}
```

## 12. Example Programs

### 12.1 Simple Packet Filter
```kernelscript
program simple_filter : xdp {
    config {
        blocked_ports: [u16; 4] = [22, 23, 135, 445],
        enable_logging: bool = false,
    }
    
    fn main(ctx: XdpContext) -> XdpAction {
        let packet = ctx.packet();
        if packet == null {
            return XdpAction::Pass;
        }
        
        if packet.is_tcp() {
            let tcp = packet.tcp_header();
            for i in 0..4 {
                if tcp.dst_port == config.blocked_ports[i] {
                    if config.enable_logging {
                        bpf_printk("Blocked port %d", tcp.dst_port);
                    }
                    return XdpAction::Drop;
                }
            }
        }
        
        return XdpAction::Pass;
    }
}

// Top-level userspace coordinator
userspace {
    fn main(argc: u32, argv: &[&str]) -> i32 {
        // Parse command line arguments
        if argc < 2 {
            print("Usage: ", argv[0], " <interface> [--quiet]");
            return 1;
        }
        
        let interface = argv[1];
        let quiet = argc > 2 && argv[2] == "--quiet";
        
        // Program loaded and attached
        let filter = BpfProgram::load("simple_filter");
        filter.attach_xdp(interface);
        
        if !quiet {
            print("Packet filter started on interface: ", interface);
            print("Blocking ports: 22, 23, 135, 445");
        }
        
        while true {
            // Monitor system health
            let stats = filter.get_stats();
            if stats.dropped_packets > 1000 && !quiet {
                print("High drop rate detected: ", stats.dropped_packets);
            }
            sleep(10000);
        }
        
        return 0;
    }
}
```

### 12.2 Performance Monitoring
```kernelscript
// Global maps for performance data
map<u32, CallInfo> active_calls : hash_map(1024);
map<u32, u64> read_stats : array(1024);
map<u32, u64> write_stats : array(1024);

struct CallInfo {
    start_time: u64,
    bytes_requested: u32,
}

program perf_monitor : kprobe("sys_read") {
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32;
        let call_info = CallInfo {
            start_time: bpf_ktime_get_ns(),
            bytes_requested: ctx.arg_u32(2),
        };
        
        active_calls.insert(pid, call_info);
        return 0;
    }
    
    fn on_return(ctx: KretprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32;
        
        let call_info = active_calls.get(pid);
        if call_info != null {
            let duration = bpf_ktime_get_ns() - call_info.start_time;
            read_stats.add(pid % 1024, duration);
            active_calls.remove(pid);
        }
        
        return 0;
    }
}

program write_monitor : kprobe("sys_write") {
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32;
        let duration = measure_write_time(ctx);
        write_stats.add(pid % 1024, duration);
        return 0;
    }
}

// Top-level userspace coordinator for all monitoring programs
userspace {
    fn main(argc: u32, argv: &[&str]) -> i32 {
        // Parse command line arguments
        let mut interval = 5000;  // Default 5 second interval
        let mut show_details = true;
        
        for i in 1..argc {
            if argv[i] == "--interval" && i + 1 < argc {
                interval = parse_u32(argv[i + 1]);
            } else if argv[i] == "--summary-only" {
                show_details = false;
            } else if argv[i] == "--help" {
                print("Usage: ", argv[0], " [--interval <ms>] [--summary-only] [--help]");
                return 0;
            }
        }
        
        // Both programs loaded and attached manually
        let read_monitor = BpfProgram::load("perf_monitor");
        let write_monitor = BpfProgram::load("write_monitor");
        
        read_monitor.attach_kprobe("sys_read");
        write_monitor.attach_kprobe("sys_write");
        
        print("Performance monitoring system started (interval: ", interval, "ms)");
        
        while true {
            sleep(interval);
            
            print("=== System Performance Stats ===");
            
            if show_details {
                // Read statistics
                print("Read Performance:");
                for (pid_slot, total_duration) in read_stats.iter() {
                    if total_duration > 0 {
                        print("  Slot ", pid_slot, ": ", total_duration, " ns");
                    }
                }
                
                // Write statistics  
                print("Write Performance:");
                for (pid_slot, total_duration) in write_stats.iter() {
                    if total_duration > 0 {
                        print("  Slot ", pid_slot, ": ", total_duration, " ns");
                    }
                }
            }
            
            // Cross-program analysis
            analyze_system_performance();
        }
        
        return 0;
    }
    
    fn analyze_system_performance() {
        // Coordinated analysis across multiple programs
        let total_read_time = read_stats.sum();
        let total_write_time = write_stats.sum();
        
        if total_read_time > total_write_time * 2 {
            print("WARNING: Read operations significantly slower than writes");
        }
    }
}
```

## 13. Complete Formal Grammar (EBNF)

```ebnf
(* KernelScript Complete Grammar *)

(* Top-level structure *)
kernelscript_file = { global_declaration } ;

global_declaration = map_declaration | type_declaration | namespace_declaration | 
                    program_declaration | userspace_declaration | import_declaration ;

(* Map declarations - global scope *)
map_declaration = "map" "<" type_annotation [ "," type_annotation ] ">" identifier 
                  ":" map_type "(" map_config ")" [ map_attributes ] ";" ;

map_type = "hash_map" | "array" | "percpu_hash" | "percpu_array" | "lru_hash" | 
           "ring_buffer" | "perf_event" | "stack_trace" | "prog_array" ;

map_config = integer_literal [ "," map_config_item { "," map_config_item } ] ;
map_config_item = identifier "=" literal ;

map_attributes = "{" map_attribute { "," map_attribute } [ "," ] "}" ;
map_attribute = identifier [ "=" literal ] ;

(* Program declarations *)
program_declaration = "program" identifier ":" program_type "{" program_body "}" ;

program_type = "xdp" | "tc" | "kprobe" | "uprobe" | "tracepoint" | "lsm" | 
               "cgroup_skb" | "socket_filter" | "sk_lookup" | "raw_tracepoint" ;

program_body = { program_item } ;

program_item = local_map_declaration | config_section |
               function_declaration | type_declaration ;

(* Local maps - inside program scope *)
local_map_declaration = "map" "<" type_annotation [ "," type_annotation ] ">" identifier 
                        ":" map_type "(" map_config ")" [ map_attributes ] ";" ;

(* Configuration section *)
config_section = "config" "{" { config_item } "}" ;
config_item = identifier ":" type_annotation [ "=" expression ] "," ;

(* Top-level userspace declaration *)
userspace_declaration = "userspace" "{" userspace_body "}" ;
userspace_body = { userspace_item } ;
userspace_item = function_declaration | struct_declaration | userspace_config ;

userspace_config = identifier "{" { userspace_config_item } "}" ;
userspace_config_item = identifier ":" literal "," ;

(* Namespace declarations *)
namespace_declaration = "namespace" identifier "{" { namespace_item } "}" ;
namespace_item = map_declaration | type_declaration ;

(* Type declarations *)
type_declaration = "type" identifier "=" type_definition ";" ;
type_definition = struct_type | enum_type | type_alias ;

struct_type = "struct" identifier "{" { struct_field } "}" ;
struct_field = identifier ":" type_annotation "," ;

enum_type = "enum" identifier "{" enum_variant { "," enum_variant } [ "," ] "}" ;
enum_variant = identifier [ "=" integer_literal ] ;

type_alias = type_annotation ;

(* Function declarations *)
function_declaration = [ visibility ] "fn" identifier "(" parameter_list ")" 
                       [ "->" type_annotation ] "{" statement_list "}" ;

visibility = "pub" | "priv" ;
parameter_list = [ parameter { "," parameter } ] ;
parameter = identifier ":" type_annotation ;

(* Statements *)
statement_list = { statement } ;
statement = expression_statement | assignment_statement | declaration_statement |
            if_statement | for_statement | while_statement | return_statement |
            break_statement | continue_statement | block_statement ;

expression_statement = expression ";" ;
assignment_statement = identifier assignment_operator expression ";" ;
assignment_operator = "=" | "+=" | "-=" | "*=" | "/=" | "%=" ;

declaration_statement = "let" [ "mut" ] identifier [ ":" type_annotation ] "=" expression ";" ;

if_statement = "if" expression "{" statement_list "}" 
               { "else" "if" expression "{" statement_list "}" }
               [ "else" "{" statement_list "}" ] ;

for_statement = "for" identifier "in" expression ".." expression "{" statement_list "}" |
                "for" "(" identifier "," identifier ")" "in" expression ".iter()" "{" statement_list "}" ;

while_statement = "while" expression "{" statement_list "}" ;

return_statement = "return" [ expression ] ";" ;
break_statement = "break" ";" ;
continue_statement = "continue" ";" ;
block_statement = "{" statement_list "}" ;

(* Expressions *)
expression = logical_or_expression ;

logical_or_expression = logical_and_expression { "or" logical_and_expression } ;
logical_and_expression = equality_expression { "and" equality_expression } ;
equality_expression = relational_expression { equality_operator relational_expression } ;
equality_operator = "==" | "!=" ;

relational_expression = additive_expression { relational_operator additive_expression } ;
relational_operator = "<" | "<=" | ">" | ">=" ;

additive_expression = multiplicative_expression { additive_operator multiplicative_expression } ;
additive_operator = "+" | "-" ;

multiplicative_expression = unary_expression { multiplicative_operator unary_expression } ;
multiplicative_operator = "*" | "/" | "%" ;

unary_expression = [ unary_operator ] primary_expression ;
unary_operator = "!" | "-" | "*" | "&" ;

primary_expression = identifier | literal | function_call | field_access | 
                     array_access | parenthesized_expression | struct_literal ;

function_call = identifier "(" argument_list ")" ;
argument_list = [ expression { "," expression } ] ;

field_access = primary_expression "." identifier ;
array_access = primary_expression "[" expression "]" ;
parenthesized_expression = "(" expression ")" ;

struct_literal = identifier "{" struct_literal_field { "," struct_literal_field } [ "," ] "}" ;
struct_literal_field = identifier ":" expression ;

(* Type annotations *)
type_annotation = primitive_type | compound_type | identifier ;

primitive_type = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | 
                 "bool" | "char" | "void" ;

compound_type = array_type | pointer_type | option_type | result_type ;

array_type = "[" type_annotation ";" integer_literal "]" ;
pointer_type = "*" [ "const" | "mut" ] type_annotation ;
option_type = "Option_" type_annotation ;
result_type = "Result_" type_annotation "_" type_annotation ;

(* Literals *)
literal = integer_literal | string_literal | char_literal | boolean_literal | 
          array_literal | null_literal ;

integer_literal = decimal_literal | hex_literal | octal_literal | binary_literal ;
decimal_literal = digit { digit } ;
hex_literal = "0x" hex_digit { hex_digit } ;
octal_literal = "0o" octal_digit { octal_digit } ;
binary_literal = "0b" binary_digit { binary_digit } ;

string_literal = '"' { string_char } '"' ;
char_literal = "'" char "'" ;
boolean_literal = "true" | "false" ;
array_literal = "[" [ expression { "," expression } ] "]" ;
null_literal = "null" ;

(* Import declarations *)
import_declaration = "import" import_target ";" ;
import_target = identifier | string_literal ;

(* Identifiers and basic tokens *)
identifier = letter { letter | digit | "_" } ;
letter = "a"..."z" | "A"..."Z" ;
digit = "0"..."9" ;
hex_digit = digit | "a"..."f" | "A"..."F" ;
octal_digit = "0"..."7" ;
binary_digit = "0" | "1" ;

(* String and character content *)
string_char = any_char_except_quote_and_backslash | escape_sequence ;
char = any_char_except_quote_and_backslash | escape_sequence ;
escape_sequence = "\" ( "n" | "t" | "r" | "\" | "'" | '"' | "0" | "x" hex_digit hex_digit ) ;

(* Comments *)
comment = line_comment ;
line_comment = "//" { any_char_except_newline } newline ;

(* Whitespace *)
whitespace = " " | "\t" | "\n" | "\r" ;
```

### Grammar Hierarchy Explanation:

**Top Level:**
- `kernelscript_file` contains global declarations
- Global maps, types, namespaces, programs, and top-level userspace

**Program Structure:**
- `program_declaration` defines an eBPF program
- `program_body` contains local maps, config, and functions
- `userspace_declaration` is a top-level block for coordinating all programs

**Scoping Rules:**
- **Global scope**: Maps, types, and userspace coordinator outside any program
- **Program scope**: Local maps, config, and functions within a program  
- **Function scope**: Variables and parameters within functions
- **Userspace scope**: Functions and configs within the top-level userspace block

This specification provides a comprehensive foundation for KernelScript while addressing the concerns about template complexity and userspace integration. The simplified type system avoids complex template metaprograming while still providing safety, and the top-level userspace section enables seamless coordination of multiple eBPF programs with centralized control plane management.
