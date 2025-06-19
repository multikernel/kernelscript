# KernelScript Language Format Specification v1.0

## 1. Design Philosophy and Scope

### 1.1 Core Principles
- **Simplicity over generality**: Avoid complex template systems that burden the compiler
- **Explicit over implicit**: Clear, readable syntax with minimal magic
- **Safety by construction**: Type system prevents common eBPF errors
- **Seamless kernel-userspace integration**: First-class support for bidirectional communication
- **Explicit program lifecycle control**: Programs are first-class values with explicit loading and attachment phases
- **Intuitive scoping model**: Clear separation between kernel and userspace code with shared resources

### 1.2 Simplified Type System
Instead of complex templates, KernelScript uses **simple type aliases** and **fixed-size types**:

```kernelscript
// Simple type aliases for common patterns
type IpAddress = u32
type Port = u16
type PacketBuffer = [u8][1500]
type SmallBuffer = [u8][256]

// Fixed-size arrays (no complex bounds)
u8[64]                 // 64-byte buffer
u32[16]                // 16 u32 values

// Simple map declarations
map<u32, u64> counters : Array(256)
map<IpAddress, PacketStats> flows : HashMap(1024)

// No complex template metaprogramming - just practical, concrete types
```

### 1.3 Intuitive Scoping Model
KernelScript uses a simple and clear scoping model that eliminates ambiguity:

- **Inside `program {}` blocks**: Kernel space (eBPF) - functions and data structures compile to eBPF bytecode
- **Outside `program {}` blocks**: User space - functions and data structures compile to native executable
- **Maps and global configs**: Shared resources accessible from both kernel and user space
- **No wrapper syntax**: Direct, flat structure without unnecessary nesting

```kernelscript
// Shared resources (accessible by both kernel and userspace)
config system { debug: bool = false }
map<u32, u64> counters : Array(256)

// Kernel space (inside program block)
program monitor : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        counters[0] += 1  // Access shared map
        return XDP_PASS
    }
}

// User space (outside program blocks)
struct Args { interface: string }
fn main(args: Args) -> i32 {
    load_program(monitor)
    attach_program(monitor, args.interface, 0)
    return 0
}
```

## 2. Lexical Structure

### 2.1 Keywords
```
program     fn          let         mut         const       config
map         type        struct      enum        if          else
for         while       loop        break       continue    return      import
export      pub         priv        static      unsafe      where       impl
true        false       null        and         or          not         in
as          is          try         catch       throw       defer       go
delete
```

### 2.2 Identifiers
```ebnf
identifier = letter { letter | digit | "_" } 
letter = "a"..."z" | "A"..."Z" 
digit = "0"..."9" 
```

### 2.3 Literals
```ebnf
integer_literal = decimal_literal | hex_literal | octal_literal | binary_literal 
decimal_literal = digit { digit } 
hex_literal = "0x" hex_digit { hex_digit } 
octal_literal = "0o" octal_digit { octal_digit } 
binary_literal = "0b" binary_digit { binary_digit } 

string_literal = '"' { string_char } '"' 
char_literal = "'" char "'" 

boolean_literal = "true" | "false" 
```

## 3. Program Structure

### 3.1 Basic Program Declaration
```ebnf
program = "program" identifier ":" program_type "{" program_body "}" 

program_type = "xdp" | "tc" | "kprobe" | "uprobe" | "tracepoint" | 
               "lsm" | "cgroup_skb" | "socket_filter" | "sk_lookup" 

program_body = { local_map_declaration | 
                 type_declaration | function_declaration | import_declaration } 
```

**Note:** Programs no longer have local `config` sections. All configuration is done through global named config blocks.

### 3.2 Named Configuration Blocks
```kernelscript
// Named configuration blocks - globally accessible
config network {
    enable_logging: bool = true,
    max_packet_size: u32 = 1500,
    blocked_ports: u16[5] = [22, 23, 135, 445, 3389],
    rate_limit: u64 = 1000000,
}

config security {
    threat_threshold: u32 = 100,
    mut current_threat_level: u32 = 0,
    mut enable_strict_mode: bool = false,
}

program network_monitor : xdp {    
    fn main(ctx: XdpContext) -> XdpAction {
        let packet = ctx.packet()
        
        // Use named configuration values
        if (packet.size > network.max_packet_size) {
            if (network.enable_logging) {
                bpf_printk("Packet too large: %d", packet.size)
            }
            return XDP_DROP
        }
        
        // Check blocked ports from network config
        if (packet.is_tcp()) {
            let tcp = packet.tcp_header()
            for (i in 0..5) {
                if (tcp.dst_port == network.blocked_ports[i]) {
                    return XDP_DROP
                }
            }
        }
        
        // Use security config for additional checks
        if (security.enable_strict_mode && security.current_threat_level > security.threat_threshold) {
            return XDP_DROP
        }
        
        return XDP_PASS
    }
}
```

### 3.3 Kernel-Userspace Scoping Model

KernelScript uses a simple and intuitive scoping model:
- **Inside `program {}` blocks**: Kernel space (eBPF) - compiles to eBPF bytecode
- **Outside `program {}` blocks**: User space - compiles to native executable
- **Maps and global configs**: Shared between both kernel and user space

```kernelscript
// Shared configuration and maps (accessible by both kernel and userspace)
config monitoring {
    enable_stats: bool = true,
    sample_rate: u32 = 100,
    mut packets_processed: u64 = 0,
}

map<u32, PacketStats> global_stats : HashMap(1024)

// Userspace types
struct PacketStats {
    packets: u64,
    bytes: u64,
    drops: u64,
}

struct Args {
    interface_id: u32,
    enable_verbose: u32,
}

// Kernel programs (inside program blocks)
program packet_analyzer : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        if (monitoring.enable_stats) {
            // Process packet and update statistics
            monitoring.packets_processed += 1
            update_stats(ctx)
        }
        return XDP_PASS
    }
    
    fn update_stats(ctx: XdpContext) {
        // Kernel helper function
        let key = ctx.hash() % 1024
        global_stats[key].packets += 1
    }
}

program flow_tracker : tc {
    fn main(ctx: TcContext) -> TcAction {
        // Track flow information using shared config
        if (monitoring.enable_stats && (ctx.hash() % monitoring.sample_rate == 0)) {
            // Sample this flow
            let key = ctx.hash() % 1024
            global_stats[key].bytes += ctx.packet_size()
        }
        return TC_ACT_OK
    }
}

// Userspace coordination (outside program blocks)
fn main(args: Args) -> i32 {
    // Command line arguments automatically parsed
    // Usage: program --interface-id=1 --enable-verbose=1
    
    let interface_index = args.interface_id
    
    // Load and coordinate multiple programs
    let analyzer_handle = load_program(packet_analyzer)
    let tracker_handle = load_program(flow_tracker)
    
    attach_program(analyzer_handle, interface_index, 0)
    attach_program(tracker_handle, interface_index, 1)
    
    if (args.enable_verbose == 1) {
        print("Multi-program system started on interface: ", interface_index)
    }
    
    while (true) {
        let stats = get_combined_stats()
        print("Total packets: ", stats.packets)
        print("Total bytes: ", stats.bytes)
        sleep(1000)
    }
    
    return 0
}

// Userspace helper functions
fn get_combined_stats() -> PacketStats {
    let mut total = PacketStats { packets: 0, bytes: 0, drops: 0 }
    for (i in 0..1024) {
        total.packets += global_stats[i].packets
        total.bytes += global_stats[i].bytes
        total.drops += global_stats[i].drops
    }
    return total
}

fn on_packet_event(event: PacketEvent) {
    // Handle events from eBPF programs
}
```

### 3.4 Explicit Program Lifecycle Management

KernelScript supports explicit control over eBPF program loading and attachment through program references and built-in lifecycle functions. This enables advanced use cases like parameter configuration between loading and attachment phases.

#### 3.4.1 Program References and Safety

Programs are first-class values that can be referenced by name and passed to lifecycle functions. The interface enforces safety by requiring programs to be loaded before attachment:

```kernelscript
program packet_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return XDP_PASS
    }
}

program flow_monitor : tc {
    fn main(ctx: TcContext) -> TcAction {
        return TC_ACT_OK
    }
}

// Userspace program coordination (outside program blocks)
fn main() -> i32 {
    // Programs can be referenced by name
    let xdp_prog = packet_filter  // Type: ProgramRef
    let tc_prog = flow_monitor    // Type: ProgramRef
    
    // Explicit loading and attachment
    let prog_handle = load_program(xdp_prog)
    let result = attach_program(prog_handle, "eth0", 0)
    
    return 0
}
```

#### 3.4.2 Lifecycle Functions

**`load_program(program_ref: ProgramRef) -> ProgramHandle`**
- Loads the specified eBPF program into the kernel
- Returns a program handle that abstracts the underlying implementation
- Must be called before attachment
- Enables configuration of program parameters before attachment

**`attach_program(handle: ProgramHandle, target: string, flags: u32) -> u32`**
- Attaches the loaded program to the specified target using its handle
- First parameter must be a ProgramHandle returned from load_program()
- Target and flags interpretation depends on program type:
  - **XDP**: target = interface name ("eth0"), flags = XDP attachment flags
  - **TC**: target = interface name ("eth0"), flags = direction (ingress/egress)
  - **Kprobe**: target = function name ("sys_read"), flags = unused (0)
  - **Cgroup**: target = cgroup path ("/sys/fs/cgroup/test"), flags = unused (0)
- Returns 0 on success, negative error code on failure

**Safety Benefits:**
- **Compile-time enforcement**: Cannot call `attach_program()` without first calling `load_program()` - the type system prevents this
- **Implementation abstraction**: Users work with `ProgramHandle` instead of raw file descriptors
- **Resource safety**: Program handles abstract away the underlying resource management

#### 3.4.3 Advanced Usage Patterns

**Configuration Between Load and Attach:**
```kernelscript
config network {
    mut enable_filtering: bool = false,
    mut max_packet_size: u32 = 1500,
}

program adaptive_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        if (network.enable_filtering && ctx.packet_size() > network.max_packet_size) {
            return XDP_DROP
        }
        return XDP_PASS
    }
}

// Userspace coordination and CLI handling
struct Args {
    interface: string,
    strict_mode: bool,
}

fn main(args: Args) -> i32 {
    // Load program first
    let prog_handle = load_program(adaptive_filter)
    
    // Configure parameters based on command line
    network.enable_filtering = args.strict_mode
    if (args.strict_mode) {
        network.max_packet_size = 1000  // Stricter limit
    }
    
    // Now attach with configured parameters
    let result = attach_program(prog_handle, args.interface, 0)
    
    if (result == 0) {
        print("Filter attached successfully")
    } else {
        print("Failed to attach filter")
        return 1
    }
    
    return 0
}
```

**Multi-Program Coordination:**
```kernelscript
program ingress_monitor : xdp {
    fn main(ctx: XdpContext) -> XdpAction { return XDP_PASS }
}

program egress_monitor : tc {
    fn main(ctx: TcContext) -> TcAction { return TC_ACT_OK }
}

program security_check : lsm {
    fn main(ctx: LsmContext) -> i32 { return 0 }
}

// Multi-program userspace coordination
fn main() -> i32 {
    // Load all programs
    let ingress_handle = load_program(ingress_monitor)
    let egress_handle = load_program(egress_monitor)
    let security_handle = load_program(security_check)
    
    // Attach in specific order for coordinated monitoring
    attach_program(security_handle, "socket_connect", 0)
    attach_program(ingress_handle, "eth0", 0)
    attach_program(egress_handle, "eth0", 1)  // Egress direction
    
    print("Multi-program monitoring system active")
    
    // Event processing loop
    while (true) {
        process_events()
        sleep(1000)
    }
    
    return 0
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

// Fixed-size string types (same syntax for both kernel and userspace)
str<N>                 // Fixed-size string with capacity N characters (N can be any positive integer)

// Pointer types (restricted usage in kernel context)
*u8, *u32, *void       // Pointers to specific types

// Program reference types (for explicit program lifecycle control)
ProgramRef             // Reference to an eBPF program for loading/attachment
ProgramHandle          // Handle returned by load_program() for safe attachment
```

### 4.2 Compound Types
```kernelscript
// Fixed-size arrays
u8[64]                 // Array of 64 bytes
u32[16]                // Array of 16 u32 values

// Structures
struct PacketHeader {
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    flags: u16,
}

// Enumerations (C-style naming)
enum XdpAction {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XDP_REDIRECT = 4,
}

enum TcAction {
    TC_ACT_UNSPEC = -1,
    TC_ACT_OK = 0,
    TC_ACT_SHOT = 2,
    TC_ACT_PIPE = 3,
    TC_ACT_STOLEN = 4,
    TC_ACT_QUEUED = 5,
    TC_ACT_REPEAT = 6,
    TC_ACT_REDIRECT = 7,
}
```

### 4.3 Type Aliases for Common Patterns
```kernelscript
// Simple type aliases without complex constraints
type IpAddress = u32
type Port = u16
type PacketSize = u16
type Timestamp = u64

// Buffer types with fixed sizes (no templates needed)
type EthBuffer = [u8 14]      // Ethernet header buffer
type IpBuffer = [u8 20]       // IP header buffer
type SmallBuffer = [u8 256];  // Small general buffer
type PacketBuffer = [u8 1500] // Maximum packet buffer

// String type aliases for common patterns
type ProcessName = str<16>     // Process name string
type IpAddressStr = str<16>    // IP address string ("255.255.255.255")
type FilePath = str<256>       // File path string
type LogMessage = str<128>     // Log message string
type ShortString = str<32>     // Short general-purpose string
type MediumString = str<128>   // Medium general-purpose string
```

### 4.4 String Operations
KernelScript supports fixed-size strings with `str<N>` syntax, where N can be any positive integer (e.g., `str<1>`, `str<10>`, `str<42>`, `str<1000>`). The following operations are supported:

```kernelscript
// String declaration and assignment (N can be any positive integer)
let name: str<16> = "John"
let surname: str<16> = "Doe"
let mut buffer: str<32> = "Hello"
let small_buffer: str<8> = "tiny"
let custom_size: str<42> = "custom"
let large_buffer: str<512> = "large text content"

// Assignment
buffer = name                  // Assignment (size must be compatible)

// Indexing (read-only character access)
let first_char: char = name[0] // Returns 'J'
let last_char: char = name[3]  // Returns 'n'

// String concatenation (explicit result size required)
let full_name: str<32> = name + surname  // "JohnDoe"
let greeting: str<20> = "Hello " + name  // "Hello John"
let custom_msg: str<100> = small_buffer + " and " + custom_size  // Arbitrary sizes work

// String comparison
if (name == "John") {             // Equality comparison
    print("Name matches")
}

if (surname != "Smith") {         // Inequality comparison
    print("Surname is not Smith")
}

// Examples with different contexts
struct PersonInfo {
    name: ProcessName,          // str<16>
    address: FilePath,          // str<256>
    status: ShortString,        // str<32>
}

// Kernel space usage
program user_monitor : kprobe("sys_open") {
    fn main(ctx: KprobeContext) -> i32 {
        let process_name: ProcessName = get_current_process_name()
        let file_path: FilePath = get_file_path(ctx)
        
        // String operations work the same in kernel space
        if (process_name == "malware") {
            let log_msg: LogMessage = "Blocked process: " + process_name
            bpf_printk(log_msg)
            return -1
        }
        
        return 0
    }
}

// Userspace usage
struct Args {
    interface: str<16>,
    config_file: str<256>,
}

fn main(args: Args) -> i32 {
    // Same string operations in userspace
    if (args.interface == "eth0") {
        let status_msg: str<64> = "Using interface: " + args.interface
        print(status_msg)
    }
    
    return 0
}
```

## 5. eBPF Maps and Global Sharing

### 5.1 Map Declaration Syntax
```ebnf
map_declaration = "map" "<" key_type "," value_type ">" identifier ":" map_type "(" map_config ")" 
                  [ map_attributes ] ";" 

map_type = "HashMap" | "Array" | "ProgArray" | "PerCpuHash" | "PerCpuArray" |
           "LruHash" | "RingBuffer" | "PerfEvent" | "StackTrace" 

map_config = max_entries [ "," additional_config ] 
map_attributes = "{" { map_attribute "," } "}" 
map_attribute = "pinned" | "read_only" | "write_only" | "userspace_writable" |
                "pin_path" "=" string_literal | "permissions" "=" string_literal 
```

### 5.2 Global Maps (Shared Across Programs)

Global maps are declared outside any program block and are automatically shared:

```kernelscript
// Global maps - automatically shared between all programs
map<FlowKey, FlowStats> global_flows : HashMap(10000) {
    pinned: "/sys/fs/bpf/global_flows",
}

map<u32, InterfaceStats> interface_stats : Array(256) {
    pinned: "/sys/fs/bpf/interface_stats",
}

map<SecurityEvent> security_events : RingBuffer(1024 * 1024) {
    pinned: "/sys/fs/bpf/security_events",
}

map<ConfigKey, ConfigValue> global_config : Array(64) {
    pinned: "/sys/fs/bpf/global_config",
}

// Program 1: Can access all global maps
program ingress_monitor : xdp {
    // Local maps (only accessible within this program)
    map<u32, LocalStats> local_cache : HashMap(512)
    
    fn main(ctx: XdpContext) -> XdpAction {
        let flow_key = extract_flow_key(ctx)?
        
        // Access global map directly
        if (global_flows[flow_key] == null) {
            global_flows[flow_key] = FlowStats::new()
        }
        global_flows[flow_key].ingress_packets += 1
        global_flows[flow_key].ingress_bytes += ctx.packet_size()
        
        // Update interface stats
        interface_stats[ctx.ingress_ifindex()].packets += 1
        
        return XDP_PASS
    }
}

// Program 2: Automatically has access to the same global maps
program egress_monitor : tc {
    // Local maps
    map<FlowKey, EgressInfo> egress_cache : LruHash(1000)
    
    fn main(ctx: TcContext) -> TcAction {
        let flow_key = extract_flow_key(ctx)?
        
        // Same global map, no import needed
        if (global_flows[flow_key] != null) {
            global_flows[flow_key].egress_packets += 1
            global_flows[flow_key].egress_bytes += ctx.packet_size()
        }
        
        // Check global configuration
        let enable_filtering = if (global_config[CONFIG_KEY_ENABLE_FILTERING] != null) {
            global_config[CONFIG_KEY_ENABLE_FILTERING]
        } else {
            CONFIG_VALUE_BOOL_FALSE
        }
        
        if (enable_filtering.as_bool() && should_drop(flow_key)) {
            // Log to global security events
            security_events.submit(SecurityEvent {
                event_type: EVENT_TYPE_PACKET_DROPPED,
                flow_key: flow_key,
                timestamp: bpf_ktime_get_ns(),
            })
            return TC_ACT_SHOT
        }
        
        return TC_ACT_OK
    }
}

// Program 3: Security analyzer using the same global maps
program security_analyzer : lsm("socket_connect") {
    fn main(ctx: LsmContext) -> i32 {
        let flow_key = extract_flow_key_from_socket(ctx)?
        
        // Check global flow statistics
        if (global_flows[flow_key] != null) {
            let flow_stats = global_flows[flow_key]
            if (flow_stats.is_suspicious()) {
                security_events.submit(SecurityEvent {
                    event_type: EVENT_TYPE_SUSPICIOUS_CONNECTION,
                    flow_key: flow_key,
                    timestamp: bpf_ktime_get_ns(),
                })
                return -EPERM  // Block connection
            }
        }
        
        return 0  // Allow connection
    }
}
```

### 5.3 Local vs Global Map Scope

```kernelscript
// Global maps (outside any program)
map<u32, GlobalCounter> global_counters : Array(256)
map<Event> event_stream : RingBuffer(1024 * 1024)

program producer : kprobe("sys_read") {
    // Local maps (only accessible within this program)
    map<u32, LocalState> producer_state : HashMap(1024)
    
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32
        
        // Update local state
        producer_state[pid] += 1
        
        // Update global counter (accessible by other programs)
        global_counters[pid % 256] += 1
        
        // Send event to global stream
        let event = Event {
            pid: pid,
            syscall: "read",
            timestamp: bpf_ktime_get_ns(),
        }
        event_stream.submit(event)
        
        return 0
    }
    
}

program consumer : kprobe("sys_write") {
    // Local maps
    map<u32, LocalState> consumer_state : HashMap(1024)
    
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32
        
        // Access global counter (same map as producer program)
        let read_count = global_counters[pid % 256]
        
        // Update local state
        let local_state = LocalState {
            write_count: 1,
            corresponding_reads: read_count,
        }
        consumer_state[pid] = local_state
        
        return 0
    }
    
}
```

### 5.4 Map Examples
```kernelscript
// Global maps accessible by all programs
map<u32, PacketStats> packet_stats : HashMap(1024) {
    pinned: "/sys/fs/bpf/packet_stats",
}

map<u32, u64> counters : PerCpuArray(256) {
    pinned: "/sys/fs/bpf/counters",
}

map<FlowKey, FlowInfo> active_flows : LruHash(10000) {
    pinned: "/sys/fs/bpf/active_flows",
}

map<PacketEvent> events : RingBuffer(1024 * 1024) {
    pinned: "/sys/fs/bpf/events",
}

map<ConfigKey, ConfigValue> config_map : Array(16) {
    pinned: "/sys/fs/bpf/config",
}

program simple_monitor : xdp {
    // Local map - only accessible within this program
    map<u32, LocalCache> cache : HashMap(256)
    
    fn main(ctx: XdpContext) -> XdpAction {
        // Access global maps directly
        packet_stats[ctx.packet_type()] += 1
        counters[0] += 1
        
        // Access local map
        cache[ctx.hash()] = LocalCache::new()
        
        return XDP_PASS
    }
}
```

## 6. Functions and Control Flow

### 6.1 Function Declaration
```ebnf
function_declaration = [ visibility ] "fn" identifier "(" parameter_list ")" [ "->" return_type ] "{" statement_list "}" 

visibility = "pub" | "priv" 
parameter_list = [ parameter { "," parameter } ] 
parameter = identifier ":" type_annotation 
return_type = type_annotation 
```

### 6.2 Main Program Function
```kernelscript
program simple_xdp : xdp {
    // Required main function - entry point
    fn main(ctx: XdpContext) -> XdpAction {
        let packet = ctx.packet()?
        
        if packet.is_tcp() {
            return XDP_PASS
        }
        
        return XDP_DROP
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
    let mut sum: u32 = 0
    for (i in 0..(len / 2)) {
        sum += data[i * 2] + (data[i * 2 + 1] << 8)
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return !(sum as u16)
}
```

### 6.4 Control Flow Statements
```kernelscript
// Conditional statements
if (condition) {
    // statements
} else if (other_condition) {
    // statements
} else {
    // statements
}

// Pattern matching (simplified)
let protocol = packet.protocol()
if (protocol == PROTOCOL_TCP) {
    handle_tcp(packet)
} else if (protocol == PROTOCOL_UDP) {
    handle_udp(packet)
} else if (protocol == PROTOCOL_ICMP) {
    handle_icmp(packet)
} else {
    // default case
}

// Loops with automatic bounds checking
for (i in 0..MAX_ITERATIONS) {
    if (should_break()) {
        break
    }
    process_item(i)
}

// While loops (compiler ensures termination)
let iterations = 0
while (condition && iterations < MAX_ITERATIONS) {
    do_work()
    iterations = iterations + 1
}
```

## 7. Error Handling and Resource Management

### 7.1 Throw and Catch Statements

KernelScript provides modern error handling through `throw` and `catch` statements that compile to efficient C error checking code. Error handling uses integer values for maximum performance and compatibility with both eBPF and userspace environments.

```kernelscript
// Error codes as simple enums or constants (C-style naming)
enum ParseError {
    PARSE_ERROR_TOO_SHORT = 1,
    PARSE_ERROR_INVALID_VERSION = 2,
    PARSE_ERROR_BAD_CHECKSUM = 3,
}

enum NetworkError {
    NETWORK_ERROR_ALLOCATION_FAILED = 10,
    NETWORK_ERROR_MAP_UPDATE_FAILED = 11,
    NETWORK_ERROR_RATE_LIMITED = 12,
}

// Or use simple constants
const ERROR_INVALID_PACKET = 100
const ERROR_RATE_LIMITED = 101

// Functions can throw integer error codes
fn parse_ip_header(packet: *u8, len: u32) -> IpHeader {
    if (len < 20) {
        throw PARSE_ERROR_TOO_SHORT  // Throws integer value 1
    }
    
    let header = cast_to_ip_header(packet)
    if (header.version != 4) {
        throw PARSE_ERROR_INVALID_VERSION  // Throws integer value 2
    }
    
    return header
}

// Error handling with try/catch blocks using integer matching
fn process_packet(ctx: XdpContext) -> XdpAction {
    try {
        let packet = get_packet(ctx)
        if (packet == null) {
            throw NETWORK_ERROR_ALLOCATION_FAILED  // Throws integer value 10
        }
        
        let header = parse_ip_header(packet.data, packet.len)
        update_flow_stats(header)
        
        return XDP_PASS
        
    } catch 1 {  // PARSE_ERROR_TOO_SHORT
        return XDP_DROP
        
    } catch 2 {  // PARSE_ERROR_INVALID_VERSION
        return XDP_DROP
        
    } catch 10 {  // NETWORK_ERROR_ALLOCATION_FAILED
        return XDP_ABORTED
        
    } catch _ {  // Catch-all for any other error
        return XDP_ABORTED
    }
}

// You can also throw literal integers or variables
fn validate_input(value: i32) {
    if (value < 0) {
        throw 42  // Direct integer throw
    }
    
    let error_code = compute_error_code(value)
    if (error_code != 0) {
        throw error_code  // Variable throw
    }
}
```

### 7.2 Resource Management with Defer

The `defer` statement ensures cleanup code runs automatically at function exit, regardless of how the function returns (normal return, throw, or early exit).

```kernelscript
// Resource management with automatic cleanup
fn update_shared_counter(index: u32) -> bool {
    let data = shared_counters[index]
    if (data == null) {
        return false
    }
    
    // Acquire lock and ensure it's always released
    bpf_spin_lock(&data.lock)
    defer bpf_spin_unlock(&data.lock)  // Always executes at function exit
    
    // Critical section
    data.counter += 1
    
    if (data.counter > 1000000) {
        throw NETWORK_ERROR_RATE_LIMITED  // defer still executes (throws 12)
    }
    
    return true  // defer executes here too
}

// Multiple defer statements execute in reverse order (LIFO)
fn complex_resource_management() -> bool {
    let buffer = allocate_buffer()
    defer free_buffer(buffer)          // Executes 3rd
    
    let lock = acquire_lock()
    defer release_lock(lock)           // Executes 2nd
    
    let fd = open_file("config.txt")
    defer close_file(fd)               // Executes 1st
    
    // Use resources safely
    return process_data(buffer, lock, fd)
    // All defer statements execute automatically in reverse order
}
```

### 7.3 Defer with Try/Catch

Defer statements work seamlessly with error handling - cleanup always occurs even when exceptions are thrown or caught.

```kernelscript
fn safe_packet_processing(ctx: XdpContext) -> XdpAction {
    let packet_buffer = allocate_packet_buffer()
    defer free_packet_buffer(packet_buffer)  // Always executes
    
    try {
        let lock = acquire_flow_lock()
        defer release_flow_lock(lock)        // Always executes
        
        let flow_data = process_flow(packet_buffer)
        if (flow_data.is_suspicious()) {
            throw NETWORK_ERROR_RATE_LIMITED  // Throws 12
        }
        
        return XDP_PASS
        
    } catch 12 {  // NETWORK_ERROR_RATE_LIMITED
        increment_drop_counter()
        return XDP_DROP
        // Both defer statements execute even in catch block
    }
}
```

### 7.4 Error Handling Rules and Compiler Behavior

#### 7.4.1 eBPF Program Functions

**All throws must be caught** in eBPF program functions. Uncaught throws result in **compilation errors**.

```kernelscript
program packet_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        try {
            let result = process_packet(ctx)  // Might throw
            return XDP_PASS
            
        } catch 1 {  // PARSE_ERROR_TOO_SHORT
            return XDP_DROP
            
        } catch 10 {  // NETWORK_ERROR_ALLOCATION_FAILED
            return XDP_ABORTED
        }
        // ❌ Compiler ERROR if any possible throw is not caught
    }
}
```

#### 7.4.2 Helper Functions

Helper functions can propagate errors without catching them - this enables natural error composition and reduces boilerplate.

```kernelscript
// Helper functions can throw without catching
fn extract_flow_key(ctx: XdpContext) -> FlowKey {
    let packet = get_packet(ctx)
    if packet == null {
        throw NETWORK_ERROR_ALLOCATION_FAILED  // ✅ OK - propagates to caller (throws 10)
    }
    
    return parse_flow_key(packet)  // May also throw - propagates up
}

fn validate_flow(key: FlowKey) -> FlowState {
    let state = lookup_flow_state(key)  // May throw
    if state.is_expired() {
        throw NETWORK_ERROR_RATE_LIMITED  // ✅ OK - propagates to caller (throws 12)
    }
    
    return state
}
```

#### 7.4.3 Userspace Functions

Userspace functions generate **compiler warnings** for uncaught throws, but compilation succeeds. Uncaught throws at runtime terminate the program.

```kernelscript
fn main() -> i32 {
    let prog = load_program(packet_filter)    // ⚠️ Warning: might throw
    attach_program(prog, "eth0", 0)           // ⚠️ Warning: might throw
    return 0
    // If any throw occurs, program terminates (like panic)
}

// Better - explicit error handling
fn main() -> i32 {
    try {
        let prog = load_program(packet_filter)
        attach_program(prog, "eth0", 0)
        print("Program attached successfully")
        return 0
        
    } catch 20 {  // LOAD_ERROR_PROGRAM_NOT_FOUND
        print("Failed to load program")
        return 1
        
    } catch 30 {  // ATTACH_ERROR_PERMISSION_DENIED
        print("Permission denied - check privileges")
        return 2
    }
}
```

### 7.5 Panic and Assertions

For unrecoverable errors, KernelScript provides panic and assert macros:

```kernelscript
// Panic for unrecoverable errors
fn critical_operation() {
    if (unsafe_condition()) {
        panic("Critical system state violated")
    }
}

// Simple assertions
fn validate_state() {
    assert(map_size < MAX_ENTRIES, "Map overflow detected")
}
```

## 8. User-Space Integration

### 8.1 Command Line Argument Handling

KernelScript provides automatic command line argument parsing for userspace programs. Users can define a custom struct to describe their command line options, and the compiler generates the parsing code using `getopt_long()`.

```kernelscript
// Define command line arguments structure (userspace)
struct Args {
    interface_id: u32,          // --interface_id=<value>
    enable_debug: u32,          // --enable_debug=<0|1>  
    packet_limit: u64,          // --packet_limit=<value>
    timeout_ms: u32,            // --timeout_ms=<value>
}

fn main(args: Args) -> i32 {
    // Arguments automatically parsed from command line
    // Usage: program --interface_id=1 --enable_debug=1 --packet_limit=1000 --timeout_ms=5000
    
    if (args.enable_debug == 1) {
        print("Debug mode enabled for interface: ", args.interface_id)
        print("Packet limit: ", args.packet_limit)
        print("Timeout: ", args.timeout_ms, " ms")
    }
    
    // Use the parsed arguments
    configure_system(args.interface_id, args.packet_limit, args.timeout_ms)
    
    return 0
}

fn configure_system(interface_id: u32, packet_limit: u64, timeout_ms: u32) {
    // Userspace helper function
}

// For programs that don't need command line arguments
fn main() -> i32 {
    print("Simple program with no arguments")
    return 0
}
```

**Automatic Code Generation:**
- Field names are used exactly as command line options: `interface_id` → `--interface_id`
- The compiler generates `getopt_long()` calls with appropriate option parsing
- Type validation ensures only supported primitive types (u8, u16, u32, u64, i8, i16, i32, i64) are used
- Help text is automatically generated based on struct field names

### 8.2 Top-Level Userspace Coordination with Global Maps
```kernelscript
// Global maps (accessible from all programs and userspace)
map<FlowKey, FlowStats> global_flows : HashMap(10000) {
    pinned: "/sys/fs/bpf/global_flows",
}

map<Event> global_events : RingBuffer(1024 * 1024) {
    pinned: "/sys/fs/bpf/global_events",
}

map<ConfigKey, ConfigValue> global_config : Array(64) {
    pinned: "/sys/fs/bpf/global_config",
}

// Multiple eBPF programs working together
program network_monitor : xdp {
    // Local maps (only accessible within this program)
    map<u32, LocalStats> local_stats : HashMap(1024)
    
    fn main(ctx: XdpContext) -> XdpAction {
        // Access global maps directly
        let flow_key = extract_flow_key(ctx)?
        global_flows[flow_key] += 1
        
        // Use named config for decisions
        if monitoring.enable_stats {
            monitoring.packets_processed += 1
        }
        
        // Send event to global stream
        global_events.submit(EVENT_PACKET_PROCESSED { flow_key })
        
        return XDP_PASS
    }
}

program security_filter : lsm("socket_connect") {
    fn main(ctx: LsmContext) -> i32 {
        let flow_key = extract_flow_key_from_socket(ctx)?
        
        // Check global flow statistics for threat detection
        if (global_flows[flow_key] != null) {
            let flow_stats = global_flows[flow_key]
            if (flow_stats.is_suspicious()) {
                global_events.submit(EVENT_THREAT_DETECTED { flow_key })
                return -EPERM  // Block connection
            }
        }
        
        return 0  // Allow connection
    }
}

struct SystemCoordinator {
    network_monitor: BpfProgram,
    security_filter: BpfProgram,
    
    // Global map access (shared across all programs)
    global_flows: &'static GlobalMap<FlowKey, FlowStats>,
    global_events: &'static GlobalRingBuffer<Event>,
    global_config: &'static GlobalMap<ConfigKey, ConfigValue>,
}

impl SystemCoordinator {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            network_monitor: load_program(network_monitor),
            security_filter: load_program(security_filter),
            
            // Global maps are automatically accessible
            global_flows: GlobalMaps::flows(),
            global_events: GlobalMaps::events(),
            global_config: GlobalMaps::config(),
        })
    }
    
    fn start(&mut self) -> Result<(), Error> {
        // Coordinate multiple programs
        attach_program(network_monitor, "eth0", 0)?
        attach_program(security_filter, "socket_connect", 0)?
        Ok(())
    }
    
    fn process_events(&self) {
        // Process events from all programs
        let event = self.global_events.read()
        if (event != null) {
            if (event.event_type == EVENT_PACKET_PROCESSED) {
                print("Processed packet for flow: ", event.flow_key)
            } else if (event.event_type == EVENT_THREAT_DETECTED) {
                print("THREAT DETECTED: ", event.flow_key)
                self.handle_threat(event.flow_key)
            }
        }
    }
    
    fn handle_threat(&self, flow_key: FlowKey) {
        // Coordinated response across all programs
        self.global_config[CONFIG_KEY_THREAT_LEVEL] = CONFIG_VALUE_HIGH
    }
}

struct Args {
    interface_id: u32,
    monitoring_enabled: u32,
}

fn main(args: Args) -> i32 {
    // Command line arguments automatically parsed
    // Usage: program --interface-id=0 --monitoring-enabled=1
    
    let mut coordinator = SystemCoordinator::new().unwrap()
    coordinator.start_on_interface_by_id(args.interface_id).unwrap()
    
    if (args.monitoring_enabled == 1) {
        print("Multi-program eBPF system started on interface: ", args.interface_id)
    }
    
    loop {
        coordinator.process_events()
        sleep(100)
    }
    
    return 0
}
```

### 8.3 Cross-Language Bindings
```kernelscript
// Runtime configuration for system behavior
config runtime {
    enable_logging: bool = true,
    verbose_mode: bool = false,
}

program network_monitor : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        if (runtime.enable_logging) {
            print("Processing packet")
        }
        return XDP_PASS
    }
}

program flow_analyzer : tc {
    fn main(ctx: TcContext) -> TcAction {
        return TC_ACT_OK
    }
}

// Userspace coordination with cross-language binding support
struct Args {
    interface_id: u32,
    verbose_mode: u32,
    enable_monitoring: u32,
}

fn main(args: Args) -> i32 {
    // Command line arguments automatically parsed
    // Usage: program --interface-id=0 --verbose-mode=1 --enable-monitoring=1
    
    let network_monitor = load_program(network_monitor)
    let flow_analyzer = load_program(flow_analyzer)
    
    attach_program(network_monitor, args.interface_id, 0)
    attach_program(flow_analyzer, args.interface_id, 1)
    
    // Update runtime config based on command line
    runtime.verbose_mode = (args.verbose_mode == 1)
    
    if (runtime.verbose_mode) {
        print("Multi-program system loaded on interface: ", args.interface_id)
        print("Verbose mode enabled")
    }
    
    // Coordinate both programs
    handle_system_events(args.verbose_mode = = 1)
    
    return 0
}

fn handle_system_events(verbose: bool) {
    while (true) {
        // Process events from all programs
        if (runtime.verbose_mode) {
            print("Processing system events...")
        }
        sleep(1000)
    }
}

```

## 9. Memory Management and Safety

### 9.1 Automatic Bounds Checking
```kernelscript
fn safe_packet_access(packet: &Packet, offset: usize, size: usize) -> *u8 {
    // Compiler automatically inserts bounds checks
    if (offset + size <= packet.len()) {
        &packet.data()[offset]
    } else {
        null
    }
}

// Array access with compile-time and runtime checks
fn process_array(arr: &u32[256], index: usize) -> u32 {
    // Compile-time check if index is constant
    arr[index]  // Compiler generates bounds check if needed
}
```

### 9.2 Stack Management
```kernelscript
// Automatic stack usage tracking
fn large_function() {
    let buffer: u8[400] = [0; 400];  // Compiler tracks stack usage
    // Compiler will automatically spill to map if stack limit exceeded
    
    process_buffer(&buffer)
    
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
    pub fn parse_ethernet(data: &[u8]) -> Result<EthernetHeader, ParseError>
    pub fn parse_ipv4(data: &[u8]) -> Result<Ipv4Header, ParseError>
    pub fn parse_tcp(data: &[u8]) -> Result<TcpHeader, ParseError>
    pub fn calculate_checksum(data: &[u8]) -> u16
}

// String utilities (limited for eBPF)
mod str {
    pub fn compare(a: &[u8], b: &[u8]) -> i32
    pub fn find_byte(haystack: &[u8], needle: u8) -> i32  // Returns index or -1 if not found
}

// Math utilities
mod math {
    pub fn min(a: u64, b: u64) -> u64
    pub fn max(a: u64, b: u64) -> u64
    pub fn clamp(value: u64, min: u64, max: u64) -> u64
}

// Program lifecycle management (userspace only)
mod program {
    // Load an eBPF program and return its handle
    pub fn load_program(program_ref: ProgramRef) -> ProgramHandle
    
    // Attach a program to a target with optional flags using its handle
    // - First parameter must be a ProgramHandle returned from load_program()
    // - For XDP: target is interface name (e.g., "eth0"), flags are XDP attachment flags
    // - For TC: target is interface name, flags indicate direction (ingress/egress)
    // - For Kprobe: target is function name (e.g., "sys_read"), flags are unused (0)
    // - For Cgroup: target is cgroup path (e.g., "/sys/fs/cgroup/test"), flags are unused (0)
    pub fn attach_program(handle: ProgramHandle, target: string, flags: u32) -> u32
}
```

### 11.2 Context Helpers
```kernelscript
// XDP context helpers
impl XdpContext {
    pub fn packet(&self) -> Result<Packet, ContextError>
    pub fn adjust_head(&mut self, delta: i32) -> Result<(), ContextError>
    pub fn adjust_tail(&mut self, delta: i32) -> Result<(), ContextError>
}

// Kprobe context helpers
impl KprobeContext {
    pub fn arg<T>(&self, index: usize) -> T
    pub fn return_value<T>(&self) -> T
    pub fn function_name(&self) -> &str
}
```

## 12. Example Programs

### 12.1 Simple Packet Filter
```kernelscript
// Named configuration for packet filtering
config filtering {
    blocked_ports: u16[4] = [22, 23, 135, 445],
    enable_logging: bool = false,
    max_packet_size: u32 = 1500,
}

config system {
    mut packets_dropped: u64 = 0,
    mut packets_processed: u64 = 0,
}

program simple_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let packet = ctx.packet()
        if (packet == null) {
            return XDP_PASS
        }
        
        system.packets_processed += 1
        
        if (packet.is_tcp()) {
            let tcp = packet.tcp_header()
            for (i in 0..4) {
                if (tcp.dst_port == filtering.blocked_ports[i]) {
                    if (filtering.enable_logging) {
                        bpf_printk("Blocked port %d", tcp.dst_port)
                    }
                    system.packets_dropped += 1
                    return XDP_DROP
                }
            }
        }
        
        return XDP_PASS
    }
}

// Userspace coordination with explicit program lifecycle
struct Args {
    interface: string,
    quiet_mode: bool,
    strict_mode: bool,
}

fn main(args: Args) -> i32 {
    // Command line arguments automatically parsed
    // Usage: program --interface=eth0 --quiet-mode=false --strict-mode=true
    
    // Configure system before loading program
    filtering.enable_logging = !args.quiet_mode
    if (args.strict_mode) {
        filtering.max_packet_size = 1000  // Stricter filtering
    }
    
    // Explicit program lifecycle management
    let prog_handle = load_program(simple_filter)
    
    let attach_result = attach_program(prog_handle, args.interface, 0)
    if (attach_result != 0) {
        print("Failed to attach program to interface: ", args.interface)
        return 1
    }
    
    if (!args.quiet_mode) {
        print("Packet filter started on interface: ", args.interface)
        print("Blocking ports: 22, 23, 135, 445")
        if (args.strict_mode) {
            print("Strict mode enabled - max packet size: 1000")
        }
    }
    
    // Monitor system health using config stats
    while (true) {
        if (system.packets_dropped > 1000 && !args.quiet_mode) {
            print("High drop rate detected: ", system.packets_dropped)
        }
        sleep(10000)
    }
    
    return 0
}
```

### 12.2 Performance Monitoring
```kernelscript
// Global maps for performance data
map<u32, CallInfo> active_calls : HashMap(1024)
map<u32, u64> read_stats : Array(1024)
map<u32, u64> write_stats : Array(1024)

struct CallInfo {
    start_time: u64,
    bytes_requested: u32,
}

program perf_monitor : kprobe("sys_read") {
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32
        let call_info = CallInfo {
            start_time: bpf_ktime_get_ns(),
            bytes_requested: ctx.arg_u32(2),
        }
        
        active_calls[pid] = call_info
        return 0
    }
    
    fn on_return(ctx: KretprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32
        
        let call_info = active_calls[pid]
        if (call_info != null) {
            let duration = bpf_ktime_get_ns() - call_info.start_time
            read_stats[pid % 1024] += duration
            delete active_calls[pid]
        }
        
        return 0
    }
}

program write_monitor : kprobe("sys_write") {
    fn main(ctx: KprobeContext) -> i32 {
        let pid = bpf_get_current_pid_tgid() as u32
        let duration = measure_write_time(ctx)
        write_stats[pid % 1024] += duration
        return 0
    }
}

// Userspace coordination for all monitoring programs
struct Args {
    interval_ms: u32,
    show_details: u32,
    help_mode: u32,
}

fn main(args: Args) -> i32 {
    // Command line arguments automatically parsed
    // Usage: program --interval-ms=5000 --show-details=1 --help-mode=0
    
    if (args.help_mode == 1) {
        print("Performance monitoring system")
        print("Options: --interval-ms = <ms> --show-details=0/1 --help-mode=0/1")
        return 0
    }
    
    let interval = if (args.interval_ms == 0) { 5000 } else { args.interval_ms }
    let show_details = (args.show_details == 1)
    
    // Explicit program lifecycle management for multiple programs
    let read_handle = load_program(perf_monitor)
    let write_handle = load_program(write_monitor)
    
    // Attach programs to different kprobe targets
    let read_attach = attach_program(read_handle, "sys_read", 0)
    let write_attach = attach_program(write_handle, "sys_write", 0)
    
    if (read_attach != 0 || write_attach != 0) {
        print("Failed to attach monitoring programs")
        return 1
    }
    
    print("Performance monitoring active - read and write syscalls")
    
    while (true) {
        if (show_details) {
            print_detailed_stats()
        } else {
            print_summary_stats()
        }
        sleep(interval)
    }
    
    return 0
}

fn print_detailed_stats() {
    // Access global maps to show detailed performance data
    for (i in 0..1024) {
        if (read_stats[i] > 0) {
            print("PID bucket ", i, " read time: ", read_stats[i])
        }
        if (write_stats[i] > 0) {
            print("PID bucket ", i, " write time: ", write_stats[i])
        }
    }
}

fn print_summary_stats() {
    let total_read_time = 0u64
    let total_write_time = 0u64
    
    for (i in 0..1024) {
        total_read_time += read_stats[i]
        total_write_time += write_stats[i]
    }
    
    print("Total read time: ", total_read_time)
    print("Total write time: ", total_write_time)
}
```

## 13. Complete Formal Grammar (EBNF)

```ebnf
(* KernelScript Complete Grammar *)

(* Top-level structure *)
kernelscript_file = { global_declaration } 

global_declaration = config_declaration | map_declaration | type_declaration | 
                    program_declaration | function_declaration | struct_declaration | 
                    bindings_declaration | import_declaration 

(* Map declarations - global scope *)
map_declaration = "map" "<" key_type "," value_type ">" identifier 
                  ":" map_type "(" map_config ")" [ map_attributes ] 

map_type = "HashMap" | "Array" | "PerCpuHash" | "PerCpuArray" | "LruHash" |
           "RingBuffer" | "PerfEvent" | "StackTrace" | "ProgArray" 

map_config = integer_literal [ "," map_config_item { "," map_config_item } ] 
map_config_item = identifier "=" literal 

map_attributes = "{" map_attribute { "," map_attribute } [ "," ] "}" 
map_attribute = identifier [ "=" literal ] 

(* Program declarations *)
program_declaration = "program" identifier ":" program_type "{" program_body "}" 

program_type = "xdp" | "tc" | "kprobe" | "uprobe" | "tracepoint" | "lsm" | 
               "cgroup_skb" | "socket_filter" | "sk_lookup" | "raw_tracepoint" 

program_body = { program_item } 

program_item = local_map_declaration | function_declaration | type_declaration 

(* Local maps - inside program scope *)
local_map_declaration = "map" "<" type_annotation [ "," type_annotation ] ">" identifier 
                        ":" map_type "(" map_config ")" [ map_attributes ] 

(* Named configuration declarations *)
config_declaration = "config" identifier "{" { config_field } "}" 
config_field = [ "mut" ] identifier ":" type_annotation [ "=" expression ] "," 

(* Scoping rules for KernelScript:
   - Inside program {} blocks: Kernel space (eBPF) - compiles to eBPF bytecode
   - Outside program {} blocks: User space - compiles to native executable  
   - Maps and global configs: Shared between both kernel and user space
   
   Userspace main function can have two forms:
   1. fn main() -> i32 { ... }                    // No command line arguments
   2. fn main(args: CustomStruct) -> i32 { ... }  // Custom argument struct, automatically parsed from command line
*)



(* Type declarations *)
type_declaration = "type" identifier "=" type_definition 
type_definition = struct_type | enum_type | type_alias 

struct_type = "struct" identifier "{" { struct_field } "}" 
struct_field = identifier ":" type_annotation "," 

enum_type = "enum" identifier "{" enum_variant { "," enum_variant } [ "," ] "}" 
enum_variant = identifier [ "=" integer_literal ] 

type_alias = type_annotation 

(* Function declarations *)
function_declaration = [ visibility ] "fn" identifier "(" parameter_list ")" 
                       [ "->" type_annotation ] "{" statement_list "}" 

visibility = "pub" | "priv" 
parameter_list = [ parameter { "," parameter } ] 
parameter = identifier ":" type_annotation 

(* Statements *)
statement_list = { statement } 
statement = expression_statement | assignment_statement | declaration_statement |
            if_statement | for_statement | while_statement | return_statement |
            break_statement | continue_statement | block_statement | delete_statement |
            try_statement | throw_statement | defer_statement 

expression_statement = expression 
assignment_statement = identifier assignment_operator expression 
assignment_operator = "=" | "+=" | "-=" | "*=" | "/=" | "%=" 

declaration_statement = "let" [ "mut" ] identifier [ ":" type_annotation ] "=" expression 

if_statement = "if" "(" expression ")" "{" statement_list "}" 
               { "else" "if" "(" expression ")" "{" statement_list "}" }
               [ "else" "{" statement_list "}" ] 

for_statement = "for" "(" identifier "in" expression ".." expression ")" "{" statement_list "}" |
                "for" "(" identifier "," identifier ")" "in" expression ".iter()" "{" statement_list "}" 

while_statement = "while" "(" expression ")" "{" statement_list "}" 

return_statement = "return" [ expression ] 
break_statement = "break" 
continue_statement = "continue" 
delete_statement = "delete" primary_expression "[" expression "]" 
block_statement = "{" statement_list "}" 

(* Error handling and resource management statements *)
try_statement = "try" "{" statement_list "}" { catch_clause } 
catch_clause = "catch" ( integer_literal | "_" ) "{" statement_list "}" 

throw_statement = "throw" expression 

defer_statement = "defer" expression 

(* Expressions *)
expression = logical_or_expression 

logical_or_expression = logical_and_expression { "||" logical_and_expression } 
logical_and_expression = equality_expression { "&&" equality_expression } 
equality_expression = relational_expression { equality_operator relational_expression } 
equality_operator = "==" | "!=" 

relational_expression = additive_expression { relational_operator additive_expression } 
relational_operator = "<" | "<=" | ">" | ">=" 

additive_expression = multiplicative_expression { additive_operator multiplicative_expression } 
additive_operator = "+" | "-" 

multiplicative_expression = unary_expression { multiplicative_operator unary_expression } 
multiplicative_operator = "*" | "/" | "%" 

unary_expression = [ unary_operator ] primary_expression 
unary_operator = "!" | "-" | "*" | "&" 

primary_expression = config_access | identifier | literal | function_call | field_access | 
                     array_access | parenthesized_expression | struct_literal 

config_access = identifier "." identifier 

function_call = identifier "(" argument_list ")" 
argument_list = [ expression { "," expression } ] 

field_access = primary_expression "." identifier 
array_access = primary_expression "[" expression "]" 
parenthesized_expression = "(" expression ")" 

struct_literal = identifier "{" struct_literal_field { "," struct_literal_field } [ "," ] "}" 
struct_literal_field = identifier ":" expression 

(* Type annotations *)
type_annotation = primitive_type | compound_type | identifier 

primitive_type = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | 
                 "bool" | "char" | "void" | "ProgramRef" | string_type 

compound_type = array_type | pointer_type | result_type 

string_type = "str" "<" integer_literal ">" 

array_type = "[" type_annotation "" integer_literal "]" 
pointer_type = "*" [ "const" | "mut" ] type_annotation 
result_type = "Result_" type_annotation "_" type_annotation 

(* Literals *)
literal = integer_literal | string_literal | char_literal | boolean_literal | 
          array_literal | null_literal 

integer_literal = decimal_literal | hex_literal | octal_literal | binary_literal 
decimal_literal = digit { digit } 
hex_literal = "0x" hex_digit { hex_digit } 
octal_literal = "0o" octal_digit { octal_digit } 
binary_literal = "0b" binary_digit { binary_digit } 

string_literal = '"' { string_char } '"' 
char_literal = "'" char "'" 
boolean_literal = "true" | "false" 
array_literal = "[" [ expression { "," expression } ] "]" 
null_literal = "null" 

(* Import declarations *)
import_declaration = "import" import_target 
import_target = identifier | string_literal 

(* Identifiers and basic tokens *)
identifier = letter { letter | digit | "_" } 
letter = "a"..."z" | "A"..."Z" 
digit = "0"..."9" 
hex_digit = digit | "a"..."f" | "A"..."F" 
octal_digit = "0"..."7" 
binary_digit = "0" | "1" 

(* String and character content *)
string_char = any_char_except_quote_and_backslash | escape_sequence 
char = any_char_except_quote_and_backslash | escape_sequence 
escape_sequence = "\" ( "n" | "t" | "r" | "\" | "'" | '"' | "0" | "x" hex_digit hex_digit ) 

(* Comments *)
comment = line_comment 
line_comment = "//" { any_char_except_newline } newline 

(* Whitespace *)
whitespace = " " | "\t" | "\n" | "\r" 
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
