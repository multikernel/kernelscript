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
type PacketBuffer = u8[1500]
type SmallBuffer = u8[256]

// Fixed-size arrays (no complex bounds)
u8[64]                 // 64-byte buffer
u32[16]                // 16 u32 values

// Simple map declarations
var counters : array<u32, u64>(256)
var flows : hash<IpAddress, PacketStats>(1024)

// No complex template metaprogramming - just practical, concrete types
```

### 1.3 Intuitive Scoping Model
KernelScript uses a simple and clear scoping model that eliminates ambiguity:

- **`@helper` functions**: Kernel-shared functions - accessible by all eBPF programs, compile to eBPF bytecode
- **Attributed functions** (e.g., `@xdp`, `@tc`, `@tracepoint`): eBPF program entry points - compile to eBPF bytecode
- **Regular functions**: User space - functions and data structures compile to native executable
- **Maps and global configs**: Shared resources accessible from both kernel and user space
- **No wrapper syntax**: Direct, flat structure without unnecessary nesting

```kernelscript
// Shared resources (accessible by both kernel and userspace)
config system { debug: bool = false }
var counters : array<u32, u64>(256)

// Kernel-shared functions (accessible by all eBPF programs)
@helper
fn update_counters(index: u32) {
    counters[index] += 1
}

@helper
fn should_log() -> bool {
    return system.debug
}

// eBPF program functions with attributes
@xdp
fn monitor(ctx: *xdp_md) -> xdp_action {
    update_counters(0)  // Call kernel-shared function
    
    if (should_log()) {  // Call another kernel-shared function
        print("Processing packet")
    }
    
    return XDP_PASS
}

@tc
fn analyzer(ctx: *__sk_buff) -> int {
    update_counters(1)  // Same kernel-shared function
    return 0  // TC_ACT_OK
}

// User space (regular functions)
struct Args { interface: str(16) }
fn main(args: Args) -> i32 {
    // Cannot call update_counters() here - it's kernel-only
    
    var monitor_handle = load(monitor)
    var analyzer_handle = load(analyzer)
    
    attach(monitor_handle, args.interface, 0)
    attach(analyzer_handle, args.interface, 1)
    
    return 0
}
```

### 1.4 Unified Import System

KernelScript supports importing both KernelScript modules and external language modules using a unified syntax. Import behavior is automatically determined by file extension:

```kernelscript
// Import KernelScript modules (.ks files)
import utils from "./common/utils.ks"           // Functions, types, maps, configs
import packet_helpers from "../net/helpers.ks"  // Shared across eBPF and userspace

// Import Python modules (.py files) - userspace only
import ml_analysis from "./ml/threat_analysis.py"
import data_processor from "./analytics/stats.py"

// Usage is identical regardless of source language
@xdp
fn intelligent_filter(ctx: *xdp_md) -> xdp_action {
    // Use KernelScript imported functions
    var protocol = utils.extract_protocol(ctx)
    
    // Use Python imported functions (FFI bridge in userspace)
    var packet_data = ctx->data
    var packet_len = ctx->data_end - ctx->data
    var threat_score = ml_analysis.compute_threat_score(packet_data, packet_len)
    
    if (threat_score > 0.8) {
        return XDP_DROP
    }
    return XDP_PASS
}

fn main() -> i32 {
    // Both KernelScript and Python functions work seamlessly in userspace
    var is_valid = utils.validate_config()
    var model_stats = ml_analysis.get_model_statistics()
    
    print("Config valid: %d, Model accuracy: %f", is_valid, model_stats.accuracy)
    
    var prog = load(intelligent_filter)
    attach(prog, "eth0", 0)
    return 0
}
```

## 2. Lexical Structure

### 2.1 Keywords
```
fn          var         const       config      local       for
pin         type        struct      enum        if          else
while       loop        break       continue    return      import
pub         priv        impl        true        false       null
try         catch       throw       defer       delete      match
```

**Note**: The `pin` keyword is used for both maps and global variables to enable filesystem persistence.

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

### 3.1 eBPF Program Function Declaration
```ebnf
ebpf_program = attribute_list "fn" identifier "(" parameter_list ")" "->" return_type "{" statement_list "}"

attribute_list = attribute { attribute }
attribute = "@" attribute_name [ "(" attribute_args ")" ]
attribute_name = "xdp" | "tc" | "probe" | "tracepoint" |
                 "struct_ops" | "kfunc" | "private" | "helper" | "test"
attribute_args = string_literal | identifier

parameter_list = parameter { "," parameter }
parameter = identifier ":" type_annotation
return_type = type_annotation
```

**Note:** eBPF programs are now simple attributed functions. All configuration is done through global named config blocks.

#### 3.1.1 Advanced Probe Functions with BTF Signature Extraction and Intelligent Probe Type Selection

KernelScript automatically extracts kernel function signatures from BTF (BPF Type Format) for probe functions and intelligently chooses between fprobe (function entrance) and kprobe (arbitrary address) based on the target specification.

```kernelscript
// Function entrance probe (uses fprobe)
@probe("sys_read")
fn function_entrance(fd: u32, buf: *u8, count: usize) -> i32 {
    // Direct access to function parameters with correct types
    // Compiler automatically extracts signature from BTF:
    // long sys_read(unsigned int fd, char __user *buf, size_t count)
    // Uses fprobe for better performance at function entrance
    
    print("Reading %d bytes from fd %d", count, fd)
    return 0
}

// Arbitrary address probe (uses kprobe)  
@probe("vfs_read+109")
fn arbitrary_address() -> i32 {
    // Probes specific instruction offset within vfs_read
    // Uses kprobe for arbitrary address probing
    // No direct parameters available at arbitrary addresses
    
    print("Probing vfs_read at offset +109")
    return 0
}
```

**Key Benefits:**
- **Intelligent Probe Selection**: Automatically chooses fprobe for function entrance (better performance) or kprobe for arbitrary addresses
- **Type Safety**: Function entrance probes have correct types extracted from kernel BTF information
- **No Magic Numbers**: Direct parameter access for function entrance probes
- **Self-Documenting**: Function signature matches the actual kernel function for entrance probes
- **Compile-Time Validation**: Invalid parameter access caught at compile time

**Probe Type Selection:**
- `@probe("function_name")` → Uses **fprobe** for function entrance with direct parameter access
- `@probe("function_name+offset")` → Uses **kprobe** for arbitrary address probing

**BTF Signature Mapping for Function Entrance:**
```kernelscript
// Kernel function: long sys_openat(int dfd, const char __user *filename, int flags, umode_t mode)
@probe("sys_openat")
fn trace_openat(dfd: i32, filename: *u8, flags: i32, mode: u16) -> i32 {
    // Direct parameter access with fprobe (no PT_REGS needed)
    print("Opening file with flags %d", flags)
    return 0
}

// For arbitrary address probing:
@probe("sys_write+50")  
fn trace_write_offset() -> i32 {
    // Uses kprobe for arbitrary offset - no direct parameters available
    print("Probing sys_write at offset +50")
    return 0
}

    }
    return 0
}
```

**Compiler Implementation:**
- Automatically queries BTF information for the target kernel function
- Generates parameter mappings to `PT_REGS_PARM*` macros
- Validates parameter count (maximum 6 on x86_64)
- Provides meaningful error messages for unknown functions

#### 3.1.2 Tracepoint Functions with BTF Event Structure Extraction

KernelScript automatically extracts tracepoint event structures from BTF (BPF Type Format) for tracepoint functions, providing type-safe access to tracepoint event data through the appropriate `trace_event_raw_*` structures.

```kernelscript
@tracepoint("sched/sched_switch")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    // Direct access to tracepoint event fields with correct types
    // Compiler automatically extracts structure from BTF:
    // struct trace_event_raw_sched_switch {
    //     struct trace_entry ent;
    //     char prev_comm[16];
    //     pid_t prev_pid;
    //     int prev_prio;
    //     long prev_state;
    //     char next_comm[16];
    //     pid_t next_pid;
    //     int next_prio;
    //     ...
    // }
    
    print("Task switch: %s[%d] -> %s[%d]", 
          ctx.prev_comm, ctx.prev_pid, 
          ctx.next_comm, ctx.next_pid)
    return 0
}

@tracepoint("syscalls/sys_enter_read")
fn sys_enter_read_handler(ctx: *trace_event_raw_sys_enter) -> i32 {
    // Syscall tracepoints use generic sys_enter structure
    // struct trace_event_raw_sys_enter {
    //     struct trace_entry ent;
    //     long id;
    //     unsigned long args[6];
    // }
    
    var fd = ctx.args[0]
    var count = ctx.args[2]
    print("sys_read: fd=%d, count=%d", fd, count)
    return 0
}

@tracepoint("net/netif_rx") 
fn netif_rx_handler(ctx: *trace_event_raw_netif_rx) -> i32 {
    // Network tracepoint with packet information
    print("Network packet received")
    return 0
}
```

**Key Benefits:**
- **Event Structure Access**: Direct access to tracepoint event fields with correct types
- **Category/Event Organization**: Clear separation using `category/event` format
- **BTF Integration**: Automatic extraction of `trace_event_raw_*` structures from kernel BTF
- **Compile-Time Safety**: Type checking for tracepoint context structures
- **Flexible Event Types**: Support for scheduler, syscall, network, and custom tracepoints

**BTF Structure Mapping:**
```kernelscript
// Scheduler tracepoints: trace_event_raw_<event_name>
@tracepoint("sched/sched_wakeup")
fn wakeup_handler(ctx: *trace_event_raw_sched_wakeup) -> i32 {
    // Access scheduler-specific fields
    print("Waking up PID %d", ctx.pid)
    return 0
}

// Syscall enter tracepoints: trace_event_raw_sys_enter (generic)
@tracepoint("syscalls/sys_enter_open") 
fn open_handler(ctx: *trace_event_raw_sys_enter) -> i32 {
    // Access syscall arguments through args array
    var filename_ptr = ctx.args[0]
    var flags = ctx.args[1]
    print("Opening file with flags %d", flags)
    return 0
}

// Syscall exit tracepoints: trace_event_raw_sys_exit (generic)
@tracepoint("syscalls/sys_exit_read")
fn read_exit_handler(ctx: *trace_event_raw_sys_exit) -> i32 {
    // Access return value
    print("sys_read returned %d", ctx.ret)
    return 0
}

// Custom subsystem tracepoints: trace_event_raw_<event_name>
@tracepoint("block/block_rq_complete")
fn block_complete_handler(ctx: *trace_event_raw_block_rq_complete) -> i32 {
    // Access block layer specific fields
    return 0
}
```

**Compiler Implementation:**
- Automatically determines BTF structure name based on category/event:
  - `syscalls/sys_enter_*` → `trace_event_raw_sys_enter` 
  - `syscalls/sys_exit_*` → `trace_event_raw_sys_exit`
  - `<category>/<event>` → `trace_event_raw_<event>`
- Extracts tracepoint structure definitions from kernel BTF information
- Generates appropriate `SEC("tracepoint")` section for eBPF programs
- Validates tracepoint context parameter types at compile time
- Provides meaningful error messages for unknown tracepoints

**Project Initialization:**
```bash
# Initialize project with specific tracepoint
kernelscript init tracepoint/sched/sched_switch my_scheduler_tracer

# Initialize project with syscall tracepoint  
kernelscript init tracepoint/syscalls/sys_enter_read my_syscall_tracer

# The init command automatically extracts BTF structures and generates
# appropriate KernelScript templates with correct context types
```

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
    current_threat_level: u32 = 0,
    enable_strict_mode: bool = false,
}

@xdp
fn network_monitor(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    
    // Use named configuration values
    if (packet.size > network.max_packet_size) {
        if (network.enable_logging) {
            print("Packet too large: %d", packet.size)
        }
        return XDP_DROP
    }
    
    // Check blocked ports from network config
    if (packet.is_tcp()) {
        var tcp = packet.tcp_header()
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
```

### 3.3 Global Variables

KernelScript supports global variable declarations at the top level that are accessible from both kernel and userspace contexts. Global variables provide a simple way to declare shared state without the complexity of full map declarations.

#### 3.3.1 Global Variable Declaration Syntax

Global variables support three forms of declaration, with optional `pin` keyword for persistence:

```kernelscript
// Form 1: Full declaration with type and initial value
var global_counter: u32 = 0
var global_string: str(256) = "default_value"
var global_flag: bool = true

// Form 2: Type-only declaration (uninitialized)
var uninitialized_counter: u32
var uninitialized_buffer: str(128)

// Form 3: Value-only declaration (type inferred)
var inferred_int = 42           // Type: u32 (default for integer literals)
var inferred_string = "hello"   // Type: str(6) (inferred from string length)
var inferred_bool = false       // Type: bool
var inferred_char = 'a'         // Type: char

// Pinned global variables - persisted to filesystem
pin var persistent_counter: u64 = 0
pin var persistent_config: str(64) = "default_config"
pin var persistent_flag: bool = false
pin var persistent_buffer: [u8; 256] = [0; 256]
```

#### 3.3.2 Type Inference Rules

When no explicit type is provided, KernelScript infers the type based on the initial value:

| Literal Type | Inferred Type | Example |
|-------------|---------------|---------|
| `IntLit` | `u32` | `var x = 42` → `u32` |
| `StringLit` | `str(N)` | `var s = "hello"` → `str(6)` |
| `BoolLit` | `bool` | `var b = true` → `bool` |
| `CharLit` | `char` | `var c = 'a'` → `char` |
| `NullLit` | `*u8` | `var p = null` → `*u8` |
| `ArrayLit` | `[u32; 1]` | `var a = [1, 2, 3]` → `[u32; 3]` |

#### 3.3.3 Global Variable Usage

Global variables are accessible from both kernel and userspace contexts:

```kernelscript
// Global variables - accessible from both contexts
var packet_count: u64 = 0
var enable_logging: bool = true
var max_packet_size: u32 = 1500

// eBPF program using global variables
@xdp
fn packet_monitor(ctx: *xdp_md) -> xdp_action {
    packet_count += 1  // Access global variable
    
    var packet = ctx.packet()
    if (packet.size > max_packet_size) {
        if (enable_logging) {
            print("Packet too large: %d", packet.size)
        }
        return XDP_DROP
    }
    
    return XDP_PASS
}

// Userspace program using global variables
struct Args {
    interface: str(16),
    debug: bool,
}

fn main(args: Args) -> i32 {
    // Configure global variables based on command line
    enable_logging = args.debug
    
    var prog_handle = load(packet_monitor)
    attach(prog_handle, args.interface, 0)
    
    // Monitor global state
    while (true) {
        print("Total packets processed: ", packet_count)
        sleep(1000)
    }
    
    return 0
}
```

#### 3.3.4 Global Variable Scoping and Pinning

KernelScript provides explicit control over global variable visibility between kernel and userspace, with optional persistence:

```kernelscript
// Shared variables (default) - accessible from both kernel and userspace
var packet_count: u64 = 0
var enable_logging: bool = true
var shared_buffer: str(256) = "default"

// Pinned shared variables - persisted to filesystem and shared
pin var persistent_packet_count: u64 = 0
pin var persistent_config: str(128) = "default_config"
pin var persistent_state: bool = false

// Local variables - kernel-only, not exposed to userspace
local var crypto_nonce: u64 = 0x123456789ABCDEF0
local var internal_debug_flags: u32 = 0
local var temp_calculation_buffer: [u8; 1024] = [0; 1024]

// ❌ COMPILATION ERROR: Cannot pin local variables
// pin local var invalid_pinned_local: u32 = 0

// eBPF program using shared, pinned, and local variables
@xdp
fn secure_packet_filter(ctx: *xdp_md) -> xdp_action {
    packet_count += 1                    // Shared: accessible via skeleton
    persistent_packet_count += 1         // Pinned: persisted and accessible
    crypto_nonce += 1                    // Local: kernel-only, not in skeleton
    
    if (enable_logging) {                // Shared: configurable from userspace
        internal_debug_flags |= 0x1      // Local: internal state only
        print("Processing packet")
    }
    
    // Use pinned configuration
    if (persistent_state) {
        print("Persistent mode enabled")
    }
    
    return XDP_PASS
}

// Userspace program accessing shared and pinned variables
fn main() -> i32 {
    // Can access shared variables via skeleton
    enable_logging = true
    
    // Can access pinned variables (persisted across program restarts)
    persistent_state = true
    
    while (true) {
        print("Packets processed: ", packet_count)             // Via skeleton
        print("Total packets: ", persistent_packet_count)      // Via pinned map
        print("Config: ", persistent_config)                   // Via pinned map
        // Cannot access crypto_nonce or internal_debug_flags
        sleep(1000)
    }
    
    return 0
}
```

**Scoping Rules:**
- **Shared variables** (`var`): Accessible from both kernel and userspace via libbpf skeleton
- **Pinned shared variables** (`pin var`): Accessible from both kernel and userspace, persisted to filesystem
- **Local variables** (`local var`): Kernel-only, hidden from userspace, not included in skeleton generation

**Pinning Rules:**
- Only shared variables can be pinned (not `local var`)
- Pinned variables are persisted to `/sys/fs/bpf/<PROJECT_NAME>/globals/pinned_globals`
- Compilation error if attempting to pin local variables: `pin local var` is invalid

**Security Benefits:**
- Sensitive data like cryptographic nonces remain kernel-only
- Internal debugging state isn't exposed to userspace
- Clear separation between public API and internal implementation
- Pinned variables provide persistent state across program restarts

#### 3.3.5 Pinned Global Variables Implementation

Since eBPF doesn't support pinning global variables directly, the compiler implements pinned global variables using a transparent map-based approach:

**Compiler Implementation Strategy:**
1. **Collect all pinned global variables** in order of declaration
2. **Generate a struct** containing all pinned variables with their original types
3. **Create a single-entry map** to store and pin this struct
4. **Generate access wrappers** to maintain the original variable access syntax

```kernelscript
// User writes this:
pin var packet_count: u64 = 0
pin var config_string: str(64) = "default"
pin var enable_feature: bool = false

// Compiler generates (conceptually):
struct PinnedGlobals {
    packet_count: u64,
    config_string: str(64),
    enable_feature: bool,
}

// Single-entry pinned map
@flags(BPF_F_NO_PREALLOC)
pin var __pinned_globals : array<u32, PinnedGlobals>(1)

// Access wrappers (transparent to user):
// packet_count access becomes: __pinned_globals[0].packet_count
// config_string access becomes: __pinned_globals[0].config_string
// enable_feature access becomes: __pinned_globals[0].enable_feature
```

**Filesystem Location:**
- Pinned globals map is stored at: `/sys/fs/bpf/<PROJECT_NAME>/globals/pinned_globals`
- Multiple programs can share the same pinned globals if they have the same project name

**Initialization Behavior:**
- On first program load, the map is created and initialized with default values
- On subsequent loads, existing values are preserved from the filesystem
- Default values are only used when no pinned map exists

**Example Usage:**
```kernelscript
// Declaration - user syntax remains clean
pin var session_counter: u64 = 0
pin var last_interface: str(16) = "eth0"
pin var debug_mode: bool = false

@xdp
fn persistent_monitor(ctx: *xdp_md) -> xdp_action {
    // Compiler transparently converts to map access
    session_counter += 1  // Becomes: __pinned_globals[0].session_counter += 1
    
    if (debug_mode) {     // Becomes: if (__pinned_globals[0].debug_mode) {
        print("Session: ", session_counter, " Interface: ", last_interface)
    }
    
    return XDP_PASS
}

// Userspace access - same transparent conversion
fn main() -> i32 {
    // Values persist across program restarts
    print("Previous session count: ", session_counter)
    
    // Configure for this session
    last_interface = "eth1"
    debug_mode = true
    
    var prog_handle = load(persistent_monitor)
    attach(prog_handle, last_interface, 0)
    
    return 0
}
```

#### 3.3.6 Global Variables vs Maps and Configs

| Feature | Global Variables | Pinned Global Variables | Maps | Configs |
|---------|------------------|-------------------------|------|---------|
| **Syntax** | `var name: type = value` | `pin var name: type = value` | `[pin] [@flags(...)] var name : Type<K,V>(size)` | `config name { field: type = value }` |
| **Use Case** | Simple shared state | Persistent simple state | Complex data structures | Structured configuration |
| **Access** | Direct variable access | Direct variable access | Key-value lookup | Dotted field access |
| **Performance** | Fastest | Fast (single map lookup) | Medium | Fastest |
| **Flexibility** | Limited | Limited | High | Medium |
| **Scoping** | Shared or local | Always shared | Always shared | Always shared |
| **Persistence** | No | Yes (filesystem) | Optional (if pinned) | No |

### 3.4 Kernel-Userspace Scoping Model

KernelScript uses a simple and intuitive scoping model:
- **Attributed functions** (e.g., `@xdp`, `@tc`, `@tracepoint`): Kernel space (eBPF) - compiles to eBPF bytecode
- **`@kfunc` functions**: Kernel modules (full privileges) - exposed to eBPF programs via BTF
- **`@private` functions**: Kernel modules (full privileges) - internal helpers for kfuncs
- **Regular functions**: User space - compiles to native executable
- **Maps, global configs, and global variables**: Shared between both kernel and user space

```kernelscript
// Shared configuration and maps (accessible by both kernel and userspace)
config monitoring {
    enable_stats: bool = true,
    sample_rate: u32 = 100,
    packets_processed: u64 = 0,
}

var global_stats : hash<u32, PacketStats>(1024)

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

// Kernel-shared functions (accessible by all eBPF programs)
@helper
fn update_stats(ctx: *xdp_md) {
    var key = ctx.hash() % 1024
    global_stats[key].packets += 1
}

// eBPF program functions with attributes
@xdp
fn packet_analyzer(ctx: *xdp_md) -> xdp_action {
    if (monitoring.enable_stats) {
        // Process packet and update statistics
        monitoring.packets_processed += 1
        update_stats(ctx)
    }
    return XDP_PASS
}

@tc
fn flow_tracker(ctx: *__sk_buff) -> int {
    // Track flow information using shared config
    if (monitoring.enable_stats && (ctx.hash() % monitoring.sample_rate == 0)) {
        // Sample this flow
        var key = ctx.hash() % 1024
        global_stats[key].bytes += ctx.packet_size()
    }
    return 0  // TC_ACT_OK
}

// Userspace coordination (regular functions)
fn main(args: Args) -> i32 {
    // Command line arguments automatically parsed
    // Usage: program --interface-id=1 --enable-verbose=1
    
    var interface_index = args.interface_id
    
    // Load and coordinate multiple programs
    var analyzer_handle = load(packet_analyzer)
    var tracker_handle = load(flow_tracker)
    
    attach(analyzer_handle, interface_index, 0)
    attach(tracker_handle, interface_index, 1)
    
    if (args.enable_verbose == 1) {
        print("Multi-program system started on interface: ", interface_index)
    }
    
    while (true) {
        var stats = get_combined_stats()
        print("Total packets: ", stats.packets)
        print("Total bytes: ", stats.bytes)
        sleep(1000)
    }
    
    return 0
}

// Userspace helper functions
fn get_combined_stats() -> PacketStats {
    var total = PacketStats { packets: 0, bytes: 0, drops: 0 }
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

### 3.5 Explicit Program Lifecycle Management

KernelScript supports explicit control over eBPF program loading and attachment through function references and built-in lifecycle functions. This enables advanced use cases like parameter configuration between loading and attachment phases.

#### 3.5.1 Program Function References and Safety

eBPF program functions are first-class values that can be referenced by name and passed to lifecycle functions. The interface enforces safety by requiring programs to be loaded before attachment:

```kernelscript
@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}

@tc
fn flow_monitor(ctx: *__sk_buff) -> int {
    return 0  // TC_ACT_OK
}

// Userspace program coordination
fn main() -> i32 {
    // Program functions can be referenced by name
    var xdp_prog = packet_filter  // Type: FunctionRef
    var tc_prog = flow_monitor    // Type: FunctionRef
    
    // Explicit loading and attachment
    var prog_handle = load(xdp_prog)
    var result = attach(prog_handle, "eth0", 0)
    
    return 0
}
```

#### 3.5.2 Lifecycle Functions

**`load(function_ref: FunctionRef) -> ProgramHandle`**
- Loads the specified eBPF program function into the kernel
- Returns a program handle that abstracts the underlying implementation
- Must be called before attachment
- Enables configuration of program parameters before attachment

**`attach(handle: ProgramHandle, target: string, flags: u32) -> u32`**
- Attaches the loaded program to the specified target using its handle
- First parameter must be a ProgramHandle returned from load()
- Target and flags interpretation depends on program type:
  - **XDP**: target = interface name ("eth0"), flags = XDP attachment flags
  - **TC**: target = interface name ("eth0"), flags = direction (ingress/egress)
  - **Kprobe**: target = function name ("sys_read"), flags = unused (0)
  - **Cgroup**: target = cgroup path ("/sys/fs/cgroup/test"), flags = unused (0)
- Returns 0 on success, negative error code on failure

**`detach(handle: ProgramHandle) -> void`**
- Detaches the program from its current attachment point using its handle
- Automatically determines the correct detachment method based on program type:
  - **XDP**: Uses `bpf_xdp_detach()` with stored interface and flags
  - **TC**: Uses `bpf_tc_detach()` with stored interface and direction
  - **Kprobe/Tracepoint**: Destroys the stored `bpf_link` handle
- No return value (void) - logs errors to stderr if detachment fails
- Safe to call multiple times on the same handle (no-op if already detached)
- Automatically cleans up internal attachment tracking

**Safety Benefits:**
- **Compile-time enforcement**: Cannot call `attach()` without first calling `load()` - the type system prevents this
- **Implementation abstraction**: Users work with `ProgramHandle` instead of raw file descriptors
- **Resource safety**: Program handles abstract away the underlying resource management
- **Automatic cleanup**: `detach()` handles all program types uniformly and cleans up tracking data
- **Idempotent operations**: Safe to call `detach()` multiple times without side effects

#### 3.5.3 Lifecycle Best Practices

**Proper Cleanup Patterns:**
```kernelscript
fn main() -> i32 {
    var prog1 = load(filter)
    var prog2 = load(monitor)
    
    // Attach programs
    var result1 = attach(prog1, "eth0", 0)
    var result2 = attach(prog2, "eth0", 1)
    
    // Error handling with partial cleanup
    if (result1 != 0 || result2 != 0) {
        // Clean up any successful attachments before returning
        if (result1 == 0) detach(prog1)
        if (result2 == 0) detach(prog2)
        return 1
    }
    
    // Normal operation...
    print("Programs running...")
    
    // Proper shutdown: detach in reverse order
    detach(prog2)  // Last attached, first detached
    detach(prog1)
    
    return 0
}
```

**Multi-Program Detachment Order:**
- Always detach programs in **reverse order** of attachment
- This ensures dependencies are cleaned up properly
- Example: if `filter` depends on `monitor`, detach `monitor` first

**Error Recovery:**
- Use conditional detachment for partial failure scenarios
- Safe to call `detach()` multiple times on the same handle
- Always clean up successful attachments before returning error codes

#### 3.5.4 Advanced Usage Patterns

**Configuration Between Load and Attach:**
```kernelscript
config network {
    enable_filtering: bool = false,
    max_packet_size: u32 = 1500,
}

@xdp
fn adaptive_filter(ctx: *xdp_md) -> xdp_action {
    if (network.enable_filtering && ctx.packet_size() > network.max_packet_size) {
        return XDP_DROP
    }
    return XDP_PASS
}

// Userspace coordination and CLI handling
struct Args {
    interface: str(16),
    strict_mode: bool,
}

fn main(args: Args) -> i32 {
    // Load program first
    var prog_handle = load(adaptive_filter)
    
    // Configure parameters based on command line
    network.enable_filtering = args.strict_mode
    if (args.strict_mode) {
        network.max_packet_size = 1000  // Stricter limit
    }
    
    // Now attach with configured parameters
    var result = attach(prog_handle, args.interface, 0)
    
    if (result == 0) {
        print("Filter attached successfully")
        
        // Simulate running the program (in real usage, this might be an event loop)
        print("Filter is processing packets...")
        
        // Proper cleanup when shutting down
        detach(prog_handle)
        print("Filter detached successfully")
    } else {
        print("Failed to attach filter")
        return 1
    }
    
    return 0
}
```

**Multi-Program Coordination:**
```kernelscript
@xdp
fn ingress_monitor(ctx: *xdp_md) -> xdp_action { return XDP_PASS }

@tc
fn egress_monitor(ctx: *__sk_buff) -> int { return 0 }  // TC_ACT_OK

// Struct_ops example using impl block approach
struct tcp_congestion_ops {
    init: fn(sk: *TcpSock) -> void,
    cong_avoid: fn(sk: *TcpSock, ack: u32, acked: u32) -> void,
    cong_control: fn(sk: *TcpSock, ack: u32, flag: u32, bytes_acked: u32) -> void,
    set_state: fn(sk: *TcpSock, new_state: u32) -> void,
    name: string,
}

@struct_ops("tcp_congestion_ops")
impl my_bbr {
    fn init(sk: *TcpSock) -> void {
        // Initialize BBR state
    }
    
    fn cong_avoid(sk: *TcpSock, ack: u32, acked: u32) -> void {
        // BBR congestion avoidance
    }
    
    fn cong_control(sk: *TcpSock, ack: u32, flag: u32, bytes_acked: u32) -> void {
        // BBR control logic
    }
    
    fn set_state(sk: *TcpSock, new_state: u32) -> void {
        // State transitions
    }
}
```

### 3.6 Custom Kernel Functions (kfunc)

KernelScript allows users to define custom kernel functions using the `@kfunc` attribute. These functions execute in kernel space with full privileges and can be called from eBPF programs. The compiler automatically generates a kernel module containing the kfunc implementation and loads it transparently when needed.

#### 3.6.1 kfunc Declaration and Usage

kfunc functions are declared using the `@kfunc` attribute and are registered with the same name as the function:

```kernelscript
// Custom kernel function - registered as "advanced_packet_analysis"
@kfunc
fn advanced_packet_analysis(data: *u8, len: u32) -> u32 {
    // Full kernel privileges - can access any kernel API
    var skb = alloc_skb(len, GFP_KERNEL)
    if (skb == null) {
        return 0
    }
    
    // Complex analysis using kernel subsystems
    var result = deep_packet_inspection(data, len)
    kfree_skb(skb)
    
    return result
}

// Rate limiting kernel function
@kfunc
fn rate_limit_flow(flow_id: u64, current_time: u64) -> bool {
    // Access kernel data structures directly
    var bucket = get_rate_limit_bucket(flow_id)
    if (bucket == null) {
        bucket = create_rate_limit_bucket(flow_id)
    }
    
    // Token bucket algorithm with kernel timers
    update_token_bucket(bucket, current_time)
    return consume_token(bucket)
}

// Crypto verification kernel function
@kfunc
fn verify_packet_signature(packet: *u8, len: u32, signature: *u8) -> i32 {
    // Use kernel crypto subsystem
    var tfm = crypto_alloc_shash("sha256", 0, 0)
    if (IS_ERR(tfm)) {
        return -ENOMEM
    }
    
    var result = crypto_verify_signature(tfm, packet, len, signature)
    crypto_free_shash(tfm)
    
    return result
}

// eBPF program calling kfuncs
@xdp
fn secure_packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    if (packet == null) {
        return XDP_PASS
    }
    
    // Call custom kernel function using function name
    var analysis_result = advanced_packet_analysis(packet.data, packet.len)
    if (analysis_result == 0) {
        return XDP_DROP
    }
    
    // Call rate limiter kfunc using function name
    var flow_id = compute_flow_id(packet)
    if (!rate_limit_flow(flow_id, bpf_ktime_get_ns())) {
        return XDP_DROP
    }
    
    // Verify packet signature for critical flows
    if (packet.is_critical_flow()) {
        var signature = extract_signature(packet)
        if (verify_packet_signature(packet.data, packet.len, signature) != 0) {
            return XDP_DROP
        }
    }
    
    return XDP_PASS
}
```

#### 3.6.2 Automatic Kernel Module Generation

The compiler automatically generates a kernel module for each kfunc:

**Generated Module Components:**
- **Function implementation**: Full kernel privileges, access to all kernel APIs
- **Registration code**: Registers kfunc with eBPF subsystem using BTF
- **Module metadata**: Proper module init/exit, dependencies, licensing
- **BTF information**: Type signatures for eBPF verifier integration

**Transparent Loading Process:**
1. User calls `load(secure_packet_filter)` in userspace
2. Compiler detects kfunc dependencies in the eBPF program
3. Kernel module containing kfuncs is loaded automatically
4. kfuncs are registered and made available to eBPF programs
5. eBPF program is loaded and can call the kfuncs
6. Module remains loaded as long as eBPF programs reference it

#### 3.6.3 kfunc Registration

```kernelscript
// kfunc registered as "packet_decrypt"
@kfunc
fn packet_decrypt(data: *u8, len: u32, key: *u8) -> i32 {
    // Registered as "packet_decrypt" in eBPF subsystem
    return kernel_crypto_decrypt(data, len, key)
}

// kfunc registered as "optimized_checksum_calculation"
@kfunc
fn optimized_checksum_calculation(data: *u8, len: u32) -> u32 {
    // Registered as "optimized_checksum_calculation" in eBPF subsystem
    // Can use hardware acceleration, SIMD, etc.
    return hardware_accelerated_checksum(data, len)
}

// eBPF program usage
@xdp
fn data_processor(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    
    // Call using function names
    var checksum = optimized_checksum_calculation(packet.data, packet.len)
    var decrypt_result = packet_decrypt(packet.data, packet.len, get_key())
    
    return XDP_PASS
}
```

#### 3.6.4 kfunc vs Other Function Types

| Aspect | `@kfunc` | `@helper` | `@xdp/@tc/etc` | Regular `fn` |
|--------|----------|-------------|----------------|--------------|
| **Execution Context** | Kernel space (full privileges) | eBPF sandbox | eBPF sandbox | Userspace |
| **Compilation Target** | Kernel module | eBPF bytecode | eBPF bytecode | Native executable |
| **Callable From** | eBPF programs only | eBPF programs | N/A (entry points) | Userspace only |
| **Kernel API Access** | Full access | eBPF helpers only | eBPF helpers only | System calls only |
| **Resource Limits** | None | eBPF verifier limits | eBPF verifier limits | Process limits |
| **Loading** | Automatic module load | Part of eBPF program | Part of eBPF program | Part of executable |

#### 3.6.5 Advanced kfunc Examples

```kernelscript
// Network policy enforcement with kernel integration
@kfunc
fn enforce_network_policy(src_ip: u32, dst_ip: u32, port: u16, protocol: u8) -> i32 {
    // Access kernel network namespaces
    var ns = get_current_net_ns()
    var policy = lookup_network_policy(ns, src_ip, dst_ip, port)
    
    if (policy == null) {
        return -ENOENT  // No policy found
    }
    
    // Check with netfilter subsystem
    return netfilter_check_policy(policy, protocol)
}

// File system integration
@kfunc
fn check_file_access(path: *char, mode: u32) -> i32 {
    // Interact with VFS and security modules
    var dentry = kern_path_lookup(path)
    if (IS_ERR(dentry)) {
        return PTR_ERR(dentry)
    }
    
    var result = security_inode_permission(dentry.d_inode, mode)
    path_put(&dentry)
    
    return result
}

// Memory management integration
@kfunc
fn allocate_secure_buffer(size: u32) -> *u8 {
    // Use kernel memory allocators with security considerations
    var buffer = kzalloc(size, GFP_KERNEL | __GFP_ZERO)
    if (buffer != null) {
        // Mark as secure/encrypted region
        mark_buffer_secure(buffer, size)
    }
    
    return buffer
}

// Usage in complex eBPF program
@lsm("socket_connect")
fn advanced_security_monitor(ctx: LsmContext) -> i32 {
    var sock = ctx.socket()
    var addr = ctx.address()
    
    // Use kfunc for complex policy checking
    var policy_result = enforce_network_policy(
        sock.src_ip, addr.dst_ip, addr.port, sock.protocol
    )
    
    if (policy_result != 0) {
        return -EPERM
    }
    
    // Use kfunc for file access checks if connection involves file transfer
    if (is_file_transfer_protocol(addr.port)) {
        var file_check = check_file_access("/tmp/allowed_transfers", R_OK)
        if (file_check != 0) {
            return -EACCES
        }
    }
    
    return 0
}
```

### 3.7 Helper Functions (@helper)

KernelScript supports kernel-shared helper functions using the `@helper` attribute. These functions compile to eBPF bytecode and are shared across all eBPF programs within the same compilation unit, providing a way to reuse common logic without duplicating code.

#### 3.7.1 @helper Declaration and Usage

Helper functions are declared using the `@helper` attribute and can be called from any eBPF program:

```kernelscript
// Shared helper functions - accessible by all eBPF programs
@helper
fn validate_packet_size(size: u32) -> bool {
    return size >= 64 && size <= 1500
}

@helper
fn calculate_hash(src_ip: u32, dst_ip: u32) -> u32 {
    return src_ip ^ dst_ip ^ (src_ip >> 16) ^ (dst_ip >> 16)
}

@helper
fn update_packet_stats(proto: u8, size: u32) {
    var key = proto as u32
    if (packet_stats.contains_key(key)) {
        packet_stats[key].count += 1
        packet_stats[key].total_bytes += size
    }
}

// eBPF programs can call helper functions
@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    
    // Call shared helper
    if (!validate_packet_size(packet.len)) {
        return XDP_DROP
    }
    
    // Call another helper
    update_packet_stats(packet.protocol, packet.len)
    
    return XDP_PASS
}

@tc
fn traffic_shaper(ctx: *__sk_buff) -> int {
    var packet = ctx.packet()
    
    // Reuse the same helpers
    if (!validate_packet_size(packet.len)) {
        return 2  // TC_ACT_SHOT
    }
    
    var hash = calculate_hash(packet.src_ip, packet.dst_ip)
    update_packet_stats(packet.protocol, packet.len)
    
    return 0  // TC_ACT_OK
}
```

#### 3.7.2 @helper vs Other Function Types

| Aspect | `@helper` | `@kfunc` | `@xdp/@tc/etc` | Regular `fn` |
|--------|-----------|----------|----------------|--------------|
| **Execution Context** | eBPF sandbox | Kernel space (full privileges) | eBPF sandbox | Userspace |
| **Callable From** | eBPF programs | eBPF programs | Not callable | Userspace functions |
| **Compilation Target** | eBPF bytecode | Kernel module | eBPF bytecode | Native executable |
| **Shared Across Programs** | Yes | Yes | No | No |
| **Memory Access** | eBPF-restricted | Unrestricted kernel | eBPF-restricted | Userspace-restricted |

#### 3.7.3 Code Organization Benefits

Using `@helper` functions provides several benefits:

**1. Code Reuse**
```kernelscript
@helper
fn extract_tcp_info(ctx: *xdp_md) -> option TcpInfo {
    var packet = ctx.packet()
    if (packet.protocol != IPPROTO_TCP) {
        return null
    }
    
    return TcpInfo {
        src_port: packet.tcp_header().src_port,
        dst_port: packet.tcp_header().dst_port,
        flags: packet.tcp_header().flags
    }
}

@xdp
fn ddos_protection(ctx: *xdp_md) -> xdp_action {
    var tcp_info = extract_tcp_info(ctx)
    if (tcp_info != null && tcp_info.flags & TCP_SYN) {
        // SYN flood protection logic
        return rate_limit_syn(tcp_info.dst_port) ? XDP_PASS : XDP_DROP
    }
    return XDP_PASS
}

@tc
fn connection_tracker(ctx: *__sk_buff) -> int {
    var tcp_info = extract_tcp_info(ctx)  // Reuse same helper
    if (tcp_info != null) {
        track_connection(tcp_info.src_port, tcp_info.dst_port)
    }
    return 0  // TC_ACT_OK
}
```

### 3.8 Private Kernel Module Functions (@private)

KernelScript supports private helper functions within kernel modules using the `@private` attribute. These functions execute in kernel space but are internal to the module - they cannot be called by eBPF programs and are not registered via BTF. They serve as utility functions for `@kfunc` implementations.

#### 3.8.1 @private Declaration and Usage

Private functions are declared using the `@private` attribute and can only be called by other functions within the same kernel module:

```kernelscript
// Private helper functions - internal to kernel module
@private
fn validate_ip_address(addr: u32) -> bool {
    // IP validation logic with full kernel privileges
    return addr != 0 && addr != 0xFFFFFFFF && !is_reserved_ip(addr)
}

@private
fn calculate_flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> u64 {
    // Complex hashing algorithm using kernel crypto
    var hash_state = crypto_alloc_shash("xxhash64", 0, 0)
    if (IS_ERR(hash_state)) {
        return simple_hash(src_ip ^ dst_ip ^ (src_port << 16) ^ dst_port)
    }
    
    var result = crypto_hash_flow(hash_state, src_ip, dst_ip, src_port, dst_port)
    crypto_free_shash(hash_state)
    return result
}

@private  
fn check_rate_limit_bucket(flow_id: u64, current_time: u64) -> bool {
    // Token bucket implementation with kernel timers
    var bucket = find_bucket(flow_id)
    if (bucket == null) {
        bucket = create_bucket(flow_id, current_time)
    }
    
    update_bucket_tokens(bucket, current_time)
    return bucket.tokens > 0
}

// Public kfunc API that uses private helpers
@kfunc
fn advanced_flow_filter(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> i32 {
    // Validate inputs using private helper
    if (!validate_ip_address(src_ip) || !validate_ip_address(dst_ip)) {
        return -EINVAL
    }
    
    // Calculate flow hash using private helper
    var flow_id = calculate_flow_hash(src_ip, dst_ip, src_port, dst_port)
    
    // Check rate limiting using private helper
    if (!check_rate_limit_bucket(flow_id, bpf_ktime_get_ns())) {
        return -EAGAIN  // Rate limited
    }
    
    return 0  // Allow flow
}

// Another kfunc using the same private helpers
@kfunc
fn flow_statistics(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> u64 {
    if (!validate_ip_address(src_ip) || !validate_ip_address(dst_ip)) {
        return 0
    }
    
    // Reuse the same flow hash calculation
    return calculate_flow_hash(src_ip, dst_ip, src_port, dst_port)
}

// eBPF program that can call kfuncs but NOT private functions
@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    if (packet == null) {
        return XDP_PASS
    }
    
    // Can call public kfunc
    var filter_result = advanced_flow_filter(
        packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port
    )
    
    if (filter_result != 0) {
        return XDP_DROP
    }
    
    // ERROR: Cannot call private functions directly
    // var is_valid = validate_ip_address(packet.src_ip)  // Compilation error!
    
    return XDP_PASS
}
```

#### 3.8.2 Function Visibility and Call Hierarchy

```kernelscript
// Example showing function call hierarchy
@private
fn low_level_crypto(data: *u8, len: u32) -> u32 {
    // Low-level cryptographic operations
    return kernel_crypto_hash(data, len)
}

@private
fn mid_level_validation(packet: *u8, len: u32) -> bool {
    // Can call other private functions in same module
    var hash = low_level_crypto(packet, len)
    return hash != 0 && validate_packet_structure(packet, len)
}

@kfunc
fn high_level_filter(packet: *u8, len: u32) -> i32 {
    // Public API that orchestrates private functions
    if (!mid_level_validation(packet, len)) {
        return -EINVAL
    }
    
    var hash = low_level_crypto(packet, len)
    return store_packet_hash(hash)
}

// eBPF usage
@tc
fn traffic_analyzer(ctx: *__sk_buff) -> int {
    var packet = ctx.packet()
    
    // Can only call the public kfunc
    var result = high_level_filter(packet.data, packet.len)
    
    return result == 0 ? TC_ACT_OK : TC_ACT_SHOT
}
```

#### 3.8.3 @private vs @kfunc Comparison

| Aspect | `@private` | `@kfunc` |
|--------|-----------|----------|
| **Visibility** | Internal to kernel module | Exposed to eBPF programs |
| **BTF Registration** | Not registered | Registered with BTF |
| **Callable From** | Other functions in same module | eBPF programs |
| **Compilation Target** | Kernel module only | Kernel module + BTF |
| **Use Case** | Internal implementation details | Public API functions |
| **Performance** | Direct function call | BTF-mediated call |

#### 3.8.4 Code Organization Benefits

Using `@private` functions provides several architectural benefits:

**1. Modularity**
```kernelscript
// Clean separation of concerns
@private fn parse_headers(packet: *u8) -> PacketHeaders { }
@private fn validate_headers(headers: PacketHeaders) -> bool { }
@private fn apply_policy(headers: PacketHeaders) -> PolicyResult { }

@kfunc
fn packet_policy_check(packet: *u8, len: u32) -> i32 {
    var headers = parse_headers(packet)
    if (!validate_headers(headers)) {
        return -EINVAL
    }
    
    var policy = apply_policy(headers)
    return policy.action
}
```

**2. Security**
```kernelscript
// Hide sensitive implementation details
@private fn decrypt_with_master_key(data: *u8, len: u32) -> bool {
    // Sensitive key operations not exposed to eBPF
    return crypto_decrypt_master(data, len, get_master_key())
}

@kfunc  
fn secure_packet_process(encrypted_packet: *u8, len: u32) -> i32 {
    // Only expose safe, validated interface
    if (!decrypt_with_master_key(encrypted_packet, len)) {
        return -EACCES
    }
    return 0
}
```

**3. Performance**
```kernelscript
// Optimize hot paths with private helpers
@private fn fast_checksum(data: *u8, len: u32) -> u32 {
    // Optimized assembly or SIMD operations
    return simd_checksum(data, len)
}

@private fn cache_lookup(key: u64) -> *CacheEntry {
    // Efficient kernel cache operations
    return rcu_dereference(cache_table[hash(key)])
}

@kfunc
fn optimized_packet_check(packet: *u8, len: u32) -> bool {
    var checksum = fast_checksum(packet, len)
    var cache_entry = cache_lookup(checksum)
    
    return cache_entry != null && cache_entry.is_valid
}
```

### 3.9 Struct_ops and Kernel Module Function Pointers

KernelScript supports eBPF struct_ops through clean impl block syntax that allows implementing kernel interfaces using eBPF programs.

#### 3.9.1 eBPF Struct_ops with Impl Blocks

eBPF struct_ops allow implementing kernel interfaces using eBPF programs. KernelScript uses impl blocks for a clean, intuitive syntax:

```kernelscript
// Define the struct_ops type (extracted from BTF)
struct tcp_congestion_ops {
    ssthresh: fn(arg: *u8) -> u32,
    cong_avoid: fn(arg: *u8, arg: u32, arg: u32) -> void,
    set_state: fn(arg: *u8, arg: u8) -> void,
    cwnd_event: fn(arg: *u8, arg: u32) -> void,
    in_ack_event: fn(arg: *u8, arg: u32) -> void,
    pkts_acked: fn(arg: *u8, arg: *u8) -> void,
    min_tso_segs: fn(arg: *u8) -> u32,
    cong_control: fn(arg: *u8, arg: u32, arg: u32, arg: *u8) -> void,
    undo_cwnd: fn(arg: *u8) -> u32,
    sndbuf_expand: fn(arg: *u8) -> u32,
    get_info: fn(arg: *u8, arg: u32, arg: *u8, arg: *u8) -> u64,
    name: u8[16],
    owner: *u8,
}

// Initialize shared state before registration
var connection_state : hash<u32, BbrState>(1024)

// Implement struct_ops using impl block syntax
@struct_ops("tcp_congestion_ops")
impl my_bbr_congestion_control {
    // Function implementations are directly defined in the impl block
    // These automatically become eBPF functions with SEC("struct_ops/function_name")
    
    fn ssthresh(sk: *u8) -> u32 {
        return 16
    }

    fn cong_avoid(sk: *u8, ack: u32, acked: u32) -> void {
        // eBPF congestion avoidance logic
        var state = connection_state[sk.id]
        // ... BBR logic with eBPF constraints
    }

    fn set_state(sk: *u8, new_state: u8) -> void {
        // eBPF state transition logic
        // In a real implementation, this would handle TCP state transitions
    }

    fn cwnd_event(sk: *u8, ev: u32) -> void {
        // eBPF congestion window event handler
        // Handle events like slow start, recovery, etc.
    }

    fn cong_control(sk: *u8, ack: u32, flag: u32, bytes_acked: *u8) -> void {
        // eBPF control logic
        var state = connection_state[sk.id]
        // ... Advanced BBR control logic
    }

    // Optional function implementations can be omitted
    // These would be null in the generated struct_ops map
}

// Register the impl block directly
register(my_bbr_congestion_control)
```

#### 3.9.2 Simplified Struct_ops Example

```kernelscript
// Minimal struct_ops implementation
@struct_ops("tcp_congestion_ops")
impl minimal_congestion_control {
    fn ssthresh(sk: *u8) -> u32 {
        return 16
    }

    fn cong_avoid(sk: *u8, ack: u32, acked: u32) -> void {
        // Minimal TCP congestion avoidance implementation
    }

    fn set_state(sk: *u8, new_state: u8) -> void {
        // Minimal state change handler
    }

    fn cwnd_event(sk: *u8, ev: u32) -> void {
        // Minimal congestion window event handler
    }

    // Optional functions can be omitted - they will be null in the struct_ops map
}

// Userspace registration
fn main() -> i32 {
    // Register the impl block directly - much cleaner than struct initialization
    var result = register(minimal_congestion_control)
    
    if (result == 0) {
        print("Congestion control algorithm registered successfully")
    } else {
        print("Failed to register congestion control algorithm")
    }
    
    return result
}
```

#### 3.9.3 Registration Function

The `register()` function is type-aware and generates the appropriate registration code:

```kernelscript
fn register(ops) -> i32
```

- For `@struct_ops` impl blocks: Generates libbpf registration using `bpf_map__attach_struct_ops()`
- Returns 0 on success, negative error code on failure
- The compiler determines the registration method based on the impl block attribute
- Impl blocks provide a cleaner syntax compared to struct initialization


## 4. Type System

### 4.1 Primitive Types
```kernelscript
// Integer types with explicit bit widths
u8, u16, u32, u64      // Unsigned integers
i8, i16, i32, i64      // Signed integers
bool                   // Boolean
char                   // 8-bit character
null                   // Represents expected absence of value

// Fixed-size string types (same syntax for both kernel and userspace)
str(N)                 // Fixed-size string with capacity N characters (N can be any positive integer)

// Pointer types - unified syntax for all contexts
*T                     // Pointer to type T (e.g., *u8, *PacketHeader, *[u8])

// Function pointer types
fn(param_types) -> return_type  // Function pointer type (e.g., fn(i32, i32) -> i32)

// Program function reference types (for explicit program lifecycle control)
FunctionRef            // Reference to an eBPF program function for loading/attachment
ProgramHandle          // Handle returned by load() for safe attachment
```

### 4.1.1 Null Semantics and Usage Guidelines

KernelScript uses `null` to represent **expected absence** of values, not error conditions. The same null semantics apply uniformly across both eBPF and userspace code.

#### When to Use `null`:
```kernelscript
// ✅ Map key lookups - absence is expected and normal
var flow_data = global_flows[flow_key]
if (flow_data == null) {
    // Key doesn't exist - create new entry
    global_flows[flow_key] = FlowData::new()
}

// ✅ Optional function return values - when no data is available
var packet = ctx.packet()  // Returns null if no packet available
if (packet == null) {
    return XDP_PASS
}

// ✅ Event polling - when no events are available
var event = event_queue.read()  // Returns null if queue is empty
if (event == null) {
    // No events to process
    return
}

// ✅ Optional configuration values
var timeout = config.optional_timeout  // Could be null if not set
var actual_timeout = if (timeout == null) { 5000 } else { timeout }
```

#### When to Use `throw` (NOT `null`):
```kernelscript
// ✅ Parse errors - unexpected failure conditions
fn parse_ip_header(data: *u8, len: u32) -> IpHeader {
    if (len < 20) {
        throw PARSE_ERROR_TOO_SHORT  // Error, not absence
    }
    if (data[0] >> 4 != 4) {
        throw PARSE_ERROR_INVALID_VERSION  // Error, not absence
    }
    return cast_to_ip_header(data)
}

// ✅ Resource allocation failures
fn allocate_buffer(size: u32) -> *u8 {
    var buffer = bpf_malloc(size)
    if (buffer == null) {
        throw ALLOCATION_ERROR_OUT_OF_MEMORY  // Error, not absence
    }
    return buffer
}

// ✅ Invalid input or state violations
fn update_counter(index: u32) {
    if (index >= MAX_COUNTERS) {
        throw VALIDATION_ERROR_INDEX_OUT_OF_BOUNDS  // Error, not absence
    }
    counters[index] += 1
}
```

#### Unified Pattern Across eBPF and Userspace:
```kernelscript
// Same null handling works identically in both contexts

// eBPF program
program packet_filter : xdp {
    fn main(ctx: *xdp_md) -> xdp_action {
        var cached_decision = decision_cache[ctx.hash()]
        if (cached_decision == null) {
            // Cache miss - compute decision
            var decision = compute_decision(ctx)
            decision_cache[ctx.hash()] = decision
            return decision
        }
        return cached_decision  // Cache hit
    }
}

// Userspace code
fn load_config(path: string) -> Config {
    var cached_config = config_cache[path]
    if (cached_config == null) {
        // Cache miss - load from disk
        var loaded = read_config_file(path)  // May throw on file errors
        config_cache[path] = loaded
        return loaded
    }
    return cached_config  // Cache hit
}
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
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XDP_REDIRECT = 4,
}

// Note: TC programs now return int values directly instead of TcAction enum
// Common TC return values:
// 0 = TC_ACT_OK, 1 = TC_ACT_RECLASSIFY, 2 = TC_ACT_SHOT, 3 = TC_ACT_PIPE, 
// 4 = TC_ACT_STOLEN, 5 = TC_ACT_QUEUED, 6 = TC_ACT_REPEAT, 7 = TC_ACT_REDIRECT
```

### 4.3 Function Pointers

KernelScript supports function pointers that allow storing and calling functions through variables. Function pointers work in both eBPF and userspace contexts.

#### 4.3.1 Function Pointer Types and Declaration

```kernelscript
// Function pointer type declaration
type BinaryOp = fn(i32, i32) -> i32
type UnaryOp = fn(u32) -> u32
type VoidCallback = fn() -> void
type ErrorHandler = fn(error_code: i32) -> bool

// Function pointer variable declaration
var operation: BinaryOp
var callback: VoidCallback
var handler: ErrorHandler

// Functions that can be assigned to function pointers
fn add_numbers(a: i32, b: i32) -> i32 {
    return a + b
}

fn multiply_numbers(a: i32, b: i32) -> i32 {
    return a * b
}

fn subtract_numbers(a: i32, b: i32) -> i32 {
    return a - b
}

// Assign functions to function pointers
operation = add_numbers
var mul_op: BinaryOp = multiply_numbers
var sub_op: BinaryOp = subtract_numbers
```

#### 4.3.2 Function Pointer Usage

```kernelscript
// Higher-order function with function pointer parameter
fn process_with_callback(x: i32, y: i32, callback: fn(i32, i32) -> i32) -> i32 {
    return callback(x, y)
}

fn main() -> i32 {
    // Assign functions to function pointers
    var add_op: BinaryOp = add_numbers
    var mul_op: BinaryOp = multiply_numbers
    
    // Call functions through function pointers
    var sum = add_op(10, 20)            // Result: 30
    var product = mul_op(5, 6)          // Result: 30
    
    // Pass function pointers as arguments
    var callback_result = process_with_callback(4, 7, add_numbers)      // Result: 11
    var callback_result2 = process_with_callback(4, 7, multiply_numbers) // Result: 28
    
    return 0
}
```

#### 4.3.3 Function Pointers in eBPF Context

```kernelscript
// Function pointer usage in eBPF programs
@helper
fn validate_packet(size: u32) -> bool {
    return size >= 64 && size <= 1500
}

@helper
fn log_packet(size: u32) -> bool {
    print("Packet size: %d", size)
    return true
}

type PacketValidator = fn(u32) -> bool

@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    if (packet == null) {
        return XDP_PASS
    }
    
    // Function pointer assignment in eBPF
    var validator: PacketValidator = validate_packet
    var logger: PacketValidator = log_packet
    
    // Call through function pointer
    if (!validator(packet.len)) {
        logger(packet.len)
        return XDP_DROP
    }
    
    return XDP_PASS
}
```

### 4.4 Type Aliases for Common Patterns
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
type ProcessName = str(16)     // Process name string
type IpAddressStr = str(16)    // IP address string ("255.255.255.255")
type FilePath = str(256)       // File path string
type LogMessage = str(128)     // Log message string
type ShortString = str(32)     // Short general-purpose string
type MediumString = str(128)   // Medium general-purpose string

// Function pointer type aliases
type BinaryOp = fn(i32, i32) -> i32     // Binary arithmetic operation
type UnaryOp = fn(u32) -> u32           // Unary operation
type PacketValidator = fn(u32) -> bool   // Packet validation function
type ErrorHandler = fn(error_code: i32) -> bool  // Error handling callback
```

### 4.5 String Operations
KernelScript supports fixed-size strings with `str(N)` syntax, where N can be any positive integer (e.g., `str(1)`, `str(10)`, `str(42)`, `str(1000)`). The following operations are supported:

```kernelscript
// String declaration and assignment (N can be any positive integer)
var name: str(16) = "John"
var surname: str(16) = "Doe"
var buffer: str(32) = "Hello"
var small_buffer: str(8) = "tiny"
var custom_size: str(42) = "custom"
var large_buffer: str(512) = "large text content"

// Assignment
buffer = name                  // Assignment (size must be compatible)

// Indexing (read-only character access)
var first_char: char = name[0] // Returns 'J'
var last_char: char = name[3]  // Returns 'n'

// String concatenation (explicit result size required)
var full_name: str(32) = name + surname  // "JohnDoe"
var greeting: str(20) = "Hello " + name  // "Hello John"
var custom_msg: str(100) = small_buffer + " and " + custom_size  // Arbitrary sizes work

// String comparison
if (name == "John") {             // Equality comparison
    print("Name matches")
}

if (surname != "Smith") {         // Inequality comparison
    print("Surname is not Smith")
}

// Examples with different contexts
struct PersonInfo {
    name: ProcessName,          // str(16)
    address: FilePath,          // str(256)
    status: ShortString,        // str(32)
}

// Kernel space usage - kprobe with BTF-extracted function signature
@probe("sys_open")
fn user_monitor(dfd: i32, filename: *u8, flags: i32, mode: u16) -> i32 {
    var process_name: ProcessName = get_current_process_name()
    var file_path: FilePath = get_file_path_from_filename(filename)
    
    // String operations work the same in kernel space
    if (process_name == "malware") {
        var log_msg: LogMessage = "Blocked process: " + process_name
        print(log_msg)
        return -1
    }
    
    return 0
}

// Userspace usage
struct Args {
    interface: str(16),
    config_file: str(256),
}

fn main(args: Args) -> i32 {
    // Same string operations in userspace
    if (args.interface == "eth0") {
        var status_msg: str(64) = "Using interface: " + args.interface
        print(status_msg)
    }
    
    return 0
}
```

### 4.6 Pointer Operations and Memory Access

KernelScript uses a unified pointer syntax `*T` for all pointer types, with the compiler transparently handling different pointer semantics based on context. This provides simplicity while maintaining safety and performance.

#### 4.6.1 Pointer Declaration and Basic Operations

```kernelscript
// Pointer declaration - unified syntax for all contexts
var data_ptr: *u8 = get_data_source()
var header_ptr: *PacketHeader = get_packet_header()
var buffer_ptr: *[u8] = allocate_buffer(1024)

// Address-of operator (&) - take address of a value
var value: u32 = 42
var value_ptr: *u32 = &value

// Dereference operator (*) - access value through pointer
var retrieved_value: u32 = *value_ptr

// Null checking - required before dereference
if (data_ptr != null) {
    var first_byte = *data_ptr
}
```

#### 4.6.2 Struct Field Access Through Pointers

```kernelscript
struct PacketHeader {
    version: u8,
    length: u16,
    protocol: u8,
    checksum: u32,
    src_ip: u32,
    dst_ip: u32,
}

// Arrow operator (->) for pointer-to-struct field access
@helper
fn process_packet_header(header_ptr: *PacketHeader) -> bool {
    // Null check required
    if (header_ptr == null) {
        return false
    }
    
    // Arrow operator for field access
    if (header_ptr->version != 4) {
        return false
    }
    
    // Field modification through pointer
    header_ptr->checksum = 0
    header_ptr->checksum = calculate_checksum(header_ptr)
    
    return header_ptr->protocol == TCP || header_ptr->protocol == UDP
}

// Alternative explicit dereference syntax (also supported)
@helper
fn explicit_dereference_style(header_ptr: *PacketHeader) {
    if (header_ptr != null) {
        var version = (*header_ptr).version    // Explicit dereference
        (*header_ptr).checksum = 0             // Explicit modification
    }
}
```

#### 4.6.3 Array Access Through Pointers

```kernelscript
struct DataBuffer {
    header: BufferHeader,
    data: [u8; 1500],
    metadata: [u32; 16],
}

@helper
fn process_buffer(buf_ptr: *DataBuffer) {
    if (buf_ptr == null) return
    
    // Array field access through pointer
    buf_ptr->data[0] = 0xFF                    // First data byte
    buf_ptr->metadata[0] = bpf_ktime_get_ns() as u32
    
    // Iterate over array field
    for (i in 0..16) {
        buf_ptr->metadata[i] = i as u32
    }
    
    // Get pointer to array element
    var data_start: *u8 = &buf_ptr->data[0]
    var metadata_ptr: *u32 = &buf_ptr->metadata[0]
    
    // Process with raw pointers
    process_raw_data(data_start, buf_ptr->header.length)
}
```

#### 4.6.4 Pointer Arithmetic

```kernelscript
@helper
fn pointer_arithmetic_examples(base_ptr: *u8, len: u32) {
    if (base_ptr == null) return
    
    // Pointer arithmetic - compiler inserts bounds checks
    var next_byte_ptr = base_ptr + 1           // Move to next byte
    var offset_ptr = base_ptr + 10             // Move by offset
    
    // Array-style indexing (preferred for readability)
    var first_byte = base_ptr[0]               // Equivalent to *base_ptr
    var tenth_byte = base_ptr[9]               // Equivalent to *(base_ptr + 9)
    
    // Pointer difference
    var byte_distance = next_byte_ptr - base_ptr  // Returns 1
}
```

#### 4.6.5 Context-Aware Pointer Semantics

```kernelscript
// eBPF Context - Automatic bounds checking and dynptr integration
@xdp
fn ebpf_pointer_usage(ctx: *xdp_md) -> xdp_action {
    // Context pointers - automatically bounded
    var packet_data: *u8 = ctx->data()          // Bounded by ctx->data_end()
    var packet_end: *u8 = ctx->data_end()       // End boundary
    
    // Compiler automatically inserts verifier-compliant bounds checks
    if (packet_data + 14 <= packet_end) {
        var eth_header = packet_data as *EthHeader
        if (eth_header->eth_type == ETH_P_IP) {
            // Safe access - bounds verified
            process_ethernet_header(eth_header)
        }
    }
    
    // Dynptr-backed pointers (transparent to user)
    var log_buffer: *u8 = event_log.reserve(256)  // Returns dynptr-backed pointer
    if (log_buffer != null) {
        // Regular pointer operations - compiler uses dynptr API internally
        log_buffer[0] = EVENT_TYPE_PACKET
        write_packet_summary(log_buffer + 1, packet_data, 255)
        event_log.submit(log_buffer)
    }
    
    return XDP_PASS
}

// Userspace Context - Full pointer functionality
fn userspace_pointer_usage() -> i32 {
    // Dynamic allocation
    var buffer: *u8 = malloc(4096)
    if (buffer == null) {
        return -1
    }
    
    // Full pointer arithmetic
    var mid_ptr = buffer + 2048
    var end_ptr = buffer + 4096
    
    // Direct memory operations
    *buffer = 0xFF
    buffer[100] = 0xAA
    
    // Cleanup
    free(buffer)
    return 0
}
```

#### 4.6.6 Function Parameters with Pointers

```kernelscript
// Explicit parameter semantics - no transparent conversion

// Value semantics - always copy (compiler warns for large structs in eBPF)
fn process_by_value(data: PacketData) {
    data.packets += 1  // Modifies local copy only
}

// Pointer semantics - explicit reference
fn process_by_pointer(data: *PacketData) {
    if (data != null) {
        data->packets += 1  // Modifies original through pointer
    }
}

// Example with compiler guidance
@helper
fn ebpf_function_parameters() {
    var large_struct = LargePacketData { /* ... */ }
    
    // ⚠️ Compiler warning: "Large struct (1024 bytes) passed by value in eBPF context"
    // process_by_value(large_struct)  
    
    // ✅ Recommended: use pointer for large structs in eBPF
    process_by_pointer(&large_struct)
}
```

#### 4.6.7 Map Integration with Pointers

```kernelscript
var flow_map : hash<FlowKey, FlowData>(1024)

@helper
fn map_pointer_operations(flow_key: FlowKey) {
    // Map lookup returns pointer to value
    var flow_data = flow_map[flow_key]
    
    if (flow_data != none) {
        // Direct modification through pointer
        flow_data->packet_count += 1
        flow_data->byte_count += packet_size
        flow_data->last_seen = bpf_ktime_get_ns()
        
        // Compiler tracks map value lifetime
        // flow_data becomes invalid after certain map operations
    }
}
```

#### 4.6.8 Safety Rules and Compiler Enforcement

```kernelscript
// Automatic null checking enforcement
@helper
fn null_safety_example(ptr: *u8) -> u8 {
    // ❌ Compilation error: potential null dereference
    // return *ptr
    
    // ✅ Required null check
    if (ptr != null) {
        return *ptr
    }
    return 0
}

// Bounds checking in eBPF context
@xdp
fn bounds_safety_example(ctx: *xdp_md) -> xdp_action {
    var data = ctx->data()
    var data_end = ctx->data_end()
    
    // Compiler automatically generates verifier-compliant bounds checks
    if (data + sizeof(EthHeader) <= data_end) {
        var eth = data as *EthHeader
        // Safe to access eth->fields
        return process_ethernet(eth)
    }
    
    return XDP_DROP
}
```

## 5. eBPF Maps and Global Sharing

### 5.1 Map Declaration Syntax
```ebnf
map_declaration = [ "pin" ] [ "@flags" "(" flag_expression ")" ] "var" identifier ":" map_type "<" key_type "," value_type ">" "(" map_config ")"

map_type = "hash" | "array" | "percpu_hash" | "percpu_array" | "lru_hash" 

map_config = max_entries [ "," additional_config ]
flag_expression = identifier | ( identifier { "|" identifier } )
```

### 5.1.1 Map Pinning

Maps declared with the `pin` keyword are automatically pinned to the BPF filesystem using standardized paths:

```
/sys/fs/bpf/<PROJECT_NAME>/maps/<MAP_NAME>
```

The project name is automatically determined from the package/executable name.

**Note**: The `pin` keyword is also used for global variables (see section 3.3.5), which are pinned to `/sys/fs/bpf/<PROJECT_NAME>/globals/pinned_globals`.

### 5.1.2 Map Flags

Map flags can be specified using the `@flags` attribute:

```kernelscript
// Map with flags
@flags(BPF_F_NO_PREALLOC | BPF_F_NO_COMMON_LRU)
var dynamic_cache : hash<u32, PacketData>(1024)

// Pinned map with flags
@flags(BPF_F_NO_PREALLOC)
pin var persisted_flows : hash<u32, FlowData>(2048)
```

**Supported flags:**
- `BPF_F_NO_PREALLOC` - Disable preallocation of map elements
- `BPF_F_NO_COMMON_LRU` - Disable common LRU for LRU maps
- `BPF_F_NUMA_NODE` - Specify NUMA node for map allocation
- `BPF_F_RDONLY` - Map is read-only from program side
- `BPF_F_WRONLY` - Map is write-only from program side
- `BPF_F_RDONLY_PROG` - Map is read-only from program side
- `BPF_F_WRONLY_PROG` - Map is write-only from program side

### 5.2 Global Maps (Shared Across Programs)

Global maps are declared at the global scope and are automatically shared between all eBPF programs.

**Map Declaration Syntax:**
- `var name : Type<K,V>(size)` - Local map (program-specific)
- `pin var name : Type<K,V>(size)` - Pinned map (persisted to filesystem)
- `@flags(...) var name : Type<K,V>(size)` - Map with specific flags
- `@flags(...) pin var name : Type<K,V>(size)` - Pinned map with flags

**Automatic Path Generation:**
Pinned maps are automatically stored at `/sys/fs/bpf/<PROJECT_NAME>/maps/<MAP_NAME>`.

```kernelscript
// Global maps - automatically shared between all programs

// Pinned maps - persisted to filesystem (/sys/fs/bpf/<PROJECT>/maps/<NAME>)
pin var global_flows : hash<FlowKey, FlowStats>(10000)
pin var interface_stats : array<u32, InterfaceStats>(256)
pin var security_events : hash<SecurityEvent, u64>(1024)

// Non-pinned maps - shared during runtime but not persisted
var session_cache : hash<u32, TempData>(512)

// Maps with flags
@flags(BPF_F_NO_PREALLOC)
pin var global_config : array<ConfigKey, ConfigValue>(64)

// Program 1: Can access all global maps
@xdp
fn ingress_monitor(ctx: *xdp_md) -> xdp_action {
    var flow_key = extract_flow_key(ctx)?
    
    // Access global map directly
    if (global_flows[flow_key] == null) {
        global_flows[flow_key] = FlowStats::new()
    }
    global_flows[flow_key].ingress_packets += 1      // Compound assignment
    global_flows[flow_key].ingress_bytes += ctx.packet_size()  // Compound assignment
    
    // Update interface stats using compound assignment
    interface_stats[ctx.ingress_ifindex()].packets += 1
    
    return XDP_PASS
}

// Program 2: Automatically has access to the same global maps
@tc
fn egress_monitor(ctx: *__sk_buff) -> int {
    var flow_key = extract_flow_key(ctx)?
    
    // Same global map, no import needed - compound assignments work everywhere
    if (global_flows[flow_key] != null) {
        global_flows[flow_key].egress_packets += 1        // Compound assignment
        global_flows[flow_key].egress_bytes += ctx.packet_size()   // Compound assignment
    }
    
    // Check global configuration
    var enable_filtering = if (global_config[CONFIG_KEY_ENABLE_FILTERING] != null) {
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
        return 2  // TC_ACT_SHOT
    }
    
    return 0  // TC_ACT_OK
}

// Program 3: Security analyzer using the same global maps
@lsm("socket_connect")
fn security_analyzer(ctx: LsmContext) -> i32 {
    var flow_key = extract_flow_key_from_socket(ctx)?
    
    // Check global flow statistics
    if (global_flows[flow_key] != null) {
        var flow_stats = global_flows[flow_key]
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
```

### 5.3 Global Map Access

```kernelscript
// Global maps - accessible by all eBPF programs
pin var global_counters : array<u32, GlobalCounter>(256)
pin var event_stream : hash<u32, Event>(1024)

@probe("sys_read")
fn producer(fd: u32, buf: *u8, count: usize) -> i32 {
    var pid = bpf_get_current_pid_tgid() as u32
    
    // Update global counter (accessible by other programs)
    global_counters[pid % 256] += 1
    
    // Send event to global stream
    var event = Event {
        pid: pid,
        syscall: "read",
        fd: fd,
        bytes_requested: count,
        timestamp: bpf_ktime_get_ns(),
    }
    event_stream.submit(event)
    
    return 0
}

@probe("sys_write")
fn consumer(fd: u32, buf: *u8, count: usize) -> i32 {
    var pid = bpf_get_current_pid_tgid() as u32
    
    // Access global counter (same map as producer program)
    var read_count = global_counters[pid % 256]
    
    // Process the write count data with actual parameters
    process_write_count(read_count, fd, count)
    
    return 0
}
```

### 5.4 Map Examples
```kernelscript
// Global maps accessible by all programs
pin var packet_stats : hash<u32, PacketStats>(1024)

pin var counters : percpu_array<u32, u64>(256)

pin var active_flows : lru_hash<FlowKey, FlowInfo>(10000)

pin var events : hash<u32, PacketEvent>(1024)

pin var config_map : array<ConfigKey, ConfigValue>(16)

@xdp
fn simple_monitor(ctx: *xdp_md) -> xdp_action {
    // Access global maps directly
    packet_stats[ctx.packet_type()] += 1
    counters[0] += 1
    
    // Process packet and update flow info
    var flow_key = extract_flow_key(ctx)
    active_flows[flow_key] = FlowInfo::new()
    
    return XDP_PASS
}
```

## 6. Assignment Operators

### 6.1 Simple Assignment
```kernelscript
var x: u32 = 10
x = 20  // Simple assignment
```

### 6.2 Compound Assignment Operators

KernelScript supports compound assignment operators that provide a concise way to perform arithmetic operations combined with assignment. These operators work identically to their C counterparts and are supported in both eBPF and userspace contexts.

#### 6.2.1 Supported Operators
```kernelscript
// Compound assignment operators
x += y   // Equivalent to: x = x + y
x -= y   // Equivalent to: x = x - y  
x *= y   // Equivalent to: x = x * y
x /= y   // Equivalent to: x = x / y
x %= y   // Equivalent to: x = x % y
```

#### 6.2.2 Type Requirements and Safety

Compound assignment operators enforce type safety and const variable protection:

```kernelscript
// Valid usage with compatible types
var counter: u32 = 0
var increment: u32 = 5

counter += increment    // ✅ Both u32 - valid
counter *= 2           // ✅ u32 with literal - valid
counter %= 10          // ✅ Modulo with u32 - valid

// Type restrictions
const MAX_VALUE: u32 = 1000
// MAX_VALUE += 1      // ❌ Compilation error: cannot assign to const

var float_val: f32 = 3.14
// counter += float_val  // ❌ Compilation error: type mismatch

// Operator restrictions - only arithmetic types support arithmetic operators
var flag: bool = true
// flag += true         // ❌ Compilation error: operator not supported for bool
```

#### 6.2.3 Usage in eBPF Programs

Compound assignments work seamlessly in eBPF programs with automatic bounds checking:

```kernelscript
// Global counters using compound assignment
var packet_count: u64 = 0
var total_bytes: u64 = 0

@xdp
fn packet_counter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    if (packet == null) {
        return XDP_PASS
    }
    
    // Compound assignments in eBPF context
    packet_count += 1                    // Increment packet counter
    total_bytes += packet.len            // Add packet size to total
    
    var processing_time = measure_time()
    processing_time *= 2                 // Double the processing time
    processing_time /= 1000              // Convert to milliseconds
    
    return XDP_PASS
}

// Map operations with compound assignment
var flow_stats : hash<u32, FlowStats>(1024)

@helper
fn update_flow_stats(flow_id: u32, packet_size: u32) {
    var stats = flow_stats[flow_id]
    if (stats != null) {
        stats.packet_count += 1
        stats.total_bytes += packet_size
        stats.avg_packet_size = stats.total_bytes / stats.packet_count
    }
}
```

#### 6.2.4 Usage in Userspace Programs

Compound assignments work identically in userspace code:

```kernelscript
struct Statistics {
    processed: u64,
    errors: u32,
    total_time: u64,
}

fn process_batch(stats: *Statistics, batch_size: u32, processing_time: u64) {
    // Compound assignment with struct fields
    stats->processed += batch_size
    stats->total_time += processing_time
    
    // Local variable compound assignment
    var error_rate: u32 = stats->errors * 100
    error_rate /= stats->processed as u32
    
    if (error_rate > 5) {
        stats->errors += 1
    }
}

fn main() -> i32 {
    var stats = Statistics { processed: 0, errors: 0, total_time: 0 }
    var batch_count: u32 = 0
    var total_items: u64 = 0
    
    for (i in 0..100) {
        batch_count += 1
        total_items += 50    // Process 50 items per batch
        
        process_batch(&stats, 50, measure_batch_time())
    }
    
    // Final calculations using compound assignment
    stats.total_time /= 1000000  // Convert nanoseconds to milliseconds
    
    print("Processed %d items in %d batches", total_items, batch_count)
    print("Total time: %d ms", stats.total_time)
    
    return 0
}
```

#### 6.2.5 Performance and Code Generation

Compound assignments generate efficient code in both contexts:

**eBPF bytecode**: Optimized to minimize instruction count
**Userspace C**: Direct compound assignment operators (`x += y`)

```c
// Generated C code for userspace
total_bytes = (total_bytes + packet_size);  // From: total_bytes += packet_size
counter = (counter * 2);                    // From: counter *= 2
value = (value % modulus);                  // From: value %= modulus
```

## 7. Functions and Control Flow

### 7.1 Function Declaration Overview

KernelScript functions support both traditional unnamed return types and modern named return values. The complete grammar is defined in Section 15 (Complete Formal Grammar).

Key function types:
- **eBPF program functions**: Attributed with `@xdp`, `@tc`, `@tracepoint`, etc. - compile to eBPF bytecode
- **Helper functions**: Attributed with `@helper` - shared across all eBPF programs
- **Userspace functions**: No attributes - compile to native executable

### 7.2 eBPF Program Functions
```kernelscript
// eBPF program function with attribute - entry point
@xdp
fn simple_xdp(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()?
    
    if packet.is_tcp() {
        return XDP_PASS
    }
    
    return XDP_DROP
}
```

### 7.3 Named Return Values

KernelScript supports both unnamed and named return values following Go's syntax pattern:

- **Unnamed returns** (backward compatible): `fn name() -> type`
- **Named returns** (new): `fn name() -> var_name: type`

Named return values automatically declare a local variable with the specified name and type. This variable can be used throughout the function, and naked returns (`return` without a value) will return the current value of the named variable.

#### 7.3.1 Named Return Syntax Examples

```kernelscript
// Backward compatible unnamed return (unchanged)
fn add_numbers(a: i32, b: i32) -> i32 {
    return a + b
}

// Named return value - 'sum' becomes a local variable
fn add_numbers_named(a: i32, b: i32) -> sum: i32 {
    sum = a + b    // Named variable is automatically declared
    return         // Naked return - returns current value of 'sum'
}

// Using named return in complex logic
fn calculate_hash(data: *u8, len: u32) -> hash_value: u64 {
    hash_value = 0  // Named return variable is available immediately
    
    for (i in 0..len) {
        hash_value = hash_value * 31 + data[i]  // Modify throughout function
    }
    
    return          // Naked return with computed hash_value
}

// Mixing named variables with explicit returns
fn validate_packet(data: *u8, len: u32) -> is_valid: bool {
    is_valid = false  // Start with default value
    
    if (len == 0) {
        return        // Early naked return with is_valid = false
    }
    
    if (data == null) {
        return false  // Explicit return still works
    }
    
    is_valid = true   // Set to true if all checks pass
    return            // Final naked return
}
```

#### 7.3.2 Named Returns in Different Contexts

Named return values work consistently across all function types:

```kernelscript
// eBPF helper functions with named returns
@helper
fn extract_ip_header(ctx: *xdp_md) -> ip_hdr: *iphdr {
    var data = ctx->data
    var data_end = ctx->data_end
    
    if (data + 14 + 20 > data_end) {
        ip_hdr = null
        return  // Naked return with null
    }
    
    ip_hdr = (iphdr*)(data + 14)
    return  // Naked return with pointer
}

// eBPF program functions with named returns
@xdp
fn packet_filter(ctx: *xdp_md) -> action: xdp_action {
    action = XDP_PASS  // Default action
    
    var size = ctx->data_end - ctx->data
    if (size < 64) {
        action = XDP_DROP
        return  // Naked return with XDP_DROP
    }
    
    return  // Naked return with XDP_PASS
}

// Userspace functions with named returns
fn lookup_counter(ip: u32) -> counter_ptr: *u64 {
    if (counters[ip] == none) {
        counters[ip] = 0
    }
    counter_ptr = &counters[ip]
    return  // Naked return
}

// Function pointer types with named returns
type HashFunction = fn(*u8, u32) -> hash: u64
type PacketProcessor = fn(*xdp_md) -> result: xdp_action
```

#### 7.3.3 Code Generation

Named return values compile to clean, efficient C code with zero runtime overhead:

**KernelScript:**
```kernelscript
fn calculate_sum(a: i32, b: i32) -> result: i32 {
    result = a + b
    return
}
```

**Generated C:**
```c
static int calculate_sum(int a, int b) {
    int result;      // Named return variable declared
    result = a + b;
    return result;   // Naked return becomes explicit
}
```

### 7.4 Helper Functions

KernelScript supports two types of functions with different scoping rules:

1. **Kernel-shared functions** (`@helper`) - Shared across all eBPF programs
2. **Userspace functions** (no `kernel` qualifier, no attributes) - Native userspace code

```kernelscript
// Kernel-shared functions - accessible by all eBPF programs
@helper
fn validate_packet(packet: *PacketHeader) -> bool {
    packet.len >= 64 && packet.len <= 1500
}

// Public kernel-shared function
@helper
pub fn calculate_checksum(data: *u8, len: u32) -> u16 {
    var sum: u32 = 0
    for (i in 0..(len / 2)) {
        sum += data[i * 2] + (data[i * 2 + 1] << 8)
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return !(sum as u16)
}

// Private kernel-shared function
@helper
priv fn internal_kernel_helper() -> u32 {
    return 42
}

@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    // Can call kernel-shared functions
    if (!validate_packet(ctx.packet())) {
        return XDP_DROP
    }
    
    var checksum = calculate_checksum(ctx->data(), ctx.len())
    
    return XDP_PASS
}

@tc
fn flow_monitor(ctx: *__sk_buff) -> int {
    // Can call the same kernel-shared functions
    if (!validate_packet(ctx.packet())) {
        return 2  // TC_ACT_SHOT
    }
    
    return 0  // TC_ACT_OK
}

// Userspace function (no kernel qualifier, no attributes)
fn setup_monitoring() -> i32 {
    print("Setting up monitoring system")
    return 0
}

fn main() -> i32 {
    setup_monitoring()  // Can call other userspace functions
    
    // Cannot call validate_packet() here - it's kernel-only
    
    var filter_handle = load(packet_filter)
    var monitor_handle = load(flow_monitor)
    
    attach(filter_handle, "eth0", 0)
    attach(monitor_handle, "eth0", 1)
    
    print("Multiple programs attached to eth0")
    print("Running packet processing pipeline...")
    
    // Proper cleanup - detach in reverse order (best practice)
    detach(monitor_handle)
    detach(filter_handle)
    print("All programs detached successfully")
    
    return 0
}
```

### 7.5 eBPF Tail Calls

KernelScript provides transparent eBPF tail call support that automatically converts function calls to tail calls when appropriate. Tail calls enable efficient program chaining without stack overhead and are especially useful for packet processing pipelines.

#### 7.4.1 Automatic Tail Call Detection

The compiler automatically converts function calls to eBPF tail calls when **all** of the following conditions are met:

1. **Return position**: The function call is in a return statement
2. **Same program type**: Both functions have the same attribute (e.g., both `@xdp`)  
3. **Compatible signature**: Same context parameter and return type
4. **eBPF context**: The call is within an attributed eBPF function

```kernelscript
// eBPF programs that can be tail-called
@xdp
fn packet_classifier(ctx: *xdp_md) -> xdp_action {
    var protocol = get_protocol(ctx)  // Regular call (@helper)
    
    return match (protocol) {
        HTTP: process_http(ctx),    // Tail call - meets all conditions
        DNS: process_dns(ctx),      // Tail call - meets all conditions  
        ICMP: handle_icmp(ctx),     // Tail call - meets all conditions
        default: XDP_DROP           // Regular return
    }
}

@xdp  
fn process_http(ctx: *xdp_md) -> xdp_action {
    // HTTP processing logic
    if (is_malicious_http(ctx)) {    // Regular call (@helper)
        return XDP_DROP
    }
    
    return filter_by_policy(ctx)     // Tail call - another @xdp function
}

@xdp
fn filter_by_policy(ctx: *xdp_md) -> xdp_action {
    // Policy enforcement
    return XDP_PASS 
}

// Kernel helper function (not tail-callable)
@helper
fn get_protocol(ctx: *xdp_md) -> u16 {
    // Extract protocol from packet
    return 6  // TCP
}

@helper
fn is_malicious_http(ctx: *xdp_md) -> bool {
    // Security analysis
    return false
}
```

#### 7.4.2 Tail Call Rules and Restrictions

**✅ Valid Tail Calls:**
```kernelscript
@xdp 
fn main_filter(ctx: *xdp_md) -> xdp_action {
    return specialized_filter(ctx)   // ✅ Same type (@xdp), return position
}

@tc
fn ingress_handler(ctx: *__sk_buff) -> int {
    return security_check(ctx)       // ✅ Same type (@tc), return position  
}
```

**❌ Invalid Tail Calls (Become Regular Calls or Errors):**
```kernelscript
@xdp
fn invalid_examples(ctx: *xdp_md) -> xdp_action {
    // ❌ ERROR: Cannot call eBPF program function directly
    var result = process_http(ctx)
    
    // ❌ ERROR: Mixed program types (@xdp calling @tc)  
    return security_check(ctx)  // security_check is @tc
    
    // ✅ Regular call: kernel function
    validate_packet(ctx)
    
    // ✅ Regular call: kernel function  
    return if (validate_packet(ctx)) { XDP_PASS } else { XDP_DROP }
}
```

#### 7.4.3 Implementation Details

**Automatic Program Array Management:**
The compiler automatically generates and manages eBPF program arrays behind the scenes:

```kernelscript
// User writes this clean code:
@xdp fn classifier(ctx: *xdp_md) -> xdp_action {
    return match (get_protocol(ctx)) {
        HTTP: process_http(ctx),
        DNS: process_dns(ctx),
        default: XDP_DROP
    }
}

// Compiler generates (hidden from user):
// 1. Program array for tail call targets
// 2. Initialization code to populate the array  
// 3. bpf_tail_call() instead of regular function calls
// 4. Proper error handling for failed tail calls
```

**Userspace Transparency:**
Tail calls are completely transparent to userspace code. Each attributed function remains a complete, independent eBPF program that can be loaded and attached individually:

```kernelscript
struct Args {
    interface: str(16),
    mode: str(16),
}

fn main(args: Args) -> i32 {
    if (args.mode == "simple") {
        // Load individual program (no tail calls)
        var http_handle = load(process_http)
        attach(http_handle, args.interface, 0)
    } else {
        // Load main program (automatically sets up tail calls)
        var main_handle = load(packet_classifier)  
        attach(main_handle, args.interface, 0)
    }
    
    return 0
}
```

#### 7.4.4 Performance and Limitations

**Benefits:**
- **Zero stack overhead**: Tail calls replace the current program rather than adding stack frames
- **Efficient chaining**: Ideal for packet processing pipelines
- **Resource sharing**: All programs in the chain share the same context and maps

**eBPF Limitations (automatically handled by compiler):**
- **Maximum chain depth**: eBPF enforces a limit of 33 tail calls per execution
- **No return to caller**: Tail calls are terminal - they replace the current program
- **Same context type**: All programs in the chain must accept the same context

### 7.5 Control Flow Statements

#### 7.5.1 Conditional Statements
```kernelscript
// Conditional statements
if (condition) {
    // statements
} else if (other_condition) {
    // statements
} else {
    // statements
}
```

#### 7.5.2 Match Expressions

KernelScript provides `match` expressions for efficient multi-way branching. Match is an expression that returns a value and can be used anywhere an expression is expected.

```kernelscript
// Basic match expression with constant patterns
var action = match (packet.protocol()) {
    IPPROTO_TCP: XDP_PASS,
    IPPROTO_UDP: XDP_PASS,
    IPPROTO_ICMP: XDP_DROP,
    default: XDP_ABORTED
}

// Match in return statements - ideal for packet processing
@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    if (packet == null) return XDP_PASS
    
    return match (packet.protocol()) {
        IPPROTO_TCP: handle_tcp(ctx),    // Function call in match arm
        IPPROTO_UDP: handle_udp(ctx),    // Can be tail call candidates
        IPPROTO_ICMP: XDP_DROP,          // Or direct return values
        default: XDP_PASS
    }
}

// Match with complex expressions in arms
var result = match (security_level) {
    HIGH: process_high_security(packet),
    MEDIUM: if (packet.is_encrypted()) { XDP_PASS } else { XDP_DROP },
    LOW: XDP_PASS,
    default: XDP_ABORTED
}

// Nested match expressions
var final_action = match (packet.protocol()) {
    IPPROTO_TCP: match (tcp_header.dst_port) {
        80: handle_http(ctx),
        443: handle_https(ctx),
        22: handle_ssh(ctx),
        default: XDP_PASS
    },
    IPPROTO_UDP: handle_udp(ctx),
    default: XDP_DROP
}
```

#### 7.5.3 Loop Statements

```kernelscript
// Loops with automatic bounds checking
for (i in 0..MAX_ITERATIONS) {
    if (should_break()) {
        break
    }
    process_item(i)
}

// While loops (compiler ensures termination)
var iterations = 0
while (condition && iterations < MAX_ITERATIONS) {
    do_work()
    iterations = iterations + 1
}
```

## 8. Error Handling and Resource Management

### 8.1 Throw and Catch Statements

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
    
    var header = cast_to_ip_header(packet)
    if (header.version != 4) {
        throw PARSE_ERROR_INVALID_VERSION  // Throws integer value 2
    }
    
    return header
}

// Error handling with try/catch blocks using integer matching
fn process_packet(ctx: *xdp_md) -> xdp_action {
    try {
        var packet = get_packet(ctx)
        if (packet == null) {
            throw NETWORK_ERROR_ALLOCATION_FAILED  // Throws integer value 10
        }
        
        var header = parse_ip_header(packet.data, packet.len)
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
    
    var error_code = compute_error_code(value)
    if (error_code != 0) {
        throw error_code  // Variable throw
    }
}
```

### 8.2 Resource Management with Defer

The `defer` statement ensures cleanup code runs automatically at function exit, regardless of how the function returns (normal return, throw, or early exit).

```kernelscript
// Resource management with automatic cleanup
fn update_shared_counter(index: u32) -> bool {
    var data = shared_counters[index]
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
    var buffer = allocate_buffer()
    defer free_buffer(buffer)          // Executes 3rd
    
    var lock = acquire_lock()
    defer release_lock(lock)           // Executes 2nd
    
    var fd = open_file("config.txt")
    defer close_file(fd)               // Executes 1st
    
    // Use resources safely
    return process_data(buffer, lock, fd)
    // All defer statements execute automatically in reverse order
}
```

### 8.3 Defer with Try/Catch

Defer statements work seamlessly with error handling - cleanup always occurs even when exceptions are thrown or caught.

```kernelscript
fn safe_packet_processing(ctx: *xdp_md) -> xdp_action {
    var packet_buffer = allocate_packet_buffer()
    defer free_packet_buffer(packet_buffer)  // Always executes
    
    try {
        var lock = acquire_flow_lock()
        defer release_flow_lock(lock)        // Always executes
        
        var flow_data = process_flow(packet_buffer)
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

### 8.4 Error Handling Rules and Compiler Behavior

#### 8.4.1 eBPF Program Functions

**All throws must be caught** in eBPF program functions. Uncaught throws result in **compilation errors**.

```kernelscript
program packet_filter : xdp {
    fn main(ctx: *xdp_md) -> xdp_action {
        try {
            var result = process_packet(ctx)  // Might throw
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

#### 8.4.2 Helper Functions

Helper functions can propagate errors without catching them - this enables natural error composition and reduces boilerplate.

```kernelscript
// Helper functions can throw without catching
fn extract_flow_key(ctx: *xdp_md) -> FlowKey {
    var packet = get_packet(ctx)
    if packet == null {
        throw NETWORK_ERROR_ALLOCATION_FAILED  // ✅ OK - propagates to caller (throws 10)
    }
    
    return parse_flow_key(packet)  // May also throw - propagates up
}

fn validate_flow(key: FlowKey) -> FlowState {
    var state = lookup_flow_state(key)  // May throw
    if state.is_expired() {
        throw NETWORK_ERROR_RATE_LIMITED  // ✅ OK - propagates to caller (throws 12)
    }
    
    return state
}
```

#### 8.4.3 Userspace Functions

Userspace functions generate **compiler warnings** for uncaught throws, but compilation succeeds. Uncaught throws at runtime terminate the program.

```kernelscript
fn main() -> i32 {
    var prog = load(packet_filter)    // ⚠️ Warning: might throw
    attach(prog, "eth0", 0)           // ⚠️ Warning: might throw
    return 0
    // If any throw occurs, program terminates (like panic)
}

// Better - explicit error handling
fn main() -> i32 {
    try {
        var prog = load(packet_filter)
        attach(prog, "eth0", 0)
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

### 8.5 Panic and Assertions

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

## 9. User-Space Integration

### 9.1 Command Line Argument Handling

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

### 9.2 Top-Level Userspace Coordination with Global Maps
```kernelscript
// Global maps (accessible from all programs and userspace)
pin var global_flows : hash<FlowKey, FlowStats>(10000)

pin var global_events : hash<u32, Event>(1024)

pin var global_config : array<ConfigKey, ConfigValue>(64)

// Multiple eBPF programs working together
@xdp fn network_monitor(ctx: *xdp_md) -> xdp_action {
    // Access global maps directly
    var flow_key = extract_flow_key(ctx)
    global_flows[flow_key] += 1
    
    // Use named config for decisions
    if (monitoring.enable_stats) {
        monitoring.packets_processed += 1
    }
    
    // Send event to global stream
    global_events.submit(EVENT_PACKET_PROCESSED { flow_key })
    
    return XDP_PASS
}

@lsm("socket_connect")
fn security_filter(ctx: LsmContext) -> i32 {
    var flow_key = extract_flow_key_from_socket(ctx)
        
    // Check global flow statistics for threat detection
    if (global_flows[flow_key] != none) {
        var flow_stats = global_flows[flow_key]
        if (flow_stats.is_suspicious()) {
            global_events.submit(EVENT_THREAT_DETECTED { flow_key })
            return -EPERM  // Block connection
        }
    }
        
    return 0  // Allow connection
}

struct SystemCoordinator {
    network_monitor: BpfProgram,
    security_filter: BpfProgram,
    
    // Global map access (shared across all programs)
    global_flows: *FlowStatsMap,
    global_events: *EventHash,
    global_config: *ConfigMap,
}

fn new_system_coordinator() -> *SystemCoordinator {
        return SystemCoordinator {
            network_monitor: load(network_monitor),
            security_filter: load(security_filter),
            
            // Global maps are automatically accessible
            global_flows: GlobalMaps::flows(),
            global_events: GlobalMaps::events(),
            global_config: GlobalMaps::config(),
        }
}

fn start_coordinator() -> i32 {
    // Coordinate multiple programs
    var result1 = attach(network_monitor, "eth0", 0)
    var result2 = attach(security_filter, "socket_connect", 0)
    return if (result1 == 0 && result2 == 0) { 0 } else { -1 }
}

fn process_events(coordinator: *SystemCoordinator) {
    // Process events from all programs
    var event = coordinator->global_events.read()
    if (event != null) {
        if (event.event_type == EVENT_PACKET_PROCESSED) {
            print("Processed packet for flow: ", event.flow_key)
        } else if (event.event_type == EVENT_THREAT_DETECTED) {
            print("THREAT DETECTED: ", event.flow_key)
            handle_threat(coordinator, event.flow_key)
        }
    }
}

fn handle_threat(coordinator: *SystemCoordinator, flow_key: FlowKey) {
    // Coordinated response across all programs
    coordinator->global_config[CONFIG_KEY_THREAT_LEVEL] = CONFIG_VALUE_HIGH
}

struct Args {
    interface_id: u32,
    monitoring_enabled: u32,
}

fn main(args: Args) -> i32 {
    // Command line arguments automatically parsed
    // Usage: program --interface-id=0 --monitoring-enabled=1
    
    var coordinator = new_system_coordinator()
    start_coordinator()
    
    if (args.monitoring_enabled == 1) {
        print("Multi-program eBPF system started on interface: ", args.interface_id)
    }
    
    while (true) {
        process_events(coordinator)
        sleep(100)
    }
    
    return 0
}
```

### 9.3 Cross-Language Bindings
```kernelscript
// Runtime configuration for system behavior
config runtime {
    enable_logging: bool = true,
    verbose_mode: bool = false,
}

program network_monitor : xdp {
    fn main(ctx: *xdp_md) -> xdp_action {
        if (runtime.enable_logging) {
            print("Processing packet")
        }
        return XDP_PASS
    }
}

program flow_analyzer : tc {
    fn main(ctx: *__sk_buff) -> int {
        return 0  // TC_ACT_OK
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
    
    var network_monitor = load(network_monitor)
    var flow_analyzer = load(flow_analyzer)
    
    attach(network_monitor, args.interface_id, 0)
    attach(flow_analyzer, args.interface_id, 1)
    
    // Update runtime config based on command line
    runtime.verbose_mode = (args.verbose_mode == 1)
    
    if (runtime.verbose_mode) {
        print("Multi-program system loaded on interface: ", args.interface_id)
        print("Verbose mode enabled")
    }
    
    // Coordinate both programs
    handle_system_events(args.verbose_mode == 1)
    
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

## 10. Memory Management and Safety

### 10.1 Pointer Safety and Bounds Checking

KernelScript employs context-aware pointer safety mechanisms that adapt to the execution environment while maintaining a consistent programming model.

```kernelscript
// eBPF Context - Automatic bounds checking with verifier compliance
@xdp
fn safe_packet_processing(ctx: *xdp_md) -> xdp_action {
    var packet_data: *u8 = ctx->data()
    var packet_end: *u8 = ctx->data_end()
    
    // Compiler automatically generates verifier-compliant bounds checks
    if (packet_data + 20 <= packet_end) {
        var ip_header = packet_data as *IpHeader
        // Safe access - bounds verified by compiler-generated checks
        if (ip_header->version == 4) {
            return process_ipv4_packet(ip_header)
        }
    }
    
    return XDP_DROP
}

// Userspace Context - Traditional pointer safety
fn safe_userspace_access(data: *u8, len: u32) -> u8 {
    // Explicit null and bounds checking
    if (data == null || len == 0) {
        throw INVALID_POINTER_ERROR
    }
    
    return data[0]  // Compiler may insert runtime bounds check
}
```

### 10.2 Dynamic Pointer Integration (Transparent Dynptr)

The compiler transparently uses eBPF's dynamic pointer (dynptr) APIs when beneficial, without exposing complexity to the programmer.

```kernelscript
var event_log : hash<u32, Event>(1024)

@helper
fn transparent_dynptr_usage(event_data: *u8, data_len: u32) {
    // User writes simple pointer code
    var log_entry: *u8 = event_log.reserve(data_len + 16)  // Dynptr-backed pointer
    if (log_entry != null) {
        // Regular pointer operations - compiler uses dynptr API internally
        var header = log_entry as *EventHeader
        header->timestamp = bpf_ktime_get_ns()
        header->data_len = data_len
        
        // Memory copy using pointer arithmetic
        memory_copy(event_data, log_entry + 16, data_len)
        
        event_log.submit(log_entry)  // Compiler ensures proper cleanup
    }
}

// What compiler generates (using modern dynptr APIs):
// - bpf_ringbuf_reserve_dynptr() for allocation
// - bpf_dynptr_data() for pointer retrieval
// - bpf_dynptr_write() for ALL field assignments (event->field = value)
// - bpf_ringbuf_submit_dynptr() for submission
// Example: event->id = 42 becomes:
//   { __u32 __tmp_val = 42;
//     bpf_dynptr_write(&event_dynptr, __builtin_offsetof(struct Event, id), &__tmp_val, 4, 0); }
```

### 10.3 Stack Management and Large Struct Handling

```kernelscript
// Context-aware stack management
@helper
fn ebpf_stack_management() {
    var small_struct = SmallData { x: 1, y: 2 }  // 8 bytes - fine
    var medium_struct = MediumData { /* 128 bytes */ }  // ⚠️ Warning
    var large_struct = LargeData { /* 1024 bytes */ }   // ❌ Error in eBPF
    
    // Compiler suggestions:
    process_small(small_struct)      // ✅ Pass by value
    process_medium(&medium_struct)   // ✅ Pass by pointer (recommended)
    // process_large(large_struct)   // ❌ Compilation error
    process_large(&large_struct)     // ✅ Must use pointer
}

// Userspace - relaxed stack rules
fn userspace_stack_management() {
    var large_struct = LargeData { /* 1024 bytes */ }
    process_large(large_struct)      // ✅ Fine in userspace - plenty of stack
}

// Automatic stack tracking for eBPF
@xdp
fn stack_aware_function(ctx: *xdp_md) -> xdp_action {
    var buffer: [u8; 256] = [0; 256]  // Compiler tracks: 256 bytes used
    var header_info = PacketInfo {    // Compiler tracks: +64 bytes
        // ... fields
    }
    
    // If total stack usage > 512 bytes, compiler may:
    // 1. Issue warning about stack pressure
    // 2. Suggest using pointers for large data
    // 3. Automatically spill to map storage (advanced optimization)
    
    return process_packet_data(&buffer, &header_info)
}
```

### 10.4 Memory Lifetime and Resource Management

```kernelscript
// Automatic resource tracking and cleanup
@helper
fn resource_safe_processing(input: *u8, len: u32) -> ProcessResult {
    // Stack-based resource with automatic cleanup
    var work_buffer: [u8; 512] = [0; 512]
    var work_ptr: *u8 = &work_buffer[0]
    
    // Heap-like resource (userspace) or map-backed storage (eBPF)
    var temp_storage: *u8 = allocate_temp_space(len * 2)
    if (temp_storage == null) {
        throw ALLOCATION_ERROR
    }
    
    // Compiler ensures cleanup on all exit paths
    defer {
        deallocate_temp_space(temp_storage)  // Automatic cleanup
    }
    
    // Process data safely
    var result = transform_data(input, len, work_ptr, temp_storage)
    
    return result  // defer ensures cleanup
}

// Map value pointer lifetime tracking
var cache_map : hash<u32, DataCache>(1024)

@helper
fn map_lifetime_safety(key: u32) {
    var cache_entry = cache_map[key]
    if (cache_entry != none) {
        // Compiler tracks that cache_entry is valid here
        cache_entry->access_count += 1
        cache_entry->last_access = bpf_ktime_get_ns()
        
        // Compiler warns/errors if cache_entry used after invalidating operations
        cache_map[other_key] = other_value  // Invalidates cache_entry
        
        // ❌ Compiler error: "Use of potentially invalidated map value pointer"
        // cache_entry->access_count += 1
    }
}
```

### 10.5 Null Safety Enforcement

```kernelscript
// Compile-time null safety checks
@helper
fn null_safety_demonstration(maybe_ptr: *PacketData) -> u32 {
    // ❌ Compilation error: "Potential null pointer dereference"
    // return maybe_ptr->packet_count
    
    // ✅ Required null check
    if (maybe_ptr != null) {
        return maybe_ptr->packet_count  // Safe - null check verified
    }
    
    return 0
}

// Optional pointer types for clarity
@helper
fn optional_pointer_example() -> i32 {
    var data_ptr: *u8 = try_get_data()  // May return null
    
    // Compiler enforces null checking
    if (data_ptr != null) {
        var result = process_data(data_ptr)
        return 0
    } else {
        return -1
    }
}
```

### 10.6 Cross-Context Memory Safety

```kernelscript
// Context boundary safety
@xdp 
fn kernel_side_processing(ctx: *xdp_md) -> xdp_action {
    var packet_data = ctx->data()
    
    // Shared memory through maps - safe across contexts
    var shared_buffer = shared_map[0]
    if (shared_buffer != none) {
        shared_buffer->kernel_processed_count += 1
        memory_copy(packet_data, shared_buffer->data, min(packet_len, 64))
    }
    
    return XDP_PASS
}

// Userspace cannot directly access kernel pointers
fn userspace_processing() -> i32 {
    // ❌ Cannot access kernel context pointers directly
    // var packet_data = some_kernel_context.data()  // Compilation error
    
    // ✅ Access through shared maps
    var shared_buffer = shared_map[0]
    if (shared_buffer != none) {
        shared_buffer->userspace_processed_count += 1
        process_shared_data(shared_buffer->data)
    }
    
    return 0
}
```

## 11. Compilation and Build System

### 11.1 Deployment Configuration (deploy.yaml)
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

### 11.3 Build Commands
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

## 12. Testing Framework

KernelScript provides a built-in testing framework that allows developers to write unit tests for their eBPF programs. The testing framework includes the `@test` attribute for marking test functions and the `test()` builtin function for running eBPF programs in a controlled test environment.

### 12.1 Test Functions with @test Attribute

Functions marked with the `@test` attribute are considered test functions and are compiled differently when using the `--test` compilation mode. Test functions can use the `test()` builtin to trigger eBPF program execution in a controlled test environment.

```kernelscript
// Simple packet filter to test
@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet_size = ctx->data_end - ctx->data
    if (packet_size > 1000) {
        return XDP_DROP
    }
    return XDP_PASS
}

// Test function using @test attribute
@test
fn test_packet_filter() -> i32 {
    // Create test context
    var test_ctx = XdpTestContext {
        packet_size: 500,
        interface_id: 1,
        expected_action: 2,  // XDP_PASS
    }
    
    // Use test() builtin to run the eBPF program
    var result = test(packet_filter, test_ctx)
    
    if (result == 2) {  // XDP_PASS
        print("Test passed")
        return 0
    } else {
        print("Test failed: expected %d, got %d", 2, result)
        return 1
    }
}
```

### 12.2 Test Compilation Mode

KernelScript supports a special `--test` compilation mode that generates test-specific userspace code instead of eBPF programs. This mode allows running unit tests in a controlled userspace environment.

**Compilation Modes:**

```bash
# Regular compilation - generates eBPF programs and userspace code
kernelscript compile program.ks

# Test compilation - generates test userspace code too
kernelscript compile --test program.ks
```

**Test Mode Behavior:**

1. **Only @test functions are compiled**: Regular eBPF programs are excluded from test builds
2. **Userspace test executable**: Generates `program.test.c` instead of `program.c` and `program.ebpf.c`
3. **Simple Makefile**: Generates basic Makefile with `test` and `run-test` targets
4. **Mock environment**: Provides mock implementations of eBPF-specific functions for testing

**Generated Makefile in Test Mode:**

```makefile
# Auto-generated Makefile for test compilation
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g

PROGRAM_NAME = program
TEST_TARGET = $(PROGRAM_NAME).test

.PHONY: test run-test clean

test: $(TEST_TARGET)

run-test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(PROGRAM_NAME).test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TEST_TARGET)
```

### 12.3 Access Control Restrictions

The `test()` builtin function is **only** available to functions marked with the `@test` attribute. Attempting to call `test()` from regular functions, helper functions, or eBPF program functions will result in a compilation error.

```kernelscript
// ✅ Valid - test() call from @test function
@test
fn test_packet_behavior() -> i32 {
    var result = test(packet_filter, test_ctx)  // This is allowed
    return if (result == 2) { 0 } else { 1 }
}

// ❌ Compilation Error - test() call from regular function
fn regular_function() -> i32 {
    var result = test(packet_filter, test_ctx)  // ERROR!
    return 0
}

// ❌ Compilation Error - test() call from helper function
@helper
fn helper_function() -> i32 {
    var result = test(packet_filter, test_ctx)  // ERROR!
    return 0
}

// ❌ Compilation Error - test() call from eBPF program function
@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var result = test(packet_filter, test_ctx)  // ERROR!
    return XDP_PASS
}
```

This restriction ensures that testing code is clearly separated from production code and prevents accidental inclusion of test runner calls in production eBPF programs.

### 12.4 Testing Best Practices

**Organize Tests by Functionality:**
```kernelscript
@test
fn test_small_packets() -> i32 {
    var test_ctx = XdpTestContext { packet_size: 64, interface_id: 1, expected_action: 2 }
    var result = test(packet_filter, test_ctx)
    return if (result == 2) { 0 } else { 1 }
}

@test
fn test_large_packets() -> i32 {
    var test_ctx = XdpTestContext { packet_size: 1500, interface_id: 1, expected_action: 1 }
    var result = test(packet_filter, test_ctx)
    return if (result == 1) { 0 } else { 1 }
}
```

**Use Descriptive Test Names:**
```kernelscript
@test
fn test_rate_limiter_blocks_excessive_traffic() -> i32 {
    var test_ctx = XdpTestContext { packet_size: 100, interface_id: 1, expected_action: 1 }
    var result = test(rate_limiting_filter, test_ctx)
    return if (result == 1) { 0 } else { 1 }
}
```

**Test Edge Cases:**
```kernelscript
@test
fn test_zero_length_packet() -> i32 {
    var test_ctx = XdpTestContext { packet_size: 0, interface_id: 1, expected_action: 1 }
    var result = test(packet_validator, test_ctx)
    return if (result == 1) { 0 } else { 1 }
}
```

## 13. Standard Library

### 13.1 Core Library Functions
```kernelscript
// Network utilities
mod net {
    pub fn parse_ethernet(data: *u8, len: u32) -> *EthernetHeader
    pub fn parse_ipv4(data: *u8, len: u32) -> *Ipv4Header
    pub fn parse_tcp(data: *u8, len: u32) -> *TcpHeader
    pub fn calculate_checksum(data: *u8, len: u32) -> u16
}

// String utilities (limited for eBPF)
mod str {
    pub fn compare(a: *u8, a_len: u32, b: *u8, b_len: u32) -> i32
    pub fn find_byte(haystack: *u8, len: u32, needle: u8) -> i32  // Returns index or -1 if not found
}

// Math utilities
mod math {
    pub fn min(a: u64, b: u64) -> u64
    pub fn max(a: u64, b: u64) -> u64
    pub fn clamp(value: u64, min: u64, max: u64) -> u64
}

// Program lifecycle management (userspace only)
mod program {
    // Load an eBPF program function and return its handle
    pub fn load(function_ref: FunctionRef) -> ProgramHandle
    
    // Attach a program to a target with optional flags using its handle
    // - First parameter must be a ProgramHandle returned from load()
    // - For XDP: target is interface name (e.g., "eth0"), flags are XDP attachment flags
    // - For TC: target is interface name, flags indicate direction (ingress/egress)
    // - For Kprobe: target is function name (e.g., "sys_read"), flags are unused (0)
    // - For Cgroup: target is cgroup path (e.g., "/sys/fs/cgroup/test"), flags are unused (0)
    pub fn attach(handle: ProgramHandle, target: string, flags: u32) -> u32
    
    // Register struct_ops impl blocks
    pub fn register(ops) -> i32
}

// Testing utilities (only available in @test functions)
mod test {
    // Run an eBPF program function in a controlled test environment
    // This builtin function can ONLY be called from functions marked with @test attribute
    // Calling test() from regular functions, @helper functions, or eBPF program functions
    // will result in a compilation error
    // 
    // Usage:
    //   test(program_function, test_context) -> return_value
    //   var result = test(packet_filter, xdp_test_ctx)  // Returns XDP action
    //   var retval = test(kprobe_handler, kprobe_test_ctx)  // Returns kprobe return value
    pub fn test(program_function: FunctionRef, test_context: TestContext) -> i32
}
```

## 14. Example Programs

### 14.1 Simple Packet Filter
```kernelscript
// Named configuration for packet filtering
config filtering {
    blocked_ports: u16[4] = [22, 23, 135, 445],
    enable_logging: bool = false,
    max_packet_size: u32 = 1500,
}

config system {
    packets_dropped: u64 = 0,
    packets_processed: u64 = 0,
}

// Custom kernel function for advanced port analysis
@kfunc
fn advanced_port_check(port: u16, protocol: u8, src_ip: u32) -> i32 {
    // Full kernel privileges - access to network namespaces, security modules
    var ns = get_current_net_ns()
    var policy = lookup_port_policy(ns, port, protocol)
    
    if (policy == null) {
        return 0  // No policy, allow
    }
    
    // Check with kernel firewall subsystem
    return netfilter_check_port_policy(policy, src_ip, port)
}

// Kernel-shared functions - accessible by all eBPF programs
@helper
fn is_port_blocked(port: u16) -> bool {
    for (i in 0..4) {
        if (port == filtering.blocked_ports[i]) {
            return true
        }
    }
    return false
}

@helper
fn log_blocked_port(port: u16) {
    if (filtering.enable_logging) {
        print("Blocked port %d", port)
    }
}

@xdp
fn simple_filter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    if (packet == null) {
        return XDP_PASS
    }
    
    system.packets_processed += 1    // Compound assignment - increment packet counter
    
    if (packet.is_tcp()) {
        var tcp = packet.tcp_header()
        
        // First check simple blocked ports (kernel-shared function)
        if (is_port_blocked(tcp.dst_port)) {
            log_blocked_port(tcp.dst_port)
            system.packets_dropped += 1   // Compound assignment - increment drop counter
            return XDP_DROP
        }
        
        // Advanced analysis using kfunc for complex policy checking
        var policy_result = advanced_port_check(tcp.dst_port, packet.protocol(), packet.src_ip())
        if (policy_result != 0) {
            log_blocked_port(tcp.dst_port)
            system.packets_dropped += 1   // Compound assignment - track policy drops
            return XDP_DROP
        }
    }
    
    return XDP_PASS
}

@tc
fn security_monitor(ctx: *__sk_buff) -> int {
    var packet = ctx.packet()
    if (packet == null) {
        return 0  // TC_ACT_OK
    }
    
    if (packet.is_tcp()) {
        var tcp = packet.tcp_header()
        
        // Check simple blocked ports first
        if (is_port_blocked(tcp.src_port)) {
            log_blocked_port(tcp.src_port)
            return 2  // TC_ACT_SHOT
        }
        
        // Use the same kfunc for advanced policy checking
        var policy_result = advanced_port_check(tcp.src_port, packet.protocol(), packet.dst_ip())
        if (policy_result != 0) {
            log_blocked_port(tcp.src_port)
            return 2  // TC_ACT_SHOT
        }
    }
    
    return 0  // TC_ACT_OK
}

// Userspace coordination with explicit program lifecycle
struct Args {
    interface: str(16),
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
    
    // Explicit program lifecycle management for multiple programs
    var filter_handle = load(simple_filter)
    var monitor_handle = load(security_monitor)
    
    var filter_result = attach(filter_handle, args.interface, 0)
    var monitor_result = attach(monitor_handle, args.interface, 1)
    
    if (filter_result != 0 || monitor_result != 0) {
        print("Failed to attach programs to interface: ", args.interface)
        // Clean up any successful attachments
        if (filter_result == 0) {
            detach(filter_handle)
        }
        if (monitor_result == 0) {
            detach(monitor_handle)
        }
        return 1
    }
    
    if (!args.quiet_mode) {
        print("Multi-program packet filtering started on interface: ", args.interface)
        print("XDP filter and TC monitor using shared kernel functions and custom kfuncs")
        print("Blocking ports: 22, 23, 135, 445")
        print("Advanced policy checking enabled via kfunc")
        if (args.strict_mode) {
            print("Strict mode enabled - max packet size: 1000")
        }
    }
    
    // Monitor system health using config stats
    var iteration_count = 0
    while (iteration_count < 100) {  // Run for limited time in example
        if (system.packets_dropped > 1000 && !args.quiet_mode) {
            print("High drop rate detected: ", system.packets_dropped)
        }
        sleep(10000)
        iteration_count += 1
    }
    
    // Proper cleanup when shutting down
    print("Shutting down, detaching programs...")
    detach(monitor_handle)  // Detach in reverse order
    detach(filter_handle)
    print("All programs detached successfully")
    
    return 0
}
```

### 14.2 Global Variables Example
```kernelscript
// Global variables - shared between kernel and userspace
var packet_count: u64 = 0
var enable_debug: bool = false
var max_allowed_size: u32 = 1500

// Pinned global variables - persisted across program restarts
pin var total_sessions: u64 = 0
pin var persistent_config: str(64) = "default_config"
pin var crash_count: u32 = 0

// Type inference examples
var inferred_counter = 0            // Type: u32
var inferred_message = "startup"    // Type: str(8)
var inferred_flag = true            // Type: bool

// Uninitialized global variables
var total_bytes: u64
var interface_name: str(16)

// eBPF program using global and pinned variables
@xdp
fn packet_counter(ctx: *xdp_md) -> xdp_action {
    var packet = ctx.packet()
    if (packet == null) {
        return XDP_PASS
    }
    
    // Access global variables directly
    packet_count += 1
    total_bytes += packet.len
    
    // Use global configuration
    if (packet.len > max_allowed_size) {
        if (enable_debug) {
            print("Packet too large: %d bytes", packet.len)
        }
        return XDP_DROP
    }
    
    return XDP_PASS
}

// Userspace program using global and pinned variables
struct Args {
    interface: str(16),
    debug: bool,
    max_size: u32,
    reset_stats: bool,
}

fn main(args: Args) -> i32 {
    // Configure global variables from command line
    enable_debug = args.debug
    max_allowed_size = args.max_size
    interface_name = args.interface
    
    // Initialize uninitialized globals
    total_bytes = 0
    
    // Handle pinned variables (persistent across restarts)
    if (args.reset_stats) {
        total_sessions = 0
        crash_count = 0
        persistent_config = "reset_config"
    } else {
        // Values persist from previous runs
        total_sessions += 1  // Increment session counter
        print("Previous sessions: %d", total_sessions - 1)
        print("Previous crashes: %d", crash_count)
        print("Persistent config: %s", persistent_config)
    }
    
    if (enable_debug) {
        print("Debug mode enabled")
        print("Max packet size: %d", max_allowed_size)
        print("Interface: %s", interface_name)
        print("Session number: %d", total_sessions)
    }
    
    // Load and attach program
    var prog_handle = load(packet_counter)
    var result = attach(prog_handle, interface_name, 0)
    
    if (result != 0) {
        print("Failed to attach program")
        crash_count += 1  // Track failures in pinned variable
        return 1
    }
    
    print("Packet counter started on interface: %s", interface_name)
    print("Session %d started", total_sessions)
    
    // Monitor global state
    while (true) {
        if (enable_debug) {
            print("Packets: %d, Total bytes: %d", packet_count, total_bytes)
            print("Session: %d, Total sessions: %d", total_sessions, total_sessions)
        }
        sleep(5000)
    }
    
    return 0
}
```

### 14.3 Performance Monitoring
```kernelscript
// Global maps for performance data
var active_calls : hash<u32, CallInfo>(1024)
var read_stats : array<u32, u64>(1024)
var write_stats : array<u32, u64>(1024)

struct CallInfo {
    start_time: u64,
    bytes_requested: u32,
}

// Custom kernel function for advanced performance analysis
@kfunc
fn analyze_syscall_performance(pid: u32, syscall_nr: u32, bytes: u32, duration: u64) -> i32 {
    // Full kernel privileges - access to process information, scheduler data
    var task = pid_task(find_vpid(pid), PIDTYPE_PID)
    if (task == null) {
        return -ESRCH
    }
    
    // Access kernel scheduler information
    var cpu_usage = task.utime + task.stime
    var context_switches = task.nvcsw + task.nivcsw
    
    // Log to kernel performance subsystem
    return perf_event_record_syscall(task, syscall_nr, bytes, duration, cpu_usage, context_switches)
}

// Kernel-shared function for measuring write time
@helper
fn measure_write_time() -> u64 {
    return bpf_ktime_get_ns()
}

@probe("sys_read")
fn perf_monitor(fd: u32, buf: *u8, count: usize) -> i32 {
    var pid = bpf_get_current_pid_tgid() as u32
    var call_info = CallInfo {
        start_time: bpf_ktime_get_ns(),
        bytes_requested: count,  // Use actual parameter instead of ctx.arg_u32(2)
        file_descriptor: fd,     // Access file descriptor directly
    }
    
    active_calls[pid] = call_info
    return 0
}

@kretprobe("sys_read")
fn perf_monitor_return(ret_value: isize) -> i32 {
    var pid = bpf_get_current_pid_tgid() as u32
    
    var call_info = active_calls[pid]
    if (call_info != null) {
        var duration = bpf_ktime_get_ns() - call_info.start_time
        read_stats[pid % 1024] += duration
        
        // Use actual return value and kfunc for detailed analysis and logging
        analyze_syscall_performance(pid, __NR_read, call_info.bytes_requested, duration)
        
        // Log if the syscall failed (negative return value)
        if (ret_value < 0) {
            print("sys_read failed with error: %d", ret_value)
        }
        
        delete active_calls[pid]
    }
    
    return 0
}

@probe("sys_write")
fn write_monitor(fd: u32, buf: *u8, count: usize) -> i32 {
    var pid = bpf_get_current_pid_tgid() as u32
    var duration = measure_write_time()  // No context needed
    write_stats[pid % 1024] += duration
    
    // Log write operation with actual parameters
    if (count > 0) {
        print("Process %d writing %d bytes to fd %d", pid, count, fd)
    }
    
    return 0
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
    
    var interval = if (args.interval_ms == 0) { 5000 } else { args.interval_ms }
    var show_details = (args.show_details == 1)
    
    // Explicit program lifecycle management for multiple programs
    var read_handle = load(perf_monitor)
    var read_ret_handle = load(perf_monitor_return)
    var write_handle = load(write_monitor)
    
    // Attach programs to different kprobe targets
    var read_attach = attach(read_handle, "sys_read", 0)
    var read_ret_attach = attach(read_ret_handle, "sys_read", 0)
    var write_attach = attach(write_handle, "sys_write", 0)
    
    if (read_attach != 0 || read_ret_attach != 0 || write_attach != 0) {
        print("Failed to attach monitoring programs")
        return 1
    }
    
    print("Performance monitoring active - read and write syscalls with advanced kfunc analysis")
    
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
    var total_read_time = 0u64
    var total_write_time = 0u64
    
    for (i in 0..1024) {
        total_read_time += read_stats[i]
        total_write_time += write_stats[i]
    }
    
    print("Total read time: ", total_read_time)
    print("Total write time: ", total_write_time)
}
```

## 15. Complete Formal Grammar (EBNF)

```ebnf
(* KernelScript Complete Grammar *)

(* Top-level structure *)
kernelscript_file = { global_declaration } 

global_declaration = config_declaration | map_declaration | type_declaration | 
                    function_declaration | struct_declaration | impl_declaration |
                    global_variable_declaration | bindings_declaration | import_declaration 

(* Map declarations - global scope *)
map_declaration = [ "pin" ] [ "@flags" "(" flag_expression ")" ] "var" identifier ":" map_type "<" key_type "," value_type ">" "(" map_config ")"

map_type = "hash" | "array" | "percpu_hash" | "percpu_array" | "lru_hash" 

map_config = integer_literal [ "," map_config_item { "," map_config_item } ] 
map_config_item = identifier "=" literal 

flag_expression = identifier | ( identifier { "|" identifier } ) 

(* eBPF program function attributes *)
attribute_list = attribute { attribute }
attribute = "@" attribute_name [ "(" attribute_args ")" ]
attribute_name = "xdp" | "tc" | "kprobe" | "tracepoint" |
                 "struct_ops" | "kfunc" | "helper" | "private" | "test"
attribute_args = string_literal | identifier 

(* Named configuration declarations *)
config_declaration = "config" identifier "{" { config_field } "}" 
config_field = identifier ":" type_annotation [ "=" expression ] ","

(* Global variable declarations *)
global_variable_declaration = [ "pin" ] [ "local" ] "var" identifier [ ":" type_annotation ] [ "=" expression ]

(* Pinning restrictions:
   - "pin local var" is a compilation error - local variables cannot be pinned
   - Only shared variables (without "local") can be pinned
   - Pinned variables are automatically shared between kernel and userspace
   - Compiler generates a struct containing all pinned variables and uses a single-entry map
*) 

(* Scoping rules for KernelScript:
   - Attributed functions (e.g., @xdp, @tc, @tracepoint): Kernel space (eBPF) - compiles to eBPF bytecode
   - Regular functions: User space - compiles to native executable  
   - Maps, global configs, and global variables: Shared between both kernel and user space
   
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
function_declaration = [ attribute_list ] [ visibility ] [ "kernel" ] "fn" identifier "(" parameter_list ")" 
                       [ return_type_spec ] "{" statement_list "}"

(* Return type specification - supports both unnamed and named return values *)
return_type_spec = "->" type_annotation                        (* Unnamed: fn() -> u64 *)
                 | "->" identifier ":" type_annotation          (* Named: fn() -> result: u64 *)

impl_declaration = [ attribute_list ] "impl" identifier "{" impl_body "}"
impl_body = { impl_function }
impl_function = "fn" identifier "(" parameter_list ")" [ return_type_spec ] "{" statement_list "}" 

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

declaration_statement = "var" identifier [ ":" type_annotation ] "=" expression 

if_statement = "if" "(" expression ")" "{" statement_list "}" 
               { "else" "if" "(" expression ")" "{" statement_list "}" }
               [ "else" "{" statement_list "}" ] 

for_statement = "for" "(" identifier "in" expression ".." expression ")" "{" statement_list "}" |
                "for" "(" identifier "," identifier ")" "in" expression "{" statement_list "}" 

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

(* Pointer operations:
   * "*" = dereference operator (access value through pointer)
   * "&" = address-of operator (take address of value)
   * "->" = arrow operator for struct field access through pointer (in field_access)
*)

primary_expression = config_access | identifier | literal | function_call | field_access | 
                     array_access | parenthesized_expression | struct_literal | match_expression 

config_access = identifier "." identifier 

function_call = identifier "(" argument_list ")" 
argument_list = [ expression { "," expression } ] 

field_access = primary_expression ("." identifier | "->" identifier)
array_access = primary_expression "[" expression "]" 
parenthesized_expression = "(" expression ")" 

struct_literal = identifier "{" struct_literal_field { "," struct_literal_field } [ "," ] "}" 
struct_literal_field = identifier ":" expression 

match_expression = "match" "(" expression ")" "{" match_arm { "," match_arm } [ "," ] "}"
match_arm = match_pattern ":" expression
match_pattern = integer_literal | identifier | "default" 

(* Type annotations *)
type_annotation = primitive_type | compound_type | identifier 

primitive_type = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | 
                 "bool" | "char" | "void" | "ProgramRef" | string_type 

compound_type = array_type | pointer_type | function_type 

string_type = "str" "(" integer_literal ")" 

array_type = "[" type_annotation "" integer_literal "]" 
pointer_type = "*" type_annotation 
function_type = "fn" "(" [ type_annotation { "," type_annotation } ] ")" [ return_type_spec ] 

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

(* Import declarations - unified syntax for KernelScript and external languages *)
import_declaration = "import" identifier "from" string_literal 

(* Examples:
   import utils from "./common/utils.ks"          // KernelScript import
   import ml_analysis from "./ml/threat.py"       // Python import (userspace only)
   
   Import behavior is determined by file extension:
   - .ks files: Import KernelScript symbols (functions, types, maps, configs)  
   - .py files: Import Python functions with automatic FFI bridging (userspace only)
*) 

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
- Global maps, types, configs, and functions (both kernel and userspace)

**Function Structure:**
- `function_declaration` defines functions with optional attributes
- Functions with attributes (e.g., `@xdp`, `@tc`, `@tracepoint`) are eBPF programs
- Functions without attributes are userspace functions
- `@helper` functions are shared across all eBPF programs

**Scoping Rules:**
- **Global scope**: Maps, types, configs, and all function declarations
- **Function scope**: Variables and parameters within functions
- **Kernel scope**: `@helper` functions accessible to all eBPF programs
- **Userspace scope**: Regular functions (no attributes, no `kernel` qualifier)

This specification provides a comprehensive foundation for KernelScript while addressing the concerns about template complexity and userspace integration. The simplified type system avoids complex template metaprograming while still providing safety, and the top-level userspace section enables seamless coordination of multiple eBPF programs with centralized control plane management.
