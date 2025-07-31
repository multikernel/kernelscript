![KernelScript Logo](logo.png)

# KernelScript

> **⚠️ Beta Version Notice**
> KernelScript is currently in beta development. The language syntax, APIs, and features are subject to change at any time without backward compatibility guarantees. This software is intended for experimental use and early feedback. Production use is not recommended at this time.

**A Domain-Specific Programming Language for eBPF-Centric Development**

KernelScript is a modern, type-safe, domain-specific programming language that unifies eBPF, userspace, and kernelspace development in a single codebase. Built with an eBPF-centric approach, it provides a clean, readable syntax while generating efficient C code for eBPF programs, coordinated userspace programs, and seamless kernel module (kfunc) integration.

KernelScript aims to become the programming language for Linux kernel customization and application-specific optimization. By leveraging kfunc and eBPF capabilities, it provides a modern alternative to traditional kernel module interfaces such as procfs and debugfs.

## Why KernelScript?

### The Problem with Current eBPF Development

Writing eBPF programs today is challenging and error-prone:

- **Raw C + libbpf**: Requires deep eBPF knowledge, verbose boilerplate, manual memory management, and complex build systems
- **Kernel development complexity**: Understanding verifier constraints, BPF helper functions, and kernel APIs
- **Complex tail call management**: Manual program array setup, explicit `bpf_tail_call()` invocation, and error handling for failed tail calls
- **Intricate dynptr APIs**: Manual management of `bpf_ringbuf_reserve_dynptr()`, `bpf_dynptr_data()`, `bpf_dynptr_write()`, and proper cleanup sequences
- **Complex struct_ops implementation**: Manual function pointer setup, intricate BTF type registration, kernel interface compliance, and lifecycle management
- **Complex kfunc implementation**: Manual kernel module creation, BTF symbol registration, export management, and module loading coordination
- **Userspace coordination**: Manually writing loaders, map management, and program lifecycle code
- **Multi-program systems**: No coordination between related eBPF programs sharing resources

### Why Not Existing Tools?

**Why not Rust?**
- **Mixed compilation targets**: Rust's crate-wide, single-target compilation model cannot emit both eBPF bytecode and userspace binaries from one source file. KernelScript's `@xdp`, `@tc`, and regular functions compile to different targets automatically
- **No first-class eBPF program values**: Rust lacks compile-time reflection to treat functions as values with load/attach lifecycle guarantees. KernelScript's type system prevents calling `attach()` before `load()` succeeds
- **Cross-domain shared maps**: Rust's visibility and orphan rules conflict with KernelScript's implicit map sharing across programs. Safe userspace APIs for BPF maps require complex build-time generation in Rust
- **Verifier-incompatible features**: Rust's generics and complex type system often produce code rejected by the eBPF verifier. KernelScript uses fixed-width arrays (`u8[64]`) and simplified types designed for verifier compatibility
- **Error handling mismatch**: Rust's `Result<T,E>` model doesn't align with eBPF's C-style integer error codes. KernelScript's throw/catch works seamlessly in both userspace and eBPF contexts
- **Missing eBPF-specific codegen**: Rust/LLVM cannot automatically generate BPF tail calls or kernel module code for `@kfunc` attributes - features that require deep compiler integration

**Why not bpftrace?**
- Domain-specific for tracing only (no XDP, TC, etc.)
- Limited programming constructs (no complex data structures, functions)
- Interpreted at runtime rather than compiled
- No support for multi-program coordination

**Why not Python/Go eBPF libraries?**
- Still require writing eBPF programs in C
- Only handle userspace coordination, not the eBPF programs themselves
- Complex build systems and dependency management

### KernelScript's Solution

KernelScript addresses these problems through revolutionary language features:

✅ **Single-file multi-target compilation** - Write userspace, eBPF, and kernel module code in one file. The compiler automatically targets each function correctly based on attributes (`@xdp`, `@helper`, regular functions)

✅ **Automatic tail call orchestration** - Simply write `return other_xdp_func(ctx)` and the compiler handles program arrays, `bpf_tail_call()` generation, and error handling automatically

✅ **Transparent dynptr integration** - Use simple pointer operations (`event_log.reserve()`, `buffer[index]`) while the compiler automatically uses complex dynptr APIs (`bpf_ringbuf_reserve_dynptr`, `bpf_dynptr_write`) behind the scenes

✅ **First-class program lifecycle safety** - Programs are typed values with compile-time guarantees that prevent calling `attach()` before `load()` succeeds

✅ **Zero-boilerplate shared state** - Global maps and config blocks are automatically accessible across all programs without imports, exports, or coordination code

✅ **Custom kernel functions (@kfunc)** - Write full-privilege kernel functions that eBPF programs can call, automatically generating kernel modules and BTF registrations

✅ **Unified error handling** - C-style integer throw/catch works seamlessly in both eBPF and userspace contexts, unlike complex Result types

✅ **Verifier-optimized type system** - Fixed-size arrays (`u8[64]`), simple type aliases, and no complex generics that confuse the eBPF verifier

✅ **Complete automated toolchain** - Generate ready-to-use projects with Makefiles, userspace loaders, and build systems from a single source file  

## Language Overview

### Program Types and Contexts

KernelScript supports all major eBPF program types with typed contexts:

```kernelscript
// XDP program for packet processing
@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
    var packet_size = ctx->data_end - ctx->data
    if (packet_size > 1500) {
        return XDP_DROP
    }
    return XDP_PASS
}

// TC program for traffic control
@tc fn traffic_shaper(ctx: *__sk_buff) -> i32 {
    if (ctx->len > 1000) {
        return TC_ACT_SHOT  // Drop large packets
    }
    return TC_ACT_OK
}

// Kprobe for kernel function tracing
@kprobe fn trace_syscall(ctx: *pt_regs) -> i32 {
    // Trace system call entry
    return 0
}
```

### Type System

KernelScript has a rich type system designed for systems programming:

```kernelscript
// Type aliases for clarity
type IpAddress = u32
type Counter = u64
type PacketSize = u16

// Struct definitions
struct PacketInfo {
    src_ip: IpAddress,
    dst_ip: IpAddress,
    protocol: u8,
    size: PacketSize
}

// Enums for constants
enum FilterAction {
    ALLOW = 0,
    BLOCK = 1,
    LOG = 2
}
```

### Maps and Data Structures

Built-in support for all eBPF map types:

```kernelscript
// Pinned maps persist across program restarts
pin var connection_count : hash<IpAddress, Counter>(1024)

// Per-CPU maps for better performance
var cpu_stats : percpu_array<u32, u64>(256)

// LRU maps for automatic eviction
var recent_packets : lru_hash<IpAddress, PacketInfo>(1000)

```

### Functions and Helpers

Clean function syntax with helper function support:

```kernelscript
// Helper functions for eBPF programs
@helper
fn extract_src_ip(ctx: *xdp_md) -> IpAddress {
    // Packet parsing logic
    return 0x7f000001  // 127.0.0.1
}

// Regular functions
fn update_stats(ip: IpAddress, size: PacketSize) {
    connection_count[ip] = connection_count[ip] + 1
}

// Function pointers for callbacks
type PacketHandler = fn(PacketInfo) -> FilterAction

fn process_packet(info: PacketInfo, handler: PacketHandler) -> FilterAction {
    return handler(info)
}
```

### Pattern Matching and Control Flow

Modern control flow with pattern matching:

```kernelscript
// Pattern matching on enums
fn handle_action(action: FilterAction) -> xdp_action {
    return match (action) {
        ALLOW: XDP_PASS,
        BLOCK: XDP_DROP,
        LOG: {
            // Log and allow
            event_log[0] = 1
            XDP_PASS
        }
    }
}

// Truthy/falsy patterns for maps
fn lookup_or_create(ip: IpAddress) -> Counter {
    var count = connection_count[ip]
    if (count != none) {
        return count  // Entry exists
    } else {
        connection_count[ip] = 1  // Create new entry
        return 1
    }
}
```

### Multi-Program Coordination

KernelScript can coordinate multiple eBPF programs:

```kernelscript
// Shared map between programs
pin var shared_counter : hash<u32, u32>(1024)

// XDP program increments counter
@xdp fn packet_counter(ctx: *xdp_md) -> xdp_action {
    shared_counter[1] = shared_counter[1] + 1
    return XDP_PASS
}

// TC program reads counter
@tc fn packet_reader(ctx: *__sk_buff) -> int {
    var count = shared_counter[1]
    if (count > 1000) {
        return TC_ACT_SHOT  // Rate limiting
    }
    return TC_ACT_OK
}

// Userspace coordination
fn main() -> i32 {
    var xdp_prog = load(packet_counter)
    var tc_prog = load(packet_reader)
    
    attach(xdp_prog, "eth0", 0)
    attach(tc_prog, "eth0", 0)
    
    return 0
}
```

📖 **For detailed language specification, syntax reference, and advanced features, please read [`SPEC.md`](SPEC.md).**

## Command Line Usage

### Initialize a New Project

Create a new KernelScript project with template code:

```bash
# Create XDP project
kernelscript init xdp my_packet_filter

# Create TC project  
kernelscript init tc my_traffic_shaper

# Create kprobe project
kernelscript init kprobe/sys_read my_tracer

# Create project with custom BTF path
kernelscript init --btf-vmlinux-path /custom/path/vmlinux xdp my_project

# Create struct_ops project
kernelscript init tcp_congestion_ops my_congestion_control
```

After initialization, you get:

```
my_project/
├── my_project.ks          # Generated KernelScript source without user code
└── README.md              # Usage instructions
```

**Available program types:**
- `xdp` - XDP programs for packet processing
- `tc` - Traffic control programs  
- `kprobe` - Kernel function tracing
- `tracepoint` - Kernel tracepoint programs

**Available struct_ops:**
- `tcp_congestion_ops` - TCP congestion control


### Compile KernelScript Programs

Compile `.ks` files to eBPF C code and userspace programs:

```bash
# Basic compilation
kernelscript compile my_project/my_project.ks

# Specify output directory
kernelscript compile my_project/my_project.ks -o my_output_dir
kernelscript compile my_project/my_project.ks --output my_output_dir

# Verbose compilation
kernelscript compile my_project/my_project.ks -v
kernelscript compile my_project/my_project.ks --verbose

# Don't generate Makefile
kernelscript compile my_project/my_project.ks --no-makefile

# Also generates tests and only @test functions become main
kernelscript compile --test my_project/my_project.ks

# Custom BTF path
kernelscript compile my_project/my_project.ks --btf-vmlinux-path /custom/path/vmlinux
```

### Complete Project Structure

After compilation, you get a complete project:

```
my_project/
├── my_project.ks          # KernelScript source
├── my_project.c           # Generated userspace program
├── my_project.ebpf.c      # Generated eBPF C code
├── my_project.mod.c       # Generated kernel module (when any kfunc exists)
├── my_project.test.c      # Generated test run code (when using --test mode)
├── Makefile               # Build system
└── README.md              # Usage instructions
```

### Build and Run

```bash
cd my_project/
make                       # Build both eBPF and userspace programs
sudo ./my_project          # Run the program
```

## Getting Started

1. **Install system dependencies (Debian/Ubuntu):**
   ```bash
   sudo apt update
   sudo apt install libbpf-dev libelf-dev zlib1g-dev
   ```

2. **Install KernelScript:**
   ```bash
   git clone https://github.com/multikernel/kernelscript.git
   cd kernelscript
   opam install . --deps-only
   eval $(opam env) && dune build && dune install
   ```

3. **Create your first project:**
   ```bash
   kernelscript init xdp hello_world
   cd hello_world/
   ```

4. **Edit the generated code:**
   ```bash
   # Edit hello_world.ks with your logic
   vim hello_world.ks
   ```

5. **Compile and run:**
   ```bash
   kernelscript compile hello_world/hello_world.ks
   cd hello_world/
   make
   sudo ./hello_world
   ```

## Examples

The `examples/` directory contains comprehensive examples:

- `packet_filter.ks` - Basic XDP packet filtering
- `multi_programs.ks` - Multiple coordinated programs
- `maps_demo.ks` - All map types and operations
- `functions.ks` - Function definitions and calls
- `types_demo.ks` - Type system features
- `error_handling_demo.ks` - Error handling patterns

## Why Choose KernelScript?

| Feature | Raw C + libbpf | Rust eBPF | bpftrace | **KernelScript** |
|---------|---------------|-----------|----------|------------------|
| **Syntax** | Complex C | Complex Rust | Simple but limited | Clean & readable |
| **Type Safety** | Manual | Yes | Limited | Yes |
| **Multi-program** | Manual | Manual | No | Automatic |
| **Build System** | Manual Makefiles | Cargo complexity | N/A | Generated |
| **Userspace Code** | Manual | Manual | N/A | Generated |
| **Learning Curve** | Steep | Steep | Easy but limited | Moderate |
| **Program Types** | All | Most | Tracing only | All |

KernelScript combines the power of low-level eBPF programming with the productivity of modern programming languages, making eBPF development accessible to a broader audience while maintaining the performance and flexibility that makes eBPF powerful.

## License

Copyright 2025 Multikernel Technologies, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Contributing

By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0.