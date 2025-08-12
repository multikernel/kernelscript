# KernelScript Builtin Functions Reference

This document provides a comprehensive reference for all builtin functions available in KernelScript. These functions are context-aware and translate differently depending on the execution environment (eBPF, userspace, or kernel module).

## Overview

KernelScript builtin functions provide essential functionality across different execution contexts:
- **eBPF Context**: Functions available within eBPF programs running in kernel space
- **Userspace Context**: Functions available in userspace programs that manage eBPF programs
- **Kernel Module Context**: Functions available when compiling to kernel modules

## Builtin Functions by Category

### 1. Input/Output Functions

#### `print(...)`
**Signature:** `print(...) -> u32`
**Variadic:** Yes (accepts any number of arguments)
**Context:** All contexts

**Description:** Print formatted output to the appropriate output stream based on context.

**Context-specific implementations:**
- **eBPF:** Uses `bpf_printk` to write to kernel trace log (limited to format string + 3 arguments)
- **Userspace:** Uses `printf` to write to console/stdout
- **Kernel Module:** Uses `printk` to write to kernel log

**Parameters:**
- Variable number of arguments of any type
- First argument typically used as format string in userspace/kernel contexts

**Return Value:**
- Returns `0` on success (like standard printf family)
- Returns error code on failure

**Examples:**
```kernelscript
print("Hello, world!")
print("Value:", 42)
print("Multiple values:", x, y, z)
```

**Notes:**
- In eBPF context, limited to 4 total arguments due to `bpf_printk` restrictions
- Automatically handles type conversion for different contexts

---

### 2. Program Lifecycle Management

#### `load(function)`
**Signature:** `load(function) -> ProgramHandle`
**Variadic:** No
**Context:** Userspace only

**Description:** Load an eBPF program function and return a handle for subsequent operations.

**Parameters:**
- `function`: Any function with eBPF attributes (`@xdp`, `@kprobe`, `@tracepoint`, etc.)

**Return Value:**
- Returns a `ProgramHandle` that can be used with `attach()` and `detach()`
- Handle represents the loaded eBPF program file descriptor

**Examples:**
```kernelscript
@xdp
fn my_xdp_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}

fn main() -> i32 {
    var prog = load(my_xdp_program)
    // Use prog with attach()
    return 0
}
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `bpf_prog_load` system call
- **Kernel Module:** Not available

---

#### `attach(handle, target, flags)`
**Signature:** `attach(handle: ProgramHandle, target: str(128), flags: u32) -> u32`
**Variadic:** No
**Context:** Userspace only

**Description:** Attach a loaded eBPF program to a target interface or attachment point.

**Parameters:**
- `handle`: Program handle returned from `load()`
- `target`: Target interface name (e.g., "eth0", "lo") or attachment point
- `flags`: Attachment flags (context-dependent)

**Return Value:**
- Returns `0` on success
- Returns error code on failure

**Examples:**
```kernelscript
var prog = load(my_xdp_program)
var result = attach(prog, "eth0", 0)
if (result != 0) {
    print("Failed to attach program")
}
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `bpf_prog_attach` system call
- **Kernel Module:** Not available

---

#### `detach(handle)`
**Signature:** `detach(handle: ProgramHandle) -> void`
**Variadic:** No
**Context:** Userspace only

**Description:** Detach a loaded eBPF program from its current attachment point.

**Parameters:**
- `handle`: Program handle returned from `load()`

**Return Value:**
- No return value (void)

**Examples:**
```kernelscript
var prog = load(my_xdp_program)
attach(prog, "eth0", 0)
// ... program runs ...
detach(prog)  // Clean up
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `detach_bpf_program_by_fd` function
- **Kernel Module:** Not available

---

### 3. Struct Operations (struct_ops)

#### `register(impl_instance)`
**Signature:** `register(impl_instance) -> u32`
**Variadic:** No
**Context:** Userspace only

**Description:** Register an implementation block instance with the kernel for struct_ops programs.

**Parameters:**
- `impl_instance`: Instance of a struct with `@struct_ops` attribute

**Return Value:**
- Returns `0` on success
- Returns error code on failure

**Validation:**
- Only accepts impl block instances with `@struct_ops` attribute
- Validates that the struct_ops type is known to the kernel
- Must be used with properly attributed implementation blocks

**Examples:**
```kernelscript
@struct_ops("tcp_congestion_ops")
impl TcpCongestion {
    // Implementation methods here
}

fn main() -> i32 {
    var tcp_impl = TcpCongestion {}
    var result = register(tcp_impl)
    return result
}
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `IRStructOpsRegister` instruction
- **Kernel Module:** Not available

---

### 4. Testing and Development

#### `test(program, test_data)`
**Signature:** `test(program, test_data) -> u32`
**Variadic:** No
**Context:** Userspace only (from `@test` functions only)

**Description:** Execute an eBPF program with test data and return the program's return value.

**Parameters:**
- `program`: eBPF program to test
- `test_data`: Test input data for the program

**Return Value:**
- Returns the program's return value
- Can be used to verify program behavior in tests

**Restrictions:**
- Can only be called from functions with the `@test` attribute
- Used for unit testing eBPF programs

**Examples:**
```kernelscript
@test
fn test_my_program() -> i32 {
    var result = test(my_xdp_program, test_packet_data)
    // Assert result == expected_value
    return result
}
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `bpf_prog_test_run` system call
- **Kernel Module:** Not available

---

### 5. Event Processing

#### `dispatch(...)`
**Signature:** `dispatch(ringbuf1, ringbuf2, ...) -> i32`
**Variadic:** Yes (accepts multiple ring buffer arguments)
**Context:** Userspace only

**Description:** Poll multiple ring buffers for events and dispatch them to their registered callbacks.

**Parameters:**
- Variable number of ring buffer arguments (RingbufRef or Ringbuf types)
- Each ring buffer should have associated event callbacks

**Return Value:**
- Returns `0` on success
- Returns error code on failure

**Validation:**
- All arguments must be ring buffer types
- Requires at least one ring buffer argument

**Examples:**
```kernelscript
var rb1: ringbuf<u32>(1024)
var rb2: ringbuf<u64>(2048)

fn main() -> i32 {
    // Poll both ring buffers for events
    var result = dispatch(rb1, rb2)
    return result
}
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `ring_buffer__poll` from libbpf
- **Kernel Module:** Not available

---

### 6. Process Management

#### `daemon()`
**Signature:** `daemon() -> void`
**Variadic:** No
**Context:** Userspace only

**Description:** Become a daemon process by detaching from the terminal and running in the background.

**Parameters:**
- No parameters

**Return Value:**
- Never returns in practice (process becomes daemon)
- Type system requires void return type

**Examples:**
```kernelscript
fn main() -> i32 {
    print("Starting daemon...")
    daemon()  // Process detaches from terminal
    // Code here runs as daemon
    return 0
}
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `daemon_builtin` custom implementation
- **Kernel Module:** Not available

---

#### `exec(python_script)`
**Signature:** `exec(python_script: str(256)) -> void`
**Variadic:** No
**Context:** Userspace only

**Description:** Replace the current process with a Python script, inheriting all eBPF maps and file descriptors.

**Parameters:**
- `python_script`: Path to Python script file (must have .py extension)

**Return Value:**
- Never returns (replaces current process)
- Type system requires void return type

**Validation:**
- Script path must be a string
- File suffix validation occurs during code generation
- Python script inherits eBPF program state

**Examples:**
```kernelscript
fn main() -> i32 {
    // Set up eBPF programs and maps
    var prog = load(my_program)
    attach(prog, "eth0", 0)
    
    // Hand off to Python for advanced processing
    exec("advanced_analysis.py")  // Never returns
}
```

**Context-specific implementations:**
- **eBPF:** Not available
- **Userspace:** Uses `exec_builtin` custom implementation
- **Kernel Module:** Not available

---

## Context Availability Summary

| Function | eBPF | Userspace | Kernel Module | Notes |
|----------|------|-----------|---------------|-------|
| `print()` | ✅ | ✅ | ✅ | Different output destinations |
| `load()` | ❌ | ✅ | ❌ | Program management only |
| `attach()` | ❌ | ✅ | ❌ | Program management only |
| `detach()` | ❌ | ✅ | ❌ | Program management only |
| `register()` | ❌ | ✅ | ❌ | struct_ops registration |
| `test()` | ❌ | ✅ | ❌ | Testing framework only |
| `dispatch()` | ❌ | ✅ | ❌ | Event processing only |
| `daemon()` | ❌ | ✅ | ❌ | Process management only |
| `exec()` | ❌ | ✅ | ❌ | Process replacement only |

## Related Concepts

### Helper Functions vs. Builtin Functions

- **Builtin Functions**: Defined by KernelScript, context-aware, part of the language
- **Helper Functions**: User-defined functions with `@helper` attribute, compiled as eBPF helpers
- **Kernel Functions (kfuncs)**: External kernel functions declared with `extern` or `@kfunc`

### External Functions

KernelScript also supports external kernel functions that can be declared and called:

```kernelscript
// External eBPF helper functions
extern bpf_ktime_get_ns() -> u64
extern bpf_trace_printk(fmt: *u8, fmt_size: u32) -> i32
extern bpf_get_current_pid_tgid() -> u64

// Usage in eBPF programs
@xdp
fn my_program(ctx: *xdp_md) -> xdp_action {
    var timestamp = bpf_ktime_get_ns()
    return XDP_PASS
}
```

### Error Handling

Most builtin functions return error codes where appropriate:
- `0`: Success
- Non-zero: Error (specific meaning depends on function)

Always check return values for functions that can fail:

```kernelscript
var result = attach(prog, "eth0", 0)
if (result != 0) {
    print("Failed to attach program, error:", result)
    return result
}
```

## See Also

- **SPEC.md**: Language specification and features
- **examples/**: Example programs demonstrating builtin function usage