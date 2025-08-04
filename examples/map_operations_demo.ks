// Map Operations Semantics Demo for KernelScript
// Demonstrates advanced map operation analysis, concurrent access safety,
// and global map sharing validation capabilities
//
// NOTE: This file uses advanced language features not yet implemented in KernelScript.

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

// TC context struct (from BTF)
struct __sk_buff {
  data: u64,
  data_end: u64,
  len: u32,
  ifindex: u32,
  protocol: u32,
  mark: u32,
}

// TC action constants
enum tc_action {
  TC_ACT_UNSPEC = 255,
  TC_ACT_OK = 0,
  TC_ACT_RECLASSIFY = 1,
  TC_ACT_SHOT = 2,
  TC_ACT_PIPE = 3,
  TC_ACT_STOLEN = 4,
  TC_ACT_QUEUED = 5,
  TC_ACT_REPEAT = 6,
  TC_ACT_REDIRECT = 7,
}

// Base trace entry struct
struct trace_entry {
  entry_type: u16,
  flags: u8,
  preempt_count: u8,
  pid: i32,
}

// Tracepoint context struct (from BTF) - sys_enter structure
struct trace_event_raw_sys_enter {
  ent: trace_entry,
  id: i64,
  args: u64[6],
}

// This example demonstrates comprehensive map operations with multi-program analysis
// It shows various access patterns and concurrent access scenarios

// Type definitions for complex data structures
struct Statistics {
    packet_count: u64,
    byte_count: u64,
    last_seen: u64,
    error_rate: u32,
}

struct PerCpuData {
    local_counter: u64,
    temp_storage: u8[64],
}

// Global maps shared across multiple programs with the new simplified syntax

// Global counter with automatic path: /sys/fs/bpf/map_operations_demo/maps/global_counter
pin var global_counter : hash<u32, u64>(10000)

// Statistics map with read-only flags
@flags(rdonly) pin var shared_stats : hash<u32, Statistics>(1000)

// Per-CPU data with automatic pinning path: /sys/fs/bpf/map_operations_demo/maps/percpu_data  
pin var percpu_data : percpu_hash<u32, PerCpuData>(256)

// Event stream ring buffer
var event_stream : ringbuf<Event>(65536)

// Sequential data array - not pinned (local to program)
var sequential_data : array<u32, ArrayElement>(1024)

struct Event {
    timestamp: u64,
    event_type: u32,
    data: u8[32],
}

struct ArrayElement {
    value: u64,
    processed: bool,
}

// Program 1: Reader-heavy workload demonstrating safe concurrent access
@xdp fn traffic_monitor(ctx: *xdp_md) -> xdp_action {
    var key = ctx->ingress_ifindex
    
    // Safe concurrent read access - multiple programs can read simultaneously
    var counter = global_counter[key]
    if (counter != none) {
        // High-frequency lookup pattern - will generate optimization suggestions
        for (i in 0..100) {
            var _ = global_counter[key + i]
        }
    } else {
        // Initialize counter for new interface
        global_counter[key] = 1
    }
    
    // Per-CPU access for maximum performance
    var cpu_id = 0
    var data = percpu_data[cpu_id]
    if (data != none) {
        data.local_counter = data.local_counter + 1
        percpu_data[cpu_id] = data
    } else {
        var new_data = PerCpuData {
            local_counter: 1,
            temp_storage: [0],
        }
        percpu_data[cpu_id] = new_data
    }
    
    return XDP_PASS
}

// Program 2: Writer workload demonstrating conflict detection
@tc fn stats_updater(ctx: *__sk_buff) -> i32 {
    var ifindex = ctx->ifindex
    
    // Potential write conflict with other programs
    var stats = shared_stats[ifindex]
    if (stats == none) {
        stats = Statistics {
            packet_count: 0,
            byte_count: 0,
            last_seen: 0,
            error_rate: 0,
        }
    }
    
    // Update statistics - this creates a write operation
    stats.packet_count = stats.packet_count + 1
    stats.byte_count = stats.byte_count + ctx->len
    stats.last_seen = 123456 // Fake timestamp
    
    // Calculate error rate (simplified)
    if (ctx->protocol == 0) {
        stats.error_rate = stats.error_rate + 1
    }
    
    shared_stats[ifindex] = stats
    
    // Batch operation pattern - will be detected as batch access
    for (i in 0..20) {
        var batch_key = ifindex + i
        var entry = shared_stats[batch_key]
        if (entry != null) {
            entry.packet_count = entry.packet_count + 1
            shared_stats[batch_key] = entry
        }
    }
    
    return TC_ACT_OK
}

// Program 3: Event streaming demonstrating ring buffer usage
@tracepoint("syscalls/sys_enter_open")
fn event_logger(ctx: *trace_event_raw_sys_enter) -> i32 {
    // Ring buffer output - single writer recommended
    try {
        // Reserve space in the ring buffer
        var reserved = event_stream.reserve()
        if (reserved != null) {
            // Successfully reserved space - populate event data inline
            reserved->timestamp = 123456  // Fake timestamp
            reserved->event_type = ctx->id  // Use syscall ID from sys_enter context
            reserved->data = [0]  // Simplified data

            // Submit the populated event
            event_stream.submit(reserved)
        } else {
            throw 1  // Ring buffer is full
        }
    } catch 1 {
        // Ring buffer full - this will generate performance warnings
        return -1
    }
    
    return 0
}

// Program 4: Sequential access pattern demonstration
@probe("vfs_read")
fn data_processor(file: *file, buf: *u8, count: usize, pos: *i64) -> i32 {
    // Sequential access pattern - will be detected and optimized
    for (i in 0..32) {
        var element = sequential_data[i]
        if (element != none) {
            if (!element.processed) {
                element.value = element.value * 2
                element.processed = true
                sequential_data[i] = element
            }
        } else {
            var new_element = ArrayElement {
                value: i,
                processed: false,
            }
            sequential_data[i] = new_element
        }
    }
    
    return 0
}

fn main() -> i32 {
    var prog1 = load(traffic_monitor)
    var prog2 = load(stats_updater)
    var prog3 = load(event_logger)
    var prog4 = load(data_processor)
    
    attach(prog1, "eth0", 0)
    attach(prog2, "eth0", 0)
    attach(prog3, "sys_enter_open", 0)
    attach(prog4, "vfs_read", 0)
    
    print("Map operations demo: All programs attached")
    print("Traffic monitor & stats on eth0, event logger on sys_enter_open, data processor on vfs_read")
    print("Demonstrating coordinated map operations...")
    
    // Detach in reverse order
    detach(prog4)
    detach(prog3)
    detach(prog2)
    detach(prog1)
    print("All map operation demo programs detached")
    
    return 0
}