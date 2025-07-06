// Map Operations Semantics Demo for KernelScript
// Demonstrates advanced map operation analysis, concurrent access safety,
// and global map sharing validation capabilities
//
// NOTE: This file uses advanced language features not yet implemented in KernelScript.

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
pin map<u32, u64> global_counter : HashMap(10000)

// Statistics map with read-only flags
@flags(rdonly) pin map<u32, Statistics> shared_stats : HashMap(1000)

// Per-CPU data with automatic pinning path: /sys/fs/bpf/map_operations_demo/maps/percpu_data  
pin map<u32, PerCpuData> percpu_data : PercpuHash(256)

// Event stream ring buffer with no preallocation flag
@flags(no_prealloc) pin map<u32, u32> event_stream : RingBuffer(65536)

// Sequential data array - not pinned (local to program)
map<u32, ArrayElement> sequential_data : Array(1024)

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
    var key = ctx->ingress_ifindex()
    
    // Safe concurrent read access - multiple programs can read simultaneously
    var counter = global_counter[key]
    if (counter != null) {
        // High-frequency lookup pattern - will generate optimization suggestions
        for (i in 0..100) {
            var _ = global_counter[key + i]
        }
    } else {
        // Initialize counter for new interface
        global_counter[key] = 1
    }
    
    // Per-CPU access for maximum performance
    var cpu_id = bpf_get_smp_processor_id()
    var data = percpu_data[cpu_id]
    if (data != null) {
        data.local_counter += 1
        percpu_data[cpu_id] = data
    } else {
        var new_data = PerCpuData {
            local_counter: 1,
            temp_storage: [0; 64],
        }
        percpu_data[cpu_id] = new_data
    }
    
    return XDP_PASS
}

// Program 2: Writer workload demonstrating conflict detection
@tc fn stats_updater(ctx: TcContext) -> TcAction {
    var ifindex = ctx->ifindex()
    
    // Potential write conflict with other programs
    var stats = shared_stats[ifindex]
    if (stats == null) {
        stats = Statistics {
            packet_count: 0,
            byte_count: 0,
            last_seen: 0,
            error_rate: 0,
        }
    }
    
    // Update statistics - this creates a write operation
    stats.packet_count += 1
    stats.byte_count += ctx->data_len()
    stats.last_seen = bpf_ktime_get_ns()
    
    // Calculate error rate (simplified)
    if (ctx->protocol() == 0) {
        stats.error_rate += 1
    }
    
    shared_stats[ifindex] = stats
    
    // Batch operation pattern - will be detected as batch access
    for (i in 0..20) {
        var batch_key = ifindex + i
        var entry = shared_stats[batch_key]
        if (entry != null) {
            entry.packet_count += 1
            shared_stats[batch_key] = entry
        }
    }
    
    return TC_ACT_OK
}

// Program 3: Event streaming demonstrating ring buffer usage
@tracepoint fn event_logger(ctx: TracepointContext) -> i32 {
    var event = Event {
        timestamp: bpf_ktime_get_ns(),
        event_type: ctx->event_id(),
        data: [0; 32],  // Simplified data
    }
    
    // Ring buffer output - single writer recommended
    match event_stream.output(&event, sizeof(Event)) {
        Ok(_) => {},
        Err(_) => {
            // Ring buffer full - this will generate performance warnings
            return -1
        }
    }
    
    return 0
}

// Program 4: Sequential access pattern demonstration
@kprobe fn data_processor(ctx: KprobeContext) -> i32 {
    // Sequential access pattern - will be detected and optimized
    for (i in 0..32) {
        var element = sequential_data[i]
        if (element != null) {
            if (!element.processed) {
                element.value = element.value * 2
                element.processed = true
                sequential_data[i] = element
            }
        } else {
            var new_element = ArrayElement {
                value: i as u64,
                processed: false,
            }
            sequential_data[i] = new_element
        }
    }
    
    return 0
}

// Configuration for map operation analysis
config {
    analysis: {
        // Enable map operation semantics analysis
        map_operations: true,
        
        // Concurrent access safety checking
        concurrency_analysis: true,
        
        // Performance profiling
        performance_profiling: true,
        
        // Access pattern detection
        pattern_detection: true,
        
        // Global map sharing validation
        sharing_validation: true,
    },
    
    optimization: {
        // Suggest optimizations for access patterns
        access_pattern_hints: true,
        
        // Recommend better map types
        map_type_suggestions: true,
        
        // Batch operation optimization
        batch_optimization: true,
        
        // Memory usage optimization
        memory_optimization: true,
    }
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
    
    return 0
}

//
// Expected Analysis Results:
//
// 1. Access Pattern Analysis:
//    - traffic_monitor: High-frequency random access (100 lookups)
//    - stats_updater: Batch access pattern (20 operations)
//    - data_processor: Sequential access pattern (0-31)
//    - event_logger: Streaming pattern (ring buffer)
//
// 2. Concurrent Access Safety:
//    - global_counter: SAFE (multiple readers, single writer per key)
//    - shared_stats: WRITE_LOCKED (multiple programs writing)
//    - percpu_data: SAFE (per-CPU isolation)
//    - event_stream: SAFE (single writer recommended)
//
// 3. Global Map Sharing Validation:
//    - global_counter: VALID (reader-heavy workload)
//    - shared_stats: CONFLICT (multiple writers detected)
//    - Recommendations: Use per-CPU maps or synchronization
//
// 4. Performance Recommendations:
//    - High-frequency access detected in traffic_monitor
//    - Consider caching for frequently accessed keys
//    - Sequential access in data_processor could use array map
//    - Batch operations detected - consider batch helpers
//
// 5. Optimization Suggestions:
//    - Convert sequential_data to array map type
//    - Use LRU eviction for shared_stats under memory pressure
//    - Consider read-only maps for static configuration data
//    - Implement proper error handling for ring buffer overflow
// 