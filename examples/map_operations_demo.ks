// Map Operations Semantics Demo for KernelScript
// Demonstrates advanced map operation analysis, concurrent access safety,
// and global map sharing validation capabilities
//
// NOTE: This file uses advanced language features not yet implemented in KernelScript.


// Global maps shared across programs
map<u32, u64> global_counter : HashMap(1000) {
    pinned: "/sys/fs/bpf/global_counter"
};

map<u32, Statistics> shared_stats : LruHash(500) {
    pinned: "/sys/fs/bpf/shared_stats"
};

// Per-CPU map for high-performance scenarios (using new block-less syntax)
map<u32, PerCpuData> percpu_data : PercpuHash(256);

// Ring buffer for event streaming (using new block-less syntax)
map<Event, ()> event_stream : RingBuffer(262144);  // 1MB buffer

// Array map for sequential access patterns (using new block-less syntax)
map<u32, ArrayElement> sequential_data : Array(128);

struct Statistics {
    packet_count: u64,
    byte_count: u64,
    last_seen: u64,
    error_rate: u32,
}

struct PerCpuData {
    local_counter: u64,
    temp_storage: [u8; 64],
}

struct Event {
    timestamp: u64,
    event_type: u32,
    data: [u8; 32],
}

struct ArrayElement {
    value: u64,
    processed: bool,
}

// Program 1: Reader-heavy workload demonstrating safe concurrent access
program traffic_monitor : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let key = ctx.ingress_ifindex();
        
        // Safe concurrent read access - multiple programs can read simultaneously
        match global_counter.lookup(&key) {
            Some(counter) => {
                // High-frequency lookup pattern - will generate optimization suggestions
                for i in 0..100 {
                    let _ = global_counter.lookup(&(key + i));
                }
            },
            None => {
                // Initialize counter for new interface
                global_counter.insert(&key, &1);
            }
        }
        
        // Per-CPU access for maximum performance
        let cpu_id = bpf_get_smp_processor_id();
        match percpu_data.lookup(&cpu_id) {
            Some(data) => {
                data.local_counter += 1;
                percpu_data.update(&cpu_id, data);
            },
            None => {
                let new_data = PerCpuData {
                    local_counter: 1,
                    temp_storage: [0; 64],
                };
                percpu_data.insert(&cpu_id, &new_data);
            }
        }
        
        return XdpAction::Pass;
    }
}

// Program 2: Writer workload demonstrating conflict detection
program stats_updater : tc {
    fn main(ctx: TcContext) -> TcAction {
        let ifindex = ctx.ifindex();
        
        // Potential write conflict with other programs
        let stats = match shared_stats.lookup(&ifindex) {
            Some(s) => s,
            None => Statistics {
                packet_count: 0,
                byte_count: 0,
                last_seen: 0,
                error_rate: 0,
            }
        };
        
        // Update statistics - this creates a write operation
        stats.packet_count += 1;
        stats.byte_count += ctx.data_len();
        stats.last_seen = bpf_ktime_get_ns();
        
        // Calculate error rate (simplified)
        if ctx.protocol() == 0 {
            stats.error_rate += 1;
        }
        
        shared_stats.update(&ifindex, &stats);
        
        // Batch operation pattern - will be detected as batch access
        for i in 0..20 {
            let batch_key = ifindex + i;
            match shared_stats.lookup(&batch_key) {
                Some(entry) => {
                    entry.packet_count += 1;
                    shared_stats.update(&batch_key, entry);
                },
                None => {}
            }
        }
        
        return TcAction::Ok;
    }
}

// Program 3: Event streaming demonstrating ring buffer usage
program event_logger : tracepoint {
    fn main(ctx: TracepointContext) -> i32 {
        let event = Event {
            timestamp: bpf_ktime_get_ns(),
            event_type: ctx.event_id(),
            data: [0; 32],  // Simplified data
        };
        
        // Ring buffer output - single writer recommended
        match event_stream.output(&event, sizeof(Event)) {
            Ok(_) => {},
            Err(_) => {
                // Ring buffer full - this will generate performance warnings
                return -1;
            }
        }
        
        return 0;
    }
}

// Program 4: Sequential access pattern demonstration
program data_processor : kprobe {
    fn main(ctx: KprobeContext) -> i32 {
        // Sequential access pattern - will be detected and optimized
        for i in 0..32 {
            match sequential_data.lookup(&i) {
                Some(element) => {
                    if !element.processed {
                        element.value = element.value * 2;
                        element.processed = true;
                        sequential_data.update(&i, element);
                    }
                },
                None => {
                    let new_element = ArrayElement {
                        value: i as u64,
                        processed: false,
                    };
                    sequential_data.insert(&i, &new_element);
                }
            }
        }
        
        return 0;
    }
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

/* 
Expected Analysis Results:

1. Access Pattern Analysis:
   - traffic_monitor: High-frequency random access (100 lookups)
   - stats_updater: Batch access pattern (20 operations)
   - data_processor: Sequential access pattern (0-31)
   - event_logger: Streaming pattern (ring buffer)

2. Concurrent Access Safety:
   - global_counter: SAFE (multiple readers, single writer per key)
   - shared_stats: WRITE_LOCKED (multiple programs writing)
   - percpu_data: SAFE (per-CPU isolation)
   - event_stream: SAFE (single writer recommended)

3. Global Map Sharing Validation:
   - global_counter: VALID (reader-heavy workload)
   - shared_stats: CONFLICT (multiple writers detected)
   - Recommendations: Use per-CPU maps or synchronization

4. Performance Recommendations:
   - High-frequency access detected in traffic_monitor
   - Consider caching for frequently accessed keys
   - Sequential access in data_processor could use array map
   - Batch operations detected - consider batch helpers

5. Optimization Suggestions:
   - Convert sequential_data to array map type
   - Use LRU eviction for shared_stats under memory pressure
   - Consider read-only maps for static configuration data
   - Implement proper error handling for ring buffer overflow
*/ 