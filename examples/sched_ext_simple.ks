// Simple sched-ext scheduler implementation
// This demonstrates a basic FIFO scheduler using sched_ext_ops

include "sched_ext_ops.kh"

// kfuncs declarations (extracted from BTF)
extern scx_bpf_select_cpu_dfl(p: *u8, prev_cpu: i32, wake_flags: u64, direct: *bool) -> i32
extern scx_bpf_dsq_insert(p: *u8, dsq_id: u64, slice: u64, enq_flags: u64) -> void
extern scx_bpf_consume(dsq_id: u64, cpu: i32, flags: u64) -> i32

// Simple FIFO scheduler implementation
@struct_ops("sched_ext_ops")
impl simple_fifo_scheduler {
    
    // Select CPU for a waking task
    fn select_cpu(p: *u8, prev_cpu: i32, wake_flags: u64) -> i32 {
        // Use default CPU selection with direct dispatch if idle core found
        var direct: bool = false
        var cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct)
        
        if (direct) {
            // Insert directly into local DSQ, skipping enqueue
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0)
        }
        
        return cpu
    }
    
    // Enqueue task into global FIFO queue
    fn enqueue(p: *u8, enq_flags: u64) -> void {
        // Simple FIFO: insert all tasks into global DSQ
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags)
    }
    
    // Dispatch tasks from global queue to local CPU
    fn dispatch(cpu: i32, prev: *u8) -> void {
        // Try to consume a task from the global DSQ
        if (scx_bpf_consume(SCX_DSQ_GLOBAL, cpu, 0) == 0) {
            // No tasks available, CPU will go idle
        }
    }
    
    // Task becomes runnable
    fn runnable(p: *u8, enq_flags: u64) -> void {
        // Optional: track runnable tasks
        // For simple FIFO, we don't need special handling
    }
    
    // Task starts running
    fn running(p: *u8) -> void {
        // Optional: track running tasks
        // For simple FIFO, we don't need special handling
    }
    
    // Task stops running
    fn stopping(p: *u8, runnable: bool) -> void {
        // Optional: handle task stopping
        // For simple FIFO, we don't need special handling
    }
    
    // Task becomes quiescent
    fn quiescent(p: *u8, deq_flags: u64) -> void {
        // Optional: handle quiescent tasks
        // For simple FIFO, we don't need special handling
    }
    
    // Initialize new task
    fn init_task(p: *u8, args: *u8) -> i32 {
        // Return 0 for success
        return 0
    }
    
    // Clean up exiting task
    fn exit_task(p: *u8, args: *u8) -> void {
        // Optional cleanup for exiting tasks
    }
    
    // Enable scheduler
    fn enable(p: *u8) -> void {
        // Optional: scheduler enable logic
    }
    
    // Initialize scheduler
    fn init() -> i32 {
        // Return 0 for successful initialization
        return 0
    }
    
    // Exit scheduler
    fn exit(info: *u8) -> void {
        // Optional cleanup on scheduler exit
    }
    
    // Scheduler name
    name: "simple_fifo",
    
    // Timeout in milliseconds (0 = no timeout)
    timeout_ms: 0,
    
    // Scheduler flags
    flags: 0,
}

// Userspace main function
fn main() -> i32 {
    // Register the sched-ext scheduler
    var result = register(simple_fifo_scheduler)
    
    if (result == 0) {
        print("Simple FIFO scheduler registered successfully")
    } else {
        print("Failed to register Simple FIFO scheduler")
    }
    
    return result
}
