// Tracepoint Example: Monitor process scheduling events
// 
// This example demonstrates how to use tracepoint to monitor the sched_switch
// kernel tracepoint, which is triggered every time the kernel switches between
// processes. This allows us to track context switches and understand process
// scheduling behavior.

// Tracepoint event signature:
// Tracepoint event: sched/sched_switch -> fn(*trace_event_raw_sched_switch) -> i32
//
// The sched_switch tracepoint provides information about:
// - The process being switched out (prev_*)
// - The process being switched in (next_*)
// - Process priorities, PIDs, and scheduling states

include "tracepoint.kh"

@tracepoint("sched/sched_switch")
fn sched_sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    // Extract process information from the context switch event
    var prev_pid = ctx->prev_pid
    var next_pid = ctx->next_pid
    var prev_prio = ctx->prev_prio
    var next_prio = ctx->next_prio
    var prev_state = ctx->prev_state

    print("SCHED_SWITCH: prev_pid=%u -> next_pid=%u", prev_pid, next_pid)
    
    print("  Priorities: prev_prio=%u, next_prio=%u", prev_prio, next_prio)

    // Decode and print the previous task's state
    // Process states (simplified representation):
    // 0 = TASK_RUNNING, 1 = TASK_INTERRUPTIBLE, 2 = TASK_UNINTERRUPTIBLE
    if (prev_state == 0) {
        print("  Previous task state: RUNNING")
    } else if (prev_state == 1) {
        print("  Previous task state: INTERRUPTIBLE")
    } else if (prev_state == 2) {
        print("  Previous task state: UNINTERRUPTIBLE")
    } else {
        print("  Previous task state: OTHER (%lu)", prev_state)
    }
    
    // Note: Process command names (prev_comm/next_comm) are available in the context
    // but require special eBPF helpers to safely access as strings.
    // For this example, we focus on the numerical data which is readily accessible.
    
    // Track interesting scheduling events
    if (prev_pid == 0) {
        print("  --> Switching FROM idle process (swapper)")
    }
    if (next_pid == 0) {
        print("  --> Switching TO idle process (swapper)")
    }
    
    // Detect high priority processes
    if (next_prio < 10) {
        print("  --> High priority process scheduled (prio=%u)", next_prio)
    }
    
    return 0
}

fn main() -> i32 {
    print("Starting sched_switch tracepoint monitoring...")
    print("This will track all process scheduling events in the kernel")
    
    var prog = load(sched_sched_switch_handler)
    
    // Attach tracepoint to target kernel event
    var result = attach(prog, "sched/sched_switch", 0)
    
    if (result == 0) {
        print("sched_switch tracepoint program attached successfully")
        
        // In a real scenario, you would wait for events or run for a specific time
        // For this example, we'll just clean up after a brief moment
        
        // Detach the program
        detach(prog)
        print("sched_switch tracepoint program detached")
    } else {
        print("Failed to attach sched_switch tracepoint program")
        print("Make sure you have sufficient privileges (root) and the kernel supports tracepoints")
        return 1
    }
    
    return 0
}
