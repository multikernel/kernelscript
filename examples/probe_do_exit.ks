// Kprobe Example: Monitor process exit events
// 
// This example demonstrates how to use probe to intercept and monitor
// the do_exit() kernel function, which is called when a process exits.
// We print the exit code parameter to see why processes are exiting.

// Target kernel function signature:
// do_exit(code: i64) -> void (in kernel)
// 
// The 'code' parameter contains the exit status/signal that caused
// the process to exit. In the kernel, it's declared as 'long' (signed 64-bit).
// 
// Note: eBPF probe functions must return i32 due to BPF_PROG() constraint,
// regardless of the target kernel function's return type.


@probe("do_exit")
fn do_exit(code: i64) -> i32 {
    // Print the exit code parameter
    // This will show us the exit status/signal for the exiting process
    print("Process exiting with code: %ld", code)
    return 0  // Continue normal execution
}

fn main() -> i32 {
    var prog = load(do_exit)
    var result = attach(prog, "do_exit", 0)
    
    if (result == 0) {
        print("probe program attached to do_exit successfully")
        print("Monitoring process exits...")
        
        // In a real scenario, you would wait for events or run for a specific time
        // For this example, we'll just clean up immediately
        
        // Detach the program
        detach(prog)
        print("probe program detached")
    } else {
        print("Failed to attach probe program")
        return 1
    }
    
    return 0
}
