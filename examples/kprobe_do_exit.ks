// Kprobe Example: Monitor process exit events
// 
// This example demonstrates how to use kprobe to intercept and monitor
// the do_exit() kernel function, which is called when a process exits.
// We print the exit code parameter to see why processes are exiting.

// Target kernel function signature:
// do_exit(code: u64) -> void
// 
// The 'code' parameter contains the exit status/signal that caused
// the process to exit.


@kprobe("do_exit")
fn do_exit(code: u64) -> void {
    // Print the exit code parameter
    // This will show us the exit status/signal for the exiting process
    print("Process exiting with code: %u", code)    
    return 0
}

fn main() -> i32 {
    var prog = load(do_exit)
    var result = attach(prog, "do_exit", 0)
    
    if (result == 0) {
        print("kprobe program attached to do_exit successfully")
        print("Monitoring process exits...")
        
        // In a real scenario, you would wait for events or run for a specific time
        // For this example, we'll just clean up immediately
        
        // Detach the program
        detach(prog)
        print("kprobe program detached")
    } else {
        print("Failed to attach kprobe program")
        return 1
    }
    
    return 0
}
