// Example demonstrating include functionality
// This shows how to include KernelScript headers (.kh files)

// Include declarations from header files
include "common_kfuncs.kh"
include "xdp_kfuncs.kh"
include "xdp.kh"


// XDP program that uses included kfunc declarations
@xdp
fn packet_processor(ctx: *xdp_md) -> xdp_action {
    // These functions are available from the included headers
    var timestamp = bpf_ktime_get_ns()
    var pid_tgid = bpf_get_current_pid_tgid()
    var result = bpf_xdp_adjust_head(ctx, -14)
    
    // Use the timestamp and pid to suppress unused variable warnings
    var action: XdpAction = 2  // XDP_PASS
    if (timestamp > 0 && pid_tgid > 0 && result >= 0) {
        return action
    }
    
    return 2  // XDP_PASS
}

fn main() -> i32 {
    return 0
}
