// Simple test to verify GFP flag validation 

include "xdp.kh"

struct TestData {
    value: u64,
}

@kfunc
fn valid_kfunc_allocation() -> i32 {
    // Basic allocation (valid in kernel context)
    var basic_ptr = new TestData(GFP_ATOMIC)
    delete basic_ptr
    return 0
}

// This should succeed - basic allocation in eBPF context
@xdp
fn valid_ebpf_allocation(ctx: *xdp_md) -> xdp_action {
    var ptr = new TestData()
    delete ptr
    return XDP_PASS
}

// This should succeed - basic allocation in userspace
fn valid_userspace_allocation() -> i32 {
    var ptr = new TestData()
    delete ptr
    return 0
}

fn main() -> i32 {
    return valid_userspace_allocation()
} 