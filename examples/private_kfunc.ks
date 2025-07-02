// Minimal example showing @private and @kfunc functions

// Private helper function - internal to kernel module, not exposed to eBPF
@private
fn validate_input(value: u32) -> bool {
    return value > 0 && value < 1000
}

// Kernel function exposed to eBPF programs via BTF
@kfunc 
fn process_value(input: u32) -> u32 {
    if (!validate_input(input)) {
        return 0  // Invalid input
    }
    return input * 2
}

// eBPF program that can call the kfunc but not the private function
@xdp
fn xdp_main(ctx: xdp_md) -> xdp_action {
    let value: u32 = 42
    let result = process_value(value)  // Can call @kfunc
    // let valid = validate_input(value)  // ERROR: Cannot call @private directly
    
    if (result > 0) {
        return XDP_PASS
    }
    return XDP_DROP
}

fn main() -> i32 {
    let prog = load(xdp_main)
    attach(prog, "lo", 0)
}