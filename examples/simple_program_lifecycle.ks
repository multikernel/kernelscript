@xdp fn simple_xdp(ctx: *xdp_md) -> xdp_action {
    print("Hello" + " world")
    return 2
}

// Userspace program lifecycle management
fn main() -> i32 {
    var prog_handle = load(simple_xdp)
    var result = attach(prog_handle, "lo", 0)
    return 0
} 
