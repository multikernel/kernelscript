program simple_xdp : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        print("Hello" + " world")
        return 2
    }
}

// Userspace program lifecycle management
fn main() -> i32 {
    let prog_handle = load(simple_xdp)
    let result = attach(prog_handle, "lo", 0)
    return 0
} 
