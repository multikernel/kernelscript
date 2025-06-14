program simple_xdp : xdp {
    fn main(ctx: XdpContext) -> u32 {
        print("Hello world");
        return 0;
    }
}

userspace {
    fn main() -> i32 {
        let prog_fd = load_program(simple_xdp);
        let result = attach_program(simple_xdp, "lo", 0);
        return 0;
    }
} 
