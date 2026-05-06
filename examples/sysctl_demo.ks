@sysctl("kernel.ostype") var ostype: str(32)
@sysctl("net.core.somaxconn") var somaxconn: u32

@xdp fn passthrough(ctx: *xdp_md) -> xdp_action {
    return 2
}

fn main() -> i32 {
    var was: u32 = somaxconn
    print("ostype=", ostype, " somaxconn=", was)
    somaxconn = 4096
    return 0
}
