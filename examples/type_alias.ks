// Test file for type alias functionality
type IpAddress = u32
type Port = u16
type EthBuffer = u8[14]

@xdp fn test_type_aliases(ctx: XdpContext) -> XdpAction {
    let port: Port = 8080
    let ip: IpAddress = 192168001001
    
    return XDP_PASS
}

fn main() -> i32 {
    let prog = load(test_type_aliases)
    attach(prog, "eth0", 0)
    return 0
} 
