// Test file for type alias functionality
type IpAddress = u32
type Port = u16
type EthBuffer = u8[14]

program test_type_aliases : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let port: Port = 8080
        let ip: IpAddress = 192168001001

        
        return 2
    }
} 
