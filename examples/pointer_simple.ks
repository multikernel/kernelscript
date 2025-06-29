// Simple pointer demo
struct Point {
    x: u32,
    y: u32,
}

@helper  
fn update_point(p: *Point) -> u32 {
    p->x = 10
    p->y = 20
    return p->x + p->y
}

@xdp
fn xdp_prog(ctx: XdpContext) -> XdpAction {
    return 2
} 