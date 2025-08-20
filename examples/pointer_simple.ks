// Simple pointer demo
include "xdp.kh"

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
fn xdp_prog(ctx: *xdp_md) -> xdp_action {
    return 2
} 