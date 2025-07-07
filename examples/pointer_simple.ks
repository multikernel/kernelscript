// XDP context struct (from BTF)
struct xdp_md {
  data: u64,
  data_end: u64,
  data_meta: u64,
  ingress_ifindex: u32,
  rx_queue_index: u32,
  egress_ifindex: u32,
}

// XDP action enum (from BTF)
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP = 1,
  XDP_PASS = 2,
  XDP_REDIRECT = 3,
  XDP_TX = 4,
}

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
fn xdp_prog(ctx: *xdp_md) -> xdp_action {
    return 2
} 