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

type IpAddress = u32

@helper
fn helper_function(value: u32) -> u32 {
  return value + 10
}

@helper
fn another_helper() -> u32 {
  return 42
}

@xdp fn test_functions(ctx: *xdp_md) -> xdp_action {
  var result = helper_function(5)
  var const_val = another_helper()
  return XDP_PASS
}

fn global_function(x: u32) -> u32 {
  return x * 2
}

fn main() -> i32 {
  var result = global_function(21)
  return 0
} 