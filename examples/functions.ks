type IpAddress = u32

@helper
fn helper_function(value: u32) -> u32 {
  return value + 10
}

@helper
fn another_helper() -> u32 {
  return 42
}

@xdp fn test_functions(ctx: XdpContext) -> XdpAction {
  let result = helper_function(5)
  let const_val = another_helper()
  return XDP_PASS
}

fn global_function(x: u32) -> u32 {
  return x * 2
}

fn main() -> i32 {
  let result = global_function(21)
  return 0
} 