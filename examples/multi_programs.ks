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

// TC context struct (from BTF)
struct __sk_buff {
  data: u64,
  data_end: u64,
  len: u32,
  ifindex: u32,
  protocol: u32,
  mark: u32,
}

// TC action constants
enum tc_action {
  TC_ACT_UNSPEC = 255,
  TC_ACT_OK = 0,
  TC_ACT_RECLASSIFY = 1,
  TC_ACT_SHOT = 2,
  TC_ACT_PIPE = 3,
  TC_ACT_STOLEN = 4,
  TC_ACT_QUEUED = 5,
  TC_ACT_REPEAT = 6,
  TC_ACT_REDIRECT = 7,
}

pin var shared_counter : hash<u32, u32>(1024)

// First eBPF program - packet counter
@xdp fn packet_counter(ctx: *xdp_md) -> xdp_action {
  shared_counter[1] = 100
  return XDP_PASS
}

@tc fn packet_filter(ctx: *__sk_buff) -> i32 {
  shared_counter[2] = 200
  return TC_ACT_OK
}

// Userspace coordination (outside program blocks)
fn main() -> i32 {
  shared_counter[1] = 0
  shared_counter[2] = 0
  
  var prog1 = load(packet_counter)
  var prog2 = load(packet_filter)
  attach(prog1, "eth0", 0)
  attach(prog2, "eth0", 0)
  
  print("Multiple XDP programs attached to eth0")
  print("Counter and filter working together...")
  
  // Detach in reverse order (good practice)
  detach(prog2)
  detach(prog1)
  print("All programs detached")
  
  return 0
} 