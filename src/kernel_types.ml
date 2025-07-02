(** Shared module for eBPF kernel type definitions *)

(** Well-known eBPF context types that are provided by kernel headers
    These should be marked as kernel_defined = true **)
let well_known_ebpf_types = [
  (* eBPF context structs - provided by linux/bpf.h *)
  "xdp_md";
  "__sk_buff";
  "pt_regs";
  "trace_entry";
  "task_struct";
  "file";
  "inode";
  
  (* eBPF action enums - provided by linux/bpf.h and friends *)
  "xdp_action";
  "tc_action";
  
  (* Other eBPF-specific context types *)
  "bpf_cgroup_storage_key";
  "bpf_sockaddr";
  "bpf_sock";
  "bpf_sock_addr";
  "bpf_sock_ops";
  "sk_msg_md";
  "sk_reuseport_md";
  "bpf_sysctl";
  "bpf_sockopt";
]

(** Check if a type name is a well-known eBPF kernel type *)
let is_well_known_ebpf_type type_name =
  List.mem type_name well_known_ebpf_types 