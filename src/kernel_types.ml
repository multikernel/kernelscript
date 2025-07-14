(*
 * Copyright 2025 Multikernel Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

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