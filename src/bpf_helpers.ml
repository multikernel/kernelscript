(*
 * Copyright 2026 Multikernel Technologies, Inc.
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

(** Standard BPF helper functions.

    These are the legacy BPF helpers invoked through a fixed helper ID. libbpf's
    [<bpf/bpf_helpers.h>] (via the auto-generated [bpf_helper_defs.h]) already
    declares every one of them as a function pointer, so the eBPF C backend must
    NOT emit its own [extern ... __ksym;] declaration for them - doing so clashes
    with the libbpf declaration ("redefinition as different kind of symbol").

    KernelScript uses the [extern] keyword for both kfuncs and helpers, so the
    backend consults this set to tell them apart: a name here is a helper (skip
    the __ksym declaration); anything else is a real kfunc (needs __ksym).

    The list mirrors libbpf's [bpf_helper_defs.h], which is generated from the
    kernel's [__BPF_FUNC_MAPPER] and only ever grows. *)

let helper_names = [
  "bpf_bind";
  "bpf_bprm_opts_set";
  "bpf_btf_find_by_name_kind";
  "bpf_cgrp_storage_delete";
  "bpf_cgrp_storage_get";
  "bpf_check_mtu";
  "bpf_clone_redirect";
  "bpf_copy_from_user";
  "bpf_copy_from_user_task";
  "bpf_csum_diff";
  "bpf_csum_level";
  "bpf_csum_update";
  "bpf_current_task_under_cgroup";
  "bpf_d_path";
  "bpf_dynptr_data";
  "bpf_dynptr_from_mem";
  "bpf_dynptr_read";
  "bpf_dynptr_write";
  "bpf_fib_lookup";
  "bpf_find_vma";
  "bpf_for_each_map_elem";
  "bpf_get_attach_cookie";
  "bpf_get_branch_snapshot";
  "bpf_get_cgroup_classid";
  "bpf_get_current_ancestor_cgroup_id";
  "bpf_get_current_cgroup_id";
  "bpf_get_current_comm";
  "bpf_get_current_pid_tgid";
  "bpf_get_current_task";
  "bpf_get_current_task_btf";
  "bpf_get_current_uid_gid";
  "bpf_get_func_arg";
  "bpf_get_func_arg_cnt";
  "bpf_get_func_ip";
  "bpf_get_func_ret";
  "bpf_get_hash_recalc";
  "bpf_get_listener_sock";
  "bpf_get_local_storage";
  "bpf_get_netns_cookie";
  "bpf_get_ns_current_pid_tgid";
  "bpf_get_numa_node_id";
  "bpf_get_prandom_u32";
  "bpf_get_retval";
  "bpf_get_route_realm";
  "bpf_get_smp_processor_id";
  "bpf_get_socket_cookie";
  "bpf_get_socket_uid";
  "bpf_getsockopt";
  "bpf_get_stack";
  "bpf_get_stackid";
  "bpf_get_task_stack";
  "bpf_ima_file_hash";
  "bpf_ima_inode_hash";
  "bpf_inode_storage_delete";
  "bpf_inode_storage_get";
  "bpf_jiffies64";
  "bpf_kallsyms_lookup_name";
  "bpf_kptr_xchg";
  "bpf_ktime_get_boot_ns";
  "bpf_ktime_get_coarse_ns";
  "bpf_ktime_get_ns";
  "bpf_ktime_get_tai_ns";
  "bpf_l3_csum_replace";
  "bpf_l4_csum_replace";
  "bpf_load_hdr_opt";
  "bpf_loop";
  "bpf_lwt_push_encap";
  "bpf_lwt_seg6_action";
  "bpf_lwt_seg6_adjust_srh";
  "bpf_lwt_seg6_store_bytes";
  "bpf_map_delete_elem";
  "bpf_map_lookup_elem";
  "bpf_map_lookup_percpu_elem";
  "bpf_map_peek_elem";
  "bpf_map_pop_elem";
  "bpf_map_push_elem";
  "bpf_map_update_elem";
  "bpf_msg_apply_bytes";
  "bpf_msg_cork_bytes";
  "bpf_msg_pop_data";
  "bpf_msg_pull_data";
  "bpf_msg_push_data";
  "bpf_msg_redirect_hash";
  "bpf_msg_redirect_map";
  "bpf_override_return";
  "bpf_per_cpu_ptr";
  "bpf_perf_event_output";
  "bpf_perf_event_read";
  "bpf_perf_event_read_value";
  "bpf_perf_prog_read_value";
  "bpf_probe_read";
  "bpf_probe_read_kernel";
  "bpf_probe_read_kernel_str";
  "bpf_probe_read_str";
  "bpf_probe_read_user";
  "bpf_probe_read_user_str";
  "bpf_probe_write_user";
  "bpf_rc_keydown";
  "bpf_rc_pointer_rel";
  "bpf_rc_repeat";
  "bpf_read_branch_records";
  "bpf_redirect";
  "bpf_redirect_map";
  "bpf_redirect_neigh";
  "bpf_redirect_peer";
  "bpf_reserve_hdr_opt";
  "bpf_ringbuf_discard";
  "bpf_ringbuf_discard_dynptr";
  "bpf_ringbuf_output";
  "bpf_ringbuf_query";
  "bpf_ringbuf_reserve";
  "bpf_ringbuf_reserve_dynptr";
  "bpf_ringbuf_submit";
  "bpf_ringbuf_submit_dynptr";
  "bpf_send_signal";
  "bpf_send_signal_thread";
  "bpf_seq_printf";
  "bpf_seq_printf_btf";
  "bpf_seq_write";
  "bpf_set_hash";
  "bpf_set_hash_invalid";
  "bpf_set_retval";
  "bpf_setsockopt";
  "bpf_sk_ancestor_cgroup_id";
  "bpf_sk_assign";
  "bpf_skb_adjust_room";
  "bpf_skb_ancestor_cgroup_id";
  "bpf_skb_cgroup_classid";
  "bpf_skb_cgroup_id";
  "bpf_skb_change_head";
  "bpf_skb_change_proto";
  "bpf_skb_change_tail";
  "bpf_skb_change_type";
  "bpf_skb_ecn_set_ce";
  "bpf_skb_get_tunnel_key";
  "bpf_skb_get_tunnel_opt";
  "bpf_skb_get_xfrm_state";
  "bpf_skb_load_bytes";
  "bpf_skb_load_bytes_relative";
  "bpf_skb_output";
  "bpf_skb_pull_data";
  "bpf_skb_set_tstamp";
  "bpf_skb_set_tunnel_key";
  "bpf_skb_set_tunnel_opt";
  "bpf_skb_store_bytes";
  "bpf_skb_under_cgroup";
  "bpf_skb_vlan_pop";
  "bpf_skb_vlan_push";
  "bpf_sk_cgroup_id";
  "bpf_skc_lookup_tcp";
  "bpf_skc_to_mptcp_sock";
  "bpf_skc_to_tcp6_sock";
  "bpf_skc_to_tcp_request_sock";
  "bpf_skc_to_tcp_sock";
  "bpf_skc_to_tcp_timewait_sock";
  "bpf_skc_to_udp6_sock";
  "bpf_skc_to_unix_sock";
  "bpf_sk_fullsock";
  "bpf_sk_lookup_tcp";
  "bpf_sk_lookup_udp";
  "bpf_sk_redirect_hash";
  "bpf_sk_redirect_map";
  "bpf_sk_release";
  "bpf_sk_select_reuseport";
  "bpf_sk_storage_delete";
  "bpf_sk_storage_get";
  "bpf_snprintf";
  "bpf_snprintf_btf";
  "bpf_sock_from_file";
  "bpf_sock_hash_update";
  "bpf_sock_map_update";
  "bpf_sock_ops_cb_flags_set";
  "bpf_spin_lock";
  "bpf_spin_unlock";
  "bpf_store_hdr_opt";
  "bpf_strncmp";
  "bpf_strtol";
  "bpf_strtoul";
  "bpf_sys_bpf";
  "bpf_sys_close";
  "bpf_sysctl_get_current_value";
  "bpf_sysctl_get_name";
  "bpf_sysctl_get_new_value";
  "bpf_sysctl_set_new_value";
  "bpf_tail_call";
  "bpf_task_pt_regs";
  "bpf_task_storage_delete";
  "bpf_task_storage_get";
  "bpf_tcp_check_syncookie";
  "bpf_tcp_gen_syncookie";
  "bpf_tcp_raw_check_syncookie_ipv4";
  "bpf_tcp_raw_check_syncookie_ipv6";
  "bpf_tcp_raw_gen_syncookie_ipv4";
  "bpf_tcp_raw_gen_syncookie_ipv6";
  "bpf_tcp_send_ack";
  "bpf_tcp_sock";
  "bpf_this_cpu_ptr";
  "bpf_timer_cancel";
  "bpf_timer_init";
  "bpf_timer_set_callback";
  "bpf_timer_start";
  "bpf_trace_printk";
  "bpf_trace_vprintk";
  "bpf_user_ringbuf_drain";
  "bpf_xdp_adjust_head";
  "bpf_xdp_adjust_meta";
  "bpf_xdp_adjust_tail";
  "bpf_xdp_get_buff_len";
  "bpf_xdp_load_bytes";
  "bpf_xdp_output";
  "bpf_xdp_store_bytes";
]

let helper_set =
  let tbl = Hashtbl.create 256 in
  List.iter (fun name -> Hashtbl.replace tbl name ()) helper_names;
  tbl

(** [is_bpf_helper name] is true if [name] is a standard BPF helper already
    declared by libbpf's bpf_helpers.h, and therefore must not be re-declared
    as a [__ksym] extern by the eBPF C backend. *)
let is_bpf_helper name = Hashtbl.mem helper_set name
