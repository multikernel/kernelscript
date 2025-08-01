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

(** Dynamic kernel type detection using BTF parsing *)

open Printf

(** Cache for BTF-extracted kernel types to avoid re-parsing *)
let kernel_types_cache : (string, string list) Hashtbl.t = Hashtbl.create 16

(** Fallback well-known eBPF types for when BTF is not available *)
let fallback_well_known_ebpf_types = [
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

(** Extract kernel types from BTF file with caching *)
let get_kernel_types_from_btf btf_path =
  match Hashtbl.find_opt kernel_types_cache btf_path with
  | Some cached_types -> cached_types
  | None ->
      let kernel_types = 
        try
          Btf_binary_parser.extract_all_kernel_struct_names btf_path
        with
        | _ -> 
            printf "Warning: Failed to extract kernel types from BTF, using fallback list\n";
            fallback_well_known_ebpf_types
      in
      Hashtbl.add kernel_types_cache btf_path kernel_types;
      kernel_types

(** Check if a type name is a well-known eBPF kernel type.
    Uses BTF if available, otherwise falls back to hardcoded list. *)
let is_well_known_ebpf_type ?btf_path type_name =
  match btf_path with
  | Some path when Sys.file_exists path ->
      let kernel_types = get_kernel_types_from_btf path in
      List.mem type_name kernel_types
  | _ ->
      (* Fallback to hardcoded list when BTF is not available *)
      List.mem type_name fallback_well_known_ebpf_types

(** Clear the kernel types cache (useful for testing or when BTF file changes) *)
let clear_cache () =
  Hashtbl.clear kernel_types_cache

(** Get all known kernel types for the given BTF file (for debugging/inspection) *)
let get_all_kernel_types ?btf_path () =
  match btf_path with
  | Some path when Sys.file_exists path ->
      get_kernel_types_from_btf path
  | _ ->
      fallback_well_known_ebpf_types 