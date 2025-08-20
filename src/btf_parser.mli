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

(** BTF Parser - Extract type information from BTF files for KernelScript *)

type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
  kernel_defined: bool; (* Mark if this type is kernel-defined *)
}

type program_template = {
  program_type: string;
  context_type: string;
  return_type: string;
  includes: string list;
  types: btf_type_info list;
  function_signatures: (string * string) list; (* Function name and signature for kprobe targets *)
}

(** Get program template based on eBPF program type with optional BTF extraction *)
val get_program_template : string -> string option -> program_template

(** Get kprobe program template for a specific target function *)
val get_kprobe_program_template : string -> string option -> program_template

(** Get tracepoint program template for a specific target function *)
val get_tracepoint_program_template : string -> string option -> program_template

(** Check if a type name is a well-known eBPF kernel type *)
val is_well_known_kernel_type : ?btf_path:string -> string -> bool

(** Extract struct_ops definitions from BTF and generate KernelScript code *)
val extract_struct_ops_definitions : string option -> string list -> string list

(** Generate struct_ops template with BTF extraction *)
val generate_struct_ops_template : ?include_kfuncs:string -> string option -> string list -> string -> string

(** Generate program-type specific header content using BTF *)
val generate_program_header : extract_kfuncs:bool -> string -> string -> string

(** Generate struct_ops-specific header content using BTF *)
val generate_struct_ops_header : string -> string -> string

(** Generate tracepoint-specific header content using BTF *)
val generate_tracepoint_header : string -> string -> string

(** Generate KernelScript source code from template *)
val generate_kernelscript_source : ?extra_param:string -> ?include_kfuncs:string -> program_template -> string -> string 