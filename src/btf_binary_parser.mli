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

(** Direct Binary BTF Parser Interface *)

type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
  kernel_defined: bool; (* Mark if this type is kernel-defined *)
}

(** Parse a binary BTF file directly and extract requested types.
    @param btf_path Path to the binary BTF file
    @param target_types List of type names to extract
    @return List of extracted type definitions in KernelScript format *)
val parse_btf_file : string -> string list -> btf_type_info list

(** Extract kernel function signatures for kprobe targets.
    @param btf_path Path to the binary BTF file
    @param function_names List of kernel function names to extract signatures for
    @return List of (function_name, signature) pairs *)
val extract_kernel_function_signatures : string -> string list -> (string * string) list

(** Extract all kernel-defined struct and enum names from BTF file.
    @param btf_path Path to the binary BTF file
    @return List of kernel struct and enum names *)
val extract_all_kernel_struct_and_enum_names : string -> string list

(** Extract kfuncs from BTF file using DECL_TAG annotations.
    @param btf_path Path to the binary BTF file
    @return List of (function_name, signature) pairs for functions tagged with "bpf_kfunc" *)
val extract_kfuncs_from_btf : string -> (string * string) list 