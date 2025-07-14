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

(** Struct_ops Registry Interface - Manage struct_ops definitions and BTF extraction *)

(** Known struct_ops types that can be extracted from BTF *)
type struct_ops_info = {
  name: string;
  description: string;
  kernel_version: string option;
  common_usage: string list;
}

(** Struct_ops field definition for code generation *)
type struct_ops_field = {
  field_name: string;
  field_type: string;
  is_function_pointer: bool;
  description: string option;
}

(** Check if a struct_ops type is known *)
val is_known_struct_ops : string -> bool

(** Get information about a struct_ops type *)
val get_struct_ops_info : string -> struct_ops_info option

(** Get all known struct_ops names *)
val get_all_known_struct_ops : unit -> string list

(** Get expected function signatures for a struct_ops type (deprecated - use struct definition in AST) *)
val get_struct_ops_signatures : string -> (string * (string * string) list * string) list option

(** Generate KernelScript struct_ops definition from BTF info *)
val generate_struct_ops_definition : Btf_binary_parser.btf_type_info -> string option

(** Extract struct_ops definitions from BTF file *)
val extract_struct_ops_from_btf : string -> string list -> string list

(** Verify struct_ops definition against BTF
    @param btf_path Path to BTF file
    @param struct_name Name of the struct_ops
    @param user_fields List of (field_name, field_type) from user definition
    @return Ok () if verification passes, Error message if it fails *)
val verify_struct_ops_against_btf : string -> string -> (string * 'a) list -> (unit, string) result

(** Generate usage example for a struct_ops *)
val generate_struct_ops_usage_example : string -> string 