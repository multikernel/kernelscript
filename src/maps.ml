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

(** eBPF Maps Module for KernelScript
    
    This module provides complete eBPF map type definitions, configuration parsing,
    pin path and attribute handling, and global vs local map semantics.
*)

open Ast

(** Extended map type definitions with detailed eBPF semantics *)
type ebpf_map_type =
  | Hash           (* BPF_MAP_TYPE_HASH *)
  | Array          (* BPF_MAP_TYPE_ARRAY *)
  | Lru_hash       (* BPF_MAP_TYPE_LRU_HASH *)
  | Percpu_hash    (* BPF_MAP_TYPE_PERCPU_HASH *)
  | Percpu_array   (* BPF_MAP_TYPE_PERCPU_ARRAY *)

(** Map attribute definitions *)
type map_attribute =
  | Pinned of string
  | NoPrealloc
  | Mmapable
  | InnerMapType of ebpf_map_type
  | NumaNode of int

(** Map configuration with eBPF-specific constraints *)
type map_config = {
  max_entries: int;
  key_size: int option;
  value_size: int option;
  attributes: map_attribute list;
  inner_map_fd: int option;
  flags: int;
}

(** Complete map declaration with semantic information *)
type map_declaration = {
  name: string;
  key_type: bpf_type;
  value_type: bpf_type;
  map_type: ebpf_map_type;
  config: map_config;
  is_global: bool;
  program_scope: string option; (* None for global, Some(prog_name) for local *)
  map_pos: position;
}

(** Map operation types for type checking *)
type map_operation =
  | MapLookup
  | MapUpdate
  | MapDelete
  | MapInsert
  | MapUpsert

(** Map access pattern for optimization *)
type access_pattern =
  | ReadWrite
  | BatchUpdate

(** Map validation results *)
type validation_result =
  | Valid
  | InvalidKeyType of string
  | InvalidValueType of string
  | InvalidConfiguration of string
  | InvalidAttributes of string
  | UnsupportedOperation of string

(** Map flag information for analysis *)
type map_flag_info = {
  map_name: string;
  has_initial_values: bool;
  initial_values: string list;
  key_type: string;
  value_type: string;
}

(** Analysis result types *)
type map_stats = { total_maps: int }
type type_analysis_result = { types_valid: bool }
type size_analysis_result = { sizes_valid: bool }
type compatibility_result = { is_compatible: bool }

type flag_validation_result = {
  all_valid: bool;
  analysis_complete: bool;
  map_statistics: map_stats;
  type_analysis: type_analysis_result option;
  size_analysis: size_analysis_result option;
  compatibility_check: compatibility_result option;
}

(** Map semantics and constraints *)

(** Get the default key and value sizes for primitive types *)
let rec get_type_size = function
  | U8 | I8 | Bool | Char -> Some 1
  | U16 | I16 -> Some 2
  | U32 | I32 -> Some 4
  | U64 | I64 -> Some 8
  | Pointer _ -> Some 8
  | Array (t, count) -> 
      (match get_type_size t with
       | Some size -> Some (size * count)
       | None -> None)
  | Struct _ -> None (* struct sizes need separate analysis *)
  | UserType _ -> None (* user type sizes need resolution *)
  | _ -> None

(** Validate key type for specific map types *)
let validate_key_type map_type key_type =
  match map_type, key_type with
  | Array, U32 -> Valid
  | Array, Enum _ -> Valid  (* Enums are compatible with u32 for array indexing *)
  | Array, _ -> InvalidKeyType "Array maps require u32 keys"
  | Percpu_array, U32 -> Valid
  | Percpu_array, Enum _ -> Valid  (* Enums are compatible with u32 for array indexing *)
  | Percpu_array, _ -> InvalidKeyType "Per-CPU array maps require u32 keys"
  | Hash, (U8|U16|U32|U64|I8|I16|I32|I64) -> Valid
  | Hash, Struct _ -> Valid
  | Hash, Array (_, _) -> Valid
  | Hash, _ -> InvalidKeyType "Hash maps require primitive or struct keys"
  | Lru_hash, (U8|U16|U32|U64|I8|I16|I32|I64) -> Valid
  | Lru_hash, Struct _ -> Valid
  | Lru_hash, _ -> InvalidKeyType "LRU hash maps require primitive or struct keys"
  | Percpu_hash, (U8|U16|U32|U64|I8|I16|I32|I64) -> Valid
  | Percpu_hash, Struct _ -> Valid
  | Percpu_hash, _ -> InvalidKeyType "Per-CPU hash maps require primitive or struct keys"

(** Validate value type for specific map types *)
let validate_value_type map_type value_type =
  match map_type, value_type with
  | Array, t when get_type_size t != None -> Valid
  | Array, _ -> InvalidValueType "Array maps require fixed-size value types"
  | Hash, _ -> Valid (* Hash maps accept any value type *)
  | Percpu_hash, _ -> Valid (* Per-CPU hash maps accept any value type *)
  | Lru_hash, _ -> Valid (* LRU hash maps accept any value type *)
  | _ -> Valid

(** Validate map configuration *)
let validate_map_config map_type config =
  (* Check max_entries constraints *)
  let max_entries_valid = match map_type with
    | Array | Percpu_array when config.max_entries > 1000000 ->
        InvalidConfiguration "Array maps limited to 1M entries"
    | Hash | Percpu_hash | Lru_hash when config.max_entries > 1000000 ->
        InvalidConfiguration "Hash maps limited to 1M entries"
    | _ when config.max_entries <= 0 ->
        InvalidConfiguration "max_entries must be positive"
    | _ -> Valid
  in
  if max_entries_valid <> Valid then max_entries_valid else

  (* Check attribute compatibility *)
  let check_attributes attrs =
    let rec check = function
      | [] -> Valid
      | Pinned path :: rest ->
          if String.length path = 0 then
            InvalidAttributes "Pinned path cannot be empty"
          else if not (String.contains path '/') then
            InvalidAttributes "Pinned path must be absolute"
          else check rest

      | NumaNode n :: rest ->
          if n < 0 then
            InvalidAttributes "NUMA node must be non-negative"
          else check rest
      | _ :: rest -> check rest
    in
    check attrs
  in
  check_attributes config.attributes

(** Validate complete map declaration *)
let validate_map_declaration map_decl =
  let key_valid = validate_key_type map_decl.map_type map_decl.key_type in
  if key_valid <> Valid then key_valid else
  
  let value_valid = validate_value_type map_decl.map_type map_decl.value_type in
  if value_valid <> Valid then value_valid else
  
  validate_map_config map_decl.map_type map_decl.config

(** Map operation validation *)
let validate_map_operation map_decl operation access_pattern =
  match operation, access_pattern with
  | MapLookup, ReadWrite -> Valid
  | MapUpdate, ReadWrite -> Valid
  | MapDelete, ReadWrite ->
      (* Delete is only supported on certain map types *)
      (match map_decl.map_type with
       | Hash | Percpu_hash | Lru_hash -> Valid
       | Array | Percpu_array -> UnsupportedOperation "Delete operations not supported on array maps")
  | MapInsert, ReadWrite -> Valid
  | MapUpsert, ReadWrite -> Valid
  | _, BatchUpdate -> Valid

(** Map creation and utility functions *)

(** Create a default map configuration *)
let make_map_config max_entries ?(key_size=None) ?(value_size=None) 
                    ?(attributes=[]) ?(inner_map_fd=None) ?(flags=0) () =
  { max_entries; key_size; value_size; attributes; inner_map_fd; flags }

(** Create a map declaration *)
let make_map_declaration name key_type value_type map_type config 
                        is_global ?program_scope pos =
  { name; key_type; value_type; map_type; config; is_global; 
    program_scope; map_pos = pos }

(** Convert AST map_type to ebpf_map_type *)
let ast_to_ebpf_map_type = function
  | Ast.Hash -> Hash
  | Ast.Array -> Array
  | Ast.Percpu_hash -> Percpu_hash
  | Ast.Percpu_array -> Percpu_array
  | Ast.Lru_hash -> Lru_hash

(** Convert ebpf_map_type to AST map_type *)
let ebpf_to_ast_map_type = function
  | Hash -> Ast.Hash
  | Array -> Ast.Array
  | Percpu_hash -> Ast.Percpu_hash
  | Percpu_array -> Ast.Percpu_array
  | Lru_hash -> Ast.Lru_hash

(** Convert AST map_attribute to Maps map_attribute - removed since old attribute system is gone *)

(** Convert AST map flags to integer representation *)
let ast_flags_to_int flags =
  let flag_to_int = function
    | Ast.NoPrealloc -> 0x1        (* BPF_F_NO_PREALLOC *)
    | Ast.NoCommonLru -> 0x2       (* BPF_F_NO_COMMON_LRU *)
    | Ast.NumaNode n -> 0x4 lor (n lsl 8)  (* BPF_F_NUMA_NODE with node ID *)
    | Ast.Rdonly -> 0x8           (* BPF_F_RDONLY *)
    | Ast.Wronly -> 0x10          (* BPF_F_WRONLY *)
    | Ast.Clone -> 0x20           (* BPF_F_CLONE *)
  in
  List.fold_left (fun acc flag -> acc lor (flag_to_int flag)) 0 flags

(** Convert AST map declaration to Maps map declaration *)
let ast_to_maps_declaration ast_map =
  let ebpf_map_type = ast_to_ebpf_map_type ast_map.Ast.map_type in
  let flags = ast_flags_to_int ast_map.Ast.config.flags in
  let config = {
    max_entries = ast_map.Ast.config.max_entries;
    key_size = ast_map.Ast.config.key_size;
    value_size = ast_map.Ast.config.value_size;
    attributes = []; (* No attributes since old attribute system is removed *)
    inner_map_fd = None;
    flags = flags;
  } in
  {
    name = ast_map.Ast.name;
    key_type = ast_map.Ast.key_type;
    value_type = ast_map.Ast.value_type;
    map_type = ebpf_map_type;
    config = config;
    is_global = ast_map.Ast.is_global;
    program_scope = if ast_map.Ast.is_global then None else Some "unknown";
    map_pos = ast_map.Ast.map_pos;
  }

(** Map analysis functions *)

(** Analyze access patterns in an expression *)
let analyze_expr_access_pattern expr =
  match expr.expr_desc with
  | Call (_, _) | ArrayAccess (_, _) | _ -> ReadWrite

(** Check if a map is compatible with a program type *)
let is_map_compatible_with_program map_type prog_type =
  match map_type, prog_type with
  | Hash, Xdp -> true
  | Percpu_hash, _ -> true
  | Hash, _ -> true
  | Array, _ -> true
  | Lru_hash, _ -> true
  | _ -> true (* Most combinations are valid *)

(** Get recommended map type for use case *)
let recommend_map_type key_type _value_type usage_pattern =
  match usage_pattern with
  | ReadWrite when key_type = U32 -> Array
  | ReadWrite -> Hash
  | BatchUpdate -> Lru_hash

(** Pretty printing functions *)

let string_of_ebpf_map_type = function
  | Hash -> "hash"
  | Array -> "array"
  | Percpu_hash -> "percpu_hash"
  | Percpu_array -> "percpu_array"
  | Lru_hash -> "lru_hash"

let string_of_map_attribute = function
  | Pinned path -> Printf.sprintf "pinned = \"%s\"" path
  | NoPrealloc -> "no_prealloc"
  | Mmapable -> "mmapable"
  | InnerMapType mt -> Printf.sprintf "inner_map_type = %s" (string_of_ebpf_map_type mt)
  | NumaNode n -> Printf.sprintf "numa_node = %d" n

let string_of_map_config config =
  let base = Printf.sprintf "max_entries = %d" config.max_entries in
  let attrs = List.map string_of_map_attribute config.attributes in
  String.concat "; " (base :: attrs)

let string_of_validation_result = function
  | Valid -> "Valid"
  | InvalidKeyType msg -> Printf.sprintf "Invalid key type: %s" msg
  | InvalidValueType msg -> Printf.sprintf "Invalid value type: %s" msg
  | InvalidConfiguration msg -> Printf.sprintf "Invalid configuration: %s" msg
  | InvalidAttributes msg -> Printf.sprintf "Invalid attributes: %s" msg
  | UnsupportedOperation msg -> Printf.sprintf "Unsupported operation: %s" msg

let string_of_map_declaration map_decl =
  let scope_str = match map_decl.program_scope with
    | None -> "global"
    | Some prog -> Printf.sprintf "local to %s" prog
  in
  Printf.sprintf "map<%s, %s> %s : %s(%s) [%s] {\n  %s\n}"
    (string_of_bpf_type map_decl.key_type)
    (string_of_bpf_type map_decl.value_type)
    map_decl.name
    (string_of_ebpf_map_type map_decl.map_type)
    (string_of_int map_decl.config.max_entries)
    scope_str
    (string_of_map_config map_decl.config)

(** Debug functions *)

let print_map_declaration map_decl =
  print_endline (string_of_map_declaration map_decl)

let print_validation_result result =
  print_endline (string_of_validation_result result)

(** Extract map flag information from AST *)
let extract_map_flags (ast : Ast.declaration list) =
  List.filter_map (function
    | Ast.MapDecl map_decl ->
        Some {
          map_name = map_decl.Ast.name;
          has_initial_values = false; (* KernelScript doesn't support map initialization yet *)
          initial_values = [];
          key_type = Ast.string_of_bpf_type map_decl.Ast.key_type;
          value_type = Ast.string_of_bpf_type map_decl.Ast.value_type;
        }
    | _ -> None
  ) ast

(** Validate map flags *)
let validate_map_flags map_flags =
  let all_valid = List.for_all (fun flag_info ->
    (* Basic validation - check that names are not empty and types are valid *)
    String.length flag_info.map_name > 0 &&
    String.length flag_info.key_type > 0 &&
    String.length flag_info.value_type > 0
  ) map_flags in
  
  ({
    all_valid = all_valid;
    analysis_complete = true;
    map_statistics = { total_maps = List.length map_flags };
    type_analysis = None;
    size_analysis = None;
    compatibility_check = None;
  } : flag_validation_result) 