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

(** Shared codegen utilities for eBPF and userspace C code generation *)

open Printf
open Ir

(** Target-specific type naming *)
type c_target = EbpfKernel | UserspaceStd

(** Convert IR type to C type string *)
let rec ir_type_to_c target = function
  | IRU8 -> (match target with EbpfKernel -> "__u8" | UserspaceStd -> "uint8_t")
  | IRU16 -> (match target with EbpfKernel -> "__u16" | UserspaceStd -> "uint16_t")
  | IRU32 -> (match target with EbpfKernel -> "__u32" | UserspaceStd -> "uint32_t")
  | IRU64 -> (match target with EbpfKernel -> "__u64" | UserspaceStd -> "uint64_t")
  | IRI8 -> (match target with EbpfKernel -> "__s8" | UserspaceStd -> "int8_t")
  | IRI16 -> (match target with EbpfKernel -> "__s16" | UserspaceStd -> "int16_t")
  | IRI32 -> (match target with EbpfKernel -> "__s32" | UserspaceStd -> "int32_t")
  | IRI64 -> (match target with EbpfKernel -> "__s64" | UserspaceStd -> "int64_t")
  | IRF32 -> (match target with EbpfKernel -> "__u32" | UserspaceStd -> "float")
  | IRF64 -> (match target with EbpfKernel -> "__u64" | UserspaceStd -> "double")
  | IRVoid -> "void"
  | IRBool -> (match target with EbpfKernel -> "__u8" | UserspaceStd -> "bool")
  | IRChar -> "char"
  | IRStr size ->
      (match target with
       | EbpfKernel -> sprintf "str_%d_t" size
       | UserspaceStd -> "char") (* Base type for userspace string - size handled in declaration *)
  | IRPointer (inner_type, _) -> sprintf "%s*" (ir_type_to_c target inner_type)
  | IRArray (inner_type, size, _) -> sprintf "%s[%d]" (ir_type_to_c target inner_type) size
  | IRStruct (name, _) -> sprintf "struct %s" name
  | IREnum (name, _) -> sprintf "enum %s" name
  | IRResult (ok_type, _err_type) -> ir_type_to_c target ok_type (* simplified to ok type *)
  | IRTypeAlias (name, _) -> name (* Use the alias name directly *)
  | IRStructOps (name, _) -> sprintf "struct %s_ops" name
  | IRFunctionPointer (param_types, return_type) ->
      let return_type_str = ir_type_to_c target return_type in
      let param_types_str = List.map (ir_type_to_c target) param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "%s (*)" return_type_str ^ sprintf "(%s)" params_str
  | IRRingbuf (_value_type, _size) ->
      (match target with
       | EbpfKernel -> "void*"
       | UserspaceStd -> "struct ring_buffer*")

(** Generate C declaration: handles function pointers, arrays, strings *)
let c_declaration target ir_type var_name =
  match ir_type with
  | IRFunctionPointer (param_types, return_type) ->
      let return_type_str = ir_type_to_c target return_type in
      let param_types_str = List.map (ir_type_to_c target) param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "%s (*%s)(%s)" return_type_str var_name params_str
  | IRStr size ->
      (match target with
       | EbpfKernel -> sprintf "str_%d_t %s" size var_name
       | UserspaceStd -> sprintf "char %s[%d]" var_name size)
  | IRArray (element_type, size, _) ->
      let element_type_str = ir_type_to_c target element_type in
      sprintf "%s %s[%d]" element_type_str var_name size
  | _ -> sprintf "%s %s" (ir_type_to_c target ir_type) var_name

(** Check if position indicates kernel-defined type (<builtin> or .kh) *)
let is_kernel_defined_pos pos =
  let is_builtin = pos.Ast.filename = "<builtin>" in
  let is_btf_type = Filename.check_suffix pos.Ast.filename ".kh" in
  is_builtin || is_btf_type

(** Check if struct should be included (not kernel-defined, unless struct_ops) *)
let should_include_struct struct_name struct_ops_declarations pos =
  let is_struct_ops_struct =
    List.exists (fun struct_ops_decl ->
      struct_ops_decl.ir_kernel_struct_name = struct_name
    ) struct_ops_declarations
  in
  if is_struct_ops_struct then
    true
  else
    not (is_kernel_defined_pos pos)

(** Generate typedef string *)
let generate_typedef target name ir_type =
  match ir_type with
  | IRFunctionPointer (param_types, return_type) ->
      let return_type_str = ir_type_to_c target return_type in
      let param_types_str = List.map (ir_type_to_c target) param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "typedef %s (*%s)(%s);" return_type_str name params_str
  | IRArray (inner_type, size, _) ->
      let element_type_str = ir_type_to_c target inner_type in
      sprintf "typedef %s %s[%d];" element_type_str name size
  | _ ->
      let c_type = ir_type_to_c target ir_type in
      sprintf "typedef %s %s;" c_type name

(** Generate struct definition string *)
let generate_struct_def target name fields =
  let field_lines = List.map (fun (field_name, field_type) ->
    match field_type with
    | IRArray (inner_type, size, _) ->
        let element_type_str = ir_type_to_c target inner_type in
        sprintf "    %s %s[%d];" element_type_str field_name size
    | IRStr size when target = UserspaceStd ->
        sprintf "    char %s[%d];" field_name size
    | _ ->
        let c_type = ir_type_to_c target field_type in
        sprintf "    %s %s;" c_type field_name
  ) fields in
  sprintf "struct %s {\n%s\n};" name (String.concat "\n" field_lines)

(** Generate enum definition string *)
let generate_enum_def name values =
  let value_count = List.length values in
  let enum_lines = List.mapi (fun i (const_name, value) ->
    sprintf "    %s = %s%s" const_name (Ast.IntegerValue.to_string value)
      (if i = value_count - 1 then "" else ",")
  ) values in
  sprintf "enum %s {\n%s\n};" name (String.concat "\n" enum_lines)
