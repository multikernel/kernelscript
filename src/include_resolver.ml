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

(** Include Resolution for KernelScript Headers (.kh files)
    
    This module handles including KernelScript header files (.kh files)
    that contain only declarations (extern, type, struct, enum, config).
    It validates that included files contain no function implementations.
*)

open Ast

(** Include validation errors *)
type include_validation_error = 
  | FunctionBodyFound of string (* function name with body *)
  | InvalidExtension of string (* non-.ksh extension *)
  | InvalidDeclaration of string (* unsupported declaration type *)

(** Include resolution errors *)
exception Include_error of string * position
exception Include_validation_error of include_validation_error * string * position

let include_error msg pos = raise (Include_error (msg, pos))

(** Validate that a declaration is allowed in header files *)
let validate_header_declaration decl =
  match decl with
  | TypeDef _ -> true
  | StructDecl _ -> true  
  | ConfigDecl _ -> true
  | ExternKfuncDecl _ -> true
  | IncludeDecl _ -> true  (* Allow nested includes *)
  | GlobalVarDecl _ -> true  (* Allow global variable declarations *)
  | AttributedFunction attr_func ->
      (* Check if this is just a declaration (no body) *)
      (match attr_func.attr_function.func_body with
       | [] -> true  (* Empty body = declaration only *)
       | _ -> false) (* Has body = implementation *)
  | GlobalFunction func ->
      (* Check if this is just a declaration (no body) *)
      (match func.func_body with
       | [] -> true  (* Empty body = declaration only *)
       | _ -> false) (* Has body = implementation *)
  | MapDecl _ -> true  (* Allow map declarations *)
  | ImplBlock _ -> false  (* Impl blocks not allowed in headers *)
  | ImportDecl _ -> true  (* Allow imports in headers *)

(** Validate that included file contains only valid header declarations *)
let validate_header_file file_path ast =
  let validate_decl decl =
    if not (validate_header_declaration decl) then
      let error_msg = match decl with
      | AttributedFunction attr_func ->
          FunctionBodyFound attr_func.attr_function.func_name
      | GlobalFunction func ->
          FunctionBodyFound func.func_name
      | ImplBlock impl_block ->
          InvalidDeclaration ("impl block '" ^ impl_block.impl_name ^ "' not allowed in headers")
      | _ ->
          InvalidDeclaration "unknown invalid declaration type"
      in
      let pos = { line = 0; column = 0; filename = file_path } in
      raise (Include_validation_error (error_msg, file_path, pos))
  in
  List.iter validate_decl ast

(** Validate file extension is .kh *)
let validate_file_extension file_path =
  if not (Filename.check_suffix file_path ".kh") then
    let pos = { line = 0; column = 0; filename = file_path } in
    raise (Include_validation_error (InvalidExtension file_path, file_path, pos))

(** Resolve a single include declaration *)
let resolve_include include_decl base_path =
  (* Resolve relative paths *)
  let file_path = if Filename.is_relative include_decl.include_path then
    Filename.concat (Filename.dirname base_path) include_decl.include_path
  else
    include_decl.include_path
  in
  
  (* Validate file extension *)
  validate_file_extension file_path;
  
  (* Check if file exists *)
  if not (Sys.file_exists file_path) then
    include_error ("Include file not found: " ^ file_path) include_decl.include_pos;
  
  try
    (* Parse the included file *)
    let ic = open_in file_path in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    let lexbuf = Lexing.from_string content in
    Lexing.set_filename lexbuf file_path;
    let ast = Parser.program Lexer.token lexbuf in
    
    (* Validate that it's a proper header file *)
    validate_header_file file_path ast;
    
    (* Update position information in all declarations to include the correct filename *)
    let update_position_in_declaration decl =
      match decl with
      | Ast.TypeDef (Ast.EnumDef (name, values, pos)) ->
          Ast.TypeDef (Ast.EnumDef (name, values, { pos with filename = file_path }))
      | Ast.TypeDef (Ast.StructDef (name, fields, pos)) ->
          Ast.TypeDef (Ast.StructDef (name, fields, { pos with filename = file_path }))
      | Ast.TypeDef (Ast.TypeAlias (name, typ, pos)) ->
          Ast.TypeDef (Ast.TypeAlias (name, typ, { pos with filename = file_path }))
      | Ast.StructDecl struct_def ->
          Ast.StructDecl { struct_def with struct_pos = { struct_def.struct_pos with filename = file_path } }
      | other -> other  (* Other declaration types don't need position updates for our filtering *)
    in
    
    (* Return the parsed declarations with updated positions *)
    List.map update_position_in_declaration ast
  with
  | Include_validation_error (err, file_path, pos) ->
      let error_msg = match err with
        | FunctionBodyFound func_name ->
            Printf.sprintf "Header file '%s' contains function implementation '%s'. Header files (.kh) should only contain declarations. Move implementations to .ks files." file_path func_name
        | InvalidExtension file_path ->
            Printf.sprintf "Include directive can only include .kh header files, but found: %s" file_path
        | InvalidDeclaration desc ->
            Printf.sprintf "Header file '%s' contains invalid declaration: %s" file_path desc
      in
      include_error error_msg pos
  | Sys_error msg -> 
      let pos = { line = 0; column = 0; filename = file_path } in
      include_error ("Cannot read header file: " ^ msg) pos
  | Parsing.Parse_error ->
      let pos = { line = 0; column = 0; filename = file_path } in
      include_error ("Parse error in header file: " ^ file_path) pos

(** Process all includes in an AST and return expanded AST with included declarations *)
let process_includes ast base_path =
  let rec process_decls decls =
    List.fold_left (fun acc decl ->
      match decl with
      | IncludeDecl include_decl ->
          (* Resolve the include and get its declarations *)
          let included_ast = resolve_include include_decl base_path in
          (* Recursively process includes in the included file *)
          let processed_included = process_decls included_ast in
          (* Add the included declarations to our AST (flatten) *)
          acc @ processed_included
      | _ ->
          (* Keep non-include declarations as-is *)
          acc @ [decl]
    ) [] decls
  in
  process_decls ast

(** Get all include declarations from an AST *)
let get_includes ast =
  List.filter_map (function
    | IncludeDecl include_decl -> Some include_decl
    | _ -> None
  ) ast