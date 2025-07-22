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

(** Unified Import Resolution for KernelScript and External Languages
    
    This module handles importing both KernelScript modules (.ks files) and
    external language modules (Python .py files). It provides a unified
    interface that automatically detects the source type based on file extension.
*)

open Ast

(** Symbol information from KernelScript imports *)
type kernelscript_symbol = {
  symbol_name: string;
  symbol_type: bpf_type;
  symbol_kind: [`Function | `Type | `Map | `Config | `GlobalVar];
  is_public: bool;
}

(** Simplified Python module info - no static analysis needed *)
type python_module_info = {
  module_path: string;
  module_name: string;
}

(** Resolved import information *)
type resolved_import = {
  module_name: string;
  source_type: import_source_type;
  resolved_path: string;
  (* For KernelScript imports *)
  ks_symbols: kernelscript_symbol list;
  (* For Python imports - simplified *)
  py_module_info: python_module_info option;
}

(** Import validation errors *)
type import_validation_error = 
  | MainFunctionFound of string (* function name *)
  | EbpfProgramFound of string * string list (* function name, unsafe attributes *)
  | InvalidModuleStructure of string

(** Import resolution errors *)
exception Import_error of string * position
exception Import_validation_error of import_validation_error * string * position

let import_error msg pos = raise (Import_error (msg, pos))
let import_validation_error err module_name pos = raise (Import_validation_error (err, module_name, pos))

(** Validate that imported KernelScript module follows import rules *)
let validate_kernelscript_module module_name ast =
  let module_pos = { line = 1; column = 1; filename = module_name } in
  
  List.iter (function
    (* Check for main() function - not allowed in imported modules *)
    | GlobalFunction func when func.func_name = "main" ->
        import_validation_error 
          (MainFunctionFound func.func_name) 
          module_name 
          module_pos
    
    (* Check for attributed functions - only allow safe attributes in imported modules *)
    | AttributedFunction attr_func ->
        let unsafe_attributes = List.filter_map (function
          | SimpleAttribute attr when List.mem attr ["helper"; "kfunc"; "private"; "test"] -> 
              None  (* These are safe attributes allowed in imported modules *)
          | SimpleAttribute attr -> 
              Some attr  (* Any other simple attribute is not allowed *)
          | AttributeWithArg (attr, _) -> 
              Some attr  (* Parameterized attributes are generally eBPF programs *)
        ) attr_func.attr_list in
        
        if unsafe_attributes <> [] then
          import_validation_error 
            (EbpfProgramFound (attr_func.attr_function.func_name, unsafe_attributes))
            module_name 
            module_pos
    
    (* Allow other declarations like regular functions, types, structs, etc. *)
    | _ -> ()
  ) ast

(** Extract exportable symbols from KernelScript AST *)
let extract_exportable_symbols ast =
  let symbols = ref [] in
  
  List.iter (function
    | GlobalFunction func ->
        let param_types = List.map snd func.func_params in
        let return_type = match get_return_type func.func_return_type with
          | Some t -> t
          | None -> Void
        in
        let func_type = Function (param_types, return_type) in
        symbols := {
          symbol_name = func.func_name;
          symbol_type = func_type;
          symbol_kind = `Function;
          is_public = true; (* Regular functions are always public *)
        } :: !symbols
        
    | AttributedFunction attr_func ->
        (* Only export non-private attributed functions with safe attributes *)
        let has_exportable_attribute = List.exists (function
          | SimpleAttribute attr when List.mem attr ["helper"; "kfunc"; "test"] -> true
          | _ -> false
        ) attr_func.attr_list in
        
        let is_private = List.exists (function
          | SimpleAttribute "private" -> true
          | _ -> false
        ) attr_func.attr_list in
        
        if has_exportable_attribute && not is_private then
          let param_types = List.map snd attr_func.attr_function.func_params in
          let return_type = match get_return_type attr_func.attr_function.func_return_type with
            | Some t -> t
            | None -> Void
          in
          let func_type = Function (param_types, return_type) in
          symbols := {
            symbol_name = attr_func.attr_function.func_name;
            symbol_type = func_type;
            symbol_kind = `Function;
            is_public = true;
          } :: !symbols
    
    | TypeDef type_def ->
        (match type_def with
         | StructDef (name, _fields, _) ->
             let struct_type = Struct name in
             symbols := {
               symbol_name = name;
               symbol_type = struct_type;
               symbol_kind = `Type;
               is_public = true;
             } :: !symbols
         | EnumDef (name, _, _) ->
             let enum_type = Enum name in
             symbols := {
               symbol_name = name;
               symbol_type = enum_type;
               symbol_kind = `Type;
               is_public = true;
             } :: !symbols
         | TypeAlias (name, underlying_type) ->
             symbols := {
               symbol_name = name;
               symbol_type = underlying_type;
               symbol_kind = `Type;
               is_public = true;
             } :: !symbols)
    
    | MapDecl map_decl ->
        let map_type = Map (map_decl.key_type, map_decl.value_type, map_decl.map_type) in
        symbols := {
          symbol_name = map_decl.name;
          symbol_type = map_type;
          symbol_kind = `Map;
          is_public = map_decl.is_global;
        } :: !symbols
    
    | ConfigDecl config_decl ->
        (* Config blocks are represented as struct types for import purposes *)
        let config_type = UserType config_decl.config_name in
        symbols := {
          symbol_name = config_decl.config_name;
          symbol_type = config_type;
          symbol_kind = `Config;
          is_public = true;
        } :: !symbols
    
    | GlobalVarDecl global_var ->
        if not global_var.is_local then (* Only non-local vars are exportable *)
          let var_type = match global_var.global_var_type with
            | Some t -> t
            | None -> U32 (* Default type inference *)
          in
          symbols := {
            symbol_name = global_var.global_var_name;
            symbol_type = var_type;
            symbol_kind = `GlobalVar;
            is_public = true;
          } :: !symbols
    
    | StructDecl struct_def ->
        let struct_type = Struct struct_def.struct_name in
        symbols := {
          symbol_name = struct_def.struct_name;
          symbol_type = struct_type;
          symbol_kind = `Type;
          is_public = true;
        } :: !symbols
    
    | _ -> () (* Other declarations are not exportable *)
  ) ast;
  
  !symbols

(** Resolve KernelScript import *)
let resolve_kernelscript_import module_name file_path =
  try
    let ic = open_in file_path in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    let lexbuf = Lexing.from_string content in
    
    let ast = Parser.program Lexer.token lexbuf in
    
    (* Validate the imported module follows import rules *)
    validate_kernelscript_module module_name ast;
    
    let symbols = extract_exportable_symbols ast in
    
    {
      module_name;
      source_type = KernelScript;
      resolved_path = file_path;
      ks_symbols = symbols;
      py_module_info = None;
    }
  with
  | Import_validation_error (err, module_name, pos) ->
      let error_msg = match err with
        | MainFunctionFound func_name ->
            Printf.sprintf "Imported module '%s' cannot contain main() function (found: %s). Main functions should only be in the main program file." module_name func_name
        | EbpfProgramFound (func_name, attrs) ->
            Printf.sprintf "Imported module '%s' cannot contain attributed program functions (found: %s with attributes [%s]). Program functions should only be in the main program file. Allowed attributes in modules: @helper, @kfunc, @private, @test." module_name func_name (String.concat ", " attrs)
        | InvalidModuleStructure msg ->
            Printf.sprintf "Invalid module structure in '%s': %s" module_name msg
      in
      import_error error_msg pos
  | Sys_error msg -> 
      let pos = { line = 0; column = 0; filename = file_path } in
      import_error ("Cannot read KernelScript file: " ^ msg) pos
  | Parsing.Parse_error ->
      let pos = { line = 0; column = 0; filename = file_path } in
      import_error ("Parse error in KernelScript file: " ^ file_path) pos

(** Resolve Python import - simplified approach without static analysis *)
let resolve_python_import module_name file_path =
  if not (Sys.file_exists file_path) then
    let pos = { line = 0; column = 0; filename = file_path } in
    import_error ("Python file not found: " ^ file_path) pos
  else
    let py_info = { module_path = file_path; module_name } in
    {
      module_name;
      source_type = Python;
      resolved_path = file_path;
      ks_symbols = [];
      py_module_info = Some py_info;
    }

(** Main import resolution function *)
let resolve_import import_decl base_path =
  (* Resolve relative paths *)
  let file_path = if Filename.is_relative import_decl.source_path then
    Filename.concat (Filename.dirname base_path) import_decl.source_path
  else
    import_decl.source_path
  in
  
  (* Check if file exists *)
  if not (Sys.file_exists file_path) then
    import_error ("Import file not found: " ^ file_path) import_decl.import_pos;
  
  (* Resolve based on source type *)
  match import_decl.source_type with
  | KernelScript -> resolve_kernelscript_import import_decl.module_name file_path
  | Python -> resolve_python_import import_decl.module_name file_path

(** Resolve all imports in an AST *)
let resolve_all_imports ast base_path =
  let imports = List.filter_map (function
    | ImportDecl import_decl -> Some import_decl
    | _ -> None
  ) ast in
  
  List.map (fun import_decl -> resolve_import import_decl base_path) imports

(** Find imported symbol by name - only for KernelScript modules *)
let find_kernelscript_symbol resolved_import symbol_name =
  match resolved_import.source_type with
  | KernelScript ->
      List.find_opt (fun sym -> sym.symbol_name = symbol_name) resolved_import.ks_symbols
  | Python ->
      (* Python modules don't support static symbol lookup - all calls are dynamic *)
      None

(** Check if a Python module import is valid *)
let validate_python_module_import resolved_import =
  match resolved_import.source_type with
  | Python -> 
      (match resolved_import.py_module_info with
       | Some _ -> Ok "Python module available for dynamic calls"
       | None -> Error "Python module info missing")
  | KernelScript -> 
      Error "Not a Python module" 