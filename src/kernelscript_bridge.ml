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

(** KernelScript FFI Bridge
    
    This module provides a C bridge for calling KernelScript functions
    from other KernelScript modules, using shared library dynamic loading.
*)

open Printf

(** KernelScript function signature information *)
type ks_function_signature = {
  func_name: string;
  param_types: Ast.bpf_type list;
  return_type: Ast.bpf_type;
}

(** KernelScript binary module info *)
type kernelscript_binary_info = {
  module_path: string;
  module_name: string;
  library_path: string;
  exported_functions: ks_function_signature list;
}

(** Convert KernelScript type to C type string *)
let rec kernelscript_type_to_c_type = function
  | Ast.U8 -> "uint8_t"
  | Ast.U16 -> "uint16_t"
  | Ast.U32 -> "uint32_t"
  | Ast.U64 -> "uint64_t"
  | Ast.I8 -> "int8_t"
  | Ast.I16 -> "int16_t"
  | Ast.I32 -> "int32_t"
  | Ast.I64 -> "int64_t"
  | Ast.Bool -> "bool"
  | Ast.Char -> "char"
  | Ast.Void -> "void"
  | Ast.Pointer inner_type ->
      sprintf "%s*" (kernelscript_type_to_c_type inner_type)
  | _ -> "void*"  (* Fallback for complex types *)

(** Generate function signature for exported function *)
let generate_function_signature func_sig =
  let return_type_str = kernelscript_type_to_c_type func_sig.return_type in
  let params = List.map kernelscript_type_to_c_type func_sig.param_types in
  let params_str = if params = [] then "void" else String.concat ", " params in
  sprintf "%s %s(%s)" return_type_str func_sig.func_name params_str

(** Generate generic KernelScript module interface *)
let generate_ks_module_interface module_name exported_functions =
  let function_pointer_typedefs = List.map (fun func_sig ->
    let return_type_str = kernelscript_type_to_c_type func_sig.return_type in
    let params = List.map kernelscript_type_to_c_type func_sig.param_types in
    let params_str = if params = [] then "void" else String.concat ", " params in
    sprintf "typedef %s (*%s_func_t)(%s);" return_type_str func_sig.func_name params_str
  ) exported_functions in
  
  let function_pointers = List.map (fun func_sig ->
    sprintf "static %s_func_t %s_func = NULL;" func_sig.func_name func_sig.func_name
  ) exported_functions in
  
  let wrapper_functions = List.map (fun func_sig ->
    let return_type_str = kernelscript_type_to_c_type func_sig.return_type in
    let param_names = List.mapi (fun i _ -> sprintf "arg%d" i) func_sig.param_types in
    let params_with_types = List.map2 (fun param_type param_name ->
      sprintf "%s %s" (kernelscript_type_to_c_type param_type) param_name
    ) func_sig.param_types param_names in
    let params_str = if params_with_types = [] then "void" else String.concat ", " params_with_types in
    let args_str = String.concat ", " param_names in
    let call_statement = if func_sig.return_type = Ast.Void then
      sprintf "    %s_func(%s);" func_sig.func_name args_str
    else
      sprintf "    return %s_func(%s);" func_sig.func_name args_str
    in
    sprintf {|%s %s(%s) {
    if (!%s_func) {
        fprintf(stderr, "Function %s not loaded from module %s\n");
%s        return%s;
    }
%s
}|} return_type_str func_sig.func_name params_str func_sig.func_name func_sig.func_name module_name
      (if func_sig.return_type = Ast.Void then "" else "        ")
      (if func_sig.return_type = Ast.Void then "" else " 0")
      call_statement
  ) exported_functions in
  
  sprintf {|
// KernelScript module interface for %s
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

static void* %s_module_handle = NULL;

// Function pointer typedefs
%s

// Function pointers
%s

// Wrapper functions
%s

// Generic function call interface
int %s_call_function_by_name(const char* func_name, void* result, void* args[], int arg_count) {
    if (!%s_module_handle) {
        fprintf(stderr, "Module %s not initialized\n");
        return -1;
    }
    
    // Dynamic symbol lookup
    char symbol_name[256];
    snprintf(symbol_name, sizeof(symbol_name), "%%s", func_name);
    
    void* func_ptr = dlsym(%s_module_handle, symbol_name);
    if (!func_ptr) {
        fprintf(stderr, "Function %%s not found in module %s: %%s\n", func_name, dlerror());
        return -1;
    }
    
    // This is a simplified generic interface - type-safe wrappers should be used
    return 0;
}|} module_name module_name 
    (String.concat "\n" function_pointer_typedefs)
    (String.concat "\n" function_pointers)
    (String.concat "\n\n" wrapper_functions)
    module_name module_name module_name module_name module_name

(** Generate module initialization *)
let generate_ks_module_init module_name library_path exported_functions =
  let function_loadings = List.map (fun func_sig ->
    sprintf {|    %s_func = (%s_func_t)dlsym(%s_module_handle, "%s");
    if (!%s_func) {
        fprintf(stderr, "Failed to load function %s from module %s: %%s\n", dlerror());
        dlclose(%s_module_handle);
        %s_module_handle = NULL;
        return -1;
    }|} func_sig.func_name func_sig.func_name module_name func_sig.func_name 
      func_sig.func_name func_sig.func_name module_name module_name module_name
  ) exported_functions in
  
  sprintf {|
// Initialize KernelScript module: %s from %s
int init_%s_bridge(void) {
    if (%s_module_handle) {
        return 0; // Already initialized
    }
    
    // Load the shared library
    %s_module_handle = dlopen("%s", RTLD_LAZY);
    if (!%s_module_handle) {
        fprintf(stderr, "Failed to load KernelScript module %s: %%s\n", dlerror());
        return -1;
    }
    
    // Load function symbols
%s
    
    printf("Successfully initialized KernelScript bridge for module: %s\n");
    return 0;
}

// Cleanup KernelScript module: %s
void cleanup_%s_bridge(void) {
    if (%s_module_handle) {
        dlclose(%s_module_handle);
        %s_module_handle = NULL;
        
        // Reset function pointers
%s
    }
}|} module_name library_path module_name module_name module_name library_path 
    module_name module_name (String.concat "\n" function_loadings) module_name
    module_name module_name module_name module_name module_name
    (String.concat "\n" (List.map (fun func_sig -> 
      sprintf "        %s_func = NULL;" func_sig.func_name) exported_functions))

(** Generate complete KernelScript bridge C file *)
let generate_kernelscript_bridge module_name library_path exported_functions =
  let headers = {|#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>|} in
  
  let module_interface = generate_ks_module_interface module_name exported_functions in
  let module_init = generate_ks_module_init module_name library_path exported_functions in
  
  sprintf {|%s

%s

%s
|} headers module_interface module_init

(** Generate header file for KernelScript bridge *)
let generate_kernelscript_bridge_header module_name exported_functions =
  let header_guard = String.uppercase_ascii module_name ^ "_BRIDGE_H" in
  
  let function_declarations = List.map (fun func_sig ->
    generate_function_signature func_sig ^ ";"
  ) exported_functions in
  
  sprintf {|#ifndef %s
#define %s

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize/cleanup KernelScript bridge for module: %s
int init_%s_bridge(void);
void cleanup_%s_bridge(void);

// Exported function declarations
%s

// Generic function call interface
int %s_call_function_by_name(const char* func_name, void* result, void* args[], int arg_count);

#ifdef __cplusplus
}
#endif

#endif // %s|} header_guard header_guard module_name module_name module_name 
    (String.concat "\n" function_declarations) module_name header_guard

(** Extract exported functions from KernelScript AST *)
let extract_exported_functions ast =
  let functions = ref [] in
  
  List.iter (function
    | Ast.GlobalFunction func ->
        let param_types = List.map snd func.func_params in
        let return_type = match Ast.get_return_type func.func_return_type with
          | Some t -> t
          | None -> Ast.Void
        in
        functions := {
          func_name = func.func_name;
          param_types;
          return_type;
        } :: !functions
        
    | Ast.AttributedFunction attr_func ->
        (* Only @helper functions are exportable to other modules *)
        let is_helper = List.exists (function
          | Ast.SimpleAttribute "helper" -> true
          | _ -> false
        ) attr_func.attr_list in
        
        if is_helper then
          let param_types = List.map snd attr_func.attr_function.func_params in
          let return_type = match Ast.get_return_type attr_func.attr_function.func_return_type with
            | Some t -> t
            | None -> Ast.Void
          in
          functions := {
            func_name = attr_func.attr_function.func_name;
            param_types;
            return_type;
          } :: !functions
    
    | _ -> () (* Other declarations are not exportable *)
  ) ast;
  
  List.rev !functions

(** Generate shared library compilation rule for Makefile *)
let generate_shared_library_rule module_name _source_file =
  sprintf {|# Shared library rule for KernelScript module %s
%s.so: %s.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< $(LIBS)

|} module_name module_name module_name

(** Generate module info for imports *)
let get_kernelscript_binary_info module_name library_path exported_functions =
  let function_list = List.map (fun func_sig ->
    sprintf "  %s" (generate_function_signature func_sig)
  ) exported_functions in
  sprintf {|Module: %s
Library: %s
Type: KernelScript Binary (shared library)
Exported Functions:
%s
|} module_name library_path (String.concat "\n" function_list) 