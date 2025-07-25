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

(** IR-based Userspace C Code Generation
    This module generates complete userspace C programs from KernelScript IR programs.
    This is the unified IR-first userspace code generator.
*)

open Ir
open Printf

(** Python function call signature for bridge generation *)
type python_function_call = {
  module_name: string;
  function_name: string;
  param_count: int;
  return_type: ir_type;
}

(** Convert IR types to C types *)
let rec c_type_from_ir_type = function
  | IRU8 -> "uint8_t"
  | IRU16 -> "uint16_t"
  | IRU32 -> "uint32_t"
  | IRU64 -> "uint64_t"
  | IRI8 -> "int8_t"
  | IRI16 -> "int16_t"
  | IRI32 -> "int32_t"
  | IRI64 -> "int64_t"
  | IRF32 -> "float"
  | IRF64 -> "double"
  | IRVoid -> "void"
  | IRBool -> "bool"
  | IRChar -> "char"
  | IRStr _ -> "char" (* Base type for userspace string - size handled in declaration *)
  | IRPointer (inner_type, _) -> sprintf "%s*" (c_type_from_ir_type inner_type)
  | IRArray (inner_type, size, _) -> sprintf "%s[%d]" (c_type_from_ir_type inner_type) size
  | IRStruct (name, _, _) -> sprintf "struct %s" name
  | IREnum (name, _, _) -> sprintf "enum %s" name
  | IRResult (ok_type, _err_type) -> c_type_from_ir_type ok_type (* simplified to ok type *)
  | IRTypeAlias (name, _) -> name (* Use the alias name directly *)
  | IRStructOps (name, _) -> sprintf "struct %s_ops" name (* struct_ops as function pointer structs *)
  | IRContext _ -> "void*" (* context pointers *)
  | IRAction _ -> "int" (* action return values *)
  | IRBpfListHead _element_type -> "void*" (* BPF lists not applicable in userspace *)
  | IRFunctionPointer (param_types, return_type) -> 
      (* For function pointers, we need special handling - this is used for type aliases *)
      let return_type_str = c_type_from_ir_type return_type in
      let param_types_str = List.map c_type_from_ir_type param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "%s (*)" return_type_str ^ sprintf "(%s)" params_str  (* Function pointer type *)

(** Generate bridge code for imported KernelScript modules *)
let generate_kernelscript_bridge_code resolved_imports =
  let ks_imports = List.filter (fun import ->
    match import.Import_resolver.source_type with
    | Ast.KernelScript -> true
    | _ -> false
  ) resolved_imports in
  
  if ks_imports = [] then ""
  else
    let bridge_code = List.map (fun import ->
      let module_name = import.Import_resolver.module_name in
      let function_decls = List.map (fun symbol ->
        match symbol.Import_resolver.symbol_type with
        | Ast.Function (param_types, return_type) ->
            let c_return_type = match return_type with
              | Ast.U8 -> "uint8_t" | Ast.U16 -> "uint16_t" | Ast.U32 -> "uint32_t" | Ast.U64 -> "uint64_t"
              | Ast.I8 -> "int8_t" | Ast.I16 -> "int16_t" | Ast.I32 -> "int32_t" | Ast.I64 -> "int64_t"
              | Ast.Bool -> "bool" | Ast.Char -> "char" | _ -> "int"
            in
            let c_param_types = List.map (function
              | Ast.U8 -> "uint8_t" | Ast.U16 -> "uint16_t" | Ast.U32 -> "uint32_t" | Ast.U64 -> "uint64_t"
              | Ast.I8 -> "int8_t" | Ast.I16 -> "int16_t" | Ast.I32 -> "int32_t" | Ast.I64 -> "int64_t"
              | Ast.Bool -> "bool" | Ast.Char -> "char" | _ -> "int"
            ) param_types in
            let params_str = if c_param_types = [] then "void" else String.concat ", " c_param_types in
            sprintf "extern %s %s_%s(%s);" c_return_type module_name symbol.symbol_name params_str
        | _ ->
            sprintf "// %s (non-function symbol)" symbol.symbol_name
      ) import.ks_symbols in
      sprintf "// External functions from %s module\n%s" module_name (String.concat "\n" function_decls)
    ) ks_imports in
    
    sprintf "\n// Bridge code for imported KernelScript modules\n%s\n"
      (String.concat "\n\n" bridge_code)

(** Collect Python function calls from IR programs *)
let collect_python_function_calls ir_programs resolved_imports =
  let python_calls = ref [] in
  
  (* Extract function calls from IR instructions *)
  let rec extract_calls_from_instrs instrs =
    List.iter (fun instr ->
      match instr.instr_desc with
      | IRCall (DirectCall func_name, args, ret_opt) when String.contains func_name '.' ->
          (* This is a module call - check if it's Python *)
          let parts = String.split_on_char '.' func_name in
          (match parts with
           | [module_name; function_name] ->
               (* Check if this module is a Python import *)
               let is_python_module = List.exists (fun import ->
                 import.Import_resolver.module_name = module_name && 
                 import.Import_resolver.source_type = Ast.Python
               ) resolved_imports in
               if is_python_module then (
                 let call_signature = {
                   module_name = module_name;
                   function_name = function_name;
                   param_count = List.length args;
                   return_type = (match ret_opt with 
                     | Some ret_val -> ret_val.val_type 
                     | None -> IRVoid);
                 } in
                 if not (List.mem call_signature !python_calls) then
                   python_calls := call_signature :: !python_calls
               )
           | _ -> ())
      | IRIf (_, then_body, else_body) ->
          extract_calls_from_instrs then_body;
          (match else_body with
           | Some else_instrs -> extract_calls_from_instrs else_instrs
           | None -> ())
      | IRIfElseChain (conditions_and_bodies, final_else) ->
          List.iter (fun (_, then_body) ->
            extract_calls_from_instrs then_body
          ) conditions_and_bodies;
          (match final_else with
           | Some else_instrs -> extract_calls_from_instrs else_instrs
           | None -> ())
      | IRBpfLoop (_, _, _, _, body_instrs) ->
          extract_calls_from_instrs body_instrs
      | IRTry (try_instrs, catch_clauses) ->
          extract_calls_from_instrs try_instrs;
          List.iter (fun clause ->
            extract_calls_from_instrs clause.catch_body
          ) catch_clauses
      | _ -> ()
    ) instrs
  in
  
  (* Extract calls from all IR functions *)
  List.iter (fun ir_func ->
    List.iter (fun block ->
      extract_calls_from_instrs block.instructions
    ) ir_func.basic_blocks
  ) ir_programs;
  
  !python_calls

(** Generate bridge code for imported KernelScript and Python modules *)
let generate_mixed_bridge_code resolved_imports ir_programs =
  let ks_imports = List.filter (fun import ->
    match import.Import_resolver.source_type with
    | Ast.KernelScript -> true
    | _ -> false
  ) resolved_imports in
  
  let py_imports = List.filter (fun import ->
    match import.Import_resolver.source_type with
    | Ast.Python -> true
    | _ -> false
  ) resolved_imports in
  
  (* Generate KernelScript bridge code *)
  let ks_bridge_code = if ks_imports = [] then ""
    else
      let ks_declarations = List.map (fun import ->
        let module_name = import.Import_resolver.module_name in
        let function_decls = List.map (fun symbol ->
          match symbol.Import_resolver.symbol_type with
          | Ast.Function (param_types, return_type) ->
              let c_return_type = match return_type with
                | Ast.U8 -> "uint8_t" | Ast.U16 -> "uint16_t" | Ast.U32 -> "uint32_t" | Ast.U64 -> "uint64_t"
                | Ast.I8 -> "int8_t" | Ast.I16 -> "int16_t" | Ast.I32 -> "int32_t" | Ast.I64 -> "int64_t"
                | Ast.Bool -> "bool" | Ast.Char -> "char" | _ -> "int"
              in
              let c_param_types = List.map (function
                | Ast.U8 -> "uint8_t" | Ast.U16 -> "uint16_t" | Ast.U32 -> "uint32_t" | Ast.U64 -> "uint64_t"
                | Ast.I8 -> "int8_t" | Ast.I16 -> "int16_t" | Ast.I32 -> "int32_t" | Ast.I64 -> "int64_t"
                | Ast.Bool -> "bool" | Ast.Char -> "char" | _ -> "int"
              ) param_types in
              let params_str = if c_param_types = [] then "void" else String.concat ", " c_param_types in
              sprintf "extern %s %s_%s(%s);" c_return_type module_name symbol.symbol_name params_str
          | _ ->
              sprintf "// %s (non-function symbol)" symbol.symbol_name
        ) import.ks_symbols in
        sprintf "// External functions from KernelScript module: %s\n%s" module_name (String.concat "\n" function_decls)
      ) ks_imports in
      sprintf "\n// Bridge code for imported KernelScript modules\n%s\n" (String.concat "\n\n" ks_declarations)
  in
  
  (* Generate Python bridge code based on actual function calls *)
  let py_bridge_code = if py_imports = [] then ""
    else
      (* Collect actual Python function calls from IR *)
      let python_calls = collect_python_function_calls ir_programs resolved_imports in
      
      if python_calls = [] then
        (* No Python function calls found - generate minimal bridge *)
        let py_headers = "\n#include <Python.h>" in
        let py_minimal_bridge = List.map (fun import ->
          let module_name = import.Import_resolver.module_name in
          let file_path = import.Import_resolver.resolved_path in
          let python_module_name = Filename.remove_extension (Filename.basename file_path) in
          sprintf {|
// Python module: %s
static PyObject* %s_module = NULL;

// Initialize Python bridge for %s
int init_%s_bridge(void) {
    if (!Py_IsInitialized()) {
        Py_Initialize();
        if (!Py_IsInitialized()) {
            fprintf(stderr, "Failed to initialize Python interpreter\n");
            return -1;
        }
    }
    
    // Add the current directory to Python path
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.insert(0, '.')");
    
    // Import the module by name
    PyObject* module_name_obj = PyUnicode_FromString("%s");
    if (!module_name_obj) {
        fprintf(stderr, "Failed to create module name string\n");
        return -1;
    }
    
    %s_module = PyImport_Import(module_name_obj);
    Py_DECREF(module_name_obj);
    
    if (!%s_module) {
        PyErr_Print();
        fprintf(stderr, "Failed to import Python module: %s (make sure %s.py is in the current directory)\n");
        return -1;
    }
    
    return 0;
}

// Cleanup Python bridge for %s
void cleanup_%s_bridge(void) {
    if (%s_module) {
        Py_DECREF(%s_module);
        %s_module = NULL;
    }
}|} module_name module_name module_name module_name python_module_name 
      module_name module_name module_name python_module_name
      module_name module_name module_name module_name module_name
        ) py_imports in
        sprintf "%s\n// Bridge code for imported Python modules\n%s\n" py_headers (String.concat "\n\n" py_minimal_bridge)
      else
        (* Generate specific bridge functions for actual calls *)
        let py_headers = "\n#include <Python.h>" in
        
        (* Group calls by module *)
        let calls_by_module = List.fold_left (fun acc call ->
          let existing_calls = try List.assoc call.module_name acc with Not_found -> [] in
          let updated_calls = call :: (List.filter (fun c -> c.function_name <> call.function_name) existing_calls) in
          (call.module_name, updated_calls) :: (List.remove_assoc call.module_name acc)
        ) [] python_calls in
        
        let py_declarations = List.map (fun import ->
          let module_name = import.Import_resolver.module_name in
          let file_path = import.Import_resolver.resolved_path in
          let python_module_name = Filename.remove_extension (Filename.basename file_path) in
          
          (* Get the calls for this module *)
          let module_calls = try List.assoc module_name calls_by_module with Not_found -> [] in
          
          (* Generate bridge functions for each called function *)
          let bridge_functions = List.map (fun call ->
            let c_return_type = c_type_from_ir_type call.return_type in
            let params_list = List.init call.param_count (fun i -> sprintf "PyObject* arg%d" i) in
            let params_str = if params_list = [] then "void" else String.concat ", " params_list in
            let args_tuple = if call.param_count = 0 then "NULL" else (
              let arg_refs = List.init call.param_count (fun i -> sprintf "arg%d" i) in
              sprintf "Py_BuildValue(\"(%s)\", %s)" 
                (String.make call.param_count 'O') 
                (String.concat ", " arg_refs)
            ) in
            
            sprintf {|
// Bridge function for %s.%s
%s %s_%s(%s) {
    if (!%s_module) {
        fprintf(stderr, "Python module %s not initialized\n");
        return (%s){0};
    }
    
    PyObject* py_func = PyObject_GetAttrString(%s_module, "%s");
    if (!py_func || !PyCallable_Check(py_func)) {
        fprintf(stderr, "Function %s not found in module %s\n");
        Py_XDECREF(py_func);
        return (%s){0};
    }
    
    PyObject* args_tuple = %s;
    PyObject* result = PyObject_CallObject(py_func, args_tuple);
    Py_DECREF(py_func);
    if (args_tuple) Py_DECREF(args_tuple);
    
    if (!result) {
        PyErr_Print();
        return (%s){0};
    }
    
    %s ret_val = %s;
    if (PyErr_Occurred()) {
        PyErr_Print();
        Py_DECREF(result);
        return (%s){0};
    }
    
    Py_DECREF(result);
    return ret_val;
}|} module_name call.function_name c_return_type module_name call.function_name params_str
      module_name module_name c_return_type module_name call.function_name call.function_name 
      module_name c_return_type args_tuple c_return_type c_return_type 
      (match call.return_type with
       | IRU64 -> "PyLong_AsUnsignedLongLong(result)"
       | IRU32 -> "(uint32_t)PyLong_AsUnsignedLong(result)" 
       | IRU16 -> "(uint16_t)PyLong_AsUnsignedLong(result)"
       | IRU8 -> "(uint8_t)PyLong_AsUnsignedLong(result)"
       | IRI64 -> "PyLong_AsLongLong(result)"
       | IRI32 -> "(int32_t)PyLong_AsLong(result)"
       | IRI16 -> "(int16_t)PyLong_AsLong(result)"
       | IRI8 -> "(int8_t)PyLong_AsLong(result)"
       | IRBool -> "PyObject_IsTrue(result)"
       | IRF64 -> "PyFloat_AsDouble(result)"
       | IRF32 -> "(float)PyFloat_AsDouble(result)"
       | IRStr _ -> "/* string conversion would go here */"
       | _ -> "0 /* unsupported type */") c_return_type
          ) module_calls in
          
          sprintf {|
// Python module: %s
static PyObject* %s_module = NULL;

%s

// Initialize Python bridge for %s
int init_%s_bridge(void) {
    if (!Py_IsInitialized()) {
        Py_Initialize();
        if (!Py_IsInitialized()) {
            fprintf(stderr, "Failed to initialize Python interpreter\n");
            return -1;
        }
    }
    
    // Add the current directory to Python path
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.insert(0, '.')");
    
    // Import the module by name
    PyObject* module_name_obj = PyUnicode_FromString("%s");
    if (!module_name_obj) {
        fprintf(stderr, "Failed to create module name string\n");
        return -1;
    }
    
    %s_module = PyImport_Import(module_name_obj);
    Py_DECREF(module_name_obj);
    
    if (!%s_module) {
        PyErr_Print();
        fprintf(stderr, "Failed to import Python module: %s (make sure %s.py is in the current directory)\n");
        return -1;
    }
    
    return 0;
}

// Cleanup Python bridge for %s
void cleanup_%s_bridge(void) {
    if (%s_module) {
        Py_DECREF(%s_module);
        %s_module = NULL;
    }
}|} module_name module_name (String.concat "\n" bridge_functions) module_name module_name 
      python_module_name module_name module_name module_name python_module_name
      module_name module_name module_name module_name module_name
        ) py_imports in
        sprintf "%s\n// Bridge code for imported Python modules\n%s\n" py_headers (String.concat "\n\n" py_declarations)
  in
  
  ks_bridge_code ^ py_bridge_code

(** Generate Python initialization calls for all Python imports *)
let generate_python_initialization_calls resolved_imports =
  let py_imports = List.filter (fun import ->
    match import.Import_resolver.source_type with
    | Ast.Python -> true
    | _ -> false
  ) resolved_imports in
  
  if py_imports = [] then ""
  else
    let init_calls = List.map (fun import ->
      let module_name = import.Import_resolver.module_name in
      sprintf "    if (init_%s_bridge() != 0) {\n        fprintf(stderr, \"Failed to initialize Python module: %s\\n\");\n        return 1;\n    }" module_name module_name
    ) py_imports in
    
    sprintf "\n    // Initialize Python modules\n%s\n" 
      (String.concat "\n" init_calls)

(** Dependency information for a single eBPF program *)
type program_dependencies = {
  program_name: string;
  program_type: string;  (* xdp, tc, kprobe, etc *)
  required_kfuncs: string list;
  required_modules: string list;
}

(** System-wide kfunc dependency information *)
type kfunc_dependency_info = {
  kfunc_definitions: (string * Ast.function_def) list;  (* kfunc_name -> function_def *)
  private_functions: (string * Ast.function_def) list;   (* private function_name -> function_def *)
  program_dependencies: program_dependencies list;
  module_name: string;
}

(** Function usage tracking for optimization *)
type function_usage = {
  mutable uses_load: bool;
  mutable uses_attach: bool;
  mutable uses_map_operations: bool;
  mutable used_maps: string list;
}

let create_function_usage () = {
  uses_load = false;
  uses_attach = false;
  uses_map_operations = false;
  used_maps = [];
}

(** Extract kfunc and private function definitions from AST *)
let extract_kfunc_and_private_functions ast =
  let kfuncs = ref [] in
  let privates = ref [] in
  
  List.iter (function
    | Ast.AttributedFunction attr_func ->
        let is_kfunc = List.exists (function
          | Ast.SimpleAttribute "kfunc" -> true
          | _ -> false
        ) attr_func.attr_list in
        let is_private = List.exists (function
          | Ast.SimpleAttribute "private" -> true
          | _ -> false
        ) attr_func.attr_list in
        
        if is_kfunc then
          kfuncs := (attr_func.attr_function.func_name, attr_func.attr_function) :: !kfuncs
        else if is_private then
          privates := (attr_func.attr_function.func_name, attr_func.attr_function) :: !privates
    | _ -> ()
  ) ast;
  
  (!kfuncs, !privates)

(** Extract function calls from IR instructions *)
let rec extract_function_calls_from_ir_instrs instrs =
  let calls = ref [] in
  
  List.iter (fun instr ->
    match instr.instr_desc with
    | IRCall (target, _, _) ->
        (match target with
         | DirectCall func_name -> calls := func_name :: !calls
         | FunctionPointerCall _ -> ())
    | IRIf (_, then_body, else_body) ->
        calls := (extract_function_calls_from_ir_instrs then_body) @ !calls;
        (match else_body with
         | Some else_instrs -> calls := (extract_function_calls_from_ir_instrs else_instrs) @ !calls
         | None -> ())
    | IRIfElseChain (conditions_and_bodies, final_else) ->
        List.iter (fun (_, then_body) ->
          calls := (extract_function_calls_from_ir_instrs then_body) @ !calls
        ) conditions_and_bodies;
        (match final_else with
         | Some else_instrs -> calls := (extract_function_calls_from_ir_instrs else_instrs) @ !calls
         | None -> ())
    | IRBpfLoop (_, _, _, _, body_instrs) ->
        calls := (extract_function_calls_from_ir_instrs body_instrs) @ !calls
    | IRTry (try_instrs, catch_clauses) ->
        calls := (extract_function_calls_from_ir_instrs try_instrs) @ !calls;
        List.iter (fun clause ->
          calls := (extract_function_calls_from_ir_instrs clause.catch_body) @ !calls
        ) catch_clauses
    | _ -> ()
  ) instrs;
  
  !calls

(** Extract function calls from an IR function *)
let extract_function_calls_from_ir_function ir_func =
  List.fold_left (fun acc block ->
    acc @ (extract_function_calls_from_ir_instrs block.instructions)
  ) [] ir_func.basic_blocks

(** Determine program type from function attributes *)
let get_program_type_from_attributes attr_list =
  List.fold_left (fun acc attr ->
    match attr with
    | Ast.SimpleAttribute attr_name when List.mem attr_name ["xdp"; "tc"; "kprobe"; "uprobe"; "tracepoint"; "lsm"; "cgroup_skb"] ->
        Some attr_name
    | _ -> acc
  ) None attr_list

(** Extract eBPF program information from AST *)
let extract_ebpf_programs ast =
  List.filter_map (function
    | Ast.AttributedFunction attr_func ->
        (match get_program_type_from_attributes attr_func.attr_list with
         | Some prog_type -> 
             Some (attr_func.attr_function.func_name, prog_type)
         | None -> None)
    | _ -> None
  ) ast

(** Analyze kfunc dependencies for all eBPF programs *)
let analyze_kfunc_dependencies module_name ast ir_programs =
  let (kfunc_definitions, private_functions) = extract_kfunc_and_private_functions ast in
  let ebpf_programs = extract_ebpf_programs ast in
  let kfunc_names = List.map fst kfunc_definitions in
  
  (* For each eBPF program, find which kfuncs it calls *)
  let program_dependencies = List.filter_map (fun (prog_name, prog_type) ->
    (* Find the corresponding IR function *)
    match List.find_opt (fun ir_func -> ir_func.func_name = prog_name) ir_programs with
    | Some ir_func ->
        let all_calls = extract_function_calls_from_ir_function ir_func in
        (* Filter to only kfunc calls *)
        let kfunc_calls = List.filter (fun call_name -> 
          List.mem call_name kfunc_names
        ) all_calls in
        
        if kfunc_calls <> [] then
          (* Remove duplicates *)
          let unique_kfuncs = List.sort_uniq String.compare kfunc_calls in
          Some {
            program_name = prog_name;
            program_type = prog_type;
            required_kfuncs = unique_kfuncs;
            required_modules = [module_name];  (* Currently all kfuncs are in one module *)
          }
        else
          None
    | None -> None
  ) ebpf_programs in
  
  {
    kfunc_definitions;
    private_functions;
    program_dependencies;
    module_name;
  }

(** Check if any eBPF programs have kfunc dependencies *)
let has_kfunc_dependencies dependency_info =
  dependency_info.program_dependencies <> []

(** Generate kernel module loading code for userspace *)
let generate_kmodule_loading_code dependency_info =
  if dependency_info.program_dependencies = [] then
    ""
  else
    let program_checks = String.concat "\n" (List.map (fun prog_dep ->
      let module_loads = String.concat "\n        " (List.map (fun module_name ->
        sprintf {|if (load_kernel_module("%s") != 0) return -1;|} module_name
      ) prog_dep.required_modules) in
      
      sprintf {|    if (strcmp(program_name, "%s") == 0) {
        /* Program %s requires modules: %s */
        %s
    }|} 
        prog_dep.program_name
        prog_dep.program_name
        (String.concat ", " prog_dep.required_modules)
        module_loads
    ) dependency_info.program_dependencies) in
    
    sprintf {|
/* Kernel module loading for kfunc dependencies */
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifndef __NR_finit_module
#define __NR_finit_module 313
#endif

static int finit_module(int fd, const char *param_values, int flags) {
    return syscall(__NR_finit_module, fd, param_values, flags);
}

static int load_kernel_module(const char *module_name) {
    char module_path[256];
    snprintf(module_path, sizeof(module_path), "%%s.mod.ko", module_name);
    
    /* Open the kernel module file */
    int fd = open(module_path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            printf("Warning: Kernel module file %%s not found (may already be loaded)\n", module_path);
            return 0;  /* Don't fail - module might already be loaded or available via modprobe */
        }
        printf("Failed to open kernel module file %%s: %%s\n", module_path, strerror(errno));
        return -1;
    }
    
    /* Load the module using finit_module syscall */
    int ret = finit_module(fd, "", 0);
    close(fd);
    
    if (ret == 0) {
        printf("Loaded kernel module: %%s\n", module_name);
        return 0;
    } else {
        if (errno == EEXIST) {
            printf("Kernel module %%s already loaded\n", module_name);
            return 0;  /* Module already loaded - this is fine */
        } else if (errno == EPERM) {
            printf("Permission denied loading kernel module %%s (try running as root)\n", module_name);
            return -1;
        } else {
            printf("Warning: Failed to load kernel module %%s: %%s (may already be loaded)\n", module_name, strerror(errno));
            return 0;  /* Don't fail - module might be loaded via different means */
        }
    }
}

static int ensure_kfunc_dependencies_loaded(const char *program_name) {
    /* Check which modules this program depends on */
%s
    return 0;
}
|} program_checks

(** Context for C code generation *)
type userspace_context = {
  temp_counter: int ref;
  function_name: string;
  is_main: bool;
  (* Track register to variable name mapping for better C code *)
  register_vars: (int, string) Hashtbl.t;
  (* Track variable declarations needed *)
  var_declarations: (string, ir_type) Hashtbl.t; (* var_name -> ir_type *)
  (* Track function usage for optimization *)
  function_usage: function_usage;
  (* Global variables for skeleton access *)
  global_variables: ir_global_variable list;
  mutable inlinable_registers: (int, string) Hashtbl.t;
  mutable current_function: ir_function option;
  mutable temp_var_counter: int;
}

let create_userspace_context ?(global_variables = []) () = {
  temp_counter = ref 0;
  function_name = "user_function";
  is_main = false;
  register_vars = Hashtbl.create 32;
  var_declarations = Hashtbl.create 32;
  function_usage = create_function_usage ();
  global_variables;
  inlinable_registers = Hashtbl.create 32;
  current_function = None;
  temp_var_counter = 0;
}

let create_main_context ?(global_variables = []) () = {
  temp_counter = ref 0;
  function_name = "main";
  is_main = true;
  register_vars = Hashtbl.create 32;
  var_declarations = Hashtbl.create 32;
  function_usage = create_function_usage ();
  global_variables;
  inlinable_registers = Hashtbl.create 32;
  current_function = None;
  temp_var_counter = 0;
}

let fresh_temp_var ctx prefix =
  incr ctx.temp_counter;
  sprintf "%s_%d" prefix !(ctx.temp_counter)

(** Track function usage based on instruction *)
let track_function_usage ctx instr =
  match instr.instr_desc with
  | IRCall (target, _, _) ->
      (match target with
       | DirectCall func_name ->
           (match func_name with
            | "load" -> ctx.function_usage.uses_load <- true
            | "attach" -> ctx.function_usage.uses_attach <- true
            | _ -> ())
       | FunctionPointerCall _ -> ())
  | IRMapLoad (map_val, _, _, _) 
  | IRMapStore (map_val, _, _, _) 
  | IRMapDelete (map_val, _) ->
      ctx.function_usage.uses_map_operations <- true;
      (match map_val.value_desc with
       | IRMapRef map_name ->
           if not (List.mem map_name ctx.function_usage.used_maps) then
             ctx.function_usage.used_maps <- map_name :: ctx.function_usage.used_maps
       | _ -> ())
  | IRConfigFieldUpdate (map_val, _, _, _) ->
      ctx.function_usage.uses_map_operations <- true;
      (match map_val.value_desc with
       | IRMapRef map_name ->
           if not (List.mem map_name ctx.function_usage.used_maps) then
             ctx.function_usage.used_maps <- map_name :: ctx.function_usage.used_maps
       | _ -> ())
  | IRConfigAccess (config_name, _, _) ->
      (* Track config access as map operations since configs are implemented as maps *)
      ctx.function_usage.uses_map_operations <- true;
      let config_map_name = config_name ^ "_config" in
      if not (List.mem config_map_name ctx.function_usage.used_maps) then
        ctx.function_usage.used_maps <- config_map_name :: ctx.function_usage.used_maps
  | IRStructOpsRegister (_, _) ->
      (* Struct_ops registration requires skeleton object to be loaded *)
      ctx.function_usage.uses_attach <- true
  | _ -> ()

(** Recursively track usage in all instructions *)
let rec track_usage_in_instructions ctx instrs =
  List.iter (fun instr ->
    track_function_usage ctx instr;
    match instr.instr_desc with
    | IRIf (_, then_body, else_body) ->
        track_usage_in_instructions ctx then_body;
        (match else_body with
         | Some else_instrs -> track_usage_in_instructions ctx else_instrs
         | None -> ())
    | IRIfElseChain (conditions_and_bodies, final_else) ->
        List.iter (fun (_, then_body) ->
          track_usage_in_instructions ctx then_body
        ) conditions_and_bodies;
        (match final_else with
         | Some else_instrs -> track_usage_in_instructions ctx else_instrs
         | None -> ())
    | IRBpfLoop (_, _, _, _, body_instrs) ->
        track_usage_in_instructions ctx body_instrs
    | IRTry (try_instrs, catch_clauses) ->
        track_usage_in_instructions ctx try_instrs;
        List.iter (fun clause ->
          track_usage_in_instructions ctx clause.catch_body
        ) catch_clauses
    | _ -> ()
  ) instrs

(** Collect string sizes from IR *)
let rec collect_string_sizes_from_ir_type = function
  | IRStr size -> [size]
  | IRPointer (inner_type, _) -> collect_string_sizes_from_ir_type inner_type
  | IRArray (inner_type, _, _) -> collect_string_sizes_from_ir_type inner_type

  | IRResult (ok_type, err_type) -> 
      (collect_string_sizes_from_ir_type ok_type) @ (collect_string_sizes_from_ir_type err_type)
  | _ -> []

let collect_string_sizes_from_ir_value ir_value =
  let type_sizes = collect_string_sizes_from_ir_type ir_value.val_type in
  let literal_sizes = match ir_value.value_desc with
    | IRLiteral (StringLit _) ->
        (match ir_value.val_type with
         | IRStr size -> [size]
         | _ -> [])
    | _ -> []
  in
    type_sizes @ literal_sizes

(** Collect string sizes from IR - but only those used in concatenation operations *)
let rec collect_string_concat_sizes_from_ir_expr ir_expr =
  match ir_expr.expr_desc with
  | IRValue _ir_value -> []  (* Values alone don't need concatenation helpers *)
  | IRBinOp (left, op, right) -> 
      (* Only collect sizes for string concatenation operations *)
      (match left.val_type, op, right.val_type with
       | IRStr _, IRAdd, IRStr _ ->
           (* This is a string concatenation - collect the result size *)
           (match ir_expr.expr_type with
            | IRStr result_size -> [result_size]
            | _ -> [])
       | _ -> [])  (* Other binary operations don't need concatenation helpers *)
  | IRUnOp (_, _operand) -> []  (* Unary operations don't need concatenation helpers *)
  | IRCast (_value, _target_type) -> []  (* Casts don't need concatenation helpers *)
  | IRFieldAccess (_obj, _) -> []  (* Field access doesn't need concatenation helpers *)
  | IRStructLiteral (_, field_assignments) ->
      List.fold_left (fun acc (_, field_val) ->
        acc @ (collect_string_concat_sizes_from_ir_value field_val)
      ) [] field_assignments
  | IRMatch (matched_val, arms) ->
      (* Collect string sizes from matched expression and all arms *)
      (collect_string_concat_sizes_from_ir_value matched_val) @
      (List.fold_left (fun acc arm ->
        acc @ (collect_string_concat_sizes_from_ir_value arm.ir_arm_value)
      ) [] arms)

and collect_string_concat_sizes_from_ir_value ir_value =
  match ir_value.value_desc with
  | IRLiteral _ -> []  (* Literals alone don't need concatenation helpers *)
  | _ -> []  (* Other values don't need concatenation helpers *)

let rec collect_string_concat_sizes_from_ir_instruction ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (_dest, expr) -> 
      (* Only collect from expressions that involve concatenation *)
      collect_string_concat_sizes_from_ir_expr expr
  | IRDeclareVariable (_dest, _typ, init_expr_opt) ->
      (match init_expr_opt with
       | Some init_expr -> collect_string_concat_sizes_from_ir_expr init_expr
       | None -> [])
  | IRCall (_, _args, _ret_opt) -> []  (* Function calls don't need concatenation helpers *)
  | IRReturn value_opt ->
      (match value_opt with
       | Some value -> collect_string_concat_sizes_from_ir_value value
       | None -> [])
  | IRIf (_cond, then_body, else_body) ->
      let then_sizes = List.fold_left (fun acc instr ->
        acc @ (collect_string_concat_sizes_from_ir_instruction instr)
      ) [] then_body in
      let else_sizes = match else_body with
        | Some else_instrs -> List.fold_left (fun acc instr ->
            acc @ (collect_string_concat_sizes_from_ir_instruction instr)
          ) [] else_instrs
        | None -> []
      in
      then_sizes @ else_sizes
  | IRIfElseChain (conditions_and_bodies, final_else) ->
      let chain_sizes = List.fold_left (fun acc (_cond, then_body) ->
        acc @ (List.fold_left (fun acc2 instr ->
          acc2 @ (collect_string_concat_sizes_from_ir_instruction instr)
        ) [] then_body)
      ) [] conditions_and_bodies in
      let final_sizes = match final_else with
        | Some else_instrs -> List.fold_left (fun acc instr ->
            acc @ (collect_string_concat_sizes_from_ir_instruction instr)
          ) [] else_instrs
        | None -> []
      in
      chain_sizes @ final_sizes
  | IRBpfLoop (_, _, _, _, body_instrs) ->
      List.fold_left (fun acc instr ->
        acc @ (collect_string_concat_sizes_from_ir_instruction instr)
      ) [] body_instrs
  | IRTry (try_instrs, catch_clauses) ->
      let try_sizes = List.fold_left (fun acc instr ->
        acc @ (collect_string_concat_sizes_from_ir_instruction instr)
      ) [] try_instrs in
      let catch_sizes = List.fold_left (fun acc clause ->
        acc @ (List.fold_left (fun acc2 instr ->
          acc2 @ (collect_string_concat_sizes_from_ir_instruction instr)
        ) [] clause.catch_body)
      ) [] catch_clauses in
      try_sizes @ catch_sizes
  | _ -> []  (* Other instruction types don't involve concatenation *)

and collect_string_concat_sizes_from_ir_function ir_func =
  List.fold_left (fun acc block ->
    List.fold_left (fun acc2 instr ->
      acc2 @ (collect_string_concat_sizes_from_ir_instruction instr)
    ) acc block.instructions
  ) [] ir_func.basic_blocks

and collect_string_concat_sizes_from_userspace_program userspace_prog =
  List.fold_left (fun acc func ->
    acc @ (collect_string_concat_sizes_from_ir_function func)
  ) [] userspace_prog.userspace_functions

(** Collect enum definitions from IR types *)
let collect_enum_definitions_from_userspace ?symbol_table userspace_prog =
  let enum_map = Hashtbl.create 16 in
  
  let rec collect_from_type = function
    | IREnum (name, values, _) -> Hashtbl.replace enum_map name values
    | IRPointer (inner_type, _) -> collect_from_type inner_type
    | IRArray (inner_type, _, _) -> collect_from_type inner_type
  
    | IRResult (ok_type, err_type) -> 
        collect_from_type ok_type; collect_from_type err_type
    | _ -> ()
  in
  
  let collect_from_value ir_val =
    collect_from_type ir_val.val_type;
    (* Also collect from enum constants *)
    (match ir_val.value_desc with
     | IREnumConstant (enum_name, constant_name, value) ->
         let current_values = try Hashtbl.find enum_map enum_name with Not_found -> [] in
         let updated_values = (constant_name, value) :: (List.filter (fun (name, _) -> name <> constant_name) current_values) in
         Hashtbl.replace enum_map enum_name updated_values
     | _ -> ())
  in
  
  let collect_from_expr ir_expr =
    match ir_expr.expr_desc with
    | IRValue ir_val -> collect_from_value ir_val
    | IRBinOp (left, _, right) -> 
        collect_from_value left; collect_from_value right
    | IRUnOp (_, ir_val) -> collect_from_value ir_val
    | IRCast (ir_val, target_type) -> 
        collect_from_value ir_val; collect_from_type target_type
    | IRFieldAccess (obj_val, _) -> collect_from_value obj_val
    | IRStructLiteral (_, field_assignments) ->
        List.iter (fun (_, field_val) -> collect_from_value field_val) field_assignments
    | IRMatch (matched_val, arms) ->
        (* Collect from matched expression and all arms *)
        collect_from_value matched_val;
        List.iter (fun arm -> collect_from_value arm.ir_arm_value) arms
  in
  
  let rec collect_from_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> 
        collect_from_value dest_val; collect_from_expr expr
    | IRDeclareVariable (dest_val, _typ, init_expr_opt) ->
        collect_from_value dest_val;
        (match init_expr_opt with
         | Some init_expr -> collect_from_expr init_expr
         | None -> ())
    | IRCall (_, args, ret_opt) ->
        List.iter collect_from_value args;
        (match ret_opt with Some ret_val -> collect_from_value ret_val | None -> ())
    | IRMapLoad (map_val, key_val, dest_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value dest_val
    | IRMapStore (map_val, key_val, value_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value value_val
    | IRReturn (Some ret_val) -> collect_from_value ret_val
    | IRMatchReturn (matched_val, arms) ->
        collect_from_value matched_val;
        List.iter (fun arm ->
          (match arm.match_pattern with
           | IRConstantPattern const_val -> collect_from_value const_val
           | IRDefaultPattern -> ());
          (match arm.return_action with
           | IRReturnValue ret_val -> collect_from_value ret_val
           | IRReturnCall (_, args) -> List.iter collect_from_value args
           | IRReturnTailCall (_, args, _) -> List.iter collect_from_value args)
        ) arms
    | IRIf (cond_val, then_instrs, else_instrs_opt) ->
        collect_from_value cond_val;
        List.iter collect_from_instr then_instrs;
        (match else_instrs_opt with Some instrs -> List.iter collect_from_instr instrs | None -> ())
    | IRIfElseChain (conditions_and_bodies, final_else) ->
        List.iter (fun (cond_val, then_instrs) ->
          collect_from_value cond_val;
          List.iter collect_from_instr then_instrs
        ) conditions_and_bodies;
        (match final_else with Some instrs -> List.iter collect_from_instr instrs | None -> ())
    | _ -> ()
  in
  
  let collect_from_function ir_func =
    List.iter (fun block ->
      List.iter collect_from_instr block.instructions
    ) ir_func.basic_blocks
  in
  
  (* Collect from struct fields *)
  List.iter (fun struct_def ->
    List.iter (fun (_field_name, field_type) ->
      collect_from_type field_type
    ) struct_def.struct_fields
  ) userspace_prog.userspace_structs;
  
  (* Collect from all userspace functions *)
  List.iter collect_from_function userspace_prog.userspace_functions;
  
  (* Also collect enum definitions from symbol table *)
  (match symbol_table with
  | Some st ->
      let global_symbols = Symbol_table.get_global_symbols st in
      List.iter (fun symbol ->
        match symbol.Symbol_table.kind with
        | Symbol_table.TypeDef (Ast.EnumDef (enum_name, enum_values, _kernel_defined)) ->
            let processed_values = List.map (fun (const_name, opt_value) ->
              (const_name, Option.value ~default:0 opt_value)
            ) enum_values in
            Hashtbl.replace enum_map enum_name processed_values
        | _ -> ()
      ) global_symbols
  | None -> ()); (* No symbol table provided *)
  
  enum_map

(** Generate enum definition *)
let generate_enum_definition_userspace enum_name enum_values =
  let value_count = List.length enum_values in
  let enum_variants = List.mapi (fun i (const_name, value) ->
    let line = sprintf "    %s = %d%s" const_name value (if i = value_count - 1 then "" else ",") in
    line
  ) enum_values in
  sprintf "enum %s {\n%s\n};" enum_name (String.concat "\n" enum_variants)

(** Generate all enum definitions for userspace *)
let generate_enum_definitions_userspace ?symbol_table userspace_prog =
  let enum_map = collect_enum_definitions_from_userspace ?symbol_table userspace_prog in
  if Hashtbl.length enum_map > 0 then (
    (* Filter out kernel-defined enums that are provided by kernel headers *)
    let user_defined_enums = Hashtbl.fold (fun enum_name enum_values acc ->
      if not (Kernel_types.is_well_known_ebpf_type enum_name) then
        (enum_name, enum_values) :: acc
      else
        acc
    ) enum_map [] in
    
    if List.length user_defined_enums > 0 then (
      let enum_defs = List.map (fun (enum_name, enum_values) ->
        generate_enum_definition_userspace enum_name enum_values
      ) user_defined_enums in
      "/* Enum definitions */\n" ^ (String.concat "\n\n" enum_defs) ^ "\n\n"
    ) else ""
  ) else ""

(** Generate string type definitions *)
let generate_string_typedefs _string_sizes =
  (* For userspace, we don't need complex string typedefs - just use char arrays *)
  ""

(** Collect type aliases from userspace program *)
let collect_type_aliases_from_userspace_program userspace_prog =
  let type_aliases = ref [] in
  
  let collect_from_type ir_type =
    match ir_type with
    | IRTypeAlias (name, underlying_type) ->
        if not (List.mem_assoc name !type_aliases) then
          type_aliases := (name, underlying_type) :: !type_aliases
    | _ -> ()
  in
  
  let rec collect_from_value ir_val =
    collect_from_type ir_val.val_type
  and collect_from_expr ir_expr =
    collect_from_type ir_expr.expr_type
  and collect_from_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> 
        collect_from_value dest_val; collect_from_expr expr
    | IRCall (_, args, ret_opt) ->
        List.iter collect_from_value args;
        (match ret_opt with Some ret_val -> collect_from_value ret_val | None -> ())
    | IRReturn (Some ret_val) -> collect_from_value ret_val
    | IRMatchReturn (matched_val, arms) ->
        collect_from_value matched_val;
        List.iter (fun arm ->
          (match arm.match_pattern with
           | IRConstantPattern const_val -> collect_from_value const_val
           | IRDefaultPattern -> ());
          (match arm.return_action with
           | IRReturnValue ret_val -> collect_from_value ret_val
           | IRReturnCall (_, args) -> List.iter collect_from_value args
           | IRReturnTailCall (_, args, _) -> List.iter collect_from_value args)
        ) arms
    | _ -> ()
  in
  
  let collect_from_function ir_func =
    List.iter (fun block ->
      List.iter collect_from_instr block.instructions
    ) ir_func.basic_blocks;
    (* Also collect from function parameters and return type *)
    List.iter (fun (_, param_type) -> collect_from_type param_type) ir_func.parameters;
    (match ir_func.return_type with Some ret_type -> collect_from_type ret_type | None -> ())
  in
  
  (* Collect from struct fields *)
  List.iter (fun struct_def ->
    List.iter (fun (_field_name, field_type) ->
      collect_from_type field_type
    ) struct_def.struct_fields
  ) userspace_prog.userspace_structs;
  
  (* Collect from all userspace functions *)
  List.iter collect_from_function userspace_prog.userspace_functions;
  
  List.rev !type_aliases

(** Get printf format specifier for IR type *)
let get_printf_format_specifier ir_type =
  match ir_type with
  | IRU8 -> "%u"
  | IRU16 -> "%u"
  | IRU32 -> "%u"
  | IRU64 -> "%llu"
  | IRI8 -> "%d"
  | IRI16 -> "%d"
  | IRI32 -> "%d"
  | IRI64 -> "%lld"
  | IRBool -> "%d"
  | IRChar -> "%c"
  | IRF32 -> "%f"
  | IRF64 -> "%f"
  | IRStr _ -> "%s"
  | IRPointer _ -> "%p"
  | _ -> "%d"  (* fallback *)

(** Fix format specifiers in a format string based on argument types *)
let fix_format_specifiers format_string arg_types =
  let format_chars = String.to_seq format_string |> List.of_seq in
  let rec fix_formats chars arg_types_list acc =
    match chars with
    | [] -> String.concat "" (List.rev acc)
    | '%' :: '%' :: rest ->
        (* Escaped % - keep as is *)
        fix_formats rest arg_types_list ("%%" :: acc)
    | '%' :: rest ->
        (* Format specifier - find the end and replace *)
        let rec find_spec_end spec_chars =
          match spec_chars with
          | [] -> ([], [])
          | ('d' | 'i' | 'u' | 'o' | 'x' | 'X' | 'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'c' | 's' | 'p' | 'n') :: rest ->
              (spec_chars, rest)
          | c :: rest ->
              let (spec, remaining) = find_spec_end rest in
              (c :: spec, remaining)
        in
        let (spec_chars, remaining) = find_spec_end rest in
        (match arg_types_list with
         | [] -> fix_formats remaining [] (String.concat "" (List.rev_map (String.make 1) spec_chars) :: "%" :: acc)
         | arg_type :: rest_types ->
             let new_spec = get_printf_format_specifier arg_type in
             fix_formats remaining rest_types (new_spec :: acc))
    | c :: rest ->
        (* Regular character - keep as is *)
        fix_formats rest arg_types_list (String.make 1 c :: acc)
  in
  fix_formats format_chars arg_types []



(** Generate type alias definitions for userspace *)
let generate_type_alias_definitions_userspace type_aliases =
  if type_aliases <> [] then (
    let type_alias_defs = List.map (fun (alias_name, underlying_type) ->
      let c_type = c_type_from_ir_type underlying_type in
      sprintf "typedef %s %s;" c_type alias_name
    ) type_aliases in
    "/* Type alias definitions */\n" ^ (String.concat "\n" type_alias_defs) ^ "\n\n"
  ) else ""

(** Generate type alias definitions for userspace from AST types *)
let generate_type_alias_definitions_userspace_from_ast type_aliases =
  if type_aliases <> [] then (
    let type_alias_defs = List.map (fun (alias_name, underlying_type) ->
      match underlying_type with
        | Ast.Array (element_type, size) ->
            let element_c_type = match element_type with
              | Ast.U8 -> "uint8_t"
              | Ast.U16 -> "uint16_t"
              | Ast.U32 -> "uint32_t"
              | Ast.U64 -> "uint64_t"
              | _ -> "uint8_t"
            in
            (* Array typedef syntax: typedef element_type alias_name[size]; *)
            sprintf "typedef %s %s[%d];" element_c_type alias_name size
        | _ ->
            let c_type = match underlying_type with
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
              | _ -> "uint32_t" (* fallback *)
            in
            sprintf "typedef %s %s;" c_type alias_name
    ) type_aliases in
    "/* Type alias definitions */\n" ^ (String.concat "\n" type_alias_defs) ^ "\n\n"
  ) else ""

(** Determine which ELF section a global variable belongs to *)
let determine_global_var_section (global_var : ir_global_variable) =
  match global_var.global_var_init with
  | None -> "bss"  (* Uninitialized variables go to .bss *)
  | Some init_val ->
      (match init_val.value_desc with
         | IRLiteral (Ast.IntLit (0, _)) -> "bss"      (* Zero-initialized integers go to .bss *)
  | IRLiteral (Ast.BoolLit false) -> "bss"      (* False booleans go to .bss *)
  | IRLiteral (Ast.NullLit) -> "bss"            (* Null pointers go to .bss *)
  | IRLiteral (Ast.NoneLit) -> "bss"            (* None values go to .bss *)
  | IRLiteral (Ast.IntLit (_, _)) -> "data"     (* Non-zero integers go to .data *)
  | IRLiteral (Ast.BoolLit true) -> "data"      (* True booleans go to .data *)
  | IRLiteral (Ast.StringLit _) -> "data"       (* String literals go to .data *)
  | IRLiteral (Ast.CharLit _) -> "data"         (* Character literals go to .data *)
  | IRLiteral (Ast.ArrayLit _) -> "data"        (* Array literals go to .data *)
       | _ -> "bss"  (* Default to .bss for unknown initialization *)
      )

(** Generate string helper functions *)
let generate_string_helpers string_sizes =
  (* Generate concatenation helper functions for each string size *)
  let concat_helpers = List.map (fun size ->
    sprintf {|static inline char* str_concat_%d(const char* left, const char* right) {
    static char result[%d];
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    if (left_len + right_len < %d) {
        strcpy(result, left);
        strcat(result, right);
    } else {
        strncpy(result, left, %d - 1);
        result[%d - 1] = '\0';
    }
    return result;
}|} size size size size size
  ) (List.sort_uniq compare string_sizes) in
  
  if concat_helpers = [] then ""
  else "/* String helper functions */\n" ^ (String.concat "\n\n" concat_helpers) ^ "\n\n"

(** Get or create a meaningful variable name for a register *)
let get_register_var_name ctx reg_id ir_type =
  match Hashtbl.find_opt ctx.register_vars reg_id with
  | Some var_name -> var_name
  | None ->
      let var_name = sprintf "var_%d" reg_id in
      Hashtbl.add ctx.register_vars reg_id var_name;
      (* Store the IR type directly *)
      if not (Hashtbl.mem ctx.var_declarations var_name) then
        Hashtbl.add ctx.var_declarations var_name ir_type;
      var_name

(** Generate proper C declaration for any IR type with variable name *)
let generate_c_declaration ir_type var_name =
  match ir_type with
  | IRFunctionPointer (param_types, return_type) ->
      let return_type_str = c_type_from_ir_type return_type in
      let param_types_str = List.map c_type_from_ir_type param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "%s (*%s)(%s)" return_type_str var_name params_str
  | IRStr size -> sprintf "char %s[%d]" var_name size
  | IRArray (element_type, size, _) ->
      let element_type_str = c_type_from_ir_type element_type in
      sprintf "%s %s[%d]" element_type_str var_name size
  | _ -> sprintf "%s %s" (c_type_from_ir_type ir_type) var_name

(** Generate C value from IR value *)
let rec generate_c_value_from_ir ?(auto_deref_map_access=false) ctx ir_value =
  let base_result = match ir_value.value_desc with
  | IRLiteral (IntLit (i, original_opt)) -> 
      (* Use original format if available, otherwise use decimal *)
      (match original_opt with
       | Some orig when String.contains orig 'x' || String.contains orig 'X' -> orig
       | Some orig when String.contains orig 'b' || String.contains orig 'B' -> orig
       | _ -> string_of_int i)
  | IRLiteral (CharLit c) -> sprintf "'%c'" c
  | IRLiteral (BoolLit b) -> if b then "true" else "false"
  | IRLiteral (NullLit) -> "NULL"
  | IRLiteral (NoneLit) -> "/* none */"
  | IRLiteral (StringLit s) -> 
      (* Generate simple string literal for userspace *)
      sprintf "\"%s\"" s
  | IRLiteral (ArrayLit init_style) -> 
      (* Generate C array initialization syntax *)
      (match init_style with
       | ZeroArray -> "{0}"  (* Empty array initialization *)
       | FillArray fill_lit ->
           let fill_str = match fill_lit with
             | Ast.IntLit (i, _) -> string_of_int i
             | Ast.BoolLit b -> if b then "true" else "false"
             | Ast.CharLit c -> sprintf "'%c'" c
             | Ast.StringLit s -> sprintf "\"%s\"" s
             | Ast.NullLit -> "NULL"
             | Ast.NoneLit -> "/* none */"
             | Ast.ArrayLit _ -> "{...}" (* nested arrays simplified *)
           in
           sprintf "{%s}" fill_str
       | ExplicitArray elems ->
           let elem_strs = List.map (function
             | Ast.IntLit (i, _) -> string_of_int i
             | Ast.CharLit c -> sprintf "'%c'" c
             | Ast.BoolLit b -> if b then "true" else "false"
             | Ast.StringLit s -> sprintf "\"%s\"" s
             | Ast.NullLit -> "NULL"
             | Ast.NoneLit -> "/* none */"
             | Ast.ArrayLit _ -> "{...}" (* nested arrays simplified *)
           ) elems in
           sprintf "{%s}" (String.concat ", " elem_strs))
  | IRVariable name -> 
      (* Check if this is a global variable that should be accessed through skeleton *)
      let is_global = List.exists (fun gv -> gv.global_var_name = name) ctx.global_variables in
      if is_global then
        (* Access global variable through skeleton *)
        let global_var = List.find (fun gv -> gv.global_var_name = name) ctx.global_variables in
        if global_var.is_local then
          (* Local global variables are not accessible from userspace *)
          failwith (Printf.sprintf "Local global variable '%s' is not accessible from userspace" name)
        else if global_var.is_pinned then
          (* Pinned global variables are accessed through map lookup *)
          sprintf "({ struct pinned_globals_struct __pg; uint32_t __key = 0; if (bpf_map_lookup_elem(pinned_globals_map_fd, &__key, &__pg) == 0) __pg.%s; else (typeof(__pg.%s)){0}; })" name name
        else
          (* Regular shared global variables are accessed through skeleton - determine correct section *)
          let section = determine_global_var_section global_var in
          sprintf "obj->%s->%s" section name
      else
        name  (* Function parameters and regular variables use their names directly *)
  | IRRegister reg_id -> get_register_var_name ctx reg_id ir_value.val_type
  | IRContextField (_ctx_type, field) -> sprintf "ctx->%s" field
  | IRMapRef map_name -> sprintf "%s_fd" map_name
  | IREnumConstant (_enum_name, constant_name, _value) ->
      (* Generate enum constant name instead of numeric value *)
      constant_name
  | IRFunctionRef function_name ->
      (* Generate function reference (just the function name) *)
      function_name
  | IRMapAccess (_, _, (underlying_desc, underlying_type)) ->
      (* Map access semantics: 
         - Default: return the dereferenced value (kernelscript semantics)
         - Special contexts (address-of, none comparisons): return the pointer
      *)
      let underlying_val = { value_desc = underlying_desc; val_type = underlying_type; stack_offset = None; bounds_checked = false; val_pos = ir_value.val_pos } in
      let ptr_str = generate_c_value_from_ir ~auto_deref_map_access:false ctx underlying_val in
      
      if auto_deref_map_access then
        (* Return the dereferenced value (default kernelscript semantics) *)
        (* For map access, the underlying_type is the pointer type, so we need to dereference it *)
        let deref_type = match underlying_type with
          | IRPointer (inner_type, _) -> inner_type
          | other_type -> other_type
        in
        sprintf "({ %s __val = {0}; if (%s) { __val = *(%s); } __val; })" 
          (c_type_from_ir_type deref_type) ptr_str ptr_str
      else
                 (* Return the pointer (for address-of operations and none comparisons) *)
         ptr_str
   in
  
  (* The auto_deref_map_access flag is now used to control whether to return 
     the value (true - default) or the pointer (false - for special contexts) *)
  base_result

(** Generate C expression from IR expression *)
let generate_c_expression_from_ir ctx ir_expr =
  match ir_expr.expr_desc with
  | IRValue ir_value -> 
      (* For IRMapAccess values, auto-dereference by default to return the value *)
      (match ir_value.value_desc with
       | IRMapAccess (_, _, _) -> generate_c_value_from_ir ~auto_deref_map_access:true ctx ir_value
       | _ -> generate_c_value_from_ir ctx ir_value)
  | IRBinOp (left_val, op, right_val) ->
      (* Check if this is a string operation *)
      (match left_val.val_type, op, right_val.val_type with
       | IRStr _, IRAdd, IRStr _ ->
           (* String concatenation - avoid compound literals by using helper function *)
           let left_str = generate_c_value_from_ir ctx left_val in
           let right_str = generate_c_value_from_ir ctx right_val in
           let result_size = match ir_expr.expr_type with
             | IRStr size -> size
             | _ -> 256 (* fallback size *)
           in
           (* Instead of compound literal, generate a function call that will be expanded *)
           sprintf "str_concat_%d(%s, %s)" result_size left_str right_str
       | IRStr _, IREq, IRStr _ ->
           (* String equality - use strcmp *)
           let left_str = generate_c_value_from_ir ctx left_val in
           let right_str = generate_c_value_from_ir ctx right_val in
           sprintf "(strcmp(%s, %s) == 0)" left_str right_str
       | IRStr _, IRNe, IRStr _ ->
           (* String inequality - use strcmp *)
           let left_str = generate_c_value_from_ir ctx left_val in
           let right_str = generate_c_value_from_ir ctx right_val in
           sprintf "(strcmp(%s, %s) != 0)" left_str right_str
       | IRStr _, IRAdd, _ when (match right_val.val_type with IRU32 | IRU16 | IRU8 -> true | _ -> false) ->
           (* String indexing: str[index] *)
           let array_str = generate_c_value_from_ir ctx left_val in
           let index_str = generate_c_value_from_ir ctx right_val in
           sprintf "%s[%s]" array_str index_str
       | _ ->
           (* Check for none comparisons first *)
           (match left_val.value_desc, op, right_val.value_desc with
            | _, IREq, IRLiteral (Ast.NoneLit) 
            | IRLiteral (Ast.NoneLit), IREq, _ ->
                (* Comparison with none: check if pointer is NULL *)
                let non_none_val = if left_val.value_desc = IRLiteral (Ast.NoneLit) then right_val else left_val in
                (* For IRMapAccess, use the underlying pointer directly for NULL check *)
                let val_str = (match non_none_val.value_desc with
                  | IRMapAccess (_, _, _) -> generate_c_value_from_ir ~auto_deref_map_access:false ctx non_none_val
                  | _ -> generate_c_value_from_ir ctx non_none_val) in
                sprintf "(%s == NULL)" val_str
            | _, IRNe, IRLiteral (Ast.NoneLit)
            | IRLiteral (Ast.NoneLit), IRNe, _ ->
                (* Not-equal comparison with none: check if pointer is not NULL *)
                let non_none_val = if left_val.value_desc = IRLiteral (Ast.NoneLit) then right_val else left_val in
                (* For IRMapAccess, use the underlying pointer directly for NULL check *)
                let val_str = (match non_none_val.value_desc with
                  | IRMapAccess (_, _, _) -> generate_c_value_from_ir ~auto_deref_map_access:false ctx non_none_val
                  | _ -> generate_c_value_from_ir ctx non_none_val) in
                sprintf "(%s != NULL)" val_str
            | _ ->
                (* Regular binary operation - auto-dereference map access for operands *)
                let left_str = (match left_val.value_desc with
                  | IRMapAccess (_, _, _) -> generate_c_value_from_ir ~auto_deref_map_access:true ctx left_val
                  | _ -> generate_c_value_from_ir ctx left_val) in
                let right_str = (match right_val.value_desc with  
                  | IRMapAccess (_, _, _) -> generate_c_value_from_ir ~auto_deref_map_access:true ctx right_val
                  | _ -> generate_c_value_from_ir ctx right_val) in
                let op_str = match op with
                  | IRAdd -> "+"
                  | IRSub -> "-"
                  | IRMul -> "*"
                  | IRDiv -> "/"
                  | IRMod -> "%"
                  | IREq -> "=="
                  | IRNe -> "!="
                  | IRLt -> "<"
                  | IRLe -> "<="
                  | IRGt -> ">"
                  | IRGe -> ">="
                  | IRAnd -> "&&"
                  | IROr -> "||"
                  | IRBitAnd -> "&"
                  | IRBitOr -> "|"
                  | IRBitXor -> "^"
                  | IRShiftL -> "<<"
                  | IRShiftR -> ">>"
                in
                sprintf "(%s %s %s)" left_str op_str right_str))
  | IRUnOp (op, operand_val) ->
      (match op with
       | IRAddressOf ->
           (* Address-of operation: for map access, return the pointer directly *)
           (match operand_val.value_desc with
            | IRMapAccess (_, _, _) -> 
                (* For map access address-of, return the underlying pointer *)
                generate_c_value_from_ir ~auto_deref_map_access:false ctx operand_val
            | _ ->
                (* For other values, take address normally *)
                let operand_str = generate_c_value_from_ir ctx operand_val in
                sprintf "&%s" operand_str)
       | _ ->
           (* For other unary operations, auto-dereference map access *)
           let operand_str = (match operand_val.value_desc with
             | IRMapAccess (_, _, _) -> generate_c_value_from_ir ~auto_deref_map_access:true ctx operand_val
             | _ -> generate_c_value_from_ir ctx operand_val) in
           let op_str = match op with
             | IRNot -> "!"
             | IRNeg -> "-"
             | IRBitNot -> "~"
             | IRDeref -> "*"
             | _ -> failwith "Unexpected unary op"
           in
           sprintf "%s%s" op_str operand_str)
  | IRCast (value, target_type) ->
      (* Handle string type conversions *)
      (match value.val_type, target_type with
       | IRStr _src_size, IRStr _dest_size ->
           (* For userspace, strings are just char arrays - no special conversion needed *)
           let value_str = generate_c_value_from_ir ctx value in
           value_str  (* Direct use since both are char* in userspace *)
       | _ ->
           let value_str = generate_c_value_from_ir ctx value in
           let type_str = c_type_from_ir_type target_type in
           sprintf "((%s)%s)" type_str value_str)
  | IRFieldAccess (obj_val, field) ->
      let obj_str = generate_c_value_from_ir ctx obj_val in
      (* Use arrow syntax for pointer types, dot syntax for others *)
      (match obj_val.val_type with
       | IRPointer _ -> sprintf "%s->%s" obj_str field
       | _ -> sprintf "%s.%s" obj_str field)
  
  | IRStructLiteral (_struct_name, field_assignments) ->
      (* Generate C struct literal: {.field1 = value1, .field2 = value2} *)
      let field_strs = List.map (fun (field_name, field_val) ->
        let field_value_str = generate_c_value_from_ir ctx field_val in
        sprintf ".%s = %s" field_name field_value_str
      ) field_assignments in
      sprintf "{%s}" (String.concat ", " field_strs)

  | IRMatch (matched_val, arms) ->
      (* Generate switch statement for userspace *)
      let matched_str = generate_c_value_from_ir ctx matched_val in
      let temp_var = fresh_temp_var ctx "match_result" in
      let result_type = c_type_from_ir_type ir_expr.expr_type in
      
      (* Generate temporary variable for the result *)
      let decl = sprintf "%s %s;" result_type temp_var in
      
      (* Generate switch statement *)
      let switch_header = sprintf "switch (%s) {" matched_str in
      let switch_arms = List.map (fun arm ->
        let arm_val_str = generate_c_value_from_ir ctx arm.ir_arm_value in
        match arm.ir_arm_pattern with
        | IRConstantPattern const_val ->
            let const_str = generate_c_value_from_ir ctx const_val in
            sprintf "case %s: %s = %s; break;" const_str temp_var arm_val_str
        | IRDefaultPattern ->
            sprintf "default: %s = %s; break;" temp_var arm_val_str
      ) arms in
      let switch_footer = "}" in
      
      (* Combine everything and return the temp variable *)
      let switch_code = String.concat "\n" ([decl; switch_header] @ switch_arms @ [switch_footer]) in
      sprintf "({ %s; %s; })" switch_code temp_var

(** Generate map operations from IR *)
let generate_map_load_from_ir ctx map_val key_val dest_val load_type =
  let map_str = generate_c_value_from_ir ctx map_val in
  let dest_str = generate_c_value_from_ir ctx dest_val in
  
  match load_type with
  | DirectLoad ->
      sprintf "%s = *%s;" dest_str map_str
  | MapLookup ->
      (* Map lookup returns pointer directly - same as eBPF *)
      (match key_val.value_desc with
        | IRLiteral _ -> 
            let temp_key = fresh_temp_var ctx "key" in
            let key_type = c_type_from_ir_type key_val.val_type in
            let key_str = generate_c_value_from_ir ctx key_val in
            sprintf "%s %s = %s;\n    %s = bpf_map_lookup_elem(%s, &%s);" 
              key_type temp_key key_str dest_str map_str temp_key
        | _ -> 
            let key_str = generate_c_value_from_ir ctx key_val in
            sprintf "%s = bpf_map_lookup_elem(%s, &(%s));" 
              dest_str map_str key_str)
  | MapPeek ->
      sprintf "%s = bpf_ringbuf_reserve(%s, sizeof(*%s), 0);" dest_str map_str dest_str

let generate_map_store_from_ir ctx map_val key_val value_val store_type =
  let map_str = generate_c_value_from_ir ctx map_val in
  
  match store_type with
  | DirectStore ->
      let value_str = generate_c_value_from_ir ctx value_val in
      sprintf "*%s = %s;" map_str value_str
  | MapUpdate ->
      let key_var = match key_val.value_desc with
        | IRLiteral _ -> 
            let temp_key = fresh_temp_var ctx "key" in
            let key_type = c_type_from_ir_type key_val.val_type in
            let key_str = generate_c_value_from_ir ctx key_val in
            (temp_key, sprintf "%s %s = %s;" key_type temp_key key_str)
        | _ -> 
            let key_str = generate_c_value_from_ir ctx key_val in
            (key_str, "")
      in
      
      let value_var = match value_val.value_desc with
        | IRLiteral _ ->
            let temp_value = fresh_temp_var ctx "value" in
            let value_type = c_type_from_ir_type value_val.val_type in
            let value_str = generate_c_value_from_ir ctx value_val in
            (temp_value, sprintf "%s %s = %s;" value_type temp_value value_str)
        | _ -> 
            let value_str = generate_c_value_from_ir ctx value_val in
            (value_str, "")
      in
      
      let (key_name, key_decl) = key_var in
      let (value_name, value_decl) = value_var in
      let setup = [key_decl; value_decl] |> List.filter (fun s -> s <> "") |> String.concat "\n    " in
      let setup_str = if setup = "" then "" else setup ^ "\n    " in
      sprintf "%sbpf_map_update_elem(%s, &%s, &%s, BPF_ANY);" setup_str map_str key_name value_name
  | MapPush ->
      let value_str = generate_c_value_from_ir ctx value_val in
      sprintf "bpf_ringbuf_submit(%s, 0);" value_str

let generate_map_delete_from_ir ctx map_val key_val =
  let map_str = generate_c_value_from_ir ctx map_val in
  
  match key_val.value_desc with
    | IRLiteral _ -> 
        let temp_key = fresh_temp_var ctx "key" in
        let key_type = c_type_from_ir_type key_val.val_type in
        let key_str = generate_c_value_from_ir ctx key_val in
        sprintf "%s %s = %s;\n    bpf_map_delete_elem(%s, &%s);" key_type temp_key key_str map_str temp_key
    | _ -> 
        let key_str = generate_c_value_from_ir ctx key_val in
        sprintf "bpf_map_delete_elem(%s, &(%s));" map_str key_str

(** Global config names collector *)
let global_config_names = ref []

(** Generate config field update instruction from IR *)
let generate_config_field_update_from_ir ctx map_val key_val field value_val =
  let map_str = generate_c_value_from_ir ctx map_val in
  let value_str = generate_c_value_from_ir ctx value_val in
  let key_str = generate_c_value_from_ir ctx key_val in
  
  (* Extract config name from map name (e.g., "&network" -> "network") *)
  let clean_map_str = if String.get map_str 0 = '&' then 
    String.sub map_str 1 (String.length map_str - 1)
  else map_str in
  let config_name = if String.contains clean_map_str '_' then
    let parts = String.split_on_char '_' clean_map_str in
    List.hd parts
  else clean_map_str in
  
  let temp_struct = fresh_temp_var ctx "config" in
  let temp_key = fresh_temp_var ctx "key" in
  
  (* Add config name to global collection during processing *)
  if not (List.mem config_name !global_config_names) then (
    global_config_names := config_name :: !global_config_names
  );
  sprintf {|    struct %s_config %s;
    uint32_t %s = %s;
    // Load current config from map
    if (bpf_map_lookup_elem(%s_config_map_fd, &%s, &%s) == 0) {
        // Update the field
        %s.%s = %s;
        // Write back to map
        bpf_map_update_elem(%s_config_map_fd, &%s, &%s, BPF_ANY);
    }|} 
    config_name temp_struct temp_key key_str config_name temp_key temp_struct
    temp_struct field value_str config_name temp_key temp_struct



(** Generate variable assignment with optional const keyword *)
let generate_variable_assignment ctx dest src is_const =
  let assignment_prefix = if is_const then "const " else "" in
  let src_str = generate_c_expression_from_ir ctx src in
  
  (* Check if this is a global variable assignment - handle specially *)
  match dest.value_desc with
  | IRVariable name ->
      let is_global = List.exists (fun gv -> gv.global_var_name = name) ctx.global_variables in
      if is_global then
        (* Global variable assignment - add null check to prevent segfault *)
        let global_var = List.find (fun gv -> gv.global_var_name = name) ctx.global_variables in
        if global_var.is_local then
          (* Local global variables are not accessible from userspace *)
          failwith (Printf.sprintf "Local global variable '%s' is not accessible from userspace" name)
        else if global_var.is_pinned then
          (* Pinned global variable assignment through map update *)
          sprintf "{ struct pinned_globals_struct __pg; uint32_t __key = 0; if (bpf_map_lookup_elem(pinned_globals_map_fd, &__key, &__pg) == 0) { __pg.%s = %s; bpf_map_update_elem(pinned_globals_map_fd, &__key, &__pg, BPF_ANY); } }" name src_str
        else
          (* Regular global variable assignment through skeleton - determine correct section *)
          let section = determine_global_var_section global_var in
          sprintf "%sobj->%s->%s = %s;" assignment_prefix section name src_str
      else
        (* Regular variable assignment *)
        let dest_str = generate_c_value_from_ir ctx dest in
        (* For string assignments, use safer approach to avoid truncation warnings *)
        let result = (match dest.val_type with
         | IRStr size -> 
             sprintf "%s{ size_t __src_len = strlen(%s); if (__src_len < %d) { strcpy(%s, %s); } else { strncpy(%s, %s, %d - 1); %s[%d - 1] = '\\0'; } }" assignment_prefix src_str size dest_str src_str dest_str src_str size dest_str size
         | _ -> 
             sprintf "%s%s = %s;" assignment_prefix dest_str src_str) in
        
        (* Transfer success flag from source to destination for map lookup results *)
        (match dest.value_desc, src.expr_desc with
                | IRRegister _dest_reg, IRValue src_val ->
           (match src_val.value_desc with
            | IRRegister _src_reg ->
                (* Success flag tracking no longer needed with simplified approach *)
                ()
            | _ -> ())
       | _ -> ());
        
        result
  | _ ->
      (* Non-variable assignment (registers, etc.) *)
      let dest_str = generate_c_value_from_ir ctx dest in
      (* For string assignments, use safer approach to avoid truncation warnings *)
      let result = (match dest.val_type with
       | IRStr size -> 
           sprintf "%s{ size_t __src_len = strlen(%s); if (__src_len < %d) { strcpy(%s, %s); } else { strncpy(%s, %s, %d - 1); %s[%d - 1] = '\\0'; } }" assignment_prefix src_str size dest_str src_str dest_str src_str size dest_str size
       | _ -> 
           sprintf "%s%s = %s;" assignment_prefix dest_str src_str) in
      
      (* Transfer success flag from source to destination for map lookup results *)
      (match dest.value_desc, src.expr_desc with
       | IRRegister _dest_reg, IRValue src_val ->
           (match src_val.value_desc with
            | IRRegister _src_reg ->
                (* Success flag tracking no longer needed with simplified approach *)
                ()
            | _ -> ())
       | _ -> ());
      
      result

(** Generate C code for truthy/falsy conversion in userspace *)
let generate_truthy_conversion_userspace ctx ir_value =
  match ir_value.val_type with
  | IRBool -> 
      (* Already boolean, use as-is *)
      generate_c_value_from_ir ctx ir_value
  | IRU8 | IRU16 | IRU32 | IRU64 | IRI8 | IRI16 | IRI32 | IRI64 ->
      (* Numbers: 0 is falsy, non-zero is truthy *)
      sprintf "(%s != 0)" (generate_c_value_from_ir ctx ir_value)
  | IRChar ->
      (* Characters: '\0' is falsy, others truthy *)
      sprintf "(%s != '\\0')" (generate_c_value_from_ir ctx ir_value)
  | IRStr _ ->
      (* Strings: empty is falsy, non-empty is truthy *)
      sprintf "(strlen(%s) > 0)" (generate_c_value_from_ir ctx ir_value)
  | IRPointer (_, _) ->
      (* Pointers: null is falsy, non-null is truthy *)
      sprintf "(%s != NULL)" (generate_c_value_from_ir ctx ir_value)
  | IREnum (_, _, _) ->
      (* Enums: based on numeric value *)
      sprintf "(%s != 0)" (generate_c_value_from_ir ctx ir_value)
  | _ ->
      (* This should never be reached due to type checking *)
      failwith ("Internal error: Type " ^ (string_of_ir_type ir_value.val_type) ^ " cannot be used in boolean context")

(** Generate C instruction from IR instruction *)
let rec generate_c_instruction_from_ir ctx instruction =
  match instruction.instr_desc with
  | IRAssign (dest, src) ->
      (* Regular assignment without const keyword *)
      generate_variable_assignment ctx dest src false
      
  | IRConstAssign (dest, src) ->
      (* Const assignment with const keyword *)
      generate_variable_assignment ctx dest src true
      
  | IRDeclareVariable (dest_val, typ, init_expr_opt) ->
      (* Variable declaration with optional initialization *)
      let var_name = match dest_val.value_desc with
        | IRVariable name -> name
        | IRRegister reg -> sprintf "temp_%d" reg
        | _ -> failwith "IRDeclareVariable target must be a variable or register"
      in
      
      (* Special handling for different types in variable declarations *)
      (match typ with
       | IRStr size ->
           (* String declaration with proper C array syntax *)
           let string_decl = sprintf "char %s[%d]" var_name size in
           (match init_expr_opt with
            | Some init_expr ->
                (* Use the existing string assignment logic for safe string handling *)
                let assignment = generate_variable_assignment ctx dest_val init_expr false in
                sprintf "%s;\n    %s" string_decl assignment
            | None ->
                sprintf "%s;" string_decl)
       | IRArray (element_type, size, _) ->
           (* Array declaration with proper C syntax *)
           let element_type_str = c_type_from_ir_type element_type in
           let array_decl = sprintf "%s %s[%d]" element_type_str var_name size in
           (match init_expr_opt with
            | Some init_expr ->
                let init_str = generate_c_expression_from_ir ctx init_expr in
                sprintf "%s = %s;" array_decl init_str
            | None ->
                sprintf "%s;" array_decl)
       | _ ->
           (* Regular variable declaration - use proper C declaration generator *)
           let decl_str = generate_c_declaration typ var_name in
           (match init_expr_opt with
            | Some init_expr ->
                let init_str = generate_c_expression_from_ir ctx init_expr in
                sprintf "%s = %s;" decl_str init_str
            | None ->
                sprintf "%s;" decl_str))
      
  | IRCall (target, args, ret_opt) ->
      (* Track function usage for optimization *)
      track_function_usage ctx instruction;
      
      (* Handle different call targets *)
      let (actual_name, translated_args) = match target with
        | DirectCall name ->
            (* Check for module calls (contain dots) and transform them *)
            let actual_function_name = if String.contains name '.' then
              (* Module call like "utils.validate_config" -> "utils_validate_config" *)
              String.map (function '.' -> '_' | c -> c) name
            else name in
            
            (* Check if this is a built-in function that needs context-specific translation *)
            (match Stdlib.get_userspace_implementation actual_function_name with
        | Some userspace_impl ->
            (* This is a built-in function - translate for userspace context *)
            let c_args = List.map (generate_c_value_from_ir ctx) args in
            (match name with
             | "print" -> 
                 (* Special handling for print: convert to printf format with proper type specifiers *)
                 (match c_args, args with
                  | [], [] -> (userspace_impl, ["\"\\n\""])
                  | [first], [_] -> 
                      (* For single string argument, check if we need to append newline to format string *)
                      let format_str = first in
                      let fixed_format = match format_str with
                        | str when String.length str >= 2 && String.get str 0 = '"' && String.get str (String.length str - 1) = '"' ->
                            (* Remove quotes, add newline, add quotes back *)
                            let inner_str = String.sub str 1 (String.length str - 2) in
                            sprintf "\"%s\\n\"" inner_str
                        | str -> 
                            (* Non-quoted string - add newline *)
                            sprintf "%s \"\\n\"" str
                      in
                      (userspace_impl, [fixed_format])
                  | format_arg :: rest_args, _ :: rest_ir_args ->
                      (* Extract the format string and fix format specifiers based on argument types *)
                      let format_str = format_arg in
                      let arg_types = List.map (fun ir_val -> ir_val.val_type) rest_ir_args in
                      let fixed_format = match format_str with
                        | str when String.length str >= 2 && String.get str 0 = '"' && String.get str (String.length str - 1) = '"' ->
                            (* Remove quotes, fix format specifiers, add newline, add quotes back *)
                            let inner_str = String.sub str 1 (String.length str - 2) in
                            let fixed_str = fix_format_specifiers inner_str arg_types in
                            sprintf "\"%s\\n\"" fixed_str
                        | str -> 
                            (* Non-quoted string - fix as is and add newline *)
                            let fixed_str = fix_format_specifiers str arg_types in
                            sprintf "\"%s\\n\"" fixed_str
                      in
                      (userspace_impl, fixed_format :: rest_args)
                  | args, _ -> (userspace_impl, args @ ["\"\\n\""]))
             | "load" ->
                 (* Special handling for load: now lightweight - just get program handle from skeleton *)
                 ctx.function_usage.uses_load <- true;
                 (match c_args with
                  | [program_name] ->
                      (* Extract program name from identifier - remove quotes if present *)
                      let clean_name = if String.contains program_name '"' then
                        String.sub program_name 1 (String.length program_name - 2)
                      else program_name in
                      ("get_bpf_program_handle", [sprintf "\"%s\"" clean_name])
                  | _ -> failwith "load expects exactly one argument")
             | "attach" ->
                 (* Special handling for attach: now takes program handle (not program name) *)
                 ctx.function_usage.uses_attach <- true;
                 (match c_args with
                  | [program_handle; target; flags] ->
                      (* Use the program handle variable directly instead of extracting program name *)
                      ("attach_bpf_program_by_fd", [program_handle; target; flags])
                  | _ -> failwith "attach expects exactly three arguments")
             | _ -> (userspace_impl, c_args))
        | None ->
            (* Regular function call *)
            let c_args = List.map (generate_c_value_from_ir ctx) args in
            (actual_function_name, c_args))
        | FunctionPointerCall func_ptr ->
            (* Function pointer call - generate the function pointer directly *)
            let func_ptr_str = generate_c_value_from_ir ctx func_ptr in
            let c_args = List.map (generate_c_value_from_ir ctx) args in
            (func_ptr_str, c_args)
      in
      let args_str = String.concat ", " translated_args in
      let basic_call = (match ret_opt with
       | Some result -> sprintf "%s = %s(%s);" (generate_c_value_from_ir ctx result) actual_name args_str
       | None -> sprintf "%s(%s);" actual_name args_str) in
      
      (* Add error checking for load in main function *)
      if ctx.is_main && (match target with DirectCall "load" -> true | _ -> false) then
        match ret_opt with
        | Some result ->
            let result_var = generate_c_value_from_ir ctx result in
            sprintf "%s\n    if (%s < 0) {\n        fprintf(stderr, \"Failed to get BPF program handle\\n\");\n        return 1;\n    }" basic_call result_var
        | None -> basic_call
      else basic_call
  
  | IRTailCall (name, args, _index) ->
      (* Tail calls are not supported in userspace - treat as regular function call *)
      (* This is the correct behavior since tail calls are purely an eBPF optimization *)
      let args_str = String.concat ", " (List.map (generate_c_value_from_ir ctx) args) in
      sprintf "return %s(%s);" name args_str
  
  | IRReturn value_opt ->
      (match value_opt with
       | Some value -> sprintf "return %s;" (generate_c_value_from_ir ctx value)
       | None -> "return;")
  
  | IRMapLoad (map_val, key_val, dest_val, load_type) ->
      track_function_usage ctx instruction;
      generate_map_load_from_ir ctx map_val key_val dest_val load_type
  
  | IRMapStore (map_val, key_val, value_val, store_type) ->
      track_function_usage ctx instruction;
      generate_map_store_from_ir ctx map_val key_val value_val store_type
  
  | IRMapDelete (map_val, key_val) ->
      track_function_usage ctx instruction;
      generate_map_delete_from_ir ctx map_val key_val
  
  | IRConfigFieldUpdate (map_val, key_val, field, value_val) ->
      track_function_usage ctx instruction;
      generate_config_field_update_from_ir ctx map_val key_val field value_val
  
  | IRObjectNew (dest_val, obj_type) ->
      let dest_str = generate_c_value_from_ir ctx dest_val in
      let type_str = c_type_from_ir_type obj_type in
      sprintf "%s = malloc(sizeof(%s));" dest_str type_str
      
  | IRObjectNewWithFlag _ ->
      (* GFP flags should never reach userspace code generation - this is an internal error *)
      failwith ("Internal error: GFP allocation flags are not supported in userspace context. " ^
                "This should have been caught by the type checker.")
      
  | IRObjectDelete ptr_val ->
      let ptr_str = generate_c_value_from_ir ctx ptr_val in
      sprintf "free(%s);" ptr_str
  
  | IRListPushFront (result_val, _list_head, _element) ->
      (* List operations are eBPF-specific, not applicable in userspace *)
      let result_str = generate_c_value_from_ir ctx result_val in
      sprintf "%s = 0; /* list_push_front - eBPF only */" result_str
      
  | IRListPushBack (result_val, _list_head, _element) ->
      (* List operations are eBPF-specific, not applicable in userspace *)
      let result_str = generate_c_value_from_ir ctx result_val in
      sprintf "%s = 0; /* list_push_back - eBPF only */" result_str
      
  | IRListPopFront (result_val, _list_head) ->
      (* List operations are eBPF-specific, not applicable in userspace *)
      let result_str = generate_c_value_from_ir ctx result_val in
      sprintf "%s = NULL; /* list_pop_front - eBPF only */" result_str
      
  | IRListPopBack (result_val, _list_head) ->
      (* List operations are eBPF-specific, not applicable in userspace *)
      let result_str = generate_c_value_from_ir ctx result_val in
      sprintf "%s = NULL; /* list_pop_back - eBPF only */" result_str
  
  | IRStructFieldAssignment (obj_val, field_name, value_val) ->
      (* Generate struct field assignment: obj.field = value or obj->field = value *)
      let obj_str = generate_c_value_from_ir ctx obj_val in
      let value_str = generate_c_value_from_ir ctx value_val in
      (* Use arrow syntax for pointer types, dot syntax for others *)
      (match obj_val.val_type with
       | IRPointer _ -> sprintf "%s->%s = %s;" obj_str field_name value_str
       | _ -> sprintf "%s.%s = %s;" obj_str field_name value_str)
  
  | IRConfigAccess (config_name, field_name, result_val) ->
      (* Generate config access for userspace - direct struct field access *)
      let result_str = generate_c_value_from_ir ctx result_val in
      sprintf "%s = get_%s_config()->%s;" result_str config_name field_name
  
  | IRContextAccess (dest, context_type, field_name) ->
      (* Use BTF-integrated context code generation for userspace too *)
      let access_str = Kernelscript_context.Context_codegen.generate_context_field_access context_type "ctx" field_name in
      sprintf "%s = %s;" (generate_c_value_from_ir ctx dest) access_str
  
  | IRJump label ->
      sprintf "goto %s;" label
  
  | IRCondJump (condition, true_label, false_label) ->
      sprintf "if (%s) goto %s; else goto %s;" 
        (generate_c_value_from_ir ctx condition) true_label false_label
  
  | IRIf (condition, then_body, else_body) ->
      (* Generate simple if statement *)
      let cond_str = generate_truthy_conversion_userspace ctx condition in
      let then_stmts_str = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) then_body) in
      let else_part = match else_body with
        | None -> ""
        | Some else_stmts ->
            let else_stmts_str = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) else_stmts) in
            sprintf " else {\n        %s\n    }" else_stmts_str
      in
      sprintf "if (%s) {\n        %s\n    }%s" cond_str then_stmts_str else_part

  | IRIfElseChain (conditions_and_bodies, final_else) ->
      (* Generate if-else-if chains with proper C formatting *)
      let if_parts = List.mapi (fun i (cond, then_stmts) ->
        let cond_str = generate_truthy_conversion_userspace ctx cond in
        let then_stmts_str = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) then_stmts) in
        let keyword = if i = 0 then "if" else "else if" in
        sprintf "%s (%s) {\n        %s\n    }" keyword cond_str then_stmts_str
      ) conditions_and_bodies in
      
      let final_part = match final_else with
        | None -> ""
        | Some else_stmts ->
            let else_stmts_str = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) else_stmts) in
            sprintf " else {\n        %s\n    }" else_stmts_str
      in
      
      String.concat " " if_parts ^ final_part
  
  | IRBoundsCheck (value, min_val, max_val) ->
      sprintf "/* bounds check: %s in [%d, %d] */" 
        (generate_c_value_from_ir ctx value) min_val max_val
  
  | IRComment comment ->
      sprintf "/* %s */" comment
  
  | IRBpfLoop (start, end_val, counter, _ctx_val, body_instrs) ->
      let start_str = generate_c_value_from_ir ctx start in
      let end_str = generate_c_value_from_ir ctx end_val in
      let counter_str = generate_c_value_from_ir ctx counter in
      let body_stmts = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) body_instrs) in
      sprintf "for (%s = %s; %s <= %s; %s++) {\n        %s\n    }" 
        counter_str start_str counter_str end_str counter_str body_stmts
  
  | IRBreak -> "break;"
  | IRContinue -> "continue;"
  
  | IRCondReturn (condition, true_ret, false_ret) ->
      let cond_str = generate_c_value_from_ir ctx condition in
      let true_str = match true_ret with
        | Some v -> generate_c_value_from_ir ctx v
        | None -> ""
      in
      let false_str = match false_ret with
        | Some v -> generate_c_value_from_ir ctx v
        | None -> ""
      in
      if true_ret <> None && false_ret <> None then
        sprintf "return %s ? %s : %s;" cond_str true_str false_str
      else if true_ret <> None then
        sprintf "if (%s) return %s;" cond_str true_str
      else
        sprintf "if (!(%s)) return %s;" cond_str false_str

  | IRTry (try_instructions, catch_clauses) ->
      (* Generate setjmp/longjmp for userspace try/catch *)
      let try_body = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) try_instructions) in
      let catch_handlers = List.mapi (fun i catch_clause ->
        let (pattern_str, case_code) = match catch_clause.catch_pattern with
          | IntCatchPattern code -> (sprintf "error_%d" code, code)
          | WildcardCatchPattern -> ("any_error", i + 1) (* Use index for wildcard *)
        in
        sprintf "    case %d: /* catch %s */\n        /* Handle error here */\n        break;" case_code pattern_str
      ) catch_clauses in
      let catch_code = String.concat "\n" catch_handlers in
      sprintf {|{
        jmp_buf exception_buffer;
        int exception_code = setjmp(exception_buffer);
        if (exception_code == 0) {
            /* try block */
            %s
        } else {
            /* catch handlers */
            switch (exception_code) {
%s
            default:
                fprintf(stderr, "Unhandled exception: %%d\\n", exception_code);
                exit(1);
            }
        }
    }|} try_body catch_code

  | IRThrow error_code ->
      (* Generate longjmp for userspace throw *)
      let code_val = match error_code with
        | IntErrorCode code -> code
      in
      sprintf "longjmp(exception_buffer, %d); /* throw error */" code_val

  | IRDefer defer_instructions ->
      (* For userspace, generate defer using function-scope cleanup *)
      let defer_body = String.concat "\n    " (List.map (generate_c_instruction_from_ir ctx) defer_instructions) in
      sprintf "/* defer block - executed at function exit */\n    {\n    %s\n    }" defer_body
  | IRMatchReturn (matched_val, arms) ->
      (* Generate if-else chain for match expression in return position for userspace *)
      let matched_str = generate_c_value_from_ir ctx matched_val in
      
      let generate_match_arm is_first arm =
        match arm.match_pattern with
        | IRConstantPattern const_val ->
            let const_str = generate_c_value_from_ir ctx const_val in
            let keyword = if is_first then "if" else "else if" in
            let condition_part = sprintf "%s (%s == %s)" keyword matched_str const_str in
            
            (* Generate appropriate return based on the return action *)
            let action_part = match arm.return_action with
              | IRReturnValue ret_val ->
                  let ret_str = generate_c_value_from_ir ctx ret_val in
                  sprintf "return %s;" ret_str
              | IRReturnCall (func_name, args) ->
                  (* For userspace, function calls in return position are regular calls *)
                  let args_str = String.concat ", " (List.map (generate_c_value_from_ir ctx) args) in
                  sprintf "return %s(%s);" func_name args_str
              | IRReturnTailCall (func_name, args, _) ->
                  (* Tail calls are not supported in userspace - treat as regular function call *)
                  let args_str = String.concat ", " (List.map (generate_c_value_from_ir ctx) args) in
                  sprintf "return %s(%s);" func_name args_str
            in
            sprintf "%s {\n        %s\n    }" condition_part action_part
        | IRDefaultPattern ->
            let action_part = match arm.return_action with
              | IRReturnValue ret_val ->
                  let ret_str = generate_c_value_from_ir ctx ret_val in
                  sprintf "return %s;" ret_str
              | IRReturnCall (func_name, args) ->
                  (* For userspace, function calls in return position are regular calls *)
                  let args_str = String.concat ", " (List.map (generate_c_value_from_ir ctx) args) in
                  sprintf "return %s(%s);" func_name args_str
              | IRReturnTailCall (func_name, args, _) ->
                  (* Tail calls are not supported in userspace - treat as regular function call *)
                  let args_str = String.concat ", " (List.map (generate_c_value_from_ir ctx) args) in
                  sprintf "return %s(%s);" func_name args_str
            in
            sprintf "else {\n        %s\n    }" action_part
      in
      
      (* Generate all arms *)
      (match arms with
       | [] -> "/* No match arms */"
       | first_arm :: rest_arms ->
           let first_part = generate_match_arm true first_arm in
           let rest_parts = List.map (generate_match_arm false) rest_arms in
           String.concat " " (first_part :: rest_parts))
  | IRStructOpsRegister (result_val, struct_ops_val) ->
      (* Generate struct_ops registration call using skeleton API *)
      let result_str = generate_c_value_from_ir ctx result_val in
      (* For struct_ops, the struct_ops_val can be either a variable name or a direct reference to the impl block *)
      let instance_name = match struct_ops_val.value_desc with
        | IRVariable name -> name
        | IRRegister _ -> 
            (* If it's a register, get the variable name from the register *)
            generate_c_value_from_ir ctx struct_ops_val
        | _ -> 
            (* For other cases (direct impl block references), extract the name from the value *)
            (match struct_ops_val.val_type with
             | IRStruct (name, _, _) -> name
             | _ -> failwith "struct_ops register() argument must be an impl block instance")
      in
      (* Generate struct_ops registration code *)
      sprintf {|({
    if (!obj) {
        fprintf(stderr, "eBPF skeleton not loaded for struct_ops registration\n");
        %s = -1;
    } else {
        struct bpf_map *map = bpf_object__find_map_by_name(obj->obj, "%s");
        if (!map) {
            fprintf(stderr, "Failed to find struct_ops map '%s'\n");
            %s = -1;
        } else {
            struct bpf_link *link = bpf_map__attach_struct_ops(map);
            %s = (link != NULL) ? 0 : -1;
            if (link) bpf_link__destroy(link);
        }
    }
    %s;
});|} result_str instance_name instance_name result_str result_str result_str

(** Generate C struct from IR struct definition *)
let generate_c_struct_from_ir ir_struct =
  let fields_str = String.concat ";\n    " 
    (List.map (fun (field_name, field_type) ->
       (* Handle array and string types specially for correct C syntax *)
       match field_type with
       | IRStr size -> sprintf "char %s[%d]" field_name size
       | IRArray (inner_type, size, _) -> 
           sprintf "%s %s[%d]" (c_type_from_ir_type inner_type) field_name size
       | _ -> sprintf "%s %s" (c_type_from_ir_type field_type) field_name
     ) ir_struct.struct_fields)
  in
  sprintf "struct %s {\n    %s;\n};" ir_struct.struct_name fields_str
  
(** Generate proper C declaration for any IR type with variable name *)
let generate_c_declaration ir_type var_name =
  match ir_type with
  | IRFunctionPointer (param_types, return_type) ->
      let return_type_str = c_type_from_ir_type return_type in
      let param_types_str = List.map c_type_from_ir_type param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "%s (*%s)(%s)" return_type_str var_name params_str
  | IRStr size -> sprintf "char %s[%d]" var_name size
  | IRArray (element_type, size, _) ->
      let element_type_str = c_type_from_ir_type element_type in
      sprintf "%s %s[%d]" element_type_str var_name size
    | _ -> sprintf "%s %s" (c_type_from_ir_type ir_type) var_name
 
(** Generate variable declarations for a function *)
let generate_variable_declarations ctx =
  let declarations = Hashtbl.fold (fun var_name ir_type acc ->
    (generate_c_declaration ir_type var_name ^ ";") :: acc
  ) ctx.var_declarations [] in
  if declarations = [] then ""
  else "    " ^ String.concat "\n    " (List.rev declarations) ^ "\n"

(** Collect function usage information from IR function *)
let collect_function_usage_from_ir_function ?(global_variables = []) ir_func =
  let ctx = create_userspace_context ~global_variables () in
  List.iter (fun block ->
    track_usage_in_instructions ctx block.instructions
  ) ir_func.basic_blocks;
  ctx.function_usage

(** Generate config initialization from declaration defaults *)
let generate_config_initialization (config_decl : Ast.config_declaration) =
  let config_name = config_decl.config_name in
  let struct_name = sprintf "%s_config" config_name in
  
  (* Generate field initializations with default values *)
  let field_initializations = List.map (fun field ->
    let initialization = match field.Ast.field_default with
      | Some default_value -> 
          (match default_value with
           | Ast.IntLit (i, _) -> sprintf "    init_config.%s = %d;" field.Ast.field_name i
           | Ast.BoolLit b -> sprintf "    init_config.%s = %s;" field.Ast.field_name (if b then "true" else "false")
           | Ast.ArrayLit init_style ->
               (* Handle enhanced array initialization *)
               (match init_style with
                | ZeroArray -> sprintf "    /* %s defaults to zero-initialized */" field.Ast.field_name
                | FillArray fill_lit ->
                    let fill_value = match fill_lit with
                      | Ast.IntLit (value, _) -> string_of_int value
                      | Ast.BoolLit b -> if b then "1" else "0"
                      | _ -> "0"
                    in
                    sprintf "    memset(init_config.%s, %s, sizeof(init_config.%s));" field.Ast.field_name fill_value field.Ast.field_name
                | ExplicitArray elements ->
                    let elements_str = List.mapi (fun i element ->
                      match element with
                      | Ast.IntLit (value, _) -> sprintf "    init_config.%s[%d] = %d;" field.Ast.field_name i value
                      | _ -> sprintf "    init_config.%s[%d] = 0;" field.Ast.field_name i (* fallback *)
                    ) elements in
                    String.concat "\n" elements_str)
           | _ -> sprintf "    init_config.%s = 0;" field.Ast.field_name (* fallback *))
      | None -> sprintf "    init_config.%s = 0;" field.Ast.field_name (* default to 0 if no default specified *)
    in
    initialization
  ) config_decl.Ast.config_fields in
  
  sprintf {|    /* Initialize %s config map with default values */
    struct %s init_config = {0};
    uint32_t config_key = 0;
%s
    if (bpf_map_update_elem(%s_config_map_fd, &config_key, &init_config, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to initialize %s config map with default values\n");
        return -1;
    }|} config_name struct_name (String.concat "\n" field_initializations) config_name config_name

(** Generate C function from IR function *)
let generate_c_function_from_ir ?(global_variables = []) ?(base_name = "") ?(config_declarations = []) ?(ir_multi_prog = None) ?(resolved_imports = []) (ir_func : ir_function) =
  let params_str = String.concat ", " 
    (List.map (fun (name, ir_type) ->
       generate_c_declaration ir_type name
     ) ir_func.parameters)
  in
  
  let return_type_str = match ir_func.return_type with
    | Some ret_type -> c_type_from_ir_type ret_type
    | None -> "void"
  in
  
  let ctx = if ir_func.func_name = "main" then create_main_context ~global_variables () else 
    { (create_userspace_context ~global_variables ()) with function_name = ir_func.func_name } in
  
  (* Function parameters are used directly, no need for local variable copies *)
  
  (* Generate function body from basic blocks *)
  let body_parts = List.map (fun block ->
    let label_part = if block.label <> "entry" then [sprintf "%s:" block.label] else [] in
    let instr_parts = List.map (generate_c_instruction_from_ir ctx) block.instructions in
    let combined_parts = label_part @ instr_parts in
    String.concat "\n    " combined_parts
  ) ir_func.basic_blocks in
  
  let body_c = String.concat "\n    " body_parts in
  
  (* Generate variable declarations, filtering out impl block variables *)
  let var_decls = 
    let all_declarations = Hashtbl.fold (fun var_name ir_type acc ->
      let declaration = generate_c_declaration ir_type var_name ^ ";" in
      (var_name, declaration) :: acc
    ) ctx.var_declarations [] in
    
    (* Filter out impl block variables if we have ir_multi_prog *)
    let filtered_declarations = match ir_multi_prog with
      | Some multi_prog ->
          List.filter (fun (var_name, _) ->
            (* Check if this variable corresponds to a struct_ops declaration *)
            not (List.exists (fun struct_ops_decl ->
              struct_ops_decl.ir_struct_ops_name = var_name
            ) multi_prog.struct_ops_declarations)
          ) all_declarations
      | None -> all_declarations
    in
    
    if filtered_declarations = [] then ""
    else "    " ^ String.concat "\n    " (List.map snd filtered_declarations) ^ "\n"
  in
  
  let adjusted_params = if ir_func.func_name = "main" then 
    (* Main function can be either main() or main(args) - generate appropriate C signature *)
    (if List.length ir_func.parameters = 0 then "void" else "int argc, char **argv")
  else
    (if params_str = "" then "void" else params_str) in
  
  let adjusted_return_type = if ir_func.func_name = "main" then "int" else return_type_str in
  
  if ir_func.func_name = "main" then
    let args_parsing_code = 
      if List.length ir_func.parameters > 0 then
        (* Generate argument parsing for struct parameter *)
        let (param_name, param_type) = List.hd ir_func.parameters in
        (match param_type with
         | IRStruct (struct_name, _, _) ->
           sprintf "    // Parse command line arguments\n    struct %s %s = parse_arguments(argc, argv);" struct_name param_name
         | _ -> "    // No argument parsing needed")
      else
        "    // No arguments to parse"
    in
    
    (* No need to copy function parameters to local variables - use them directly *)
    let args_assignment_code = "" in
    
    (* Always load eBPF object at the beginning of main() if global variables exist or BPF functions are used *)
    let has_global_vars = List.length global_variables > 0 in
    let func_usage = collect_function_usage_from_ir_function ir_func in
    let needs_object_loading = has_global_vars || func_usage.uses_load || func_usage.uses_attach in
    let skeleton_loading_code = if needs_object_loading then
      sprintf {|    // Implicit eBPF skeleton loading - makes global variables immediately accessible
    if (!obj) {
        obj = %s_ebpf__open_and_load();
        if (!obj) {
            fprintf(stderr, "Failed to open and load eBPF skeleton\n");
            return 1;
        }
    }|} base_name
    else ""
    in
    
    (* Check if this main function uses maps and needs auto-initialization *)
    let func_usage = collect_function_usage_from_ir_function ir_func in
    let needs_auto_init = func_usage.uses_map_operations && not func_usage.uses_load in
    let auto_init_call = if needs_auto_init then
      "    \n    // Auto-initialize BPF maps\n    atexit(cleanup_bpf_maps);\n    if (init_bpf_maps() < 0) {\n        return 1;\n    }"
    else "" in
    
    (* Include setup code when object is loaded in main() *)
    let pinned_globals_vars = List.filter (fun gv -> gv.is_pinned) global_variables in
    let has_pinned_globals = List.length pinned_globals_vars > 0 in
    let setup_call = if needs_object_loading && (List.length config_declarations > 0 || func_usage.uses_map_operations || has_pinned_globals) then
      let all_setup_parts = List.filter (fun s -> s <> "") [
        (if func_usage.uses_map_operations then "    // Map setup would go here if needed" else "");
        (if has_pinned_globals then
          let project_name = base_name in
          let pin_path = sprintf "/sys/fs/bpf/%s/globals/pinned_globals" project_name in
          sprintf {|    /* Load or create pinned globals map */
    pinned_globals_map_fd = bpf_obj_get("%s");
    if (pinned_globals_map_fd < 0) {
        /* Map not pinned yet, load from eBPF object and pin it */
        struct bpf_map *pinned_globals_map = bpf_object__find_map_by_name(obj->obj, "__pinned_globals");
        if (!pinned_globals_map) {
            fprintf(stderr, "Failed to find pinned globals map in eBPF object\n");
            return 1;
        }
        /* Pin the map to the specified path */
        if (bpf_map__pin(pinned_globals_map, "%s") < 0) {
            fprintf(stderr, "Failed to pin globals map\n");
            return 1;
        }
        /* Get file descriptor after pinning */
        pinned_globals_map_fd = bpf_map__fd(pinned_globals_map);
        if (pinned_globals_map_fd < 0) {
            fprintf(stderr, "Failed to get fd for pinned globals map\n");
            return 1;
        }
    }|} pin_path pin_path
        else "");
        (if List.length config_declarations > 0 then 
          String.concat "\n" (List.map (fun config_decl ->
            let config_name = config_decl.Ast.config_name in
            let load_code = sprintf {|    
    // Load %s config map from eBPF object
    %s_config_map_fd = bpf_object__find_map_fd_by_name(obj->obj, "%s_config_map");
    if (%s_config_map_fd < 0) {
        fprintf(stderr, "Failed to find %s config map in eBPF object\n");
        return 1;
    }|} config_name config_name config_name config_name config_name in
            let init_code = generate_config_initialization config_decl in
            load_code ^ "\n" ^ init_code
          ) config_declarations)
        else "");
      ] in
      if all_setup_parts <> [] then "\n" ^ String.concat "\n" all_setup_parts else ""
    else "" in
    
    (* Add error handling notice for BPF program loading *)
    let error_handling_notice = if func_usage.uses_load then
      "    // Note: Skeleton loaded implicitly above, load() now gets program handles"
    else "" in
    
    (* Add Python initialization for main function *)
    let python_init_code = if ir_func.func_name = "main" then
      generate_python_initialization_calls resolved_imports
    else "" in
    
    (* Combine skeleton loading with other initialization *)
    let initialization_code = String.concat "\n" (List.filter (fun s -> s <> "") [
      skeleton_loading_code;
      setup_call;
      auto_init_call;
      python_init_code;
      error_handling_notice;
    ]) in
    
    (* Generate ONLY what the user explicitly wrote with skeleton loading at the beginning *)
    sprintf {|%s %s(%s) {
%s%s%s
%s
    
    %s
}|} adjusted_return_type ir_func.func_name adjusted_params var_decls args_parsing_code args_assignment_code initialization_code body_c
  else
    sprintf {|%s %s(%s) {
%s    %s
}|} adjusted_return_type ir_func.func_name adjusted_params var_decls body_c

(** Generate skeleton definitions and initialization for global variables *)
let generate_skeleton_code base_name global_variables =
  (* Use standard libbpf skeleton - no custom skeleton generation needed *)
  if global_variables = [] then
    ""
  else
    let shared_vars = List.filter (fun gv -> not gv.is_local) global_variables in
    if shared_vars = [] then
      ""
    else
      sprintf "/* Standard libbpf skeleton */\nstruct %s_bpf *obj = NULL;\n" base_name

(** Generate struct_ops registration code *)
let generate_struct_ops_registration_code ir_multi_program =
  if ir_multi_program.struct_ops_instances = [] then
    ""
  else
    let registration_code = List.map (fun struct_ops_inst ->
      let instance_name = struct_ops_inst.ir_instance_name in
      sprintf {|    /* Register struct_ops instance %s */
    if (bpf_map__attach_struct_ops(bpf_object__find_map_by_name(bpf_obj, "%s"))) {
        fprintf(stderr, "Failed to register struct_ops instance %s\n");
        return -1;
    }
    printf("✅ Registered struct_ops instance: %s\n");|} 
        instance_name instance_name instance_name instance_name
    ) ir_multi_program.struct_ops_instances in
    
    "\n    /* Register eBPF struct_ops instances */\n" ^ 
    (String.concat "\n" registration_code) ^ "\n"

(** Generate struct_ops attachment functions for userspace *)
let generate_struct_ops_attach_functions ir_multi_program =
  if ir_multi_program.struct_ops_instances = [] then
    ""
  else
    let attach_functions = List.map (fun struct_ops_inst ->
      let instance_name = struct_ops_inst.ir_instance_name in
      sprintf "int attach_struct_ops_%s(void) { return 0; }\nint detach_struct_ops_%s(void) { return 0; }" 
        instance_name instance_name
    ) ir_multi_program.struct_ops_instances in
    String.concat "\n" attach_functions

(** Generate command line argument parsing for struct parameter *)
let generate_getopt_parsing (struct_name : string) (param_name : string) (struct_fields : (string * ir_type) list) =
  (* Generate option struct array for getopt_long *)
  let options = List.mapi (fun i (field_name, _) ->
    sprintf "        {\"%s\", required_argument, 0, %d}," field_name (i + 1)
  ) struct_fields in
  
  let options_array = String.concat "\n" options in
  
  (* Generate case statements for option parsing *)
  let case_statements = List.mapi (fun i (field_name, field_type) ->
         let parse_code = match field_type with
       | IRU8 | IRU16 | IRU32 -> sprintf "%s.%s = (uint32_t)atoi(optarg);" param_name field_name
       | IRU64 -> sprintf "%s.%s = (uint64_t)atoll(optarg);" param_name field_name
       | IRI8 -> sprintf "%s.%s = (int8_t)atoi(optarg);" param_name field_name
       | IRBool -> sprintf "%s.%s = (atoi(optarg) != 0);" param_name field_name
       | IRStr size -> sprintf "strncpy(%s.%s, optarg, %d - 1); %s.%s[%d - 1] = '\\0';" param_name field_name size param_name field_name size
       | _ -> sprintf "%s.%s = (uint32_t)atoi(optarg); // fallback" param_name field_name
    in
    sprintf "        case %d:\n            %s\n            break;" (i + 1) parse_code
  ) struct_fields in
  
  let case_code = String.concat "\n" case_statements in
  
  (* Generate help text *)
     let help_options = List.map (fun (field_name, field_type) ->
     let type_hint = match field_type with
       | IRU8 | IRU16 | IRU32 | IRU64 -> "<number>"
       | IRI8 -> "<number>" 
       | IRBool -> "<0|1>"
       | IRStr _ -> "<string>"
       | _ -> "<value>"
    in
    sprintf "    printf(\"  --%s=%s\\n\");" field_name type_hint
  ) struct_fields in
  
  let help_text = String.concat "\n" help_options in
  
  sprintf {|
/* Parse command line arguments into %s */
struct %s parse_arguments(int argc, char **argv) {
    struct %s %s = {0}; // Initialize all fields to 0
    
    static struct option long_options[] = {
%s
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
        switch (c) {
%s
        case 'h':
            printf("Usage: %%s [options]\n", argv[0]);
            printf("Options:\n");
%s
            printf("  --help           Show this help message\n");
            exit(0);
            break;
        case '?':
            fprintf(stderr, "Unknown option. Use --help for usage information.\n");
            exit(1);
            break;
        default:
            fprintf(stderr, "Error parsing arguments\n");
            exit(1);
        }
    }
    
    return %s;
}
|} struct_name struct_name struct_name param_name options_array case_code help_text param_name

(** Generate map file descriptor declarations *)
let generate_map_fd_declarations maps =
  List.map (fun map ->
    sprintf "int %s_fd = -1;" map.map_name
  ) maps |> String.concat "\n"

(** Generate pinned globals support code *)
let generate_pinned_globals_support _project_name global_variables =
  let pinned_vars = List.filter (fun gv -> gv.is_pinned) global_variables in
  if pinned_vars = [] then
    ("", "", "")
  else
    let struct_definition = 
      let fields_str = String.concat ";\n    " (List.map (fun gv ->
        let c_type = c_type_from_ir_type gv.global_var_type in
        match gv.global_var_type with
        | IRStr size -> sprintf "char %s[%d]" gv.global_var_name size
        | _ -> sprintf "%s %s" c_type gv.global_var_name
      ) pinned_vars) in
      sprintf "struct pinned_globals_struct {\n    %s;\n};" fields_str
    in
    
    let map_fd_declaration = "int pinned_globals_map_fd = -1;" in
    
    (* Setup code is now handled in main function generation to avoid duplication *)
    (struct_definition, map_fd_declaration, "")

(** Generate map operation functions *)
let generate_map_operation_functions maps =
  List.map (fun map ->
    let key_type = c_type_from_ir_type map.map_key_type in
    let value_type = c_type_from_ir_type map.map_value_type in
  sprintf {|
// Map operations for %s
int %s_lookup(%s *key, %s *value) {
    return bpf_map_lookup_elem(%s_fd, key, value);
}

int %s_update(%s *key, %s *value) {
    return bpf_map_update_elem(%s_fd, key, value, BPF_ANY);
}

int %s_delete(%s *key) {
    return bpf_map_delete_elem(%s_fd, key);
}

int %s_get_next_key(%s *key, %s *next_key) {
    return bpf_map_get_next_key(%s_fd, key, next_key);
}|} 
      map.map_name
      map.map_name key_type value_type map.map_name
      map.map_name key_type value_type map.map_name
      map.map_name key_type map.map_name
      map.map_name key_type key_type map.map_name
  ) maps |> String.concat "\n"

(** Generate map setup code - handle both regular and pinned maps *)
let generate_map_setup_code maps =
  List.map (fun map ->
    match map.pin_path with
    | Some pin_path ->
        (* For pinned maps, try multiple approaches in order *)
        Printf.sprintf "/* Load or create pinned %s map at %s */" map.map_name pin_path
    | None ->
        (* For non-pinned maps, just load from BPF object *)
        Printf.sprintf "/* Load %s map from eBPF object */" map.map_name
  ) maps |> String.concat "\n"

(** Generate config struct definition from config declaration - reusing eBPF logic *)
let generate_config_struct_from_decl (config_decl : Ast.config_declaration) =
  let config_name = config_decl.config_name in
  let struct_name = sprintf "%s_config" config_name in
  
  (* Generate C struct for config - using same logic as eBPF but with standard C types *)
  let field_declarations = List.map (fun field ->
    let field_declaration = match field.Ast.field_type with
      | Ast.U8 -> sprintf "    uint8_t %s;" field.Ast.field_name
      | Ast.U16 -> sprintf "    uint16_t %s;" field.Ast.field_name
      | Ast.U32 -> sprintf "    uint32_t %s;" field.Ast.field_name
      | Ast.U64 -> sprintf "    uint64_t %s;" field.Ast.field_name
      | Ast.I8 -> sprintf "    int8_t %s;" field.Ast.field_name
      | Ast.I16 -> sprintf "    int16_t %s;" field.Ast.field_name
      | Ast.I32 -> sprintf "    int32_t %s;" field.Ast.field_name
      | Ast.I64 -> sprintf "    int64_t %s;" field.Ast.field_name
      | Ast.Bool -> sprintf "    bool %s;" field.Ast.field_name
      | Ast.Char -> sprintf "    char %s;" field.Ast.field_name
      | Ast.Array (Ast.U16, size) -> sprintf "    uint16_t %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U32, size) -> sprintf "    uint32_t %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U64, size) -> sprintf "    uint64_t %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U8, size) -> sprintf "    uint8_t %s[%d];" field.Ast.field_name size
      | _ -> sprintf "    uint32_t %s;" field.Ast.field_name  (* fallback *)
    in
    field_declaration
  ) config_decl.Ast.config_fields in
  
  sprintf "struct %s {\n%s\n};" struct_name (String.concat "\n" field_declarations)



(** Generate necessary headers based on maps used *)
let generate_headers_for_maps ?(uses_bpf_functions=false) maps =
  let has_maps = List.length maps > 0 in
  let has_pinned_maps = List.exists (fun map -> map.pin_path <> None) maps in

  
  let base_headers = [
    "#include <stdio.h>";
    "#include <stdlib.h>";
    "#include <string.h>";
    "#include <errno.h>";
    "#include <unistd.h>";
    "#include <signal.h>";
  ] in
  
  let bpf_headers = if has_maps || uses_bpf_functions then [
    "#include <bpf/bpf.h>";
    "#include <bpf/libbpf.h>";
  ] else [] in
  
  let pinning_headers = if has_pinned_maps then [
    "#include <sys/stat.h>";
    "#include <sys/types.h>";
  ] else [] in
  
  let event_headers = [] in
  
  String.concat "\n" (base_headers @ bpf_headers @ pinning_headers @ event_headers)

(** Generate userspace code with tail call dependency management *)
let generate_load_function_with_tail_calls _base_name all_usage tail_call_analysis _all_setup_code kfunc_dependencies _global_variables =
  (* kfunc_dependencies is used implicitly in the generated C code via ensure_kfunc_dependencies_loaded call *)
  let _ensure_deps_exist = kfunc_dependencies in  (* Suppress unused warning *)
  if all_usage.uses_load then
    let dep_loading_code = 
      if tail_call_analysis.Tail_call_analyzer.prog_array_size > 0 then
        sprintf {|
    // Load tail call dependencies automatically
    struct bpf_map *prog_array_map = bpf_object__find_map_by_name(obj->obj, "prog_array");
    if (!prog_array_map) {
        fprintf(stderr, "Failed to find prog_array map\n");
        return -1;
    }
    
    int prog_array_fd = bpf_map__fd(prog_array_map);
    if (prog_array_fd < 0) {
        fprintf(stderr, "Failed to get prog_array map file descriptor\n");
        return -1;
    }
    
    // Load and register tail call targets
    %s
    |}
        (String.concat "\n    " 
          (Hashtbl.fold (fun target index acc ->
            (sprintf {|{
        struct bpf_program *target_prog = bpf_object__find_program_by_name(obj->obj, "%s");
        if (target_prog) {
            int target_fd = bpf_program__fd(target_prog);
            if (target_fd >= 0) {
                __u32 prog_index = %d;
                if (bpf_map_update_elem(prog_array_fd, &prog_index, &target_fd, BPF_ANY) < 0) {
                    fprintf(stderr, "Failed to update prog_array for %s\n");
                }
            }
        }
    }|} target index target) :: acc
          ) tail_call_analysis.Tail_call_analyzer.index_mapping []))
      else
        "" 
    in

    (* Lightweight load function - skeleton already loaded in main() *)
    sprintf {|int get_bpf_program_handle(const char *program_name) {
    if (!obj) {
        fprintf(stderr, "eBPF skeleton not loaded - this should not happen with implicit loading\n");
        return -1;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj->obj, program_name);
    if (!prog) {
        fprintf(stderr, "Failed to find program '%%s' in BPF object\n", program_name);
        return -1;
    }
    
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for program '%%s'\n", program_name);
        return -1;
    }
    
%s
    return prog_fd;
}|} dep_loading_code
  else ""

(** Generate complete userspace program from IR *)
let generate_complete_userspace_program_from_ir ?(config_declarations = []) ?(type_aliases = []) ?(tail_call_analysis = {Tail_call_analyzer.dependencies = []; prog_array_size = 0; index_mapping = Hashtbl.create 16; errors = []}) ?(kfunc_dependencies = {kfunc_definitions = []; private_functions = []; program_dependencies = []; module_name = ""}) ?(resolved_imports = []) ?symbol_table (userspace_prog : ir_userspace_program) (global_maps : ir_map_def list) (ir_multi_prog : ir_multi_program) source_filename =
  (* Collect function usage information from all functions first to determine if we need BPF headers *)
  let all_usage = List.fold_left (fun acc_usage func ->
    let func_usage = collect_function_usage_from_ir_function ~global_variables:ir_multi_prog.global_variables func in
    {
      uses_load = acc_usage.uses_load || func_usage.uses_load;
      uses_attach = acc_usage.uses_attach || func_usage.uses_attach;
      uses_map_operations = acc_usage.uses_map_operations || func_usage.uses_map_operations;
      used_maps = List.fold_left (fun acc map_name ->
        if List.mem map_name acc then acc else map_name :: acc
      ) acc_usage.used_maps func_usage.used_maps;
    }
  ) (create_function_usage ()) userspace_prog.userspace_functions in

  let uses_bpf_functions = all_usage.uses_load || all_usage.uses_attach in
  let base_includes = generate_headers_for_maps ~uses_bpf_functions global_maps in
  let additional_includes = {|#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <fcntl.h>
#include <net/if.h>
#include <setjmp.h>
#include <linux/bpf.h>
#include <sys/resource.h>

/* Generated from KernelScript IR */
|} in
  
  (* Add kfunc dependency loading code if needed *)
  let kmodule_loading_code = generate_kmodule_loading_code kfunc_dependencies in
  
  (* Generate skeleton header include for standard libbpf skeleton *)
  let base_name = Filename.remove_extension (Filename.basename source_filename) in
  let needs_skeleton_header = ir_multi_prog.global_variables <> [] || uses_bpf_functions || ir_multi_prog.struct_ops_instances <> [] in
  let skeleton_include = if needs_skeleton_header then
    sprintf "#include \"%s.skel.h\"\n" base_name
  else "" in
  
  (* Generate bridge code for imported KernelScript and Python modules *)
  let bridge_code = generate_mixed_bridge_code resolved_imports userspace_prog.userspace_functions in
  
  let includes = base_includes ^ "\n" ^ additional_includes ^ kmodule_loading_code ^ skeleton_include ^ bridge_code in

  (* Reset and use the global config names collector *)
  global_config_names := [];
  
  (* Check if main function has struct parameters and generate getopt parsing *)
  let main_function = List.find_opt (fun f -> f.func_name = "main") userspace_prog.userspace_functions in
  let getopt_parsing_code = match main_function with
    | Some main_func when List.length main_func.parameters > 0 ->
        let (param_name, param_type) = List.hd main_func.parameters in
        (match param_type with
         | IRStruct (struct_name, _, _) ->
           (* Look up the actual struct definition to get the fields *)
           (match List.find_opt (fun s -> s.struct_name = struct_name) userspace_prog.userspace_structs with
            | Some struct_def -> generate_getopt_parsing struct_name param_name struct_def.struct_fields
            | None -> "")
         | _ -> "")
    | _ -> ""
  in
  
  (* Collect string sizes from the userspace program - only those used in concatenation *)
  let string_sizes = collect_string_concat_sizes_from_userspace_program userspace_prog in
  
  (* Generate string type definitions and helpers *)
  let string_typedefs = generate_string_typedefs string_sizes in
  let string_helpers = generate_string_helpers string_sizes in
  
  (* Generate enum definitions *)
  let enum_definitions = generate_enum_definitions_userspace ?symbol_table userspace_prog in
  
  (* Generate type alias definitions from AST *)
  let type_alias_definitions = generate_type_alias_definitions_userspace_from_ast type_aliases in

  (* Generate eBPF object instance - also needed for struct_ops *)
  let needs_skeleton = ir_multi_prog.global_variables <> [] || uses_bpf_functions || ir_multi_prog.struct_ops_instances <> [] in
  let skeleton_code = if needs_skeleton then
    sprintf "/* eBPF skeleton instance */\nstruct %s_ebpf *obj = NULL;\n" base_name
  else "" in
  
  (* Generate functions first so config names get collected *)
  let functions = String.concat "\n\n" 
    (List.map (generate_c_function_from_ir ~global_variables:ir_multi_prog.global_variables ~base_name ~config_declarations ~ir_multi_prog:(Some ir_multi_prog) ~resolved_imports) userspace_prog.userspace_functions) in
  
  (* Generate config struct definitions using actual config declarations *)
  let config_structs = List.map generate_config_struct_from_decl config_declarations in
  
  (* Filter out config structs from IR structs since we generate them separately from config_declarations *)
  let non_config_ir_structs = List.filter (fun ir_struct ->
    not (String.contains ir_struct.struct_name '_' && 
         String.ends_with ~suffix:"_config" ir_struct.struct_name)
  ) userspace_prog.userspace_structs in
  
  (* Filter out kernel-defined structs that are provided by kernel headers *)
  let user_defined_ir_structs = List.filter (fun ir_struct ->
    not ir_struct.kernel_defined && 
    not (Kernel_types.is_well_known_ebpf_type ir_struct.struct_name) &&
    not (Struct_ops_registry.is_known_struct_ops ir_struct.struct_name)
  ) non_config_ir_structs in
  
  let structs = String.concat "\n\n" 
    ((List.map generate_c_struct_from_ir user_defined_ir_structs) @ config_structs) in
  
  (* Generate map-related code only if maps are actually used *)
  let used_global_maps = List.filter (fun map ->
    List.mem map.map_name all_usage.used_maps
  ) global_maps in
  
  let map_fd_declarations = if all_usage.uses_map_operations then
    generate_map_fd_declarations used_global_maps
  else "" in
  
  (* Generate pinned globals support *)
  let project_name = Filename.remove_extension (Filename.basename source_filename) in
  let (pinned_globals_struct, pinned_globals_fd, pinned_globals_setup) = 
    generate_pinned_globals_support project_name ir_multi_prog.global_variables in
  
  (* Generate config map file descriptors if there are config declarations *)
  let config_fd_declarations = if List.length config_declarations > 0 then
    List.map (fun config_decl ->
      sprintf "int %s_config_map_fd = -1;" config_decl.Ast.config_name
    ) config_declarations
  else [] in
  
  let all_fd_declarations = 
    let parts = [map_fd_declarations; pinned_globals_fd] @ config_fd_declarations in
    let non_empty_parts = List.filter (fun s -> s <> "") parts in
    if non_empty_parts = [] then "" else String.concat "\n" non_empty_parts in
  
  let map_operation_functions = if all_usage.uses_map_operations then
    generate_map_operation_functions used_global_maps
  else "" in
  
  let map_setup_code = if all_usage.uses_map_operations then
    generate_map_setup_code used_global_maps
  else "" in
  
  (* Generate config map setup code - load from eBPF object and initialize with defaults *)
  (* Always generate config setup if there are config declarations, since eBPF programs may use them *)
  let config_setup_code = if List.length config_declarations > 0 then
    List.map (fun config_decl ->
      let config_name = config_decl.Ast.config_name in
      let load_code = sprintf {|    /* Load %s config map from eBPF object */
    %s_config_map_fd = bpf_object__find_map_fd_by_name(obj->obj, "%s_config_map");
    if (%s_config_map_fd < 0) {
        fprintf(stderr, "Failed to find %s config map in eBPF object\n");
        return -1;
    }|} config_name config_name config_name config_name config_name in
      let init_code = generate_config_initialization config_decl in
      load_code ^ "\n" ^ init_code
    ) config_declarations |> String.concat "\n"
  else "" in
  
  (* Generate struct_ops registration code *)
  let struct_ops_registration_code = generate_struct_ops_registration_code ir_multi_prog in
  
  let all_setup_code = 
    let parts = [map_setup_code; pinned_globals_setup; config_setup_code; struct_ops_registration_code] in
    let non_empty_parts = List.filter (fun s -> s <> "") parts in
    String.concat "\n" non_empty_parts in
  
  let structs_with_pinned = if pinned_globals_struct <> "" then
    structs ^ "\n\n" ^ pinned_globals_struct
  else structs in
  
  (* Base name already extracted earlier *)
  
  (* Generate automatic BPF object initialization when maps are used but load is not called *)
  let needs_auto_bpf_init = all_usage.uses_map_operations && not all_usage.uses_load in
  let auto_bpf_init_code = if needs_auto_bpf_init && all_setup_code <> "" then
    sprintf {|
/* Auto-generated BPF object initialization */
static struct bpf_object *bpf_obj = NULL;

int init_bpf_maps(void) {
    if (bpf_obj) return 0; // Already initialized
    
    bpf_obj = bpf_object__open_file("%s.ebpf.o", NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return -1;
    }
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return -1;
    }
    
%s
    return 0;
}

void cleanup_bpf_maps(void) {
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
}
|} base_name all_setup_code
  else "" in
  
  (* Only generate BPF helper functions when they're actually used *)
  let bpf_helper_functions = 
    let load_function = generate_load_function_with_tail_calls base_name all_usage tail_call_analysis all_setup_code kfunc_dependencies ir_multi_prog.global_variables in
    
    let attach_function = if all_usage.uses_attach then
      {|int attach_bpf_program_by_fd(int prog_fd, const char *target, int flags) {
    if (prog_fd < 0) {
        fprintf(stderr, "Invalid program file descriptor: %d\n", prog_fd);
        return -1;
    }
    
    // Get program type from file descriptor  
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    int ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (ret) {
        fprintf(stderr, "Failed to get program info: %s\n", strerror(errno));
        return -1;
    }
    
    switch (info.type) {
        case BPF_PROG_TYPE_XDP: {
            int ifindex = if_nametoindex(target);
            if (ifindex == 0) {
                fprintf(stderr, "Failed to get interface index for '%s'\n", target);
                return -1;
            }
            
            // Use modern libbpf API for XDP attachment
            ret = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
            if (ret) {
                fprintf(stderr, "Failed to attach XDP program to interface '%s': %s\n", target, strerror(errno));
                return -1;
            }
            
            return 0;
        }
        case BPF_PROG_TYPE_KPROBE: {
            // For kprobe programs, target should be the kernel function name (e.g., "sys_read")
            // Use libbpf high-level API for kprobe attachment
            
            // Get the bpf_program struct from the object and file descriptor
            struct bpf_program *prog = NULL;
            struct bpf_object *obj_iter;

            // Find the program object corresponding to this fd
            // We need to get the program from the skeleton object
            if (!obj) {
                fprintf(stderr, "eBPF skeleton not loaded for kprobe attachment\n");
                return -1;
            }

            bpf_object__for_each_program(prog, obj->obj) {
                if (bpf_program__fd(prog) == prog_fd) {
                    break;
                }
            }

            if (!prog) {
                fprintf(stderr, "Failed to find bpf_program for fd %d\n", prog_fd);
                return -1;
            }

            // Use libbpf's high-level kprobe attachment API
            struct bpf_link *link = bpf_program__attach_kprobe(prog, false, target);
            if (!link) {
                fprintf(stderr, "Failed to attach kprobe to function '%s': %s\n", target, strerror(errno));
                return -1;
            }
            
            // For now, close immediately - in a production system you'd store this for cleanup
            bpf_link__destroy(link);
            printf("✅ Kprobe attached to function: %s\n", target);
            
            return 0;
        }
        default:
            fprintf(stderr, "Unsupported program type for attachment: %d\n", info.type);
            return -1;
    }
}|}
    else "" in
    
    let bpf_obj_decl = "" in  (* Skeleton now handles the BPF object *)
    
    let functions_list = List.filter (fun s -> s <> "") [load_function; attach_function] in
    if functions_list = [] && bpf_obj_decl = "" then ""
    else
      sprintf "\n/* BPF Helper Functions (generated only when used) */\n%s\n\n%s" 
        bpf_obj_decl (String.concat "\n\n" functions_list) in
  
  (* Generate struct_ops attach functions *)
  let struct_ops_attach_functions = generate_struct_ops_attach_functions ir_multi_prog in

  sprintf {|%s

%s

%s

%s

%s

%s

%s

%s

%s
%s

%s
%s

%s

%s
|} includes string_typedefs type_alias_definitions string_helpers enum_definitions structs_with_pinned skeleton_code all_fd_declarations map_operation_functions auto_bpf_init_code getopt_parsing_code bpf_helper_functions struct_ops_attach_functions functions

(** Generate userspace C code from IR multi-program *)
let generate_userspace_code_from_ir ?(config_declarations = []) ?(type_aliases = []) ?(tail_call_analysis = {Tail_call_analyzer.dependencies = []; prog_array_size = 0; index_mapping = Hashtbl.create 16; errors = []}) ?(kfunc_dependencies = {kfunc_definitions = []; private_functions = []; program_dependencies = []; module_name = ""}) ?(resolved_imports = []) ?symbol_table (ir_multi_prog : ir_multi_program) ?(output_dir = ".") source_filename =
  let content = match ir_multi_prog.userspace_program with
    | Some userspace_prog -> 
        generate_complete_userspace_program_from_ir ~config_declarations ~type_aliases ~tail_call_analysis ~kfunc_dependencies ~resolved_imports ?symbol_table userspace_prog ir_multi_prog.global_maps ir_multi_prog source_filename
    | None -> 
        sprintf {|#include <stdio.h>

int main(void) {
    printf("No userspace program defined in IR\n");
    return 0;
}
|}
  in
  
  (* Create output directory *)
  (try Unix.mkdir output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  
  (* Generate output file *)
  let base_name = Filename.remove_extension (Filename.basename source_filename) in
  let filename = sprintf "%s.c" base_name in
  let filepath = Filename.concat output_dir filename in
  let oc = open_out filepath in
  output_string oc content;
  close_out oc;
  printf "✅ Generated IR-based userspace program: %s\n" filepath

(** Compatibility functions for tests *)
let generate_c_statement _stmt = "/* IR-based statement generation */"

(** Check if a variable name is an impl block instance *)
let is_impl_block_variable ir_multi_prog var_name =
  List.exists (fun struct_ops_decl ->
    struct_ops_decl.ir_instance_name = var_name
  ) ir_multi_prog.struct_ops_instances





