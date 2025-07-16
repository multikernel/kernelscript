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

(** Test Code Generation
    This module handles both AST filtering/transformation and C code generation for test mode compilation.
    It converts @test functions into executable test programs that can run eBPF programs with synthetic data.
*)

open Ast
open Printf

(** Check if an attributed function has the @test attribute *)
let has_test_attribute attr_func =
  List.exists (function SimpleAttribute "test" -> true | _ -> false) attr_func.attr_list

(** Extract @test function names from AST *)
let extract_test_function_names ast =
  List.filter_map (function
    | AttributedFunction attr_func when has_test_attribute attr_func ->
        Some attr_func.attr_function.func_name
    | _ -> None
  ) ast

(** Create a main function that calls all test functions *)
let create_test_main test_function_names filename =
  let dummy_pos = { filename; line = 1; column = 1 } in
  
  let test_calls = List.map (fun func_name ->
    let identifier_expr = { 
      expr_desc = Identifier func_name; 
      expr_pos = dummy_pos; 
      expr_type = None; 
      type_checked = false; 
      program_context = None; 
      map_scope = None 
    } in
    let call_expr = { 
      expr_desc = Call (identifier_expr, []); 
      expr_pos = dummy_pos; 
      expr_type = None; 
      type_checked = false; 
      program_context = None; 
      map_scope = None 
    } in
    { stmt_desc = ExprStmt call_expr; stmt_pos = dummy_pos }
  ) test_function_names in
  
  let return_expr = { 
    expr_desc = Literal (IntLit (0, None)); 
    expr_pos = dummy_pos; 
    expr_type = None; 
    type_checked = false; 
    program_context = None; 
    map_scope = None 
  } in
  
  let main_body = test_calls @ [
    { stmt_desc = Return (Some return_expr); stmt_pos = dummy_pos }
  ] in
  
  {
    func_name = "main";
    func_params = [];
    func_return_type = Some I32;
    func_body = main_body;
    func_scope = Userspace;
    func_pos = dummy_pos;
    tail_call_targets = [];
    is_tail_callable = false;
  }

(** Filter AST declarations for test mode *)
let filter_declarations ast =
  List.filter_map (function
    | AttributedFunction attr_func when has_test_attribute attr_func ->
        (* Keep @test functions as AttributedFunction to preserve @test attribute for type checking *)
        Some (AttributedFunction attr_func)
    | AttributedFunction attr_func ->
        (* Keep non-test attributed functions (eBPF programs needed for testing) *)
        Some (AttributedFunction attr_func)
    | GlobalFunction func when func.func_name = "main" ->
        (* Remove existing main function *)
        None
    | GlobalFunction _ ->
        (* Remove other global functions *)
        None
    | other ->
        (* Keep all other declarations (structs, enums, maps, configs, etc.) *)
        Some other
  ) ast

(** Filter AST for testing: keep @test functions and supporting declarations *)
let filter_ast_for_testing ast filename =
  let test_function_names = extract_test_function_names ast in
  
  if test_function_names = [] then
    failwith "No @test functions found in test mode";
  
  let filtered_decls = filter_declarations ast in
  let main_func = create_test_main test_function_names filename in
  
  filtered_decls @ [GlobalFunction main_func] 

(** Convert KernelScript type to C type for test functions *)
let kernelscript_type_to_c_type = function
  | U8 -> "uint8_t"
  | U16 -> "uint16_t"
  | U32 -> "uint32_t"
  | U64 -> "uint64_t"
  | I8 -> "int8_t"
  | I16 -> "int16_t"
  | I32 -> "int32_t"
  | I64 -> "int64_t"
  | Bool -> "bool"
  | Char -> "char"
  | Void -> "void"
  | _ -> "int"  (* fallback *)

(** Generate C expression from KernelScript expression *)
let rec generate_expression_to_c expr =
  match expr.expr_desc with
  | Literal literal ->
      (match literal with
       | IntLit (value, _) -> sprintf "%d" value
       | StringLit s -> sprintf "\"%s\"" s
       | BoolLit true -> "true"
       | BoolLit false -> "false"
       | _ -> "0")
  | Identifier name -> name
  | Call (callee, args) ->
      let callee_str = generate_expression_to_c callee in
      (* Handle builtin functions *)
      (match callee.expr_desc with
                | Identifier "print" -> 
             (* Convert print() to printf() and add newline to format string if needed *)
             (match args with
              | [] -> "printf(\"\\n\")"
              | first_arg :: rest_args ->
                let first_str = generate_expression_to_c first_arg in
                let rest_str = List.map generate_expression_to_c rest_args in
                (* Check if first arg is a string literal that needs newline *)
                let format_str = match first_arg.expr_desc with
                  | Literal (StringLit s) -> 
                      (* Add newline to format string *)
                      sprintf "\"%s\\n\"" s
                  | _ -> first_str
                in
                let all_args = format_str :: rest_str in
                sprintf "printf(%s)" (String.concat ", " all_args))
       | Identifier "test" ->
           (* Special handling for test() builtin function *)
           (match args with
            | [func_name_arg; test_ctx_arg] ->
                let func_name_str = match func_name_arg.expr_desc with
                  | Identifier name -> sprintf "\"%s\"" name  (* Convert function identifier to string *)
                  | _ -> generate_expression_to_c func_name_arg
                in
                let test_ctx_str = sprintf "&%s" (generate_expression_to_c test_ctx_arg) in  (* Pass by reference *)
                sprintf "test(%s, %s)" func_name_str test_ctx_str
            | _ -> 
                let args_str = String.concat ", " (List.map generate_expression_to_c args) in
                sprintf "test(%s)" args_str)
       | _ -> 
           let args_str = String.concat ", " (List.map generate_expression_to_c args) in
           sprintf "%s(%s)" callee_str args_str)
  | StructLiteral (struct_name, field_assignments) ->
      let field_strs = List.map (fun (field_name, field_expr) ->
        let field_value = generate_expression_to_c field_expr in
        sprintf ".%s = %s" field_name field_value
      ) field_assignments in
      sprintf "(struct %s){%s}" struct_name (String.concat ", " field_strs)
  | BinaryOp (left, op, right) ->
      let left_str = generate_expression_to_c left in
      let right_str = generate_expression_to_c right in
      let op_str = match op with
        | Add -> "+"
        | Sub -> "-"
        | Mul -> "*"
        | Div -> "/"
        | Mod -> "%"
        | Eq -> "=="
        | Ne -> "!="
        | Lt -> "<"
        | Le -> "<="
        | Gt -> ">"
        | Ge -> ">="
        | And -> "&&"
        | Or -> "||"
      in
      sprintf "(%s %s %s)" left_str op_str right_str
  | _ -> "0"  (* fallback for unsupported expressions *)

(** Generate C statement from KernelScript statement *)
let rec generate_statement_to_c stmt =
  match stmt.stmt_desc with
  | Declaration (var_name, Some var_type, Some init_expr) ->
      let c_type = kernelscript_type_to_c_type var_type in
      let init_str = generate_expression_to_c init_expr in
      sprintf "    %s %s = %s;" c_type var_name init_str
  | Declaration (var_name, Some var_type, None) ->
      let c_type = kernelscript_type_to_c_type var_type in
      sprintf "    %s %s;" c_type var_name
  | Declaration (var_name, var_type_opt, Some init_expr) ->
      let init_str = generate_expression_to_c init_expr in
      (* Use explicit type if provided, otherwise infer from initialization *)
      let c_type = match var_type_opt with
        | Some explicit_type -> kernelscript_type_to_c_type explicit_type
        | None ->
            (* Try to infer type from the initialization expression *)
                         (* Direct approach: check variable name first, then expression type *)
             (match var_name, init_expr.expr_desc with
              | "test_ctx", _ -> "struct XdpTestContext"  (* Always use struct type for test_ctx *)
              | _, StructLiteral (struct_name, _) -> sprintf "struct %s" struct_name
              | _, Call (callee, _) ->
                  (* Special handling for known function return types *)
                  (match callee.expr_desc with
                   | Identifier "test" -> "int"  (* test() builtin returns int *)
                   | _ -> "int")  (* Default to int for function calls *)
              | _, Literal (IntLit (_, _)) -> "int"
              | _, Literal (BoolLit _) -> "bool"
              | _, _ -> "int")  (* Default to int *)
      in
      sprintf "    %s %s = %s;" c_type var_name init_str

  | Assignment (var_name, expr) ->
      sprintf "    %s = %s;" var_name (generate_expression_to_c expr)
  | If (condition, then_stmts, else_stmts) ->
      let condition_str = generate_expression_to_c condition in
      let then_block = String.concat "\n" (List.map generate_statement_to_c then_stmts) in
      let else_block = match else_stmts with
        | Some stmts -> sprintf " else {\n%s\n    }" (String.concat "\n" (List.map generate_statement_to_c stmts))
        | None -> ""
      in
      sprintf "    if (%s) {\n%s\n    }%s" condition_str then_block else_block
  | Return (Some expr) ->
      sprintf "    return %s;" (generate_expression_to_c expr)
  | Return None ->
      "    return;"
  | ExprStmt expr ->
      sprintf "    %s;" (generate_expression_to_c expr)
  | _ -> "    /* TODO: Implement statement */"

(** Generate test program C code for @test functions *)
let generate_test_program ast _program_name =
  (* Extract struct definitions for test context types *)
  let all_struct_defs = List.filter_map (function
    | StructDecl struct_def -> Some struct_def
    | _ -> None
  ) ast in
  
  (* Filter out kernel-defined structs that are provided by kernel headers *)
  let struct_defs = List.filter (fun struct_def ->
    not (Kernel_types.is_well_known_ebpf_type struct_def.struct_name) &&
    not (Struct_ops_registry.is_known_struct_ops struct_def.struct_name)
  ) all_struct_defs in
  
  (* Extract test functions *)
  let test_functions = List.filter_map (function
    | GlobalFunction func when func.func_name <> "main" -> Some func
    | _ -> None
  ) ast in
  
  (* Generate struct definitions *)
  let struct_code = List.map (fun struct_def ->
    let fields = List.map (fun (field_name, field_type) ->
      let c_type = match field_type with
        | U32 -> "uint32_t"
        | I32 -> "int32_t"
        | U64 -> "uint64_t"
        | I64 -> "int64_t"
        | U16 -> "uint16_t"
        | I16 -> "int16_t"
        | U8 -> "uint8_t"
        | I8 -> "int8_t"
        | _ -> "int"
      in
      sprintf "  %s %s;" c_type field_name
    ) struct_def.struct_fields in
    sprintf "struct %s {\n%s\n};" struct_def.struct_name (String.concat "\n" fields)
  ) struct_defs in
  
  (* Generate test() builtin function implementation *)
  let test_builtin_impl = sprintf {|
// test() builtin function - loads and runs BPF program with test data
int test(const char* program_name, void* test_context) {
    printf("Testing BPF program: %%s\n", program_name);
    
    // Construct BPF object file path
    char obj_path[256];
    snprintf(obj_path, sizeof(obj_path), "%%s.ebpf.o", program_name);
    
    // Load BPF object
    struct bpf_object *obj = bpf_object__open(obj_path);
    if (libbpf_get_error(obj)) {
        printf("Failed to open BPF object %%s\n", obj_path);
        return -1;
    }
    
    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object %%s\n", obj_path);
        bpf_object__close(obj);
        return -1;
    }
    
    // Find the main BPF program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, program_name);
    if (!prog) {
        printf("BPF program %%s not found in object\n", program_name);
        bpf_object__close(obj);
        return -1;
    }
    
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        printf("Failed to get file descriptor for BPF program %%s\n", program_name);
        bpf_object__close(obj);
        return -1;
    }
    
    // Prepare test data
    unsigned char test_data[1500] = {0}; // Maximum ethernet frame
    unsigned int test_data_size = sizeof(test_data);
    
    // If test_context is provided, use it to customize test data
    if (test_context) {
        printf("Using provided test context\n");
        // Real implementation would parse test_context based on program type
    }
    
    // Execute BPF program with test data
    struct bpf_test_run_opts opts = {
        .sz = sizeof(opts),
        .data_in = test_data,
        .data_size_in = test_data_size,
        .data_out = NULL,
        .data_size_out = 0,
        .repeat = 1,
    };
    
    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("BPF program test run failed: %%d\n", err);
        bpf_object__close(obj);
        return -1;
    }
    
    printf("BPF program executed successfully\n");
    printf("Return value: %%u, Duration: %%uns\n", opts.retval, opts.duration);
    
    bpf_object__close(obj);
    return (int)opts.retval;
}


|} in
  
  (* Generate test function calls *)
  let test_calls = List.map (fun func ->
    sprintf "    printf(\"Running test: %s\\n\");\n    %s();" func.func_name func.func_name
  ) test_functions in
  
  (* Generate test function implementations *)
  let test_function_code = List.map (fun func ->
    let return_type = match func.func_return_type with
      | Some I32 -> "int"
      | Some U32 -> "uint32_t"
      | _ -> "int"
    in
    
    let body_statements = List.map (generate_statement_to_c) func.func_body in
    let body = sprintf "{\n%s\n}" (String.concat "\n" body_statements) in
    
    sprintf "%s %s() %s" return_type func.func_name body
  ) test_functions in
  
  (* Combine everything *)
  let full_code = sprintf {|#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

%s

%s

%s

int main() {
    printf("Running KernelScript tests\\n");
    printf("==========================================\\n\\n");
     
%s
     
    printf("\\nAll tests completed!\\n");
    return 0;
}
|} (String.concat "\n\n" struct_code) test_builtin_impl (String.concat "\n\n" test_function_code) (String.concat "\n" test_calls) in
  
  full_code 