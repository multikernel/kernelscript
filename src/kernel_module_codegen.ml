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

(** Kernel Module Code Generation for @kfunc Functions
    
    This module generates kernel module C code for functions annotated with @kfunc.
    The generated module automatically registers kfuncs with the eBPF subsystem.
*)

open Ast
open Printf

(** Kernel module generation context *)
type kmodule_context = {
  module_name: string;
  kfunc_functions: function_def list;
  private_functions: function_def list;
  dependencies: string list;
}

(** Create a new kernel module context *)
let create_context module_name = {
  module_name;
  kfunc_functions = [];
  private_functions = [];
  dependencies = [];
}

(** Add a kfunc to the context *)
let add_kfunc context func_def = {
  context with kfunc_functions = func_def :: context.kfunc_functions
}

(** Add a private function to the context *)
let add_private context func_def = {
  context with private_functions = func_def :: context.private_functions
}

(** Convert KernelScript type to C type for kernel module *)
let kernelscript_type_to_c_type = function
  | U8 -> "u8"
  | U16 -> "u16"
  | U32 -> "u32"
  | U64 -> "u64"
  | I8 -> "s8"
  | I16 -> "s16"
  | I32 -> "s32"
  | I64 -> "s64"
  | Bool -> "bool"
  | Char -> "char"
  | Void -> "void"
  | Pointer U8 -> "u8 *"
  | Pointer U16 -> "u16 *"
  | Pointer U32 -> "u32 *"
  | Pointer U64 -> "u64 *"
  | Pointer I8 -> "s8 *"
  | Pointer I16 -> "s16 *"
  | Pointer I32 -> "s32 *"
  | Pointer I64 -> "s64 *"
  | Pointer Char -> "char *"
  | Pointer Void -> "void *"
  | _ -> "void *"  (* Fallback for complex types *)

(** Generate function signature for regular kernel module functions *)
let generate_function_signature func_def =
  let return_type = match get_return_type func_def.func_return_type with
    | Some ret_type -> kernelscript_type_to_c_type ret_type
    | None -> "void"
  in
  let params = List.map (fun (param_name, param_type) ->
    sprintf "%s %s" (kernelscript_type_to_c_type param_type) param_name
  ) func_def.func_params in
  let params_str = if params = [] then "void" else String.concat ", " params in
  sprintf "static %s %s(%s)" return_type func_def.func_name params_str

(** Generate function signature for kfunc kernel module functions with proper annotations *)
let generate_kfunc_signature func_def =
  let return_type = match get_return_type func_def.func_return_type with
    | Some ret_type -> kernelscript_type_to_c_type ret_type
    | None -> "void"
  in
  let params = List.map (fun (param_name, param_type) ->
    sprintf "%s %s" (kernelscript_type_to_c_type param_type) param_name
  ) func_def.func_params in
  let params_str = if params = [] then "void" else String.concat ", " params in
  sprintf "__bpf_kfunc %s %s(%s)" return_type func_def.func_name params_str

(** Generate function prototype for regular kernel module functions *)
let generate_function_prototype func_def =
  let return_type = match get_return_type func_def.func_return_type with
    | Some ret_type -> kernelscript_type_to_c_type ret_type
    | None -> "void"
  in
  let params = List.map (fun (param_name, param_type) ->
    sprintf "%s %s" (kernelscript_type_to_c_type param_type) param_name
  ) func_def.func_params in
  let params_str = if params = [] then "void" else String.concat ", " params in
  sprintf "static %s %s(%s);" return_type func_def.func_name params_str

(** Generate function prototype for kfunc kernel module functions with proper annotations *)
let generate_kfunc_prototype func_def =
  let return_type = match get_return_type func_def.func_return_type with
    | Some ret_type -> kernelscript_type_to_c_type ret_type
    | None -> "void"
  in
  let params = List.map (fun (param_name, param_type) ->
    sprintf "%s %s" (kernelscript_type_to_c_type param_type) param_name
  ) func_def.func_params in
  let params_str = if params = [] then "void" else String.concat ", " params in
  sprintf "__bpf_kfunc %s %s(%s);" return_type func_def.func_name params_str

(** Generate statement translation *)
let rec generate_statement_translation stmt =
  match stmt.stmt_desc with
  | Return (Some expr) ->
      sprintf "    return %s;" (generate_expression_translation expr)
  | Return None ->
      "    return;"
  | Assignment (var_name, expr) ->
      sprintf "    %s = %s;" var_name (generate_expression_translation expr)
  | CompoundAssignment (var_name, op, expr) ->
      let expr_str = generate_expression_translation expr in
      let op_str = match op with
        | Add -> "+"
        | Sub -> "-"  
        | Mul -> "*"
        | Div -> "/"
        | Mod -> "%"
        | _ -> failwith "Unsupported operator in compound assignment"
      in
      sprintf "    %s %s= %s;" var_name op_str expr_str
  | Declaration (var_name, Some var_type, expr_opt) ->
      (match expr_opt with
       | Some expr ->
           sprintf "    %s %s = %s;" 
             (kernelscript_type_to_c_type var_type) 
             var_name 
             (generate_expression_translation expr)
       | None ->
           sprintf "    %s %s;" 
             (kernelscript_type_to_c_type var_type) 
             var_name)
  | Declaration (var_name, None, expr_opt) ->
      (match expr_opt with
       | Some expr -> sprintf "    auto %s = %s;" var_name (generate_expression_translation expr)
       | None -> sprintf "    /* Declaration %s; */" var_name)
  | If (condition, then_stmts, else_stmts) ->
      let condition_str = generate_expression_translation condition in
      let then_block = String.concat "\n" (List.map generate_statement_translation then_stmts) in
      let else_block = match else_stmts with
        | Some stmts -> sprintf " else {\n%s\n    }" (String.concat "\n" (List.map generate_statement_translation stmts))
        | None -> ""
      in
      sprintf "    if (%s) {\n%s\n    }%s" condition_str then_block else_block
  | For (var_name, start_expr, end_expr, body_stmts) ->
      let start_str = generate_expression_translation start_expr in
      let end_str = generate_expression_translation end_expr in
      let body_str = String.concat "\n" (List.map generate_statement_translation body_stmts) in
      sprintf "    for (int %s = %s; %s < %s; %s++) {\n%s\n    }" 
        var_name start_str var_name end_str var_name body_str
  | While (condition, body_stmts) ->
      let condition_str = generate_expression_translation condition in
      let body_str = String.concat "\n" (List.map generate_statement_translation body_stmts) in
      sprintf "    while (%s) {\n%s\n    }" condition_str body_str
  | ExprStmt expr ->
      sprintf "    %s;" (generate_expression_translation expr)
  | Break -> "    break;"
  | Continue -> "    continue;"
  | _ -> "    /* TODO: Implement statement translation */"

(** Generate expression translation *)
and generate_expression_translation expr =
  match expr.expr_desc with
  | Literal (IntLit (value, _)) -> string_of_int value
  | Literal (StringLit str) -> sprintf "\"%s\"" str
  | Literal (BoolLit true) -> "true"
  | Literal (BoolLit false) -> "false"
  | Literal NullLit -> "NULL"
  | Identifier name -> name
  | BinaryOp (left, op, right) ->
      let left_str = generate_expression_translation left in
      let right_str = generate_expression_translation right in
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
  | UnaryOp (op, operand) ->
      let operand_str = generate_expression_translation operand in
      let op_str = match op with
        | Not -> "!"
        | Neg -> "-"
        | Deref -> "*"
        | AddressOf -> "&"
      in
      sprintf "(%s%s)" op_str operand_str
  | Call (callee_expr, args) ->
      (* Generate the callee expression (could be function name or function pointer) *)
      let callee_str = generate_expression_translation callee_expr in
      
      (* Check if this is a simple function name (identifier) that needs special handling *)
      let (actual_name, translated_args) = match callee_expr.expr_desc with
        | Identifier func_name ->
            (* Check if this is a built-in function that needs context-specific translation *)
            (match Stdlib.get_kernel_implementation func_name with
             | Some kernel_impl when kernel_impl <> "" ->
                 (* This is a built-in function - translate for kernel module context *)
                 (match func_name with
                  | "print" -> 
                      (* For kernel modules, printk needs KERN_INFO prefix and proper formatting *)
                      let c_args = List.map generate_expression_translation args in
                      (match c_args with
                       | [] -> (kernel_impl, ["KERN_INFO \"\""])
                       | [first] -> (kernel_impl, [sprintf "KERN_INFO %s" first])
                       | first :: rest -> 
                           (* For multiple args, format as: printk(KERN_INFO format, args...) *)
                           let format_specifiers = List.map (fun _ -> "%s") rest in
                           let format_str = sprintf "KERN_INFO %s %s" first (String.concat " " format_specifiers) in
                           (kernel_impl, format_str :: rest))
                  | _ -> 
                      (* For other built-in functions, use standard conversion *)
                      let c_args = List.map generate_expression_translation args in
                      (kernel_impl, c_args))
             | _ ->
                 (* Regular function call *)
                 let c_args = List.map generate_expression_translation args in
                 (func_name, c_args))
        | _ ->
            (* Complex expression (function pointer call) *)
            let c_args = List.map generate_expression_translation args in
            (callee_str, c_args)
      in
      let args_str = String.concat ", " translated_args in
      sprintf "%s(%s)" actual_name args_str
  | FieldAccess (obj, field) ->
      sprintf "%s.%s" (generate_expression_translation obj) field
  | ArrowAccess (obj, field) ->
      sprintf "%s->%s" (generate_expression_translation obj) field
  | ArrayAccess (array, index) ->
      sprintf "%s[%s]" (generate_expression_translation array) (generate_expression_translation index)
  | _ -> "/* TODO: Implement expression translation */"

(** Generate function implementation for regular kernel module functions *)
let generate_function_implementation func_def =
  let signature = generate_function_signature func_def in
  let body = String.concat "\n" (List.map generate_statement_translation func_def.func_body) in
  sprintf "%s\n{\n%s\n}" signature body

(** Generate function implementation for kfunc kernel module functions *)
let generate_kfunc_implementation func_def =
  let signature = generate_kfunc_signature func_def in
  let body = String.concat "\n" (List.map generate_statement_translation func_def.func_body) in
  sprintf "%s\n{\n%s\n}" signature body

(** Generate BTF information for kfunc *)
let generate_btf_info func_def =
  let param_types = List.map (fun (_, param_type) ->
    kernelscript_type_to_c_type param_type
  ) func_def.func_params in
  let return_type = match get_return_type func_def.func_return_type with
    | Some ret_type -> kernelscript_type_to_c_type ret_type
    | None -> "void"
  in
  sprintf "/* BTF info for %s: %s(%s) */" 
    func_def.func_name 
    return_type 
    (String.concat ", " param_types)

(** Generate complete kernel module *)
let generate_kernel_module context =
  let header = sprintf {|/*
 * Generated kernel module for kfunc definitions
 * Module: %s
 * Generated by KernelScript compiler
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bpf.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelScript Compiler");
MODULE_DESCRIPTION("Auto-generated kfunc module for %s");
MODULE_VERSION("1.0");

|} context.module_name context.module_name in

  (* Generate function prototypes *)
  let private_prototypes = String.concat "\n" (List.map generate_function_prototype context.private_functions) in
  let kfunc_prototypes = String.concat "\n" (List.map generate_kfunc_prototype context.kfunc_functions) in
  let function_prototypes = 
    if private_prototypes = "" then kfunc_prototypes
    else if kfunc_prototypes = "" then private_prototypes
    else sprintf "%s\n%s" private_prototypes kfunc_prototypes
  in
  
  (* Generate private function implementations first (so kfuncs can call them) *)
  let private_implementations = String.concat "\n\n" (List.map generate_function_implementation context.private_functions) in
  
  (* Generate kfunc implementations *)
  let kfunc_implementations = 
    if context.kfunc_functions = [] then ""
    else sprintf {|
/* Begin kfunc definitions */
__bpf_kfunc_start_defs();

%s

/* End kfunc definitions */
__bpf_kfunc_end_defs();
|} (String.concat "\n\n" (List.map generate_kfunc_implementation context.kfunc_functions)) in
  
  let btf_declarations = String.concat "\n" (List.map generate_btf_info context.kfunc_functions) in
  
  let kfunc_btf_ids = String.concat "\n" (List.map (fun func_def ->
    sprintf "BTF_ID_FLAGS(func, %s)" func_def.func_name
  ) context.kfunc_functions) in
  
  let btf_id_set = sprintf {|
/* BTF ID set for kfuncs */
BTF_KFUNCS_START(%s_kfunc_btf_ids)
%s
BTF_KFUNCS_END(%s_kfunc_btf_ids)

static const struct btf_kfunc_id_set %s_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &%s_kfunc_btf_ids,
};
|} context.module_name kfunc_btf_ids context.module_name context.module_name context.module_name in

  let init_function = sprintf {|
static int __init %s_init(void)
{
    int ret;
    
    pr_info("Loading %s kfunc module\n");
    
    /* Register BTF kfunc set */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &%s_kfunc_set);
    if (ret < 0) {
        pr_err("Failed to register kfunc set: %%d\n", ret);
        return ret;
    }
    
    pr_info("%s kfunc module loaded successfully\n");
    return 0;
}

static void __exit %s_exit(void)
{
    /* Cleanup is handled automatically by the kernel during module unload */
    pr_info("%s kfunc module unloaded successfully\n");
}

module_init(%s_init);
module_exit(%s_exit);
|} context.module_name context.module_name context.module_name context.module_name context.module_name context.module_name context.module_name context.module_name in

  (* Combine all function implementations *)
  let all_implementations = if private_implementations = "" then
    kfunc_implementations
  else if kfunc_implementations = "" then  
    private_implementations
  else
    sprintf "%s\n\n%s" private_implementations kfunc_implementations
  in
  
  sprintf "%s\n/* Function prototypes */\n%s\n\n%s\n\n%s\n\n%s\n\n%s" 
    header 
    function_prototypes
    btf_declarations 
    all_implementations 
    btf_id_set 
    init_function

(** Extract kfunc functions from AST *)
let extract_kfunc_functions ast =
  List.filter_map (function
    | AttributedFunction attr_func ->
        (* Check if this is a kfunc *)
        let is_kfunc = List.exists (function
          | SimpleAttribute "kfunc" -> true
          | _ -> false
        ) attr_func.attr_list in
        if is_kfunc then Some attr_func.attr_function else None
    | _ -> None
  ) ast

(** Extract private functions from AST *)
let extract_private_functions ast =
  List.filter_map (function
    | AttributedFunction attr_func ->
        (* Check if this is a private function *)
        let is_private = List.exists (function
          | SimpleAttribute "private" -> true
          | _ -> false
        ) attr_func.attr_list in
        if is_private then Some attr_func.attr_function else None
    | _ -> None
  ) ast

(** Main entry point for kernel module generation *)
let generate_kernel_module_from_ast module_name ast =
  let kfunc_functions = extract_kfunc_functions ast in
  let private_functions = extract_private_functions ast in
  if kfunc_functions = [] && private_functions = [] then
    None  (* No kernel module functions found, don't generate module *)
  else
    let context = create_context module_name in
    let context_with_kfuncs = List.fold_left add_kfunc context kfunc_functions in
    let context_with_all = List.fold_left add_private context_with_kfuncs private_functions in
    Some (generate_kernel_module context_with_all) 