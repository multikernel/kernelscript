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

(** KernelScript Standard Library
    This module defines built-in functions and their type signatures.
    Built-in functions are context-aware and translate differently 
    depending on the execution environment (eBPF vs userspace).
*)

open Ast

(** Helper function to take first n elements of a list *)
let rec take n lst =
  if n <= 0 then []
  else match lst with
  | [] -> []
  | h :: t -> h :: take (n - 1) t

(** Built-in function definition *)
type builtin_function = {
  name: string;
  param_types: bpf_type list;
  return_type: bpf_type;
  description: string;
  (* Function is variadic (accepts variable number of arguments) *)
  is_variadic: bool;
  (* Context-specific implementations *)
  ebpf_impl: string;      (* eBPF C implementation *)
  userspace_impl: string; (* Userspace C implementation *)
  kernel_impl: string;    (* Kernel module C implementation *)
  (* Optional custom validation function *)
  validate: (bpf_type list -> declaration list -> position -> bool * string option) option;
}

(** Validation function for register() - only accepts impl block arguments *)
let validate_register_function arg_types ast_context _pos =
  if List.length arg_types <> 1 then
    (false, Some "register() takes exactly one argument")
  else
    let arg_type = List.hd arg_types in
    match arg_type with
    | Struct struct_name | UserType struct_name -> 
        (* Check if this is an impl block with @struct_ops attribute *)
        let impl_block_info = List.fold_left (fun acc decl ->
          match decl with
          | ImplBlock impl_block when impl_block.impl_name = struct_name ->
              (* Extract the struct_ops name from the attribute *)
              let struct_ops_name = List.fold_left (fun acc_name attr ->
                match attr with
                | AttributeWithArg ("struct_ops", name) -> Some name
                | _ -> acc_name
              ) None impl_block.impl_attributes in
              Some (true, struct_ops_name)
          | _ -> acc
        ) None ast_context in
        
        (match impl_block_info with
         | Some (true, Some struct_ops_name) ->
             (* Validate that the struct_ops name is known *)
             if Struct_ops_registry.is_known_struct_ops struct_ops_name then
               (true, None)
             else
               (false, Some ("Unknown struct_ops type: '" ^ struct_ops_name ^ "'. Known types: " ^ 
                           String.concat ", " (Struct_ops_registry.get_all_known_struct_ops ())))
         | Some (true, None) ->
             (false, Some ("Malformed @struct_ops attribute - missing struct_ops name"))
         | Some (false, _) | None ->
             (false, Some ("register() can only be used with impl block instances (with @struct_ops attribute). '" ^ struct_name ^ "' is not an impl block.")))
    | _ -> 
        (false, Some "register() requires an impl block argument")

(** Standard library built-in functions *)
let builtin_functions = [
  {
    name = "print";
    param_types = []; (* Variadic - accepts any number of arguments *)
    return_type = U32; (* Returns 0 on success, like printf *)
    description = "Print formatted output to console (userspace), trace log (eBPF), or kernel log (kernel module)";
    is_variadic = true;
    ebpf_impl = "bpf_printk";
    userspace_impl = "printf";
    kernel_impl = "printk";
    validate = None;
  };
  {
    name = "load";
    param_types = [Function ([], U32)]; (* Accept any function - will be generalized in type checker *)
    return_type = ProgramHandle; (* Returns program handle instead of fd *)
    description = "Load an eBPF attributed function and return its handle";
    is_variadic = false;
    ebpf_impl = ""; (* Not available in eBPF context *)
    userspace_impl = "bpf_prog_load";
    kernel_impl = "";
    validate = None;
  };
  {
    name = "attach";
    param_types = [ProgramHandle; Str 128; U32]; (* program handle, target interface, flags *)
    return_type = U32; (* Returns 0 on success *)
    description = "Attach a loaded eBPF program to a target with flags";
    is_variadic = false;
    ebpf_impl = ""; (* Not available in eBPF context *)
    userspace_impl = "bpf_prog_attach";
    kernel_impl = "";
    validate = None;
  };
  {
    name = "register";
    param_types = []; (* Custom validation handles type checking *)
    return_type = U32; (* Returns 0 on success *)
    description = "Register an impl block instance (struct_ops) with the kernel";
    is_variadic = false;
    ebpf_impl = ""; (* Not available in eBPF context *)
    userspace_impl = "bpf_map__attach_struct_ops";
    kernel_impl = "";
    validate = Some validate_register_function;
  };
  {
    name = "test";
    param_types = []; (* Use custom validation for flexible type checking *)
    return_type = U32; (* Returns program return value *)
    description = "Execute eBPF program with test data and return result";
    is_variadic = false;
    ebpf_impl = ""; (* Not available in eBPF context *)
    userspace_impl = "bpf_prog_test_run";
    kernel_impl = "";
    validate = None; (* Accept any two arguments - validate during compilation *)
  };

]

(** Get built-in function definition by name *)
let get_builtin_function name =
  List.find_opt (fun f -> f.name = name) builtin_functions

(** Check if a function name is a built-in function *)
let is_builtin_function name =
  List.exists (fun f -> f.name = name) builtin_functions

(** Get built-in function signature for type checking *)
let get_builtin_function_signature name =
  match get_builtin_function name with
  | Some func -> 
      if func.is_variadic then
        (* For variadic functions, we accept any arguments *)
        Some ([], func.return_type)
      else
        Some (func.param_types, func.return_type)
  | None -> None

(** Get context-specific implementation *)
let get_ebpf_implementation name =
  match get_builtin_function name with
  | Some func -> Some func.ebpf_impl
  | None -> None

let get_userspace_implementation name =
  match get_builtin_function name with
  | Some func -> Some func.userspace_impl
  | None -> None

let get_kernel_implementation name =
  match get_builtin_function name with
  | Some func -> Some func.kernel_impl
  | None -> None

(** Validate builtin function call with custom validation if available *)
let validate_builtin_call name arg_types ast_context pos =
  match get_builtin_function name with
  | Some func ->
      (match func.validate with
       | Some validate_fn -> validate_fn arg_types ast_context pos
       | None -> (true, None)) (* No custom validation - accept *)
  | None -> (false, Some ("Unknown builtin function: " ^ name))

(** Format arguments for function call based on context *)
let format_function_args context_type args =
  match context_type with
  | `eBPF -> 
      (* For eBPF, we need to format arguments for bpf_printk *)
      (* bpf_printk expects format string + up to 3 additional arguments *)
      (match args with
       | [] -> ["\"\""] (* Empty print *)
       | first :: rest ->
           (* Convert all arguments to strings for format string *)
           let format_parts = List.mapi (fun i _ -> 
             match i with
             | 0 -> "%s"
             | 1 -> "%d" 
             | 2 -> "%d"
             | 3 -> "%d"
             | _ -> "" (* bpf_printk limited to 4 args total *)
           ) (first :: rest) in
           let format_str = "\"" ^ String.concat "" format_parts ^ "\"" in
           format_str :: (take (min 3 (List.length rest)) rest))
  | `Userspace ->
      (* For userspace, printf can handle more flexible formatting *)
      (match args with
       | [] -> ["\"\\n\""] (* Empty print with newline *)
       | _ -> args) (* Pass arguments as-is *) 