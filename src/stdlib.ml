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
}

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
  };
  {
    name = "register";
    param_types = [UserType "struct_ops"]; (* Accept any struct_ops instance *)
    return_type = U32; (* Returns 0 on success *)
    description = "Register a struct_ops instance with the kernel";
    is_variadic = false;
    ebpf_impl = ""; (* Not available in eBPF context *)
    userspace_impl = "bpf_map__attach_struct_ops";
    kernel_impl = "";
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