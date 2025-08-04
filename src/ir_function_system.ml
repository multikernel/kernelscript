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

(** Simplified IR Function System *)

open Ir

(** Function signature validation *)
type signature_info = {
  func_name: string;
  param_types: (string * ir_type) list;
  return_type: ir_type option;
  visibility: visibility;
  is_main: bool;
  is_valid: bool;
  validation_errors: string list;
}

let validate_function_signature (ir_func : ir_function) : signature_info =
  let errors = ref [] in
  
  let param_count = List.length ir_func.parameters in
  if param_count > 5 then
    errors := "Too many parameters (max 5 for eBPF)" :: !errors;
  
  (* Check if this is a struct_ops function - if so, skip main function validation *)
  let is_struct_ops_function = match ir_func.func_program_type with
    | Some Ast.StructOps -> true
    | _ -> false
  in
  
  (* Check if this is a probe function *)
  let is_kprobe_function = match ir_func.func_program_type with
    | Some (Ast.Probe _) -> true
    | _ -> false
  in
  
  if ir_func.is_main && not is_struct_ops_function && not is_kprobe_function then (
    if param_count <> 1 then
      errors := "Main function must have exactly one parameter (context)" :: !errors;
    match ir_func.parameters with
    | [(_, IRContext _)] -> ()
    | [(_, IRPointer (IRContext _, _))] -> ()
    | [(_, IRPointer (IRStruct ("__sk_buff", _), _))] -> ()  (* Also recognize __sk_buff as TC context *)
    | [(_, IRPointer (IRStruct (struct_name, _), _))] when String.starts_with struct_name ~prefix:"trace_event_raw_" -> ()  (* Recognize tracepoint BTF structs *)
    | _ -> errors := "Main function parameter must be a context type" :: !errors;
    
    (* Check return type based on context type *)
    let is_tc_program = match ir_func.parameters with
      | [(_, IRPointer (IRContext TcCtx, _))] -> true
      | [(_, IRContext TcCtx)] -> true
      | [(_, IRPointer (IRStruct ("__sk_buff", _), _))] -> true  (* Also recognize __sk_buff as TC *)
      | _ -> false
    in
    
    match ir_func.return_type with
    | Some (IRAction _) when not is_tc_program -> ()  (* Action types for programs that use actions *)
    | Some (IRI32) when is_tc_program -> ()  (* int return type for TC programs *)
    | Some (IRU32) when is_tc_program -> ()  (* Allow u32/int for TC programs *)
    | Some _ when is_tc_program -> errors := "TC programs must return int (i32)" :: !errors;
    | Some _ -> errors := "Main function must return an action type (or int for TC programs)" :: !errors;
    | None -> errors := "Main function must have a return type" :: !errors
  );
  
  (* Validation for kprobe functions *)
  if ir_func.is_main && is_kprobe_function then (
    (* Kprobe functions support up to 6 parameters (kernel function signature) *)
    if param_count > 6 then
      errors := "Kprobe functions support maximum 6 parameters" :: !errors;
    
    (* Validate return type for kprobe functions *)
    match ir_func.return_type with
    | Some (IRI32) -> ()  (* Standard kprobe return type *)
    | Some (IRU32) -> ()  (* Allow u32 as well *)
    | Some (IRVoid) -> () (* Allow void return type for some kprobes *)
    | Some _ -> errors := "Kprobe programs must return int (i32), u32, or void" :: !errors;
    | None -> errors := "Kprobe functions must have a return type" :: !errors
  );
  
  (* For struct_ops functions, we have different validation rules *)
  if is_struct_ops_function then (
    (* struct_ops functions can have various signatures depending on the struct_ops type *)
    (* For now, we'll be permissive and allow any signature *)
    ()
  );
  
  {
    func_name = ir_func.func_name;
    param_types = ir_func.parameters;
    return_type = ir_func.return_type;
    visibility = ir_func.visibility;
    is_main = ir_func.is_main;
    is_valid = !errors = [];
    validation_errors = List.rev !errors;
  }

(** Simple function system analysis *)
type simple_function_analysis = {
  signature_validations: signature_info list;
  analysis_summary: string;
}

(** Analyze a single IR program including kernel functions from multi-program context *)
let analyze_ir_program_with_kernel_functions (prog : ir_program) (kernel_functions : ir_function list) : simple_function_analysis =
  let entry_func = prog.entry_function in
  let entry_validation = validate_function_signature entry_func in
  
  (* Analyze all kernel functions as well *)
  let kernel_validations = List.map validate_function_signature kernel_functions in
  
  let all_validations = entry_validation :: kernel_validations in
  
  let valid_count = List.length (List.filter (fun sig_info -> sig_info.is_valid) all_validations) in
  let total_count = List.length all_validations in
  
  let summary = Printf.sprintf
    "Function Analysis:\n\
     - Entry function: %s\n\
     - Kernel functions: %d\n\
     - Total functions: %d\n\
     - Valid signatures: %d/%d"
    entry_func.func_name
    (List.length kernel_functions)
    total_count
    valid_count
    total_count in
  
  {
    signature_validations = all_validations;
    analysis_summary = summary;
  }

(** Original simple analysis for backward compatibility *)
let analyze_ir_program_simple (prog : ir_program) : simple_function_analysis =
  analyze_ir_program_with_kernel_functions prog []

(** Analyze multi-program structure to get all functions *)
let analyze_ir_multi_program (multi_prog : ir_multi_program) : simple_function_analysis =
  (* Get the first program as the main program to analyze *)
  let main_program = List.hd multi_prog.programs in
  analyze_ir_program_with_kernel_functions main_program multi_prog.kernel_functions 