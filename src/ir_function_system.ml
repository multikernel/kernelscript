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
  
  if ir_func.is_main then (
    if param_count <> 1 then
      errors := "Main function must have exactly one parameter (context)" :: !errors;
    match ir_func.parameters with
    | [(_, IRContext _)] -> ()
    | [(_, IRPointer (IRContext _, _))] -> ()
    | _ -> errors := "Main function parameter must be a context type" :: !errors;
    
    match ir_func.return_type with
    | Some (IRAction _) -> ()
    | Some _ -> errors := "Main function must return an action type" :: !errors;
    | None -> errors := "Main function must have a return type" :: !errors
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