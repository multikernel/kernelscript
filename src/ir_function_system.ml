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

let analyze_ir_program_simple (prog : ir_program) : simple_function_analysis =
  let all_functions = prog.main_function :: prog.functions in
  let signature_validations = List.map validate_function_signature all_functions in
  
  let valid_signatures = List.filter (fun sig_info -> sig_info.is_valid) signature_validations in
  let invalid_signatures = List.filter (fun sig_info -> not sig_info.is_valid) signature_validations in
  
  let summary = Printf.sprintf
    "Simple Function Analysis:\n\
     - Total functions: %d\n\
     - Valid signatures: %d\n\
     - Invalid signatures: %d"
    (List.length all_functions)
    (List.length valid_signatures)
    (List.length invalid_signatures) in
  
  {
    signature_validations;
    analysis_summary = summary;
  } 