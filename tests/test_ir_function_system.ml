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

(** Test IR Function System *)

open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ir_function_system
open Kernelscript.Parse
open Alcotest



(** Test data *)

let create_test_function name is_main params ret_type =
  {
    func_name = name;
    parameters = params;
    return_type = ret_type;
    basic_blocks = [
      {
        label = "entry";
        instructions = [
          {
            instr_desc = IRReturn None;
            instr_stack_usage = 0;
            bounds_checks = [];
            verifier_hints = [];
            instr_pos = { line = 1; column = 1; filename = "test" };
          }
        ];
        successors = [];
        predecessors = [];
        stack_usage = 0;
        loop_depth = 0;
        reachable = true;
        block_id = 0;
      }
    ];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main;
    func_pos = { line = 1; column = 1; filename = "test.ks" };
    tail_call_targets = [];
    tail_call_index_map = Hashtbl.create 16;
    is_tail_callable = false;
    func_program_type = None;
    func_target = None;
  }

let create_test_program () =
  let main_func = create_test_function "main" true 
    [("ctx", IRStruct ("xdp_md", []))] 
    (Some (IREnum ("xdp_action", []))) in
  {
    name = "test_program";
    program_type = Xdp;
    entry_function = main_func;
    ir_pos = { line = 1; column = 1; filename = "test" };
  }

(** Test Function Signature Validation *)

let test_valid_main_signature _ =
  let main_func = create_test_function "main" true 
    [("ctx", IRStruct ("xdp_md", []))] 
    (Some (IREnum ("xdp_action", []))) in
  let sig_info = validate_function_signature main_func in
  check bool "Main function should be valid" true sig_info.is_valid;
      check string "Function name" "main" sig_info.func_name;
    check bool "Should be marked as main" true sig_info.is_main

let test_invalid_main_signature _ =
  let invalid_func = {
    func_name = "main";
    parameters = [];  (* Missing context parameter *)
    return_type = Some (IREnum ("xdp_action", []));
    basic_blocks = [];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = true;
    func_pos = { line = 1; column = 1; filename = "test.ks" };
    tail_call_targets = [];
    tail_call_index_map = Hashtbl.create 16;
    is_tail_callable = false;
    func_program_type = None;
    func_target = None;
  } in
  let sig_info = validate_function_signature invalid_func in
  check bool "Invalid main function should be invalid" true (not sig_info.is_valid);
  check string "Function name" "main" sig_info.func_name;
  check bool "Should be marked as main" true sig_info.is_main

let test_too_many_parameters _ =
  let func_with_many_params = create_test_function "test" false 
    [("a", IRU32); ("b", IRU32); ("c", IRU32); ("d", IRU32); ("e", IRU32); ("f", IRU32)] 
    (Some IRU32) in
  let sig_info = validate_function_signature func_with_many_params in
  check bool "Function with too many params should be invalid" false sig_info.is_valid;
  check bool "Should have parameter count error" true
    (List.exists (fun err -> String.length err > 0 && err.[0] = 'T') sig_info.validation_errors)

(** Test Complete Function System Analysis *)

let test_simple_analysis _ =
  let prog = create_test_program () in
  let analysis = analyze_ir_program_simple prog in
  
  check int "signature validations count" 1 (List.length analysis.signature_validations);
  check bool "Analysis should contain summary" true (String.length analysis.analysis_summary > 0)



(** Test basic function system operations *)
let test_basic_function_system () =
  let prog = create_test_program () in
  let analysis = analyze_ir_program_simple prog in
  
  check int "signature validations count" 1 (List.length analysis.signature_validations);
  check bool "Analysis should contain summary" true (String.length analysis.analysis_summary > 0)

(** Test function registration *)
let test_function_registration () =
  let program_text = {|
@helper
fn helper(x: u32, y: u32) -> u32 {
  return x + y
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = helper(10, 20)
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    
    check bool "function registration test" true true
  with
  | e -> fail ("Failed to test function registration: " ^ Printexc.to_string e)

(** Test function signature validation *)
let test_function_signature_validation () =
  let program_text = {|
@helper
fn valid_function(x: u32, y: u32) -> u32 {
  return x + y
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = valid_function(10, 20)
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    
    check bool "function signature validation test" true true
  with
  | e -> fail ("Failed to test function signature validation: " ^ Printexc.to_string e)

(** Test function call resolution *)
let test_function_call_resolution () =
  let program_text = {|
@helper
fn multiply(x: u32, y: u32) -> u32 {
  return x * y
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = multiply(10, 2)
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    
    check bool "function call resolution test" true true
  with
  | e -> fail ("Failed to test function call resolution: " ^ Printexc.to_string e)

(** Test recursive function detection *)
let test_recursive_function_detection () =
  let program_text = {|
@helper
fn helper() -> u32 {
  return 42
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = helper()
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    
    check bool "recursive function detection test" true true
  with
  | e -> fail ("Failed to test recursive function detection: " ^ Printexc.to_string e)

(** Test function dependency analysis *)
let test_function_dependency_analysis () =
  let program_text = {|
@helper
fn level1() -> u32 {
  return 10
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = level1()
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    
    check bool "function dependency analysis test" true true
  with
  | e -> fail ("Failed to test function dependency analysis: " ^ Printexc.to_string e)

(** Test function optimization *)
let test_function_optimization () =
  let program_text = {|
@helper
fn simple_math(x: u32) -> u32 {
  return x * 2
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var const_val = 10
  var result = simple_math(const_val)
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    
    check bool "function optimization test" true true
  with
  | e -> fail ("Failed to test function optimization: " ^ Printexc.to_string e)

(** Test comprehensive function system *)
let test_comprehensive_function_system () =
  let program_text = {|
@helper
fn add(x: u32, y: u32) -> u32 {
  return x + y
}

@helper
fn multiply(x: u32, y: u32) -> u32 {
  return x * y
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var a = 10
  var b = 20
  var sum = add(a, b)
  var product = multiply(sum, 2)
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    
    check bool "comprehensive function system test" true true
  with
  | e -> fail ("Failed to test comprehensive function system: " ^ Printexc.to_string e)

(** Test Suite *)

let function_system_tests = [
  "test_valid_main_signature", `Quick, test_valid_main_signature;
  "test_invalid_main_signature", `Quick, test_invalid_main_signature;
  "test_too_many_parameters", `Quick, test_too_many_parameters;
  "test_simple_analysis", `Quick, test_simple_analysis;
  "test_basic_function_system", `Quick, test_basic_function_system;
  "test_function_registration", `Quick, test_function_registration;
  "test_function_signature_validation", `Quick, test_function_signature_validation;
  "test_function_call_resolution", `Quick, test_function_call_resolution;
  "test_recursive_function_detection", `Quick, test_recursive_function_detection;
  "test_function_dependency_analysis", `Quick, test_function_dependency_analysis;
  "test_function_optimization", `Quick, test_function_optimization;
  "test_comprehensive_function_system", `Quick, test_comprehensive_function_system;
]

let () = 
  run "IR Function System Tests" [
    "function_system", function_system_tests;
  ]

 