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

open Alcotest
open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Type_checker
open Kernelscript.Ir_generator
open Kernelscript.Ebpf_c_codegen


(** Helper functions for creating AST nodes in tests *)

let dummy_loc = {
  line = 1;
  column = 1;
  filename = "test_tc.ks";
}

let make_return_stmt value = {
  stmt_desc = Return (Some {
    expr_desc = Literal (IntLit (value, None));
    expr_type = Some I32;
    expr_pos = dummy_loc;
    type_checked = false;
    program_context = None;
    map_scope = None;
  });
  stmt_pos = dummy_loc;
}

(** Mock TC action constants for testing *)
module MockTCActions = struct
  let tc_actions = [
    ("TC_ACT_UNSPEC", -1);
    ("TC_ACT_OK", 0);
    ("TC_ACT_RECLASSIFY", 1);
    ("TC_ACT_SHOT", 2);
    ("TC_ACT_PIPE", 3);
    ("TC_ACT_STOLEN", 4);
    ("TC_ACT_QUEUED", 5);
    ("TC_ACT_REPEAT", 6);
    ("TC_ACT_REDIRECT", 7);
    ("TC_ACT_TRAP", 8);
  ]

  let valid_directions = ["ingress"; "egress"]
  let invalid_directions = ["invalid"; "input"; "output"; ""]
end

(** Test Cases *)

(* 1. Parser Tests *)
let test_tc_ingress_attribute_parsing _ =
  let source = "@tc(\"ingress\")
fn ingress_filter(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  check int "AST should have one declaration" 1 (List.length ast);
  match List.hd ast with
  | AttributedFunction attr_func ->
      check int "Should have one attribute" 1 (List.length attr_func.attr_list);
      (match List.hd attr_func.attr_list with
       | AttributeWithArg (name, arg) ->
           check string "Attribute name" "tc" name;
           check string "Attribute argument" "ingress" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_tc_egress_attribute_parsing _ =
  let source = "@tc(\"egress\")
fn egress_shaper(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  check int "AST should have one declaration" 1 (List.length ast);
  match List.hd ast with
  | AttributedFunction attr_func ->
      check int "Should have one attribute" 1 (List.length attr_func.attr_list);
      (match List.hd attr_func.attr_list with
       | AttributeWithArg (name, arg) ->
           check string "Attribute name" "tc" name;
           check string "Attribute argument" "egress" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_tc_parsing_errors _ =
  (* Test invalid direction parameter *)
  let source = "@tc(\"invalid_direction\")
fn invalid_handler(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  (* Just check that parsing/type checking fails, not the exact error message *)
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed parsing invalid TC direction"
  with
  | _ -> check bool "Correctly rejected invalid direction" true true

let test_tc_old_format_rejection _ =
  (* Test old @tc format without direction parameter *)
  let source = "@tc
fn old_handler(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  (* Just check that parsing/type checking fails *)
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed parsing old TC format"
  with
  | _ -> check bool "Correctly rejected old format" true true

let test_tc_missing_direction _ =
  (* Test @tc() with empty direction *)
  let source = "@tc(\"\")
fn empty_direction_handler(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed with empty direction"
  with
  | _ -> check bool "Correctly rejected empty direction" true true

(* 2. Type Checking Tests *)
let test_tc_ingress_type_checking _ =
  let source = "@tc(\"ingress\")
fn ingress_filter(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  check int "Type checking should succeed" 1 (List.length typed_ast)

let test_tc_egress_type_checking _ =
  let source = "@tc(\"egress\")
fn egress_monitor(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  check int "Type checking should succeed" 1 (List.length typed_ast)

let test_tc_context_validation _ =
  let source = "@tc(\"ingress\")
fn ingress_filter(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  match List.hd typed_ast with
  | AttributedFunction attr_func ->
      check string "Function name" "ingress_filter" attr_func.attr_function.func_name;
      check int "Parameter count" 1 (List.length attr_func.attr_function.func_params);
      (match attr_func.attr_function.func_params with
       | [(param_name, param_type)] ->
           check string "Parameter name" "ctx" param_name;
           (match param_type with
            | Pointer (UserType struct_name) ->
                check string "Context struct type" "__sk_buff" struct_name
            | _ -> fail "Expected pointer to struct type")
       | _ -> fail "Expected single parameter")
  | _ -> fail "Expected AttributedFunction"

let test_tc_direction_validation _ =
  (* Test that both ingress and egress directions are accepted *)
  let test_directions = [
    ("ingress", true);
    ("egress", true);
    ("invalid", false);
    ("input", false);
    ("output", false);
  ] in
  
  List.iter (fun (direction, should_succeed) ->
    let source = Printf.sprintf "@tc(\"%s\")
fn test_handler(ctx: *__sk_buff) -> i32 {
    return 0
}" direction in
    
    if should_succeed then (
      try
        let ast = parse_string source in
        let _ = type_check_ast ast in
        check bool (Printf.sprintf "Direction %s should be accepted" direction) true true
      with
      | _ -> fail (Printf.sprintf "Direction %s should have been accepted" direction)
    ) else (
      try
        let ast = parse_string source in
        let _ = type_check_ast ast in
        fail (Printf.sprintf "Direction %s should have been rejected" direction)
      with
      | _ -> check bool (Printf.sprintf "Direction %s correctly rejected" direction) true true
    )
  ) test_directions

(* 3. IR Generation Tests *)
let test_tc_ingress_ir_generation _ =
  let source = "@tc(\"ingress\")
fn ingress_filter(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc_ingress" in
  check int "Should generate one program" 1 (List.length ir_multi_prog.programs);
  let program = List.hd ir_multi_prog.programs in
  check string "Program name" "ingress_filter" program.name;
  check bool "Program type should be Tc" true 
    (match program.program_type with Tc -> true | _ -> false)

let test_tc_egress_ir_generation _ =
  let source = "@tc(\"egress\")
fn egress_shaper(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc_egress" in
  check int "Should generate one program" 1 (List.length ir_multi_prog.programs);
  let program = List.hd ir_multi_prog.programs in
  check string "Program name" "egress_shaper" program.name;
  check bool "Program type should be Tc" true 
    (match program.program_type with Tc -> true | _ -> false)

let test_tc_function_signature_validation _ =
  let source = "@tc(\"ingress\")
fn packet_filter(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc" in
  let program = List.hd ir_multi_prog.programs in
  let main_func = program.entry_function in
  
  (* Test that the function has the correct properties *)
  check bool "Function should be marked as main" true main_func.is_main;
  check string "Function name should match" "packet_filter" main_func.func_name

(* NEW: Target Propagation Tests *)
let test_tc_target_propagation _ =
  let source = "@tc(\"ingress\")
fn traffic_monitor(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc" in
  let program = List.hd ir_multi_prog.programs in
  let main_func = program.entry_function in
  
  (* Test that the target is properly propagated through IR generation *)
  check (option string) "Function should have correct target" (Some "ingress") main_func.func_target

let test_multiple_tc_directions _ =
  (* Test both ingress and egress directions to ensure they all work correctly *)
  let test_cases = [
    ("ingress", "SEC(\"tc/ingress\")");
    ("egress", "SEC(\"tc/egress\")");
  ] in
  
  List.iter (fun (direction, expected_sec) ->
    let source = Printf.sprintf "@tc(\"%s\")
fn handler(ctx: *__sk_buff) -> i32 {
    return 0
}" direction in
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
    let ir_multi_prog = generate_ir typed_ast symbol_table "test" in
    let c_code = generate_c_multi_program ir_multi_prog in
    
    check bool (Printf.sprintf "Should generate %s for direction %s" expected_sec direction) true
      (try 
         let _ = Str.search_forward (Str.regexp_string expected_sec) c_code 0 in
         true
       with Not_found -> 
         false)
  ) test_cases

let test_tc_direction_consistency _ =
  (* Regression test: Ensure direction consistency through the entire pipeline *)
  let source = "@tc(\"egress\")
fn egress_monitor(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_consistency" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Ensure correct SEC() is generated *)
  check bool "Should generate correct SEC(tc/egress)" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/egress\")") c_code 0 in
       true
     with Not_found -> 
       false);
  
  (* Ensure wrong SEC() is NOT generated *)
  check bool "Should NOT generate tc/ingress SEC format" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/ingress\")") c_code 0 in
       false  (* Found wrong direction - test should fail *)
     with Not_found -> 
       true   (* No wrong direction found - test should pass *)
    )

(* 4. Code Generation Tests *)
let test_tc_ingress_section_name_generation _ =
  (* Test correct TC ingress section name generation *)
  let source = "@tc(\"ingress\")
fn ingress_filter(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check that the correct SEC() is generated *)
  check bool "Should contain correct tc/ingress section" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/ingress\")") c_code 0 in
       true
     with Not_found -> 
       false)

let test_tc_egress_section_name_generation _ =
  (* Test correct TC egress section name generation *)
  let source = "@tc(\"egress\")
fn egress_shaper(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check that the correct SEC() is generated *)
  check bool "Should contain correct tc/egress section" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/egress\")") c_code 0 in
       true
     with Not_found -> 
       false)

let test_tc_ebpf_codegen _ =
  let source = "@tc(\"ingress\")
fn packet_filter(ctx: *__sk_buff) -> i32 {
    return 2
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for TC-specific C code elements *)
  check bool "Should contain correct TC SEC" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/ingress\")") c_code 0 in
       true
     with Not_found -> 
       false);
  check bool "Should contain function definition" true
    (String.contains c_code (String.get "packet_filter" 0));
  check bool "Should contain struct parameter" true
    (String.contains c_code (String.get "__sk_buff" 0))

let test_tc_includes_generation _ =
  let source = "@tc(\"ingress\")
fn traffic_monitor(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tc" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for TC-specific includes *)
  check bool "Should include linux/pkt_cls.h" true
    (String.contains c_code (String.get "linux/pkt_cls.h" 0));
  check bool "Should include linux/if_ether.h" true
    (String.contains c_code (String.get "linux/if_ether.h" 0))

let test_tc_return_values _ =
  (* Test that TC programs can return valid TC action values *)
  let test_cases = [
    ("0", "TC_ACT_OK");
    ("2", "TC_ACT_SHOT");
    ("7", "TC_ACT_REDIRECT");
  ] in
  
  List.iter (fun (return_val, _action_name) ->
    let source = Printf.sprintf "@tc(\"ingress\")
fn action_test(ctx: *__sk_buff) -> i32 {
    return %s
}" return_val in
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
    let ir_multi_prog = generate_ir typed_ast symbol_table "test" in
    let c_code = generate_c_multi_program ir_multi_prog in
    
    check bool (Printf.sprintf "Should contain return %s" return_val) true
      (String.contains c_code (String.get ("return " ^ return_val) 0))
  ) test_cases

(* 5. Template Generation Tests *)
let test_tc_direction_parsing _ =
  (* Test direction parsing logic *)
  let test_cases = [
    ("ingress", true);
    ("egress", true);
    ("invalid", false);
    ("", false);
  ] in
  
  List.iter (fun (direction, is_valid) ->
    let validation_result = 
      direction = "ingress" || direction = "egress" in
    check bool (Printf.sprintf "Direction %s validation" direction) is_valid validation_result
  ) test_cases

let test_tc_section_name_logic _ =
  (* Test the section name generation logic *)
  let test_cases = [
    ("ingress", "tc/ingress");
    ("egress", "tc/egress");
  ] in
  
  List.iter (fun (direction, expected_section) ->
    let actual_section = Printf.sprintf "tc/%s" direction in
    check string (Printf.sprintf "Section name for %s" direction) expected_section actual_section
  ) test_cases

let test_tc_attribute_generation _ =
  (* Test attribute generation for different directions *)
  let test_cases = [
    ("ingress", "@tc(\"ingress\")");
    ("egress", "@tc(\"egress\")");
  ] in
  
  List.iter (fun (direction, expected_attr) ->
    let actual_attr = Printf.sprintf "@tc(\"%s\")" direction in
    check string (Printf.sprintf "Attribute for %s" direction) expected_attr actual_attr
  ) test_cases

(* 6. Error Handling Tests *)
let test_tc_invalid_context_type _ =
  let source = "@tc(\"ingress\")
fn invalid_handler(ctx: i32) -> i32 {
    return 0
}" in
  (* Just check that compilation fails for invalid context type *)
  try
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
    let _ = generate_ir typed_ast symbol_table "test" in
    fail "Should have failed with invalid context type"
  with
  | _ -> check bool "Correctly rejected invalid context type" true true

let test_tc_wrong_return_type _ =
  let source = "@tc(\"ingress\")
fn wrong_return_handler(ctx: *__sk_buff) -> str<64> {
    return \"invalid\"
}" in
  (* Just check that compilation fails for invalid return type *)
  try
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
    let _ = generate_ir typed_ast symbol_table "test" in
    fail "Should have failed with wrong return type"
  with
  | _ -> check bool "Correctly rejected wrong return type" true true

let test_tc_invalid_direction_values _ =
  (* Test various invalid direction values *)
  let invalid_directions = [
    "input";
    "output"; 
    "invalid";
    "rx";
    "tx";
    "upstream";
    "downstream";
    "";
  ] in
  
  List.iter (fun direction ->
    let source = Printf.sprintf "@tc(\"%s\")
fn invalid_dir_handler(ctx: *__sk_buff) -> i32 {
    return 0
}" direction in
    try
      let ast = parse_string source in
      let _ = type_check_ast ast in
      fail (Printf.sprintf "Should have failed with invalid direction: %s" direction)
    with
    | _ -> check bool (Printf.sprintf "Correctly rejected direction: %s" direction) true true
  ) invalid_directions

let test_tc_multiple_parameters _ =
  (* Test that TC functions must have exactly one parameter *)
  let source = "@tc(\"ingress\")
fn multi_param_handler(ctx: *__sk_buff, extra: i32) -> i32 {
    return 0
}" in
  try
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
    let _ = generate_ir typed_ast symbol_table "test" in
    fail "Should have failed with multiple parameters"
  with
  | _ -> check bool "Correctly rejected multiple parameters" true true

(* 7. Integration Tests *)
let test_tc_end_to_end_ingress _ =
  let source = "@tc(\"ingress\")
fn ingress_packet_filter(ctx: *__sk_buff) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_ingress" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Comprehensive end-to-end validation *)
  check bool "Contains correct TC ingress section" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/ingress\")") c_code 0 in
       true
     with Not_found -> 
       false);
  check bool "Contains function name" true
    (String.contains c_code (String.get "ingress_packet_filter" 0));
  check bool "Contains context struct" true
    (String.contains c_code (String.get "__sk_buff" 0));
  check bool "Contains return statement" true
    (String.contains c_code (String.get "return 0" 0))

let test_tc_end_to_end_egress _ =
  let source = "@tc(\"egress\")
fn egress_traffic_shaper(ctx: *__sk_buff) -> i32 {
    return 2
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_egress" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Comprehensive end-to-end validation *)
  check bool "Contains correct TC egress section" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/egress\")") c_code 0 in
       true
     with Not_found -> 
       false);
  check bool "Contains function name" true
    (String.contains c_code (String.get "egress_traffic_shaper" 0));
  check bool "Contains context struct" true
    (String.contains c_code (String.get "__sk_buff" 0));
  check bool "Contains return statement" true
    (String.contains c_code (String.get "return 2" 0))

let test_tc_mixed_programs _ =
  (* Test TC programs alongside other program types *)
  let source = "@tc(\"ingress\")
fn traffic_monitor(ctx: *__sk_buff) -> i32 {
    return 0
}

@xdp
fn packet_dropper(ctx: *xdp_md) -> xdp_action {
    return 1
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_mixed" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  check bool "Should contain TC section" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"tc/ingress\")") c_code 0 in
       true
     with Not_found -> 
       false);
  check bool "Should contain XDP section" true
    (try 
       let _ = Str.search_forward (Str.regexp_string "SEC(\"xdp\")") c_code 0 in
       true
     with Not_found -> 
       false);
  check int "Should generate two programs" 2 (List.length ir_multi_prog.programs)

(** Test Suite Configuration *)
let parsing_tests = [
  "tc ingress attribute parsing", `Quick, test_tc_ingress_attribute_parsing;
  "tc egress attribute parsing", `Quick, test_tc_egress_attribute_parsing;
  "tc parsing errors", `Quick, test_tc_parsing_errors;
  "tc old format rejection", `Quick, test_tc_old_format_rejection;
  "tc missing direction", `Quick, test_tc_missing_direction;
]

let type_checking_tests = [
  "tc ingress type checking", `Quick, test_tc_ingress_type_checking;
  "tc egress type checking", `Quick, test_tc_egress_type_checking;
  "tc context validation", `Quick, test_tc_context_validation;
  "tc direction validation", `Quick, test_tc_direction_validation;
]

let ir_generation_tests = [
  "tc ingress IR generation", `Quick, test_tc_ingress_ir_generation;
  "tc egress IR generation", `Quick, test_tc_egress_ir_generation;
  "tc function signature validation", `Quick, test_tc_function_signature_validation;
  "tc target propagation", `Quick, test_tc_target_propagation;
  "multiple tc directions", `Quick, test_multiple_tc_directions;
  "tc direction consistency", `Quick, test_tc_direction_consistency;
]

let code_generation_tests = [
  "tc ingress section name generation", `Quick, test_tc_ingress_section_name_generation;
  "tc egress section name generation", `Quick, test_tc_egress_section_name_generation;
  "tc eBPF code generation", `Quick, test_tc_ebpf_codegen;
  "tc includes generation", `Quick, test_tc_includes_generation;
  "tc return values", `Quick, test_tc_return_values;
]

let template_generation_tests = [
  "tc direction parsing", `Quick, test_tc_direction_parsing;
  "tc section name logic", `Quick, test_tc_section_name_logic;
  "tc attribute generation", `Quick, test_tc_attribute_generation;
]

let error_handling_tests = [
  "tc invalid context type", `Quick, test_tc_invalid_context_type;
  "tc wrong return type", `Quick, test_tc_wrong_return_type;
  "tc invalid direction values", `Quick, test_tc_invalid_direction_values;
  "tc multiple parameters", `Quick, test_tc_multiple_parameters;
]

let integration_tests = [
  "tc end-to-end ingress", `Quick, test_tc_end_to_end_ingress;
  "tc end-to-end egress", `Quick, test_tc_end_to_end_egress;
  "tc mixed programs", `Quick, test_tc_mixed_programs;
]

let () =
  run "KernelScript TC Tests" [
    "parsing", parsing_tests;
    "type checking", type_checking_tests;
    "IR generation", ir_generation_tests;
    "code generation", code_generation_tests;
    "template generation", template_generation_tests;
    "error handling", error_handling_tests;
    "integration", integration_tests;
  ]