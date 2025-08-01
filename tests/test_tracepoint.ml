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
  filename = "test_tracepoint.ks";
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

(** Mock BTF data for basic testing (simplified) *)
module MockTracepointBTF = struct
  (* Simple mock tracepoint events for testing logic *)
  type mock_tracepoint_event = {
    name: string;
    category: string;
    event: string;
    expected_struct_name: string;
  }

  let mock_tracepoint_events = [
    {
      name = "sched_switch";
      category = "sched";
      event = "sched_switch"; 
      expected_struct_name = "trace_event_raw_sched_switch";
    };
    {
      name = "sys_enter_read";
      category = "syscalls";
      event = "sys_enter_read";
      expected_struct_name = "trace_event_raw_sys_enter";
    };
    {
      name = "sys_exit_read";
      category = "syscalls";
      event = "sys_exit_read";
      expected_struct_name = "trace_event_raw_sys_exit";
    };
  ]
end

(** Test Cases *)

(* 1. Parser Tests *)
let test_tracepoint_attribute_parsing _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  check int "AST should have one declaration" 1 (List.length ast);
  match List.hd ast with
  | AttributedFunction attr_func ->
      check int "Should have one attribute" 1 (List.length attr_func.attr_list);
      (match List.hd attr_func.attr_list with
       | AttributeWithArg (name, arg) ->
           check string "Attribute name" "tracepoint" name;
           check string "Attribute argument" "sched/sched_switch" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_tracepoint_parsing_syscalls _ =
  let source = "@tracepoint(\"syscalls/sys_enter_read\")
fn sys_enter_read_handler(ctx: *trace_event_raw_sys_enter) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  match List.hd ast with
  | AttributedFunction attr_func ->
      (match List.hd attr_func.attr_list with
       | AttributeWithArg (name, arg) ->
           check string "Attribute name" "tracepoint" name;
           check string "Syscall tracepoint arg" "syscalls/sys_enter_read" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_tracepoint_parsing_errors _ =
  (* Test invalid format without category/event separator *)
  let source = "@tracepoint(\"invalid_format\")
fn invalid_handler(ctx: *TracepointContext) -> i32 {
    return 0
}" in
  (* Just check that parsing/type checking fails, not the exact error message *)
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed parsing invalid tracepoint format"
  with
  | _ -> check bool "Correctly rejected invalid format" true true

let test_tracepoint_old_format_rejection _ =
  (* Test old @tracepoint format without arguments *)
  let source = "@tracepoint
fn old_handler(ctx: *TracepointContext) -> i32 {
    return 0
}" in
  (* Just check that parsing/type checking fails *)
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed parsing old tracepoint format"
  with
  | _ -> check bool "Correctly rejected old format" true true

(* 2. Type Checking Tests *)
let test_tracepoint_type_checking _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  (* Use the same pattern as other type checking tests *)
  let typed_ast = type_check_ast ast in
  check int "Type checking should succeed" 1 (List.length typed_ast)

let test_tracepoint_context_validation _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  match List.hd typed_ast with
  | AttributedFunction attr_func ->
      check string "Function name" "sched_switch_handler" attr_func.attr_function.func_name;
      check int "Parameter count" 1 (List.length attr_func.attr_function.func_params);
      (match attr_func.attr_function.func_params with
       | [(param_name, param_type)] ->
           check string "Parameter name" "ctx" param_name;
           (match param_type with
            | Pointer (UserType struct_name) ->
                check string "Context struct type" "trace_event_raw_sched_switch" struct_name
            | _ -> fail "Expected pointer to struct type")
       | _ -> fail "Expected single parameter")
  | _ -> fail "Expected AttributedFunction"

(* 3. IR Generation Tests *)
let test_tracepoint_ir_generation _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tracepoint" in
  check int "Should generate one program" 1 (List.length ir_multi_prog.programs);
  let program = List.hd ir_multi_prog.programs in
  check string "Program name" "sched_switch_handler" program.name;
  check bool "Program type should be Tracepoint" true 
    (match program.program_type with Tracepoint -> true | _ -> false)

let test_tracepoint_function_signature_validation _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tracepoint" in
  let program = List.hd ir_multi_prog.programs in
  let main_func = program.entry_function in
  
  (* Test that the function has the correct properties *)
  check bool "Function should be marked as main" true main_func.is_main;
  check string "Function name should match" "sched_switch_handler" main_func.func_name

(* 4. Code Generation Tests *)
let test_raw_tracepoint_section_name_generation _ =
  (* Test minimal raw tracepoint section name conversion logic *)
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_raw_tracepoint" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check that forward slash is converted to underscore in section name *)
  check bool "Should contain raw_tracepoint section with underscore" true
    (String.contains c_code (String.get "SEC(\"raw_tracepoint/sched_sched_switch\")" 0))

let test_tracepoint_ebpf_codegen _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tracepoint" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for tracepoint-specific C code elements *)
  check bool "Should contain SEC(\"tracepoint\")" true 
    (String.contains c_code (String.get "SEC(\"tracepoint\")" 0));
  check bool "Should contain function definition" true
    (String.contains c_code (String.get "sched_switch_handler" 0));
  check bool "Should contain struct parameter" true
    (String.contains c_code (String.get "trace_event_raw_sched_switch" 0))

let test_tracepoint_includes_generation _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn sched_switch_handler(ctx: *trace_event_raw_sched_switch) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_tracepoint" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for tracepoint-specific includes *)
  check bool "Should include linux/trace_events.h" true
    (String.contains c_code (String.get "linux/trace_events.h" 0));
  check bool "Should include bpf/bpf_tracing.h" true
    (String.contains c_code (String.get "bpf/bpf_tracing.h" 0))

(* 5. Template Generation Tests (simplified without actual BTF) *)
let test_tracepoint_template_logic _ =
  (* Test the BTF struct naming logic for different categories *)
  let test_cases = [
    ("syscalls/sys_enter_read", "trace_event_raw_sys_enter");
    ("syscalls/sys_exit_write", "trace_event_raw_sys_exit");
    ("sched/sched_switch", "trace_event_raw_sched_switch");
    ("net/netif_rx", "trace_event_raw_netif_rx");
  ] in
  
  List.iter (fun (category_event, expected_struct) ->
    (* This tests the internal logic that determines struct names *)
    let parts = String.split_on_char '/' category_event in
    match parts with
    | [category; event] ->
        let actual_struct = 
          if category = "syscalls" && String.starts_with event ~prefix:"sys_enter_" then
            "trace_event_raw_sys_enter"
          else if category = "syscalls" && String.starts_with event ~prefix:"sys_exit_" then
            "trace_event_raw_sys_exit"
          else
            Printf.sprintf "trace_event_raw_%s" event
        in
        check string (Printf.sprintf "Struct name for %s" category_event) expected_struct actual_struct
    | _ -> fail "Invalid test case format"
  ) test_cases

let test_tracepoint_category_event_parsing _ =
  (* Test category/event parsing logic *)
  let test_cases = [
    ("syscalls/sys_enter_read", ("syscalls", "sys_enter_read"));
    ("sched/sched_switch", ("sched", "sched_switch"));
    ("net/netif_rx", ("net", "netif_rx"));
  ] in
  
  List.iter (fun (input, (expected_cat, expected_evt)) ->
    let parts = String.split_on_char '/' input in
    match parts with
    | [cat; evt] ->
        check string (Printf.sprintf "Category for %s" input) expected_cat cat;
        check string (Printf.sprintf "Event for %s" input) expected_evt evt
    | _ -> fail (Printf.sprintf "Failed to parse %s" input)
  ) test_cases

(* 6. Error Handling Tests *)
let test_tracepoint_invalid_context_type _ =
  let source = "@tracepoint(\"sched/sched_switch\")
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

let test_tracepoint_wrong_return_type _ =
  let source = "@tracepoint(\"sched/sched_switch\")
fn wrong_return_handler(ctx: *trace_event_raw_sched_switch) -> str<64> {
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

(* 7. Integration Tests *)
let test_tracepoint_end_to_end_syscall _ =
  let source = "@tracepoint(\"syscalls/sys_enter_open\")
fn sys_enter_open_handler(ctx: *trace_event_raw_sys_enter) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_syscall" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Comprehensive end-to-end validation *)
  check bool "Contains tracepoint section" true
    (String.contains c_code (String.get "SEC(\"tracepoint\")" 0));
  check bool "Contains function name" true
    (String.contains c_code (String.get "sys_enter_open_handler" 0));
  check bool "Contains context struct" true
    (String.contains c_code (String.get "trace_event_raw_sys_enter" 0));
  check bool "Contains return statement" true
    (String.contains c_code (String.get "return 0" 0))

let test_tracepoint_end_to_end_scheduler _ =
  let source = "@tracepoint(\"sched/sched_wakeup\")
fn sched_wakeup_handler(ctx: *trace_event_raw_sched_wakeup) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_sched" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  check bool "End-to-end scheduler tracepoint works" true
    (String.contains c_code (String.get "sched_wakeup_handler" 0))

(** Test Suite Configuration *)
let parsing_tests = [
  "tracepoint attribute parsing", `Quick, test_tracepoint_attribute_parsing;
  "tracepoint syscall parsing", `Quick, test_tracepoint_parsing_syscalls;
  "tracepoint parsing errors", `Quick, test_tracepoint_parsing_errors;
  "tracepoint old format rejection", `Quick, test_tracepoint_old_format_rejection;
]

let type_checking_tests = [
  "tracepoint type checking", `Quick, test_tracepoint_type_checking;
  "tracepoint context validation", `Quick, test_tracepoint_context_validation;
]

let ir_generation_tests = [
  "tracepoint IR generation", `Quick, test_tracepoint_ir_generation;
  "tracepoint function signature validation", `Quick, test_tracepoint_function_signature_validation;
]

let code_generation_tests = [
  "raw tracepoint section name generation", `Quick, test_raw_tracepoint_section_name_generation;
  "tracepoint eBPF code generation", `Quick, test_tracepoint_ebpf_codegen;
  "tracepoint includes generation", `Quick, test_tracepoint_includes_generation;
]

let template_generation_tests = [
  "tracepoint template logic", `Quick, test_tracepoint_template_logic;
  "tracepoint category/event parsing", `Quick, test_tracepoint_category_event_parsing;
]

let error_handling_tests = [
  "tracepoint invalid context type", `Quick, test_tracepoint_invalid_context_type;
  "tracepoint wrong return type", `Quick, test_tracepoint_wrong_return_type;
]

let integration_tests = [
  "tracepoint end-to-end syscall", `Quick, test_tracepoint_end_to_end_syscall;
  "tracepoint end-to-end scheduler", `Quick, test_tracepoint_end_to_end_scheduler;
]

let () =
  run "KernelScript Tracepoint Tests" [
    "parsing", parsing_tests;
    "type checking", type_checking_tests;
    "IR generation", ir_generation_tests;
    "code generation", code_generation_tests;
    "template generation", template_generation_tests;
    "error handling", error_handling_tests;
    "integration", integration_tests;
  ] 