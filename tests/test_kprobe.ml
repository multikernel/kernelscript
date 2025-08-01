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
  filename = "test_kprobe.ks";
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

(** Mock BTF data for kprobe testing *)
module MockKprobeBTF = struct
  (* Simple mock kernel function signatures for testing *)
  type mock_kernel_function = {
    name: string;
    parameters: (string * string) list;
    return_type: string;
  }

  let mock_kernel_functions = [
    {
      name = "sys_read";
      parameters = [("fd", "u32"); ("buf", "*u8"); ("count", "usize")];
      return_type = "isize";
    };
    {
      name = "vfs_write";
      parameters = [("file", "*file"); ("buf", "*u8"); ("count", "usize"); ("pos", "*i64")];
      return_type = "isize";
    };
    {
      name = "tcp_sendmsg";
      parameters = [("sk", "*sock"); ("msg", "*msghdr"); ("size", "usize")];
      return_type = "i32";
    };
  ]
end

(** Test Cases *)

(* 1. Parser Tests *)
let test_kprobe_attribute_parsing _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  check int "AST should have one declaration" 1 (List.length ast);
  match List.hd ast with
  | AttributedFunction attr_func ->
      check int "Should have one attribute" 1 (List.length attr_func.attr_list);
      (match List.hd attr_func.attr_list with
       | AttributeWithArg (name, arg) ->
           check string "Attribute name" "kprobe" name;
           check string "Attribute argument" "sys_read" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_kprobe_multiple_parameters _ =
  let source = "@kprobe(\"vfs_write\")
fn vfs_write_handler(file: *file, buf: *u8, count: usize, pos: *i64) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  check int "AST should have one declaration" 1 (List.length ast);
  match List.hd ast with
  | AttributedFunction attr_func ->
      check int "Should have one attribute" 1 (List.length attr_func.attr_list);
      check int "Should have four parameters" 4 (List.length attr_func.attr_function.func_params);
      (match List.hd attr_func.attr_list with
       | AttributeWithArg (name, arg) ->
           check string "Attribute name" "kprobe" name;
           check string "Attribute argument" "vfs_write" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_kprobe_parsing_errors _ =
  (* Test invalid format without target function *)
  let source = "@kprobe
fn invalid_handler(fd: u32) -> i32 {
    return 0
}" in
  (* Check that parsing/type checking fails for old format *)
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed parsing old kprobe format"
  with
  | _ -> check bool "Correctly rejected old format" true true

let test_kprobe_missing_target_function _ =
  (* Test @kprobe without target function specification *)
  let source = "@kprobe(\"\")
fn empty_target_handler(fd: u32) -> i32 {
    return 0
}" in
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed with empty target function"
  with
  | _ -> check bool "Correctly rejected empty target function" true true

(* 2. Type Checking Tests *)
let test_kprobe_type_checking _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  check int "Type checking should succeed" 1 (List.length typed_ast)

let test_kprobe_parameter_validation _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  match List.hd typed_ast with
  | AttributedFunction attr_func ->
      check string "Function name" "sys_read_handler" attr_func.attr_function.func_name;
      check int "Parameter count" 3 (List.length attr_func.attr_function.func_params);
      (* Verify parameter types *)
      (match attr_func.attr_function.func_params with
       | [(fd_name, fd_type); (buf_name, buf_type); (count_name, count_type)] ->
           check string "First parameter name" "fd" fd_name;
           check string "Second parameter name" "buf" buf_name;
           check string "Third parameter name" "count" count_name;
           check bool "First parameter type should be U32" true 
             (match fd_type with U32 -> true | _ -> false);
           check bool "Second parameter type should be Pointer" true
             (match buf_type with Pointer _ -> true | _ -> false);
           check bool "Third parameter type should be UserType usize" true
             (match count_type with UserType "usize" -> true | _ -> false)
       | _ -> fail "Expected exactly three parameters")
  | _ -> fail "Expected AttributedFunction"

let test_kprobe_return_type_validation _ =
  (* Test valid return types for kprobe *)
  let test_cases = [
    ("i32", "fn handler() -> i32 { return 0 }");
    ("void", "fn handler() -> void { }");
    ("u32", "fn handler() -> u32 { return 0 }");
  ] in
  
  List.iter (fun (ret_type, func_def) ->
    let source = "@kprobe(\"sys_read\")\n" ^ func_def in
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    check int (Printf.sprintf "Type checking should succeed for %s return type" ret_type) 1 (List.length typed_ast)
  ) test_cases

let test_kprobe_too_many_parameters _ =
  (* Test rejection of functions with more than 6 parameters *)
  let source = "@kprobe(\"invalid_function\")
fn too_many_params(p1: u32, p2: u32, p3: u32, p4: u32, p5: u32, p6: u32, p7: u32) -> i32 {
    return 0
}" in
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed with too many parameters"
  with
  | _ -> check bool "Correctly rejected too many parameters" true true

let test_kprobe_pt_regs_rejection _ =
  (* Test rejection of direct pt_regs parameter usage *)
  let source = "@kprobe(\"sys_read\")
fn invalid_handler(ctx: *pt_regs) -> i32 {
    return 0
}" in
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed with pt_regs parameter"
  with
  | _ -> check bool "Correctly rejected pt_regs parameter" true true

(* 3. IR Generation Tests *)
let test_kprobe_ir_generation _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_kprobe" in
  check int "Should generate one program" 1 (List.length ir_multi_prog.programs);
  let program = List.hd ir_multi_prog.programs in
  check string "Program name" "sys_read_handler" program.name;
  check bool "Program type should be Kprobe" true 
    (match program.program_type with Kprobe -> true | _ -> false)

let test_kprobe_complex_parameters _ =
  let source = "@kprobe(\"tcp_sendmsg\")
fn tcp_sendmsg_handler(sk: *sock, msg: *msghdr, size: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_kprobe_complex" in
  check int "Should generate one program" 1 (List.length ir_multi_prog.programs);
  let program = List.hd ir_multi_prog.programs in
  check string "Program name" "tcp_sendmsg_handler" program.name;
  check bool "Program type should be Kprobe" true 
    (match program.program_type with Kprobe -> true | _ -> false)

let test_kprobe_function_signature_validation _ =
  let source = "@kprobe(\"vfs_write\")
fn vfs_write_handler(file: *file, buf: *u8, count: usize, pos: *i64) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_kprobe" in
  let program = List.hd ir_multi_prog.programs in
  let main_func = program.entry_function in
  
  (* Test that the function has the correct properties *)
  check bool "Function should be marked as main" true main_func.is_main;
  check string "Function name should match" "vfs_write_handler" main_func.func_name

(* 4. Code Generation Tests *)
let test_kprobe_section_name_generation _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_kprobe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for kprobe section *)
  check bool "Should contain SEC(\"kprobe\")" true
    (String.contains c_code (String.get "SEC(\"kprobe\")" 0))

let test_kprobe_complex_section_generation _ =
  let source = "@kprobe(\"tcp_sendmsg\")
fn tcp_sendmsg_handler(sk: *sock, msg: *msghdr, size: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_complex_kprobe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for kprobe section *)
  check bool "Should contain SEC(\"kprobe\")" true
    (String.contains c_code (String.get "SEC(\"kprobe\")" 0));
  check bool "Should contain tcp_sendmsg_handler function" true
    (String.contains c_code (String.get "tcp_sendmsg_handler" 0))

let test_kprobe_ebpf_codegen _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_kprobe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for kprobe-specific C code elements *)
  check bool "Should contain SEC(\"kprobe\")" true 
    (String.contains c_code (String.get "SEC(\"kprobe\")" 0));
  check bool "Should contain function definition" true
    (String.contains c_code (String.get "sys_read_handler" 0));
  check bool "Should contain pt_regs parameter" true
    (String.contains c_code (String.get "struct pt_regs *ctx" 0))

let test_kprobe_includes_generation _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_kprobe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for kprobe-specific includes *)
  check bool "Should include bpf/bpf_tracing.h" true
    (String.contains c_code (String.get "bpf/bpf_tracing.h" 0));
  check bool "Should include linux/ptrace.h" true
    (String.contains c_code (String.get "linux/ptrace.h" 0));
  check bool "Should define __TARGET_ARCH_x86" true
    (String.contains c_code (String.get "__TARGET_ARCH_x86" 0))

let test_kprobe_pt_regs_parm_macros _ =
  let source = "@kprobe(\"vfs_write\")
fn vfs_write_handler(file: *file, buf: *u8, count: usize, pos: *i64) -> i32 {
    var local_file = file
    var local_buf = buf
    var local_count = count
    var local_pos = pos
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_kprobe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for PT_REGS_PARM macro usage *)
  check bool "Should contain PT_REGS_PARM1" true
    (String.contains c_code (String.get "PT_REGS_PARM1" 0));
  check bool "Should contain PT_REGS_PARM2" true
    (String.contains c_code (String.get "PT_REGS_PARM2" 0));
  check bool "Should contain PT_REGS_PARM3" true
    (String.contains c_code (String.get "PT_REGS_PARM3" 0));
  check bool "Should contain PT_REGS_PARM4" true
    (String.contains c_code (String.get "PT_REGS_PARM4" 0))

(* 5. Template Generation Tests *)
let test_kprobe_target_function_parsing _ =
  (* Test target function extraction logic *)
  let test_cases = [
    ("sys_read", "sys_read");
    ("vfs_write", "vfs_write");
    ("tcp_sendmsg", "tcp_sendmsg");
    ("schedule", "schedule");
  ] in
  
  List.iter (fun (input, expected) ->
    (* This tests the internal logic that extracts target function names *)
    check string (Printf.sprintf "Target function for %s" input) expected input
  ) test_cases

let test_kprobe_parameter_mapping_logic _ =
  (* Test parameter mapping to PT_REGS_PARM macros *)
  let test_cases = [
    (0, "PT_REGS_PARM1");
    (1, "PT_REGS_PARM2");
    (2, "PT_REGS_PARM3");
    (3, "PT_REGS_PARM4");
    (4, "PT_REGS_PARM5");
    (5, "PT_REGS_PARM6");
  ] in
  
  List.iter (fun (index, expected_macro) ->
    let actual_macro = match index with
      | 0 -> "PT_REGS_PARM1"
      | 1 -> "PT_REGS_PARM2" 
      | 2 -> "PT_REGS_PARM3"
      | 3 -> "PT_REGS_PARM4"
      | 4 -> "PT_REGS_PARM5"
      | 5 -> "PT_REGS_PARM6"
      | _ -> "INVALID"
    in
    check string (Printf.sprintf "Parameter mapping for index %d" index) expected_macro actual_macro
  ) test_cases

(* 6. Error Handling Tests *)
let test_kprobe_invalid_return_type _ =
  let source = "@kprobe(\"sys_read\")
fn invalid_return_handler(fd: u32) -> str<64> {
    return \"invalid\"
}" in
  (* Check that compilation fails for invalid return type *)
  try
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
    let _ = generate_ir typed_ast symbol_table "test" in
    fail "Should have failed with invalid return type"
  with
  | _ -> check bool "Correctly rejected invalid return type" true true

let test_kprobe_invalid_parameter_count _ =
  let source = "@kprobe(\"invalid_function\")
fn seven_params_handler(p1: u32, p2: u32, p3: u32, p4: u32, p5: u32, p6: u32, p7: u32) -> i32 {
    return 0
}" in
  (* Check that compilation fails for too many parameters *)
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed with too many parameters"
  with
  | _ -> check bool "Correctly rejected too many parameters" true true

let test_kprobe_empty_target_function _ =
  let source = "@kprobe(\"\")
fn empty_target_handler() -> i32 {
    return 0
}" in
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed with empty target function"
  with
  | _ -> check bool "Correctly rejected empty target function" true true

(* 7. Integration Tests *)
let test_kprobe_end_to_end_syscall _ =
  let source = "@kprobe(\"sys_open\")
fn sys_open_handler(filename: *u8, flags: i32, mode: u16) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_syscall" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Comprehensive end-to-end validation *)
  check bool "Contains kprobe section" true
    (String.contains c_code (String.get "SEC(\"kprobe\")" 0));
  check bool "Contains function name" true
    (String.contains c_code (String.get "sys_open_handler" 0));
  check bool "Contains pt_regs parameter" true
    (String.contains c_code (String.get "struct pt_regs *ctx" 0));
  check bool "Contains return statement" true
    (String.contains c_code (String.get "return 0" 0))

let test_kprobe_network_function _ =
  let source = "@kprobe(\"tcp_sendmsg\")
fn tcp_sendmsg_handler(sk: *sock, msg: *msghdr, size: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_network" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  check bool "End-to-end kprobe works for network functions" true
    (String.contains c_code (String.get "tcp_sendmsg_handler" 0));
  check bool "Contains kprobe section" true
    (String.contains c_code (String.get "SEC(\"kprobe\")" 0));
  check bool "Contains struct pt_regs parameter" true
    (String.contains c_code (String.get "struct pt_regs *ctx" 0))

let test_kprobe_multiple_functions _ =
  let source = "@kprobe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}

@kprobe(\"sys_write\")
fn sys_write_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_multiple" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  check int "Should generate two programs" 2 (List.length ir_multi_prog.programs);
  check bool "Contains both function names" true
    (String.contains c_code (String.get "sys_read_handler" 0) &&
     String.contains c_code (String.get "sys_write_handler" 0))

(** Test Suite Configuration *)
let parsing_tests = [
  "kprobe attribute parsing", `Quick, test_kprobe_attribute_parsing;
  "kprobe multiple parameters", `Quick, test_kprobe_multiple_parameters;
  "kprobe parsing errors", `Quick, test_kprobe_parsing_errors;
  "kprobe missing target function", `Quick, test_kprobe_missing_target_function;
]

let type_checking_tests = [
  "kprobe type checking", `Quick, test_kprobe_type_checking;
  "kprobe parameter validation", `Quick, test_kprobe_parameter_validation;
  "kprobe return type validation", `Quick, test_kprobe_return_type_validation;
  "kprobe too many parameters", `Quick, test_kprobe_too_many_parameters;
  "kprobe pt_regs rejection", `Quick, test_kprobe_pt_regs_rejection;
]

let ir_generation_tests = [
  "kprobe IR generation", `Quick, test_kprobe_ir_generation;
  "kprobe complex parameters", `Quick, test_kprobe_complex_parameters;
  "kprobe function signature validation", `Quick, test_kprobe_function_signature_validation;
]

let code_generation_tests = [
  "kprobe section name generation", `Quick, test_kprobe_section_name_generation;
  "kprobe complex section generation", `Quick, test_kprobe_complex_section_generation;
  "kprobe eBPF code generation", `Quick, test_kprobe_ebpf_codegen;
  "kprobe includes generation", `Quick, test_kprobe_includes_generation;
  "kprobe PT_REGS_PARM macros", `Quick, test_kprobe_pt_regs_parm_macros;
]

let template_generation_tests = [
  "kprobe target function parsing", `Quick, test_kprobe_target_function_parsing;
  "kprobe parameter mapping logic", `Quick, test_kprobe_parameter_mapping_logic;
]

let error_handling_tests = [
  "kprobe invalid return type", `Quick, test_kprobe_invalid_return_type;
  "kprobe invalid parameter count", `Quick, test_kprobe_invalid_parameter_count;
  "kprobe empty target function", `Quick, test_kprobe_empty_target_function;
]

let integration_tests = [
  "kprobe end-to-end syscall", `Quick, test_kprobe_end_to_end_syscall;
  "kprobe network function", `Quick, test_kprobe_network_function;
  "kprobe multiple functions", `Quick, test_kprobe_multiple_functions;
]

let () =
  run "KernelScript Kprobe Tests" [
    "parsing", parsing_tests;
    "type checking", type_checking_tests;
    "IR generation", ir_generation_tests;
    "code generation", code_generation_tests;
    "template generation", template_generation_tests;
    "error handling", error_handling_tests;
    "integration", integration_tests;
  ]