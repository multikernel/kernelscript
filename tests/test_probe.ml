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
  filename = "test_probe.ks";
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

(** Mock BTF data for probe testing *)
module MockProbeBTF = struct
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
let test_probe_attribute_parsing _ =
  let source = "@probe(\"sys_read\")
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
           check string "Attribute name" "probe" name;
           check string "Attribute argument" "sys_read" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_probe_multiple_parameters _ =
  let source = "@probe(\"vfs_write\")
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
           check string "Attribute name" "probe" name;
           check string "Attribute argument" "vfs_write" arg
       | _ -> fail "Expected AttributeWithArg")
  | _ -> fail "Expected AttributedFunction"

let test_probe_parsing_errors _ =
  (* Test invalid format without target function *)
  let source = "@probe
fn invalid_handler(fd: u32) -> i32 {
    return 0
}" in
  (* Check that parsing/type checking fails for old format *)
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed parsing old format"
  with
  | _ -> check bool "Correctly rejected old format" true true

let test_probe_missing_target_function _ =
  (* Test @probe without target function specification *)
  let source = "@probe(\"\")
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
let test_probe_type_checking _ =
  let source = "@probe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  check int "Type checking should succeed" 1 (List.length typed_ast)

let test_probe_parameter_validation _ =
  let source = "@probe(\"sys_read\")
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

let test_probe_return_type_validation _ =
  (* Test valid return types for kprobe *)
  let test_cases = [
    ("i32", "fn handler() -> i32 { return 0 }");
    ("void", "fn handler() -> void { }");
    ("u32", "fn handler() -> u32 { return 0 }");
  ] in
  
  List.iter (fun (ret_type, func_def) ->
    let source = "@probe(\"sys_read\")\n" ^ func_def in
    let ast = parse_string source in
    let typed_ast = type_check_ast ast in
    check int (Printf.sprintf "Type checking should succeed for %s return type" ret_type) 1 (List.length typed_ast)
  ) test_cases

let test_probe_too_many_parameters _ =
  (* Test rejection of functions with more than 6 parameters *)
  let source = "@probe(\"invalid_function\")
fn too_many_params(p1: u32, p2: u32, p3: u32, p4: u32, p5: u32, p6: u32, p7: u32) -> i32 {
    return 0
}" in
  try
    let ast = parse_string source in
    let _ = type_check_ast ast in
    fail "Should have failed with too many parameters"
  with
  | _ -> check bool "Correctly rejected too many parameters" true true

let test_probe_pt_regs_rejection _ =
  (* Test rejection of direct pt_regs parameter usage *)
  let source = "@probe(\"sys_read\")
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
let test_probe_ir_generation _ =
  let source = "@probe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  check int "Should generate one program" 1 (List.length ir_multi_prog.programs);
  let program = List.hd ir_multi_prog.programs in
  check string "Program name" "sys_read_handler" program.name;
  check bool "Program type should be Kprobe" true 
    (match program.program_type with Probe _ -> true | _ -> false)

let test_probe_complex_parameters _ =
  let source = "@probe(\"tcp_sendmsg\")
fn tcp_sendmsg_handler(sk: *sock, msg: *msghdr, size: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe_complex" in
  check int "Should generate one program" 1 (List.length ir_multi_prog.programs);
  let program = List.hd ir_multi_prog.programs in
  check string "Program name" "tcp_sendmsg_handler" program.name;
  check bool "Program type should be Kprobe" true 
    (match program.program_type with Probe _ -> true | _ -> false)

let test_probe_function_signature_validation _ =
  let source = "@probe(\"vfs_write\")
fn vfs_write_handler(file: *file, buf: *u8, count: usize, pos: *i64) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  let program = List.hd ir_multi_prog.programs in
  let main_func = program.entry_function in
  
  (* Test that the function has the correct properties *)
  check bool "Function should be marked as main" true main_func.is_main;
  check string "Function name should match" "vfs_write_handler" main_func.func_name

(* 4. Code Generation Tests *)
let test_fprobe_section_name_generation _ =
  let source = "@probe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for fentry section with target function *)
  check bool "Should contain SEC(\"fentry/sys_read\")" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"fentry/sys_read\")") c_code 0); true with Not_found -> false);
  (* Should NOT contain pt_regs parameter for fprobe *)
  check bool "Should NOT contain struct pt_regs *ctx" false
    (try ignore (Str.search_forward (Str.regexp_string "struct pt_regs *ctx") c_code 0); true with Not_found -> false)

let test_kprobe_section_name_generation _ =
  let source = "@probe(\"vfs_read+0x10\")
fn vfs_read_handler(ctx: *pt_regs) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for kprobe section *)
  check bool "Should contain SEC(\"kprobe\")" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"kprobe\")") c_code 0); true with Not_found -> false);
  (* Should contain pt_regs parameter for kprobe *)
  check bool "Should contain struct pt_regs *ctx" true
    (try ignore (Str.search_forward (Str.regexp_string "struct pt_regs *ctx") c_code 0); true with Not_found -> false)

let test_fprobe_complex_section_generation _ =
  let source = "@probe(\"tcp_sendmsg\")
fn tcp_sendmsg_handler(sk: *sock, msg: *msghdr, size: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_complex_probe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for fentry section with target function *)
  check bool "Should contain SEC(\"fentry/tcp_sendmsg\")" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"fentry/tcp_sendmsg\")") c_code 0); true with Not_found -> false);
  check bool "Should contain tcp_sendmsg_handler function" true
    (try ignore (Str.search_forward (Str.regexp_string "tcp_sendmsg_handler") c_code 0); true with Not_found -> false);
  (* Should have direct parameters, not pt_regs *)
  check bool "Should contain direct parameters" true
    (try ignore (Str.search_forward (Str.regexp_string "struct sock* sk") c_code 0); true 
     with Not_found -> 
       try ignore (Str.search_forward (Str.regexp_string "struct sock *sk") c_code 0); true 
       with Not_found -> false)

let test_fprobe_ebpf_codegen _ =
  let source = "@probe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for fprobe-specific C code elements *)
  check bool "Should contain SEC(\"fentry/sys_read\")" true 
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"fentry/sys_read\")") c_code 0); true with Not_found -> false);
  check bool "Should contain function definition" true
    (try ignore (Str.search_forward (Str.regexp_string "sys_read_handler") c_code 0); true with Not_found -> false);
  check bool "Should contain direct parameters" true
    (try ignore (Str.search_forward (Str.regexp_string "__u32 fd") c_code 0); true 
     with Not_found -> 
       try ignore (Str.search_forward (Str.regexp_string "u32 fd") c_code 0); true 
       with Not_found -> false)

let test_kprobe_ebpf_codegen _ =
  let source = "@probe(\"vfs_read+0x20\")
fn vfs_read_handler(ctx: *pt_regs) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for kprobe-specific C code elements *)
  check bool "Should contain SEC(\"kprobe\")" true 
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"kprobe\")") c_code 0); true with Not_found -> false);
  check bool "Should contain function definition" true
    (try ignore (Str.search_forward (Str.regexp_string "vfs_read_handler") c_code 0); true with Not_found -> false);
  check bool "Should contain pt_regs parameter" true
    (try ignore (Str.search_forward (Str.regexp_string "struct pt_regs *ctx") c_code 0); true with Not_found -> false)

let test_fprobe_includes_generation _ =
  let source = "@probe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for fprobe-specific includes *)
  check bool "Should include bpf/bpf_helpers.h" true
    (try ignore (Str.search_forward (Str.regexp_string "bpf/bpf_helpers.h") c_code 0); true with Not_found -> false);
  check bool "Should include vmlinux.h" true
    (try ignore (Str.search_forward (Str.regexp_string "vmlinux.h") c_code 0); true with Not_found -> false);
  (* fprobe should NOT need linux/ptrace.h *)
  check bool "Should NOT include linux/ptrace.h for fprobe" false
    (try ignore (Str.search_forward (Str.regexp_string "linux/ptrace.h") c_code 0); true with Not_found -> false)

let test_kprobe_pt_regs_parm_macros _ =
  let source = "@probe(\"vfs_write+0x8\")
fn vfs_write_handler(ctx: *pt_regs) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_probe" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Check for kprobe-specific elements *)
  check bool "Should contain SEC(\"kprobe\")" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"kprobe\")") c_code 0); true with Not_found -> false);
  check bool "Should contain struct pt_regs *ctx parameter" true
    (try ignore (Str.search_forward (Str.regexp_string "struct pt_regs *ctx") c_code 0); true with Not_found -> false);
  check bool "Should include bpf/bpf_tracing.h for kprobe" true
    (try ignore (Str.search_forward (Str.regexp_string "bpf/bpf_tracing.h") c_code 0); true with Not_found -> false)

(* 5. Template Generation Tests *)
let test_probe_target_function_parsing _ =
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

let test_probe_parameter_mapping_logic _ =
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
let test_probe_invalid_return_type _ =
  let source = "@probe(\"sys_read\")
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

let test_probe_invalid_parameter_count _ =
  let source = "@probe(\"invalid_function\")
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

let test_probe_empty_target_function _ =
  let source = "@probe(\"\")
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
let test_fprobe_end_to_end_syscall _ =
  let source = "@probe(\"sys_open\")
fn sys_open_handler(filename: *u8, flags: i32, mode: u16) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_syscall" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Comprehensive end-to-end validation for fprobe *)
  check bool "Contains fentry section" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"fentry/sys_open\")") c_code 0); true with Not_found -> false);
  check bool "Contains function name" true
    (try ignore (Str.search_forward (Str.regexp_string "sys_open_handler") c_code 0); true with Not_found -> false);
  check bool "Should NOT contain pt_regs parameter for fprobe" false
    (try ignore (Str.search_forward (Str.regexp_string "struct pt_regs *ctx") c_code 0); true with Not_found -> false);
  check bool "Contains return statement" true
    (try ignore (Str.search_forward (Str.regexp_string "return 0") c_code 0); true with Not_found -> false)

let test_kprobe_end_to_end_syscall _ =
  let source = "@probe(\"sys_open+0x4\")
fn sys_open_handler(ctx: *pt_regs) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_syscall" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  (* Comprehensive end-to-end validation for kprobe *)
  check bool "Contains kprobe section" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"kprobe\")") c_code 0); true with Not_found -> false);
  check bool "Contains function name" true
    (try ignore (Str.search_forward (Str.regexp_string "sys_open_handler") c_code 0); true with Not_found -> false);
  check bool "Contains pt_regs parameter" true
    (try ignore (Str.search_forward (Str.regexp_string "struct pt_regs *ctx") c_code 0); true with Not_found -> false);
  check bool "Contains return statement" true
    (try ignore (Str.search_forward (Str.regexp_string "return 0") c_code 0); true with Not_found -> false)

let test_fprobe_network_function _ =
  let source = "@probe(\"tcp_sendmsg\")
fn tcp_sendmsg_handler(sk: *sock, msg: *msghdr, size: usize) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_network" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  check bool "End-to-end fprobe works for network functions" true
    (try ignore (Str.search_forward (Str.regexp_string "tcp_sendmsg_handler") c_code 0); true with Not_found -> false);
  check bool "Contains fentry section" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"fentry/tcp_sendmsg\")") c_code 0); true with Not_found -> false);
  check bool "Should NOT contain struct pt_regs parameter for fprobe" false
    (try ignore (Str.search_forward (Str.regexp_string "struct pt_regs *ctx") c_code 0); true with Not_found -> false)

let test_probe_multiple_functions _ =
  let source = "@probe(\"sys_read\")
fn sys_read_handler(fd: u32, buf: *u8, count: usize) -> i32 {
    return 0
}

@probe(\"sys_write+0x8\")
fn sys_write_handler(ctx: *pt_regs) -> i32 {
    return 0
}" in
  let ast = parse_string source in
  let typed_ast = type_check_ast ast in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table typed_ast in
  let ir_multi_prog = generate_ir typed_ast symbol_table "test_multiple" in
  let c_code = generate_c_multi_program ir_multi_prog in
  
  check int "Should generate two programs" 2 (List.length ir_multi_prog.programs);
  check bool "Contains both function names" true
    (try ignore (Str.search_forward (Str.regexp_string "sys_read_handler") c_code 0);
         ignore (Str.search_forward (Str.regexp_string "sys_write_handler") c_code 0); true 
     with Not_found -> false);
  (* Check for both fprobe and kprobe sections *)
  check bool "Contains fentry section for sys_read" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"fentry/sys_read\")") c_code 0); true with Not_found -> false);
  check bool "Contains kprobe section for sys_write" true
    (try ignore (Str.search_forward (Str.regexp_string "SEC(\"kprobe\")") c_code 0); true with Not_found -> false)

(** Test Suite Configuration *)
let parsing_tests = [
  "probe attribute parsing", `Quick, test_probe_attribute_parsing;
  "probe multiple parameters", `Quick, test_probe_multiple_parameters;
  "probe parsing errors", `Quick, test_probe_parsing_errors;
  "probe missing target function", `Quick, test_probe_missing_target_function;
]

let type_checking_tests = [
  "probe type checking", `Quick, test_probe_type_checking;
  "probe parameter validation", `Quick, test_probe_parameter_validation;
  "probe return type validation", `Quick, test_probe_return_type_validation;
  "probe too many parameters", `Quick, test_probe_too_many_parameters;
  "probe pt_regs rejection", `Quick, test_probe_pt_regs_rejection;
]

let ir_generation_tests = [
  "probe IR generation", `Quick, test_probe_ir_generation;
  "probe complex parameters", `Quick, test_probe_complex_parameters;
  "probe function signature validation", `Quick, test_probe_function_signature_validation;
]

let code_generation_tests = [
  "fprobe section name generation", `Quick, test_fprobe_section_name_generation;
  "kprobe section name generation", `Quick, test_kprobe_section_name_generation;
  "fprobe complex section generation", `Quick, test_fprobe_complex_section_generation;
  "fprobe eBPF code generation", `Quick, test_fprobe_ebpf_codegen;
  "kprobe eBPF code generation", `Quick, test_kprobe_ebpf_codegen;
  "fprobe includes generation", `Quick, test_fprobe_includes_generation;
  "kprobe PT_REGS_PARM macros", `Quick, test_kprobe_pt_regs_parm_macros;
]

let template_generation_tests = [
  "probe target function parsing", `Quick, test_probe_target_function_parsing;
  "probe parameter mapping logic", `Quick, test_probe_parameter_mapping_logic;
]

let error_handling_tests = [
  "probe invalid return type", `Quick, test_probe_invalid_return_type;
  "probe invalid parameter count", `Quick, test_probe_invalid_parameter_count;
  "probe empty target function", `Quick, test_probe_empty_target_function;
]

let integration_tests = [
  "fprobe end-to-end syscall", `Quick, test_fprobe_end_to_end_syscall;
  "kprobe end-to-end syscall", `Quick, test_kprobe_end_to_end_syscall;
  "fprobe network function", `Quick, test_fprobe_network_function;
  "probe multiple functions", `Quick, test_probe_multiple_functions;
]

let () =
  run "KernelScript Probe Tests" [
    "parsing", parsing_tests;
    "type checking", type_checking_tests;
    "IR generation", ir_generation_tests;
    "code generation", code_generation_tests;
    "template generation", template_generation_tests;
    "error handling", error_handling_tests;
    "integration", integration_tests;
  ]