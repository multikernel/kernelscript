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
open Kernelscript.Parse
open Kernelscript.Type_checker
open Kernelscript.Ir
open Kernelscript.Ebpf_c_codegen
open Kernelscript.Ast

(** Common test position for IR/codegen tests *)
let test_pos = make_position 1 1 "test.ks"

(** Helper function to parse and evaluate a program with break/continue *)
let parse_and_check_break_continue program_text =
  try
    let ast = parse_string program_text in
    let typed_ast = type_check_ast ast in
    Ok typed_ast
  with
  | Parse_error (msg, _pos) -> Error ("Parse error: " ^ msg)
  | Type_error (msg, _pos) -> Error ("Type error: " ^ msg)
  | e -> Error ("Other error: " ^ Printexc.to_string e)

(** Test basic break statement parsing *)
let test_break_statement_parsing () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 0..10) {
    if (i == 5) {
      break
    }
    var x = i
  }
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "break statement parsed and type checked" true true
  | Error msg -> fail ("Failed to parse break statement: " ^ msg)

(** Test basic continue statement parsing *)
let test_continue_statement_parsing () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 0..10) {
    if (i == 5) {
      continue
    }
    var x = i
  }
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "continue statement parsed and type checked" true true
  | Error msg -> fail ("Failed to parse continue statement: " ^ msg)

(** Test break in while loop *)
let test_break_in_while_loop () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var i = 0
  while (i < 10) {
    i = i + 1
    if (i == 5) {
      break
    }
    var x = 5
  }
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "break in while loop parsed and type checked" true true
  | Error msg -> fail ("Failed to parse break in while loop: " ^ msg)

(** Test continue in while loop *)
let test_continue_in_while_loop () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var i = 0
  while (i < 10) {
    i = i + 1
    if (i % 2 == 0) {
      continue
    }
    var x = 5
  }
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "continue in while loop parsed and type checked" true true
  | Error msg -> fail ("Failed to parse continue in while loop: " ^ msg)

(** Test error case: break outside loop *)
let test_break_outside_loop_error () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = 5
  break
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> fail "Should have failed with break outside loop error"
  | Error msg -> 
      check bool "break outside loop produces error" 
        (try ignore (Str.search_forward (Str.regexp "Break statement can only be used inside loops") msg 0); true with Not_found -> false) true

(** Test error case: continue outside loop *)
let test_continue_outside_loop_error () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = 5
  continue
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> fail "Should have failed with continue outside loop error"
  | Error msg -> 
      check bool "continue outside loop produces error" 
        (try ignore (Str.search_forward (Str.regexp "Continue statement can only be used inside loops") msg 0); true with Not_found -> false) true

(** Test break and continue in nested conditional inside loop *)
let test_break_continue_in_nested_conditional () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 0..20) {
    if (i < 5) {
      continue
    } else {
      if (i > 15) {
        break
      }
    }
    var processed = i * 3
  }
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "break/continue in nested conditional parsed and type checked" true true
  | Error msg -> fail ("Failed to parse break/continue in nested conditional: " ^ msg)

(** Test multiple break/continue statements in same loop *)
let test_multiple_break_continue_statements () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 0..100) {
    if (i < 10) {
      continue
    }
    if (i == 50) {
      break
    }
    if (i > 80) {
      continue
    }
    var x = i * 2
  }
  return 2
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "multiple break/continue statements parsed and type checked" true true
  | Error msg -> fail ("Failed to parse multiple break/continue statements: " ^ msg)

(** Test evaluation of break statement (simple simulation) *)
let test_break_evaluation () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 1..3) {
    if (i == 2) {
      break
    }
  }
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    (* For this test, we just verify it parses and type checks correctly *)
    (* Full evaluation testing would require more complex setup *)
    check bool "break statement evaluation setup works" true true
  with
  | e -> fail ("Failed break evaluation test: " ^ Printexc.to_string e)

(** Test that verifies the elegant callback generation architecture
    This test ensures that callback functions are properly generated with consistent
    variable naming using the new IR-based approach.
*)
let test_break_continue_unbound_variable_naming () =
  (* Create a minimal IR multi-program with a bpf_loop to test callback generation *)
  let counter_val = make_ir_value (IRVariable "i") IRU32 test_pos in
  let start_val = make_ir_value (IRLiteral (IntLit (Signed64 0L, None))) IRU32 test_pos in
  let end_val = make_ir_value (IRLiteral (IntLit (Signed64 1000L, None))) IRU32 test_pos in
  let ctx_val = make_ir_value (IRTempVariable "loop_ctx") (IRPointer (IRU8, make_bounds_info ())) test_pos in
  
  (* Create body instructions with temp variables *)
  let temp_val = make_ir_value (IRTempVariable "__binop_0") IRU32 test_pos in
  let two_val = make_ir_value (IRLiteral (IntLit (Signed64 2L, None))) IRU32 test_pos in
  let mod_expr = make_ir_expr (IRBinOp (counter_val, IRMod, two_val)) IRU32 test_pos in
  let mod_assign = make_ir_instruction (IRAssign (temp_val, mod_expr)) test_pos in
  
  let body_instructions = [mod_assign] in
  
  let bpf_loop_instr = make_ir_instruction 
    (IRBpfLoop (start_val, end_val, counter_val, ctx_val, body_instructions))
    test_pos in
  
  (* Create a minimal IR function and multi-program *)
  let entry_block = make_ir_basic_block "entry" [bpf_loop_instr] 0 in
  let ir_func = make_ir_function "test_func" [] (Some IRU32) [entry_block] test_pos in
  
  let ir_prog = make_ir_program "test_prog" Xdp ir_func test_pos in
  
  (* Create source declarations to trigger the main compilation path *)
  let func_source_decl = {
    decl_desc = IRDeclFunctionDef ir_func;
    decl_order = 0;
    decl_pos = test_pos;
  } in
  let ir_multi_prog = make_ir_multi_program "test_source" [ir_prog] [] [] ~source_declarations:[func_source_decl] test_pos in
  
  (* Use the elegant compilation pipeline to generate C code *)
  let (generated_c_code, _tail_call_analysis) = compile_multi_to_c_with_tail_calls ir_multi_prog in
  
  (* Verify that callback functions are generated with proper variable naming *)
  let has_callback_function = String.contains generated_c_code 's' && 
    (try ignore (Str.search_forward (Str.regexp "static long loop_callback_[0-9]+") generated_c_code 0); true 
     with Not_found -> false) in
  check bool "Callback function was generated" true has_callback_function;
  
  (* Verify that the callback function contains the expected variable operations *)
  let has_modulo_operation = 
    try ignore (Str.search_forward (Str.regexp "i % 2") generated_c_code 0); true 
    with Not_found -> false in
  check bool "Callback contains modulo operation" true has_modulo_operation;
  
  (* Verify that temp variables are properly declared in callback *)
  let has_temp_var_declaration = 
    try ignore (Str.search_forward (Str.regexp "__binop_0") generated_c_code 0); true 
    with Not_found -> false in
  check bool "Temp variables are properly declared" true has_temp_var_declaration;
  
  (* Verify that the callback function has the correct signature *)
  let has_correct_callback_signature = 
    try ignore (Str.search_forward (Str.regexp "static long loop_callback_0(__u32 index, void \\*ctx_ptr)") generated_c_code 0); true 
    with Not_found -> false in
  check bool "Callback has correct signature" true has_correct_callback_signature


let break_continue_tests = [
  "break_statement_parsing", `Quick, test_break_statement_parsing;
  "continue_statement_parsing", `Quick, test_continue_statement_parsing;
  "break_in_while_loop", `Quick, test_break_in_while_loop;
  "continue_in_while_loop", `Quick, test_continue_in_while_loop;
  "break_outside_loop_error", `Quick, test_break_outside_loop_error;
  "continue_outside_loop_error", `Quick, test_continue_outside_loop_error;
  "break_continue_in_nested_conditional", `Quick, test_break_continue_in_nested_conditional;
  "multiple_break_continue_statements", `Quick, test_multiple_break_continue_statements;
  "break_evaluation", `Quick, test_break_evaluation;
  "break_continue_unbound_variable_naming", `Quick, test_break_continue_unbound_variable_naming;
]

let () =
  run "KernelScript Break/Continue Tests" [
    "break_continue", break_continue_tests;
  ] 