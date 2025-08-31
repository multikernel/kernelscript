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

(** Test that verifies the fix for break/continue in unbound loops
    This test ensures that callback functions have consistent variable naming
    between declarations and usage. Previously, variables were declared as
    tmp_X but referenced as val_X, causing compilation errors.
*)
let test_break_continue_unbound_variable_naming () =
  let ctx = create_c_context () in
  
  (* Create registers for variables that would be used in break/continue logic *)
  let counter_reg = 1 in
  let condition_reg = 2 in
  let temp_reg = 3 in
  
  (* Create IR values representing loop variables *)
  let counter_val = make_ir_value (IRTempVariable (Printf.sprintf "counter_%d" counter_reg)) IRU32 test_pos in
  let condition_val = make_ir_value (IRTempVariable (Printf.sprintf "condition_%d" condition_reg)) IRBool test_pos in
  let temp_val = make_ir_value (IRTempVariable (Printf.sprintf "temp_%d" temp_reg)) IRU32 test_pos in
  
  (* Create a modulo operation and comparison (similar to the original failing case) *)
  let two_val = make_ir_value (IRLiteral (IntLit (Signed64 2L, None))) IRU32 test_pos in
  let zero_val = make_ir_value (IRLiteral (IntLit (Signed64 0L, None))) IRU32 test_pos in
  
  (* Create IR instructions that would be in a bpf_loop callback *)
  let mod_expr = make_ir_expr (IRBinOp (counter_val, IRMod, two_val)) IRU32 test_pos in
  let mod_assign = make_ir_instruction (IRAssign (temp_val, mod_expr)) test_pos in
  
  let eq_expr = make_ir_expr (IRBinOp (temp_val, IREq, zero_val)) IRBool test_pos in
  let eq_assign = make_ir_instruction (IRAssign (condition_val, eq_expr)) test_pos in
  
  (* Create the bpf_loop instruction with these body instructions *)
  let start_val = make_ir_value (IRLiteral (IntLit (Signed64 0L, None))) IRU32 test_pos in
  let end_val = make_ir_value (IRLiteral (IntLit (Signed64 1000L, None))) IRU32 test_pos in
  let ctx_val = make_ir_value (IRTempVariable "loop_ctx") (IRPointer (IRU8, make_bounds_info ())) test_pos in
  let body_instructions = [mod_assign; eq_assign] in
  
  let bpf_loop_instr = make_ir_instruction 
    (IRBpfLoop (start_val, end_val, counter_val, ctx_val, body_instructions))
    test_pos in
  
  (* Generate C code for the bpf_loop instruction *)
  generate_c_instruction ctx bpf_loop_instr;
  
  (* Get the generated code *)
  let _output = String.concat "\n" ctx.output_lines in
  
  (* Extract any pending callbacks (this is where the fix matters) *)
  let callback_code = String.concat "\n" ctx.pending_callbacks in
  
  (* Verify that the callback code doesn't contain inconsistent variable naming *)
  let has_consistent_naming = 
    (* Check that if variables are declared as tmp_X, they're also used as tmp_X *)
    let tmp_declarations = Str.split (Str.regexp "tmp_[0-9]+") callback_code in
    let val_usage = Str.split (Str.regexp "val_[0-9]+") callback_code in
    (* If there are tmp declarations, there shouldn't be val usage in the same callback *)
    if List.length tmp_declarations > 1 then
      List.length val_usage <= 1 (* Only the split creates one extra element *)
    else
      true
  in
  
  check bool "Variable naming is consistent in callback" true has_consistent_naming;
  
  (* Also verify that the generated code contains a callback function *)
  let has_callback = String.length callback_code > 0 in
  check bool "Callback function was generated" true has_callback;
  
  (* Additional check: verify no undeclared variable usage *)
  let lines = String.split_on_char '\n' callback_code in
  let has_undeclared_usage = List.exists (fun line ->
    (* Look for patterns like "val_X = " where val_X wasn't declared *)
    Str.string_match (Str.regexp ".*val_[0-9]+ =.*") line 0 &&
    not (Str.string_match (Str.regexp ".*__u32 val_[0-9]+.*") line 0)
  ) lines in
  
  check bool "No undeclared variable usage" false has_undeclared_usage


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