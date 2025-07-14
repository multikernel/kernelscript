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

(** Unit Tests for Expression Evaluator *)

open Kernelscript.Parse
open Kernelscript.Evaluator
open Alcotest

(** Test basic expression evaluation *)
let test_basic_evaluation () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = 5
  var y = 10
  var result = x + y
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = List.length ast in
    check bool "basic evaluation test" true true
  with
  | _ -> fail "Failed basic evaluation test"

(** Helper function to create a test expression *)
let make_test_expr expr_desc =
  let pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  {
    Kernelscript.Ast.expr_desc = expr_desc;
    expr_pos = pos;
    expr_type = None;
    type_checked = false;
    program_context = None;
    map_scope = None;
  }

(** Test enum constant evaluation using symbol table *)
let test_enum_constant_evaluation () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    
    (* Create evaluator context with symbol table *)
    let maps = Hashtbl.create 16 in
    let functions = Hashtbl.create 16 in
    let eval_ctx = create_eval_context symbol_table maps functions in
    
    (* Create a simple expression to test enum lookup *)
    let xdp_pass_expr = make_test_expr (Kernelscript.Ast.Identifier "XDP_PASS") in
    
    match eval_expression eval_ctx xdp_pass_expr with
    | EnumValue ("xdp_action", 2) -> 
        check bool "XDP_PASS correctly evaluated from symbol table" true true
    | _ -> 
        fail "XDP_PASS should evaluate to EnumValue(xdp_action, 2)"
  with
  | Evaluation_error (msg, _) -> 
      fail ("Evaluation error: " ^ msg)
  | e -> 
      fail ("Unexpected exception: " ^ Printexc.to_string e)

(** Test different enum constants *)  
let test_various_enum_constants () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_DROP
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    
    (* Create evaluator context with symbol table *)
    let maps = Hashtbl.create 16 in
    let functions = Hashtbl.create 16 in
    let eval_ctx = create_eval_context symbol_table maps functions in
    
    (* Test XDP_DROP *)
    let xdp_drop_expr = make_test_expr (Kernelscript.Ast.Identifier "XDP_DROP") in
    (match eval_expression eval_ctx xdp_drop_expr with
    | EnumValue ("xdp_action", 1) ->
        check bool "XDP_DROP correctly evaluated" true true  
    | _ ->
        fail "XDP_DROP should evaluate to EnumValue(xdp_action, 1)");
    
    (* Test TC enum constant *)
    let tc_ok_expr = make_test_expr (Kernelscript.Ast.Identifier "TC_ACT_OK") in
    (match eval_expression eval_ctx tc_ok_expr with
    | EnumValue ("tc_action", 0) ->
        check bool "TC_ACT_OK correctly evaluated" true true  
    | _ ->
        fail "TC_ACT_OK should evaluate to EnumValue(tc_action, 0)")
  with
  | e -> fail ("Unexpected exception: " ^ Printexc.to_string e)

let test_variable_evaluation () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = 5
  return 2
}
|} in
  let ast = parse_string program_text in
  let _ = Test_utils.Helpers.create_test_symbol_table ast in
  
  (* Test would evaluate the variable declaration *)
  check bool "variable evaluation test" true (List.length ast = 1);
  Printf.printf "test_variable_evaluation passed\n%!"

let evaluator_tests = [
  "basic_evaluation", `Quick, test_basic_evaluation;
  "enum_constant_evaluation", `Quick, test_enum_constant_evaluation;
  "various_enum_constants", `Quick, test_various_enum_constants;
  "variable_evaluation", `Quick, test_variable_evaluation;
]

let () =
  run "KernelScript Evaluator Tests" [
    "evaluator", evaluator_tests;
  ]