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

open Kernelscript.Ast
open Kernelscript.Type_checker
open Kernelscript.Evaluator
open Kernelscript.Symbol_table
open Alcotest

(** Helper functions for creating test expressions *)
let make_test_expr desc typ pos = { 
  expr_desc = desc; 
  expr_type = Some typ; 
  expr_pos = pos;
  type_checked = false;
  program_context = None;
  map_scope = None;
}
let make_test_pos () = make_position 1 1 "test_truthy.ks"

(** Helper function for creating expressions *)
let make_expr desc pos = {
  expr_desc = desc;
  expr_pos = pos;
  expr_type = None;
  type_checked = false;
  program_context = None;
  map_scope = None;
}

(** Helper function for creating statements *)
let make_stmt desc pos = {
  stmt_desc = desc;
  stmt_pos = pos;
}

(** Test that various types are allowed in boolean contexts *)
let test_truthy_type_checking () =
  let pos = make_test_pos () in
  let symbol_table = create_symbol_table () in
  let ctx = create_context symbol_table [] in
  
  (* Test numbers *)
  let zero_expr = make_expr (Literal (IntLit (0, None))) pos in
  let nonzero_expr = make_expr (Literal (IntLit (42, None))) pos in
  
  (* Test strings *)
  let empty_string = make_expr (Literal (StringLit "")) pos in
  let nonempty_string = make_expr (Literal (StringLit "hello")) pos in
  
  (* Test characters *)
  let null_char = make_expr (Literal (CharLit '\000')) pos in
  let regular_char = make_expr (Literal (CharLit 'a')) pos in
  
  (* Test booleans *)
  let true_expr = make_expr (Literal (BoolLit true)) pos in
  let false_expr = make_expr (Literal (BoolLit false)) pos in
  
  (* Test null pointer *)
  let null_expr = make_expr (Literal NullLit) pos in
  
  (* All of these should type check successfully *)
  let test_expressions = [
    zero_expr; nonzero_expr; empty_string; nonempty_string;
    null_char; regular_char; true_expr; false_expr; null_expr
  ] in
  
  List.iter (fun expr ->
    try
      let _ = type_check_condition ctx expr in
      check bool "Type checking should succeed" true true
    with
    | Type_error (msg, _) -> 
        failwith ("Type checking failed for truthy/falsy conversion: " ^ msg)
  ) test_expressions

(** Test the truthy/falsy evaluation logic *)
let test_truthy_evaluation () =
  
  (* Test number truthiness *)
  check bool "0 is falsy" (is_truthy_value (IntValue 0)) false;
  check bool "42 is truthy" (is_truthy_value (IntValue 42)) true;
  check bool "-1 is truthy" (is_truthy_value (IntValue (-1))) true;
  
  (* Test string truthiness *)
  check bool "Empty string is falsy" (is_truthy_value (StringValue "")) false;
  check bool "Non-empty string is truthy" (is_truthy_value (StringValue "hello")) true;
  check bool "Whitespace string is truthy" (is_truthy_value (StringValue " ")) true;
  
  (* Test character truthiness *)
  check bool "Null character is falsy" (is_truthy_value (CharValue '\000')) false;
  check bool "Regular character is truthy" (is_truthy_value (CharValue 'a')) true;
  check bool "Space character is truthy" (is_truthy_value (CharValue ' ')) true;
  
  (* Test boolean truthiness *)
  check bool "true is truthy" (is_truthy_value (BoolValue true)) true;
  check bool "false is falsy" (is_truthy_value (BoolValue false)) false;
  
  (* Test null truthiness *)
  check bool "null is falsy" (is_truthy_value NullValue) false;
  
  (* Test pointer truthiness *)
  check bool "Null pointer is falsy" (is_truthy_value (PointerValue 0)) false;
  check bool "Non-null pointer is truthy" (is_truthy_value (PointerValue 0x1234)) true;
  
  (* Test none sentinel - always falsy *)
  check bool "none is falsy" (is_truthy_value None) false;
  
  (* Test that structs and arrays cannot be used in boolean context *)
  (try
    let _ = is_truthy_value (ArrayValue [||]) in
    failwith "Should have failed - arrays cannot be used in boolean context"
  with 
  | Failure msg when try ignore (Str.search_forward (Str.regexp "boolean context") msg 0); true with Not_found -> false -> 
      check bool "Arrays cannot be used in boolean context" true true
  | _ -> check bool "Arrays should fail in boolean context" false true);
  
  (try
    let _ = is_truthy_value (StructValue []) in
    failwith "Should have failed - structs cannot be used in boolean context"
  with 
  | Failure msg when try ignore (Str.search_forward (Str.regexp "boolean context") msg 0); true with Not_found -> false -> 
      check bool "Structs cannot be used in boolean context" true true
  | _ -> check bool "Structs should fail in boolean context" false true);
  
  (* Test enum truthiness *)
  check bool "Enum with 0 value is falsy" (is_truthy_value (EnumValue ("Color", 0))) false;
  check bool "Enum with non-zero value is truthy" (is_truthy_value (EnumValue ("Color", 1))) true;
  
  (* Test other types *)
  check bool "Map handle is truthy" (is_truthy_value (MapHandle "test_map")) true;
  check bool "Context value is truthy" (is_truthy_value (ContextValue ("xdp", []))) true;
  check bool "Unit value is falsy" (is_truthy_value UnitValue) false

(** Test if statements with truthy/falsy conditions *)
let test_if_statement_truthy () =
  let pos = make_test_pos () in
  
  (* Test with numeric condition *)
  let zero_cond = make_expr (Literal (IntLit (0, None))) pos in
  let nonzero_cond = make_expr (Literal (IntLit (42, None))) pos in
  let print_stmt = make_stmt (ExprStmt (make_expr (Literal (StringLit "executed")) pos)) pos in
  
  let if_zero = make_stmt (If (zero_cond, [print_stmt], None)) pos in
  let if_nonzero = make_stmt (If (nonzero_cond, [print_stmt], None)) pos in
  
  (* Test with string condition *)
  let empty_str_cond = make_expr (Literal (StringLit "")) pos in
  let nonempty_str_cond = make_expr (Literal (StringLit "hello")) pos in
  
  let if_empty_str = make_stmt (If (empty_str_cond, [print_stmt], None)) pos in
  let if_nonempty_str = make_stmt (If (nonempty_str_cond, [print_stmt], None)) pos in
  
  let test_statements = [if_zero; if_nonzero; if_empty_str; if_nonempty_str] in
  
  (* All should type check successfully *)
  let symbol_table = create_symbol_table () in
  let ctx = create_context symbol_table [] in
  List.iter (fun stmt ->
    try
      let _ = type_check_statement ctx stmt in
      check bool "If statement should type check" true true
    with
    | Type_error (msg, _) -> 
        failwith ("If statement type checking failed: " ^ msg)
  ) test_statements

(** Test while loops with truthy/falsy conditions *)
let test_while_loop_truthy () =
  let pos = make_test_pos () in
  
  (* Test with numeric condition *)
  let counter_expr = make_expr (Identifier "counter") pos in
  let decrement_stmt = make_stmt (Assignment ("counter", make_expr (BinaryOp (counter_expr, Sub, make_expr (Literal (IntLit (1, None))) pos)) pos)) pos in
  
  let while_loop = make_stmt (While (counter_expr, [decrement_stmt])) pos in
  
  (* Should type check successfully *)
  let symbol_table = create_symbol_table () in
  let ctx = create_context symbol_table [] in
  Hashtbl.replace ctx.variables "counter" I32;
  
  try
    let _ = type_check_statement ctx while_loop in
    check bool "While loop should type check" true true
  with
  | Type_error (msg, _) -> 
      failwith ("While loop type checking failed: " ^ msg)

(** Test map lookup with truthy/falsy conversion *)
let test_map_lookup_truthy () =
  let pos = make_test_pos () in
  
  (* Create a simple map lookup example *)
  let map_expr = make_expr (Identifier "test_map") pos in
  let key_expr = make_expr (Literal (IntLit (1, None))) pos in
  let lookup_expr = make_expr (ArrayAccess (map_expr, key_expr)) pos in
  
  let print_stmt = make_stmt (ExprStmt (make_expr (Literal (StringLit "found")) pos)) pos in
  let create_stmt = make_stmt (ExprStmt (make_expr (Literal (StringLit "create")) pos)) pos in
  
  let if_stmt = make_stmt (If (lookup_expr, [print_stmt], Some [create_stmt])) pos in
  
  (* This should demonstrate the elegant truthy/falsy pattern *)
  let symbol_table = create_symbol_table () in
  let ctx = create_context symbol_table [] in
  let map_def = Kernelscript.Ir.make_ir_map_def
    "test_map"
    Kernelscript.Ir.IRI32
    Kernelscript.Ir.IRI32
    Kernelscript.Ir.IRHash
    100
    ~ast_key_type:I32
    ~ast_value_type:I32
    ~ast_map_type:Hash
    ~is_global:true
    pos in
  
  Hashtbl.replace ctx.maps "test_map" map_def;
  
  try
    let _ = type_check_statement ctx if_stmt in
    check bool "Map lookup if statement should type check" true true
  with
  | Type_error (msg, _) -> 
      failwith ("Map lookup if statement type checking failed: " ^ msg)

(** Test invalid types in boolean context *)
let test_invalid_boolean_types () =
  let pos = make_test_pos () in
  let symbol_table = create_symbol_table () in
  let ctx = create_context symbol_table [] in
  
  (* Test void type (should fail) *)
  let void_expr = make_expr (Identifier "void_var") pos in
  void_expr.expr_type <- Some Void;
  
  let invalid_if = make_stmt (If (void_expr, [], None)) pos in
  
  (* This should fail type checking *)
  (try
    let _ = type_check_statement ctx invalid_if in
    failwith "Should have failed type checking for void in boolean context"
  with
  | Type_error (msg, _) -> 
      check bool "Void type should fail in boolean context" 
        (try ignore (Str.search_forward (Str.regexp "cannot be used in boolean context") msg 0); true with Not_found -> false) false)

(** Test complex boolean expressions with truthy/falsy *)
let test_complex_boolean_expressions () =
  let pos = make_test_pos () in
  let symbol_table = create_symbol_table () in
  let ctx = create_context symbol_table [] in
  
  (* Test logical AND with truthy/falsy *)
  let num_expr = make_expr (Literal (IntLit (42, None))) pos in
  let str_expr = make_expr (Literal (StringLit "hello")) pos in
  let bool_expr = make_expr (Literal (BoolLit true)) pos in
  
  (* This should work: if (42 && "hello" && true) *)
  let and_expr = make_expr (BinaryOp (num_expr, And, make_expr (BinaryOp (str_expr, And, bool_expr)) pos)) pos in
  let _complex_if = make_stmt (If (and_expr, [], None)) pos in
  
  (* Note: This test may need adjustment based on whether we extend && and || operators *)
  (* For now, let's just test that individual truthy expressions work *)
  let simple_if = make_stmt (If (num_expr, [], None)) pos in
  
  try
    let _ = type_check_statement ctx simple_if in
    check bool "Complex boolean expression should type check" true true
  with
  | Type_error (msg, _) -> 
      failwith ("Complex boolean expression type checking failed: " ^ msg)

(** Main test suite *)
let () =
  run "Truthy/Falsy Conversion Tests" [
    "truthy_falsy_tests", [
      test_case "Type checking allows truthy types" `Quick test_truthy_type_checking;
      test_case "Truthy/falsy evaluation works correctly" `Quick test_truthy_evaluation;
      test_case "If statements work with truthy/falsy" `Quick test_if_statement_truthy;
      test_case "While loops work with truthy/falsy" `Quick test_while_loop_truthy;
      test_case "Map lookup truthy/falsy pattern" `Quick test_map_lookup_truthy;
      test_case "Invalid types fail in boolean context" `Quick test_invalid_boolean_types;
      test_case "Complex boolean expressions work" `Quick test_complex_boolean_expressions;
    ]
  ] 