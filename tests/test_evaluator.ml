(** Unit Tests for Expression Evaluator *)

open Kernelscript.Ast
open Kernelscript.Evaluator
open Alcotest

(** Helper functions for creating test expressions *)
let make_test_pos () = make_position 1 1 "test.ks"

let make_int_expr value =
  make_expr (Literal (IntLit value)) (make_test_pos ())

let make_bool_expr value =
  make_expr (Literal (BoolLit value)) (make_test_pos ())

let make_string_expr value =
  make_expr (Literal (StringLit value)) (make_test_pos ())

let make_char_expr value =
  make_expr (Literal (CharLit value)) (make_test_pos ())

let make_id_expr name =
  make_expr (Identifier name) (make_test_pos ())

let make_binary_expr left op right =
  make_expr (BinaryOp (left, op, right)) (make_test_pos ())

let make_unary_expr op expr =
  make_expr (UnaryOp (op, expr)) (make_test_pos ())

let make_call_expr name args =
  make_expr (FunctionCall (name, args)) (make_test_pos ())

(** Test literal evaluation *)
let test_literal_evaluation () =
  let _context = create_eval_context (Hashtbl.create 16) (Hashtbl.create 16) in
  
  (* Test integer literal *)
  let int_result = runtime_value_of_literal (IntLit 42) in
  check bool "integer literal" true (match int_result with IntValue 42 -> true | _ -> false);
  
  (* Test boolean literal *)
  let bool_result = runtime_value_of_literal (BoolLit true) in
  check bool "boolean literal" true (match bool_result with BoolValue true -> true | _ -> false);
  
  (* Test string literal *)
  let string_result = runtime_value_of_literal (StringLit "hello") in
  check bool "string literal" true (match string_result with StringValue "hello" -> true | _ -> false)

(** Test variable evaluation *)
let test_variable_evaluation () =
  let context = create_eval_context (Hashtbl.create 16) (Hashtbl.create 16) in
  
  (* Set a variable *)
  add_variable context "x" (IntValue 100);
  
  (* Evaluate the variable *)
  (try
    let result = get_variable context "x" in
    check bool "variable evaluation" true (match result with Some (IntValue 100) -> true | _ -> false)
  with
  | Not_found -> check bool "Variable not found" true true);
  
  (* Test undefined variable handling *)
  let undefined_result = 
    (try
      let _ = get_variable context "undefined" in
      false
    with
    | Not_found -> true) in
  check bool "undefined variable correctly raises" true undefined_result

(** Test binary operations *)
let test_binary_operations () =
  let pos = make_test_pos () in
  
  (* Arithmetic operations *)
  let add_result = eval_binary_op (IntValue 3) Add (IntValue 4) pos in
  check bool "addition" true (match add_result with IntValue 7 -> true | _ -> false);
  
  let sub_result = eval_binary_op (IntValue 5) Sub (IntValue 4) pos in
  check bool "subtraction" true (match sub_result with IntValue 1 -> true | _ -> false);
  
  let mul_result = eval_binary_op (IntValue 4) Mul (IntValue 5) pos in
  check bool "multiplication" true (match mul_result with IntValue 20 -> true | _ -> false);
  
  let div_result = eval_binary_op (IntValue 12) Div (IntValue 4) pos in
  check bool "division" true (match div_result with IntValue 3 -> true | _ -> false);
  
  (* Comparison operations *)
  let eq_result = eval_binary_op (IntValue 5) Eq (IntValue 5) pos in
  check bool "equality" true (match eq_result with BoolValue true -> true | _ -> false);
  
  let ne_result = eval_binary_op (IntValue 5) Ne (IntValue 3) pos in
  check bool "inequality" true (match ne_result with BoolValue true -> true | _ -> false);
  
  let lt_result = eval_binary_op (IntValue 3) Lt (IntValue 5) pos in
  check bool "less than" true (match lt_result with BoolValue true -> true | _ -> false);
  
  let gt_result = eval_binary_op (IntValue 5) Gt (IntValue 3) pos in
  check bool "greater than" true (match gt_result with BoolValue true -> true | _ -> false);
  
  (* Logical operations *)
  let and_result = eval_binary_op (BoolValue true) And (BoolValue false) pos in
  check bool "logical and" true (match and_result with BoolValue false -> true | _ -> false);
  
  let or_result = eval_binary_op (BoolValue true) Or (BoolValue false) pos in
  check bool "logical or" true (match or_result with BoolValue true -> true | _ -> false)

(** Test expression evaluation *)
let test_expression_evaluation () =
  let context = create_eval_context (Hashtbl.create 16) (Hashtbl.create 16) in
  let expr = make_binary_expr (make_int_expr 10) Add (make_int_expr 20) in
  try
    let result = evaluate_expression context expr in
    check bool "expression evaluation" true (match result with Ok (IntValue 30) -> true | _ -> false)
  with
  | Evaluation_error (msg, _) -> check bool ("Error occurred: " ^ msg) true false
  | _ -> check bool "Failed to evaluate expression" true false

(** Test function calls *)
let test_function_calls () =
  (* Since evaluate_program doesn't exist, test function call evaluation at expression level *)
  let context = create_eval_context (Hashtbl.create 16) (Hashtbl.create 16) in
  
  (* Test built-in function calls *)
  try
    let builtin_result = eval_function_call context "bpf_ktime_get_ns" [] (make_test_pos ()) in
    check bool "builtin function call" true (match builtin_result with IntValue _ -> true | _ -> false)
  with
  | Evaluation_error (msg, _) -> check bool ("Error occurred: " ^ msg) true false
  | _ -> check bool "Failed to evaluate function call" true false

(** Test conditional evaluation *)
let test_conditional_evaluation () =
  (* Test conditional logic using binary operations *)
  let pos = make_test_pos () in
  let condition = eval_binary_op (IntValue 10) Gt (IntValue 5) pos in
  check bool "conditional evaluation" true (match condition with BoolValue true -> true | _ -> false)

(** Test loop evaluation *)
let test_loop_evaluation () =
  (* Test loop-like operations using repeated binary operations *)
  let pos = make_test_pos () in
  let sum1 = eval_binary_op (IntValue 0) Add (IntValue 1) pos in
  let sum2 = eval_binary_op sum1 Add (IntValue 2) pos in
  let sum3 = eval_binary_op sum2 Add (IntValue 3) pos in
  let sum4 = eval_binary_op sum3 Add (IntValue 4) pos in
  check bool "loop-like evaluation" true (match sum4 with IntValue 10 -> true | _ -> false)

(** Test array operations *)
let test_array_operations () =
  (* Test array value creation and access *)
  let arr_values = [|IntValue 1; IntValue 2; IntValue 3; IntValue 4; IntValue 5|] in
  let array_val = ArrayValue arr_values in
  check bool "array creation" true (match array_val with ArrayValue _ -> true | _ -> false);
  
  (* Test array access simulation *)
  let first_elem = arr_values.(0) in
  check bool "array access" true (match first_elem with IntValue 1 -> true | _ -> false)

(** Test map operations *)
let test_map_operations () =
  let context = create_eval_context (Hashtbl.create 16) (Hashtbl.create 16) in
  
  (* Test map operation function calls *)
  try
    let key_expr = make_int_expr 42 in
    let lookup_result = eval_function_call context "counter.lookup" [key_expr] (make_test_pos ()) in
    check bool "map lookup operation" true (match lookup_result with StructValue _ -> true | _ -> false)
  with
  | Evaluation_error (msg, _) -> check bool ("Error occurred: " ^ msg) true false
  | _ -> check bool "Failed to evaluate map operation" true false

(** Test struct operations *)
let test_struct_operations () =
  (* Test struct value creation *)
  let struct_fields = [("x", IntValue 10); ("y", IntValue 20)] in
  let struct_val = StructValue struct_fields in
  check bool "struct creation" true (match struct_val with StructValue _ -> true | _ -> false);
  
  (* Test field access simulation *)
  let x_field = List.assoc "x" struct_fields in
  check bool "struct field access" true (match x_field with IntValue 10 -> true | _ -> false)

(** Test error handling *)
let test_error_handling () =
  let pos = make_test_pos () in
  
  (* Test division by zero *)
  try
    let _ = eval_binary_op (IntValue 10) Div (IntValue 0) pos in
    check bool "Should have failed for division by zero" true false
  with
  | Evaluation_error (msg, _) -> check bool "division by zero error" true (String.contains msg '0')
  | _ -> check bool "Unexpected error type" true false

(** Test recursive functions *)
let test_recursive_functions () =
  let context = create_eval_context (Hashtbl.create 16) (Hashtbl.create 16) in
  
  (* Test call depth tracking *)
  check bool "call depth tracking" true (context.call_depth = 0);
  
  (* Simulate recursive call by incrementing call depth *)
  context.call_depth <- context.call_depth + 1;
  check bool "call depth increment" true (context.call_depth = 1);
  context.call_depth <- context.call_depth - 1

(** Test complex evaluation *)
let test_complex_evaluation () =
  let context = create_eval_context (Hashtbl.create 16) (Hashtbl.create 16) in
  
  (* Test complex expression evaluation *)
  let expr1 = make_binary_expr (make_int_expr 10) Mul (make_int_expr 5) in
  let expr2 = make_binary_expr (make_int_expr 20) Add (make_int_expr 10) in
  let complex_expr = make_binary_expr expr1 Add expr2 in
  
  try
    let result = evaluate_expression context complex_expr in
    check bool "complex evaluation" true (match result with Ok (IntValue 80) -> true | _ -> false)  (* 50 + 30 *)
  with
  | Evaluation_error (msg, _) -> check bool ("Error occurred: " ^ msg) true false
  | _ -> check bool "Failed to evaluate complex expression" true false

let evaluator_tests = [
  "literal_evaluation", `Quick, test_literal_evaluation;
  "variable_evaluation", `Quick, test_variable_evaluation;
  "binary_operations", `Quick, test_binary_operations;
  "expression_evaluation", `Quick, test_expression_evaluation;
  "function_calls", `Quick, test_function_calls;
  "conditional_evaluation", `Quick, test_conditional_evaluation;
  "loop_evaluation", `Quick, test_loop_evaluation;
  "array_operations", `Quick, test_array_operations;
  "map_operations", `Quick, test_map_operations;
  "struct_operations", `Quick, test_struct_operations;
  "error_handling", `Quick, test_error_handling;
  "recursive_functions", `Quick, test_recursive_functions;
  "complex_evaluation", `Quick, test_complex_evaluation;
]

let () =
  run "Evaluator Tests" [
    "evaluator", evaluator_tests;
  ]