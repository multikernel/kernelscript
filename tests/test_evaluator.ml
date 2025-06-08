(** Unit Tests for Expression Evaluator *)

open OUnit2
open Kernelscript.Ast
open Kernelscript.Evaluator

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
let test_literal_evaluation _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test integer literals *)
  let int_expr = make_int_expr 42 in
  let result = evaluate_expression ctx int_expr in
  assert_equal (Ok (IntValue 42)) result;
  
  (* Test boolean literals *)
  let bool_expr = make_bool_expr true in
  let result = evaluate_expression ctx bool_expr in
  assert_equal (Ok (BoolValue true)) result;
  
  (* Test string literals *)
  let str_expr = make_string_expr "hello" in
  let result = evaluate_expression ctx str_expr in
  assert_equal (Ok (StringValue "hello")) result;
  
  (* Test character literals *)
  let char_expr = make_char_expr 'x' in
  let result = evaluate_expression ctx char_expr in
  assert_equal (Ok (CharValue 'x')) result

(** Test arithmetic operations *)
let test_arithmetic_operations _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test addition *)
  let add_expr = make_binary_expr (make_int_expr 10) Add (make_int_expr 5) in
  let result = evaluate_expression ctx add_expr in
  assert_equal (Ok (IntValue 15)) result;
  
  (* Test subtraction *)
  let sub_expr = make_binary_expr (make_int_expr 10) Sub (make_int_expr 3) in
  let result = evaluate_expression ctx sub_expr in
  assert_equal (Ok (IntValue 7)) result;
  
  (* Test multiplication *)
  let mul_expr = make_binary_expr (make_int_expr 6) Mul (make_int_expr 7) in
  let result = evaluate_expression ctx mul_expr in
  assert_equal (Ok (IntValue 42)) result;
  
  (* Test division *)
  let div_expr = make_binary_expr (make_int_expr 20) Div (make_int_expr 4) in
  let result = evaluate_expression ctx div_expr in
  assert_equal (Ok (IntValue 5)) result;
  
  (* Test modulo *)
  let mod_expr = make_binary_expr (make_int_expr 17) Mod (make_int_expr 5) in
  let result = evaluate_expression ctx mod_expr in
  assert_equal (Ok (IntValue 2)) result

(** Test division by zero *)
let test_division_by_zero _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  let div_expr = make_binary_expr (make_int_expr 10) Div (make_int_expr 0) in
  let result = evaluate_expression ctx div_expr in
  assert_bool "Should fail with division by zero error" (match result with
    | Error (msg, _) -> String.contains msg 'z'
    | Ok _ -> false)

(** Test operator precedence *)
let test_operator_precedence _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test multiplication before addition: 2 + 3 * 4 = 14 *)
  let expr = make_binary_expr 
    (make_int_expr 2) 
    Add 
    (make_binary_expr (make_int_expr 3) Mul (make_int_expr 4)) in
  let result = evaluate_expression ctx expr in
  assert_equal (Ok (IntValue 14)) result;
  
  (* Test parentheses: (2 + 3) * 4 = 20 *)
  let expr2 = make_binary_expr 
    (make_binary_expr (make_int_expr 2) Add (make_int_expr 3))
    Mul 
    (make_int_expr 4) in
  let result2 = evaluate_expression ctx expr2 in
  assert_equal (Ok (IntValue 20)) result2

(** Test comparison operations *)
let test_comparison_operations _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test equality *)
  let eq_expr = make_binary_expr (make_int_expr 5) Eq (make_int_expr 5) in
  let result = evaluate_expression ctx eq_expr in
  assert_equal (Ok (BoolValue true)) result;
  
  (* Test inequality *)
  let ne_expr = make_binary_expr (make_int_expr 5) Ne (make_int_expr 3) in
  let result = evaluate_expression ctx ne_expr in
  assert_equal (Ok (BoolValue true)) result;
  
  (* Test less than *)
  let lt_expr = make_binary_expr (make_int_expr 3) Lt (make_int_expr 5) in
  let result = evaluate_expression ctx lt_expr in
  assert_equal (Ok (BoolValue true)) result;
  
  (* Test greater than *)
  let gt_expr = make_binary_expr (make_int_expr 7) Gt (make_int_expr 5) in
  let result = evaluate_expression ctx gt_expr in
  assert_equal (Ok (BoolValue true)) result

(** Test logical operations *)
let test_logical_operations _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test logical AND *)
  let and_expr = make_binary_expr (make_bool_expr true) And (make_bool_expr false) in
  let result = evaluate_expression ctx and_expr in
  assert_equal (Ok (BoolValue false)) result;
  
  (* Test logical OR *)
  let or_expr = make_binary_expr (make_bool_expr true) Or (make_bool_expr false) in
  let result = evaluate_expression ctx or_expr in
  assert_equal (Ok (BoolValue true)) result

(** Test unary operations *)
let test_unary_operations _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test logical NOT *)
  let not_expr = make_unary_expr Not (make_bool_expr true) in
  let result = evaluate_expression ctx not_expr in
  assert_equal (Ok (BoolValue false)) result;
  
  (* Test negation *)
  let neg_expr = make_unary_expr Neg (make_int_expr 42) in
  let result = evaluate_expression ctx neg_expr in
  assert_equal (Ok (IntValue (-42))) result

(** Test variable access *)
let test_variable_access _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Add a variable to context *)
  add_variable ctx "test_var" (IntValue 123);
  
  let var_expr = make_id_expr "test_var" in
  let result = evaluate_expression ctx var_expr in
  assert_equal (Ok (IntValue 123)) result;
  
  (* Test undefined variable *)
  let undef_expr = make_id_expr "undefined_var" in
  let result = evaluate_expression ctx undef_expr in
  assert_bool "Should fail with undefined variable error" (match result with
    | Error (msg, _) -> String.contains msg 'U'
    | Ok _ -> false)

(** Test built-in function calls *)
let test_builtin_functions _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test ctx.packet function *)
  let packet_expr = make_call_expr "ctx.packet" [] in
  let result = evaluate_expression ctx packet_expr in
  assert_bool "ctx.packet should return pointer value" (match result with
    | Ok (PointerValue _) -> true
    | _ -> false);
  
  (* Test bpf_get_current_pid_tgid function *)
  let pid_expr = make_call_expr "bpf_get_current_pid_tgid" [] in
  let result = evaluate_expression ctx pid_expr in
  assert_bool "bpf_get_current_pid_tgid should return integer value" (match result with
    | Ok (IntValue _) -> true
    | _ -> false);
  
  (* Test bpf_trace_printk function *)
  let print_expr = make_call_expr "bpf_trace_printk" [
    make_string_expr "Hello";
    make_int_expr 5
  ] in
  let result = evaluate_expression ctx print_expr in
  assert_bool "bpf_trace_printk should return success code" (match result with
    | Ok (IntValue 0) -> true
    | _ -> false)

(** Test enum constants *)
let test_enum_constants _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test XdpAction constants *)
  let pass_expr = make_id_expr "XdpAction::Pass" in
  let result = evaluate_expression ctx pass_expr in
  assert_bool "Should be XdpAction::Pass enum value" (match result with
    | Ok (EnumValue ("XdpAction", 2)) -> true
    | _ -> false);
  
  let drop_expr = make_id_expr "XdpAction::Drop" in
  let result = evaluate_expression ctx drop_expr in
  assert_bool "Should be XdpAction::Drop enum value" (match result with
    | Ok (EnumValue ("XdpAction", 1)) -> true
    | _ -> false)

(** Test string concatenation *)
let test_string_concatenation _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  let concat_expr = make_binary_expr 
    (make_string_expr "Hello") 
    Add 
    (make_string_expr " World") in
  let result = evaluate_expression ctx concat_expr in
  assert_equal (Ok (StringValue "Hello World")) result

(** Test array access *)
let test_array_access _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Create array and add to context *)
  let test_array = ArrayValue [|IntValue 10; IntValue 20; IntValue 30|] in
  add_variable ctx "test_arr" test_array;
  
  let access_expr = make_expr (ArrayAccess (
    make_id_expr "test_arr",
    make_int_expr 1
  )) (make_test_pos ()) in
  
  let result = evaluate_expression ctx access_expr in
  assert_equal (Ok (IntValue 20)) result

(** Test string indexing *)
let test_string_indexing _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  add_variable ctx "test_str" (StringValue "hello");
  
  let index_expr = make_expr (ArrayAccess (
    make_id_expr "test_str",
    make_int_expr 1
  )) (make_test_pos ()) in
  
  let result = evaluate_expression ctx index_expr in
  assert_equal (Ok (CharValue 'e')) result

(** Test function call with wrong argument count *)
let test_function_call_wrong_args _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* ctx.packet takes no arguments, but we pass one *)
  let bad_call = make_call_expr "ctx.packet" [make_int_expr 42] in
  let result = evaluate_expression ctx bad_call in
  assert_bool "Should fail with wrong arguments error" (match result with
    | Error (msg, _) -> String.contains msg 'a'
    | Ok _ -> false)

(** Test type mismatch in operations *)
let test_type_mismatch _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Try to add integer and boolean *)
  let bad_expr = make_binary_expr (make_int_expr 5) Add (make_bool_expr true) in
  let result = evaluate_expression ctx bad_expr in
  assert_bool "Should fail with type mismatch error" (match result with
    | Error (msg, _) -> String.contains msg 'C'
    | Ok _ -> false)

(** Test runtime value string representation *)
let test_runtime_value_string _ =
  (* Test various runtime value string representations *)
  assert_equal "42" (string_of_runtime_value (IntValue 42));
  assert_equal "true" (string_of_runtime_value (BoolValue true));
  assert_equal "\"hello\"" (string_of_runtime_value (StringValue "hello"));
  assert_equal "'x'" (string_of_runtime_value (CharValue 'x'));
  assert_equal "0x1000" (string_of_runtime_value (PointerValue 0x1000));
  assert_equal "()" (string_of_runtime_value UnitValue)

(** Test context manipulation *)
let test_context_manipulation _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test adding and getting variables *)
  add_variable ctx "x" (IntValue 10);
  let result = get_variable ctx "x" in
  assert_equal (Some (IntValue 10)) result;
  
  (* Test non-existent variable *)
  let result = get_variable ctx "y" in
  assert_equal None result

(** Test bounds checking *)
let test_bounds_checking _ =
  let ctx = create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  let test_array = ArrayValue [|IntValue 1; IntValue 2|] in
  add_variable ctx "arr" test_array;
  
  (* Test out of bounds access *)
  let bad_access = make_expr (ArrayAccess (
    make_id_expr "arr",
    make_int_expr 5
  )) (make_test_pos ()) in
  
  let result = evaluate_expression ctx bad_access in
  assert_bool "Should fail with bounds error" (match result with
    | Error (msg, _) -> String.contains msg 'b'
    | Ok _ -> false)

(** Create test suite *)
let evaluator_suite =
  "Evaluator Tests" >::: [
    "test_literal_evaluation" >:: test_literal_evaluation;
    "test_arithmetic_operations" >:: test_arithmetic_operations;
    "test_division_by_zero" >:: test_division_by_zero;
    "test_operator_precedence" >:: test_operator_precedence;
    "test_comparison_operations" >:: test_comparison_operations;
    "test_logical_operations" >:: test_logical_operations;
    "test_unary_operations" >:: test_unary_operations;
    "test_variable_access" >:: test_variable_access;
    "test_builtin_functions" >:: test_builtin_functions;
    "test_enum_constants" >:: test_enum_constants;
    "test_string_concatenation" >:: test_string_concatenation;
    "test_array_access" >:: test_array_access;
    "test_string_indexing" >:: test_string_indexing;
    "test_function_call_wrong_args" >:: test_function_call_wrong_args;
    "test_type_mismatch" >:: test_type_mismatch;
    "test_runtime_value_string" >:: test_runtime_value_string;
    "test_context_manipulation" >:: test_context_manipulation;
    "test_bounds_checking" >:: test_bounds_checking;
  ]

let () = run_test_tt_main evaluator_suite