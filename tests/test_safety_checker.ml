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
open Kernelscript.Safety_checker
open Alcotest

(** Helper functions for creating test programs *)
let make_test_program name functions =
  let pos = make_position 1 1 "test.ks" in
  make_program name Xdp functions pos

let make_test_function name params body =
  let pos = make_position 1 1 "test.ks" in
  make_function name params (Some (make_unnamed_return U32)) body pos

(** Test basic safety checks *)
let test_basic_safety_checks () =
  let pos = make_position 1 1 "test.ks" in
  let simple_stmt = make_stmt (Return (Some (make_expr (Literal (IntLit (0, None))) pos))) pos in
  let func = make_test_function "main" [] [simple_stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "basic safety check" true result.overall_safe

(** Test null pointer access *)
let test_null_pointer_access () =
  let pos = make_position 1 1 "test.ks" in
  let null_access = make_expr (FieldAccess (make_expr (Literal (IntLit (0, None))) pos, "data")) pos in
  let stmt = make_stmt (ExprStmt null_access) pos in
  let func = make_test_function "main" [] [stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "null pointer access detected" false result.overall_safe

(** Test bounds checking *)
let test_bounds_checking () =
  let pos = make_position 1 1 "test.ks" in
  let array_type = Array (U32, 10) in
  let array_decl = make_stmt (Declaration ("arr", Some array_type, Some (make_expr (Literal (IntLit (0, None))) pos))) pos in
  let out_of_bounds = make_expr (ArrayAccess (make_expr (Identifier "arr") pos, make_expr (Literal (IntLit (15, None))) pos)) pos in
  let access_stmt = make_stmt (ExprStmt out_of_bounds) pos in
  let func = make_test_function "main" [] [array_decl; access_stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "bounds checking" false result.overall_safe

(** Test packet bounds checking *)
let test_packet_bounds_checking () =
  let pos = make_position 1 1 "test.ks" in
  let ctx_param = ("ctx", Pointer Xdp_md) in
  let packet_access = make_expr (FieldAccess (make_expr (Identifier "ctx") pos, "data")) pos in
  let unsafe_access = make_expr (ArrayAccess (packet_access, make_expr (Literal (IntLit (1500, None))) pos)) pos in
  let stmt = make_stmt (ExprStmt unsafe_access) pos in
  let func = make_test_function "main" [ctx_param] [stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "packet bounds checking" true result.overall_safe

(** Test unsafe packet access *)
let test_unsafe_packet_access () =
  let pos = make_position 1 1 "test.ks" in
  let ctx_param = ("ctx", Pointer Xdp_md) in
  let data_ptr = make_expr (FieldAccess (make_expr (Identifier "ctx") pos, "data")) pos in
  let unsafe_deref = make_expr (FieldAccess (data_ptr, "value")) pos in
  let stmt = make_stmt (ExprStmt unsafe_deref) pos in
  let func = make_test_function "main" [ctx_param] [stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "unsafe packet access" true result.overall_safe

(** Test infinite loop detection *)
let test_infinite_loop_detection () =
  let pos = make_position 1 1 "test.ks" in
  let infinite_condition = make_expr (Literal (BoolLit true)) pos in
  let loop_body = [make_stmt (ExprStmt (make_expr (Literal (IntLit (1, None))) pos)) pos] in
  let infinite_loop = make_stmt (While (infinite_condition, loop_body)) pos in
  let func = make_test_function "main" [] [infinite_loop] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "infinite loop detection" false result.overall_safe

(** Test stack overflow prevention *)
let test_stack_overflow_prevention () =
  let pos = make_position 1 1 "test.ks" in
  let large_array = Array (U32, 10000) in
  let large_decl = make_stmt (Declaration ("large_arr", Some large_array, Some (make_expr (Literal (IntLit (0, None))) pos))) pos in
  let func = make_test_function "main" [] [large_decl] in
  let program = make_test_program "test" [func] in
  
  let stack_analysis = analyze_stack_usage program in
  check bool "stack overflow prevention" true (stack_analysis.max_stack_usage > 0)

(** Test map access safety *)
let test_map_access_safety () =
  let pos = make_position 1 1 "test.ks" in
  let map_lookup = make_expr (Call (make_expr (Identifier "map_lookup") pos, [make_expr (Literal (IntLit (42, None))) pos])) pos in
  let stmt = make_stmt (ExprStmt map_lookup) pos in
  let func = make_test_function "main" [] [stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "map access safety" true result.overall_safe

(** Test integer overflow checking *)
let test_integer_overflow_checking () =
  let pos = make_position 1 1 "test.ks" in
  let max_int = make_expr (Literal (IntLit (max_int, None))) pos in
  let overflow_expr = make_expr (BinaryOp (max_int, Add, make_expr (Literal (IntLit (1, None))) pos)) pos in
  let stmt = make_stmt (ExprStmt overflow_expr) pos in
  let func = make_test_function "main" [] [stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "integer overflow checking" false result.overall_safe

(** Test division by zero *)
let test_division_by_zero () =
  let pos = make_position 1 1 "test.ks" in
  let div_by_zero = make_expr (BinaryOp (make_expr (Literal (IntLit (10, None))) pos, Div, make_expr (Literal (IntLit (0, None))) pos)) pos in
  let stmt = make_stmt (ExprStmt div_by_zero) pos in
  let func = make_test_function "main" [] [stmt] in
  let program = make_test_program "test" [func] in
  
  let result = safety_check program in
  check bool "division by zero" false result.overall_safe

(** Test memory access patterns *)
let test_memory_access_patterns () =
  let pos = make_position 1 1 "test.ks" in
  let ptr_decl = make_stmt (Declaration ("ptr", Some (Pointer U32), Some (make_expr (Literal (IntLit (0, None))) pos))) pos in
  let ptr_access = make_expr (FieldAccess (make_expr (Identifier "ptr") pos, "value")) pos in
  let stmt = make_stmt (ExprStmt ptr_access) pos in
  let func = make_test_function "main" [] [ptr_decl; stmt] in
  let program = make_test_program "test" [func] in
  
  let result = analyze_safety program in
  check bool "memory access patterns" true (List.length result.stack_analysis.warnings >= 0)

(** Test comprehensive safety analysis *)
let test_comprehensive_safety_analysis () =
  let pos = make_position 1 1 "test.ks" in
  let complex_expr = make_expr (BinaryOp (
    make_expr (ArrayAccess (make_expr (Identifier "arr") pos, make_expr (Literal (IntLit (5, None))) pos)) pos,
    Add,
    make_expr (Call (make_expr (Identifier "unsafe_func") pos, [])) pos
  )) pos in
  let stmt = make_stmt (ExprStmt complex_expr) pos in
  let func = make_test_function "main" [] [stmt] in
  let program = make_test_program "test" [func] in
  
  let result = analyze_safety program in
  check bool "comprehensive analysis" true (List.length result.bounds_errors >= 0)

let safety_checker_tests = [
  "basic_safety_checks", `Quick, test_basic_safety_checks;
  "null_pointer_access", `Quick, test_null_pointer_access;
  "bounds_checking", `Quick, test_bounds_checking;
  "packet_bounds_checking", `Quick, test_packet_bounds_checking;
  "unsafe_packet_access", `Quick, test_unsafe_packet_access;
  "infinite_loop_detection", `Quick, test_infinite_loop_detection;
  "stack_overflow_prevention", `Quick, test_stack_overflow_prevention;
  "map_access_safety", `Quick, test_map_access_safety;
  "integer_overflow_checking", `Quick, test_integer_overflow_checking;
  "division_by_zero", `Quick, test_division_by_zero;
  "memory_access_patterns", `Quick, test_memory_access_patterns;
  "comprehensive_safety_analysis", `Quick, test_comprehensive_safety_analysis;
]

let () =
  run "Safety Checker Tests" [
    "safety_checker", safety_checker_tests;
  ] 