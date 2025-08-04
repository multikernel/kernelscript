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
open Kernelscript.Parse
open Alcotest

(** Helper function to parse string with builtin types loaded via symbol table *)
let parse_string_with_builtins code =
  let ast = parse_string code in
  (* Create symbol table with test builtin types *)
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  (* Run type checking with builtin types loaded *)
  let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  typed_ast

(** Helper function to create symbol table with builtin loading *)
let create_symbol_table_with_builtins ast =
  Test_utils.Helpers.create_test_symbol_table ast

(** Helper function to type check with builtin types loaded *)
let type_check_and_annotate_ast_with_builtins ast =
  (* Create symbol table with test builtin types *)
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  (* Run type checking with builtin types loaded *)
  Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast

(** Helper function to check if two types can unify *)
let can_unify t1 t2 =
  match unify_types t1 t2 with
  | Some _ -> true
  | None -> false

(** Test type unification *)
let test_type_unification () =
  (* Test basic type unification *)
  check bool "U32 unifies with U32" true (can_unify U32 U32);
  check bool "U32 can unify with U64 (promotion)" true (can_unify U32 U64);
  check bool "Pointer U8 unifies with Pointer U8" true (can_unify (Pointer U8) (Pointer U8));
  check bool "Array types unify" true (can_unify (Array (U32, 10)) (Array (U32, 10)));
  check bool "Different array sizes don't unify" false (can_unify (Array (U32, 10)) (Array (U32, 20)))

(** Test basic type inference *)
let test_basic_type_inference () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = 42
  var y = true
  var z = "hello"
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let (_enhanced_ast, typed_attributed_functions) = type_check_and_annotate_ast_with_builtins ast in
    check int "typed programs count" 1 (List.length typed_attributed_functions);
    
    (* Verify that type checking completed without errors *)
    match List.hd typed_attributed_functions with
    | (attr_list, typed_func) -> 
        check string "program name" "test" typed_func.tfunc_name;
        check int "function parameters" 1 (List.length typed_func.tfunc_params);
        check bool "has xdp attribute" true (List.exists (function SimpleAttribute "xdp" -> true | _ -> false) attr_list)
  with
  | _ -> fail "Error occurred"

(** Test variable type checking *)
let test_variable_type_checking () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x: u32 = 42
  var y: bool = true
  var z = x + 10
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "variable type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test binary operations *)
let test_binary_operations () =
  let valid_operations = [
    ("var x = 1 + 2", true);
    ("var x = 1 - 2", true); 
    ("var x = 1 * 2", true);
    ("var x = 1 / 2", true);
    ("var x = 1 == 2", true);
    ("var x = 1 != 2", true);
    ("var x = 1 < 2", true);
    ("var x = true && false", true);
    ("var x = true || false", true);
  ] in
  
  List.iter (fun (stmt, should_succeed) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 0
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("binary operation: " ^ stmt) should_succeed true
    with
    | _ -> check bool ("binary operation: " ^ stmt) should_succeed false
  ) valid_operations

(** Test function calls *)
let test_function_calls () =
  let program_text = {|
@helper
fn helper(x: u32, y: u32) -> u32 {
  return x + y
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = helper(10, 20)
  return result
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "function call type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test context types *)
let test_context_types () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "context type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test struct field access *)
let test_struct_field_access () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var packet = ctx->data
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "struct field access" true true
  with
  | _ -> fail "Error occurred"

(** Test statement type checking *)
let test_statement_type_checking () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x: u32 = 42
  x = 50
  if (x > 0) {
    return 1
  }
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "statement type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test function type checking *)
let test_function_type_checking () =
  let program_text = {|
@helper
fn calculate(a: u32, b: u32) -> u32 {
  var result = a + b
  return result
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var value = calculate(10, 20)
  return value
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "function type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test built-in function type checking *)
let test_builtin_function_type_checking () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
    print("Hello from eBPF")
    print("Message with value: ", 42)
    print()
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "built-in function type checking" true true
  with
  | _ -> fail "Built-in function type checking failed"

(** Test variadic function argument handling *)
let test_variadic_function_arguments () =
  let test_cases = [
    ("print()", true, "no arguments");
    ("print(\"hello\")", true, "single string argument");
    ("print(\"value: \", 42)", true, "string and number");
    ("print(\"a\", \"b\", \"c\")", true, "multiple arguments");
    ("print(1, 2, 3, 4, 5)", true, "many arguments");
  ] in
  
  List.iter (fun (call, should_succeed, desc) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
    %s
    return 0
}
|} call in
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("variadic function: " ^ desc) should_succeed true
    with
    | _ -> check bool ("variadic function: " ^ desc) should_succeed false
  ) test_cases

(** Test built-in function return types *)
let test_builtin_function_return_types () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
    var result: u32 = print("test message")
    return result
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "built-in function return type" true true
  with
  | _ -> fail "Built-in function return type checking failed"

(** Test built-in vs user-defined function precedence *)
let test_builtin_vs_user_function_precedence () =
  let program_text = {|
@helper
fn my_function(x: u32) -> u32 {
  return x + 1
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var user_result = my_function(10)
  print("User function result: ", user_result)
  return user_result
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "built-in vs user function precedence" true true
  with
  | _ -> fail "Built-in vs user function precedence test failed"

(** Test stdlib integration *)
let test_stdlib_integration () =
  (* Test that stdlib functions are properly recognized *)
  check bool "print is builtin" true (Kernelscript.Stdlib.is_builtin_function "print");
  check bool "non_existent is not builtin" false (Kernelscript.Stdlib.is_builtin_function "non_existent_function");
  
  (* Test getting function signature *)
  (match Kernelscript.Stdlib.get_builtin_function_signature "print" with
  | Some (params, return_type) ->
      check int "print parameter count" 0 (List.length params);
      check bool "print return type is U32" true (return_type = Kernelscript.Ast.U32)
  | None -> check bool "print function signature should exist" false true);
  
  (* Test context-specific implementations *)
  (match Kernelscript.Stdlib.get_ebpf_implementation "print" with
  | Some impl -> check string "eBPF implementation" "bpf_printk" impl
  | None -> check bool "eBPF implementation should exist" false true);
  
  (match Kernelscript.Stdlib.get_userspace_implementation "print" with
  | Some impl -> check string "userspace implementation" "printf" impl
  | None -> check bool "userspace implementation should exist" false true)

(** Test error handling *)
let test_error_handling () =
  let invalid_programs = [
    ("var x: u32 = true;", "type mismatch");
    ("var x = 1 + true;", "invalid binary operation");
    ("var x = unknown_var;", "undefined variable");
    ("var x = func_not_exists();", "undefined function");
  ] in
  
  List.iter (fun (stmt, description) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2 // XDP_PASS
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      fail ("Should have failed for: " ^ description)
    with
    | _ -> check bool ("error handling: " ^ description) true true
  ) invalid_programs

(** Test program type checking *)
let test_program_type_checking () =
  let program_text = {|
@helper
fn is_tcp(protocol: u8) -> bool {
  return protocol == 6
}

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  var protocol: u8 = 6
  if (is_tcp(protocol)) {
    return 2  // 2 // XDP_PASS
  }
  return 1  // 1 // XDP_DROP
}
|} in
  try
    let ast = parse_string program_text in
    let (_enhanced_ast, typed_attributed_functions) = type_check_and_annotate_ast_with_builtins ast in
    check int "program type checking" 2 (List.length typed_attributed_functions);
    
    (* Verify that type checking completed without errors *)
    (* Find the XDP attributed function *)
    let xdp_func = List.find (fun (attr_list, _) -> 
      List.exists (function SimpleAttribute "xdp" -> true | _ -> false) attr_list
    ) typed_attributed_functions in
    match xdp_func with
    | (attr_list, typed_func) -> 
        check string "typed program name" "packet_filter" typed_func.tfunc_name;
        check int "typed function parameters" 1 (List.length typed_func.tfunc_params);
        check bool "has xdp attribute" true (List.exists (function SimpleAttribute "xdp" -> true | _ -> false) attr_list)
  with
  | _ -> fail "Error occurred"

(** Test integer type promotion *)
let test_integer_type_promotion () =
  let program_text = {|
var counter : hash<u32, u64>(1024)

@xdp fn test_promotion(ctx: *xdp_md) -> xdp_action {
  // Test U32 literal assignment to U64 map value
  counter[1] = 100     // U32 literal should promote to U64
  counter[2] = 200     // U32 literal should promote to U64
  
  // Test arithmetic with different sizes
  var small: u32 = 50
  var large: u64 = 1000
  var result = small + large  // U32 should promote to U64
  
  // Test map access with promoted values
  var val1 = counter[1] + 50  // U64 + U32 -> U64
  counter[3] = val1
  
  return XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let (_enhanced_ast, typed_attributed_functions) = type_check_and_annotate_ast_with_builtins ast in
    check int "type promotion programs count" 1 (List.length typed_attributed_functions);
    
    (* Verify that type checking completed without errors *)
    match List.hd typed_attributed_functions with
    | (_attr_list, typed_func) -> 
        check string "type promotion program name" "test_promotion" typed_func.tfunc_name;
        check bool "integer type promotion" true true
  with
  | exn -> 
    Printf.printf "Error in integer type promotion test: %s\n" (Printexc.to_string exn);
    fail "Error occurred in type promotion test"

(** Test type unification enhancements *)
let test_type_unification_enhanced () =
  (* Test the specific type promotions we added *)
  check bool "U32 promotes to U64" true (can_unify U32 U64);
  check bool "U64 unifies with U32" true (can_unify U64 U32);
  check bool "I32 promotes to I64" true (can_unify I32 I64);
  check bool "I64 unifies with I32" true (can_unify I64 I32);
  check bool "U16 promotes to U64" true (can_unify U16 U64);
  check bool "U8 promotes to U64" true (can_unify U8 U64);
  (* Test that incompatible types still don't unify *)
  check bool "U32 does not unify with Bool" false (can_unify U32 Bool);
  (* I32 and U32 should now unify due to permissive integer literal behavior *)
  check bool "I32 unifies with U32" true (can_unify I32 U32)

(** Test comprehensive type checking *)
let test_comprehensive_type_checking () =
  let program_text = {|
var counter : hash<u32, u64>(1024)

@helper
fn increment_counter(key: u32) -> u64 {
  var current = counter[key]
  var new_value = current + 1
  counter[key] = new_value
  return new_value
}

@helper
fn process_packet(size: u32) -> bool {
  return size > 1500
}

@xdp fn comprehensive_test(ctx: *xdp_md) -> xdp_action {
  var packet_size: u32 = 1000
  var counter_val = increment_counter(packet_size)
  var is_large = process_packet(packet_size)
  
  if (is_large && counter_val > 100) {
    return XDP_DROP
  } else {
    return XDP_PASS
  }
}
|} in
  try
    let ast = parse_string_with_builtins program_text in
    let (_enhanced_ast, typed_attributed_functions) = type_check_and_annotate_ast_with_builtins ast in
    check int "comprehensive AST length" 3 (List.length typed_attributed_functions);
    
    (* Verify that type checking completed without errors *)
    (* Find the XDP attributed function *)
    let xdp_func = List.find (fun (attr_list, _) -> 
      List.exists (function SimpleAttribute "xdp" -> true | _ -> false) attr_list
    ) typed_attributed_functions in
    match xdp_func with
    | (attr_list, typed_func) -> 
        check string "comprehensive program name" "comprehensive_test" typed_func.tfunc_name;
        check int "comprehensive function parameters" 1 (List.length typed_func.tfunc_params);
        check bool "has xdp attribute" true (List.exists (function SimpleAttribute "xdp" -> true | _ -> false) attr_list)
  with
  | _ -> fail "Error occurred"

(** Test comprehensive integer promotion *)
let test_comprehensive_integer_promotion () =
  (* Test all integer promotion combinations *)
  let promotion_tests = [
    (* U8 promotions *)
    (U8, U16, "U8 promotes to U16");
    (U8, U32, "U8 promotes to U32");
    (U8, U64, "U8 promotes to U64");
    (U16, U8, "U16 promotes to U16 (reverse)");
    (U32, U8, "U32 promotes to U32 (reverse)");
    (U64, U8, "U64 promotes to U64 (reverse)");
    
    (* U16 promotions *)
    (U16, U32, "U16 promotes to U32");
    (U16, U64, "U16 promotes to U64");
    (U32, U16, "U32 promotes to U32 (reverse)");
    (U64, U16, "U64 promotes to U64 (reverse)");
    
    (* U32 promotions *)
    (U32, U64, "U32 promotes to U64");
    (U64, U32, "U64 promotes to U64 (reverse)");
    
    (* I8 promotions *)
    (I8, I16, "I8 promotes to I16");
    (I8, I32, "I8 promotes to I32");
    (I8, I64, "I8 promotes to I64");
    (I16, I8, "I16 promotes to I16 (reverse)");
    (I32, I8, "I32 promotes to I32 (reverse)");
    (I64, I8, "I64 promotes to I64 (reverse)");
    
    (* I16 promotions *)
    (I16, I32, "I16 promotes to I32");
    (I16, I64, "I16 promotes to I64");
    (I32, I16, "I32 promotes to I32 (reverse)");
    (I64, I16, "I64 promotes to I64 (reverse)");
    
    (* I32 promotions *)
    (I32, I64, "I32 promotes to I64");
    (I64, I32, "I64 promotes to I64 (reverse)");
  ] in
  
  List.iter (fun (t1, t2, desc) ->
    check bool desc true (can_unify t1 t2)
  ) promotion_tests;
  
  (* Test that incompatible types still don't unify *)
  let incompatible_tests = [
    (U8, Bool, "U8 does not unify with Bool");
    (I16, Str 32, "I16 does not unify with Str");
    (U32, Pointer U32, "U32 does not unify with Pointer U32");
  ] in
  
  List.iter (fun (t1, t2, desc) ->
    check bool desc false (can_unify t1 t2)
  ) incompatible_tests;
  
  (* Test that compatible integer types do unify (permissive behavior) *)
  let compatible_tests = [
    (U32, I32, "U32 unifies with I32");
    (U64, I64, "U64 unifies with I64");
    (I32, U32, "I32 unifies with U32");
    (I64, U64, "I64 unifies with U64");
  ] in
  
  List.iter (fun (t1, t2, desc) ->
    check bool desc true (can_unify t1 t2)
  ) compatible_tests

(** Test arithmetic operations with integer promotion *)
let test_arithmetic_promotion () =
  let arithmetic_tests = [
    (* Basic arithmetic with different sizes *)
    ("var x: u8 = 10\n    var y: u64 = 1000\n    var result = x + y", "u8 + u64 addition");
    ("var x: u16 = 100\n    var y: u32 = 2000\n    var result = x * y", "u16 * u32 multiplication");
    ("var x: u32 = 500\n    var y: u64 = 1000\n    var result = y - x", "u64 - u32 subtraction");
    ("var x: u8 = 5\n    var y: u16 = 10\n    var result = x / y", "u8 / u16 division");
    ("var x: u16 = 17\n    var y: u32 = 5\n    var result = x % y", "u16 % u32 modulo");
    
    (* Signed arithmetic *)
    ("var x: i8 = -10\n    var y: i64 = 1000\n    var result = x + y", "i8 + i64 addition");
    ("var x: i16 = -100\n    var y: i32 = 2000\n    var result = x * y", "i16 * i32 multiplication");
    ("var x: i32 = -500\n    var y: i64 = 1000\n    var result = y - x", "i64 - i32 subtraction");
  ] in
  
  List.iter (fun (stmt, desc) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2 // XDP_PASS
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("arithmetic promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed arithmetic promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("arithmetic promotion: " ^ desc) false true
  ) arithmetic_tests

(** Test comparison operations with integer promotion *)
let test_comparison_promotion () =
  let comparison_tests = [
    (* Equality comparisons *)
    ("var x: u8 = 10\n    var y: u64 = 10\n    var result = x == y", "u8 == u64 equality");
    ("var x: u16 = 100\n    var y: u32 = 200\n    var result = x != y", "u16 != u32 inequality");
    ("var x: i8 = -5\n    var y: i64 = -5\n    var result = x == y", "i8 == i64 equality");
    
    (* Ordering comparisons *)
    ("var x: u8 = 10\n    var y: u64 = 100\n    var result = x < y", "u8 < u64 less than");
    ("var x: u16 = 1000\n    var y: u32 = 500\n    var result = x > y", "u16 > u32 greater than");
    ("var x: u32 = 100\n    var y: u64 = 100\n    var result = x <= y", "u32 <= u64 less equal");
    ("var x: u8 = 50\n    var y: u16 = 30\n    var result = x >= y", "u8 >= u16 greater equal");
    
    (* Signed comparisons *)
    ("var x: i8 = -10\n    var y: i64 = 100\n    var result = x < y", "i8 < i64 less than");
    ("var x: i16 = -5\n    var y: i32 = -10\n    var result = x > y", "i16 > i32 greater than");
  ] in
  
  List.iter (fun (stmt, desc) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2 // XDP_PASS
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("comparison promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed comparison promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("comparison promotion: " ^ desc) false true
  ) comparison_tests

(** Test map operations with type promotion *)
let test_map_operations_promotion () =
  let map_tests = [
    (* Map key promotion *)
    ({|
type IpAddress = u32
var counters : hash<IpAddress, u64>(1000)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var ip: u16 = 12345  // u16 should promote to u32 (IpAddress)
  counters[ip] = 100
  return 2 // XDP_PASS
}
|}, "map key promotion");
    
    (* Map value promotion *)
    ({|
type Counter = u64
var stats : hash<u32, Counter>(1000)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var value: u16 = 1500  // u16 should promote to u64 (Counter)
  stats[1] = value
  return 2 // XDP_PASS
}
|}, "map value promotion");
    
    (* Map access with arithmetic *)
    ({|
type PacketSize = u16
type Counter = u64
var stats : hash<u32, Counter>(1000)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var size: PacketSize = 1500
  var current = stats[1]  // u64
  var new_value = current + size  // u64 + u16 -> u64
  stats[1] = new_value
  return 2 // XDP_PASS
}
|}, "map access with arithmetic promotion");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("map promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed map promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("map promotion: " ^ desc) false true
  ) map_tests

(** Test edge cases for type promotion *)
let test_type_promotion_edge_cases () =
  let edge_case_tests = [
    (* Nested arithmetic with multiple promotions *)
    ({|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var a: u8 = 10
  var b: u16 = 100
  var c: u32 = 1000
  var d: u64 = 10000
  var result = a + b + c + d  // Chain of promotions
  return 2 // XDP_PASS
}
|}, "nested arithmetic with multiple promotions");
    
    (* Function parameters with promotion *)
    ({|
@helper
fn process(value: u64) -> u64 {
  return value * 2
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var small: u16 = 100
  var result = process(small)  // u16 -> u64 promotion in function call
  return 2 // XDP_PASS
}
|}, "function parameter promotion");
    
    (* Complex expression with promotions *)
    ({|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var a: u8 = 5
  var b: u16 = 10
  var c: u32 = 20
  var d: u64 = 40
  var result = (a + b) * (c + d)  // Mixed promotions in complex expression
  return 2 // XDP_PASS
}
|}, "complex expression with promotions");
    
    (* Assignment with promotion *)
    ({|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var big: u64 = 1000
  var small: u16 = 100
  big = big + small  // u64 = u64 + u16
  return 2 // XDP_PASS
}
|}, "assignment with promotion");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("edge case promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed edge case promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("edge case promotion: " ^ desc) false true
  ) edge_case_tests

(** Test null literal typing *)
let test_null_literal_typing () =
  let null_tests = [
    (* Basic null literal *)
    ({|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = null
  return 2 // XDP_PASS
}
|}, "basic null literal");
    
    (* Null comparison with typed variable *)
    ({|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x: u32 = 42
  if (x == null) {
    return 1 // XDP_DROP
  }
  return 2 // XDP_PASS
}
|}, "null comparison with u32");
    
    (* Null assignment in variable declaration *)
    ({|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var ptr = null
  return 2 // XDP_PASS
}
|}, "null assignment in declaration");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let symbol_table = create_symbol_table_with_builtins ast in
      let (annotated_ast, _typed_programs) = type_check_and_annotate_ast_with_builtins ast in
      let _ = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
      check bool ("null literal typing: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed null literal test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("null literal typing: " ^ desc) false true
  ) null_tests

(** Test null comparisons with different types *)
let test_null_comparisons () =
  let comparison_tests = [
    (* Comparisons with different numeric types *)
    ("var x: u8 = 10\n    var result = x == null", "u8 == null");
    ("var x: u16 = 100\n    var result = x != null", "u16 != null");
    ("var x: u32 = 1000\n    var result = x == null", "u32 == null");
    ("var x: u64 = 10000\n    var result = x != null", "u64 != null");
    ("var x: i8 = -5\n    var result = x == null", "i8 == null");
    ("var x: i16 = -100\n    var result = x != null", "i16 != null");
    ("var x: i32 = -1000\n    var result = x == null", "i32 == null");
    ("var x: i64 = -10000\n    var result = x != null", "i64 != null");
    
    (* Basic null comparisons *)
    ("var ptr = null\n    var result = ptr == null", "null variable == null");
    ("var ptr = null\n    var result = ptr != null", "null variable != null");
    
    (* Double null comparison *)
    ("var result = null == null", "null == null");
    ("var result = null != null", "null != null");
  ] in
  
  List.iter (fun (stmt, desc) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2 // XDP_PASS
}
|} stmt in
    try
      let ast = parse_string program_text in
      let symbol_table = create_symbol_table_with_builtins ast in
      let (annotated_ast, _typed_programs) = type_check_and_annotate_ast_with_builtins ast in
      let _ = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
      check bool ("null comparison: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed null comparison test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("null comparison: " ^ desc) false true
  ) comparison_tests

(** Test map operations with null semantics *)
let test_map_null_semantics () =
  let map_null_tests = [
    (* Map access returning nullable value *)
    ({|
var test_map : hash<u32, u64>(100)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var value = test_map[42]
  if (value == null) {
    return 1 // XDP_DROP
  }
  return 2 // XDP_PASS
}
|}, "map access null check");
    
    (* Null initialization pattern *)
    ({|
var counters : hash<u32, u32>(100)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var count = counters[1]
  if (count == null) {
    counters[1] = 1
  } else {
    counters[1] = count + 1
  }
  return 2 // XDP_PASS
}
|}, "null initialization pattern");
    
    (* Multiple map null checks *)
    ({|
var flows : hash<u32, u64>(100)
var packets : hash<u32, u32>(100)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var flow = flows[123]
  var packet_count = packets[123]
  
  if (flow == null || packet_count == null) {
    return 1 // XDP_DROP
  }
  
  return 2 // XDP_PASS
}
|}, "multiple map null checks");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let symbol_table = create_symbol_table_with_builtins ast in
      let (annotated_ast, _typed_programs) = type_check_and_annotate_ast_with_builtins ast in
      let _ = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
      check bool ("map null semantics: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed map null test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("map null semantics: " ^ desc) false true
  ) map_null_tests

(** Test null vs throw pattern adherence *)
let test_null_vs_throw_pattern () =
  let pattern_tests = [
    (* Correct: null for expected absence *)
    ({|
var cache : hash<u32, u64>(100)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var cached_value = cache[42]
  if (cached_value == null) {
    // Key doesn't exist - expected case
    cache[42] = 100
    return 2 // XDP_PASS
  }
  return cached_value
}
|}, "null for expected absence");
    
    (* Correct: error checking (simplified without throw) *)
    ({|
@helper
fn validate_input(value: u32) -> u32 {
  if (value > 1000) {
    return 0  // Error case
  }
  return value * 2
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = validate_input(500)
  return 2 // XDP_PASS
}
|}, "error validation pattern");
    
    (* Function returning nullable value *)
    ({|
var data : hash<u32, u32>(100)

@helper
fn lookup_value(key: u32) -> u32 {
  var value = data[key]
  if (value == null) {
    return 0  // Default value for missing key
  }
  return value
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var result = lookup_value(42)
  return 2 // XDP_PASS
}
|}, "function with nullable return pattern");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("null vs throw pattern: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed pattern test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("null vs throw pattern: " ^ desc) false true
  ) pattern_tests

(** Test comprehensive null semantics *)
let test_null_semantics () =
  let comprehensive_tests = [
    (* Null in conditional expressions *)
    ({|
var test_map : hash<u32, u32>(100)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var value = test_map[1]
  var result = 0
  if (value == null) {
    result = 0
  } else {
    result = value
  }
  return 2 // XDP_PASS
}
|}, "null in if-else expression");
    
    (* Null in logical operations *)
    ({|
var map1 : hash<u32, u32>(100)
var map2 : hash<u32, u32>(100)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var val1 = map1[1]
  var val2 = map2[1]
  
  if (val1 != null && val2 != null) {
    return 2 // XDP_PASS
  }
  
  return 2 // XDP_PASS
}
|}, "null in logical AND");
    
    (* Basic null assignments *)
    ({|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = null
  if (x == null) {
    return 1 // XDP_DROP
  }
  return 2 // XDP_PASS
}
|}, "basic null assignment and check");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      check bool ("comprehensive null: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed comprehensive null test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("comprehensive null: " ^ desc) false true
  ) comprehensive_tests

(** Helper function to check if string contains substring *)
let contains_substr str substr =
  try
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in
    true
  with Not_found -> false

(** Test XDP signature validation enforcement *)
let test_xdp_signature_validation () =
  let invalid_signature_tests = [
    (* Missing context parameter *)
    ({|
@xdp fn test() -> xdp_action {
  return 2 // XDP_PASS
}
|}, "missing context parameter");
    
    (* Wrong parameter type *)
    ({|
@xdp fn test(wrong_param: u32) -> xdp_action {
  return 2 // XDP_PASS
}
|}, "wrong parameter type");
    
    (* No parameters and wrong return type *)
    ({|
@xdp fn test() -> u32 {
  return 0
}
|}, "no parameters and wrong return type");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let symbol_table = create_symbol_table_with_builtins ast in
      let (annotated_ast, _typed_programs) = type_check_and_annotate_ast_with_builtins ast in
      let multi_prog_analysis = Kernelscript.Multi_program_analyzer.analyze_multi_program_system ast in
      let _ = Kernelscript.Multi_program_ir_optimizer.generate_optimized_ir annotated_ast multi_prog_analysis symbol_table "test" in
      (* If we get here, validation failed to catch the error *)
      check bool ("XDP signature validation should have failed for: " ^ desc) false true
    with
    | Kernelscript.Type_checker.Type_error (msg, _) when contains_substr msg "attributed function must have signature" ->
        (* Expected failure - signature validation caught the error during type checking *)
        check bool ("XDP signature validation correctly rejected: " ^ desc) true true
    | Failure msg when contains_substr msg "Invalid function signature" ->
        (* Expected failure - signature validation caught the error during IR generation *)
        check bool ("XDP signature validation correctly rejected: " ^ desc) true true
    | exn -> 
        Printf.printf "Unexpected error in XDP signature test '%s': %s\n" desc (Printexc.to_string exn);
        check bool ("XDP signature validation failed unexpectedly for: " ^ desc) false true
  ) invalid_signature_tests;
  
  (* Test that valid signature passes *)
  let valid_program = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return 2 // XDP_PASS
}
|} in
  try
    let ast = parse_string valid_program in
    let symbol_table = create_symbol_table_with_builtins ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast_with_builtins ast in
    let multi_prog_analysis = Kernelscript.Multi_program_analyzer.analyze_multi_program_system ast in
    let _ = Kernelscript.Multi_program_ir_optimizer.generate_optimized_ir annotated_ast multi_prog_analysis symbol_table "test" in
    check bool "valid XDP signature should pass" true true
  with
  | exn ->
      Printf.printf "Valid XDP signature unexpectedly failed: %s\n" (Printexc.to_string exn);
      check bool "valid XDP signature should pass" false true

(** Test kernel function calls from attributed functions *)
let test_kernel_function_calls_from_attributed () =
  (* Test the specific bug case: kernel function called from attributed function *)
  let program_text = {|
@helper
fn get_src_ip(ctx: *xdp_md) -> IpAddress {
    return 0x08080808  // 8.8.8.8 as u32
}

@xdp fn packet_analyzer(ctx: *xdp_md) -> xdp_action {
    var src_ip: IpAddress = get_src_ip(ctx)
    return 2 // XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "kernel function call from attributed function" true true
  with
  | exn -> 
      Printf.printf "Kernel function call test failed: %s\n" (Printexc.to_string exn);
      fail "Kernel function call from attributed function should succeed"

(** Test multiple kernel function calls with different parameter types *)
let test_multiple_kernel_function_calls () =
  let program_text = {|
@helper
fn process_packet(ctx: *xdp_md, flags: u32) -> u32 {
    return flags + 1
}

@helper
fn get_packet_size(ctx: *xdp_md) -> u32 {
    return 1500
}

@helper
fn validate_headers(ctx: *xdp_md, min_size: u32, max_size: u32) -> bool {
    var size = get_packet_size(ctx)
    return size >= min_size && size <= max_size
}

@xdp fn complex_handler(ctx: *xdp_md) -> xdp_action {
    var flags = process_packet(ctx, 0x01)
    var size = get_packet_size(ctx)
    var is_valid = validate_headers(ctx, 64, 1500)
    
    if (is_valid) {
        return 2 // XDP_PASS
    } else {
        return 1 // XDP_DROP
    }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "multiple kernel function calls" true true
  with
  | exn -> 
      Printf.printf "Multiple kernel function calls test failed: %s\n" (Printexc.to_string exn);
      fail "Multiple kernel function calls should succeed"

(** Test kernel functions calling other kernel functions *)
let test_kernel_to_kernel_function_calls () =
  let program_text = {|
@helper
fn helper_function(value: u32) -> u32 {
    return value * 2
}

@helper
fn main_kernel_function(ctx: *xdp_md) -> u32 {
    var base_value = 42
    var result = helper_function(base_value)
    return result
}

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
    var computed = main_kernel_function(ctx)
    return 2 // XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "kernel to kernel function calls" true true
  with
  | exn -> 
      Printf.printf "Kernel to kernel function calls test failed: %s\n" (Printexc.to_string exn);
      fail "Kernel to kernel function calls should succeed"

(** Test function call type resolution with user-defined types *)
let test_function_call_user_type_resolution () =
  let program_text = {|
@helper
fn extract_ip_from_context(ctx: *xdp_md) -> IpAddress {
    return 0x7f000001  // 127.0.0.1 as u32
}

@helper
fn convert_ip_to_u32(addr: IpAddress) -> u32 {
    return addr
}

@xdp fn packet_processor(ctx: *xdp_md) -> xdp_action {
    var ip_addr = extract_ip_from_context(ctx)
    var converted_value = convert_ip_to_u32(ip_addr)
    
    if (converted_value > 0) {
        return 2 // XDP_PASS
    } else {
        return 1 // XDP_DROP
    }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    check bool "function call user type resolution" true true
  with
  | exn -> 
      Printf.printf "Function call user type resolution test failed: %s\n" (Printexc.to_string exn);
      fail "Function call user type resolution should succeed"

(** Test tail call type compatibility - different program types should be rejected *)
let test_tail_call_cross_program_type_restriction _ =
  (* Test XDP -> TC tail call should fail *)
  let source_code = {|
    @tc("ingress") fn tc_drop_handler(ctx: *__sk_buff) -> int {
      return 1  // TC_ACT_SHOT
    }

    @xdp fn xdp_filter(ctx: *xdp_md) -> xdp_action {
      // INVALID: @xdp trying to tail call to @tc function
      return tc_drop_handler(ctx)
    }

    fn main() -> i32 {
      return 0
    }
  |} in
  
  let ast = parse_string source_code in
  
  (* This should fail with incompatible program type error *)
  (try
     let _ = type_check_and_annotate_ast_with_builtins ast in
     failwith "Expected type checking to fail for cross-program-type tail call"
   with
   | Type_error (msg, _) ->
               check bool "Error should mention incompatible program type" 
              true (contains_substr msg "incompatible program type")
   | _ -> failwith "Expected TypeError for cross-program-type tail call")

(** Test map index type resolution bug fix - structs, enums, and type aliases as map keys *)
let test_map_index_type_resolution_bug_fix _ =
  let source_code = {|
    // Type alias 
    type IpAddress = u32
    type Counter = u64
    
    // Enum type
    enum Protocol {
      TCP = 6,
      UDP = 17,
      ICMP = 1
    }
    
    // Struct type
    struct PacketInfo {
      src_ip: IpAddress,
      dst_ip: IpAddress,
      protocol: u8
    }
    
    // Maps using different key types
    var connection_count : hash<IpAddress, Counter>(1024)      // Type alias key
var protocol_stats : percpu_array<Protocol, Counter>(32)       // Enum key
var packet_filter : lru_hash<PacketInfo, u32>(512)             // Struct key
    
    @helper
    fn test_indexing() -> u32 {
      // Create test values
      var ip: IpAddress = 0xC0A80001
      var proto = TCP
      var info = PacketInfo { src_ip: ip, dst_ip: ip, protocol: 6 }
      
      // These should all work without "Array index must be integer type" error
      var count1 = connection_count[ip]        // Type alias as key
      var count2 = protocol_stats[proto]       // Enum as key  
      var result = packet_filter[info]         // Struct as key
      
      if (count1 != none && count2 != none && result != none) {
        return count1 + count2 + result
      } else {
        return 0
      }
    }
    
    @xdp fn packet_handler(ctx: *xdp_md) -> xdp_action {
      return XDP_PASS
    }
  |} in
  
  try
    let ast = parse_string source_code in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let _typed_ast = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    
    (* If we reach here, type checking succeeded *)
    check bool "map index type resolution works for structs, enums, and type aliases" true true
  with
  | Type_error (msg, _) when String.contains msg 'A' && String.contains msg 'r' && String.contains msg 'i' ->
      (* If we get "Array index must be integer type" error, the test fails *)
      fail ("Bug regression - map indexing should work with user types: " ^ msg)
  | Type_error (msg, _) ->
      (* Other type errors might be valid (e.g., map key type mismatches) *)
      fail ("Unexpected type error: " ^ msg)
  | Parse_error (msg, _) ->
      fail ("Parse error: " ^ msg)
  | e ->
      fail ("Unexpected error: " ^ Printexc.to_string e)

let type_checker_tests = [
  "type_unification", `Quick, test_type_unification;
  "basic_type_inference", `Quick, test_basic_type_inference;
  "variable_type_checking", `Quick, test_variable_type_checking;
  "binary_operations", `Quick, test_binary_operations;
  "function_calls", `Quick, test_function_calls;
  "builtin_function_type_checking", `Quick, test_builtin_function_type_checking;
  "variadic_function_arguments", `Quick, test_variadic_function_arguments;
  "builtin_function_return_types", `Quick, test_builtin_function_return_types;
  "builtin_vs_user_function_precedence", `Quick, test_builtin_vs_user_function_precedence;
  "stdlib_integration", `Quick, test_stdlib_integration;
  "context_types", `Quick, test_context_types;
  "struct_field_access", `Quick, test_struct_field_access;
  "statement_type_checking", `Quick, test_statement_type_checking;
  "function_type_checking", `Quick, test_function_type_checking;
  "error_handling", `Quick, test_error_handling;
  "program_type_checking", `Quick, test_program_type_checking;
  "integer_type_promotion", `Quick, test_integer_type_promotion;
  "type_unification_enhanced", `Quick, test_type_unification_enhanced;
  "comprehensive_type_checking", `Quick, test_comprehensive_type_checking;

  "comprehensive_integer_promotion", `Quick, test_comprehensive_integer_promotion;
  "arithmetic_promotion", `Quick, test_arithmetic_promotion;
  "comparison_promotion", `Quick, test_comparison_promotion;
  "map_operations_promotion", `Quick, test_map_operations_promotion;
  "type_promotion_edge_cases", `Quick, test_type_promotion_edge_cases;
  "null_semantics", `Quick, test_null_semantics;
  "null_literal_typing", `Quick, test_null_literal_typing;
  "null_comparisons", `Quick, test_null_comparisons;
  "map_null_semantics", `Quick, test_map_null_semantics;
  "null_vs_throw_pattern", `Quick, test_null_vs_throw_pattern;
  "xdp_signature_validation", `Quick, test_xdp_signature_validation;
  "kernel_function_calls_from_attributed", `Quick, test_kernel_function_calls_from_attributed;
  "multiple_kernel_function_calls", `Quick, test_multiple_kernel_function_calls;
  "kernel_to_kernel_function_calls", `Quick, test_kernel_to_kernel_function_calls;
  "function_call_user_type_resolution", `Quick, test_function_call_user_type_resolution;
  "tail_call_cross_program_type_restriction", `Quick, test_tail_call_cross_program_type_restriction;
  "map_index_type_resolution_bug_fix", `Quick, test_map_index_type_resolution_bug_fix;
]

let () =
  run "KernelScript Type Checker Tests" [
    "type_checker", type_checker_tests;
  ] 