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

(** Helper: type-check a program and extract function body *)
let type_check_and_get_body program_text =
  let ast = parse_string program_text in
  let typed_ast = type_check_ast ast in
  match typed_ast with
  | [AttributedFunction af] -> af.attr_function.func_body
  | _ -> Alcotest.fail "expected single attributed function"

let body_has_for body =
  List.exists (fun s -> match s.stmt_desc with For _ -> true | _ -> false) body

(** Test for loop with constant bounds *)
let test_for_constant_bounds () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 0..5) {
    var x = i * 2
  }
  return 2
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with variable bounds *)
let test_for_variable_bounds () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var start = 1
  var endval = 10
  for (i in start..endval) {
    var x = i
  }
  return 2
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with empty body *)
let test_for_empty_body () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 1..10) {
  }
  return 0
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with single iteration (same bounds) *)
let test_for_single_iteration () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 5..5) {
    var y = 42
  }
  return 0
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with simple arithmetic *)
let test_for_simple_arithmetic () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 1..3) {
    var temp = i * 2
  }
  return 1
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with break statement *)
let test_for_with_break () =
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
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with continue statement *)
let test_for_with_continue () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 0..10) {
    if (i % 2 == 0) {
      continue
    }
    var x = i
  }
  return 2
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with complex expressions in bounds *)
let test_for_complex_bounds () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var base = 5
  var multiplier = 2
  for (i in (base - 1)..(base + multiplier)) {
    var result = i * base
  }
  return 2
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with different integer types *)
let test_for_different_integer_types () =
  let test_cases = [
    ("u8", "u8");
    ("u16", "u16"); 
    ("u32", "u32");
    ("u64", "u64");
    (* Skip signed integer types as they might have different literal parsing rules *)
  ] in
  
  List.iter (fun (type_name, _) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var start: %s = 1
  var end_val: %s = 5
  for (i in start..end_val) {
    var x = i
  }
  return 2
}
|} type_name type_name in
    let body = type_check_and_get_body program_text in
    check bool (type_name ^ " bounds has for stmt") true (body_has_for body)
  ) test_cases

(** Test for loop with large bounds *)
let test_for_large_bounds () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 0..1000000) {
    var large = i
  }
  return 2
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop with reverse bounds (start > end) *)
let test_for_reverse_bounds () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  for (i in 10..5) {
    var never_executed = i
  }
  return 2
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop variable scoping *)
let test_for_variable_scoping () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var i = 100
  for (i in 0..5) {
    var x = i * 2
  }
  var after_loop = i
  return 2
}
|} in
  let body = type_check_and_get_body program_text in
  check bool "body contains for stmt" true (body_has_for body)

(** Test for loop in global functions *)
let test_for_in_global_function () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn helper() -> u32 {
  for (i in 1..3) {
    var helper_var = i + 10
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  let ast = parse_string program_text in
  let typed_ast = type_check_ast ast in
  check int "decl count" 3 (List.length typed_ast);
  let helper_body = List.find_map (fun d -> match d with
    | GlobalFunction f when f.func_name = "helper" -> Some f.func_body
    | _ -> None) typed_ast in
  check bool "helper body has for stmt" true (body_has_for (Option.get helper_body))

(** Test error cases for for statements *)
let test_for_error_cases () =
  let error_cases = [
    (* Invalid range syntax *)
    ("for i in 0...5 { }", "should reject triple-dot syntax");
    
    (* Missing range operator *)
    ("for i in 0 5 { }", "should require .. range operator");
  ] in
  
  List.iter (fun (code, desc) ->
    let full_program = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 0
}
|} code in
    (try
      let _ = parse_string full_program in
      fail ("Should have failed: " ^ desc)
    with
    | Parse_error _ | Type_error _ -> ()
    | e -> fail ("Expected parse or type error for: " ^ desc ^ ", got: " ^ Printexc.to_string e))
  ) error_cases

let for_statement_tests = [
  "for_constant_bounds", `Quick, test_for_constant_bounds;
  "for_variable_bounds", `Quick, test_for_variable_bounds;
  "for_empty_body", `Quick, test_for_empty_body;
  "for_single_iteration", `Quick, test_for_single_iteration;
  "for_simple_arithmetic", `Quick, test_for_simple_arithmetic;
  "for_with_break", `Quick, test_for_with_break;
  "for_with_continue", `Quick, test_for_with_continue;
  "for_complex_bounds", `Quick, test_for_complex_bounds;
  "for_different_integer_types", `Quick, test_for_different_integer_types;
  "for_large_bounds", `Quick, test_for_large_bounds;
  "for_reverse_bounds", `Quick, test_for_reverse_bounds;
  "for_variable_scoping", `Quick, test_for_variable_scoping;
  "for_in_global_function", `Quick, test_for_in_global_function;
  "for_error_cases", `Quick, test_for_error_cases;
]

let () =
  run "KernelScript For Statement Tests" [
    "for_statements", for_statement_tests;
  ] 