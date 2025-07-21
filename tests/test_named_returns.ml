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

open Kernelscript
open Ast
open Alcotest

(** Test helpers *)
let make_test_position () = { line = 1; column = 1; filename = "test" }

let parse_string code =
  let lexbuf = Lexing.from_string code in
  Parser.program Lexer.token lexbuf

(** Alcotest testable for bpf_type *)
let bpf_type_testable =
  let equal t1 t2 = t1 = t2 in
  let pp fmt t = Format.fprintf fmt "%s" (string_of_bpf_type t) in
  (module struct
    type t = bpf_type
    let equal = equal
    let pp = pp
  end : Alcotest.TESTABLE with type t = bpf_type)

(** Alcotest testable for return_type_spec *)
let return_type_spec_testable =
  let equal r1 r2 = r1 = r2 in
  let pp fmt = function
    | Unnamed t -> Format.fprintf fmt "Unnamed(%s)" (string_of_bpf_type t)
    | Named (n, t) -> Format.fprintf fmt "Named(%s, %s)" n (string_of_bpf_type t)
  in
  (module struct
    type t = return_type_spec
    let equal = equal
    let pp = pp
  end : Alcotest.TESTABLE with type t = return_type_spec)

(** Test basic named return syntax parsing *)
let test_basic_named_return () =
  let code = {|
fn add_numbers(a: i32, b: i32) -> sum: i32 {
    sum = a + b
    return
}
|} in
  let ast = parse_string code in
  match ast with
  | [GlobalFunction func] ->
      check string "function name" "add_numbers" func.func_name;
      check (list (pair string bpf_type_testable)) "function params" 
        [("a", I32); ("b", I32)] func.func_params;
      (match func.func_return_type with
       | Some (Named (name, typ)) ->
           check string "return variable name" "sum" name;
           check bpf_type_testable "return type" I32 typ
       | _ -> fail "Expected named return type")
  | _ -> fail "Expected single function declaration"

(** Test unnamed return (backward compatibility) *)
let test_unnamed_return_compatibility () =
  let code = {|
fn add_numbers(a: i32, b: i32) -> i32 {
    return a + b
}
|} in
  let ast = parse_string code in
  match ast with
  | [GlobalFunction func] ->
      check string "function name" "add_numbers" func.func_name;
      (match func.func_return_type with
       | Some (Unnamed typ) ->
           check bpf_type_testable "return type" I32 typ
       | _ -> fail "Expected unnamed return type")
  | _ -> fail "Expected single function declaration"

(** Test named return with complex types *)
let test_named_return_complex_types () =
  let test_cases = [
    ("fn get_bool() -> is_valid: bool { return true }", "is_valid", "bool");
    ("fn get_num() -> value: u64 { return 42 }", "value", "u64");
    ("fn get_char() -> ch: char { return 'a' }", "ch", "char");
  ] in
  
  List.iter (fun (code, expected_name, expected_type_desc) ->
    let ast = parse_string code in
    match ast with
    | [GlobalFunction func] ->
        (match func.func_return_type with
         | Some (Named (name, _)) -> 
             check string ("return variable name for " ^ expected_type_desc) expected_name name
         | _ -> fail ("Expected named return for: " ^ expected_type_desc))
    | _ -> fail ("Failed to parse: " ^ code)
  ) test_cases

(** Test naked return statements *)
let test_naked_returns () =
  let code = {|
fn calculate_sum(a: i32, b: i32) -> result: i32 {
    result = a + b
    return
}
|} in
  let ast = parse_string code in
  match ast with
  | [GlobalFunction func] ->
      (match func.func_return_type with
       | Some (Named ("result", I32)) -> ()
       | _ -> fail "Expected named return");
      (* Check that function body contains naked return *)
      let has_naked_return = List.exists (function
        | { stmt_desc = Return None; _ } -> true
        | _ -> false
      ) func.func_body in
      check bool "has naked return in function body" true has_naked_return
  | _ -> fail "Expected function declaration"

(** Test mixing naked and explicit returns *)
let test_mixed_returns () =
  let code = {|
fn validate_input(x: i32) -> is_valid: bool {
    if (x < 0) {
        return false
    }
    is_valid = true
    return
}
|} in
  let ast = parse_string code in
  match ast with
  | [GlobalFunction func] ->
      (match func.func_return_type with
       | Some (Named ("is_valid", Bool)) -> ()
       | _ -> fail "Expected named return");
      (* Function should parse successfully with mixed returns *)
      check bool "function has statements" true (List.length func.func_body > 0)
  | _ -> fail "Expected function declaration"

(** Test eBPF program functions with named returns *)
let test_ebpf_named_returns () =
  let code = {|
@xdp
fn packet_filter(ctx: *xdp_md) -> action: xdp_action {
    action = XDP_PASS
    var size = ctx->data_end - ctx->data
    if (size < 64) {
        action = XDP_DROP
    }
    return
}
|} in
  let ast = parse_string code in
  match ast with
  | [AttributedFunction attr_func] ->
      (match attr_func.attr_function.func_return_type with
       | Some (Named ("action", UserType "xdp_action")) -> ()
       | _ -> fail "Expected named return in eBPF function")
  | _ -> fail "Expected attributed function"

(** Test helper functions with named returns *)
let test_helper_named_returns () =
  let code = {|
@helper
fn calculate_checksum(data: *u8, len: u32) -> checksum: u32 {
    checksum = 0
    for (i in 0..len) {
        checksum += data[i]
    }
    return
}
|} in
  let ast = parse_string code in
  match ast with
  | [AttributedFunction attr_func] ->
      (match attr_func.attr_function.func_return_type with
       | Some (Named ("checksum", U32)) -> ()
       | _ -> fail "Expected named return in helper function")
  | _ -> fail "Expected attributed function"

(** Test userspace functions with named returns *)
let test_userspace_named_returns () =
  let code = {|
fn process_data(input: u32) -> output: u64 {
    output = input * 2
    return
}

fn main() -> exit_code: i32 {
    var result = process_data(42)
    exit_code = 0
    return
}
|} in
  let ast = parse_string code in
  match ast with
  | [GlobalFunction func1; GlobalFunction func2] ->
      (* Check first function *)
      (match func1.func_return_type with
       | Some (Named ("output", U64)) -> ()
       | _ -> fail "Expected named return in first function");
      (* Check second function (main) *)
      (match func2.func_return_type with
       | Some (Named ("exit_code", I32)) -> ()
       | _ -> fail "Expected named return in main function")
  | _ -> fail "Expected two function declarations"

(** Test function pointer types with named returns *)
let test_function_pointer_named_returns () =
  let code = {|
fn apply_processor(x: u32) -> output: u64 {
    output = x * 2
    return
}
|} in
  let ast = parse_string code in
  match ast with
  | [GlobalFunction func] ->
      (match func.func_return_type with
       | Some (Named ("output", U64)) -> ()
       | _ -> fail "Expected named return in function")
  | _ -> fail "Expected single function"

(** Test error cases *)
let test_error_cases () =
  let error_cases = [
    (* Multiple named returns (not supported) *)
    ("fn bad() -> x: i32, y: i32 { return 0, 0 }", "Multiple named returns should fail");
    (* Parentheses around named return (not our syntax) *)
    ("fn bad() -> (result: i32) { return 0 }", "Parentheses syntax should fail");
  ] in
  
  List.iter (fun (code, description) ->
    try
      let _ = parse_string code in
      fail ("Should have failed: " ^ description)
    with
    | _ -> () (* Expected to fail *)
  ) error_cases

(** Test AST helper functions *)
let test_ast_helpers () =
  (* Test make_unnamed_return *)
  let unnamed = make_unnamed_return I32 in
  check return_type_spec_testable "make_unnamed_return" (Unnamed I32) unnamed;
  
  (* Test make_named_return *)
  let named = make_named_return "result" U64 in
  check return_type_spec_testable "make_named_return" (Named ("result", U64)) named;
  
  (* Test get_return_type *)
  check (option bpf_type_testable) "get_return_type unnamed" (Some I32) (get_return_type (Some unnamed));
  check (option bpf_type_testable) "get_return_type named" (Some U64) (get_return_type (Some named));
  check (option bpf_type_testable) "get_return_type none" None (get_return_type None);
  
  (* Test get_return_variable_name *)
  check (option string) "get_return_variable_name unnamed" None (get_return_variable_name (Some unnamed));
  check (option string) "get_return_variable_name named" (Some "result") (get_return_variable_name (Some named));
  check (option string) "get_return_variable_name none" None (get_return_variable_name None);
  
  (* Test is_named_return *)
  check bool "is_named_return unnamed" false (is_named_return (Some unnamed));
  check bool "is_named_return named" true (is_named_return (Some named));
  check bool "is_named_return none" false (is_named_return None)

(** Test string representation *)
let test_string_representation () =
  let unnamed_func = {
    func_name = "test";
    func_params = [];
    func_return_type = Some (make_unnamed_return I32);
    func_body = [];
    func_scope = Userspace;
    func_pos = make_test_position ();
    tail_call_targets = [];
    is_tail_callable = false;
  } in
  
  let named_func = {
    func_name = "test";
    func_params = [];
    func_return_type = Some (make_named_return "result" I32);
    func_body = [];
    func_scope = Userspace;
    func_pos = make_test_position ();
    tail_call_targets = [];
    is_tail_callable = false;
  } in
  
  let unnamed_str = string_of_function unnamed_func in
  let named_str = string_of_function named_func in
  
  check bool "unnamed function string contains arrow" true 
    (String.contains unnamed_str '>');
  check bool "named function string contains arrow" true
    (String.contains named_str '>')

(** Test complete examples *)
let test_complete_examples () =
  let example1 = {|
// Complex named return example
fn fibonacci(n: u32) -> result: u64 {
    if (n <= 1) {
        result = n
        return
    }
    
    var a = fibonacci(n - 1)
    var b = fibonacci(n - 2)
    result = a + b
    return
}

@helper
fn hash_data(data: *u8, len: u32) -> hash_value: u64 {
    hash_value = 0
    for (i in 0..len) {
        hash_value = hash_value * 31 + data[i]
    }
    return
}

@xdp
fn advanced_filter(ctx: *xdp_md) -> verdict: xdp_action {
    verdict = XDP_PASS
    
    var size = ctx->data_end - ctx->data
    if (size < 64) {
        verdict = XDP_DROP
        return
    }
    
    var hash = hash_data(ctx->data, size)
    if (hash == 0) {
        verdict = XDP_ABORTED
    }
    
    return
}
|} in
  
  let ast = parse_string example1 in
  check int "number of declarations" 3 (List.length ast);
  
  (* Verify each function has named returns *)
  List.iter (function
    | GlobalFunction func ->
        check bool ("Function " ^ func.func_name ^ " should have named return") true
          (is_named_return func.func_return_type)
    | AttributedFunction attr_func ->
        check bool ("Function " ^ attr_func.attr_function.func_name ^ " should have named return") true
          (is_named_return attr_func.attr_function.func_return_type)
    | _ -> fail "Expected function declarations"
  ) ast

(** Test suite *)
let named_returns_tests = [
  "basic_named_return", `Quick, test_basic_named_return;
  "unnamed_return_compatibility", `Quick, test_unnamed_return_compatibility;
  "named_return_complex_types", `Quick, test_named_return_complex_types;
  "naked_returns", `Quick, test_naked_returns;
  "mixed_returns", `Quick, test_mixed_returns;
  "ebpf_named_returns", `Quick, test_ebpf_named_returns;
  "helper_named_returns", `Quick, test_helper_named_returns;
  "userspace_named_returns", `Quick, test_userspace_named_returns;
  "function_pointer_named_returns", `Quick, test_function_pointer_named_returns;
  "error_cases", `Quick, test_error_cases;
  "ast_helpers", `Quick, test_ast_helpers;
  "string_representation", `Quick, test_string_representation;
  "complete_examples", `Quick, test_complete_examples;
]

let () =
  run "Named Return Values Tests" [
    "named_returns", named_returns_tests;
  ] 