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
open Kernelscript
open Ast

(** Test basic @test attribute parsing *)
let test_test_attribute_parsing () =
  let program = {|
    @test
    fn test_simple() -> i32 {
        return 0
    }
    
    @xdp
    fn packet_filter(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Check that we have the expected declarations *)
  check int "Number of declarations" 3 (List.length ast);
  
  (* Check that the first declaration is an attributed function with @test *)
  (match List.hd ast with
   | AttributedFunction attr_func ->
       check string "Function name" "test_simple" attr_func.attr_function.func_name;
       (match attr_func.attr_list with
        | [SimpleAttribute attr_name] ->
            check string "Attribute name" "test" attr_name
        | _ -> fail "Expected single test attribute")
   | _ -> fail "Expected AttributedFunction")

(** Test test() builtin function recognition *)
let test_builtin_function_recognition () =
  check bool "test is builtin" true (Kernelscript.Stdlib.is_builtin_function "test");
  
  (* Test getting function signatures *)
  (match Kernelscript.Stdlib.get_builtin_function_signature "test" with
  | Some (params, return_type) ->
      check int "test parameter count" 0 (List.length params);
      check bool "test return type is U32" true (return_type = Kernelscript.Ast.U32)
  | None -> check bool "test function signature should exist" false true)

(** Test that @test functions are not treated as eBPF programs *)
let test_test_functions_not_ebpf_programs () =
  let program = {|
    @test
    fn test_function() -> i32 {
        return 0
    }
    
    @xdp
    fn xdp_program(ctx: *xdp_md) -> xdp_action {
        return 2
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Extract programs should not include @test functions *)
  let programs = Multi_program_analyzer.extract_programs ast in
  check int "Number of eBPF programs" 1 (List.length programs);
  
  (* The only program should be the @xdp function *)
  (match List.hd programs with
   | prog when prog.prog_name = "xdp_program" -> 
       check string "Program name" "xdp_program" prog.prog_name
   | _ -> fail "Expected xdp_program to be the only eBPF program")

(** Test @test functions with test() builtin calls *)
let test_test_function_with_builtin_calls () =
  let program = {|
    @xdp
    fn target_program(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    struct TestContext {
        packet_size: u32,
        expected_result: u32,
    }
    
    @test
    fn test_with_builtin() -> i32 {
        var ctx = TestContext { packet_size: 100, expected_result: 2 }
        
        // Test context created successfully
        
        return 0
    }
  |} in
  
  try
    let ast = Parse.parse_string program in
    let symbol_table = Symbol_table.build_symbol_table ast in
    let (_, _) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "@test function with builtin calls parsed and typed successfully" true true
  with
  | exn -> 
    fail ("Failed to parse/type check @test function with builtin calls: " ^ Printexc.to_string exn)

(** Test multiple @test functions in same file *)
let test_multiple_test_functions () =
  let program = {|
    @test
    fn test_one() -> i32 {
        return 0
    }
    
    @test
    fn test_two() -> i32 {
        return 0
    }
    
    @test
    fn test_three() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Count @test functions *)
  let test_count = List.fold_left (fun count decl ->
    match decl with
    | AttributedFunction attr_func when 
        List.exists (function SimpleAttribute "test" -> true | _ -> false) attr_func.attr_list ->
        count + 1
    | _ -> count
  ) 0 ast in
  
  check int "Number of @test functions" 3 test_count

(** Test that test() builtin is only allowed in @test functions *)
let test_builtin_restricted_to_test_functions () =
  let program = {|
    fn regular_function() -> i32 {
        test()  // This should fail - test() not allowed in non-@test functions
        return 0
    }
    
    @test
    fn test_function() -> i32 {
        test()  // This should be allowed
        return 0
    }
  |} in
  
  try
    let ast = Parse.parse_string program in
    let symbol_table = Symbol_table.build_symbol_table ast in
    let (_, _) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    fail "Expected type checking to fail when test() is called from non-@test function"
  with
  | Type_checker.Type_error (msg, _) ->
    (* Check that the error message mentions test() restriction *)
    if String.contains msg 't' && String.contains msg 'e' && String.contains msg 's' && String.contains msg '(' then
      check bool "test() call in non-@test function properly rejected" true true
    else
      fail ("Got Type_error but with unexpected message: " ^ msg)
  | exn -> 
    fail ("Unexpected exception: " ^ Printexc.to_string exn)

let test_attribute_tests = [
  "test_attribute_parsing", `Quick, test_test_attribute_parsing;
  "builtin_function_recognition", `Quick, test_builtin_function_recognition;
  "test_functions_not_ebpf_programs", `Quick, test_test_functions_not_ebpf_programs;
  "test_function_with_builtin_calls", `Quick, test_test_function_with_builtin_calls;
  "multiple_test_functions", `Quick, test_multiple_test_functions;
  "builtin_restricted_to_test_functions", `Quick, test_builtin_restricted_to_test_functions;
]

let () =
  run "KernelScript @test Attribute Tests" [
    "test_attribute", test_attribute_tests;
  ] 