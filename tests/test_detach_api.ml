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
 
(** Unit tests for detach() API *)

open Alcotest
open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Stdlib
open Kernelscript.Type_checker
open Kernelscript.Ir_generator
open Kernelscript.Userspace_codegen

(* Helper function for string containment *)
let string_contains_substring s sub =
  try
    let _ = Str.search_forward (Str.regexp_string sub) s 0 in
    true
  with
  | Not_found -> false

let test_detach_in_stdlib () =
  (* Test that detach function is recognized as builtin *)
  check bool "detach is builtin" true (is_builtin_function "detach");
  
  (* Test function signature *)
  match get_builtin_function_signature "detach" with
  | Some (params, return_type) ->
      check int "detach parameter count" 1 (List.length params);
      check bool "detach first param is ProgramHandle" true 
        (match params with
         | [ProgramHandle] -> true
         | _ -> false);
      check bool "detach return type is Void" true (return_type = Void)
  | None -> (fail "detach function signature should exist" : unit);
  
  (* Test userspace implementation *)
  match get_userspace_implementation "detach" with
  | Some impl -> check string "detach userspace impl" "detach_bpf_program_by_fd" impl
  | None -> (fail "detach userspace implementation should exist" : unit)

let test_detach_code_generation () =
  let program = {|
@xdp fn test_handler(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  var prog = load(test_handler)
  attach(prog, "eth0", 0)
  detach(prog)
  return 0
}
|} in
  
  try
    let ast = parse_string program in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ~include_xdp:true ast in
    let (typed_ast, _) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir_multi_prog = generate_ir typed_ast symbol_table "test" in
    
    let userspace_prog = match ir_multi_prog.userspace_program with
      | Some prog -> prog
      | None -> (fail "No userspace program generated" : 'a) in
    let generated_code = generate_complete_userspace_program_from_ir 
      userspace_prog [] ir_multi_prog "test.ks" in
    
    (* Check that detach function is generated *)
    check bool "detach function is generated" true 
      (string_contains_substring generated_code "void detach_bpf_program_by_fd(int prog_fd)");
    
    (* Check that attachment storage is generated *)
    check bool "attachment storage is generated" true 
      (string_contains_substring generated_code "struct attachment_entry");
    
    (* Check that pthread.h is included *)
    check bool "pthread.h is included" true 
      (string_contains_substring generated_code "#include <pthread.h>")
      
  with
  | e -> (fail ("Code generation test failed: " ^ Printexc.to_string e) : unit)

let test_detach_function_usage_tracking () =
  let program = {|
@xdp fn handler(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  var prog = load(handler)
  detach(prog)
  return 0
}
|} in
  
  try
    let ast = parse_string program in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ~include_xdp:true ast in
    let (typed_ast, _) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir_multi_prog = generate_ir typed_ast symbol_table "test" in
    
    let userspace_prog = match ir_multi_prog.userspace_program with
      | Some prog -> prog
      | None -> (fail "No userspace program generated" : 'a) in
    let generated_code = generate_complete_userspace_program_from_ir 
      userspace_prog [] ir_multi_prog "test.ks" in
    
    (* When only detach is used (no attach), attachment storage should still be generated *)
    check bool "attachment storage generated with detach only" true 
      (string_contains_substring generated_code "struct attachment_entry");
    check bool "detach function generated with detach only" true 
      (string_contains_substring generated_code "void detach_bpf_program_by_fd(")
      
  with
  | e -> (fail ("Function usage tracking test failed: " ^ Printexc.to_string e) : unit)

let test_detach_type_error () =
  let program = {|
fn main() -> i32 {
  detach("invalid_argument")
  return 0
}
|} in
  
  try
    let ast = parse_string program in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    (fail "Should have failed with type error" : unit)
  with
  | Type_error (_, _) -> 
      (* Expected type error *)
      check bool "Got expected type error" true true
  | Failure msg when string_contains_substring msg "type" -> 
      (* Expected type error as Failure *)
      check bool "Got expected type error" true true
  | _ -> (fail "Should have failed with type error" : unit)

(* Test suite definition *)
let detach_api_tests = [
  ("stdlib_function_definition", `Quick, test_detach_in_stdlib);
  ("code_generation", `Quick, test_detach_code_generation);
  ("function_usage_tracking", `Quick, test_detach_function_usage_tracking);
  ("type_error_detection", `Quick, test_detach_type_error);
]

let () =
  Alcotest.run "Detach API Tests" [
    ("detach_api", detach_api_tests);
  ]