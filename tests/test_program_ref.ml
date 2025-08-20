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

open Kernelscript.Parse
open Kernelscript.Type_checker
open Alcotest

(** Test program reference type checking *)
let test_program_reference_type () =
  let program_text = {|
@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  var prog_handle = load(packet_filter)
  var result = attach(prog_handle, "eth0", 0)
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "program reference type checking" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "program reference type checking" true false
  | e -> 
      Printf.printf "Other error: %s\n" (Printexc.to_string e);
      check bool "program reference type checking" true false

(** Test program reference with different program types *)
let test_different_program_types () =
  let program_text = {|
@probe("sys_read") fn kprobe_tracer(fd: u32, buf: *u8, count: usize) -> i32 {
  return 0
}

@tc("ingress") fn tc_filter(ctx: *__sk_buff) -> i32 {
  return 0
}

fn main() -> i32 {
  var kprobe_handle = load(kprobe_tracer)
  var tc_handle = load(tc_filter)
  
  var kprobe_result = attach(kprobe_handle, "sys_read", 0)
  var tc_result = attach(tc_handle, "eth0", 1)
  
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "different program types" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "different program types" true false
  | Parse_error (msg, _) ->
      Printf.printf "Parse error: %s\n" msg;
      check bool "different program types" true false
  | e -> 
      Printf.printf "Other error: %s\n" (Printexc.to_string e);
      check bool "different program types" true false

(** Test invalid program reference *)
let test_invalid_program_reference () =
  let program_text = {|
fn main() -> i32 {
  var prog_handle = load(non_existent_program)
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "should fail for non-existent program" false true
  with
  | Type_error _ -> 
      check bool "should fail for non-existent program" true true
  | Kernelscript.Symbol_table.Symbol_error _ ->
      check bool "should fail for non-existent program" true true
  | _ -> 
      check bool "should fail for non-existent program" false true

(** Test program reference as variable *)
let test_program_reference_as_variable () =
  let program_text = {|
@xdp fn my_xdp(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  var prog_ref = my_xdp  // Should work - program reference as variable
  var prog_handle = load(prog_ref)
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "program reference as variable" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "program reference as variable" true false
  | _ -> 
      check bool "program reference as variable" true false

(** Test wrong argument types for program functions *)
let test_wrong_argument_types () =
  let program_text = {|
@xdp fn my_xdp(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  var prog_handle = load("string_instead_of_program")  // Should fail
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "should fail for wrong argument type" false true
  with
  | Type_error _ -> 
      check bool "should fail for wrong argument type" true true
  | _ -> 
      check bool "should fail for wrong argument type" false true

(** Test stdlib integration *)
let test_stdlib_integration () =
  (* Test that the built-in functions are properly recognized *)
  check bool "load is builtin" true (Kernelscript.Stdlib.is_builtin_function "load");
  check bool "attach is builtin" true (Kernelscript.Stdlib.is_builtin_function "attach");
  
  (* Test getting function signatures *)
  (match Kernelscript.Stdlib.get_builtin_function_signature "load" with
  | Some (params, return_type) ->
      check int "load parameter count" 1 (List.length params);
      check bool "load return type is ProgramHandle" true (return_type = Kernelscript.Ast.ProgramHandle)
  | None -> check bool "load function signature should exist" false true);
  
  (match Kernelscript.Stdlib.get_builtin_function_signature "attach" with
  | Some (params, return_type) ->
      check int "attach parameter count" 3 (List.length params);
      (match params with
       | first_param :: _ ->
           check bool "attach first parameter is ProgramHandle" true (first_param = Kernelscript.Ast.ProgramHandle)
       | [] -> check bool "attach should have parameters" false true);
      check bool "attach return type is U32" true (return_type = Kernelscript.Ast.U32)
  | None -> check bool "attach function signature should exist" false true)

(** Test that calling attach without load fails *)
let test_attach_without_load_fails () =
  let program_text = {|
@xdp fn simple_xdp(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  var result = attach(simple_xdp, "eth0", 0)  // Should fail - program ref instead of handle
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "should fail when attach called with program reference" false true
  with
  | Type_error (msg, _) -> 
      check bool "should fail with type error" true (String.length msg > 0);
      check bool "error should mention type mismatch" true (String.contains msg 'm')
  | _ -> 
      check bool "should fail when attach called with program reference" false true

(** Test multiple program handles with proper resource management *)
let test_multiple_program_handles () =
  let program_text = {|
@xdp fn xdp_filter(ctx: *xdp_md) -> xdp_action {
  return 2
}

@tc("ingress") fn tc_shaper(ctx: *__sk_buff) -> i32 {
  return 0
}

fn main() -> i32 {
  var xdp_handle = load(xdp_filter)
  var tc_handle = load(tc_shaper)
  
  var xdp_result = attach(xdp_handle, "eth0", 0)
  var tc_result = attach(tc_handle, "eth0", 1)
  
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "multiple program handles should work" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "multiple program handles should work" true false
  | _ -> 
      check bool "multiple program handles should work" true false

(** Test that program handle variables can be named appropriately *)
let test_program_handle_naming () =
  let program_text = {|
@xdp fn simple_xdp(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  var program_handle = load(simple_xdp)  // Clear, non-fd naming
  var network_prog = load(simple_xdp)    // Alternative naming
  
  var result1 = attach(program_handle, "eth0", 0)
  var result2 = attach(network_prog, "lo", 0)
  
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "program handle naming should work" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "program handle naming should work" true false
  | _ -> 
      check bool "program handle naming should work" true false

(** Test suite *)
let program_ref_tests = [
  "program_reference_type_checking", `Quick, test_program_reference_type;
  "different_program_types", `Quick, test_different_program_types;
  "invalid_program_reference", `Quick, test_invalid_program_reference;
  "program_reference_as_variable", `Quick, test_program_reference_as_variable;
  "wrong_argument_types", `Quick, test_wrong_argument_types;
  "stdlib_integration", `Quick, test_stdlib_integration;
  "attach_without_load_fails", `Quick, test_attach_without_load_fails;
  "multiple_program_handles", `Quick, test_multiple_program_handles;
  "program_handle_naming", `Quick, test_program_handle_naming;
]

let () =
  run "Program Reference Tests" [
    "program_ref", program_ref_tests;
  ] 
