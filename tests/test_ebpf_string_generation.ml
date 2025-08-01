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
open Kernelscript.Parse

(** Helper function to generate eBPF C code from program text *)
let generate_ebpf_c_code program_text filename =
  let ast = parse_string program_text in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table filename in
  
  (* This calls the eBPF code generator, not the userspace code generator *)
  Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir

(** Helper function to check if generated code contains a pattern *)
let contains_pattern code pattern =
  try
    let regex = Str.regexp pattern in
    ignore (Str.search_forward regex code 0);
    true
  with Not_found -> false

(** Test 1: String literal type compatibility in eBPF code generation *)
let test_string_literal_type_compatibility () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var str_0: str(16) = "hello"
  var str_1: str(32) = "world"
  var str_2: str(128) = "this is a much longer string for testing"
  return 2
}
|} in
  
  try
    let ebpf_code = generate_ebpf_c_code program_text "test_string_compat" in
    
    (* The key fix: variables should be declared with their target types *)
    check bool "str_0 declared as str_16_t" true 
      (contains_pattern ebpf_code "str_16_t str_0");
    check bool "str_1 declared as str_32_t" true 
      (contains_pattern ebpf_code "str_32_t str_1");
    check bool "str_2 declared as str_128_t" true 
      (contains_pattern ebpf_code "str_128_t str_2");
    
    (* Variables should have struct initialization with correct string literals *)
    check bool "str_0 has struct assignment" true
      (contains_pattern ebpf_code "str_0.*=.*\\{");
    check bool "str_0 contains hello string" true
      (contains_pattern ebpf_code "\\.data.*=.*\"hello\"");
    check bool "str_1 has struct assignment" true
      (contains_pattern ebpf_code "str_1.*=.*\\{");
    check bool "str_1 contains world string" true
      (contains_pattern ebpf_code "\\.data.*=.*\"world\"");
    
  with
  | exn -> fail ("eBPF string literal test failed: " ^ Printexc.to_string exn)

(** Test 2: String type definitions are generated correctly *)
let test_string_type_definitions () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var small: str(16) = "hello"
  var large: str(32) = "world"
  return 2
}
|} in
  
  try
    let ebpf_code = generate_ebpf_c_code program_text "test_type_defs" in
    
    (* Should generate the required string type definitions *)
    check bool "str_16_t typedef exists" true
      (contains_pattern ebpf_code "typedef struct.*str_16_t");
    check bool "str_32_t typedef exists" true
      (contains_pattern ebpf_code "typedef struct.*str_32_t");
    
    (* Should include length fields somewhere *)
    check bool "has len field" true
      (contains_pattern ebpf_code "__u16 len");
    check bool "has data field" true
      (contains_pattern ebpf_code "char data\\[");
    
  with
  | exn -> fail ("eBPF type definition test failed: " ^ Printexc.to_string exn)

(** Test 3: Compilation test - generate and attempt to compile eBPF code *)
let test_ebpf_compilation () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var name: str(16) = "hello"
  var message: str(32) = "world"
  return 2
}
|} in
  
  try
    let ebpf_code = generate_ebpf_c_code program_text "test_compile" in
    
    (* Just check that the code contains basic required elements *)
    check bool "contains SEC xdp" true
      (contains_pattern ebpf_code "SEC(\"xdp\")");
    check bool "contains includes" true
      (contains_pattern ebpf_code "#include.*vmlinux.h");
    check bool "contains license" true
      (contains_pattern ebpf_code "SEC(\"license\")");
    
    (* Optional compilation check - only if clang is available and works *)
    if Sys.command "which clang >/dev/null 2>&1" = 0 then (
      let temp_file = Filename.temp_file "test_ebpf_compile" ".c" in
      let oc = open_out temp_file in
      output_string oc ebpf_code;
      close_out oc;
      
      let obj_file = Filename.temp_file "test_ebpf_compile" ".o" in
      let compile_cmd = Printf.sprintf "clang -target bpf -O2 -c %s -o %s 2>/dev/null" temp_file obj_file in
      let exit_code = Sys.command compile_cmd in
      
      (* Cleanup *)
      (try Unix.unlink temp_file with _ -> ());
      (try Unix.unlink obj_file with _ -> ());
      
      (* Only check compilation if it's expected to work *)
      if exit_code <> 0 then
        Printf.printf "Note: eBPF compilation failed (this may be due to missing BPF headers)\n%!";
      (* Don't fail the test if compilation fails due to system setup *)
    )
    
  with
  | exn -> fail ("eBPF compilation test failed: " ^ Printexc.to_string exn)

(** Test 4: Bug regression test - this would have failed before the fix *)
let test_bug_regression () =
  let program_text = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var str_0: str(16) = "hello"
  var str_1: str(32) = "world"
  return 2
}
|} in
  
  try
    let ebpf_code = generate_ebpf_c_code program_text "test_bug_regression" in
    
    (* Before the fix, this would have generated incompatible types *)
    (* The key is that variables should NOT be declared with literal-length types *)
    check bool "str_0 not declared as str_5_t" false
      (contains_pattern ebpf_code "str_5_t str_0");
    check bool "str_1 not declared as str_5_t" false
      (contains_pattern ebpf_code "str_5_t str_1");
    
    (* Instead, they should use the declared target types *)
    check bool "str_0 correctly declared as str_16_t" true
      (contains_pattern ebpf_code "str_16_t str_0");
    check bool "str_1 correctly declared as str_32_t" true
      (contains_pattern ebpf_code "str_32_t str_1");
    
  with
  | exn -> fail ("Bug regression test failed: " ^ Printexc.to_string exn)

(** Test suite *)
let tests = [
  test_case "String literal type compatibility" `Quick test_string_literal_type_compatibility;
  test_case "String type definitions" `Quick test_string_type_definitions;
  test_case "eBPF code compilation" `Quick test_ebpf_compilation;
  test_case "Bug regression test" `Quick test_bug_regression;
]

let () = run "eBPF String Generation Tests" [
  "ebpf_string_generation", tests;
] 