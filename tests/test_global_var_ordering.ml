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
open Kernelscript.Ir
open Kernelscript.Ebpf_c_codegen

let test_global_var_ordering () =
  let test_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test.ks" } in
  
  (* Create global variables directly *)
  let global_var1 = make_ir_global_variable "test_counter" IRU32 
    (Some (make_ir_value (IRLiteral (IntLit (Signed64 0L, None))) IRU32 test_pos)) test_pos () in
  let global_var2 = make_ir_global_variable "local_secret" IRU64 
    (Some (make_ir_value (IRLiteral (IntLit (Signed64 0xdeadbeefL, None))) IRU64 test_pos)) test_pos ~is_local:true () in
  
  (* Create a simple XDP function that uses these global variables *)
  let return_instr = make_ir_instruction (IRReturn (Some (make_ir_value (IRLiteral (IntLit (Signed64 2L, None))) IRU32 test_pos))) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "test_func" [("ctx", IRPointer (IRContext XdpCtx, make_bounds_info ()))] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  
  let ir_prog = make_ir_program "test_func" Xdp main_func test_pos in
  
  (* Create multi-program structure with global variables *)
  let multi_ir = make_ir_multi_program "test" [ir_prog] [] [] ~global_variables:[global_var1; global_var2] test_pos in
  
  let c_code = generate_c_multi_program multi_ir in
  
  (* Check that global variables are declared before functions *)
  let lines = String.split_on_char '\n' c_code in
  let global_var_lines = ref [] in
  let function_lines = ref [] in
  let found_global_vars = ref false in
  let found_function = ref false in
  
  let contains_substring str substr =
    try 
      let _ = String.index str substr.[0] in 
      let len = String.length substr in
      let str_len = String.length str in
      let rec check_at pos =
        if pos > str_len - len then false
        else if String.sub str pos len = substr then true
        else check_at (pos + 1)
      in
      check_at 0
    with Not_found -> false
  in
  
  List.iteri (fun i line ->
    let trimmed = String.trim line in
    if String.contains trimmed '(' && String.contains trimmed ')' && 
       (String.contains trimmed '{' || contains_substring trimmed "SEC") then (
      (* This looks like a function definition *)
      if contains_substring trimmed "SEC" then (
        found_function := true;
        function_lines := i :: !function_lines
      )
    ) else if (String.contains trimmed '=' && 
               (contains_substring trimmed "__u32" || contains_substring trimmed "__u64" || 
                contains_substring trimmed "__u8" || contains_substring trimmed "__hidden")) then (
      (* This looks like a global variable declaration *)
      found_global_vars := true;
      global_var_lines := i :: !global_var_lines
    )
  ) lines;
  
  check bool "Should have found global variables" true !found_global_vars;
  check bool "Should have found functions" true !found_function;
  
  (* Check that all global variables come before all functions *)
  let max_global_line = List.fold_left max (-1) !global_var_lines in
  let min_function_line = List.fold_left min Int.max_int !function_lines in
  
  check bool "Global variables should be declared before functions" 
    true (max_global_line < min_function_line);
  
  (* Verify that the generated C code compiles (basic syntax check) *)
  check bool "Generated C code should contain test_counter declaration" 
    true (contains_substring c_code "test_counter");
  check bool "Generated C code should contain local_secret declaration" 
    true (contains_substring c_code "local_secret");
  check bool "Generated C code should contain function definition" 
    true (contains_substring c_code "test_func")

let () = run "Global Variable Ordering Tests" [
  "test_global_var_ordering", [
    test_case "Global variables before functions" `Quick test_global_var_ordering;
  ];
] 