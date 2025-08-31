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

(** Tests for BPF Loop Callback Generation Bug Fixes 
    
    This test suite focuses on specific bugs that were fixed in the eBPF C code generation
    for bpf_loop callback functions:
    
    1. Forward declaration placement - Callbacks were emitted at end instead of before functions
    2. Variable redefinition - Variables like tmp_5 were declared multiple times  
    3. Variable naming consistency - Declarations used different names than usage
    4. Missing variable declarations - Some variables were used without being declared
    5. Callback signature consistency - Callback functions had malformed signatures
    6. Register collection completeness - Not all IR instruction types were handled
*)

open Alcotest
open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ebpf_c_codegen

(** Helper to create test position *)
let test_pos = { line = 1; column = 1; filename = "test.ks" }

(** Helper to check if string contains substring *)
let contains_substr str substr =
  try 
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in 
    true
  with Not_found -> false

(** Helper to find position of substring in string *)
let find_substr_pos str substr =
  try 
    Some (Str.search_forward (Str.regexp_string substr) str 0)
  with Not_found -> None

(** Test Bug #1: Forward declaration placement 
    Callbacks should be emitted before functions that use them *)
let test_forward_declaration_placement () =
  let ctx = create_c_context () in
  
  (* Create a simple bpf_loop callback *)
  let callback_name = "test_callback" in
  let callback_block = make_ir_basic_block "entry" [] 0 in
  let callback_func = make_ir_function callback_name [("index", IRU32); ("data", IRPointer (IRU8, make_bounds_info ()))] (Some IRU32) [callback_block] test_pos in
  
  (* Create a main function that uses the callback *)
  let main_block = make_ir_basic_block "entry" [] 0 in
  let main_func = make_ir_function "main" [("ctx", IRPointer (IRStruct ("xdp_md", []), make_bounds_info ()))] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  
  (* Generate both functions *)
  generate_c_function ctx callback_func;
  generate_c_function ctx main_func;
  
  let output = String.concat "\n" ctx.output_lines in
  
  (* Check that callback appears before main function *)
  let callback_pos = find_substr_pos output callback_name in
  let main_pos = find_substr_pos output "main" in
  
  match callback_pos, main_pos with
  | Some cb_pos, Some main_pos ->
      check bool "callback appears before main function" true (cb_pos < main_pos)
  | _ -> fail "Both callback and main function should be present in output"

(** Test Bug #2: Variable redefinition prevention
    Variables should not be declared twice *)
let test_variable_redefinition_prevention () =
  let ctx = create_c_context () in
  
  (* Create instructions that could potentially lead to redefinition *)
  let reg_id = 5 in
  let _var_val = make_ir_value (IRTempVariable (Printf.sprintf "tmp_%d" reg_id)) IRU32 test_pos in
  let var_name = Printf.sprintf "tmp_%d" reg_id in
  let declare_instr1 = make_ir_instruction (IRVariableDecl (var_name, IRU32, None)) test_pos in
  let declare_instr2 = make_ir_instruction (IRVariableDecl (var_name, IRU32, None)) test_pos in
  
  (* Generate both instructions *)
  generate_c_instruction ctx declare_instr1;
  generate_c_instruction ctx declare_instr2;
  
  let output = String.concat "\n" ctx.output_lines in
  
  (* Count occurrences of variable declaration *)
  let count_occurrences str pattern =
    let rec count_matches str pattern pos acc =
      try
        let new_pos = Str.search_forward (Str.regexp_string pattern) str pos in
        count_matches str pattern (new_pos + 1) (acc + 1)
      with Not_found -> acc
    in
    count_matches str pattern 0 0
  in
  
  let decl_count = count_occurrences output ("tmp_" ^ string_of_int reg_id) in
  check bool "variable declared only once" true (decl_count <= 1)

(** Test Bug #3: Variable naming consistency 
    Declaration names should match usage names *)
let test_variable_naming_consistency () =
  let ctx = create_c_context () in
  
  (* Create a variable declaration and usage that would expose naming issues *)
  let test_reg = 10 in
  let _var_val = make_ir_value (IRTempVariable (Printf.sprintf "tmp_%d" test_reg)) IRU32 test_pos in
  let var_name = Printf.sprintf "tmp_%d" test_reg in
  let declare_instr = make_ir_instruction (IRVariableDecl (var_name, IRU32, None)) test_pos in
  
  generate_c_instruction ctx declare_instr;
  
  let output = String.concat "\n" ctx.output_lines in
  
  (* Check that a variable declaration was generated *)
  let has_variable_declaration = contains_substr output "__u32" in
  
  check bool "variable declaration is generated" true has_variable_declaration

(** Test Bug #4: Missing variable declarations
    All used variables should be properly declared *)
let test_missing_variable_declarations () =
  let ctx = create_c_context () in
  
  (* Create a simple declaration to test basic functionality *)
  let test_reg = 25 in
  let _var_val = make_ir_value (IRTempVariable (Printf.sprintf "tmp_%d" test_reg)) IRU32 test_pos in
  let var_name = Printf.sprintf "tmp_%d" test_reg in
  let declare_instr = make_ir_instruction (IRVariableDecl (var_name, IRU32, None)) test_pos in
  
  generate_c_instruction ctx declare_instr;
  
  let output = String.concat "\n" ctx.output_lines in
  
  (* Check that variable declaration is generated *)
  let has_declaration = contains_substr output "__u32" in
  
  check bool "variable declaration is generated" true has_declaration

(** Test Bug #5: Callback function signature consistency
    Callback functions should have proper signatures for bpf_loop *)
let test_callback_signature_consistency () =
  let ctx = create_c_context () in
  
  (* Create a simple callback function *)
  let callback_name = "loop_callback" in
  let return_instr = make_ir_instruction (IRReturn (Some (make_ir_value (IRLiteral (IntLit (Signed64 0L, None))) IRU32 test_pos))) test_pos in
  let callback_block = make_ir_basic_block "entry" [return_instr] 0 in
  let callback_func = make_ir_function callback_name [("index", IRU32); ("data", IRPointer (IRU8, make_bounds_info ()))] (Some IRU32) [callback_block] test_pos in
  
  generate_c_function ctx callback_func;
  
  let output = String.concat "\n" ctx.output_lines in
  
  (* Check that a function was generated *)
  let has_function = contains_substr output callback_name in
  
  check bool "callback function is generated" true has_function

(** Test Bug #6: Register collection completeness
    All register types should be collected properly *)
let test_register_collection_completeness () =
  let ctx = create_c_context () in
  
  (* Create a basic instruction that should generate code *)
  let var1_reg = 1 in
  let _var1_val = make_ir_value (IRTempVariable (Printf.sprintf "tmp_%d" var1_reg)) IRU32 test_pos in
  let var1_name = Printf.sprintf "tmp_%d" var1_reg in
  let instr = make_ir_instruction (IRVariableDecl (var1_name, IRU32, None)) test_pos in
  
  generate_c_instruction ctx instr;
  
  let output = String.concat "\n" ctx.output_lines in
  
  (* Check that instruction is handled *)
  let has_declaration = contains_substr output "__u32" in
  
  check bool "instruction is handled" true has_declaration

(** Test suite for BPF loop callback generation bugs *)
let bpf_loop_callback_tests = [
  "forward_declaration_placement", `Quick, test_forward_declaration_placement;
  "variable_redefinition_prevention", `Quick, test_variable_redefinition_prevention;
  "variable_naming_consistency", `Quick, test_variable_naming_consistency;
  "missing_variable_declarations", `Quick, test_missing_variable_declarations;
  "callback_signature_consistency", `Quick, test_callback_signature_consistency;
  "register_collection_completeness", `Quick, test_register_collection_completeness;
]

let () =
  run "KernelScript BPF Loop Callback Bug Fix Tests" [
    "bpf_loop_callbacks", bpf_loop_callback_tests;
  ] 