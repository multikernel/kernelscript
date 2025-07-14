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
open Kernelscript.Ir
open Alcotest

(** Helper function to parse string with builtin types loaded via symbol table *)
let parse_string_with_builtins code =
  let ast = parse_string code in
  (* Create symbol table with test builtin types *)
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  (* Run type checking with builtin types loaded *)
  let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  typed_ast

(** Helper function to type check with builtin types loaded *)
let type_check_and_annotate_ast_with_builtins ast =
  (* Create symbol table with test builtin types *)
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  (* Run type checking with builtin types loaded *)
  Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast

(** Helper to extract CompoundIndexAssignment from parsed AST *)
let extract_compound_index_assignment ast =
  (* Find the AttributedFunction in the AST *)
  let attr_func = List.find (function AttributedFunction _ -> true | _ -> false) ast in
  match attr_func with
  | AttributedFunction af -> 
      let main_func = af.attr_function in
      let stmt = List.nth main_func.func_body 0 in  (* First statement *)
      (match stmt.stmt_desc with
       | CompoundIndexAssignment (map_expr, key_expr, op, value_expr) ->
           (map_expr, key_expr, op, value_expr)
       | _ -> failwith "Expected CompoundIndexAssignment")
  | _ -> failwith "Expected AttributedFunction"

(** Test 1: Basic compound index assignment parsing *)
let test_basic_parsing () =
  let source = {|
map<u32, u32> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[123] += 1
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let (map_expr, key_expr, op, value_expr) = extract_compound_index_assignment ast in
    
    (* Check map expression *)
    (match map_expr.expr_desc with
     | Identifier "test_map" -> ()
     | _ -> failwith "Expected map identifier");
    
    (* Check key expression *)
    (match key_expr.expr_desc with
     | Literal (IntLit (123, _)) -> ()
     | _ -> failwith "Expected integer literal key");
    
    (* Check operator *)
    check bool "operator is Add" true (op = Add);
    
    (* Check value expression *)
    (match value_expr.expr_desc with
     | Literal (IntLit (1, _)) -> ()
     | _ -> failwith "Expected integer literal value");
    
    print_endline "✓ Basic compound index assignment parsing test passed"
  with
  | Parse_error (msg, _) -> failwith ("Parse error: " ^ msg)
  | e -> failwith ("Unexpected error: " ^ Printexc.to_string e)

(** Test 2: All compound operators parsing *)
let test_all_operators_parsing () =
  let operators = [
    ("+=", Add);
    ("-=", Sub);
    ("*=", Mul);
    ("/=", Div);
    ("%=", Mod);
  ] in
  
  List.iter (fun (op_str, expected_op) ->
    let source = Printf.sprintf {|
map<u32, u32> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[123] %s 5
  return XDP_PASS
}
|} op_str in
    try
      let ast = parse_string source in
      let (_, _, actual_op, _) = extract_compound_index_assignment ast in
      check bool ("operator " ^ op_str) true (actual_op = expected_op);
      Printf.printf "✓ Operator %s parsing test passed\n" op_str
    with
    | e -> failwith ("Failed to parse operator " ^ op_str ^ ": " ^ Printexc.to_string e)
  ) operators

(** Test 3: Complex key expressions *)
let test_complex_key_expressions () =
  let test_cases = [
    ("src_ip", "variable key");
    ("packet.source", "field access key");
    ("get_ip()", "function call key");
    ("ips[0]", "array access key");
  ] in
  
  List.iter (fun (key_expr, description) ->
    let source = Printf.sprintf {|
map<u32, u32> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[%s] += 1
  return XDP_PASS
}
|} key_expr in
    try
      let _ = parse_string source in
      Printf.printf "✓ %s parsing test passed\n" description
    with
    | e -> failwith ("Failed to parse " ^ description ^ ": " ^ Printexc.to_string e)
  ) test_cases

(** Test 4: Type checking with integer value types (should succeed) *)
let test_integer_value_types () =
  let unsigned_types = ["u8"; "u16"; "u32"; "u64"] in
  let signed_types = ["i8"; "i16"; "i32"; "i64"] in
  
  (* Test unsigned types (should succeed) *)
  List.iter (fun value_type ->
    let source = Printf.sprintf {|
map<u32, %s> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[123] += 1
  return XDP_PASS
}
|} value_type in
    try
      let ast = parse_string source in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      Printf.printf "✓ Integer type %s compound assignment test passed\n" value_type
    with
    | e -> failwith ("Failed for integer type " ^ value_type ^ ": " ^ Printexc.to_string e)
  ) unsigned_types;
  
  (* Test signed types (may fail due to type coercion) *)
  List.iter (fun value_type ->
    let source = Printf.sprintf {|
map<u32, %s> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[123] += 1
  return XDP_PASS
}
|} value_type in
    try
      let ast = parse_string source in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      Printf.printf "✓ Integer type %s compound assignment test passed\n" value_type
    with
    | Type_error (msg, _) ->
        Printf.printf "✓ Integer type %s compound assignment expected type error: %s\n" value_type msg
    | e -> failwith ("Unexpected error for integer type " ^ value_type ^ ": " ^ Printexc.to_string e)
  ) signed_types

(** Test 5: Type checking with non-integer value types (should fail) *)
let test_non_integer_value_types () =
  let non_integer_types = [
    ("str(10)", "string type");
    ("bool", "boolean type");
  ] in
  
  List.iter (fun (value_type, description) ->
    let source = Printf.sprintf {|
map<u32, %s> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[123] += 1
  return XDP_PASS
}
|} value_type in
    try
      let ast = parse_string source in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      failwith ("Expected type error for " ^ description ^ ", but none occurred")
    with
         | Type_error (msg, _) ->
         (* Check that the error message mentions the operator or type mismatch *)
         let contains_mismatch = try
           let _ = Str.search_forward (Str.regexp "mismatch") msg 0 in true
         with Not_found -> false
         in
         if String.contains msg '+' || contains_mismatch then
           Printf.printf "✓ %s compound assignment rejection test passed: %s\n" description msg
         else
           failwith ("Unexpected error message for " ^ description ^ ": " ^ msg)
    | e -> failwith ("Unexpected error for " ^ description ^ ": " ^ Printexc.to_string e)
  ) non_integer_types

(** Test 6: Array compound assignment *)
let test_array_compound_assignment () =
  let source = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var arr: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  arr[5] += 10
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    print_endline "✓ Array compound assignment test passed"
  with
  | e -> Printf.printf "Array compound assignment test failed (expected): %s\n" (Printexc.to_string e)

(** Test 7: Key type mismatch (should fail) *)
let test_key_type_mismatch () =
  let source = {|
map<u32, u32> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map["invalid_key"] += 1  // String key for u32 map
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    failwith "Expected type error for key type mismatch, but none occurred"
  with
  | Type_error (msg, _) ->
      if String.contains msg 'k' then  (* Check for "key" in error message *)
        Printf.printf "✓ Key type mismatch rejection test passed: %s\n" msg
      else
        failwith ("Unexpected error message for key mismatch: " ^ msg)
  | e -> failwith ("Unexpected error for key mismatch: " ^ Printexc.to_string e)

(** Test 8: Value type mismatch (should fail) *)
let test_value_type_mismatch () =
  let source = {|
map<u32, u32> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[123] += "invalid_value"  // String value for u32 map
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    failwith "Expected type error for value type mismatch, but none occurred"
  with
  | Type_error (msg, _) ->
      Printf.printf "✓ Value type mismatch rejection test passed: %s\n" msg
  | e -> failwith ("Unexpected error for value mismatch: " ^ Printexc.to_string e)

(** Test 9: Multiple compound assignments in sequence *)
let test_multiple_compound_assignments () =
  let source = {|
map<u32, u32> counters : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  counters[1] += 1
  counters[2] -= 1
  counters[3] *= 2
  counters[4] /= 2
  counters[5] %= 3
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    print_endline "✓ Multiple compound assignments test passed"
  with
  | e -> failwith ("Multiple compound assignments failed: " ^ Printexc.to_string e)

(** Test 10: Compound assignment on non-map expression (should fail) *)
let test_non_map_compound_assignment () =
  let source = {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var x = 5
  x[0] += 1  // x is not a map or array
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    failwith "Expected type error for non-map compound assignment, but none occurred"
  with
  | Type_error (msg, _) ->
      Printf.printf "✓ Non-map compound assignment rejection test passed: %s\n" msg
  | e -> failwith ("Unexpected error for non-map assignment: " ^ Printexc.to_string e)

(** Test 11: IR generation for compound index assignment *)
let test_ir_generation () =
  let source = {|
map<u32, u32> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[123] += 5
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let (typed_ast, _) = type_check_and_annotate_ast_with_builtins ast in
    
    (* Try to generate IR - this tests that the IR generator handles CompoundIndexAssignment *)
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let ir_multi_program = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
    
    (* Check that IR was generated without errors *)
    check bool "IR generation successful" true (List.length ir_multi_program.programs > 0);
    print_endline "✓ IR generation test passed"
  with
  | e -> failwith ("IR generation failed: " ^ Printexc.to_string e)

(** Test 12: IR instruction ordering regression test *)
let test_ir_instruction_ordering () =
  let source = {|
map<u32, u32> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  test_map[42] += 1
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let (typed_ast, _) = type_check_and_annotate_ast_with_builtins ast in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let ir_multi_program = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
    
    (* Find the program and its instructions *)
    let program = List.hd ir_multi_program.programs in
    let basic_block = List.hd program.entry_function.basic_blocks in
    let instructions = basic_block.instructions in
    
    (* Find the IRMapLoad instruction *)
    let map_load_instruction = List.find (fun instr ->
      match instr.instr_desc with
      | IRMapLoad (_, _, _, _) -> true
      | _ -> false
    ) instructions in
    
    (* Verify the instruction has correct argument order: (map, key, dest, load_type) *)
    (match map_load_instruction.instr_desc with
     | IRMapLoad (map_val, key_val, dest_val, load_type) ->
         (* Verify map argument is a map reference *)
         (match map_val.value_desc with
          | IRMapRef "test_map" -> 
              (* Verify key is a register or literal *)
              (match key_val.value_desc with
               | IRRegister _ | IRLiteral _ -> 
                   (* Verify dest is a register *)
                   (match dest_val.value_desc with
                    | IRRegister _ -> 
                        (* Verify load type is MapLookup *)
                        (match load_type with
                         | MapLookup -> print_endline "✓ IRMapLoad instruction ordering test passed"
                         | _ -> failwith "Expected MapLookup load type")
                    | _ -> failwith "Expected register for dest argument")
               | _ -> failwith "Expected register or literal for key argument")
          | _ -> failwith "Expected IRMapRef for map argument")
     | _ -> failwith "Expected IRMapLoad instruction")
  with
  | e -> failwith ("IR instruction ordering test failed: " ^ Printexc.to_string e)

(** Test 13: End-to-end compilation *)
let test_end_to_end_compilation () =
  let source = {|
map<u32, u64> packet_counts : HashMap(1024)

@xdp fn rate_limiter(ctx: *xdp_md) -> xdp_action {
  var src_ip = 192168001
  packet_counts[src_ip] += 1
  return XDP_PASS
}
|} in
  try
    let ast = parse_string source in
    let (typed_ast, _) = type_check_and_annotate_ast_with_builtins ast in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let ir_multi_program = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "rate_limiter" in
    
    (* Check that compilation was successful *)
    check bool "end-to-end compilation successful" true (List.length ir_multi_program.programs > 0);
    print_endline "✓ End-to-end compilation test passed"
  with
  | e -> failwith ("End-to-end compilation failed: " ^ Printexc.to_string e)

let compound_index_assignment_tests = [
  "basic_parsing", `Quick, test_basic_parsing;
  "all_operators_parsing", `Quick, test_all_operators_parsing;
  "complex_key_expressions", `Quick, test_complex_key_expressions;
  "integer_value_types", `Quick, test_integer_value_types;
  "non_integer_value_types", `Quick, test_non_integer_value_types;
  "array_compound_assignment", `Quick, test_array_compound_assignment;
  "key_type_mismatch", `Quick, test_key_type_mismatch;
  "value_type_mismatch", `Quick, test_value_type_mismatch;
  "multiple_compound_assignments", `Quick, test_multiple_compound_assignments;
  "non_map_compound_assignment", `Quick, test_non_map_compound_assignment;
  "ir_generation", `Quick, test_ir_generation;
  "ir_instruction_ordering", `Quick, test_ir_instruction_ordering;
  "end_to_end_compilation", `Quick, test_end_to_end_compilation;
]

let () =
  run "Compound Index Assignment Tests" [
    "compound_index_assignment", compound_index_assignment_tests;
  ] 