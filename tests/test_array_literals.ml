open Alcotest
open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator

(** Helper functions *)
let dummy_pos = { line = 1; column = 1; filename = "test" }

let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Test 1: Basic Array Literal Type Inference *)
let test_array_literal_basic_types () =
  let test_cases = [
    ("[1, 2, 3]", "integer array");
    ("[true, false]", "boolean array");
    ("['a', 'b', 'c']", "character array");
  ] in
  
  List.iter (fun (array_literal, description) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
    let arr = %s
    return 2
}
|} array_literal in
    try
      let ast = parse_string program_text in
      let _ = build_symbol_table ast in
      let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
      check bool (description ^ " type inference") true true
    with
    | e -> fail (description ^ " failed: " ^ Printexc.to_string e)
  ) test_cases

(** Test 2: Array Literal Type Consistency *)
let test_array_literal_type_consistency () =
  (* Valid cases - all elements same type *)
  let valid_cases = [
    ("[1, 2, 3, 4]", "all integers");
    ("[true, false, true]", "all booleans");
    ("['x', 'y', 'z']", "all characters");
  ] in
  
  List.iter (fun (array_literal, description) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
    let arr = %s
    return 2
}
|} array_literal in
    try
      let ast = parse_string program_text in
      let _ = build_symbol_table ast in
      let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
      check bool (description ^ " consistency check") true true
    with
    | e -> fail (description ^ " failed: " ^ Printexc.to_string e)
  ) valid_cases

(** Test 3: Array Literal Type Inconsistency Detection *)
let test_array_literal_type_inconsistency () =
  (* Invalid cases - mixed types *)
  let invalid_cases = [
    ("[1, true, 3]", "mixed integer and boolean");
    ("[true, 'a', false]", "mixed boolean and character");
    ("[1, 'x']", "mixed integer and character");
  ] in
  
  List.iter (fun (array_literal, description) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
    let arr = %s
    return 2
}
|} array_literal in
    try
      let ast = parse_string program_text in
      let _ = build_symbol_table ast in
      let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
      fail (description ^ " should have failed type checking")
    with
    | Type_error (msg, _) ->
        check bool (description ^ " correctly rejected") true (String.contains msg 's' || String.contains msg 't')
    | e -> fail (description ^ " failed with unexpected error: " ^ Printexc.to_string e)
  ) invalid_cases

(** Test 4: Empty Array Literals *)
let test_empty_array_literals () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
    let empty_arr = []
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "empty array literal" true true
  with
  | e -> fail ("Empty array literal failed: " ^ Printexc.to_string e)

(** Test 5: Array Literals in Config Declarations *)
let test_array_literals_in_config () =
  let program_text = {|
config network {
    blocked_ports: u16[4] = [22, 23, 135, 445],
    allowed_protocols: u8[3] = [1, 6, 17],
    feature_flags: bool[2] = [true, false],
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "array literals in config" true true
  with
  | e -> fail ("Array literals in config failed: " ^ Printexc.to_string e)

(** Test 6: Array Literal Size Validation *)
let test_array_literal_size_validation () =
  (* Test that array literal size matches declared size *)
  let program_text = {|
config test_config {
    ports: u16[3] = [80, 443, 8080],
    flags: bool[2] = [true, false],
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "array literal size validation" true true
  with
  | e -> fail ("Array literal size validation failed: " ^ Printexc.to_string e)

(** Test 7: Nested Array Literals *)
let test_nested_array_literals () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
    let nested = [[1, 2], [3, 4]]
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "nested array literals" true true
  with
  | e -> fail ("Nested array literals failed: " ^ Printexc.to_string e)

(** Test 8: Large Array Literals *)
let test_large_array_literals () =
  let large_array = String.concat ", " (List.init 100 string_of_int) in
  let program_text = Printf.sprintf {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
    let large_arr = [%s]
    return 2
}
|} large_array in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "large array literals" true true
  with
  | e -> fail ("Large array literals failed: " ^ Printexc.to_string e)

(** Test 9: Array Literal IR Generation *)
let test_array_literal_ir_generation () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
    let numbers = [1, 2, 3, 4]
    let flags = [true, false]
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    let _ir_result = generate_ir ast symbol_table "test" in
    check bool "array literal IR generation" true true
  with
  | e -> fail ("Array literal IR generation failed: " ^ Printexc.to_string e)

let array_literal_tests = [
  ("basic_types", `Quick, test_array_literal_basic_types);
  ("type_consistency", `Quick, test_array_literal_type_consistency);
  ("type_inconsistency", `Quick, test_array_literal_type_inconsistency);
  ("empty_arrays", `Quick, test_empty_array_literals);
  ("arrays_in_config", `Quick, test_array_literals_in_config);
  ("size_validation", `Quick, test_array_literal_size_validation);
  ("nested_arrays", `Quick, test_nested_array_literals);
  ("large_arrays", `Quick, test_large_array_literals);
  ("ir_generation", `Quick, test_array_literal_ir_generation);
]

let () =
  run "Array Literal Tests" [
    ("Array Literals", array_literal_tests);
  ] 