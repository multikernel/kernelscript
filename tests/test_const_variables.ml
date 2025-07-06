open Alcotest
open Kernelscript.Ast
open Kernelscript.Parse

let dummy_pos = { line = 1; column = 1; filename = "test" }

let parse_program_string s =
  parse_string s

let test_valid_const_declaration () =
  let program_text = {|
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      const MAX_SIZE: u32 = 1500
      const MIN_SIZE: u16 = 64
      const THRESHOLD = 100
      return 2
    }
  |} in
  try
    let ast = parse_program_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "valid const declaration" true true
  with
  | e -> fail ("Valid const declaration failed: " ^ Printexc.to_string e)

let test_const_assignment_error () =
  let program_text = {|
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      const MAX_SIZE: u32 = 1500
      MAX_SIZE = 2000
      return 2
    }
  |} in
  try
    let ast = parse_program_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    fail "Should have failed with const assignment error"
  with
  | Kernelscript.Type_checker.Type_error ("Cannot assign to const variable: MAX_SIZE", _) ->
    check bool "const assignment error" true true
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

let test_const_integer_types_only () =
  let program_text = {|
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      const name: str<16> = "test"
      return 2
    }
  |} in
  try
    let ast = parse_program_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    fail "Should have failed with const string type error"
  with
  | Kernelscript.Type_checker.Type_error ("Const variables can only be integer types", _) ->
    check bool "const integer types only" true true
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

let test_const_must_be_literal () =
  let program_text = {|
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      var x = 10
      const MAX_SIZE: u32 = x
      return 2
    }
  |} in
  try
    let ast = parse_program_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    fail "Should have failed with const literal requirement error"
  with
  | Kernelscript.Type_checker.Type_error ("Const variable must be initialized with a literal value", _) ->
    check bool "const must be literal" true true
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

let test_const_type_inference () =
  let program_text = {|
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      const SMALL_VALUE = 10  // Should infer u32
      const BIG_VALUE = 0xFFFFFFFF  // Should infer u32
      return 2
    }
  |} in
  try
    let ast = parse_program_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "const type inference" true true
  with
  | e -> fail ("Const type inference failed: " ^ Printexc.to_string e)

let test_const_in_userspace () =
  let program_text = {|
    fn main() -> i32 {
      const DEFAULT_PORT: u16 = 8080
      const MAX_CONNECTIONS = 1000
      return 0
    }
  |} in
  try
    let ast = parse_program_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "const in userspace" true true
  with
  | e -> fail ("Const in userspace failed: " ^ Printexc.to_string e)

let test_const_with_different_integer_types () =
  let program_text = {|
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      const BYTE_VAL: u8 = 255
      const SHORT_VAL: u16 = 65535
      const INT_VAL: u32 = 429496729
      const LONG_VAL: u64 = 1844674407
      const SIGNED_BYTE: i8 = -128
      const SIGNED_SHORT: i16 = -32768
      const SIGNED_INT: i32 = -214748364
      const SIGNED_LONG: i64 = -92233720368
      return 2
    }
  |} in
  try
    let ast = parse_program_string program_text in
    let _ = Kernelscript.Symbol_table.build_symbol_table ast in
    let (_enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    check bool "const with different integer types" true true
  with
  | e -> fail ("Const with different integer types failed: " ^ Printexc.to_string e)

let const_variable_tests = [
  ("valid_const_declaration", `Quick, test_valid_const_declaration);
  ("const_assignment_error", `Quick, test_const_assignment_error);
  ("const_integer_types_only", `Quick, test_const_integer_types_only);
  ("const_must_be_literal", `Quick, test_const_must_be_literal);
  ("const_type_inference", `Quick, test_const_type_inference);
  ("const_in_userspace", `Quick, test_const_in_userspace);
  ("const_different_integer_types", `Quick, test_const_with_different_integer_types);
]

let () =
  Alcotest.run "Const Variables Tests" [
    ("const_variables", const_variable_tests);
  ] 