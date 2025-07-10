open Alcotest
open Kernelscript.Ast
open Kernelscript.Type_checker

(* Helper function to parse and type check a program *)
let parse_and_type_check source =
  let lexbuf = Lexing.from_string source in
  let ast = Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf in
  let empty_symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context empty_symbol_table ast in
  (* For basic tests, we'll test individual expressions *)
  match ast with
  | [AttributedFunction attr_func] ->
      (* Type check the attributed function *)
      let typed_func = type_check_function ctx attr_func.attr_function in
      (ctx, typed_func)
  | _ -> failwith "Expected single attributed function"

(* Test str<N> type parsing *)
let test_string_type_parsing _ =
  let program_text = {|
    @xdp fn test(ctx: *xdp_md) -> i32 {
      var name: str(16) = "hello"
      var message: str(64) = "world"
      var large_buffer: str(512) = "large message"
      return 0
    }
  |} in
  
  let lexbuf = Lexing.from_string program_text in
  let ast = Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf in
  
  (* Verify that the AST contains the string types *)
  match ast with
  | [AttributedFunction attr_func] ->
      (match attr_func.attr_function.func_body with
       | [{stmt_desc = Declaration ("name", Some (Str 16), _); _}; 
          {stmt_desc = Declaration ("message", Some (Str 64), _); _};
          {stmt_desc = Declaration ("large_buffer", Some (Str 512), _); _};
          _] -> () (* Success *)
       | _ -> fail "String type declarations not parsed correctly")
  | _ -> fail "Expected single attributed function"

(* Test string concatenation type checking *)
let test_string_concatenation _ =
  let program_text = {|
    @xdp fn test(ctx: *xdp_md) -> i32 {
      var first: str(10) = "hello"
      var second: str(10) = "world"
      var result: str(20) = first + second
      return 0
    }
  |} in
  
  try
    let (_ctx, _typed_prog) = parse_and_type_check program_text in
    (* If we get here without exception, type checking passed *)
    check bool "String concatenation type checking passed" true true
  with
  | Type_error (msg, _) -> 
      fail ("String concatenation failed: " ^ msg)
  | e -> 
      fail ("Unexpected error: " ^ Printexc.to_string e)

(* Test string equality comparison *)
let test_string_equality _ =
  let program_text = {|
    @xdp fn test(ctx: *xdp_md) -> i32 {
      var name: str(16) = "test"
      var other: str(16) = "other"
      if (name == "test") {
        return 1
      }
      if (name != other) {
        return 2
      }
      return 0
    }
  |} in
  
  try
    let (_ctx, _typed_prog) = parse_and_type_check program_text in
    check bool "String equality comparison type checking passed" true true
  with
  | Type_error (msg, _) -> 
      fail ("String equality failed: " ^ msg)
  | e -> 
      fail ("Unexpected error: " ^ Printexc.to_string e)

(* Test string indexing *)
let test_string_indexing _ =
  let program_text = {|
    @xdp fn test(ctx: *xdp_md) -> i32 {
      var name: str(16) = "hello"
      var first_char: char = name[0]
      var second_char: char = name[1]
      return 0
    }
  |} in
  
  try
    let (_ctx, _typed_prog) = parse_and_type_check program_text in
    check bool "String indexing type checking passed" true true
  with
  | Type_error (msg, _) -> 
      fail ("String indexing failed: " ^ msg)
  | e -> 
      fail ("Unexpected error: " ^ Printexc.to_string e)

(* Test invalid string operations *)
let test_invalid_string_operations _ =
  (* Test ordering comparison (should fail) *)
  let program_text = {|
    @xdp fn test(ctx: *xdp_md) -> i32 {
      var first: str(10) = "hello"
      var second: str(10) = "world"
      if (first < second) {
        return 1
      }
      return 0
    }
  |} in
  
  (try
    let (_ctx, _typed_prog) = parse_and_type_check program_text in
    fail "Should have failed on string ordering comparison"
  with
  | Type_error (msg, _) when String.contains msg '<' -> 
      check bool "Correctly rejected string ordering comparison" true true
  | _ -> 
      fail "Wrong error for string ordering comparison")

(* Test string assignment compatibility *)
let test_string_assignment _ =
  let program_text = {|
    @xdp fn test(ctx: *xdp_md) -> i32 {
      var buffer: str(32) = "initial"
      var small: str(16) = "small"
      buffer = small
      return 0
    }
  |} in
  
  try
    let (_ctx, _typed_prog) = parse_and_type_check program_text in
    check bool "String assignment type checking passed" true true
  with
  | Type_error (msg, _) -> 
      fail ("String assignment failed: " ^ msg)
  | e -> 
      fail ("Unexpected error: " ^ Printexc.to_string e)

(* Test arbitrary string sizes *)
let test_arbitrary_string_sizes _ =
  let program_text = {|
    @xdp fn test(ctx: *xdp_md) -> i32 {
      var tiny: str(1) = "a"
      var small: str(7) = "small"
      var medium: str(42) = "answer"
      var large: str(1000) = "very long text"
      return 0
    }
  |} in
  
  try
    let (_ctx, _typed_prog) = parse_and_type_check program_text in
    check bool "Arbitrary string sizes type checking passed" true true
  with
  | Type_error (msg, _) -> 
      fail ("Arbitrary string sizes failed: " ^ msg)
  | e -> 
      fail ("Unexpected error: " ^ Printexc.to_string e)

(* Test suite *)
let tests = [
  test_case "String type parsing" `Quick test_string_type_parsing;
  test_case "String concatenation" `Quick test_string_concatenation;
  test_case "String equality" `Quick test_string_equality;
  test_case "String indexing" `Quick test_string_indexing;
  test_case "Invalid string operations" `Quick test_invalid_string_operations;
  test_case "String assignment" `Quick test_string_assignment;
  test_case "Arbitrary string sizes" `Quick test_arbitrary_string_sizes;
]

let () = run "String Type Tests" [
  "String operations", tests;
] 