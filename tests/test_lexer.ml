open Alcotest
open Kernelscript

let token_testable = testable (fun fmt -> function
  | Parser.PROGRAM -> Format.fprintf fmt "PROGRAM"
  | Parser.FN -> Format.fprintf fmt "FN"
  | Parser.MAP -> Format.fprintf fmt "MAP"
  | Parser.INT (i, _) -> Format.fprintf fmt "INT(%d)" i
  | Parser.STRING s -> Format.fprintf fmt "STRING(%s)" s
  | Parser.BOOL_LIT b -> Format.fprintf fmt "BOOL_LIT(%b)" b
  | Parser.CHAR_LIT c -> Format.fprintf fmt "CHAR_LIT(%c)" c
  | Parser.IDENTIFIER s -> Format.fprintf fmt "IDENTIFIER(%s)" s
  | Parser.PLUS -> Format.fprintf fmt "PLUS"
  | Parser.MINUS -> Format.fprintf fmt "MINUS"
  | Parser.MULTIPLY -> Format.fprintf fmt "MULTIPLY"
  | Parser.DIVIDE -> Format.fprintf fmt "DIVIDE"
  | Parser.MODULO -> Format.fprintf fmt "MODULO"
  | Parser.EQ -> Format.fprintf fmt "EQ"
  | Parser.NE -> Format.fprintf fmt "NE"
  | Parser.LT -> Format.fprintf fmt "LT"
  | Parser.LE -> Format.fprintf fmt "LE"
  | Parser.GT -> Format.fprintf fmt "GT"
  | Parser.GE -> Format.fprintf fmt "GE"
  | Parser.AND -> Format.fprintf fmt "AND"
  | Parser.OR -> Format.fprintf fmt "OR"
  | Parser.NOT -> Format.fprintf fmt "NOT"
  | Parser.LBRACE -> Format.fprintf fmt "LBRACE"
  | Parser.RBRACE -> Format.fprintf fmt "RBRACE"
  | Parser.LPAREN -> Format.fprintf fmt "LPAREN"
  | Parser.RPAREN -> Format.fprintf fmt "RPAREN"
  | Parser.LBRACKET -> Format.fprintf fmt "LBRACKET"
  | Parser.RBRACKET -> Format.fprintf fmt "RBRACKET"
  | Parser.COMMA -> Format.fprintf fmt "COMMA"
  | Parser.DOT -> Format.fprintf fmt "DOT"
  | Parser.COLON -> Format.fprintf fmt "COLON"
  | Parser.ARROW -> Format.fprintf fmt "ARROW"
  | Parser.ASSIGN -> Format.fprintf fmt "ASSIGN"
  | Parser.U8 -> Format.fprintf fmt "U8"
  | Parser.U16 -> Format.fprintf fmt "U16"
  | Parser.U32 -> Format.fprintf fmt "U32"
  | Parser.U64 -> Format.fprintf fmt "U64"
  | Parser.I8 -> Format.fprintf fmt "I8"
  | Parser.I16 -> Format.fprintf fmt "I16"
  | Parser.I32 -> Format.fprintf fmt "I32"
  | Parser.I64 -> Format.fprintf fmt "I64"
  | Parser.BOOL -> Format.fprintf fmt "BOOL"
  | Parser.CHAR -> Format.fprintf fmt "CHAR"
  | Parser.IF -> Format.fprintf fmt "IF"
  | Parser.ELSE -> Format.fprintf fmt "ELSE"
  | Parser.FOR -> Format.fprintf fmt "FOR"
  | Parser.WHILE -> Format.fprintf fmt "WHILE"
  | Parser.RETURN -> Format.fprintf fmt "RETURN"
  | Parser.BREAK -> Format.fprintf fmt "BREAK"
  | Parser.CONTINUE -> Format.fprintf fmt "CONTINUE"
  | Parser.LET -> Format.fprintf fmt "LET"
  | Parser.CONFIG -> Format.fprintf fmt "CONFIG"
  | Parser.EOF -> Format.fprintf fmt "EOF"
  | _ -> Format.fprintf fmt "OTHER_TOKEN"
) (=)

let test_keywords () =
  let tokens = Lexer.tokenize_string "program fn map" in
  check (list token_testable) "keywords" [Parser.PROGRAM; Parser.FN; Parser.MAP] tokens

let test_literals () =
  let tokens = Lexer.tokenize_string "42 \"hello\" true" in
  check (list token_testable) "literals" [Parser.INT (42, None); Parser.STRING "hello"; Parser.BOOL_LIT true] tokens

let test_hex_literals () =
  let tokens = Lexer.tokenize_string "0xFF" in
  check (list token_testable) "hex literals" [Parser.INT (255, Some "0xFF")] tokens

let test_binary_literals () =
  let tokens = Lexer.tokenize_string "0b1010" in
  check (list token_testable) "binary literals" [Parser.INT (10, Some "0b1010")] tokens

let test_string_literals () =
  let tokens = Lexer.tokenize_string "\"hello world\"" in
  check (list token_testable) "string literals" [Parser.STRING "hello world"] tokens

let test_string_escapes () =
  let tokens = Lexer.tokenize_string "\"hello\\nworld\\t\"" in
  check (list token_testable) "string escapes" [Parser.STRING "hello\nworld\t"] tokens

let test_char_literals () =
  let tokens = Lexer.tokenize_string "'a' '\\n' '\\x41'" in
  check (list token_testable) "char literals" [Parser.CHAR_LIT 'a'; Parser.CHAR_LIT '\n'; Parser.CHAR_LIT 'A'] tokens

let test_identifiers () =
  let tokens = Lexer.tokenize_string "variable_name function123 CamelCase" in
  check (list token_testable) "identifiers" [Parser.IDENTIFIER "variable_name"; Parser.IDENTIFIER "function123"; Parser.IDENTIFIER "CamelCase"] tokens

let test_operators () =
  let tokens = Lexer.tokenize_string "+ - * / % == != < <= > >= && || !" in
  check (list token_testable) "operators" [Parser.PLUS; Parser.MINUS; Parser.MULTIPLY; Parser.DIVIDE; Parser.MODULO; Parser.EQ; Parser.NE; Parser.LT; Parser.LE; Parser.GT; Parser.GE; Parser.AND; Parser.OR; Parser.NOT] tokens

let test_punctuation () =
  let tokens = Lexer.tokenize_string "{ } ( ) [ ] , . : -> =" in
  check (list token_testable) "punctuation" [Parser.LBRACE; Parser.RBRACE; Parser.LPAREN; Parser.RPAREN; Parser.LBRACKET; Parser.RBRACKET; Parser.COMMA; Parser.DOT; Parser.COLON; Parser.ARROW; Parser.ASSIGN] tokens

let test_primitive_types () =
  let tokens = Lexer.tokenize_string "u8 u16 u32 u64 i8 i16 i32 i64 bool char" in
  check (list token_testable) "primitive types" [Parser.U8; Parser.U16; Parser.U32; Parser.U64; Parser.I8; Parser.I16; Parser.I32; Parser.I64; Parser.BOOL; Parser.CHAR] tokens

let test_control_flow () =
  let tokens = Lexer.tokenize_string "if else for while return break continue" in
  check (list token_testable) "control flow" [Parser.IF; Parser.ELSE; Parser.FOR; Parser.WHILE; Parser.RETURN; Parser.BREAK; Parser.CONTINUE] tokens

let test_variable_keywords () =
  let tokens = Lexer.tokenize_string "let config" in
  check (list token_testable) "variable keywords" [Parser.LET; Parser.CONFIG] tokens

let test_line_comments () =
  let tokens = Lexer.tokenize_string "program // this is a comment\nfn" in
  check (list token_testable) "line comments" [Parser.PROGRAM; Parser.FN] tokens

let test_whitespace_handling () =
  let tokens = Lexer.tokenize_string "  program   \t\n  fn  " in
  check (list token_testable) "whitespace handling" [Parser.PROGRAM; Parser.FN] tokens

let test_program_types_as_identifiers () =
  let tokens = Lexer.tokenize_string "xdp tc kprobe uprobe tracepoint lsm" in
  check (list token_testable) "program types as identifiers" [
    Parser.IDENTIFIER "xdp"; Parser.IDENTIFIER "tc"; Parser.IDENTIFIER "kprobe"; 
    Parser.IDENTIFIER "uprobe"; Parser.IDENTIFIER "tracepoint"; Parser.IDENTIFIER "lsm"
  ] tokens

let test_complex_program () =
  let code = {|
    program test : xdp {
      fn main() {
        let x = 42
        return x
      }
    }
  |} in
  let tokens = Lexer.tokenize_string code in
  let expected = [
    Parser.PROGRAM; Parser.IDENTIFIER "test"; Parser.COLON; Parser.IDENTIFIER "xdp"; Parser.LBRACE;
    Parser.FN; Parser.IDENTIFIER "main"; Parser.LPAREN; Parser.RPAREN; Parser.LBRACE;
    Parser.LET; Parser.IDENTIFIER "x"; Parser.ASSIGN; Parser.INT (42, None);
    Parser.RETURN; Parser.IDENTIFIER "x";
    Parser.RBRACE;
    Parser.RBRACE
  ] in
  check (list token_testable) "complex program" expected tokens

let test_mixed_literals () =
  let tokens = Lexer.tokenize_string "0xFF 255 0b11111111 true false \"test\" 'c'" in
  check (list token_testable) "mixed literals" [
    Parser.INT (255, Some "0xFF"); Parser.INT (255, None); Parser.INT (255, Some "0b11111111"); 
    Parser.BOOL_LIT true; Parser.BOOL_LIT false; Parser.STRING "test"; Parser.CHAR_LIT 'c'
  ] tokens

let test_error_handling () =
  let test_cases = [
    ("@", "Unexpected character");
    ("\"unterminated", "Unterminated string");
    ("''", "Empty character literal");
  ] in
  
  List.iter (fun (code, expected_msg) ->
    try
      let _ = Lexer.tokenize_string code in
      fail ("Expected lexer error: " ^ expected_msg)
    with
    | Lexer.Lexer_error msg -> 
        check bool ("Error handling: " ^ expected_msg) true 
          (String.length msg > 0)  (* Just check that we got some error message *)
    | _ -> fail "Expected Lexer_error"
  ) test_cases

let lexer_tests = [
  "keywords", `Quick, test_keywords;
  "literals", `Quick, test_literals;
  "hex_literals", `Quick, test_hex_literals;
  "binary_literals", `Quick, test_binary_literals;
  "string_literals", `Quick, test_string_literals;
  "string_escapes", `Quick, test_string_escapes;
  "char_literals", `Quick, test_char_literals;
  "identifiers", `Quick, test_identifiers;
  "operators", `Quick, test_operators;
  "punctuation", `Quick, test_punctuation;
  "primitive_types", `Quick, test_primitive_types;
  "control_flow", `Quick, test_control_flow;
  "variable_keywords", `Quick, test_variable_keywords;
  "program_types_as_identifiers", `Quick, test_program_types_as_identifiers;
  "line_comments", `Quick, test_line_comments;
  "whitespace_handling", `Quick, test_whitespace_handling;
  "complex_program", `Quick, test_complex_program;
  "mixed_literals", `Quick, test_mixed_literals;
  "error_handling", `Quick, test_error_handling;
]

let () =
  run "KernelScript Lexer Tests" [
    "lexer", lexer_tests;
  ] 