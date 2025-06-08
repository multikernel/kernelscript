open OUnit2
open Kernelscript.Tokens
open Kernelscript.Lexer

let test_keywords _ =
  let tokens = tokenize_string "program fn map" in
  assert_equal [PROGRAM; FN; MAP] tokens

let test_literals _ =
  let tokens = tokenize_string "42 \"hello\" true" in
  assert_equal [INT 42; STRING "hello"; BOOL_LIT true] tokens

let test_hex_literals _ =
  let tokens = tokenize_string "0xFF" in
  assert_equal [INT 255] tokens

let test_binary_literals _ =
  let tokens = tokenize_string "0b1010" in
  assert_equal [INT 10] tokens

let test_string_literals _ =
  let tokens = tokenize_string "\"hello world\"" in
  assert_equal [STRING "hello world"] tokens

let test_string_escapes _ =
  let tokens = tokenize_string "\"hello\\nworld\\t\"" in
  assert_equal [STRING "hello\nworld\t"] tokens

let test_char_literals _ =
  let tokens = tokenize_string "'a' '\\n' '\\x41'" in
  assert_equal [CHAR_LIT 'a'; CHAR_LIT '\n'; CHAR_LIT 'A'] tokens

let test_identifiers _ =
  let tokens = tokenize_string "variable_name function123 CamelCase" in
  assert_equal [IDENTIFIER "variable_name"; IDENTIFIER "function123"; IDENTIFIER "CamelCase"] tokens

let test_operators _ =
  let tokens = tokenize_string "+ - * / % == != < <= > >= && || !" in
  assert_equal [PLUS; MINUS; MULTIPLY; DIVIDE; MODULO; EQ; NE; LT; LE; GT; GE; AND; OR; NOT] tokens

let test_punctuation _ =
  let tokens = tokenize_string "{ } ( ) [ ] ; , . : -> =" in
  assert_equal [LBRACE; RBRACE; LPAREN; RPAREN; LBRACKET; RBRACKET; SEMICOLON; COMMA; DOT; COLON; ARROW; ASSIGN] tokens

let test_program_types _ =
  let tokens = tokenize_string "xdp tc kprobe uprobe tracepoint lsm" in
  assert_equal [XDP; TC; KPROBE; UPROBE; TRACEPOINT; LSM] tokens

let test_primitive_types _ =
  let tokens = tokenize_string "u8 u16 u32 u64 i8 i16 i32 i64 bool char" in
  assert_equal [U8; U16; U32; U64; I8; I16; I32; I64; BOOL; CHAR] tokens

let test_control_flow _ =
  let tokens = tokenize_string "if else for while return break continue" in
  assert_equal [IF; ELSE; FOR; WHILE; RETURN; BREAK; CONTINUE] tokens

let test_variable_keywords _ =
  let tokens = tokenize_string "let mut pub priv config userspace" in
  assert_equal [LET; MUT; PUB; PRIV; CONFIG; USERSPACE] tokens

let test_line_comments _ =
  let tokens = tokenize_string "program // this is a comment\nfn" in
  assert_equal [PROGRAM; FN] tokens

let test_block_comments _ =
  let tokens = tokenize_string "program /* this is a\n   block comment */ fn" in
  assert_equal [PROGRAM; FN] tokens

let test_whitespace_handling _ =
  let tokens = tokenize_string "  program   \t\n  fn  " in
  assert_equal [PROGRAM; FN] tokens

let test_complex_program _ =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        let x = 42;
        return XdpAction::Pass;
      }
    }
  |} in
  let tokens = tokenize_string code in
  let expected = [
    PROGRAM; IDENTIFIER "test"; COLON; XDP; LBRACE;
    FN; IDENTIFIER "main"; LPAREN; IDENTIFIER "ctx"; COLON;
    IDENTIFIER "XdpContext"; RPAREN; ARROW; IDENTIFIER "XdpAction"; LBRACE;
    LET; IDENTIFIER "x"; ASSIGN; INT 42; SEMICOLON;
    RETURN; IDENTIFIER "XdpAction"; COLON; COLON; IDENTIFIER "Pass"; SEMICOLON;
    RBRACE;
    RBRACE
  ] in
  assert_equal expected tokens

let test_mixed_literals _ =
  let tokens = tokenize_string "0xFF 255 0b11111111 true false \"test\" 'c'" in
  assert_equal [INT 255; INT 255; INT 255; BOOL_LIT true; BOOL_LIT false; STRING "test"; CHAR_LIT 'c'] tokens

let test_nested_block_comments _ =
  let tokens = tokenize_string "program /* outer /* inner */ still outer */ fn" in
  assert_equal [PROGRAM; FN] tokens

let test_error_handling _ =
  let test_lexer_error code expected_msg =
    try
      let _ = tokenize_string code in
      assert_failure ("Expected lexer error: " ^ expected_msg)
    with
    | Lexer_error msg -> assert_bool ("Error message should contain: " ^ expected_msg) (String.contains msg (String.get expected_msg 0))
    | _ -> assert_failure "Expected Lexer_error"
  in
  test_lexer_error "@" "Unexpected character";
  test_lexer_error "\"unterminated" "Unterminated string";
  test_lexer_error "''" "Empty character literal";
  test_lexer_error "/* unterminated" "Unterminated block comment"

let suite =
  "Lexer tests" >::: [
    "test_keywords" >:: test_keywords;
    "test_literals" >:: test_literals;
    "test_hex_literals" >:: test_hex_literals;
    "test_binary_literals" >:: test_binary_literals;
    "test_string_literals" >:: test_string_literals;
    "test_string_escapes" >:: test_string_escapes;
    "test_char_literals" >:: test_char_literals;
    "test_identifiers" >:: test_identifiers;
    "test_operators" >:: test_operators;
    "test_punctuation" >:: test_punctuation;
    "test_program_types" >:: test_program_types;
    "test_primitive_types" >:: test_primitive_types;
    "test_control_flow" >:: test_control_flow;
    "test_variable_keywords" >:: test_variable_keywords;
    "test_line_comments" >:: test_line_comments;
    "test_block_comments" >:: test_block_comments;
    "test_whitespace_handling" >:: test_whitespace_handling;
    "test_complex_program" >:: test_complex_program;
    "test_mixed_literals" >:: test_mixed_literals;
    "test_nested_block_comments" >:: test_nested_block_comments;
    "test_error_handling" >:: test_error_handling;
  ]

let () = run_test_tt_main suite 