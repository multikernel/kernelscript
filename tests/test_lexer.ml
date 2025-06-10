open Alcotest
open Kernelscript.Tokens
open Kernelscript.Lexer

let token_testable = testable (fun fmt -> function
  | PROGRAM -> Format.fprintf fmt "PROGRAM"
  | FN -> Format.fprintf fmt "FN"
  | MAP -> Format.fprintf fmt "MAP"
  | INT i -> Format.fprintf fmt "INT(%d)" i
  | STRING s -> Format.fprintf fmt "STRING(%s)" s
  | BOOL_LIT b -> Format.fprintf fmt "BOOL_LIT(%b)" b
  | CHAR_LIT c -> Format.fprintf fmt "CHAR_LIT(%c)" c
  | IDENTIFIER s -> Format.fprintf fmt "IDENTIFIER(%s)" s
  | PLUS -> Format.fprintf fmt "PLUS"
  | MINUS -> Format.fprintf fmt "MINUS"
  | MULTIPLY -> Format.fprintf fmt "MULTIPLY"
  | DIVIDE -> Format.fprintf fmt "DIVIDE"
  | MODULO -> Format.fprintf fmt "MODULO"
  | EQ -> Format.fprintf fmt "EQ"
  | NE -> Format.fprintf fmt "NE"
  | LT -> Format.fprintf fmt "LT"
  | LE -> Format.fprintf fmt "LE"
  | GT -> Format.fprintf fmt "GT"
  | GE -> Format.fprintf fmt "GE"
  | AND -> Format.fprintf fmt "AND"
  | OR -> Format.fprintf fmt "OR"
  | NOT -> Format.fprintf fmt "NOT"
  | LBRACE -> Format.fprintf fmt "LBRACE"
  | RBRACE -> Format.fprintf fmt "RBRACE"
  | LPAREN -> Format.fprintf fmt "LPAREN"
  | RPAREN -> Format.fprintf fmt "RPAREN"
  | LBRACKET -> Format.fprintf fmt "LBRACKET"
  | RBRACKET -> Format.fprintf fmt "RBRACKET"
  | SEMICOLON -> Format.fprintf fmt "SEMICOLON"
  | COMMA -> Format.fprintf fmt "COMMA"
  | DOT -> Format.fprintf fmt "DOT"
  | COLON -> Format.fprintf fmt "COLON"
  | ARROW -> Format.fprintf fmt "ARROW"
  | ASSIGN -> Format.fprintf fmt "ASSIGN"
  | XDP -> Format.fprintf fmt "XDP"
  | TC -> Format.fprintf fmt "TC"
  | KPROBE -> Format.fprintf fmt "KPROBE"
  | UPROBE -> Format.fprintf fmt "UPROBE"
  | TRACEPOINT -> Format.fprintf fmt "TRACEPOINT"
  | LSM -> Format.fprintf fmt "LSM"
  | U8 -> Format.fprintf fmt "U8"
  | U16 -> Format.fprintf fmt "U16"
  | U32 -> Format.fprintf fmt "U32"
  | U64 -> Format.fprintf fmt "U64"
  | I8 -> Format.fprintf fmt "I8"
  | I16 -> Format.fprintf fmt "I16"
  | I32 -> Format.fprintf fmt "I32"
  | I64 -> Format.fprintf fmt "I64"
  | BOOL -> Format.fprintf fmt "BOOL"
  | CHAR -> Format.fprintf fmt "CHAR"
  | IF -> Format.fprintf fmt "IF"
  | ELSE -> Format.fprintf fmt "ELSE"
  | FOR -> Format.fprintf fmt "FOR"
  | WHILE -> Format.fprintf fmt "WHILE"
  | RETURN -> Format.fprintf fmt "RETURN"
  | BREAK -> Format.fprintf fmt "BREAK"
  | CONTINUE -> Format.fprintf fmt "CONTINUE"
  | LET -> Format.fprintf fmt "LET"
  | MUT -> Format.fprintf fmt "MUT"
  | PUB -> Format.fprintf fmt "PUB"
  | PRIV -> Format.fprintf fmt "PRIV"
  | CONFIG -> Format.fprintf fmt "CONFIG"
  | USERSPACE -> Format.fprintf fmt "USERSPACE"
  | _ -> Format.fprintf fmt "UNKNOWN"
) (=)

let test_keywords () =
  let tokens = tokenize_string "program fn map" in
  check (list token_testable) "keywords" [PROGRAM; FN; MAP] tokens

let test_literals () =
  let tokens = tokenize_string "42 \"hello\" true" in
  check (list token_testable) "literals" [INT 42; STRING "hello"; BOOL_LIT true] tokens

let test_hex_literals () =
  let tokens = tokenize_string "0xFF" in
  check (list token_testable) "hex literals" [INT 255] tokens

let test_binary_literals () =
  let tokens = tokenize_string "0b1010" in
  check (list token_testable) "binary literals" [INT 10] tokens

let test_string_literals () =
  let tokens = tokenize_string "\"hello world\"" in
  check (list token_testable) "string literals" [STRING "hello world"] tokens

let test_string_escapes () =
  let tokens = tokenize_string "\"hello\\nworld\\t\"" in
  check (list token_testable) "string escapes" [STRING "hello\nworld\t"] tokens

let test_char_literals () =
  let tokens = tokenize_string "'a' '\\n' '\\x41'" in
  check (list token_testable) "char literals" [CHAR_LIT 'a'; CHAR_LIT '\n'; CHAR_LIT 'A'] tokens

let test_identifiers () =
  let tokens = tokenize_string "variable_name function123 CamelCase" in
  check (list token_testable) "identifiers" [IDENTIFIER "variable_name"; IDENTIFIER "function123"; IDENTIFIER "CamelCase"] tokens

let test_operators () =
  let tokens = tokenize_string "+ - * / % == != < <= > >= && || !" in
  check (list token_testable) "operators" [PLUS; MINUS; MULTIPLY; DIVIDE; MODULO; EQ; NE; LT; LE; GT; GE; AND; OR; NOT] tokens

let test_punctuation () =
  let tokens = tokenize_string "{ } ( ) [ ] ; , . : -> =" in
  check (list token_testable) "punctuation" [LBRACE; RBRACE; LPAREN; RPAREN; LBRACKET; RBRACKET; SEMICOLON; COMMA; DOT; COLON; ARROW; ASSIGN] tokens

let test_program_types () =
  let tokens = tokenize_string "xdp tc kprobe uprobe tracepoint lsm" in
  check (list token_testable) "program types" [XDP; TC; KPROBE; UPROBE; TRACEPOINT; LSM] tokens

let test_primitive_types () =
  let tokens = tokenize_string "u8 u16 u32 u64 i8 i16 i32 i64 bool char" in
  check (list token_testable) "primitive types" [U8; U16; U32; U64; I8; I16; I32; I64; BOOL; CHAR] tokens

let test_control_flow () =
  let tokens = tokenize_string "if else for while return break continue" in
  check (list token_testable) "control flow" [IF; ELSE; FOR; WHILE; RETURN; BREAK; CONTINUE] tokens

let test_variable_keywords () =
  let tokens = tokenize_string "let mut pub priv config userspace" in
  check (list token_testable) "variable keywords" [LET; MUT; PUB; PRIV; CONFIG; USERSPACE] tokens

let test_line_comments () =
  let tokens = tokenize_string "program // this is a comment\nfn" in
  check (list token_testable) "line comments" [PROGRAM; FN] tokens



let test_whitespace_handling () =
  let tokens = tokenize_string "  program   \t\n  fn  " in
  check (list token_testable) "whitespace handling" [PROGRAM; FN] tokens

let test_complex_program () =
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
  check (list token_testable) "complex program" expected tokens

let test_mixed_literals () =
  let tokens = tokenize_string "0xFF 255 0b11111111 true false \"test\" 'c'" in
  check (list token_testable) "mixed literals" [INT 255; INT 255; INT 255; BOOL_LIT true; BOOL_LIT false; STRING "test"; CHAR_LIT 'c'] tokens



let test_error_handling () =
  let test_cases = [
    ("@", "Unexpected character");
    ("\"unterminated", "Unterminated string");
    ("''", "Empty character literal");
  ] in
  
  List.iter (fun (code, expected_msg) ->
    try
      let _ = tokenize_string code in
      fail ("Expected lexer error: " ^ expected_msg)
    with
    | Lexer_error msg -> 
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
  "program_types", `Quick, test_program_types;
  "primitive_types", `Quick, test_primitive_types;
  "control_flow", `Quick, test_control_flow;
  "variable_keywords", `Quick, test_variable_keywords;
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