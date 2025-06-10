open Kernelscript
open Alcotest

(* Pretty printer for tokens *)
let pp_token fmt = function
  | Parser.PROGRAM -> Format.fprintf fmt "PROGRAM"
  | Parser.FN -> Format.fprintf fmt "FN"
  | Parser.MAP -> Format.fprintf fmt "MAP"
  | Parser.INT i -> Format.fprintf fmt "INT(%d)" i
  | Parser.STRING s -> Format.fprintf fmt "STRING(%s)" s
  | Parser.BOOL_LIT b -> Format.fprintf fmt "BOOL_LIT(%b)" b
  | Parser.PLUS -> Format.fprintf fmt "PLUS"
  | Parser.MINUS -> Format.fprintf fmt "MINUS"
  | Parser.MULTIPLY -> Format.fprintf fmt "MULTIPLY"
  | Parser.DIVIDE -> Format.fprintf fmt "DIVIDE"
  | Parser.IDENTIFIER id -> Format.fprintf fmt "IDENTIFIER(%s)" id
  | Parser.LBRACE -> Format.fprintf fmt "LBRACE"
  | Parser.RBRACE -> Format.fprintf fmt "RBRACE"
  | Parser.SEMICOLON -> Format.fprintf fmt "SEMICOLON"
  | Parser.COLON -> Format.fprintf fmt "COLON"
  | Parser.COMMA -> Format.fprintf fmt "COMMA"
  | Parser.LPAREN -> Format.fprintf fmt "LPAREN"
  | Parser.RPAREN -> Format.fprintf fmt "RPAREN"
  | Parser.LBRACKET -> Format.fprintf fmt "LBRACKET"
  | Parser.RBRACKET -> Format.fprintf fmt "RBRACKET"
  | Parser.ASSIGN -> Format.fprintf fmt "ASSIGN"
  | Parser.EQ -> Format.fprintf fmt "EQ"
  | Parser.NE -> Format.fprintf fmt "NE"
  | Parser.LT -> Format.fprintf fmt "LT"
  | Parser.LE -> Format.fprintf fmt "LE"
  | Parser.GT -> Format.fprintf fmt "GT"
  | Parser.GE -> Format.fprintf fmt "GE"
  | Parser.AND -> Format.fprintf fmt "AND"
  | Parser.OR -> Format.fprintf fmt "OR"
  | Parser.NOT -> Format.fprintf fmt "NOT"
  | Parser.IF -> Format.fprintf fmt "IF"
  | Parser.ELSE -> Format.fprintf fmt "ELSE"
  | Parser.WHILE -> Format.fprintf fmt "WHILE"
  | Parser.FOR -> Format.fprintf fmt "FOR"
  | Parser.RETURN -> Format.fprintf fmt "RETURN"
  | Parser.LET -> Format.fprintf fmt "LET"
  | Parser.DOT -> Format.fprintf fmt "DOT"
  | Parser.ARROW -> Format.fprintf fmt "ARROW"
  | Parser.EOF -> Format.fprintf fmt "EOF"
  | _ -> Format.fprintf fmt "OTHER_TOKEN"

let token_testable = testable pp_token (=)

let test_keywords () =
  let tokens = Lexer.tokenize_string "program fn map" in
  let expected = [Parser.PROGRAM; Parser.FN; Parser.MAP] in
  check (list token_testable) "keywords parsing" expected tokens

let test_literals () =
  let tokens = Lexer.tokenize_string "42 \"hello\" true" in
  let expected = [Parser.INT 42; Parser.STRING "hello"; Parser.BOOL_LIT true] in
  check (list token_testable) "literals parsing" expected tokens

let test_hex_literals () =
  let tokens = Lexer.tokenize_string "0xFF" in
  let expected = [Parser.INT 255] in
  check (list token_testable) "hex literals parsing" expected tokens

let test_operators () =
  let tokens = Lexer.tokenize_string "+ - * /" in
  let expected = [Parser.PLUS; Parser.MINUS; Parser.MULTIPLY; Parser.DIVIDE] in
  check (list token_testable) "operators parsing" expected tokens

let lexer_tests = [
  "keywords", `Quick, test_keywords;
  "literals", `Quick, test_literals; 
  "hex_literals", `Quick, test_hex_literals;
  "operators", `Quick, test_operators;
]

let () =
  run "KernelScript Lexer Tests" [
    "lexer", lexer_tests;
  ] 