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

{
  open Parser
  
  exception Lexer_error of string

  let create_lexer_error msg =
    raise (Lexer_error msg)

  let current_line = ref 1
  let current_col = ref 1
  
  let next_line () =
    incr current_line;
    current_col := 1

  let next_col () =
    incr current_col

  let string_of_char c =
    String.make 1 c

  let char_for_backslash = function
    | 'n' -> '\n'
    | 't' -> '\t'
    | 'r' -> '\r'
    | '\\' -> '\\'
    | '\'' -> '\''
    | '"' -> '"'
    | '0' -> '\000'
    | c -> c

  let parse_hex_literal s =
    let s = String.sub s 2 (String.length s - 2) in (* Remove "0x" or "0X" *)
    let rec aux i acc =
      if i >= String.length s then acc
      else
        match s.[i] with
        | '0'..'9' as c -> aux (i+1) (Int64.add (Int64.mul acc 16L) (Int64.of_int (Char.code c - Char.code '0')))
        | 'a'..'f' as c -> aux (i+1) (Int64.add (Int64.mul acc 16L) (Int64.of_int (Char.code c - Char.code 'a' + 10)))
        | 'A'..'F' as c -> aux (i+1) (Int64.add (Int64.mul acc 16L) (Int64.of_int (Char.code c - Char.code 'A' + 10)))
        | _ -> create_lexer_error ("Invalid hex literal: " ^ s)
    in
    let raw_val = aux 0 0L in
    (* Hex literals are typically unsigned in C-like languages *)
    if Int64.compare raw_val 0L < 0 then Ast.Unsigned64 raw_val else Ast.Signed64 raw_val

  let parse_binary_literal s =
    let s = String.sub s 2 (String.length s - 2) in (* Remove "0b" or "0B" *)
    let rec aux i acc =
      if i >= String.length s then acc
      else
        match s.[i] with
        | '0' -> aux (i+1) (Int64.mul acc 2L)
        | '1' -> aux (i+1) (Int64.add (Int64.mul acc 2L) 1L)
        | _ -> create_lexer_error ("Invalid binary literal: " ^ s)
    in
    let raw_val = aux 0 0L in
    (* Binary literals are typically unsigned in C-like languages *)
    if Int64.compare raw_val 0L < 0 then Ast.Unsigned64 raw_val else Ast.Signed64 raw_val

  let lookup_keyword = function
    | "fn" -> FN
    | "extern" -> EXTERN
    | "include" -> INCLUDE
    | "pin" -> PIN
    | "type" -> TYPE
    | "struct" -> STRUCT
    | "enum" -> ENUM
    | "impl" -> IMPL
    (* Program types are now parsed as identifiers and resolved semantically *)
    | "u8" -> U8
    | "u16" -> U16
    | "u32" -> U32
    | "u64" -> U64
    | "i8" -> I8
    | "i16" -> I16
    | "i32" -> I32
    | "i64" -> I64
    | "bool" -> BOOL
    | "char" -> CHAR
    | "void" -> VOID
    | "str" -> STR
    | "if" -> IF
    | "else" -> ELSE
    | "for" -> FOR
    | "while" -> WHILE
    | "return" -> RETURN
    | "break" -> BREAK
    | "continue" -> CONTINUE
    | "var" -> VAR
    | "const" -> CONST
    | "config" -> CONFIG
    | "local" -> LOCAL
    | "in" -> IN
    | "new" -> NEW
    | "delete" -> DELETE
    | "try" -> TRY
    | "catch" -> CATCH
    | "throw" -> THROW
    | "defer" -> DEFER
    | "match" -> MATCH
    | "default" -> DEFAULT
    | "import" -> IMPORT
    | "from" -> FROM
    
    | "true" -> BOOL_LIT true
    | "false" -> BOOL_LIT false
    | "null" -> NULL
    | "none" -> NONE
    | id -> IDENTIFIER id
}

let whitespace = [' ' '\t']
let newline = '\r' | '\n' | "\r\n"
let letter = ['a'-'z' 'A'-'Z']
let digit = ['0'-'9']
let identifier = (letter | '_') (letter | digit | '_')*

let decimal_literal = digit+
let hex_literal = '0' ['x' 'X'] ['0'-'9' 'a'-'f' 'A'-'F']+
let binary_literal = '0' ['b' 'B'] ['0' '1']+

rule token = parse
  | whitespace+ { token lexbuf }
  | newline { Lexing.new_line lexbuf; token lexbuf }
  
  (* Comments *)
  | "//" [^ '\r' '\n']* { token lexbuf }
  
  (* Literals *)
  | decimal_literal as lit { 
      try
        let int_val = Ast.IntegerValue.of_string lit in
        INT (int_val, None)
      with Failure msg ->
        create_lexer_error msg
    }
  | hex_literal as lit { INT (parse_hex_literal lit, Some lit) }
  | binary_literal as lit { INT (parse_binary_literal lit, Some lit) }
  
  (* String literals *)
  | '"' { string_literal (Buffer.create 256) lexbuf }
  
  (* Character literals *)
  | '\'' { char_literal lexbuf }
  
  (* Identifiers and keywords *)
  | identifier as id { lookup_keyword id }
  
  (* Two-character operators *)
  | "->" { ARROW }
  | "==" { EQ }
  | "!=" { NE }
  | "<=" { LE }
  | ">=" { GE }
  | "&&" { AND }
  | "||" { OR }
  | "+=" { PLUS_ASSIGN }
  | "-=" { MINUS_ASSIGN }
  | "*=" { MULTIPLY_ASSIGN }
  | "/=" { DIVIDE_ASSIGN }
  | "%=" { MODULO_ASSIGN }
  
  (* Single-character operators and punctuation *)
  | '=' { ASSIGN }
  | '+' { PLUS }
  | '-' { MINUS }
  | '*' { MULTIPLY }
  | '/' { DIVIDE }
  | '%' { MODULO }
  | '<' { LT }
  | '>' { GT }
  | '!' { NOT }
  | '&' { AMPERSAND }
  | '@' { AT }
  | '|' { PIPE }
  | '{' { LBRACE }
  | '}' { RBRACE }
  | '(' { LPAREN }
  | ')' { RPAREN }
  | '[' { LBRACKET }
  | ']' { RBRACKET }
  | ',' { COMMA }
  | '.' { DOT }
  | ':' { COLON }
  
  (* End of file *)
  | eof { EOF }
  
  (* Error case *)
  | _ as c { create_lexer_error ("Unexpected character: " ^ string_of_char c) }



and string_literal buf = parse
  | '"' { STRING (Buffer.contents buf) }
  | '\\' (['\\' '\'' '"' 'n' 't' 'r' '0'] as c) 
    { Buffer.add_char buf (char_for_backslash c); string_literal buf lexbuf }
  | '\\' 'x' (['0'-'9' 'a'-'f' 'A'-'F'] ['0'-'9' 'a'-'f' 'A'-'F'] as hex)
    { let code = int_of_string ("0x" ^ hex) in
      Buffer.add_char buf (Char.chr code);
      string_literal buf lexbuf }
  | newline { Lexing.new_line lexbuf; Buffer.add_char buf '\n'; string_literal buf lexbuf }
  | _ as c { Buffer.add_char buf c; string_literal buf lexbuf }
  | eof { create_lexer_error "Unterminated string literal" }

and char_literal = parse
  | '\'' { create_lexer_error "Empty character literal" }
  | '\\' (['\\' '\'' '"' 'n' 't' 'r' '0'] as c) '\''
    { CHAR_LIT (char_for_backslash c) }
  | '\\' 'x' (['0'-'9' 'a'-'f' 'A'-'F'] ['0'-'9' 'a'-'f' 'A'-'F'] as hex) '\''
    { let code = int_of_string ("0x" ^ hex) in
      CHAR_LIT (Char.chr code) }
  | (_ as c) '\'' { CHAR_LIT c }
  | eof { create_lexer_error "Unterminated character literal" }
  | _ { create_lexer_error "Invalid character literal" }

{
  let tokenize_string str =
    let lexbuf = Lexing.from_string str in
    let tokens = ref [] in
    let rec aux () =
      match token lexbuf with
      | EOF -> List.rev !tokens
      | tok -> tokens := tok :: !tokens; aux ()
    in
    aux ()

  let tokenize_file filename =
    let ic = open_in filename in
    let lexbuf = Lexing.from_channel ic in
    let tokens = ref [] in
    let rec aux () =
      match token lexbuf with
      | EOF -> close_in ic; List.rev !tokens
      | tok -> tokens := tok :: !tokens; aux ()
    in
    aux ()
} 