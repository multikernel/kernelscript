(** Parser interface for KernelScript *)

open Ast

exception Parse_error of string * position

let create_parse_error msg pos =
  raise (Parse_error (msg, pos))

(** Parse a string into an AST *)
let parse_string ?(filename="<string>") str =
  let lexbuf = Lexing.from_string str in
  Lexing.set_filename lexbuf filename;
  try
    Parser.program Lexer.token lexbuf
  with
  | Parser.Error ->
      let pos = Lexing.lexeme_start_p lexbuf in
      let parse_pos = { 
        line = pos.pos_lnum; 
        column = pos.pos_cnum - pos.pos_bol + 1; 
        filename = pos.pos_fname 
      } in
      create_parse_error "Syntax error" parse_pos
  | Lexer.Lexer_error msg ->
      let pos = Lexing.lexeme_start_p lexbuf in
      let parse_pos = { 
        line = pos.pos_lnum; 
        column = pos.pos_cnum - pos.pos_bol + 1; 
        filename = pos.pos_fname 
      } in
      create_parse_error ("Lexer error: " ^ msg) parse_pos
  | e -> 
      let pos = { line = 1; column = 1; filename } in
      create_parse_error ("Parse error: " ^ Printexc.to_string e) pos

(** Parse a file into an AST *)
let parse_file filename =
  try
    let ic = open_in filename in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    parse_string ~filename content
  with
  | Sys_error msg -> 
      let pos = { line = 1; column = 1; filename } in
      create_parse_error ("File error: " ^ msg) pos

(** Parse just an expression (for testing) *)
let parse_expression_string ?(filename="<expr>") str =
  try
    let lexbuf = Lexing.from_string str in
    Lexing.set_filename lexbuf filename;
    (* We need to modify our parser to support standalone expressions *)
    (* For now, we'll wrap the expression in a minimal program *)
    let wrapped = Printf.sprintf "program test : xdp { fn main() { return %s; } }" str in
    let ast = parse_string ~filename wrapped in
    match ast with
    | [Program { prog_functions = [{ func_body = [{ stmt_desc = Return (Some expr); _ }]; _ }]; _ }] -> expr
    | _ -> failwith "Failed to extract expression from parsed program"
  with
  | e -> 
      let pos = { line = 1; column = 1; filename } in
      create_parse_error ("Expression parse error: " ^ Printexc.to_string e) pos

(** Validate parsed AST *)
let validate_ast ast =
  let rec validate_expr expr =
    match expr.expr_desc with
    | Literal _ | Identifier _ -> true
    | ConfigAccess (_, _) -> true  (* Config access is always valid syntactically *)
    | FunctionCall (_, args) -> List.for_all validate_expr args
    | ArrayAccess (arr, idx) -> validate_expr arr && validate_expr idx
    | FieldAccess (obj, _) -> validate_expr obj
    | BinaryOp (left, _, right) -> validate_expr left && validate_expr right
    | UnaryOp (_, expr) -> validate_expr expr
  in
  
  let rec validate_stmt stmt =
    match stmt.stmt_desc with
    | ExprStmt expr -> validate_expr expr
    | Assignment (_, expr) -> validate_expr expr
    | IndexAssignment (map_expr, key_expr, value_expr) ->
        validate_expr map_expr && validate_expr key_expr && validate_expr value_expr
    | Declaration (_, _, expr) -> validate_expr expr
    | Return None -> true
    | Return (Some expr) -> validate_expr expr
    | If (cond, then_stmts, else_opt) ->
        validate_expr cond && 
        List.for_all validate_stmt then_stmts &&
        (match else_opt with None -> true | Some stmts -> List.for_all validate_stmt stmts)
    | For (_, start, end_, body) ->
        validate_expr start && validate_expr end_ && List.for_all validate_stmt body
    | ForIter (_, _, iterable, body) ->
        validate_expr iterable && List.for_all validate_stmt body
    | While (cond, body) ->
        validate_expr cond && List.for_all validate_stmt body
    | Delete (map_expr, key_expr) ->
        validate_expr map_expr && validate_expr key_expr
    | Break -> true
    | Continue -> true
  in
  
  let validate_function func =
    List.for_all validate_stmt func.func_body
  in
  
  let validate_declaration =   function
    | Program prog -> List.for_all validate_function prog.prog_functions
    | GlobalFunction func -> validate_function func
    | TypeDef _ -> true (* Type definitions are always valid once parsed *)
    | MapDecl _ -> true (* Map declarations are always valid once parsed *)
    | ConfigDecl _ -> true (* Config declarations are always valid once parsed *)
    | Userspace userspace_block -> List.for_all validate_function userspace_block.userspace_functions
  in
  
  List.for_all validate_declaration ast

(** Pretty-print parse errors *)
let string_of_parse_error (msg, pos) =
  Printf.sprintf "%s at %s" msg (string_of_position pos)

let print_parse_error (msg, pos) =
  Printf.eprintf "Parse error: %s\n" (string_of_parse_error (msg, pos)) 