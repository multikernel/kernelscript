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


(** Validate parsed AST *)
let validate_ast ast =
  let rec validate_expr expr =
    match expr.expr_desc with
    | Literal _ | Identifier _ -> true
    | ConfigAccess (_, _) -> true  (* Config access is always valid syntactically *)
    | Call (callee_expr, args) -> validate_expr callee_expr && List.for_all validate_expr args
    | ArrayAccess (arr, idx) -> validate_expr arr && validate_expr idx
    | FieldAccess (obj, _) -> validate_expr obj
    | ArrowAccess (obj, _) -> validate_expr obj
    | BinaryOp (left, _, right) -> validate_expr left && validate_expr right
    | UnaryOp (_, expr) -> validate_expr expr
    | StructLiteral (_, field_assignments) -> 
        List.for_all (fun (_, field_expr) -> validate_expr field_expr) field_assignments
    | TailCall (_, args) -> List.for_all validate_expr args
    | ModuleCall module_call -> List.for_all validate_expr module_call.args
        | Match (matched_expr, arms) ->
        validate_expr matched_expr &&
        List.for_all (fun arm -> 
          match arm.arm_body with
          | SingleExpr expr -> validate_expr expr
          | Block stmts -> List.for_all validate_stmt stmts
        ) arms
    | New _ -> true
    | NewWithFlag (_, flag_expr) -> validate_expr flag_expr  (* New expressions are always syntactically valid *)
  
  and validate_stmt stmt =
    match stmt.stmt_desc with
    | ExprStmt expr -> validate_expr expr
    | Assignment (_, expr) -> validate_expr expr
    | CompoundAssignment (_, _, expr) -> validate_expr expr
    | CompoundIndexAssignment (map_expr, key_expr, _, value_expr) ->
        validate_expr map_expr && validate_expr key_expr && validate_expr value_expr
    | FieldAssignment (obj_expr, _, value_expr) ->
        validate_expr obj_expr && validate_expr value_expr
    | ArrowAssignment (obj_expr, _, value_expr) ->
        validate_expr obj_expr && validate_expr value_expr
    | IndexAssignment (map_expr, key_expr, value_expr) ->
        validate_expr map_expr && validate_expr key_expr && validate_expr value_expr
    | Declaration (_, _, expr_opt) -> 
        (match expr_opt with
         | Some expr -> validate_expr expr
         | None -> true)
    | ConstDeclaration (_, _, expr) -> validate_expr expr
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
    | Delete target ->
        (match target with
         | DeleteMapEntry (map_expr, key_expr) -> validate_expr map_expr && validate_expr key_expr
         | DeletePointer ptr_expr -> validate_expr ptr_expr)
    | Break -> true
    | Continue -> true
    | Try (try_stmts, catch_clauses) ->
        List.for_all validate_stmt try_stmts &&
        List.for_all (fun clause -> List.for_all validate_stmt clause.catch_body) catch_clauses
    | Throw _ -> true  (* Throw statements are always valid syntactically *)
    | Defer expr -> validate_expr expr
  in
  
  let validate_function func =
    List.for_all validate_stmt func.func_body
  in
  
  let validate_declaration = function
    | AttributedFunction attr_func -> validate_function attr_func.attr_function
    | GlobalFunction func -> validate_function func
    | TypeDef _ -> true (* Type definitions are always valid once parsed *)
    | MapDecl _ -> true (* Map declarations are always valid once parsed *)
    | ConfigDecl _ -> true (* Config declarations are always valid once parsed *)
    | StructDecl _ -> true (* Struct declarations are always valid once parsed *)
    | GlobalVarDecl _ -> true (* Global variable declarations are always valid once parsed *)
    | ImplBlock impl_block -> 
        (* Validate all functions in the impl block *)
        List.for_all (function
          | ImplFunction func -> validate_function func
          | ImplStaticField (_, expr) -> validate_expr expr
        ) impl_block.impl_items
    | ImportDecl _ -> true (* Import declarations are always valid once parsed *)
  in
  
  List.for_all validate_declaration ast

(** Pretty-print parse errors *)
let string_of_parse_error (msg, pos) =
  Printf.sprintf "%s at %s" msg (string_of_position pos)

let print_parse_error (msg, pos) =
  Printf.eprintf "Parse error: %s\n" (string_of_parse_error (msg, pos)) 