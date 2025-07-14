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

open Kernelscript.Parse
open Kernelscript.Ast
open Alcotest

(** Test that comments at line 1, column 1 don't cause parse errors *)
let test_comment_at_start () =
  let program_text = {|// This is a comment at line 1, column 1
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}|} in
  try
    let ast = parse_string program_text in
    check int "AST declarations count" 1 (List.length ast);
    check bool "comment at start parsing" true true
  with
  | Parse_error (msg, pos) ->
    fail ("Parse error: " ^ msg ^ " at " ^ string_of_position pos)

(** Test that comments with whitespace before them work *)
let test_comment_with_whitespace () =
  let program_text = {|   // Comment with whitespace before it
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}|} in
  try
    let ast = parse_string program_text in
    check int "AST declarations count" 1 (List.length ast);
    check bool "comment with whitespace parsing" true true
  with
  | Parse_error (msg, pos) ->
    fail ("Parse error: " ^ msg ^ " at " ^ string_of_position pos)

(** Test that error positions are correctly reported when there's a comment at the start *)
let test_error_position_after_comment () =
  let program_text = {|// Comment at start
@xdp fn test_invalid_syntax_here|} in
  try
    let _ = parse_string program_text in
    fail "Expected parse error but parsing succeeded"
  with
  | Parse_error (msg, pos) ->
    check int "error line" 2 pos.line;
    check bool "error column reasonable" true (pos.column >= 1);  (* Parser reports actual error position *)
    check string "error message" "Syntax error" msg

(** Test that error positions are correctly reported without comments *)
let test_error_position_no_comment () =
  let program_text = {|@xdp fn test_invalid_syntax_here|} in
  try
    let _ = parse_string program_text in
    fail "Expected parse error but parsing succeeded"
  with
  | Parse_error (msg, pos) ->
    check int "error line" 1 pos.line;
    check bool "error column reasonable" true (pos.column >= 1);  (* Parser reports actual error position *)
    check string "error message" "Syntax error" msg

(** Test multiple lines with comments *)
let test_multiple_line_comments () =
  let program_text = {|// First comment
// Second comment  
// Third comment
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  // Comment inside function
  return XDP_PASS
}|} in
  try
    let ast = parse_string program_text in
    check int "AST declarations count" 1 (List.length ast);
    check bool "multiple line comments parsing" true true
  with
  | Parse_error (msg, pos) ->
    fail ("Parse error: " ^ msg ^ " at " ^ string_of_position pos)

(** Test that inline comments work *)
let test_inline_comments () =
  let program_text = {|@xdp fn test(ctx: *xdp_md) -> xdp_action { // Inline comment, Another inline comment
  return XDP_PASS // Final comment
}|} in
  try
    let ast = parse_string program_text in
    check int "AST declarations count" 1 (List.length ast);
    check bool "inline comments parsing" true true
  with
  | Parse_error (msg, pos) ->
    fail ("Parse error: " ^ msg ^ " at " ^ string_of_position pos)

(** Test error position in a multi-line file with comments *)
let test_error_position_multiline () =
  let program_text = {|// Comment line 1
// Comment line 2
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  let x = if (missing_condition_error) {
    return XDP_PASS
  }
  return XDP_PASS
}|} in
  try
    let _ = parse_string program_text in
    fail "Expected parse error but parsing succeeded"
  with
  | Parse_error (msg, pos) ->
    check int "error line" 4 pos.line;  (* Error is on line 4 where the syntax error occurs *)
    check bool "error column reasonable" true (pos.column >= 1);  (* Parser reports actual error position *)
    check string "error message" "Syntax error" msg

let comment_position_tests = [
  "comment_at_start", `Quick, test_comment_at_start;
  "comment_with_whitespace", `Quick, test_comment_with_whitespace;
  "error_position_after_comment", `Quick, test_error_position_after_comment;
  "error_position_no_comment", `Quick, test_error_position_no_comment;
  "multiple_line_comments", `Quick, test_multiple_line_comments;
  "inline_comments", `Quick, test_inline_comments;
  "error_position_multiline", `Quick, test_error_position_multiline;
]

let () =
  run "KernelScript Comment Position Tests" [
    "comment_positions", comment_position_tests;
  ] 