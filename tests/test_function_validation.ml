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

open Alcotest
open Kernelscript.Parse
open Kernelscript.Symbol_table
open Kernelscript.Type_checker

(** Test that @xdp fn main is rejected *)
let test_attributed_main_function_rejection () =
  let program_text = {|
@xdp fn main(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    check bool "should reject @xdp fn main" false true
  with
  | Symbol_error (msg, _) ->
      check bool "correctly rejected @xdp fn main" true (String.contains msg 'm')
  | _ ->
      check bool "unexpected error type" false true

(** Test that duplicate main functions are rejected *)
let test_duplicate_main_functions_rejection () =
  let program_text = {|
fn main() -> i32 {
  return 0
}

fn main(x: u32) -> i32 {
  return 1
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    check bool "should reject duplicate main functions" false true
  with
  | Symbol_error (msg, _) ->
      check bool "correctly rejected duplicate main" true (String.contains msg 'D' || String.contains msg 'd')
  | _ ->
      check bool "unexpected error type" false true

(** Test that @tc fn main is also rejected *)
let test_tc_attributed_main_rejection () =
  let program_text = {|
@tc fn main(ctx: TcContext) -> TcAction {
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    check bool "should reject @tc fn main" false true
  with
  | Symbol_error (msg, _) ->
      check bool "correctly rejected @tc fn main" true (String.contains msg 'm')
  | _ ->
      check bool "unexpected error type" false true

(** Test that proper eBPF function names are accepted *)
let test_proper_ebpf_function_names () =
  let program_text = {|
@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_, _) = type_check_and_annotate_ast ast in
    check bool "proper eBPF function names should be accepted" true true
  with
  | _ ->
      check bool "proper eBPF function names rejected unexpectedly" false true

(** Test that main function without attributes is accepted *)
let test_userspace_main_function () =
  let program_text = {|
@xdp fn monitor(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_, _) = type_check_and_annotate_ast ast in
    check bool "userspace main function should be accepted" true true
  with
  | _ ->
      check bool "userspace main function rejected unexpectedly" false true

(** Test mixed invalid cases *)
let test_mixed_invalid_cases () =
  let program_text = {|
@xdp fn main(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    check bool "should reject mixed invalid main functions" false true
  with
  | Symbol_error (msg, _) ->
      (* Should fail on the first error - attributed main *)
      check bool "correctly rejected mixed invalid main" true (String.contains msg 'm')
  | _ ->
      check bool "unexpected error type" false true

let function_validation_tests = [
  ("attributed_main_rejection", `Quick, test_attributed_main_function_rejection);
  ("duplicate_main_rejection", `Quick, test_duplicate_main_functions_rejection);
  ("tc_attributed_main_rejection", `Quick, test_tc_attributed_main_rejection);
  ("proper_ebpf_function_names", `Quick, test_proper_ebpf_function_names);
  ("userspace_main_function", `Quick, test_userspace_main_function);
  ("mixed_invalid_cases", `Quick, test_mixed_invalid_cases);
]

let () =
  run "Function Validation Tests" [
    ("function_validation", function_validation_tests);
  ] 