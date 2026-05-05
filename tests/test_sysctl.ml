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

open Kernelscript.Ast
open Kernelscript.Parse

let test_parse_sysctl_attribute () =
  let src = {|
@sysctl("net.core.somaxconn")
var somaxconn: u32

fn main() -> i32 { return 0 }
|} in
  let ast = parse_string src in
  let found = List.exists (function
    | GlobalVarDecl gv ->
        gv.global_var_name = "somaxconn"
        && List.exists (function
             | AttributeWithArg ("sysctl", "net.core.somaxconn") -> true
             | _ -> false)
           gv.global_var_attributes
    | _ -> false) ast in
  Alcotest.(check bool) "sysctl attribute parsed" true found

let test_parse_simple_attribute () =
  let src = {|
@some_simple_attr
var x: u32

fn main() -> i32 { return 0 }
|} in
  let ast = parse_string src in
  let found = List.exists (function
    | GlobalVarDecl gv ->
        gv.global_var_name = "x"
        && List.exists (function
             | SimpleAttribute "some_simple_attr" -> true
             | _ -> false)
           gv.global_var_attributes
    | _ -> false) ast in
  Alcotest.(check bool) "simple attribute parsed" true found

let test_parse_multiple_attributes () =
  let src = {|
@first @sysctl("net.core.somaxconn")
var x: u32

fn main() -> i32 { return 0 }
|} in
  let ast = parse_string src in
  let count = List.fold_left (fun acc d ->
    match d with
    | GlobalVarDecl gv when gv.global_var_name = "x" ->
        acc + List.length gv.global_var_attributes
    | _ -> acc) 0 ast in
  Alcotest.(check int) "two attributes accumulated" 2 count

let () =
  Alcotest.run "sysctl" [
    "parse", [
      Alcotest.test_case "attribute on global var" `Quick test_parse_sysctl_attribute;
      Alcotest.test_case "simple attribute on global var" `Quick test_parse_simple_attribute;
      Alcotest.test_case "multiple attributes on global var" `Quick test_parse_multiple_attributes;
    ];
  ]
