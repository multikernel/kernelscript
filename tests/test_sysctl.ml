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

let typecheck_string src =
  let ast = Kernelscript.Parse.parse_string src in
  Kernelscript.Type_checker.type_check_ast ast

let expect_typecheck_error ~fragment src =
  let got =
    try Ok (typecheck_string src) with
    | Kernelscript.Type_checker.Type_error (m, _) -> Error m
  in
  match got with
  | Error m ->
    let contains hay needle =
      try ignore (Str.search_forward (Str.regexp_string needle) hay 0); true
      with Not_found -> false
    in
    Alcotest.(check bool) ("error contains '" ^ fragment ^ "'") true (contains m fragment)
  | Ok _ ->
    Alcotest.failf "expected type error containing '%s', got success" fragment

let test_reject_unsupported_type () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("net.core.somaxconn")
var somaxconn: hash<u32, u32>(1)
fn main() -> i32 { return 0 }
|}

let test_reject_bad_path_double_dot () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("net..core")
var x: u32
fn main() -> i32 { return 0 }
|}

let test_reject_bad_path_absolute () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("/proc/sys/net/core/somaxconn")
var x: u32
fn main() -> i32 { return 0 }
|}

let test_reject_initializer () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("net.core.somaxconn")
var x: u32 = 100
fn main() -> i32 { return 0 }
|}

let test_reject_pin_combination () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("net.core.somaxconn")
pin var x: u32
fn main() -> i32 { return 0 }
|}

let test_accept_int_bool_str () =
  ignore (typecheck_string {|
@sysctl("net.core.somaxconn") var somaxconn: u32
@sysctl("net.ipv4.ip_forward") var ip_forward: bool
@sysctl("kernel.hostname") var hostname: str(64)
fn main() -> i32 { return 0 }
|})

let test_reject_sysctl_in_xdp () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("net.core.somaxconn") var somaxconn: u32
@xdp fn f(ctx: *xdp_md) -> xdp_action {
  var x = somaxconn
  return 2
}
fn main() -> i32 { return 0 }
|}

let test_reject_sysctl_in_helper () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("net.core.somaxconn") var somaxconn: u32
@helper fn h() -> u32 { return somaxconn }
@xdp fn f(ctx: *xdp_md) -> xdp_action { return 2 }
fn main() -> i32 { return 0 }
|}

let test_reject_sysctl_in_kfunc () =
  expect_typecheck_error ~fragment:"sysctl"
    {|
@sysctl("net.core.somaxconn") var somaxconn: u32
@kfunc fn k() -> u32 { return somaxconn }
fn main() -> i32 { return 0 }
|}

let test_allow_sysctl_in_userspace () =
  ignore (typecheck_string {|
@sysctl("net.core.somaxconn") var somaxconn: u32
fn read_it() -> u32 { return somaxconn }
fn main() -> i32 {
  somaxconn = 4096
  return 0
}
|})

let ir_of src =
  let ast = Kernelscript.Parse.parse_string src in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (typed_ast, _) =
    Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test"

let test_ir_carries_sysctl_path () =
  let ir = ir_of {|
@sysctl("net.core.somaxconn") var somaxconn: u32
@xdp fn p(ctx: *xdp_md) -> xdp_action { return 2 }
fn main() -> i32 { return 0 }
|} in
  let globals = Kernelscript.Ir.get_global_variables ir in
  let found =
    List.exists (fun gv ->
      gv.Kernelscript.Ir.global_var_name = "somaxconn"
      && gv.Kernelscript.Ir.sysctl_path = Some "net.core.somaxconn")
      globals in
  Alcotest.(check bool) "IR records sysctl path" true found

let test_ir_no_path_for_plain_global () =
  let ir = ir_of {|
var plain: u32
@xdp fn p(ctx: *xdp_md) -> xdp_action { return 2 }
fn main() -> i32 { return 0 }
|} in
  let globals = Kernelscript.Ir.get_global_variables ir in
  let found =
    List.exists (fun gv ->
      gv.Kernelscript.Ir.global_var_name = "plain"
      && gv.Kernelscript.Ir.sysctl_path = None)
      globals in
  Alcotest.(check bool) "plain global has sysctl_path = None" true found

let ebpf_c_of src =
  let ir = ir_of src in
  Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir

let mentions s c =
  try ignore (Str.search_forward (Str.regexp_string s) c 0); true
  with Not_found -> false

let test_ebpf_codegen_omits_sysctl_globals () =
  let c = ebpf_c_of {|
@sysctl("net.core.somaxconn") var somaxconn: u32
@xdp fn f(ctx: *xdp_md) -> xdp_action { return 2 }
fn main() -> i32 { return 0 }
|} in
  Alcotest.(check bool) "no sysctl global in eBPF" false (mentions "somaxconn" c);
  Alcotest.(check bool) "no /proc/sys reference"  false (mentions "/proc/sys" c)

let () =
  Alcotest.run "sysctl" [
    "parse", [
      Alcotest.test_case "attribute on global var" `Quick test_parse_sysctl_attribute;
      Alcotest.test_case "simple attribute on global var" `Quick test_parse_simple_attribute;
      Alcotest.test_case "multiple attributes on global var" `Quick test_parse_multiple_attributes;
    ];
    "typecheck", [
      Alcotest.test_case "reject unsupported type" `Quick test_reject_unsupported_type;
      Alcotest.test_case "reject bad path (double dot)" `Quick test_reject_bad_path_double_dot;
      Alcotest.test_case "reject bad path (absolute)" `Quick test_reject_bad_path_absolute;
      Alcotest.test_case "reject initializer" `Quick test_reject_initializer;
      Alcotest.test_case "reject pin combination" `Quick test_reject_pin_combination;
      Alcotest.test_case "accept int/bool/str" `Quick test_accept_int_bool_str;
      Alcotest.test_case "reject access from @xdp" `Quick test_reject_sysctl_in_xdp;
      Alcotest.test_case "reject access from @helper" `Quick test_reject_sysctl_in_helper;
      Alcotest.test_case "reject access from @kfunc" `Quick test_reject_sysctl_in_kfunc;
      Alcotest.test_case "allow access from userspace" `Quick test_allow_sysctl_in_userspace;
    ];
    "ir", [
      Alcotest.test_case "IR carries sysctl path" `Quick test_ir_carries_sysctl_path;
      Alcotest.test_case "plain global has no sysctl path" `Quick test_ir_no_path_for_plain_global;
    ];
    "codegen", [
      Alcotest.test_case "eBPF codegen omits sysctl globals" `Quick test_ebpf_codegen_omits_sysctl_globals;
    ];
  ]
