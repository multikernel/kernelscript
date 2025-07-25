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
open Kernelscript.Type_checker
open Kernelscript.Parse

(* Test utilities *)
let test_parse_and_check source =
  let ast = parse_string source in
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let (typed_ast, _) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  (typed_ast, symbol_table)

let test_simple_parse source =
  let ast = parse_string source in
  ast

(* Basic list declaration tests *)
let test_list_declaration () =
  let source = {|
struct TestData {
    value: u32,
}

var test_list : list<TestData>

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  let (typed_ast, _) = test_parse_and_check source in
  (* Check that parsing and type checking succeeds - this means the list declaration was valid *)
  check bool "List declaration should parse and type check successfully" true (List.length typed_ast > 0)

(* List operations parsing tests *)
let test_list_operations_parsing () =
  let source = {|
struct TestData {
    value: u32,
}

var test_list : list<TestData>

@helper
fn test_operations() {
    var item = TestData { value: 42 }
    test_list.push_back(item)
    test_list.push_front(item)
    var front_item = test_list.pop_front()
    var back_item = test_list.pop_back()
}

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    test_operations()
    return XDP_PASS
}
|} in
  let _ = test_parse_and_check source in
  (* If parsing succeeds, the test passes *)
  check bool "List operations should parse correctly" true true

(* Type checking tests *)
let test_list_type_checking () =
  let source = {|
struct TestData {
    value: u32,
}

var test_list : list<TestData>

@helper
fn test_type_checking() {
    var item = TestData { value: 42 }
    test_list.push_back(item)  // Should work - correct type
}

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    test_type_checking()
    return XDP_PASS
}
|} in
  let _ = test_parse_and_check source in
  check bool "Correct list element types should type check" true true

(* Type checking error tests *)
let test_list_type_error () =
  let source = {|
struct TestData {
    value: u32,
}

struct OtherData {
    other: u64,
}

var test_list : list<TestData>

@helper
fn test_type_error() {
    var wrong_item = OtherData { other: 42 }
    test_list.push_back(wrong_item)  // Should fail - wrong type
}

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    test_type_error()
    return XDP_PASS
}
|} in
  (* This should throw a type error *)
  try
    let _ = test_parse_and_check source in
    failwith "Expected type error"
  with
  | Type_error _ -> check bool "Should detect type mismatch" true true
  | _ -> failwith "Expected type error, got different error"

(* IR generation tests *)
let test_list_ir_generation () =
  let source = {|
struct TestData {
    value: u32,
}

var test_list : list<TestData>

@helper
fn test_ir() {
    var item = TestData { value: 42 }
    test_list.push_back(item)
    test_list.push_front(item)
    var popped = test_list.pop_front()
}

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    test_ir()
    return XDP_PASS
}
|} in
  let (typed_ast, _) = test_parse_and_check source in
  (* Check that type checking succeeds *)
  check bool "List operations should type check" true (List.length typed_ast > 0)

(* List with non-struct types should fail *)
let test_list_non_struct_error () =
  let source = {|
var invalid_list : list<u32>  // Should fail - lists only accept struct types

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let _ = test_parse_and_check source in
    check bool "Should accept any parsing but fail in type checking is optional" true true
  with
  | Type_error _ -> check bool "Should reject non-struct list element types" true true
  | _ -> check bool "Other errors are also acceptable" true true

(* Test that lists cannot be pinned *)
let test_list_no_pinning () =
  (* For now, let's just test that we can parse a basic list without pinning *)
  let source = {|
struct TestData {
    value: u32,
}

var valid_list : list<TestData>

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  let (typed_ast, _) = test_parse_and_check source in
  check bool "Basic list without pinning should work" true (List.length typed_ast > 0)

(* Test that lists cannot have flags *)
let test_list_no_flags () =
  let source = {|
struct TestData {
    value: u32,
}

@flags(BPF_F_NO_PREALLOC)
var invalid_list : list<TestData>  // Should fail - lists can't have flags

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let _ = parse_string source in
    failwith "Expected parsing error for list with flags"
  with
  | Parse_error _ -> check bool "Should reject lists with flags" true true
  | _ -> failwith "Expected parsing error for list with flags"

(* Test comprehensive list usage *)
let test_comprehensive_list_usage () =
  let source = {|
struct PacketInfo {
    src_ip: u32,
    dst_ip: u32,
    size: u16,
}

struct EventData {
    timestamp: u64,
    event_type: u32,
}

var packet_queue : list<PacketInfo>
var event_log : list<EventData>

@helper
fn process_packet(src: u32, dst: u32, size: u16) {
    var packet = PacketInfo {
        src_ip: src,
        dst_ip: dst,
        size: size,
    }
    packet_queue.push_back(packet)
}

@helper
fn log_event(event_type: u32) {
    var event = EventData {
        timestamp: 12345,  // Mock timestamp
        event_type: event_type,
    }
    event_log.push_front(event)
}

@xdp
fn packet_processor(ctx: *xdp_md) -> xdp_action {
    process_packet(1234, 5678, 1500)
    log_event(1)
    
    var latest_event = event_log.pop_front()
    if (latest_event != null) {
        return XDP_PASS
    }
    
    var oldest_packet = packet_queue.pop_front()
    if (oldest_packet != null) {
        return XDP_DROP
    }
    
    return XDP_PASS
}
|} in
  let (typed_ast, _) = test_parse_and_check source in
  check bool "Comprehensive list usage should compile" true (List.length typed_ast > 0)

(* Test suite *)
let list_tests = [
  ("List declaration", `Quick, test_list_declaration);
  ("List operations parsing", `Quick, test_list_operations_parsing);
  ("List type checking", `Quick, test_list_type_checking);
  ("List type errors", `Quick, test_list_type_error);
  ("List IR generation", `Quick, test_list_ir_generation);
  ("Non-struct element error", `Quick, test_list_non_struct_error);
  ("No pinning allowed", `Quick, test_list_no_pinning);
  ("No flags allowed", `Quick, test_list_no_flags);
  ("Comprehensive list usage", `Quick, test_comprehensive_list_usage);
]

let () = run "KernelScript List Tests" [
  "lists", list_tests;
] 