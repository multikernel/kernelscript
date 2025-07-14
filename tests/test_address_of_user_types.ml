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

open Kernelscript.Type_checker
open Alcotest

(** Test that address-of operator correctly resolves user types for function calls *)
let test_address_of_user_type_resolution () =
  let code = {|
    struct DataBuffer {
        data: u8[32],
        size: u32
    }
    
    map<u32, DataBuffer> buffer_map : HashMap(1024)
    
    @helper
    fn process_map_data(buffer_ptr: *DataBuffer) -> u32 {
        var size_value = buffer_ptr->size
        return size_value
    }
    
    @xdp  
    fn test(ctx: *xdp_md) -> xdp_action {
        var key = 1
        var buffer_value = buffer_map[key]
        var buffer_ptr = &buffer_value
        var map_size = process_map_data(buffer_ptr)
        return 2
    }
  |} in
  
  (* This should compile without type errors *)
  try
    let ast = Kernelscript.Parse.parse_string code in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ~include_xdp:true ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "Address-of user type resolution test passed" true true
  with
  | Type_error (msg, _) -> 
    Alcotest.fail ("Type error should not occur: " ^ msg)
  | exn -> 
    Alcotest.fail ("Unexpected error: " ^ Printexc.to_string exn)

(** Test that address-of correctly handles nested user types *)
let test_address_of_nested_user_types () =
  let code = {|
    struct Point {
        x: u32,
        y: u32
    }
    
    struct Container {
        point: Point,
        count: u32
    }
    
    @helper
    fn process_point(point_ptr: *Point) -> u32 {
        return point_ptr->x + point_ptr->y
    }
    
    @helper
    fn process_container(container_ptr: *Container) -> u32 {
        var point_ptr = &container_ptr->point
        return process_point(point_ptr)
    }
    
    @xdp
    fn test(ctx: *xdp_md) -> xdp_action {
        var container = Container { point: Point { x: 10, y: 20 }, count: 1 }
        var result = process_container(&container)
        return 2
    }
  |} in
  
  try
    let ast = Kernelscript.Parse.parse_string code in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ~include_xdp:true ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "Nested address-of user type resolution test passed" true true
  with
  | Type_error (msg, _) -> 
    Alcotest.fail ("Type error should not occur: " ^ msg)
  | exn -> 
    Alcotest.fail ("Unexpected error: " ^ Printexc.to_string exn)

(** Test that type mismatches are still caught correctly *)
let test_address_of_type_mismatch_detection () =
  let code = {|
    struct DataBuffer {
        data: u8[32],
        size: u32
    }
    
    struct OtherStruct {
        value: u32
    }
    
    @helper
    fn process_data_buffer(buffer_ptr: *DataBuffer) -> u32 {
        return buffer_ptr->size
    }
    
    @xdp
    fn test(ctx: *xdp_md) -> xdp_action {
        var other = OtherStruct { value: 42 }
        var other_ptr = &other
        var result = process_data_buffer(other_ptr)  // This should fail
        return 2
    }
  |} in
  
  (* This should fail with a type error *)
  try
    let ast = Kernelscript.Parse.parse_string code in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ~include_xdp:true ast in
    let (_, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    Alcotest.fail "Type error should have been detected"
  with
  | Type_error (msg, _) -> 
    check bool "Type mismatch correctly detected" true (String.contains msg 'T')
  | exn -> 
    Alcotest.fail ("Unexpected error: " ^ Printexc.to_string exn)

let tests = [
  "address-of user type resolution", `Quick, test_address_of_user_type_resolution;
  "nested address-of user types", `Quick, test_address_of_nested_user_types;
  "address-of type mismatch detection", `Quick, test_address_of_type_mismatch_detection;
]

let () = Alcotest.run "Address-of User Types" [
  "address-of user types", tests
] 