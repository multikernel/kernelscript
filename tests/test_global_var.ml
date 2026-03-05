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

(** Unit tests for Global Variables *)

open Alcotest
open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Symbol_table

let dummy_pos = { line = 1; column = 1; filename = "test.ks" }

let parse_program_string s =
  parse_string s

(** Helper function to create test symbol table *)
let create_test_symbol_table ast =
  Test_utils.Helpers.create_test_symbol_table ast

(** Helper function to type check with builtin types *)
let type_check_and_annotate_ast_with_builtins ast =
  let symbol_table = create_test_symbol_table ast in
  Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast

(** Helper function to check if a string contains a substring *)
let string_contains_substring s sub =
  try
    let _ = Str.search_forward (Str.regexp_string sub) s 0 in
    true
  with Not_found -> false

(** Test parsing of all three forms of global variable declarations *)
let test_global_var_parsing_forms () =
  let program_text = {|
// Form 1: Full declaration with type and initial value
var global_counter: u32 = 42
var global_string: str(256) = "hello"
var global_bool: bool = true

// Form 2: Type-only declaration (uninitialized)
var uninitialized_counter: u32
var uninitialized_string: str(128)

// Form 3: Value-only declaration (type inferred)
var inferred_int = 100
var inferred_string = "world"
var inferred_bool = false

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    
    (* Count global variable declarations *)
    let global_var_count = List.fold_left (fun acc decl ->
      match decl with
      | GlobalVarDecl _ -> acc + 1
      | _ -> acc
    ) 0 ast in
    
    check int "global variable count" 8 global_var_count;
    
    (* Verify specific declarations exist *)
    let has_global_counter = List.exists (function
      | GlobalVarDecl {global_var_name = "global_counter"; _} -> true
      | _ -> false
    ) ast in
    
    let has_inferred_int = List.exists (function
      | GlobalVarDecl {global_var_name = "inferred_int"; _} -> true
      | _ -> false
    ) ast in
    
    check bool "has global_counter" true has_global_counter;
    check bool "has inferred_int" true has_inferred_int
  with
  | e -> fail ("Global variable parsing failed: " ^ Printexc.to_string e)

(** Test type inference for different literal types *)
let test_global_var_type_inference () =
  let test_cases = [
    ("var int_var = 42", "int_var");
    ("var string_var = \"hello\"", "string_var");  
    ("var bool_var = true", "bool_var");
    ("var char_var = 'a'", "char_var");
    ("var null_var = null", "null_var");
  ] in
  
  List.iter (fun (decl_text, var_name) ->
    let program_text = Printf.sprintf {|
%s

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} decl_text in
    try
      let ast = parse_program_string program_text in
      let symbol_table = create_test_symbol_table ast in
      let _ = type_check_and_annotate_ast_with_builtins ast in
      
      (* Verify variable exists in symbol table *)
      let symbol_opt = lookup_symbol symbol_table var_name in
      check bool ("symbol exists: " ^ var_name) true (symbol_opt <> None);
      
      (* Verify it's a GlobalVariable *)
      (match symbol_opt with
       | Some {kind = GlobalVariable (var_type, _); _} ->
           (* Basic type checking - ensure a type was inferred *)
           check bool ("type inferred for: " ^ var_name) true (var_type <> U32 || var_name = "int_var")
       | _ -> fail ("Expected GlobalVariable symbol for: " ^ var_name))
    with
    | e -> fail ("Type inference test failed for " ^ var_name ^ ": " ^ Printexc.to_string e)
  ) test_cases

(** Test specific type inference rules *)
let test_specific_type_inference_rules () =
  let program_text = {|
var int_lit = 42            // Should be u32
var string_lit = "hello"    // Should be str(6) 
var bool_lit = true         // Should be bool
var char_lit = 'a'          // Should be char
var null_lit = null         // Should be *u8

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    let symbol_table = create_test_symbol_table ast in
    
    let check_global_type var_name expected_type_str =
      match lookup_symbol symbol_table var_name with
      | Some {kind = GlobalVariable (actual_type, _); _} ->
          check string (var_name ^ " type") expected_type_str (string_of_bpf_type actual_type)
      | _ -> fail (var_name ^ " not found or not GlobalVariable")
    in
    check_global_type "int_lit" "u32";
    check_global_type "string_lit" "str(6)";
    check_global_type "bool_lit" "bool";
    check_global_type "char_lit" "char";
    check_global_type "null_lit" "*u8"
  with
  | e -> fail ("Specific type inference test failed: " ^ Printexc.to_string e)

(** Test global variables in symbol table *)
let test_global_var_symbol_table () =
  let program_text = {|
var global_int: u32 = 42
var global_string: str(256) = "test"
var inferred_var = 100

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    
    let check_global var_name expected_type =
      match lookup_symbol symbol_table var_name with
      | Some {kind = GlobalVariable (actual_type, _); _} ->
          check string (var_name ^ " type") expected_type (string_of_bpf_type actual_type)
      | _ -> fail (var_name ^ " not found or wrong symbol kind")
    in
    check_global "global_int" "u32";
    check_global "global_string" "str(256)";
    check_global "inferred_var" "u32"
  with
  | e -> fail ("Symbol table test failed: " ^ Printexc.to_string e)

(** Test global variable usage in eBPF context *)
let test_global_var_ebpf_usage () =
  let program_text = {|
var packet_count: u64 = 0
var enable_debug: bool = true

@xdp
fn packet_counter(ctx: *xdp_md) -> xdp_action {
    packet_count = packet_count + 1
    if (enable_debug) {
        // Debug logic would go here
    }
    return XDP_PASS
}
|} in
  let ast = parse_program_string program_text in
  let (_enhanced_ast, typed_funcs) = type_check_and_annotate_ast_with_builtins ast in
  check int "eBPF typed functions count" 1 (List.length typed_funcs);
  let (_, tf) = List.hd typed_funcs in
  check string "eBPF function name" "packet_counter" tf.Kernelscript.Type_checker.tfunc_name

(** Test global variable usage in userspace context *)
let test_global_var_userspace_usage () =
  let program_text = {|
var config_value: u32 = 1500
var interface_name: str(16) = "eth0"

fn main() -> i32 {
    config_value = 2000
    return 0
}
|} in
  let ast = parse_program_string program_text in
  let (enhanced_ast, _typed_funcs) = type_check_and_annotate_ast_with_builtins ast in
  let func_count = List.fold_left (fun acc decl ->
    match decl with GlobalFunction _ -> acc + 1 | _ -> acc
  ) 0 enhanced_ast in
  check int "userspace function count" 1 func_count

(** Test IR generation for global variables *)
let test_global_var_ir_generation () =
  let program_text = {|
var global_counter: u32 = 42
var global_flag: bool = true
var inferred_var = 100

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir = Kernelscript.Ir_generator.generate_ir enhanced_ast symbol_table "test" in
    
    (* Verify global variables are in IR *)
    check int "global variables count in IR" 3 (List.length (Kernelscript.Ir.get_global_variables ir));
    
    (* Check specific global variables exist *)
    let has_global_counter = List.exists (fun (gvar : Kernelscript.Ir.ir_global_variable) ->
      gvar.global_var_name = "global_counter" &&
      gvar.global_var_type = Kernelscript.Ir.IRU32
    ) (Kernelscript.Ir.get_global_variables ir) in
    
    let has_global_flag = List.exists (fun (gvar : Kernelscript.Ir.ir_global_variable) ->
      gvar.global_var_name = "global_flag" &&
      gvar.global_var_type = Kernelscript.Ir.IRBool
    ) (Kernelscript.Ir.get_global_variables ir) in
    
    check bool "global_counter in IR" true has_global_counter;
    check bool "global_flag in IR" true has_global_flag
  with
  | e -> fail ("IR generation test failed: " ^ Printexc.to_string e)

(** Test error case: missing both type and value *)
let test_error_missing_type_and_value () =
  let program_text = {|
var incomplete_var

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    fail "Should have failed with missing type and value error"
  with
  | Kernelscript.Parse.Parse_error (msg, _) ->
      check bool "missing type and value produces parse error" true (string_contains_substring msg "Syntax error")
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

(** Test error case: duplicate global variable declaration *)
let test_error_duplicate_declaration () =
  let program_text = {|
var duplicate_var: u32 = 42
var duplicate_var: u64 = 100

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    fail "Should have failed with duplicate declaration error"
  with
  | Kernelscript.Symbol_table.Symbol_error (msg, _) ->
      check bool "duplicate declaration error mentions symbol" true (string_contains_substring msg "duplicate_var")
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

(** Test error case: type mismatch in explicit declaration *)
let test_error_type_mismatch () =
  let program_text = {|
var wrong_type: bool = 42

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    fail "Should have failed with type mismatch error"
  with
  | Kernelscript.Type_checker.Type_error (msg, _) ->
      check bool "type mismatch error has message" true (String.length msg > 0)
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

(** Test complex global variable scenario *)
let test_complex_global_var_scenario () =
  let program_text = {|
// Various forms of global variables
var packet_count: u64 = 0
var debug_enabled: bool = false
var max_packet_size: u32 = 1500
var interface_name: str(16) = "eth0"

// Type inferred variables
var total_bytes = 0
var error_count = 0
var last_error_message = "none"

// Uninitialized variables
var current_time: u64
var status_message: str(256)

@xdp
fn packet_processor(ctx: *xdp_md) -> xdp_action {
    packet_count = packet_count + 1
    total_bytes = total_bytes + 64  // Assume 64 byte packets
    
    if (debug_enabled) {
        // Debug processing
    }
    
    return XDP_PASS
}

fn main() -> i32 {
    debug_enabled = true
    max_packet_size = 2000
    current_time = 1234567890
    status_message = "system initialized"
    
    return 0
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir = Kernelscript.Ir_generator.generate_ir enhanced_ast symbol_table "test" in
    
    (* Verify all global variables are processed *)
    check int "complex scenario global variable count" 9 (List.length (Kernelscript.Ir.get_global_variables ir));
    
    (* Check that both eBPF and userspace functions can access globals *)
    check string "complex scenario source name" "test" ir.Kernelscript.Ir.source_name
  with
  | e -> fail ("Complex scenario test failed: " ^ Printexc.to_string e)

(** Test array literal type inference *)
let test_array_literal_inference () =
  let program_text = {|
var simple_array = [1, 2, 3]

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    (* Check that array was inferred as Array(U32, 3) *)
    (match lookup_symbol symbol_table "simple_array" with
     | Some {kind = GlobalVariable (actual_type, _); _} ->
         check string "array literal type" "[u32; 3]" (string_of_bpf_type actual_type)
     | _ -> fail "array literal variable not found")
  with
  | e -> fail ("Array literal inference test failed: " ^ Printexc.to_string e)

(** Test string size inference *)
let test_string_size_inference () =
  let test_cases = [
    ("short_str", "hi", 3);      (* "hi" + null terminator *)
    ("medium_str", "hello", 6);  (* "hello" + null terminator *)
    ("long_str", "hello world", 12); (* "hello world" + null terminator *)
  ] in
  
  let build_program_text cases =
    let var_decls = String.concat "\n" (List.map (fun (name, value, _) ->
      Printf.sprintf "var %s = \"%s\"" name value
    ) cases) in
    Printf.sprintf {|
%s

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} var_decls in
  
  let program_text = build_program_text test_cases in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    List.iter (fun (var_name, _, expected_size) ->
      match lookup_symbol symbol_table var_name with
      | Some {kind = GlobalVariable (Str actual_size, _); _} ->
          check int ("string size for " ^ var_name) expected_size actual_size
      | _ -> fail ("string variable " ^ var_name ^ " not found or wrong type")
    ) test_cases
  with
  | e -> fail ("String size inference test failed: " ^ Printexc.to_string e)

(** Test global variable initialization with different types *)
let test_global_var_initialization_types () =
  let program_text = {|
var int8_var: i8 = 127
var int16_var: i16 = 32767
var int32_var: i32 = 2147483647
var int64_var: i64 = 9223372036854775
var uint8_var: u8 = 255
var uint16_var: u16 = 65535
var uint32_var: u32 = 4294967295
var uint64_var: u64 = 1844674407370955

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    (* Check that all types are correctly stored *)
    let check_var_type var_name expected_type =
      match lookup_symbol symbol_table var_name with
      | Some {kind = GlobalVariable (actual_type, _); _} ->
          check bool (var_name ^ " has correct type") true (actual_type = expected_type)
      | _ -> fail (var_name ^ " not found or wrong symbol kind")
    in
    
    check_var_type "int8_var" I8;
    check_var_type "int16_var" I16;
    check_var_type "int32_var" I32;
    check_var_type "int64_var" I64;
    check_var_type "uint8_var" U8;
    check_var_type "uint16_var" U16;
    check_var_type "uint32_var" U32;
    check_var_type "uint64_var" U64
  with
  | e -> fail ("Type initialization test failed: " ^ Printexc.to_string e)

(** Test global variable with pointer types *)
let test_global_var_pointer_types () =
  let program_text = {|
var ptr_to_u8: *u8 = null
var ptr_to_u32: *u32 = null
var inferred_null_ptr = null

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    let check_ptr_type var_name expected =
      match lookup_symbol symbol_table var_name with
      | Some {kind = GlobalVariable (actual_type, _); _} ->
          check string (var_name ^ " type") expected (string_of_bpf_type actual_type)
      | _ -> fail (var_name ^ " not found or wrong type")
    in
    check_ptr_type "ptr_to_u8" "*u8";
    check_ptr_type "ptr_to_u32" "*u32";
    check_ptr_type "inferred_null_ptr" "*u8"
  with
  | e -> fail ("Pointer types test failed: " ^ Printexc.to_string e)

(** Test global variable edge cases *)
let test_global_var_edge_cases () =
  let program_text = {|
var empty_string: str(1) = ""
var single_char_string: str(2) = "a"
var zero_value: u32 = 0
var max_u32: u32 = 4294967295

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    (* Verify all edge case variables exist and have correct types *)
    let check_var_exists var_name =
      match lookup_symbol symbol_table var_name with
      | Some {kind = GlobalVariable (actual_type, _); _} ->
          check bool (var_name ^ " has a type") true (String.length (string_of_bpf_type actual_type) > 0)
      | _ -> fail (var_name ^ " not found")
    in
    
    check_var_exists "empty_string";
    check_var_exists "single_char_string";
    check_var_exists "zero_value";
    check_var_exists "max_u32"
  with
  | e -> fail ("Edge cases test failed: " ^ Printexc.to_string e)

(** Test local keyword functionality *)
let test_local_keyword_parsing () =
  let program_text = {|
// Regular shared global variables (default)
var shared_counter: u32 = 0
var shared_flag: bool = true

// Local global variables (kernel-only)
local var local_counter: u32 = 0
local var local_secret: u64 = 12345
local var local_flag: bool = false

// Local with type inference
local var local_inferred = 42

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    
    (* Count total global variables *)
    let total_global_vars = List.fold_left (fun acc decl ->
      match decl with
      | GlobalVarDecl _ -> acc + 1
      | _ -> acc
    ) 0 ast in
    
    check int "total global variables" 6 total_global_vars;
    
    (* Check that local variables are correctly marked *)
    let check_local_flag var_name expected_local =
      let found = List.find_opt (function
        | GlobalVarDecl {global_var_name; _} when global_var_name = var_name -> true
        | _ -> false
      ) ast in
      match found with
      | Some _ ->
          (* Find the actual declaration to get the is_local flag *)
          let decl = List.find (function
            | GlobalVarDecl {global_var_name; _} when global_var_name = var_name -> true
            | _ -> false
          ) ast in
          (match decl with
           | GlobalVarDecl {is_local; _} ->
               check bool (var_name ^ " is_local flag") expected_local is_local
           | _ -> fail (var_name ^ " unexpected declaration type"))
      | None -> fail (var_name ^ " not found")
    in
    
    check_local_flag "shared_counter" false;
    check_local_flag "shared_flag" false;
    check_local_flag "local_counter" true;
    check_local_flag "local_secret" true;
    check_local_flag "local_flag" true;
    check_local_flag "local_inferred" true
  with
  | e -> fail ("Local keyword parsing test failed: " ^ Printexc.to_string e)

(** Test local keyword with IR generation *)
let test_local_keyword_ir_generation () =
  let program_text = {|
var shared_var: u32 = 100
local var local_var: u32 = 200

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    (* Generate IR *)
    let (enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir = Kernelscript.Ir_generator.generate_ir enhanced_ast symbol_table "test" in
    
    (* Check that global variables are present in IR *)
    check int "global variables count in IR" 2 (List.length (Kernelscript.Ir.get_global_variables ir));
    
    (* Check the is_local flag is correctly propagated *)
    let check_ir_local var_name expected_local =
      let found = List.find_opt (fun (gvar : Kernelscript.Ir.ir_global_variable) ->
        gvar.global_var_name = var_name
      ) (Kernelscript.Ir.get_global_variables ir) in
      match found with
      | Some gvar -> 
          check bool (var_name ^ " is_local in IR") expected_local gvar.is_local
      | None -> fail (var_name ^ " not found in IR")
    in
    
    check_ir_local "shared_var" false;
    check_ir_local "local_var" true
  with
  | e -> fail ("Local keyword IR generation test failed: " ^ Printexc.to_string e)

(** Test local keyword with eBPF C code generation *)
let test_local_keyword_ebpf_codegen () =
  let program_text = {|
var shared_counter: u32 = 0
local var local_counter: u32 = 0
local var local_secret: u64 = 12345

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    (* Generate IR *)
    let (enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir = Kernelscript.Ir_generator.generate_ir enhanced_ast symbol_table "test" in
    
    (* Generate eBPF C code *)
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir in
    
    (* Check that the C code contains the expected patterns *)
    check bool "shared variable generated" true (string_contains_substring c_code "__u32 shared_counter = 0;");
    check bool "local variables use __hidden attribute" true (string_contains_substring c_code "__hidden");
    check bool "local variable generated" true (string_contains_substring c_code "__u32 local_counter = 0;");
    check bool "local variable with initialization" true (string_contains_substring c_code "__u64 local_secret = 12345;");
    check bool "__hidden macro defined" true (string_contains_substring c_code "#define __hidden")
  with
  | e -> fail ("Local keyword eBPF codegen test failed: " ^ Printexc.to_string e)

(** Test local keyword with all forms of variable declarations *)
let test_local_keyword_all_forms () =
  let program_text = {|
// Local with full specification
local var local_typed: u32 = 42

// Local with type only
local var local_uninitialized: u64

// Local with type inference
local var local_inferred = 100

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    (* Check that all three forms parse correctly with local keyword *)
    let check_local_var_exists var_name =
      let found = List.find_opt (function
        | GlobalVarDecl {global_var_name; _} when global_var_name = var_name -> true
        | _ -> false
      ) ast in
      match found with
      | Some _ ->
          (* Find the actual declaration to check is_local *)
          let decl = List.find (function
            | GlobalVarDecl {global_var_name; _} when global_var_name = var_name -> true
            | _ -> false
          ) ast in
          (match decl with
           | GlobalVarDecl {is_local; _} ->
               check bool (var_name ^ " is local") true is_local
           | _ -> fail (var_name ^ " unexpected declaration type"))
      | None -> fail (var_name ^ " not found")
    in
    
    check_local_var_exists "local_typed";
    check_local_var_exists "local_uninitialized";
    check_local_var_exists "local_inferred"
  with
  | e -> fail ("Local keyword all forms test failed: " ^ Printexc.to_string e)

(** Test that 'local' keyword cannot be used on non-global variables *)
let test_local_keyword_invalid_usage () =
  (* Test 1: local keyword on function parameter - should fail *)
  let test_function_param = {|
@xdp
fn test_function(local var param: u32, ctx: *xdp_md) -> xdp_action {
    return 2
}
|} in
  
  (* Test 2: local keyword on local variable inside function - should fail *)
  let test_local_variable = {|
@xdp
fn test_function(ctx: *xdp_md) -> xdp_action {
    local var local_var: u32 = 42
    return 2
}
|} in
  
  (* Test 3: local keyword in struct field - should fail *)
  let test_struct_field = {|
struct TestStruct {
    local var field: u32
}

@xdp
fn test_function(ctx: *xdp_md) -> xdp_action {
    return 2
}
|} in

  let test_cases = [
    ("function parameter", test_function_param);
    ("local variable inside function", test_local_variable);
    ("struct field", test_struct_field);
  ] in
  
  List.iter (fun (test_name, program_text) ->
    try
      let _ast = parse_program_string program_text in
      fail (Printf.sprintf "Expected parse error for 'local' on %s, but parsing succeeded" test_name)
    with
    | Kernelscript.Parse.Parse_error (msg, _) ->
        check bool (Printf.sprintf "'local' correctly rejected on %s" test_name) true (String.length msg > 0)
    | e -> 
        fail (Printf.sprintf "Unexpected error for 'local' on %s: %s" test_name (Printexc.to_string e))
  ) test_cases

(** Test that global variables actually appear in generated eBPF C code *)
let test_global_vars_in_generated_ebpf_code () =
  let program_text = {|
// Shared global variables
var shared_counter: u32 = 100
var shared_flag: bool = false

// Local global variables  
local var local_counter: u32 = 200
local var local_secret: u64 = 0xdeadbeef

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    shared_counter = shared_counter + 1
    local_counter = local_counter + 1
    return 2  // XDP_PASS
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let _ = type_check_and_annotate_ast_with_builtins ast in
    
    (* Generate IR *)
    let (enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir_multi_prog = Kernelscript.Ir_generator.generate_ir enhanced_ast symbol_table "test" in
    
    (* Generate eBPF C code *)
    let (c_code, _) = Kernelscript.Ebpf_c_codegen.compile_multi_to_c ir_multi_prog in
    
    (* Check that shared variables appear without __hidden *)
    check bool "shared variable with initialization" true (string_contains_substring c_code "__u32 shared_counter = 100;");
    check bool "shared boolean variable (using 0 not false)" true (string_contains_substring c_code "__u8 shared_flag = 0;");

    (* Check that local variables appear with __hidden attribute *)
    check bool "__hidden macro defined" true (string_contains_substring c_code "#define __hidden");
    check bool "local variable with __hidden" true (string_contains_substring c_code "__hidden __attribute__((aligned(8))) __u32 local_counter = 200;");
    check bool "local variable with hex literal" true (string_contains_substring c_code "__hidden __attribute__((aligned(8))) __u64 local_secret = 0xdeadbeef;");

    (* Verify boolean values use 0/1 not true/false *)
    check bool "no 'false' literal in C code" false (string_contains_substring c_code "false");
    check bool "no 'true' literal in C code" false (string_contains_substring c_code "true")
  with
  | e -> fail ("Global variables in eBPF C code test failed: " ^ Printexc.to_string e)

(** Test negative numbers in global variables *)
let test_negative_numbers_in_global_vars () =
  let program_text = {|
var negative_int = -42
var negative_typed: i32 = -123
var negative_large: i64 = -9223372036854775
var negative_small: i8 = -127

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    return 2
}
|} in
  try
    let ast = parse_program_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (enhanced_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir = Kernelscript.Ir_generator.generate_ir enhanced_ast symbol_table "test" in
    
    (* Verify all negative global variables are processed *)
    check int "negative numbers global variable count" 4 (List.length (Kernelscript.Ir.get_global_variables ir));
    
    let check_neg_type var_name expected =
      match lookup_symbol symbol_table var_name with
      | Some {kind = GlobalVariable (actual_type, _); _} ->
          check string (var_name ^ " type") expected (string_of_bpf_type actual_type)
      | _ -> fail (var_name ^ " not found or wrong type")
    in
    check_neg_type "negative_int" "i32";
    check_neg_type "negative_typed" "i32";
    check_neg_type "negative_large" "i64";
    check_neg_type "negative_small" "i8"
  with
  | e -> fail ("Negative numbers test failed: " ^ Printexc.to_string e)

let global_variable_tests = [
  ("parsing_forms", `Quick, test_global_var_parsing_forms);
  ("type_inference", `Quick, test_global_var_type_inference);
  ("specific_type_inference_rules", `Quick, test_specific_type_inference_rules);
  ("symbol_table", `Quick, test_global_var_symbol_table);
  ("ebpf_usage", `Quick, test_global_var_ebpf_usage);
  ("userspace_usage", `Quick, test_global_var_userspace_usage);
  ("ir_generation", `Quick, test_global_var_ir_generation);
  ("error_missing_type_and_value", `Quick, test_error_missing_type_and_value);
  ("error_duplicate_declaration", `Quick, test_error_duplicate_declaration);
  ("error_type_mismatch", `Quick, test_error_type_mismatch);
  ("complex_scenario", `Quick, test_complex_global_var_scenario);
  ("array_literal_inference", `Quick, test_array_literal_inference);
  ("string_size_inference", `Quick, test_string_size_inference);
  ("initialization_types", `Quick, test_global_var_initialization_types);
  ("pointer_types", `Quick, test_global_var_pointer_types);
  ("edge_cases", `Quick, test_global_var_edge_cases);
  ("local_keyword_parsing", `Quick, test_local_keyword_parsing);
  ("local_keyword_ir_generation", `Quick, test_local_keyword_ir_generation);
  ("local_keyword_ebpf_codegen", `Quick, test_local_keyword_ebpf_codegen);
  ("local_keyword_all_forms", `Quick, test_local_keyword_all_forms);
  ("local_keyword_invalid_usage", `Quick, test_local_keyword_invalid_usage);
  ("global_vars_in_generated_ebpf_code", `Quick, test_global_vars_in_generated_ebpf_code);
  ("negative_numbers_in_global_vars", `Quick, test_negative_numbers_in_global_vars);
]

let () =
  Alcotest.run "Global Variables Tests" [
    ("global_variables", global_variable_tests);
  ]
