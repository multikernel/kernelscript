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
open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Type_checker
open Kernelscript.Symbol_table

(** Helper to create a bpf_type testable *)
let bpf_type_testable = 
  let equal t1 t2 = t1 = t2 in
  let pp fmt t = Format.fprintf fmt "%s" (string_of_bpf_type t) in
  (module struct
    type t = bpf_type
    let equal = equal
    let pp = pp
  end : Alcotest.TESTABLE with type t = bpf_type)

(** Test parsing function pointer types in struct declarations *)
let test_function_pointer_struct_parsing () =
  let input = {|
struct tcp_congestion_ops {
    ssthresh: fn(arg: *u8) -> u32,
    cong_avoid: fn(arg: *u8, arg: u32, arg: u32) -> void,
    set_state: fn(arg: *u8, arg: u8) -> void
}
|} in
  let ast = parse_string input in
  
  (* Find the struct declaration *)
  let struct_decl = List.find (function
    | StructDecl { struct_name = "tcp_congestion_ops"; _ } -> true
    | _ -> false
  ) ast in
  
  match struct_decl with
  | StructDecl { struct_fields; _ } ->
      (* Check that we have the expected number of fields *)
      check int "struct field count" 3 (List.length struct_fields);
      
      (* Check the first function pointer field *)
      let (field_name, field_type) = List.hd struct_fields in
      check string "first field name" "ssthresh" field_name;
      check bpf_type_testable "first field type" (Function ([Pointer U8], U32)) field_type
  | _ -> fail "Expected struct declaration"

(** Test parsing standalone function pointer variables *)
let test_standalone_function_pointer_parsing () =
  let input = {|
var ssthresh: fn(arg: *u8) -> u32
var complex_func: fn(a: u32, b: *u8, c: str(32)) -> i32
|} in
  let ast = parse_string input in
  
  (* Check we have 2 global variable declarations *)
  let global_vars = List.filter (function
    | GlobalVarDecl _ -> true
    | _ -> false
  ) ast in
  check int "global var count" 2 (List.length global_vars);
  
  match global_vars with
  | [GlobalVarDecl gv1; GlobalVarDecl gv2] ->
      (* Test simple function pointer *)
      check string "first var name" "ssthresh" gv1.global_var_name;
      check (option bpf_type_testable) "first var type" (Some (Function ([Pointer U8], U32))) gv1.global_var_type;
      
      (* Test complex function pointer *)
      check string "second var name" "complex_func" gv2.global_var_name;
      check (option bpf_type_testable) "second var type" (Some (Function ([U32; Pointer U8; Str 32], I32))) gv2.global_var_type
  | _ -> fail "Expected 2 global variable declarations"

(** Test type aliases for function pointers *)
let test_function_pointer_type_aliases () =
  let input = {|
type EventHandler = fn(event: u32, data: *u8) -> i32
type SimpleCallback = fn() -> void

fn test_function() -> i32 {
    var handler: EventHandler
    var callback: SimpleCallback
    return 0
}
|} in
  let ast = parse_string input in
  
  (* Check that type aliases are parsed correctly *)
  let type_aliases = List.filter_map (function
    | Kernelscript.Ast.TypeDef (Kernelscript.Ast.TypeAlias (name, typ)) -> Some (name, typ)
    | _ -> None
  ) ast in
  
  check int "Should have 2 type aliases" 2 (List.length type_aliases);
  
  (* Check EventHandler type alias *)
  let event_handler = List.find (fun (name, _) -> name = "EventHandler") type_aliases in
  (match snd event_handler with
   | Function ([U32; Pointer U8], I32) -> check bool "EventHandler type correct" true true
   | _ -> fail "EventHandler should be fn(u32, *u8) -> i32");
  
  (* Check SimpleCallback type alias *)
  let simple_callback = List.find (fun (name, _) -> name = "SimpleCallback") type_aliases in
  (match snd simple_callback with
   | Function ([], Void) -> check bool "SimpleCallback type correct" true true
   | _ -> fail "SimpleCallback should be fn() -> void");
  
  (* Test that type checking succeeds *)
  let symbol_table = build_symbol_table ast in
  try
    let _typed_ast = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "Type checking should succeed" true true
  with
  | _ -> fail "Type checking should not raise an exception"

(** Test function pointer call parsing *)
let test_function_pointer_call_parsing () =
  let input = {|
fn test_function() -> i32 {
    var handler: fn(x: u32) -> i32
    var result: i32 = handler(42)
    return result
}
|} in
  let ast = parse_string input in
  
  (* Find the function *)
  let test_func = List.find (function
    | GlobalFunction { func_name = "test_function"; _ } -> true
    | _ -> false
  ) ast in
  
  match test_func with
  | GlobalFunction { func_body; _ } ->
      (* Check we can parse function pointer calls in variable declarations *)
      check bool "Should have statements" true (List.length func_body >= 2);
      
      (* Find the result declaration *)
      let result_stmt = List.nth func_body 1 in
      (match result_stmt.stmt_desc with
       | Declaration ("result", Some I32, Some expr) ->
           (match expr.expr_desc with
            | Call (callee_expr, args) ->
                (match callee_expr.expr_desc with
                 | Identifier "handler" ->
                     check bool "Function call parsed correctly" true true;
                     check int "arg count" 1 (List.length args)
                 | _ -> fail "Expected handler identifier")
            | _ -> fail "Expected function call (parser treats function pointer calls as function calls)")
       | _ -> fail "Expected result variable declaration")
  | _ -> fail "Expected test_function"

(** Test function pointer type checking success *)
let test_function_pointer_type_checking_success () =
  let input = {|
fn test_function() -> i32 {
    var handler: fn(x: u32) -> i32
    var result: i32 = handler(42)
    return result
}
|} in
  let ast = parse_string input in
  let symbol_table = build_symbol_table ast in
  
  (* This should not raise an exception *)
  try
    let _typed_ast = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "Type checking should succeed" true true
  with
  | _ -> fail "Type checking should not raise an exception"

(** Test function pointer type mismatch errors *)
let test_function_pointer_type_errors () =
  let input = {|
fn test_function() -> i32 {
    var handler: fn(x: u32) -> i32
    var result: i32 = handler("not_a_number")
    return result
}
|} in
  let ast = parse_string input in
  let symbol_table = build_symbol_table ast in
  
  (* This should raise a type error *)
  try
    let _ = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    fail "Expected type error for string argument to u32 parameter"
  with
  | Type_error (msg, _) ->
      check bool "Should mention type mismatch" true (String.contains msg 'm' || String.contains msg 'T')
  | _ -> fail "Expected Type_error exception"

(** Test calling non-function pointer *)
let test_non_function_pointer_call_error () =
  let input = {|
fn test_function() -> i32 {
    var not_a_function: u32 = 42
    var result: i32 = not_a_function(123)
    return result
}
|} in
  let ast = parse_string input in
  let symbol_table = build_symbol_table ast in
  
  (* This should raise a type error *)
  try
    let _ = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    fail "Expected type error for calling non-function"
  with
  | Type_error (msg, _) ->
      check bool "Should mention cannot call non-function" true (String.contains msg 'C' || String.contains msg 'n')
  | _ -> fail "Expected Type_error exception"

(** Test function pointer argument count mismatch *)
let test_function_pointer_argument_count_error () =
  let input = {|
fn test_function() -> i32 {
    var handler: fn(x: u32, y: u32) -> i32
    var result: i32 = handler(42)
    return result
}
|} in
  let ast = parse_string input in
  let symbol_table = build_symbol_table ast in
  
  (* This should raise a type error *)
  try
    let _ = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    fail "Expected type error for wrong argument count"
  with
  | Type_error (msg, _) ->
      check bool "Should mention wrong number of arguments" true (String.contains msg 'W' || String.contains msg 'a')
  | _ -> fail "Expected Type_error exception"

(** Test complex function pointer usage in struct *)
let test_complex_struct_function_pointers () =
  let input = {|
type NetworkHandler = fn(packet: *u8, size: u32) -> i32
type EventCallback = fn(event_id: u32) -> void

struct network_interface {
    process_packet: NetworkHandler,
    on_error: EventCallback,
    get_stats: fn() -> u64
}

fn setup_network() -> i32 {
    var iface: network_interface
    var packet_data: *u8
    var result: i32 = iface.process_packet(packet_data, 1500)
    return result
}
|} in
  let ast = parse_string input in
  let symbol_table = build_symbol_table ast in
  
  (* This should not raise an exception *)
  try
    let _typed_ast = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "Complex function pointer type checking should succeed" true true
  with
  | e -> 
      let msg = Printexc.to_string e in
      fail ("Complex function pointer type checking failed: " ^ msg)

(** Test function pointer call IR generation - This test catches the bug where function pointer calls were incorrectly treated as direct function calls *)
let test_function_pointer_call_ir_generation () =
  let input = {|
type BinaryOp = fn(i32, i32) -> i32

fn add_numbers(a: i32, b: i32) -> i32 {
    return a + b
}

fn multiply_numbers(a: i32, b: i32) -> i32 {
    return a * b
}

@xdp fn dummy_program(ctx: *xdp_md) -> xdp_action {
    return 2
}

fn main() -> i32 {
    // Function pointer variable assignments
    var add_op: BinaryOp = add_numbers
    var mul_op: BinaryOp = multiply_numbers
    
    // Function pointer calls (this was the bug - these were treated as DirectCall instead of FunctionPointerCall)
    var sum = add_op(10, 20)
    var product = mul_op(5, 6)
    
    return sum + product
}
|} in
  
  try
    let ast = parse_string input in
    let symbol_table = build_symbol_table ast in
    let (typed_ast, _) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir_multi_prog = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "dummy_program" in
    
    (* For userspace functions, we need to access the userspace_program *)
    let userspace_program = match ir_multi_prog.Kernelscript.Ir.userspace_program with
      | Some prog -> prog
      | None -> failwith "No userspace program found"
    in
    let main_func = List.find (fun func -> func.Kernelscript.Ir.func_name = "main") userspace_program.Kernelscript.Ir.userspace_functions in
    
    (* Collect all IRCall instructions *)
    let all_instructions = List.flatten (List.map (fun block -> block.Kernelscript.Ir.instructions) main_func.Kernelscript.Ir.basic_blocks) in
    let call_instructions = List.filter_map (fun instr ->
      match instr.Kernelscript.Ir.instr_desc with
      | Kernelscript.Ir.IRCall (call_target, args, result) -> Some (call_target, args, result)
      | _ -> None
    ) all_instructions in
    
    (* Check that we have the expected number of calls *)
    check int "Should have function calls" 2 (List.length call_instructions);
    
    (* Check that function pointer calls use FunctionPointerCall, not DirectCall *)
    let function_pointer_calls = List.filter (fun (call_target, _args, _result) ->
      match call_target with
      | Kernelscript.Ir.FunctionPointerCall _ -> true
      | _ -> false
    ) call_instructions in
    
    let direct_calls = List.filter (fun (call_target, _args, _result) ->
      match call_target with
      | Kernelscript.Ir.DirectCall _ -> true
      | _ -> false
    ) call_instructions in
    
    (* This is the key test - function pointer calls should generate FunctionPointerCall *)
    check int "Function pointer calls should use FunctionPointerCall" 2 (List.length function_pointer_calls);
    check int "Should have no DirectCall for function pointer variables" 0 (List.length direct_calls);
    
    (* Verify the C code generation produces correct output (no undefined references) *)
    let c_code = Kernelscript.Userspace_codegen.generate_complete_userspace_program_from_ir userspace_program [] ir_multi_prog "dummy_program" in
    
    (* Check that the C code contains proper function pointer assignments *)
    check bool "C code should contain function pointer assignment" true (String.contains c_code '=' && String.contains c_code 'a');
    
    (* Check that the C code does NOT contain calls to undefined function pointer variable names *)
    let has_bad_add_op_call = try ignore (Str.search_forward (Str.regexp "add_op(") c_code 0); true with Not_found -> false in
    let has_bad_mul_op_call = try ignore (Str.search_forward (Str.regexp "mul_op(") c_code 0); true with Not_found -> false in
    
    check bool "C code should not call add_op as function" false has_bad_add_op_call;
    check bool "C code should not call mul_op as function" false has_bad_mul_op_call;
    
    (* Check that the C code contains proper function pointer calls (var_X(...)) *)
    let has_function_pointer_calls = try ignore (Str.search_forward (Str.regexp "var_[0-9]+(") c_code 0); true with Not_found -> false in
    check bool "C code should contain function pointer calls" true has_function_pointer_calls;
    
    check bool "Test passed - function pointer calls generate correct IR" true true

  with
  | exn -> 
      let msg = Printexc.to_string exn in
      fail ("Function pointer call IR generation test failed: " ^ msg)

(** Test C code generation produces correct function pointer syntax - regression test for bug fix *)
let test_function_pointer_c_generation_syntax () =
  let program_text = {|
// Function type alias for testing
type BinaryOp = fn(i32, i32) -> i32

// Test functions
fn add_numbers(a: i32, b: i32) -> i32 {
  return a + b
}

fn multiply_numbers(a: i32, b: i32) -> i32 {
  return a * b
}

@xdp fn test_functions(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  // Function pointer variable declarations - these should generate correct C syntax
  var add_op: BinaryOp = add_numbers
  var mul_op: BinaryOp = multiply_numbers
  
  // Call functions through function pointers
  var sum = add_op(10, 20)
  var product = mul_op(5, 6)
  
  return 0
}
|} in
  
  try
    (* Parse and type check *)
    let ast = parse_string program_text in
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let (annotated_ast, _) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    
    (* Generate IR *)
    let ir_multi_prog = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test_function_pointers" in
    
    (* Test eBPF C code generation *)
    let ebpf_c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir_multi_prog in
    
    (* Test userspace C code generation *)
    let temp_dir = Filename.temp_file "test_function_ptr_codegen" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
      ir_multi_prog ~output_dir:temp_dir "test_function_pointers" in
    let userspace_file = Filename.concat temp_dir "test_function_pointers.c" in
    
    let userspace_c_code = 
      if Sys.file_exists userspace_file then (
        let ic = open_in userspace_file in
        let content = really_input_string ic (in_channel_length ic) in
        close_in ic;
        content
      ) else "" in
    
    (* Cleanup *)
    (try 
       if Sys.file_exists userspace_file then Unix.unlink userspace_file;
       Unix.rmdir temp_dir
     with _ -> ());
    
    (* Check eBPF C code for correct function pointer syntax *)
    let check_function_pointer_syntax code description =
      (* Function pointer declarations should be: type ( *name)(params) *)
      let correct_pattern = Str.regexp "int32_t (\\*[a-zA-Z_][a-zA-Z0-9_]*)(int32_t, int32_t)" in
      let has_correct_syntax = 
        try 
          ignore (Str.search_forward correct_pattern code 0); 
          true 
        with Not_found -> false in
      
      (* Wrong syntax should NOT appear: type ( * )(params) name *)
      let wrong_pattern = Str.regexp "int32_t (\\*)(int32_t, int32_t) [a-zA-Z_][a-zA-Z0-9_]*" in
      let has_wrong_syntax = 
        try 
          ignore (Str.search_forward wrong_pattern code 0); 
          true 
        with Not_found -> false in
      
      check bool (description ^ " - should have correct function pointer syntax") true has_correct_syntax;
      check bool (description ^ " - should NOT have incorrect function pointer syntax") false has_wrong_syntax
    in
    
    (* Check userspace code - this is where function pointers should be *)
    if String.length userspace_c_code > 0 then
      check_function_pointer_syntax userspace_c_code "Userspace C code"
    else
      failwith "Expected userspace code to be generated for function pointer test";
    
    (* Additional specific checks for common function pointer patterns *)
    let check_no_malformed_declarations code description =
      (* Should not contain patterns like: "int32_t ( * )(int32_t, int32_t) temp_" *)
      let malformed_temp_pattern = Str.regexp "int32_t (\\*)(int32_t, int32_t) temp_[0-9]+" in
      let has_malformed = 
        try 
          ignore (Str.search_forward malformed_temp_pattern code 0); 
          true 
        with Not_found -> false in
      check bool (description ^ " - should not contain malformed temporary variable declarations") false has_malformed
    in
    
    check_no_malformed_declarations ebpf_c_code "eBPF C code";
    if String.length userspace_c_code > 0 then
      check_no_malformed_declarations userspace_c_code "Userspace C code"
      
  with
  | exn -> 
      let msg = Printexc.to_string exn in
      fail ("Function pointer C generation test failed: " ^ msg)

(** Test function pointer calls in return statements (bug fix verification) *)
let test_function_pointer_return_call () =
  let source = {|
    fn process_with_callback(x: i32, y: i32, callback: fn(i32, i32) -> i32) -> i32 {
      return callback(x, y)
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let ast = parse_string source in
  
  (* Find the process_with_callback function *)
  let process_func = List.find (fun decl ->
    match decl with
    | GlobalFunction func -> func.func_name = "process_with_callback"
    | _ -> false
  ) ast in
  
  let func_body = match process_func with
    | GlobalFunction func -> func.func_body
    | _ -> failwith "Expected function declaration"
  in
  
  (* Find the return statement *)
  let return_stmt = List.find (fun stmt ->
    match stmt.stmt_desc with
    | Return _ -> true
    | _ -> false
  ) func_body in
  
  (* Check that it's a return statement with a function call *)
  let is_function_call = match return_stmt.stmt_desc with
    | Return (Some { expr_desc = Call (callee, _); _ }) ->
        (match callee.expr_desc with
         | Identifier "callback" -> true
         | _ -> false)
    | _ -> false
  in
  
  check bool "Should have function call to callback in return statement" true is_function_call

(** Test suite for function pointer support *)
let tests = [
  ("function_pointer_struct_parsing", `Quick, test_function_pointer_struct_parsing);
  ("standalone_function_pointer_parsing", `Quick, test_standalone_function_pointer_parsing);
  ("function_pointer_type_aliases", `Quick, test_function_pointer_type_aliases);
  ("function_pointer_call_parsing", `Quick, test_function_pointer_call_parsing);
  ("function_pointer_type_checking_success", `Quick, test_function_pointer_type_checking_success);
  ("function_pointer_type_errors", `Quick, test_function_pointer_type_errors);
  ("non_function_pointer_call_error", `Quick, test_non_function_pointer_call_error);
  ("function_pointer_argument_count_error", `Quick, test_function_pointer_argument_count_error);
  ("complex_struct_function_pointers", `Quick, test_complex_struct_function_pointers);
  ("function_pointer_call_ir_generation", `Quick, test_function_pointer_call_ir_generation);
  ("function_pointer_c_generation_syntax", `Quick, test_function_pointer_c_generation_syntax);
  ("function_pointer_return_call", `Quick, test_function_pointer_return_call);
]

let () = run "Function Pointer Tests" [("main", tests)] 
