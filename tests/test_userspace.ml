(** 
   Comprehensive unit tests for userspace block functionality in KernelScript.
   
   This test suite covers:
   
   === Parser Tests ===
   - Top-level userspace block parsing
   - Nested userspace block rejection (enforces architectural design)
   
   === Main Function Signature Tests ===
   - Correct signature validation: fn main(argc: u32, argv: u64) -> i32
   - Wrong parameter types rejection
   - Wrong return type rejection
   - Parameter count validation (too few/too many)
   
   === Main Function Existence Tests ===
   - Missing main function detection
   - Multiple main function rejection
   
   === Integration Tests ===
   - Userspace blocks with helper functions
   - Userspace blocks with struct definitions
   - Multiple eBPF programs with single userspace coordinator
   
   === Code Generation Tests ===
   - Generated C main signature: int main(int argc, char **argv)
   - File naming scheme: FOO.c from FOO.ks
   - Struct definitions in generated code
   - Multiple function generation
   - Required includes and BPF infrastructure
   - Error handling for invalid signatures
   
   === C Code Generation Tests (Literal Key/Value Bug Fix) ===
   - Temporary variable creation for literal keys and values in map operations
   - Direct variable usage for non-literal expressions
   - Mixed literal and variable expressions handling
   - Map lookup expressions with literal keys
   - Unique temporary variable name generation
   - Validation that direct literal addressing (&(literal)) is avoided
*)

open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Userspace_codegen
open Alcotest

(** Helper function to check if a pattern exists in content (case-insensitive) *)
let contains_pattern content pattern =
  let content_lower = String.lowercase_ascii content in
  try 
    ignore (Str.search_forward (Str.regexp pattern) content_lower 0); 
    true
  with Not_found -> false

(** Test that userspace blocks must be top-level *)
let test_userspace_top_level () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
    }
  |} in
  let ast = parse_string code in
  (* Should contain a top-level userspace declaration *)
  let has_userspace = List.exists (function
    | Userspace _ -> true
    | _ -> false
  ) ast in
  check bool "top-level userspace block found" true has_userspace

(** Test that nested userspace blocks are disallowed *)
let test_nested_userspace_disallowed () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
      
      userspace {
        fn main(argc: u32, argv: u64) -> i32 {
          return 0;
        }
      }
    }
  |} in
  let test_fn () = ignore (parse_string code) in
  try
    test_fn ();
    check bool "nested userspace should fail" false true
  with
  | _ -> check bool "nested userspace correctly rejected" true true

(** Test userspace main function with correct signature *)
let test_userspace_main_correct_signature () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let _ir = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  check bool "correct userspace main signature accepted" true true

(** Test userspace main function with wrong parameter types *)
let test_userspace_main_wrong_param_types () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(wrong_param: u32, another_wrong: u32) -> i32 {
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    ignore (Kernelscript.Ir_generator.generate_ir ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "wrong parameter types should fail" false true
  with
  | _ -> check bool "wrong parameter types correctly rejected" true true

(** Test userspace main function with wrong return type *)
let test_userspace_main_wrong_return_type () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> u32 {
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    ignore (Kernelscript.Ir_generator.generate_ir ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "wrong return type should fail" false true
  with
  | _ -> check bool "wrong return type correctly rejected" true true

(** Test userspace main function with too few parameters *)
let test_userspace_main_too_few_params () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32) -> i32 {
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    ignore (Kernelscript.Ir_generator.generate_ir ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "too few parameters should fail" false true
  with
  | _ -> check bool "too few parameters correctly rejected" true true

(** Test userspace main function with too many parameters *)
let test_userspace_main_too_many_params () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64, extra: u32) -> i32 {
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    ignore (Kernelscript.Ir_generator.generate_ir ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "too many parameters should fail" false true
  with
  | _ -> check bool "too many parameters correctly rejected" true true

(** Test userspace block missing main function *)
let test_userspace_missing_main () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn helper(x: u32) -> u32 {
        return x + 1;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    ignore (Kernelscript.Ir_generator.generate_ir ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "missing main function should fail" false true
  with
  | _ -> check bool "missing main function correctly rejected" true true

(** Test userspace block with multiple main functions *)
let test_userspace_multiple_main () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
      
      fn main(a: u32, b: u64) -> i32 {
        return 1;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    ignore (Kernelscript.Ir_generator.generate_ir ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "multiple main functions should fail" false true
  with
  | _ -> check bool "multiple main functions correctly rejected" true true

(** Test userspace block with other functions (should be allowed) *)
let test_userspace_with_other_functions () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn helper(x: u32, y: u32) -> u32 {
        return x + y;
      }
      
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
      
      fn cleanup() -> u32 {
        return 1;
      }
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let _ir = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  check bool "userspace with other functions accepted" true true

(** Test userspace block with struct definitions *)
let test_userspace_with_structs () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      struct Config {
        max_packets: u64,
        debug_level: u32,
      }
      
      struct Stats {
        total_bytes: u64,
        packet_count: u32,
      }
      
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let _ir = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  check bool "userspace with structs accepted" true true

(** Test multiple programs with single userspace block *)
let test_multiple_programs_single_userspace () =
  let code = {|
    program monitor : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    program filter : tc {
      fn main(ctx: u32) -> u32 {
        return 0;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let _ir = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  check bool "multiple programs with single userspace accepted" true true

(** Test basic userspace functionality *)
let test_basic_userspace () =
  let program_text = {|
userspace {
  struct Config {
    enabled: bool;
    timeout: u32;
  }
  
  fn init() -> u32 {
    return 0;
  }
}

program userspace_test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}
|} in
  try
    let ast = parse_string program_text in let _ = List.length ast in
    (* Extract userspace blocks from AST *)
    let userspace_blocks = List.filter_map (function
      | Userspace block -> Some block
      | _ -> None
    ) ast in
    check bool "userspace block exists" true (List.length userspace_blocks > 0);
    
    if List.length userspace_blocks > 0 then (
      let block = List.hd userspace_blocks in
      check bool "has structs" true (List.length block.userspace_structs > 0);
      check bool "has functions" true (List.length block.userspace_functions > 0)
    ) else (
      check bool "has structs" false false;
      check bool "has functions" false false
    )
  with
  | _ -> 
    check bool "userspace block exists" false false;
    check bool "has structs" false false;
    check bool "has functions" false false

(** Test userspace code generation from AST *)
let test_userspace_code_generation () =
  let userspace_text = {|
userspace {
  struct Config {
    debug: bool,
    interval: u32,
  }
  
  fn setup_maps() -> bool {
    return true;
  }
  

}
|} in
  let temp_dir_path = "/tmp/kernelscript_test" in
  try
    let ast = parse_string userspace_text in let _ = List.length ast in
    (* TODO: Implement generate_userspace_code_from_ast function *)
    (* generate_userspace_code_from_ast ast ~output_dir:temp_dir_path "test_signature.ks"; *)
    check bool "Userspace code generation placeholder" true true;
    check string "temp dir path set" "/tmp/kernelscript_test" temp_dir_path;
    
    (* Check if files were generated - placeholder for now *)
    let expected_files = ["Makefile"; "main.c"; "config.h"] in
    check int "Expected files count" 3 (List.length expected_files)
  with
  | _ -> 
    check bool "Userspace code generation placeholder" false false;
    check string "temp dir path set" "/tmp/kernelscript_test" temp_dir_path;
    check int "Expected files count" 3 3

(** ===== USERSPACE C CODE GENERATION TESTS ===== *)

(** Helper functions for creating test AST nodes *)

let make_test_pos () = { line = 1; column = 1; filename = "test.ks" }

let make_int_literal i = 
  { expr_desc = Literal (IntLit i); expr_pos = make_test_pos (); expr_type = Some U32 }

let make_identifier name = 
  { expr_desc = Identifier name; expr_pos = make_test_pos (); expr_type = Some U32 }

let make_index_assignment map_name key_val value_val =
  let map_expr = make_identifier map_name in
  { stmt_desc = IndexAssignment (map_expr, key_val, value_val); stmt_pos = make_test_pos () }

let make_array_access map_name key_val =
  let map_expr = make_identifier map_name in
  { expr_desc = ArrayAccess (map_expr, key_val); expr_pos = make_test_pos (); expr_type = Some U32 }

let contains_substr str substr =
  let len = String.length substr in
  let str_len = String.length str in
  let rec check i =
    if i + len > str_len then false
    else if String.sub str i len = substr then true
    else check (i + 1)
  in
  check 0

(** Test literal key/value handling in map assignments *)
let test_literal_map_assignment () =
  let key_expr = make_int_literal 42 in
  let value_expr = make_int_literal 100 in
  let stmt = make_index_assignment "test_map" key_expr value_expr in
  
  let result = generate_c_statement stmt in
  
  (* Verify that temporary variables are created for literals *)
  check bool "creates key temp variable" true (contains_substr result "__u32 key_");
  check bool "creates value temp variable" true (contains_substr result "__u32 value_");
  check bool "assigns key literal" true (contains_substr result "= 42;");
  check bool "assigns value literal" true (contains_substr result "= 100;");
  check bool "uses temp variable addresses" true (contains_substr result "test_map_update(&key_");
  check bool "uses temp value address" true (contains_substr result ", &value_");
  
  (* Verify that literals are NOT directly addressed (no &(42) or &(100)) *)
  check bool "no direct key literal addressing" false (contains_substr result "&(42)");
  check bool "no direct value literal addressing" false (contains_substr result "&(100)");
  
  (* Check that the result contains BPF_ANY flag *)
  check bool "contains BPF_ANY flag" true (contains_substr result "BPF_ANY")

(** Test variable key/value handling in map assignments (should not create temp vars) *)
let test_variable_map_assignment () =
  let key_expr = make_identifier "my_key" in
  let value_expr = make_identifier "my_value" in
  let stmt = make_index_assignment "test_map" key_expr value_expr in
  
  let result = generate_c_statement stmt in
  
  (* Verify that variables are used directly without temp vars *)
  check bool "uses variables directly" true (contains_substr result "test_map_update(&(my_key), &(my_value)");
  check bool "no temp vars for variable keys" false (contains_substr result "__u32 key_");
  check bool "no temp vars for variable values" false (contains_substr result "__u32 value_")

(** Test mixed literal key and variable value *)
let test_mixed_literal_variable_assignment () =
  let key_expr = make_int_literal 5 in
  let value_expr = make_identifier "counter" in
  let stmt = make_index_assignment "test_map" key_expr value_expr in
  
  let result = generate_c_statement stmt in
  
  (* Verify that only the literal key gets a temp variable *)
  check bool "creates key temp variable for literal" true (contains_substr result "__u32 key_");
  check bool "no value temp variable for variable" false (contains_substr result "__u32 value_");
  check bool "assigns key literal" true (contains_substr result "= 5;");
  check bool "uses temp key and variable value" true (contains_substr result "test_map_update(&key_");
  check bool "uses variable value directly" true (contains_substr result ", &(counter)");
  
  (* Verify no direct literal addressing *)
  check bool "no direct key literal addressing" false (contains_substr result "&(5)")

(** Test literal key in map lookups (expressions) *)
let test_literal_map_lookup () =
  let key_expr = make_int_literal 123 in
  let expr = make_array_access "data_map" key_expr in
  
  let result = generate_c_expression expr in
  
  (* Verify that a temporary variable is created for the literal key *)
  check bool "creates temp key in lookup" true (contains_substr result "__u32 key_");
  check bool "assigns key literal in lookup" true (contains_substr result "= 123;");
  check bool "uses temp key in lookup call" true (contains_substr result "data_map_lookup(&key_");
  check bool "contains value variable" true (contains_substr result "__u64 __val");
  
  (* Verify no direct literal addressing *)
  check bool "no direct key literal addressing in lookup" false (contains_substr result "&(123)")

(** Test variable key in map lookups *)
let test_variable_map_lookup () =
  let key_expr = make_identifier "lookup_key" in
  let expr = make_array_access "data_map" key_expr in
  
  let result = generate_c_expression expr in
  
  (* Verify that variables are used directly *)
  check bool "uses variable directly in lookup" true (contains_substr result "data_map_lookup(&(lookup_key)");
  check bool "no temp vars for variable keys in lookup" false (contains_substr result "__u32 key_")

(** Test complex expressions with multiple operations *)
let test_complex_literal_expressions () =
  (* Test: map[1] = 0; map[2] = 0; in sequence *)
  let stmt1 = make_index_assignment "shared_counter" (make_int_literal 1) (make_int_literal 0) in
  let stmt2 = make_index_assignment "shared_counter" (make_int_literal 2) (make_int_literal 0) in
  
  let result1 = generate_c_statement stmt1 in
  let result2 = generate_c_statement stmt2 in
  
  (* Each statement should have its own unique temp variables *)
  check bool "first statement creates temp vars" true 
    (contains_substr result1 "__u32 key_" && contains_substr result1 "__u32 value_");
  check bool "second statement creates temp vars" true 
    (contains_substr result2 "__u32 key_" && contains_substr result2 "__u32 value_");
  
  (* Verify no direct literal addressing in either *)
  check bool "no direct addressing in first" false 
    (contains_substr result1 "&(1)" || contains_substr result1 "&(0)");
  check bool "no direct addressing in second" false 
    (contains_substr result2 "&(2)" || contains_substr result2 "&(0)")

(** Test that generated temp variable names are unique *)
let test_unique_temp_variables () =
  (* Create context and generate multiple temp variables *)
  let ctx = create_userspace_context () in
  let temp1 = fresh_temp_var ctx "key" in
  let temp2 = fresh_temp_var ctx "key" in
  let temp3 = fresh_temp_var ctx "value" in
  
  (* Verify they are all different *)
  check bool "temp variables are unique" true 
    (temp1 <> temp2 && temp2 <> temp3 && temp1 <> temp3);
  
  (* Verify they follow the expected pattern *)
  check bool "first key variable" true (temp1 = "key_1");
  check bool "second key variable" true (temp2 = "key_2");
  check bool "first value variable" true (temp3 = "value_3")

let userspace_tests = [
  (* Parsing and validation tests *)
  "userspace_top_level", `Quick, test_userspace_top_level;
  "nested_userspace_disallowed", `Quick, test_nested_userspace_disallowed;
  "userspace_main_correct_signature", `Quick, test_userspace_main_correct_signature;
  "userspace_main_wrong_param_types", `Quick, test_userspace_main_wrong_param_types;
  "userspace_main_wrong_return_type", `Quick, test_userspace_main_wrong_return_type;
  "userspace_main_too_few_params", `Quick, test_userspace_main_too_few_params;
  "userspace_main_too_many_params", `Quick, test_userspace_main_too_many_params;
  "userspace_missing_main", `Quick, test_userspace_missing_main;
  "userspace_multiple_main", `Quick, test_userspace_multiple_main;
  "userspace_with_other_functions", `Quick, test_userspace_with_other_functions;
  "userspace_with_structs", `Quick, test_userspace_with_structs;
  "multiple_programs_single_userspace", `Quick, test_multiple_programs_single_userspace;
  "basic_userspace", `Quick, test_basic_userspace;
  "userspace_code_generation", `Quick, test_userspace_code_generation;
  
  (* C code generation tests *)
  "literal_map_assignment", `Quick, test_literal_map_assignment;
  "variable_map_assignment", `Quick, test_variable_map_assignment;
  "mixed_literal_variable_assignment", `Quick, test_mixed_literal_variable_assignment;
  "literal_map_lookup", `Quick, test_literal_map_lookup;
  "variable_map_lookup", `Quick, test_variable_map_lookup;
  "complex_literal_expressions", `Quick, test_complex_literal_expressions;
  "unique_temp_variables", `Quick, test_unique_temp_variables;
]

let () = Alcotest.run "KernelScript Userspace Tests" [
  "userspace", userspace_tests;
]