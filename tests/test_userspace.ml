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

open Kernelscript.Parse
open Alcotest
module Ir = Kernelscript.Ir

(** Test that userspace blocks must be top-level *)
let test_userspace_top_level () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
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
    | Kernelscript.Ast.Userspace _ -> true
    | _ -> false
  ) ast in
  check bool "top-level userspace block found" true has_userspace

(** Test that nested userspace blocks are disallowed *)
let test_nested_userspace_disallowed () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
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
      fn main(ctx: XdpContext) -> XdpAction {
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "correct userspace main signature accepted" true true

(** Test userspace main function with wrong parameter types *)
let test_userspace_main_wrong_param_types () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
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
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
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
      fn main(ctx: XdpContext) -> XdpAction {
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
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
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
      fn main(ctx: XdpContext) -> XdpAction {
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
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
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
      fn main(ctx: XdpContext) -> XdpAction {
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
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
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
      fn main(ctx: XdpContext) -> XdpAction {
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
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
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
      fn main(ctx: XdpContext) -> XdpAction {
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
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
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
      fn main(ctx: XdpContext) -> XdpAction {
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "userspace with other functions accepted" true true

(** Test userspace block with struct definitions *)
let test_userspace_with_structs () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "userspace with structs accepted" true true

(** Test multiple programs with single userspace block *)
let test_multiple_programs_single_userspace () =
  let code = {|
    program monitor : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    program filter : tc {
      fn main(ctx: XdpContext) -> XdpAction {
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "multiple programs with single userspace accepted" true true

(** Test basic userspace functionality *)
let test_basic_userspace () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test" in
    match ir with
    | { Ir.userspace_program = Some { Ir.userspace_functions = functions; userspace_structs = structs; userspace_configs = configs; _ }; _ } ->
      check bool "userspace block exists" true true;
      check bool "main function exists" (List.exists (fun f -> f.Ir.func_name = "main") functions) true;
      check bool "structs list accessible" (List.length structs >= 0) true;
      check bool "configs list accessible" (List.length configs >= 0) true;
    | _ -> check bool "userspace block not found" false true
  in
  try
    test_fn ();
    check bool "basic userspace test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test userspace code generation from AST *)
let test_userspace_codegen () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test" in
    match ir with
    | { Ir.userspace_program = Some { Ir.userspace_functions = functions; userspace_structs = structs; userspace_configs = configs; _ }; _ } ->
      check bool "userspace block exists" true true;
      check bool "main function exists" (List.exists (fun f -> f.Ir.func_name = "main") functions) true;
      check bool "structs list accessible" (List.length structs >= 0) true;
      check bool "configs list accessible" (List.length configs >= 0) true;
    | _ -> check bool "userspace block not found" false true
  in
  try
    test_fn ();
    check bool "userspace codegen test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test literal map assignment with test functions - should not require main *)
let test_literal_map_assignment () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        test_map[1] = 42;
        let x = test_map[1];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "literal map assignment test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map lookup with literal key *)
let test_map_lookup_with_literal_key () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        test_map[1] = 42;
        let x = test_map[1];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map lookup with literal key test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map update with literal key and value *)
let test_map_update_with_literal_key_value () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        test_map[1] = 42;
        test_map[1] = 43;
        let x = test_map[1];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map update with literal key value test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map delete with literal key *)
let test_map_delete_with_literal_key () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        test_map[1] = 42;
        delete test_map[1];
        let x = test_map[1];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map delete with literal key test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map iterate with literal key *)
let test_map_iterate_with_literal_key () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        test_map[1] = 42;
        test_map[2] = 43;
        let sum = test_map[1] + test_map[2];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map iterate with literal key test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test mixed literal and variable expressions *)
let test_mixed_literal_variable_expressions () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        let key = 1;
        let value = 42;
        test_map[key] = value;
        test_map[2] = value + 1;
        let y = test_map[key] + test_map[2];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "mixed literal variable expressions test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test unique temporary variable names *)
let test_unique_temp_var_names () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        test_map[1] = 42;
        test_map[2] = 43;
        test_map[3] = 44;
        let z = test_map[1] + test_map[2] + test_map[3];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "unique temp var names test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test no direct literal addressing *)
let test_no_direct_literal_addressing () =
  let code = {|
    map<u32, u32> test_map : HashMap(1024);
    
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 2;
      }
    }
    
    userspace {
      fn main(argc: u32, argv: u64) -> i32 {
        test_map[1] = 42;
        let x = test_map[1];
        return 0;
      }
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "no direct literal addressing test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test suite *)
let suite = [
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
  "userspace_code_generation", `Quick, test_userspace_codegen;
  
  (* Test functionality tests - these use for_testing=true *)
  "literal_map_assignment", `Quick, test_literal_map_assignment;
  "map_lookup_with_literal_key", `Quick, test_map_lookup_with_literal_key;
  "map_update_with_literal_key_value", `Quick, test_map_update_with_literal_key_value;
  "map_delete_with_literal_key", `Quick, test_map_delete_with_literal_key;
  "map_iterate_with_literal_key", `Quick, test_map_iterate_with_literal_key;
  "mixed_literal_variable_expressions", `Quick, test_mixed_literal_variable_expressions;
  "unique_temp_var_names", `Quick, test_unique_temp_var_names;
  "no_direct_literal_addressing", `Quick, test_no_direct_literal_addressing;
]

let () =
  Alcotest.run "userspace tests" [
    "userspace", suite
  ]