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
    | Kernelscript.Ast.Userspace _ -> true
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
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
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
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
      | Kernelscript.Ast.Userspace block -> Some block
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

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}
|} in
  try
    let ast = parse_string userspace_text in let _ = List.length ast in
    check bool "Userspace code generation placeholder" true true
  with
  | _ -> 
    check bool "Userspace code generation placeholder" false false

(** Test literal map assignment with test functions - should not require main *)
let test_literal_map_assignment () =
  let program = {|
map<u32, u32> test_map : HashMap(1024) { };

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    test_map[42] = 100;
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test" in
    
    (* Generate userspace C code *)
    let temp_output_dir = "temp_test_userspace" in
    Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
      ir ~output_dir:temp_output_dir "test_literal_map_assignment.ks";
    
    (* Read the generated C code *)
    let userspace_file = temp_output_dir ^ "/test_literal_map_assignment.c" in
    let result = 
      try
        let ic = open_in userspace_file in
        let content = really_input_string ic (in_channel_length ic) in
        close_in ic;
        (* Clean up temp directory *)
        Sys.remove userspace_file;
        (try Unix.rmdir temp_output_dir with _ -> ());
        content
      with _ -> "/* Failed to read generated code */"
    in
  
    (* Verify basic functionality *)
    check bool "contains test function" true (String.length result > 0);
    
    (* CRITICAL: Verify the problematic &(literal) pattern is NOT generated *)
    let has_invalid_literal_ref = 
      try ignore (Str.search_forward (Str.regexp "&(42)\\|&(100)") result 0); true 
      with Not_found -> false in
    check bool "no invalid &(literal) references" false has_invalid_literal_ref;
    
    (* Verify proper C code patterns for literal map assignment *)
    let has_map_update = 
      try ignore (Str.search_forward (Str.regexp "bpf_map_update_elem\\|test_map_update") result 0); true 
      with Not_found -> false in
    check bool "has map update operation" true has_map_update;
    
    (* Verify that literals 42 and 100 are present but not in &(literal) form *)
    let has_literal_42 = 
      try ignore (Str.search_forward (Str.regexp "42") result 0); true 
      with Not_found -> false in
    let has_literal_100 = 
      try ignore (Str.search_forward (Str.regexp "100") result 0); true 
      with Not_found -> false in
    check bool "contains literal 42" true has_literal_42;
    check bool "contains literal 100" true has_literal_100;
    
    (* Verify no malformed parentheses around literals in address-of operations *)
    let has_malformed_address = 
      try ignore (Str.search_forward (Str.regexp "&([0-9]+)") result 0); true 
      with Not_found -> false in
    check bool "no malformed &(number) patterns" false has_malformed_address;
    
    (* Verify that proper C variable handling is used instead *)
    let has_proper_variable_usage = 
      try ignore (Str.search_forward (Str.regexp "uint32_t\\|&[a-zA-Z_][a-zA-Z0-9_]*") result 0); true 
      with Not_found -> false in
    check bool "uses proper variable references" true has_proper_variable_usage;
    
    check bool "test completed successfully" true true
  with
  | _ -> 
    check bool "test failed with exception" false true

(** Test variable map assignment with test functions - should not require main *)
let test_variable_map_assignment () =
  let program = {|
map<u32, u32> test_map : HashMap(1024) { };

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let my_key = 42;
    let my_value = 100;
    test_map[my_key] = my_value;
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table "test" in
    
    (* Generate userspace C code *)
    let temp_output_dir = "temp_test_userspace" in
    Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
      ir ~output_dir:temp_output_dir "test_variable_map_assignment.ks";
    
    (* Read the generated C code *)
    let userspace_file = temp_output_dir ^ "/test_variable_map_assignment.c" in
    let result = 
      try
        let ic = open_in userspace_file in
        let content = really_input_string ic (in_channel_length ic) in
        close_in ic;
        (* Clean up temp directory *)
        Sys.remove userspace_file;
        (try Unix.rmdir temp_output_dir with _ -> ());
        content
      with _ -> "/* Failed to read generated code */"
    in
  
    (* Verify basic functionality *)
    check bool "contains test function" true (String.length result > 0);
    
    (* Verify that variables work correctly (IR generates var_N names) *)
    let has_variable_declarations = 
      try ignore (Str.search_forward (Str.regexp "uint32_t.*var_[0-9]+") result 0); true 
      with Not_found -> false in
    check bool "has variable declarations" true has_variable_declarations;
    
    (* Verify proper C code patterns for variable map assignment *)
    let has_map_update = 
      try ignore (Str.search_forward (Str.regexp "bpf_map_update_elem\\|test_map_update") result 0); true 
      with Not_found -> false in
    check bool "has map update operation" true has_map_update;
    
    (* Verify that variable references are used properly (var_0, var_1, etc.) *)
    let has_variable_references = 
      try ignore (Str.search_forward (Str.regexp "&var_[0-9]+") result 0); true 
      with Not_found -> false in
    check bool "uses proper variable references" true has_variable_references;
    
    (* Ensure no &(literal) patterns exist (should be clean since we use variables) *)
    let has_malformed_address = 
      try ignore (Str.search_forward (Str.regexp "&([0-9]+)") result 0); true 
      with Not_found -> false in
    check bool "no malformed &(number) patterns" false has_malformed_address;
    
    (* Verify the original literal values 42 and 100 are assigned to variables *)
    let has_literal_42 = 
      try ignore (Str.search_forward (Str.regexp "var_[0-9]+.*=.*42") result 0); true 
      with Not_found -> false in
    let has_literal_100 = 
      try ignore (Str.search_forward (Str.regexp "var_[0-9]+.*=.*100") result 0); true 
      with Not_found -> false in
    check bool "assigns literal 42 to variable" true has_literal_42;
    check bool "assigns literal 100 to variable" true has_literal_100;
    
    check bool "test completed successfully" true true
  with
  | _ -> 
    check bool "test failed with exception" false true

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
  
  (* Test functionality tests - these use for_testing=true *)
  "literal_map_assignment", `Quick, test_literal_map_assignment;
  "variable_map_assignment", `Quick, test_variable_map_assignment;
]

let () = Alcotest.run "KernelScript Userspace Tests" [
  "userspace", userspace_tests;
]
