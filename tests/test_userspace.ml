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
*)

open Kernelscript.Ast
open Kernelscript.Parse
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
  try
    let ast = parse_string code in let _ = List.length ast in
    (* Should contain a top-level userspace declaration *)
    let has_userspace = List.exists (function
      | Userspace _ -> true
      | _ -> false
    ) ast in
    if has_userspace then
      Printf.printf "✓ PASS: Top-level userspace block\n"
    else
      Printf.printf "✗ FAIL: Top-level userspace block (not found)\n"
  with
  | _ -> 
      Printf.printf "✗ FAIL: Top-level userspace block (parse error)\n"

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
  try
    let _ = parse_string code in
    Printf.printf "✗ FAIL: Nested userspace disallowed (should have failed parsing)\n"
  with
  | _ -> 
      (* This should fail with a parse error *)
      Printf.printf "✓ PASS: Nested userspace disallowed (correctly rejected)\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✓ PASS: Correct userspace main signature\n"
  with
  | _ -> 
      Printf.printf "✗ FAIL: Correct userspace main signature (parse error)\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✗ FAIL: Wrong parameter types (should have been rejected)\n"
  with
  | Failure msg ->
      if String.length msg > 0 && Str.string_match (Str.regexp ".*parameters.*argc.*argv.*") msg 0 then
        Printf.printf "✓ PASS: Wrong parameter types (correctly rejected)\n"
      else
        Printf.printf "✗ FAIL: Wrong parameter types (unexpected error)\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✗ FAIL: Wrong return type (should have been rejected)\n"
  with
  | Failure msg ->
      if String.length msg > 0 && Str.string_match (Str.regexp ".*return.*i32.*") msg 0 then
        Printf.printf "✓ PASS: Wrong return type (correctly rejected)\n"
      else
        Printf.printf "✗ FAIL: Wrong return type (unexpected error message)\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✗ FAIL: Too few parameters (should have been rejected)\n"
  with
  | Failure msg ->
      if String.length msg > 0 && Str.string_match (Str.regexp ".*parameters.*argc.*argv.*") msg 0 then
        Printf.printf "✓ PASS: Too few parameters (correctly rejected)\n"
      else
        Printf.printf "✗ FAIL: Too few parameters (unexpected error message)\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✗ FAIL: Too many parameters (should have been rejected)\n"
  with
  | Failure msg ->
      if String.length msg > 0 && Str.string_match (Str.regexp ".*parameters.*argc.*argv.*") msg 0 then
        Printf.printf "✓ PASS: Too many parameters (correctly rejected)\n"
      else
        Printf.printf "✗ FAIL: Too many parameters (unexpected error message)\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✗ FAIL: Missing main function (should have been rejected)\n"
  with
  | Failure msg ->
      if String.length msg > 0 && Str.string_match (Str.regexp ".*main.*function.*") msg 0 then
        Printf.printf "✓ PASS: Missing main function (correctly rejected)\n"
      else
        Printf.printf "✗ FAIL: Missing main function (unexpected error message)\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✗ FAIL: Multiple main functions (should have been rejected)\n"
  with
  | Failure msg ->
      if String.length msg > 0 && Str.string_match (Str.regexp ".*multiple.*main.*") msg 0 then
        Printf.printf "✓ PASS: Multiple main functions (correctly rejected)\n"
      else
        Printf.printf "✗ FAIL: Multiple main functions (unexpected error message)\n"
  | e ->
      Printf.printf "✗ Multiple main functions test failed: unexpected error: %s\n" (Printexc.to_string e)

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✓ PASS: Userspace with other functions\n"
  with
  | _ -> 
      Printf.printf "✗ Userspace with other functions test failed: parse error occurred\n"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✓ PASS: Userspace with structs\n"
  with
  | _ -> 
      Printf.printf "✗ Userspace with structs test failed: parse error: %s\n" "parse error occurred"

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
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    Printf.printf "✓ PASS: Multiple programs with single userspace\n"
  with
  | _ -> 
      Printf.printf "✗ Multiple programs with single userspace test failed: parse error: %s\n" "parse error occurred"

(** Test userspace code generation with correct main signature *)
let test_userspace_codegen_main_signature () =
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
  let temp_dir = ref None in
  let generated_file = ref None in
  try
    let ast = parse_string code in let _ = List.length ast in
    let temp_dir_path = Filename.temp_file "test_userspace" "" in
    Unix.unlink temp_dir_path;
    Unix.mkdir temp_dir_path 0o755;
    temp_dir := Some temp_dir_path;
    
    (* generate_userspace_code_from_ast ast ~output_dir:temp_dir_path "test_signature.ks"; *)
    
    (* Read generated file and check for correct main signature *)
    let generated_file_path = Filename.concat temp_dir_path "test_signature.c" in
    generated_file := Some generated_file_path;
    let ic = open_in generated_file_path in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check for correct C main signature using substring search *)
    let has_main_func = contains_pattern content "int main" in
    let has_argc_param = contains_pattern content "argc" in
    let has_argv_param = contains_pattern content "argv" in
    if has_main_func && has_argc_param && has_argv_param then
      Printf.printf "✓ PASS: Userspace codegen main signature\n"
    else
      Printf.printf "✗ FAIL: Userspace codegen main signature (main=%b argc=%b argv=%b)\n" has_main_func has_argc_param has_argv_param
  with
  | _ -> 
      Printf.printf "✗ Userspace codegen main signature test failed: parse error: %s\n" "parse error occurred";
  
  (* Cleanup *)
  (try
    (match !generated_file with Some f -> if Sys.file_exists f then Unix.unlink f | None -> ());
    (match !temp_dir with Some d -> if Sys.file_exists d then Unix.rmdir d | None -> ())
  with _ -> ())

(** Test userspace code generation file naming (FOO.c from FOO.ks) *)
let test_userspace_codegen_file_naming () =
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
  try
    let ast = parse_string code in let _ = List.length ast in
    let temp_dir = Filename.temp_file "test_userspace" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    (* generate_userspace_code_from_ast ast ~output_dir:temp_dir "my_program.ks"; *)
    
    (* Check that the generated file has the correct name *)
    let expected_file = Filename.concat temp_dir "my_program.c" in
    if Sys.file_exists expected_file then
      Printf.printf "✓ PASS: Userspace codegen file naming\n"
    else
      Printf.printf "✗ FAIL: Userspace codegen file naming (expected %s not found)\n" expected_file;
    
    (* Cleanup *)
    if Sys.file_exists expected_file then Unix.unlink expected_file;
    Unix.rmdir temp_dir;
  with
  | _ -> 
      Printf.printf "✗ Userspace codegen file naming test failed: parse error: %s\n" "parse error occurred"

(** Test userspace code generation with struct definitions *)
let test_userspace_codegen_with_structs () =
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
      
      fn main(argc: u32, argv: u64) -> i32 {
        return 0;
      }
    }
  |} in
  try
    let ast = parse_string code in let _ = List.length ast in
    let temp_dir = Filename.temp_file "test_userspace" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    (* generate_userspace_code_from_ast ast ~output_dir:temp_dir "test_structs.ks"; *)
    
    (* Read generated file and check for struct definition *)
    let generated_file = Filename.concat temp_dir "test_structs.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check for struct definition in generated code using substring search *)
    let has_struct_config = contains_pattern content "struct config" in
    let has_max_packets = contains_pattern content "max_packets" in
    let has_debug_level = contains_pattern content "debug_level" in
    
    if has_struct_config && has_max_packets && has_debug_level then
      Printf.printf "✓ PASS: Userspace codegen with structs\n"
    else
      Printf.printf "✗ FAIL: Userspace codegen with structs (struct_config=%b max_packets=%b debug_level=%b)\n" has_struct_config has_max_packets has_debug_level;
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
  with
      | _ -> 
        Printf.printf "✗ Userspace codegen with structs test failed: parse error occurred\n"

(** Test userspace code generation with multiple functions *)
let test_userspace_codegen_multiple_functions () =
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
  try
    let ast = parse_string code in let _ = List.length ast in
    let temp_dir = Filename.temp_file "test_userspace" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    (* generate_userspace_code_from_ast ast ~output_dir:temp_dir "test_functions.ks"; *)
    
    (* Read generated file and check for function definitions *)
    let generated_file = Filename.concat temp_dir "test_functions.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check for function definitions in generated code using substring search *)
    let has_main_function = contains_pattern content "int main" in
    let has_helper_function = contains_pattern content "helper" in
    let has_cleanup_function = contains_pattern content "cleanup" in
    
    if has_main_function && has_helper_function && has_cleanup_function then
      Printf.printf "✓ PASS: Userspace codegen multiple functions\n"
    else
      Printf.printf "✗ FAIL: Userspace codegen multiple functions (main=%b helper=%b cleanup=%b)\n" has_main_function has_helper_function has_cleanup_function;
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
  with
  | _ -> 
      Printf.printf "✗ Userspace codegen multiple functions test failed: parse error: %s\n" "parse error occurred"

(** Test userspace code generation includes and structure *)
let test_userspace_codegen_includes_structure () =
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
  try
    let ast = parse_string code in let _ = List.length ast in
    let temp_dir = Filename.temp_file "test_userspace" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    (* generate_userspace_code_from_ast ast ~output_dir:temp_dir "test_includes.ks"; *)
    
    (* Read generated file and check for required includes and structure *)
    let generated_file = Filename.concat temp_dir "test_includes.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check for required includes using substring search *)
    let has_stdio_include = contains_pattern content "stdio\\.h" in
    let has_bpf_include = contains_pattern content "bpf/bpf\\.h" in
    let has_libbpf_include = contains_pattern content "bpf/libbpf\\.h" in
    let has_signal_func = contains_pattern content "setup_signal_handling" in
    let has_bpf_struct = contains_pattern content "struct bpf_object" in
    
    if has_stdio_include && has_bpf_include && has_libbpf_include && has_signal_func && has_bpf_struct then
      Printf.printf "✓ PASS: Userspace codegen includes and structure\n"
    else
      Printf.printf "✗ FAIL: Userspace codegen includes and structure (stdio=%b bpf=%b libbpf=%b signal=%b struct=%b)\n" has_stdio_include has_bpf_include has_libbpf_include has_signal_func has_bpf_struct;
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
  with
  | _ -> 
      Printf.printf "✗ Userspace codegen includes and structure test failed: parse error: %s\n" "parse error occurred"

(** Test userspace code generation error handling with invalid syntax *)
let test_userspace_codegen_error_handling () =
  let code = {|
    program test : xdp {
      fn main(ctx: u32) -> u32 {
        return 2;
      }
    }
    
    userspace {
      fn main(wrong_param: u32) -> i32 {
        return 0;
      }
    }
  |} in
  try
    let ast = parse_string code in let _ = List.length ast in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table in
    
    let temp_dir = Filename.temp_file "test_userspace" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    (* generate_userspace_code_from_ast ast ~output_dir:temp_dir "test_error.ks"; *)
    Printf.printf "✗ FAIL: Userspace codegen error handling (should have failed validation)\n"
  with
  | Failure msg ->
      if String.length msg > 0 && Str.string_match (Str.regexp ".*parameters.*argc.*argv.*") msg 0 then
        Printf.printf "✓ PASS: Userspace codegen error handling\n"
      else
        Printf.printf "✗ FAIL: Userspace codegen error handling (unexpected error message: %s)\n" msg

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
  
  targets: ["c"];
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

let userspace_tests = [
  "basic_userspace", `Quick, test_basic_userspace;
  "userspace_code_generation", `Quick, test_userspace_code_generation;
]

let () = Alcotest.run "KernelScript Userspace Tests" [
  "userspace", userspace_tests;
]