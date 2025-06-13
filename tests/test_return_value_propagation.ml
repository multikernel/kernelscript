open Alcotest
open Kernelscript.Parse
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator
open Kernelscript.Userspace_codegen

(** Helper function to generate userspace C code from program text *)
let generate_userspace_code_from_program program_text source_name =
  let ast = parse_string program_text in
  let symbol_table = build_symbol_table ast in
  let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
  let ir = generate_ir annotated_ast symbol_table source_name in
  
  let temp_dir = Filename.temp_file "test_return_value" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  let _output_file = generate_userspace_code_from_ir 
    ir ~output_dir:temp_dir (source_name ^ ".ks") in
  let generated_file = Filename.concat temp_dir (source_name ^ ".c") in
  
  if Sys.file_exists generated_file then (
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    content
  ) else (
    failwith "Failed to generate userspace code file"
  )

(** Helper function to check if a string contains a pattern *)
let contains_pattern content pattern =
  try
    ignore (Str.search_forward (Str.regexp pattern) content 0);
    true
  with Not_found -> false

(** Test 1: Basic return value propagation in main function *)
let test_basic_return_value_propagation () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn main() -> i32 {
    return 0;
  }
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_basic_return" in
    
    (* Verify that direct return statements are replaced with __return_value assignment and goto *)
    check bool "has __return_value assignment" true (contains_pattern generated_code "__return_value = 0; goto cleanup;");
    
    (* Verify that cleanup label exists *)
    check bool "has cleanup label" true (contains_pattern generated_code "cleanup:");
    
    (* Verify that final return uses __return_value *)
    check bool "final return uses __return_value" true (contains_pattern generated_code "return __return_value;");
    
    (* Verify that user logic uses goto cleanup instead of direct returns *)
    check bool "no direct return in user logic" false (contains_pattern generated_code "return 0;\n    \n    cleanup:");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 2: Multiple return statements in main function *)
let test_multiple_return_statements () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn main() -> i32 {
    let x = 10;
    if x > 5 {
      return 1;
    }
    return 0;
  }
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_multiple_returns" in
    
    (* Verify that both return statements are replaced *)
    check bool "has first __return_value assignment" true (contains_pattern generated_code "__return_value = 1; goto cleanup;");
    check bool "has second __return_value assignment" true (contains_pattern generated_code "__return_value = 0; goto cleanup;");
    
    (* Verify cleanup section exists *)
    check bool "has cleanup label" true (contains_pattern generated_code "cleanup:");
    check bool "cleanup calls cleanup_bpf_environment" true (contains_pattern generated_code "cleanup_bpf_environment();");
    check bool "cleanup has shutdown message" true (contains_pattern generated_code "Userspace coordinator shutting down");
    check bool "final return uses __return_value" true (contains_pattern generated_code "return __return_value;");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 3: Return statements in loops and conditionals *)
let test_return_in_control_structures () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn main() -> i32 {
    for i in 0..10 {
      if i == 5 {
        return 42;
      }
    }
    return 0;
  }
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_return_in_loops" in
    
    (* Verify that return inside loop is converted correctly *)
    check bool "has return in loop converted" true (contains_pattern generated_code "__return_value = 42; goto cleanup;");
    check bool "has final return converted" true (contains_pattern generated_code "__return_value = 0; goto cleanup;");
    
    (* Verify no direct returns exist in user logic *)
    check bool "no direct return 42" false (contains_pattern generated_code "return 42;");
    check bool "user logic uses goto pattern" true (contains_pattern generated_code "__return_value.*goto cleanup");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 4: Non-main functions should still use direct returns *)
let test_non_main_function_returns () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn helper() -> u32 {
    return 123;
  }
  
  fn main() -> i32 {
    let result = helper();
    return 0;
  }
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_non_main_returns" in
    
    (* Verify that helper function still uses direct return *)
    check bool "helper function uses direct return" true (contains_pattern generated_code "return 123;");
    
    (* Verify that main function uses goto cleanup *)
    check bool "main function uses goto cleanup" true (contains_pattern generated_code "__return_value = 0; goto cleanup;");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 5: Cleanup section is always reachable *)
let test_cleanup_always_reachable () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn main() -> i32 {
    return 1;
  }
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_cleanup_reachable" in
    
    (* Split the generated code at the cleanup label *)
    let parts = Str.split (Str.regexp "cleanup:") generated_code in
    check bool "cleanup section exists" true (List.length parts = 2);
    
    if List.length parts = 2 then (
      let before_cleanup = List.nth parts 0 in
      let after_cleanup = List.nth parts 1 in
      
      (* Verify no direct returns from user logic before cleanup *)
      check bool "no direct returns from user logic" false (contains_pattern before_cleanup "final_block:.*return [0-9]+;");
      
      (* Verify cleanup section has proper structure *)
      check bool "cleanup calls bpf cleanup" true (contains_pattern after_cleanup "cleanup_bpf_environment");
      check bool "cleanup has shutdown message" true (contains_pattern after_cleanup "shutting down");
      check bool "cleanup returns __return_value" true (contains_pattern after_cleanup "return __return_value");
    )
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** All return value propagation tests *)
let return_value_propagation_tests = [
  "basic_return_value_propagation", `Quick, test_basic_return_value_propagation;
  "multiple_return_statements", `Quick, test_multiple_return_statements;
  "return_in_control_structures", `Quick, test_return_in_control_structures;
  "non_main_function_returns", `Quick, test_non_main_function_returns;
  "cleanup_always_reachable", `Quick, test_cleanup_always_reachable;
]

let () =
  run "KernelScript Return Value Propagation Tests" [
    "return_value_propagation", return_value_propagation_tests;
  ] 