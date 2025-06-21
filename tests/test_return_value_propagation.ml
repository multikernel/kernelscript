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
@xdp fn test(ctx: XdpContext) -> XdpAction {
  return 2
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_basic_return" in
    
    (* With explicit-only semantics, return statements are preserved as-is *)
    check bool "has direct return statement" true (contains_pattern generated_code "return 0");
    
    (* Verify the main function exists and is properly generated *)
    check bool "main function exists" true (contains_pattern generated_code "int main(");
    
    (* Verify no implicit cleanup infrastructure *)
    check bool "no __return_value variable" false (contains_pattern generated_code "__return_value");
    check bool "no goto cleanup statements" false (contains_pattern generated_code "goto cleanup");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 2: Multiple return statements in main function *)
let test_multiple_return_statements () =
  let program_text = {|
@xdp fn test(ctx: XdpContext) -> XdpAction {
  return 2
}

fn main() -> i32 {
  let x = 10
  if (x > 5) {
    return 1
  }
  return 0
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_multiple_returns" in
    
    (* With explicit-only semantics, return statements are preserved as-is *)
    check bool "has first return statement" true (contains_pattern generated_code "return 1");
    check bool "has second return statement" true (contains_pattern generated_code "return 0");
    
    (* Verify no implicit cleanup infrastructure *)
    check bool "no __return_value variable" false (contains_pattern generated_code "__return_value");
    check bool "no goto cleanup statements" false (contains_pattern generated_code "goto cleanup");
    check bool "no cleanup label" false (contains_pattern generated_code "cleanup:");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 3: Return statements in loops and conditionals *)
let test_return_in_control_structures () =
  let program_text = {|
@xdp fn test(ctx: XdpContext) -> XdpAction {
  return 2
}

fn main() -> i32 {
  for (i in 0..10) {
    if (i == 5) {
        return 42
      }
  }
  return 0
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_return_in_loops" in
    
    (* With explicit-only semantics, return statements are preserved as-is *)
    check bool "has return in loop preserved" true (contains_pattern generated_code "return 42");
    check bool "has final return preserved" true (contains_pattern generated_code "return 0");
    
    (* Verify no implicit transformation occurred *)
    check bool "no __return_value variable" false (contains_pattern generated_code "__return_value");
    check bool "no goto cleanup statements" false (contains_pattern generated_code "goto cleanup");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 4: Non-main functions should still use direct returns *)
let test_non_main_function_returns () =
  let program_text = {|
@xdp fn test(ctx: XdpContext) -> XdpAction {
  return 2
}

fn helper() -> u32 {
  return 123
}

fn main() -> i32 {
  let result = helper()
  return 0
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_non_main_returns" in
    
    (* With explicit-only semantics, both helper and main functions use direct returns *)
    check bool "helper function uses direct return" true (contains_pattern generated_code "return 123");
    check bool "main function uses direct return" true (contains_pattern generated_code "return 0");
    
    (* Verify no implicit transformation occurred *)
    check bool "no __return_value variable" false (contains_pattern generated_code "__return_value");
    check bool "no goto cleanup statements" false (contains_pattern generated_code "goto cleanup");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 5: No automatic cleanup section in explicit-only semantics *)
let test_cleanup_always_reachable () =
  let program_text = {|
@xdp fn test(ctx: XdpContext) -> XdpAction {
  return 2
}

fn main() -> i32 {
  return 1
}
|} in
  
  try
    let generated_code = generate_userspace_code_from_program program_text "test_cleanup_reachable" in
    
    (* With explicit-only semantics, there's no automatic cleanup infrastructure *)
    check bool "no cleanup label" false (contains_pattern generated_code "cleanup:");
    check bool "no __return_value variable" false (contains_pattern generated_code "__return_value");
    check bool "no goto cleanup statements" false (contains_pattern generated_code "goto cleanup");
    
    (* Verify direct return is preserved *)
    check bool "has direct return" true (contains_pattern generated_code "return 1");
    check bool "main function exists" true (contains_pattern generated_code "int main(");
    
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