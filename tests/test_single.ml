open Alcotest
open Kernelscript.Parse

(** Helper function to check if generated code contains a pattern *)
let contains_pattern code pattern =
  try
    let regex = Str.regexp pattern in
    ignore (Str.search_forward regex code 0);
    true
  with Not_found -> false

(** Helper function to generate userspace code from a program with proper IR generation *)
let generate_userspace_code_from_program program_text filename =
  let ast = parse_string program_text in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table filename in
  
  let temp_dir = Filename.temp_file "test_string_codegen" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
    ir ~output_dir:temp_dir filename in
  let generated_file = Filename.concat temp_dir (filename ^ ".c") in
  
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

(** Test: String comparison generates strcmp calls *)
let test_string_comparison_codegen () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let name: str<20> = "Alice"
  let other: str<20> = "Bob"
  
  if name == "Alice" {
    return 1
  }
  
  if name != other {
    return 2
  }
  
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_string_compare" in
    
    (* Should generate strcmp for equality *)
    check bool "equality uses strcmp" true (contains_pattern result "strcmp.*var_.*\"Alice\".*==.*0");
    check bool "inequality uses strcmp" true (contains_pattern result "strcmp.*var_.*var_.*!=.*0");
    check bool "has string literal comparison" true (contains_pattern result "strcmp.*var_.*\"Alice\"");
    check bool "has variable comparison" true (contains_pattern result "strcmp.*var_.*var_");
    
    (* Should be stored in variables then used in conditionals *)
    check bool "assigns comparison result" true (contains_pattern result "var_.*=.*strcmp");
    check bool "uses comparison variable in if" true (contains_pattern result "if.*var_");
  with
  | exn -> fail ("String comparison test failed: " ^ Printexc.to_string exn)

let () =
  Alcotest.run "Single String Comparison Test" [
    ("single_test", [
      test_case "String comparison code generation" `Quick test_string_comparison_codegen;
    ]);
  ] 