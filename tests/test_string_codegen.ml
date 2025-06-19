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

(** Test 1: String assignment generates safe strcpy/strncpy code *)
let test_string_assignment_codegen () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let greeting: str<20> = "Hello"
  let name: str<30> = "World"
  let short: str<5> = "Hi"
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_string_assignment" in
    
    (* Should generate runtime length checking to avoid truncation warnings *)
    check bool "has strlen check" true (contains_pattern result "strlen.*__src_len");
    check bool "has strcpy for safe case" true (contains_pattern result "strcpy.*var_.*\"Hello\"");
    check bool "has strncpy for truncation case" true (contains_pattern result "strncpy.*var_");
    check bool "has explicit null termination" true (contains_pattern result "\\[.*\\].*=.*'\\\\0'");
    
    (* Should have proper bounds checking *)
    check bool "has size comparison" true (contains_pattern result "if.*__src_len.*<.*[0-9]+");
  with
  | exn -> fail ("String assignment test failed: " ^ Printexc.to_string exn)

(** Test 2: String concatenation generates safe concatenation code *)
let test_string_concatenation_codegen () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let first: str<10> = "Hello"
  let second: str<10> = "World"
  let result: str<25> = first + second
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_string_concat" in
    
    (* Should generate safe concatenation with temporary buffers *)
    check bool "uses temporary buffer" true (contains_pattern result "__tmp\\[[0-9]+\\]");
    check bool "initializes temp buffer" true (contains_pattern result "__tmp\\[[0-9]+\\].*=.*{0}");
    check bool "has strlen checks for concat" true (contains_pattern result "strlen.*__left_len.*strlen.*__right_len");
    check bool "has safe concat path" true (contains_pattern result "strcpy.*__tmp.*strcat.*__tmp");
    check bool "has truncation path" true (contains_pattern result "strncpy.*__tmp");
    check bool "bounds check for concat" true (contains_pattern result "if.*__left_len.*\\+.*__right_len.*<");
    
    (* Should return the temporary buffer within the assignment context *)
    check bool "returns temp buffer" true (contains_pattern result "__tmp.*}.*}");
  with
  | exn -> fail ("String concatenation test failed: " ^ Printexc.to_string exn)

(** Test 3: String comparison generates strcmp calls *)
let test_string_comparison_codegen () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let name: str<20> = "Alice"
  let second: str<20> = "Bob"
  
  if (name == second) {
    return 1
  }
  
  return 0
}
|} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test_string_compare" in
    
    let temp_dir = Filename.temp_file "test_string_codegen" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
      ir ~output_dir:temp_dir "test_string_compare" in
    let generated_file = Filename.concat temp_dir ("test_string_compare" ^ ".c") in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      let result = content in
      
      (* Should generate strcmp for equality with variable assignment *)
      check bool "equality uses strcmp" true (contains_pattern result "strcmp.*var_.*var_.*==.*0");
      check bool "has variable comparison" true (contains_pattern result "strcmp.*var_.*var_");
      check bool "assigns comparison result" true (contains_pattern result "var_.*=.*(strcmp");
      check bool "uses comparison variable in if" true (contains_pattern result "if.*(var_");
      
      (* Should have proper string assignments *)
      check bool "has Alice assignment" true (contains_pattern result "strcpy.*var_.*\"Alice\"");
      check bool "has Bob assignment" true (contains_pattern result "strcpy.*var_.*\"Bob\"");
    ) else (
      failwith "Failed to generate userspace code file"
    )
  with
  | exn -> 
    fail ("String comparison test failed: " ^ Printexc.to_string exn)

(** Test 4: String indexing generates array access *)
let test_string_indexing_codegen () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let message: str<20> = "Hello"
  let first: char = message[0]
  let second: char = message[1]
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_string_index" in
    
    (* Should generate direct array access *)
    check bool "has array indexing syntax" true (contains_pattern result "var_.*\\[0\\]");
    check bool "second index access" true (contains_pattern result "var_.*\\[1\\]");
    check bool "char assignment" true (contains_pattern result "var_.*=.*var_.*\\[[0-9]+\\]");
    
    (* Should not have complex bounds checking for simple indexing *)
    check bool "direct array access" true (contains_pattern result "var_.*=.*var_.*\\[.*\\]");
  with
  | exn -> fail ("String indexing test failed: " ^ Printexc.to_string exn)

(** Test 5: String truncation edge cases *)
let test_string_truncation_edge_cases () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let short: str<6> = "toolong"  // Will be truncated
  let exact: str<6> = "exact"    // Fits exactly
  let tiny: str<3> = "hi"        // Much shorter than buffer
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_string_truncation" in
    
    (* Should handle all cases safely *)
    check bool "has strlen checks" true (contains_pattern result "strlen.*\"toolong\"");
    check bool "has safe strcpy path" true (contains_pattern result "strcpy.*var_.*\"exact\"");
    check bool "has truncation path" true (contains_pattern result "strncpy.*var_.*\"toolong\".*[0-9]+.*-.*1");
    check bool "explicit null termination" true (contains_pattern result "var_.*\\[.*-.*1\\].*=.*'\\\\0'");
    
    (* Should have proper size checking - the runtime checks use the declared buffer size *)
    check bool "size check for short buffer" true (contains_pattern result "__src_len.*<.*[0-9]+");
    check bool "size check for tiny buffer" true (contains_pattern result "__src_len.*<.*[0-9]+");
  with
  | exn -> fail ("String truncation test failed: " ^ Printexc.to_string exn)

(** Test 6: Complex string operations together *)
let test_complex_string_operations () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let greeting: str<10> = "Hello"
  let target: str<10> = "World"
  let punctuation: str<5> = "!"
  
  let message: str<25> = greeting + target
  let final_msg: str<30> = message + punctuation
  
  if (final_msg == "HelloWorld!") {
    let first_char: char = final_msg[0]
    let last_char: char = final_msg[10]
    return 1
  }
  
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_complex_strings" in
    
    (* Should have all string operations *)
    check bool "has string assignment" true (contains_pattern result "strlen.*__src_len");
    check bool "has concatenation" true (contains_pattern result "__tmp\\[[0-9]+\\].*strcpy.*strcat");
    check bool "has comparison" true (contains_pattern result "strcmp.*\"HelloWorld!\".*==.*0");
    check bool "has indexing" true (contains_pattern result "var_.*\\[[0-9]+\\]");
    
    (* Should be properly nested and structured *)
    check bool "has conditional with comparison variable" true (contains_pattern result "if.*var_");
    check bool "has temp buffer usage" true (contains_pattern result "__tmp\\[[0-9]+\\]");
  with
  | exn -> fail ("Complex string operations test failed: " ^ Printexc.to_string exn)

(** Test 7: Empty and single character strings *)
let test_empty_and_single_char_strings () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let single: str<2> = "A"
  let empty_like: str<1> = ""
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_edge_strings" in
    
    (* Should handle small strings safely *)
    check bool "handles single char" true (contains_pattern result "strlen.*\"A\"");
    check bool "handles empty string" true (contains_pattern result "strlen.*\"\"");
    check bool "size check for single" true (contains_pattern result "__src_len.*<.*2");
    check bool "size check for empty buffer" true (contains_pattern result "__src_len.*<.*1");
    
    (* Should still use safe string handling *)
    check bool "safe assignment for single" true (contains_pattern result "strcpy.*var_.*\"A\"");
  with
  | exn -> fail ("Empty and single char strings test failed: " ^ Printexc.to_string exn)

(** Test 8: Variable declarations use correct C array syntax *)
let test_string_variable_declarations () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let small: str<16> = "small"
  let medium: str<64> = "medium"
  let large: str<256> = "large"
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_string_declarations" in
    
    (* Should declare variables with proper C array syntax *)
    check bool "declares char array 16" true (contains_pattern result "char var_.*\\[16\\]");
    check bool "declares char array 64" true (contains_pattern result "char var_.*\\[64\\]");
    check bool "declares char array 256" true (contains_pattern result "char var_.*\\[256\\]");
    
    (* Should NOT use incorrect syntax *)
    check bool "no char[N] var syntax" false (contains_pattern result "char\\[[0-9]+\\] var_");
    check bool "no str_N_t typedefs" false (contains_pattern result "str_[0-9]+_t var_");
  with
  | exn -> fail ("String variable declarations test failed: " ^ Printexc.to_string exn)

(** Test 9: String literal and mixed comparisons *)
let test_string_literal_and_mixed_comparisons () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let name: str<20> = "Alice"
  let other: str<20> = "Bob"
  
  if (name == "Alice") {
    return 1
  }
  
  if (name != other) {
    return 2
  }
  
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_string_literal_compare" in
    
    (* Should generate strcmp for equality with string literals *)
    check bool "equality uses strcmp" true (contains_pattern result "strcmp.*var_.*\"Alice\".*==.*0");
    check bool "inequality uses strcmp" true (contains_pattern result "strcmp.*var_.*var_.*!=.*0");
    check bool "has string literal comparison" true (contains_pattern result "strcmp.*var_.*\"Alice\"");
    check bool "has variable comparison" true (contains_pattern result "strcmp.*var_.*var_");
    
    (* Should be stored in variables then used in conditionals *)
    check bool "assigns comparison result" true (contains_pattern result "var_.*=.*strcmp");
    check bool "uses comparison variable in if" true (contains_pattern result "if.*var_");
  with
  | exn -> fail ("String literal and mixed comparisons test failed: " ^ Printexc.to_string exn)

(** Test suite for string code generation *)
let tests = [
  test_case "String assignment code generation" `Quick test_string_assignment_codegen;
  test_case "String indexing code generation" `Quick test_string_indexing_codegen;
  test_case "String comparison code generation" `Quick test_string_comparison_codegen;
  test_case "String concatenation code generation" `Quick test_string_concatenation_codegen;
  test_case "String truncation edge cases" `Quick test_string_truncation_edge_cases;
  test_case "Complex string operations" `Quick test_complex_string_operations;
  test_case "Empty and single character strings" `Quick test_empty_and_single_char_strings;
  test_case "String variable declarations" `Quick test_string_variable_declarations;
  test_case "String literal and mixed comparisons" `Quick test_string_literal_and_mixed_comparisons;
]

(** Main test runner *)
let () =
  Alcotest.run "String Code Generation Tests" [
    ("string_codegen", tests);
  ] 