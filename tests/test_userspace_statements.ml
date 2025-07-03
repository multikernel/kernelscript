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
  
  let temp_dir = Filename.temp_file "test_userspace_statements" "" in
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

(** Test 1: Basic If statement without else clause *)
let test_basic_if_statement () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var x = 5
  if (x == 5) {
    var result = 1
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_basic_if" in
    
    check bool "generates if keyword" true (contains_pattern result "if");
    check bool "has condition with equality" true (contains_pattern result "== 5");
    check bool "has opening brace" true (contains_pattern result "{");
    check bool "has closing brace" true (contains_pattern result "}");
    check bool "contains then body" true (contains_pattern result "= 1");
    check bool "no else clause" false (contains_pattern result "else");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 2: If statement with else clause *)
let test_if_else_statement () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var count = 15
  if (count > 10) {
    var status = 1
  } else {
    var status = 0
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_if_else" in
    
    check bool "generates if keyword" true (contains_pattern result "if");
    check bool "has condition with greater than" true (contains_pattern result "> 10");
    check bool "has then body" true (contains_pattern result "= 1");
    check bool "has else keyword" true (contains_pattern result "else");
    check bool "has else body" true (contains_pattern result "= 0");
    check bool "proper brace structure" true (contains_pattern result "} else {");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 3: Break statement generation *)
let test_break_statement () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  for (i in 0..10) {
    if (i == 5) {
      break
    }
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_break" in
    
    check bool "generates break statement" true (contains_pattern result "break;");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 4: Continue statement generation *)
let test_continue_statement () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  for (i in 0..10) {
    if (i % 2 == 0) {
      continue
    }
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_continue" in
    
    check bool "generates continue statement" true (contains_pattern result "continue;");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 5: If statement with break inside for loop *)
let test_if_with_break_in_loop () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var count = 0
  for (i in 0..10) {
    if (i == 5) {
      break
    }
    count = count + 1
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_if_break_loop" in
    
    check bool "generates for loop" true (contains_pattern result "for.*=");
    check bool "has if condition" true (contains_pattern result "== 5");
    check bool "has break statement" true (contains_pattern result "break;");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 6: If statement with continue inside for loop *)
let test_if_with_continue_in_loop () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var sum = 0
  for (i in 1..10) {
    if (i % 2 == 0) {
      continue
    }
    sum = sum + i
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_if_continue_loop" in
    
    check bool "generates for loop" true (contains_pattern result "for");
    check bool "has modulo operation" true (contains_pattern result "% 2");
    check bool "has equality check" true (contains_pattern result "== 0");
    check bool "has continue statement" true (contains_pattern result "continue;");
    check bool "has sum assignment" true (contains_pattern result "\\+");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 7: Complex binary operators in if conditions *)
let test_complex_binary_operators () =
  let program_text_and = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var a = 10
  var b = 5
  if (a > b && b > 0) {
    var result = 1
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in

  let program_text_or = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var a = 10
  var b = 5
  if (a < 0 || b > 3) {
    var result = 1
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result_and = generate_userspace_code_from_program program_text_and "test_and_operator" in
    
    check bool "generates if keyword" true (contains_pattern result_and "if");
    check bool "has AND operator" true (contains_pattern result_and "&&");
    check bool "has first comparison" true (contains_pattern result_and ">");
    check bool "has second comparison" true (contains_pattern result_and ">");
    
    let result_or = generate_userspace_code_from_program program_text_or "test_or_operator" in
    
    check bool "generates if keyword for OR" true (contains_pattern result_or "if");
    check bool "has OR operator" true (contains_pattern result_or "||");
    check bool "has first OR comparison" true (contains_pattern result_or "< 0");
    check bool "has second OR comparison" true (contains_pattern result_or "> 3");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 8: If statement with OR operator *)
let test_if_or_operator () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var x = 5
  if (x == 5 || x == 10) {
    var result = 1
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_or_operator" in
    
    check bool "generates if keyword" true (contains_pattern result "if");
    check bool "has OR operator" true (contains_pattern result "||");
    check bool "has first equality" true (contains_pattern result "== 5");
    check bool "has second equality" true (contains_pattern result "== 10");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 9: Nested if statements *)
let test_nested_if_statements () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var x = 10
  if (x > 5) {
    if (x < 20) {
      var result = 1
    }
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_nested_if" in
    
    check bool "generates outer if" true (contains_pattern result "if");
    check bool "has outer condition" true (contains_pattern result "> 5");
    check bool "has inner if" true (contains_pattern result "if");
    check bool "has inner condition" true (contains_pattern result "< 20");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 10: If-else chain *)
let test_if_else_chain () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var grade = 85
  if (grade >= 90) {
    var letter = 1
  } else if (grade >= 80) {
    var letter = 2
  } else if (grade >= 70) {
    var letter = 3
  } else {
    var letter = 4
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_if_else_chain" in
    
    check bool "generates if keyword" true (contains_pattern result "if");
    check bool "has first condition" true (contains_pattern result ">= 90");
    (* The code generator creates nested if statements, not else if, which is semantically equivalent *)
    check bool "has nested else structure" true (contains_pattern result "} else {");
    check bool "has second condition" true (contains_pattern result ">= 80");
    check bool "has third condition" true (contains_pattern result ">= 70");
    check bool "has final else" true (contains_pattern result "else");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 11: Assignment in if statement *)
let test_assignment_in_if () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}

fn test_func() -> u32 {
  var counter = 0
  if (counter == 0) {
    counter = 5
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_assignment_in_if" in
    
    check bool "generates if keyword" true (contains_pattern result "if");
    check bool "has condition" true (contains_pattern result "== 0");
    check bool "has assignment" true (contains_pattern result "= 5");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** All global function statement codegen tests *)
let global_function_statements_tests = [
  "basic_if_statement", `Quick, test_basic_if_statement;
  "if_else_statement", `Quick, test_if_else_statement;
  "break_statement", `Quick, test_break_statement;
  "continue_statement", `Quick, test_continue_statement;
  "if_with_break_in_loop", `Quick, test_if_with_break_in_loop;
  "if_with_continue_in_loop", `Quick, test_if_with_continue_in_loop;
  "complex_binary_operators", `Quick, test_complex_binary_operators;
  "if_or_operator", `Quick, test_if_or_operator;
  "nested_if_statements", `Quick, test_nested_if_statements;
  "if_else_chain", `Quick, test_if_else_chain;
  "assignment_in_if", `Quick, test_assignment_in_if;
]

let () =
  run "KernelScript Global Function Statement Codegen Tests" [
    "global_function_statements", global_function_statements_tests;
] 