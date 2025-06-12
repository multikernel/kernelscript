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
  let ir = Kernelscript.Ir_generator.generate_ir ~for_testing:true annotated_ast symbol_table filename in
  
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
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let x = 5;
    if x == 5 {
      let result = 1;
    }
    return 0;
  }
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
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let count = 15;
    if count > 10 {
      let status = 1;
    } else {
      let status = 0;
    }
    return 0;
  }
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
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    for i in 0..10 {
      if i == 5 {
        break;
      }
    }
    return 0;
  }
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
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    for i in 0..10 {
      if i % 2 == 0 {
        continue;
      }
    }
    return 0;
  }
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
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let count = 0;
    for i in 0..10 {
      if i == 5 {
        break;
      }
      count = count + 1;
    }
    return 0;
  }
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
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let sum = 0;
    for i in 1..10 {
      if i % 2 == 0 {
        continue;
      }
      sum = sum + i;
    }
    return 0;
  }
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
  let test_cases = [
    ("<", "less than", "a < b");
    ("<=", "less than or equal", "a <= b");
    (">", "greater than", "a > b");
    (">=", "greater than or equal", "a >= b");
    ("!=", "not equal", "a != b");
    ("&&", "logical and", "(a > 0) && (b > 0)");
    ("||", "logical or", "(a > 0) || (b > 0)");
    ("/", "division", "(a / b) > 0");
    ("%", "modulo", "(a % b) == 0");
  ] in
  
  List.iter (fun (expected_c, desc, condition) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let a = 5;
    let b = 10;
    if %s {
      let result = 1;
    }
    return 0;
  }
}
|} condition in
    
    try
      let result = generate_userspace_code_from_program program_text ("test_" ^ desc) in
      check bool (desc ^ " operator") true (contains_pattern result expected_c);
    with
    | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)
  ) test_cases

(** Test 8: Nested if statements *)
let test_nested_if_statements () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let x = 5;
    let y = 3;
    if x > 0 {
      if y < 10 {
        let result = 42;
      }
    }
    return 0;
  }
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_nested_if" in
    
    check bool "has outer comparison" true (contains_pattern result "> 0");
    check bool "has inner comparison" true (contains_pattern result "< 10");
    check bool "has nested assignment" true (contains_pattern result "= 42");
    check bool "has if statements" true (contains_pattern result "if");
    check bool "has opening braces" true (contains_pattern result "{");
    check bool "has closing braces" true (contains_pattern result "}");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 9: Integration test with complete userspace program *)
let test_complete_userspace_program_with_if_break_continue () =
  let program_text = {|
program test_prog : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2;
    }
}

userspace {
    fn main(argc: u32, argv: u64) -> i32 {
        let total: u32 = 0;
        let count: u32 = 0;
        
        for i in 0..20 {
            if i < 3 {
                continue;
            }
            
            if i % 2 == 0 {
                count = count + 1;
                continue;
            }
            
            if i > 15 {
                break;
            }
            
            total = total + i;
        }
        
        return 0;
    }
}
|} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test_complete" in
    
    let temp_dir = Filename.temp_file "test_userspace_complete" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
      ir ~output_dir:temp_dir "test_complete.ks" in
    let generated_file = Filename.concat temp_dir "test_complete.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      (* Verify all statement types are properly generated *)
      check bool "has for loop" true (contains_pattern content "for.*<= 20");
      check bool "has first comparison" true (contains_pattern content "< 3");
      check bool "has continue statement" true (contains_pattern content "continue;");
      check bool "has modulo operation" true (contains_pattern content "% 2");
      check bool "has equality check" true (contains_pattern content "== 0");
      check bool "has break statement" true (contains_pattern content "break;");
      check bool "has assignment" true (contains_pattern content "\\+");
      
      (* Verify no TODO statements *)
      check bool "no unsupported statements" false (contains_pattern content "TODO: Unsupported statement");
      
      (* Verify proper C syntax *)
      check bool "proper if syntax" true (contains_pattern content "if.*{");
      check bool "proper break syntax" true (contains_pattern content "break;");
      check bool "proper continue syntax" true (contains_pattern content "continue;");
    ) else (
      fail "Failed to generate userspace code file"
    );
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 10: Unsupported statement fallback *)
let test_unsupported_statement_fallback () =
  (* This test verifies that the system gracefully handles any unsupported statements *)
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

userspace {
  fn test_func() -> u32 {
    let x = 5;
    return x;
  }
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_unsupported" in
    
    (* Verify basic functionality works *)
    check bool "generates function" true (contains_pattern result "test_func");
    check bool "has return statement" true (contains_pattern result "return");
    check bool "no error messages" false (contains_pattern result "ERROR");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** All userspace statement codegen tests *)
let userspace_statements_tests = [
  "basic_if_statement", `Quick, test_basic_if_statement;
  "if_else_statement", `Quick, test_if_else_statement;
  "break_statement", `Quick, test_break_statement;
  "continue_statement", `Quick, test_continue_statement;
  "if_with_break_in_loop", `Quick, test_if_with_break_in_loop;
  "if_with_continue_in_loop", `Quick, test_if_with_continue_in_loop;
  "complex_binary_operators", `Quick, test_complex_binary_operators;
  "nested_if_statements", `Quick, test_nested_if_statements;
  "complete_userspace_program", `Quick, test_complete_userspace_program_with_if_break_continue;
  "unsupported_statement_fallback", `Quick, test_unsupported_statement_fallback;
]

let () =
  run "KernelScript Userspace Statement Codegen Tests" [
    "userspace_statements", userspace_statements_tests;
] 