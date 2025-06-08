open Kernelscript.Ast
open Kernelscript.Parse

(** Test simple program parsing *)
let test_simple_program () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return 0;
      }
    }
  |} in
  try
    let ast = parse_string code in
    match ast with
    | [Program { prog_name = "test"; prog_type = Xdp; _ }] ->
        Printf.printf "✓ Simple program test passed\n"
    | _ -> 
        Printf.printf "✗ Simple program test failed: unexpected AST structure\n"
  with
  | Parse_error (msg, pos) -> 
      Printf.printf "✗ Simple program test failed: %s\n" (string_of_parse_error (msg, pos))

(** Test expressions with operator precedence *)
let test_expressions () =
  let test_cases = [
    ("x + y * 2", "should parse with correct precedence");
    ("(x + y) * 2", "should handle parentheses");
    ("a.b.c", "should handle field access");
    ("arr[0]", "should handle array access");
    ("func(x, y)", "should handle function calls");
  ] in
  
  let rec test_expression_list cases =
    match cases with
    | [] -> Printf.printf "✓ Expression parsing tests passed\n"
    | (expr_str, desc) :: rest ->
        try
          let _ = parse_expression_string expr_str in
          test_expression_list rest
        with
        | Parse_error (msg, pos) -> 
            Printf.printf "✗ Expression test failed for '%s' (%s): %s\n" 
              expr_str desc (string_of_parse_error (msg, pos))
        | e ->
            Printf.printf "✗ Expression test failed for '%s' (%s): %s\n" 
              expr_str desc (Printexc.to_string e)
  in
  test_expression_list test_cases

(** Test basic statements *)
let test_statements () =
  let code = {|
    program test : xdp {
      fn main() {
        let x = 42;
        let y: u32 = x + 10;
        x = y * 2;
        if (x > 100) {
          return 1;
        } else {
          return 0;
        }
      }
    }
  |} in
  try
    let ast = parse_string code in
    match ast with
    | [Program { prog_functions = [{ func_body = statements; _ }]; _ }] ->
        let expected_count = 4 in (* let, let, assignment, if *)
        if List.length statements = expected_count then
          Printf.printf "✓ Statement parsing test passed\n"
        else
          Printf.printf "✗ Statement parsing test failed: expected %d statements, got %d\n" 
            expected_count (List.length statements)
    | _ -> 
        Printf.printf "✗ Statement parsing test failed: unexpected AST structure\n"
  with
  | Parse_error (msg, pos) -> 
      Printf.printf "✗ Statement parsing test failed: %s\n" (string_of_parse_error (msg, pos))

(** Test function declarations *)
let test_function_declarations () =
  let code = {|
    program test : kprobe {
      fn helper(x: u32, y: u64) -> bool {
        return x < y;
      }
      
      fn main(ctx: KprobeContext) -> i32 {
        let result = helper(10, 20);
        return 0;
      }
    }
  |} in
  try
    let ast = parse_string code in
    match ast with
    | [Program { prog_functions = functions; _ }] ->
        if List.length functions = 2 then
          Printf.printf "✓ Function declaration test passed\n"
        else
          Printf.printf "✗ Function declaration test failed: expected 2 functions, got %d\n" 
            (List.length functions)
    | _ -> 
        Printf.printf "✗ Function declaration test failed: unexpected AST structure\n"
  with
  | Parse_error (msg, pos) -> 
      Printf.printf "✗ Function declaration test failed: %s\n" (string_of_parse_error (msg, pos))

(** Test program types *)
let test_program_types () =
  let test_cases = [
    ("xdp", Xdp);
    ("tc", Tc);
    ("kprobe", Kprobe);
    ("uprobe", Uprobe);
    ("tracepoint", Tracepoint);
    ("lsm", Lsm);
  ] in
  
  let test_program_type (type_str, expected_type) =
    let code = Printf.sprintf {|
      program test : %s {
        fn main() {
          return 0;
        }
      }
    |} type_str in
    try
      let ast = parse_string code in
      match ast with
      | [Program { prog_type = actual_type; _ }] ->
          if actual_type = expected_type then true
          else (
            Printf.printf "✗ Program type test failed for %s: wrong type\n" type_str;
            false
          )
      | _ -> 
          Printf.printf "✗ Program type test failed for %s: unexpected AST\n" type_str;
          false
    with
    | Parse_error (msg, pos) -> 
        Printf.printf "✗ Program type test failed for %s: %s\n" 
          type_str (string_of_parse_error (msg, pos));
        false
  in
  
  let all_passed = List.for_all test_program_type test_cases in
  if all_passed then
    Printf.printf "✓ Program type tests passed\n"
  else
    Printf.printf "✗ Some program type tests failed\n"

(** Test BPF types *)
let test_bpf_types () =
  let code = {|
    program test : xdp {
      fn test_types(
        a: u8, b: u16, c: u32, d: u64,
        e: i8, f: i16, g: i32, h: i64,
        i: bool, j: char,
        k: CustomType,
        l: [u8; 256],
        m: *u32
      ) -> bool {
        return true;
      }
    }
  |} in
  try
    let ast = parse_string code in
    match ast with
    | [Program { prog_functions = [{ func_params = params; _ }]; _ }] ->
        let expected_param_count = 13 in
        if List.length params = expected_param_count then
          Printf.printf "✓ BPF type parsing test passed\n"
        else
          Printf.printf "✗ BPF type parsing test failed: expected %d params, got %d\n" 
            expected_param_count (List.length params)
    | _ -> 
        Printf.printf "✗ BPF type parsing test failed: unexpected AST structure\n"
  with
  | Parse_error (msg, pos) -> 
      Printf.printf "✗ BPF type parsing test failed: %s\n" (string_of_parse_error (msg, pos))

(** Test control flow statements *)
let test_control_flow () =
  let code = {|
    program test : xdp {
      fn main() {
        let i = 0;
        while (i < 10) {
          i = i + 1;
        }
        
        for (j in 0..5) {
          if (j % 2 == 0) {
            j = j + 1;
          }
        }
        
        return 0;
      }
    }
  |} in
  try
    let ast = parse_string code in
    match ast with
    | [Program { prog_functions = [{ func_body = statements; _ }]; _ }] ->
        let expected_count = 4 in (* let, while, for, return *)
        if List.length statements = expected_count then
          Printf.printf "✓ Control flow parsing test passed\n"
        else
          Printf.printf "✗ Control flow parsing test failed: expected %d statements, got %d\n" 
            expected_count (List.length statements)
    | _ -> 
        Printf.printf "✗ Control flow parsing test failed: unexpected AST structure\n"
  with
  | Parse_error (msg, pos) -> 
      Printf.printf "✗ Control flow parsing test failed: %s\n" (string_of_parse_error (msg, pos))

(** Test error handling *)
let test_error_handling () =
  let invalid_programs = [
    ("program missing_colon xdp { }", "missing colon");
    ("program test : invalid_type { }", "invalid program type");
    ("program test : xdp { fn bad_syntax( { } }", "bad function syntax");
    ("program test : xdp { fn main() { let x = ; } }", "incomplete assignment");
  ] in
  
  let test_error_case (code, description) =
    try
      let _ = parse_string code in
      Printf.printf "✗ Error test failed for '%s': should have failed\n" description;
      false
    with
    | Parse_error _ -> true (* Expected *)
    | e -> 
        Printf.printf "✗ Error test failed for '%s': unexpected error %s\n" 
          description (Printexc.to_string e);
        false
  in
  
  let all_failed_correctly = List.for_all test_error_case invalid_programs in
  if all_failed_correctly then
    Printf.printf "✓ Error handling tests passed\n"
  else
    Printf.printf "✗ Some error handling tests failed\n"

(** Test operator precedence *)
let test_operator_precedence () =
  let code = {|
    program test : xdp {
      fn main() {
        let x = a + b * c;
        let y = (a + b) * c;
        let z = a && b || c && d;
        let w = !a && b;
        return 0;
      }
    }
  |} in
  try
    let ast = parse_string code in
    match ast with
    | [Program { prog_functions = [{ func_body = _statements; _ }]; _ }] ->
        (* We mainly test that it parses without errors *)
        Printf.printf "✓ Operator precedence test passed\n"
    | _ -> 
        Printf.printf "✗ Operator precedence test failed: unexpected AST structure\n"
  with
  | Parse_error (msg, pos) -> 
      Printf.printf "✗ Operator precedence test failed: %s\n" (string_of_parse_error (msg, pos))

(** Test complete program parsing *)
let test_complete_program () =
  let code = {|
    program network_monitor : xdp {
      fn is_large_packet(size: u32) -> bool {
        return size > 1500;
      }
      
      fn main(ctx: XdpContext) -> XdpAction {
        let packet_size: u32 = ctx.data_end - ctx.data;
        
        if (is_large_packet(packet_size)) {
          return 1;
        } else {
          return 0;
        }
      }
    }
  |} in
  try
    let ast = parse_string code in
    let is_valid = validate_ast ast in
    if is_valid then
      Printf.printf "✓ Complete program parsing test passed\n"
    else
      Printf.printf "✗ Complete program parsing test failed: AST validation failed\n"
  with
  | Parse_error (msg, pos) -> 
      Printf.printf "✗ Complete program parsing test failed: %s\n" (string_of_parse_error (msg, pos))

let run_tests () =
  Printf.printf "Running KernelScript Parser Tests\n";
  Printf.printf "==================================\n\n";
  test_simple_program ();
  test_expressions ();
  test_statements ();
  test_function_declarations ();
  test_program_types ();
  test_bpf_types ();
  test_control_flow ();
  test_error_handling ();
  test_operator_precedence ();
  test_complete_program ();
  Printf.printf "\nParser tests completed.\n"

let () = run_tests () 