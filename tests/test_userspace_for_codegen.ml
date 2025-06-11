open Alcotest
open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Userspace_codegen

(** Helper function to create test expressions *)
let dummy_loc = {
  line = 1;
  column = 1;
  filename = "test";
}

let make_test_pos () = dummy_loc

let make_int_literal value =
  { expr_desc = Literal (IntLit value); expr_pos = make_test_pos (); 
    expr_type = None; type_checked = false; program_context = None; map_scope = None }

let make_for_stmt loop_var start_expr end_expr body =
  { stmt_desc = For (loop_var, start_expr, end_expr, body); stmt_pos = make_test_pos () }

let make_declaration name value =
  { stmt_desc = Declaration (name, Some U32, value); stmt_pos = make_test_pos () }

let make_identifier name =
  { expr_desc = Identifier name; expr_pos = make_test_pos (); 
    expr_type = None; type_checked = false; program_context = None; map_scope = None }

let make_binary_op left op right =
  { expr_desc = BinaryOp (left, op, right); expr_pos = make_test_pos (); 
    expr_type = None; type_checked = false; program_context = None; map_scope = None }

(** Helper function to check if generated code contains a pattern *)
let contains_pattern code pattern =
  try
    let regex = Str.regexp pattern in
    ignore (Str.search_forward regex code 0);
    true
  with Not_found -> false

(** Generate userspace code from a simple for loop test *)
let get_userspace_for_code loop_var start_val end_val body_statements =
  let start_expr = make_int_literal start_val in
  let end_expr = make_int_literal end_val in
  let for_stmt = make_for_stmt loop_var start_expr end_expr body_statements in
  
  let ctx = create_userspace_context () in
  generate_c_statement_with_context ctx for_stmt

(** Test 1: Basic for loop with constant bounds generates ordinary C for loop *)
let test_basic_for_loop_constant_bounds () =
  let body = [make_declaration "x" (make_int_literal 42)] in
  let result = get_userspace_for_code "i" 0 10 body in
  
  (* Should generate ordinary C for loop, not unrolled or goto-based *)
  check bool "generates for keyword" true (contains_pattern result "for.*(");
  check bool "uses loop variable initialization" true (contains_pattern result "= 0");
  check bool "has loop condition" true (contains_pattern result "<= 10");
  check bool "has increment" true (contains_pattern result "\\+\\+");
  check bool "has curly braces" true (contains_pattern result "{");
  
  (* Should NOT contain unrolling patterns *)
  check bool "no manual unrolling" false (contains_pattern result "x_0.*x_1.*x_2");
  check bool "no goto statements" false (contains_pattern result "goto");
  check bool "no loop_start labels" false (contains_pattern result "loop_start:");
  ()

(** Test 2: For loop with variable bounds generates ordinary C for loop *)
let test_for_loop_variable_bounds () =
  let program_text = {|
userspace {
  fn main(argc: u32, argv: u64) -> i32 {
    let start = 1;
    let end_val = 5;
    for i in start..end_val {
      let temp = i * 2;
    }
    return 0;
  }
}

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}
|} in
  
  try
    let ast = parse_string program_text in
    let temp_dir = Filename.temp_file "test_userspace_for" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = generate_userspace_code_from_ast ast ~output_dir:temp_dir "test_for_variable.ks" in
    let generated_file = Filename.concat temp_dir "test_for_variable.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      (* Verify ordinary C for loop generation *)
      check bool "generates C for loop" true (contains_pattern content "for.*(");
      check bool "no bounds checking macros" false (contains_pattern content "BPF_LOOP_BOUND_CHECK");
      check bool "no verifier annotations" false (contains_pattern content "__bounded");
      check bool "no goto-based implementation" false (contains_pattern content "goto.*loop");
      
      (* Should use variable bounds directly *)
      check bool "uses variable bounds" true (contains_pattern content "start.*end_val");
    ) else (
      fail "Failed to generate userspace code file"
    );
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 3: For loop with complex expressions generates ordinary C *)
let test_for_loop_complex_expressions () =
  (* Test that we can generate for loops with complex body statements *)
  let doubled_decl = make_declaration "doubled" (make_binary_op (make_identifier "i") Kernelscript.Ast.Mul (make_int_literal 2)) in
  let squared_decl = make_declaration "squared" (make_binary_op (make_identifier "i") Kernelscript.Ast.Mul (make_identifier "i")) in
  let complex_body = [doubled_decl; squared_decl] in
  let result = get_userspace_for_code "i" 0 10 complex_body in
  
  (* Should handle complex expressions inside loop without transformation *)
  check bool "generates for loop" true (contains_pattern result "for.*(");
  check bool "includes doubled variable" true (contains_pattern result "doubled");
  check bool "includes squared variable" true (contains_pattern result "squared");
  check bool "has multiplication" true (contains_pattern result "\\*");
  
  (* Should not apply eBPF-specific transformations *)
  check bool "no verifier hints" false (contains_pattern result "__always_inline");
  check bool "no stack depth limits" false (contains_pattern result "BPF_STACK_LIMIT");
  ()

(** Test 4: For loop with single iteration still generates C for loop *)
let test_for_loop_single_iteration () =
  let body = [make_declaration "single" (make_int_literal 99)] in
  let result = get_userspace_for_code "k" 5 5 body in
  
  (* Even single iteration should generate for loop, not be optimized away *)
  check bool "single iteration uses for loop" true (contains_pattern result "for.*(");
  check bool "condition is k <= 5" true (contains_pattern result "k <= 5");
  check bool "not optimized to direct assignment" false (contains_pattern result "single.*=.*99.*//.*optimized");
  ()

(** Test 5: Large bounds should not trigger special handling *)
let test_for_loop_large_bounds () =
  let body = [make_declaration "large" (make_int_literal 1)] in
  let result = get_userspace_for_code "big" 0 1000000 body in
  
  (* Large bounds should not trigger unrolling limits or special handling *)
  check bool "large bounds use ordinary for" true (contains_pattern result "for.*(");
  check bool "no unrolling limit warnings" false (contains_pattern result "UNROLL_LIMIT_EXCEEDED");
  check bool "no bounds reduction" false (contains_pattern result "Reduced bounds");
  check bool "preserves original bounds" true (contains_pattern result "1000000");
  ()

(** Test 6: Zero-iteration loop (start > end) generates valid C *)
let test_for_loop_zero_iterations () =
  let body = [make_declaration "never" (make_int_literal 0)] in
  let result = get_userspace_for_code "empty" 10 5 body in
  
  (* Should generate syntactically correct C even for impossible loops *)
  check bool "zero iteration generates for loop" true (contains_pattern result "for.*(");
  check bool "condition respects bounds" true (contains_pattern result "empty <= 5");
  check bool "no special case handling" false (contains_pattern result "Zero iterations");
  check bool "no context-specific handling" false (contains_pattern result "Main function");
  ()

(** Test 7: For loop in non-main function context *)
let test_for_loop_in_helper_function () =
  let program_text = {|
userspace {
  fn helper() -> u32 {
    for i in 1..3 {
      let helper_var = i + 10;
    }
    return 42;
  }
  
  fn main(argc: u32, argv: u64) -> i32 {
    let result = helper();
    return 0;
  }
}

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}
|} in
  
  try
    let ast = parse_string program_text in
    let temp_dir = Filename.temp_file "test_userspace_helper" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = generate_userspace_code_from_ast ast ~output_dir:temp_dir "test_helper.ks" in
    let generated_file = Filename.concat temp_dir "test_helper.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      (* Should handle for loops in helper functions the same way *)
      check bool "helper function has for loop" true (contains_pattern content "for.*(.*i.*1.*3");
      check bool "no context-specific handling" false (contains_pattern content "Main function");
      check bool "uses return statement" true (contains_pattern content "return 42");
      check bool "coordinator program structure" true (contains_pattern content "bpf_object");
    ) else (
      fail "Failed to generate userspace code file"
    );
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 8: Comparison with eBPF codegen - userspace should be different *)
let test_userspace_vs_ebpf_for_loop_differences () =
  (* This test documents that userspace should generate different code than eBPF *)
  let body = [make_declaration "test" (make_int_literal 1)] in
  let userspace_result = get_userspace_for_code "i" 0 100 body in
  
  (* Userspace should NOT have eBPF-specific patterns *)
  check bool "no BPF loop pragmas" false (contains_pattern userspace_result "#pragma unroll");
  check bool "no verifier annotations" false (contains_pattern userspace_result "__bounded");
  check bool "no BPF helper calls" false (contains_pattern userspace_result "bpf_for_each");
  check bool "no instruction counting" false (contains_pattern userspace_result "INSTRUCTION_COUNT");
  
  (* Should be plain C *)
  check bool "plain C for loop" true (contains_pattern userspace_result "for.*(");
  check bool "standard C increment" true (contains_pattern userspace_result "++");
  ()

(** All userspace for statement codegen tests *)
let userspace_for_codegen_tests = [
  "basic_for_loop_constant_bounds", `Quick, test_basic_for_loop_constant_bounds;
  "for_loop_variable_bounds", `Quick, test_for_loop_variable_bounds;
  "for_loop_complex_expressions", `Quick, test_for_loop_complex_expressions;
  "for_loop_single_iteration", `Quick, test_for_loop_single_iteration;
  "for_loop_large_bounds", `Quick, test_for_loop_large_bounds;
  "for_loop_zero_iterations", `Quick, test_for_loop_zero_iterations;
  "for_loop_in_helper_function", `Quick, test_for_loop_in_helper_function;
  "userspace_vs_ebpf_differences", `Quick, test_userspace_vs_ebpf_for_loop_differences;
]

let () =
  run "KernelScript Userspace For Statement Codegen Tests" [
    "userspace_for_codegen", userspace_for_codegen_tests;
]
