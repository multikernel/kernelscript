(** Tests for specific string literal bugs to prevent regression *)

open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ebpf_c_codegen

(** Helper to create test position *)
let test_pos = { line = 1; column = 1; filename = "test.ks" }

(** Helper to check if string contains substring *)
let contains_substr str substr =
  try 
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in 
    true
  with Not_found -> false

(** 
 * Bug Fix Test 1: String Truncation Bug
 * 
 * ISSUE: "Hello world" (11 chars) was being truncated to "Hello worl" (10 chars)
 * ROOT CAUSE: max_content_len = size - 1 was reserving space for null terminator incorrectly
 * FIX: Use max_content_len = size since str<N> types already account for the needed size
 *)
let test_hello_world_truncation_bug () =
  let ctx = create_c_context () in
  
  (* Test the exact case that was failing: "Hello world" in str<11> *)
  let hello_world_val = make_ir_value (IRLiteral (StringLit "Hello world")) (IRStr 11) test_pos in
  let _ = generate_c_value ctx hello_world_val in
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* REGRESSION TEST: Ensure "Hello world" is NOT truncated *)
  Alcotest.(check bool) "Hello world is NOT truncated to Hello worl" 
    false (contains_substr output "\"Hello worl\"");
  
  (* POSITIVE TEST: Ensure full string is present *)
  Alcotest.(check bool) "Hello world is complete" 
    true (contains_substr output "\"Hello world\"");
  
  (* POSITIVE TEST: Ensure correct length is set *)
  Alcotest.(check bool) "Hello world has length 11, not 10" 
    true (contains_substr output ".len = 11");
  
  (* REGRESSION TEST: Ensure wrong length is not set *)
  Alcotest.(check bool) "Hello world does NOT have length 10" 
    false (contains_substr output ".len = 10")

(**
 * Bug Fix Test 2: Function Call Argument Bug
 * 
 * ISSUE: bpf_printk("%s", str_lit_1) was passing struct instead of .data field
 * ROOT CAUSE: String struct was passed directly to functions instead of accessing .data
 * FIX: Detect string literal variables and append .data when used in function calls
 *)
let test_bpf_printk_data_field_bug () =
  let ctx = create_c_context () in
  
  (* Test print function with string literal - this was generating wrong code *)
  let debug_msg_val = make_ir_value (IRLiteral (StringLit "Debug message")) (IRStr 13) test_pos in
  let print_instr = make_ir_instruction (IRCall ("print", [debug_msg_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* POSITIVE TEST: Ensure .data field is used *)
  Alcotest.(check bool) "Function call uses .data field" 
    true (contains_substr output "str_lit_1.data");
  
  (* REGRESSION TEST: Ensure struct is NOT passed directly *)
  Alcotest.(check bool) "Function call does NOT pass struct directly" 
    false (contains_substr output "bpf_printk(\"%s\", str_lit_1);");
  
  (* POSITIVE TEST: Ensure bpf_printk is generated *)
  Alcotest.(check bool) "Generates bpf_printk call" 
    true (contains_substr output "bpf_printk")

(**
 * Bug Fix Test 3: Multi-argument Function Call Bug
 * 
 * ISSUE: Multi-argument print calls also had the same .data field issue
 * ROOT CAUSE: Same as above but in multi-argument context
 * FIX: Apply .data field fix to multi-argument case as well
 *)
let test_multi_arg_printk_data_field_bug () =
  let ctx = create_c_context () in
  
  (* Test multi-argument print call *)
  let format_val = make_ir_value (IRLiteral (StringLit "Count: %d")) (IRStr 9) test_pos in
  let count_val = make_ir_value (IRLiteral (IntLit 42)) IRU32 test_pos in
  let print_instr = make_ir_instruction (IRCall ("print", [format_val; count_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* POSITIVE TEST: Ensure .data field is used in multi-arg context *)
  Alcotest.(check bool) "Multi-arg call uses .data field" 
    true (contains_substr output "str_lit_1.data");
  
  (* POSITIVE TEST: Ensure integer argument is included *)
  Alcotest.(check bool) "Multi-arg call includes integer" 
    true (contains_substr output "42");
  
  (* REGRESSION TEST: Ensure struct is NOT passed directly in multi-arg *)
  Alcotest.(check bool) "Multi-arg call does NOT pass struct directly" 
    false (contains_substr output ", str_lit_1, 42")

(**
 * Integration Test: Both bugs together
 * 
 * This test combines both bugs in a single scenario to ensure the fixes work together
 *)
let test_combined_bugs_integration () =
  let ctx = create_c_context () in
  
  (* Use the exact string that was failing: "Hello world" *)
  let hello_world_val = make_ir_value (IRLiteral (StringLit "Hello world")) (IRStr 11) test_pos in
  let print_instr = make_ir_instruction (IRCall ("print", [hello_world_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* REGRESSION TEST: String should not be truncated *)
  Alcotest.(check bool) "Integration: No truncation" 
    false (contains_substr output "\"Hello worl\"");
  
  (* POSITIVE TEST: Full string present *)
  Alcotest.(check bool) "Integration: Full string present" 
    true (contains_substr output "\"Hello world\"");
  
  (* POSITIVE TEST: Correct length *)
  Alcotest.(check bool) "Integration: Correct length" 
    true (contains_substr output ".len = 11");
  
  (* POSITIVE TEST: Uses .data field *)
  Alcotest.(check bool) "Integration: Uses .data field" 
    true (contains_substr output "str_lit_1.data");
  
  (* REGRESSION TEST: Does not pass struct directly *)
  Alcotest.(check bool) "Integration: Does not pass struct directly" 
    false (contains_substr output "bpf_printk(\"%s\", str_lit_1);")

(**
 * Edge Case Test: Boundary conditions that might trigger the bugs
 *)
let test_edge_cases_for_bugs () =
  (* Test exact fit strings *)
  let ctx1 = create_c_context () in
  let exact_fit_val = make_ir_value (IRLiteral (StringLit "exact")) (IRStr 5) test_pos in
  let _ = generate_c_value ctx1 exact_fit_val in
  let output1 = String.concat "\n" (List.rev ctx1.output_lines) in
  
  Alcotest.(check bool) "Exact fit: Full string" 
    true (contains_substr output1 "\"exact\"");
  Alcotest.(check bool) "Exact fit: Correct length" 
    true (contains_substr output1 ".len = 5");
  
  (* Test single character *)
  let ctx2 = create_c_context () in
  let single_char_val = make_ir_value (IRLiteral (StringLit "x")) (IRStr 1) test_pos in
  let print_instr = make_ir_instruction (IRCall ("print", [single_char_val], None)) test_pos in
  generate_c_instruction ctx2 print_instr;
  let output2 = String.concat "\n" (List.rev ctx2.output_lines) in
  
  Alcotest.(check bool) "Single char: Uses .data field" 
    true (contains_substr output2 "str_lit_1.data");
  Alcotest.(check bool) "Single char: Has correct content" 
    true (contains_substr output2 "\"x\"");
  
  (* Test empty string *)
  let ctx3 = create_c_context () in
  let empty_val = make_ir_value (IRLiteral (StringLit "")) (IRStr 1) test_pos in
  let print_instr = make_ir_instruction (IRCall ("print", [empty_val], None)) test_pos in
  generate_c_instruction ctx3 print_instr;
  let output3 = String.concat "\n" (List.rev ctx3.output_lines) in
  
  Alcotest.(check bool) "Empty string: Uses .data field" 
    true (contains_substr output3 "str_lit_1.data");
  Alcotest.(check bool) "Empty string: Has zero length" 
    true (contains_substr output3 ".len = 0")

(** Test suite for string literal bug fixes *)
let bug_fix_suite =
  [
    ("Bug Fix: Hello world truncation", `Quick, test_hello_world_truncation_bug);
    ("Bug Fix: bpf_printk .data field", `Quick, test_bpf_printk_data_field_bug);
    ("Bug Fix: Multi-arg .data field", `Quick, test_multi_arg_printk_data_field_bug);
    ("Integration: Combined bugs", `Quick, test_combined_bugs_integration);
    ("Edge cases for bugs", `Quick, test_edge_cases_for_bugs);
  ]

(** Run the bug fix tests *)
let () =
  Alcotest.run "String Literal Bug Fixes" [
    ("string_literal_bugs", bug_fix_suite);
  ] 