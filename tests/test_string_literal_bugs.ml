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
  
  (* Test the exact case that was failing: "Hello world" in str(11) *)
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
  
  (* Test print function with string literal - the fix now passes strings directly to bpf_printk *)
  let debug_msg_val = make_ir_value (IRLiteral (StringLit "Debug message")) (IRStr 13) test_pos in
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [debug_msg_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* POSITIVE TEST: Ensure string literal is passed directly to bpf_printk (the fix) *)
  Alcotest.(check bool) "Function call uses string literal directly" 
    true (contains_substr output "bpf_printk(\"Debug message\")");
  
  (* REGRESSION TEST: Ensure .data field is NOT used for string literals in print *)
  Alcotest.(check bool) "Function call does NOT use .data field for string literals" 
    false (contains_substr output "str_lit_1.data");
  
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
  
  (* Test multi-argument print call - the fix now passes strings directly *)
  let format_val = make_ir_value (IRLiteral (StringLit "Count: %d")) (IRStr 9) test_pos in
  let count_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [format_val; count_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* POSITIVE TEST: Ensure string literal is passed directly in multi-arg context *)
  Alcotest.(check bool) "Multi-arg call uses string literal directly" 
    true (contains_substr output "bpf_printk(\"Count: %d\", 42)");
  
  (* POSITIVE TEST: Ensure integer argument is included *)
  Alcotest.(check bool) "Multi-arg call includes integer" 
    true (contains_substr output "42");
  
  (* REGRESSION TEST: Ensure .data field is NOT used for string literals in multi-arg print *)
  Alcotest.(check bool) "Multi-arg call does NOT use .data field for string literals" 
    false (contains_substr output "str_lit_1.data")

(**
 * Integration Test: Both bugs together
 * 
 * This test combines both bugs in a single scenario to ensure the fixes work together
 *)
let test_combined_bugs_integration () =
  let ctx = create_c_context () in
  
  (* Use the exact string that was failing: "Hello world" *)
  let hello_world_val = make_ir_value (IRLiteral (StringLit "Hello world")) (IRStr 11) test_pos in
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [hello_world_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* REGRESSION TEST: String should not be truncated *)
  Alcotest.(check bool) "Integration: No truncation" 
    false (contains_substr output "\"Hello worl\"");
  
  (* POSITIVE TEST: Full string present and passed directly to bpf_printk *)
  Alcotest.(check bool) "Integration: Full string passed directly" 
    true (contains_substr output "bpf_printk(\"Hello world\")");
  
  (* REGRESSION TEST: Does not use string struct for print statement *)
  Alcotest.(check bool) "Integration: Does not generate string struct for print" 
    false (contains_substr output ".len = 11");
  
  (* REGRESSION TEST: Does not use .data field for string literals in print *)
  Alcotest.(check bool) "Integration: Does not use .data field for string literals" 
    false (contains_substr output "str_lit_1.data");
  
  (* POSITIVE TEST: Uses bpf_printk correctly *)
  Alcotest.(check bool) "Integration: Uses bpf_printk correctly" 
    true (contains_substr output "bpf_printk")

(**
 * Bug Fix Test 4: Null Terminator Buffer Size Bug
 * 
 * ISSUE: typedef allocated only content size, not content + null terminator
 * ROOT CAUSE: char data[N] instead of char data[N+1] for N-character strings
 * FIX: Allocate size + 1 in typedef generation to accommodate null terminator
 *)
let test_null_terminator_buffer_bug () =
  (* Test that typedefs allocate enough space for null terminator *)
  let return_val = make_ir_value (IRLiteral (IntLit (2, None))) IRU32 test_pos in
  let string_val = make_ir_value (IRLiteral (StringLit "Hello")) (IRStr 5) test_pos in
  let assign_instr = make_ir_instruction (IRAssign (make_ir_value (IRVariable "test_str") (IRStr 5) test_pos, make_ir_expr (IRValue string_val) (IRStr 5) test_pos)) test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [assign_instr; return_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRContext XdpCtx)] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test_prog" Xdp main_func test_pos in
  
  let c_code = compile_to_c ir_prog in
  
  (* POSITIVE TEST: typedef should allocate 6 bytes for 5-character string *)
  Alcotest.(check bool) "typedef allocates space for null terminator" 
    true (contains_substr c_code "char data[6]");
  
  (* REGRESSION TEST: should NOT allocate only content size *)
  Alcotest.(check bool) "typedef does NOT allocate only content size" 
    false (contains_substr c_code "typedef struct { char data[5]; __u16 len; } str_5_t;");
  
  (* POSITIVE TEST: verify correct typedef structure *)
  Alcotest.(check bool) "typedef has correct structure" 
    true (contains_substr c_code "typedef struct { char data[6]; __u16 len; } str_5_t;")

(**
 * Bug Fix Test 5: String Concatenation Bounds Check Bug
 * 
 * ISSUE: String concatenation used result_size - 1 for bounds checking
 * ROOT CAUSE: max_content_len = result_size - 1 incorrectly reduced capacity
 * FIX: Use result_size directly since typedef allocates result_size + 1 bytes
 *)
let test_string_concat_bounds_bug () =
  (* Create string concatenation that should use full 11-character capacity *)
  let return_val = make_ir_value (IRLiteral (IntLit (2, None))) IRU32 test_pos in
  let left_str = make_ir_value (IRLiteral (StringLit "Hello")) (IRStr 5) test_pos in
  let right_str = make_ir_value (IRLiteral (StringLit " world")) (IRStr 6) test_pos in
  let concat_expr = make_ir_expr (IRBinOp (left_str, IRAdd, right_str)) (IRStr 11) test_pos in
  let result_var = make_ir_value (IRVariable "result") (IRStr 11) test_pos in
  let assign_instr = make_ir_instruction (IRAssign (result_var, concat_expr)) test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [assign_instr; return_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRContext XdpCtx)] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test_prog" Xdp main_func test_pos in
  
  let c_code = compile_to_c ir_prog in
  
  (* POSITIVE TEST: Should check against 11, not 10 *)
  Alcotest.(check bool) "uses correct bounds check >= 11" 
    true (contains_substr c_code ">= 11");
  
  (* POSITIVE TEST: Should use unconditional null termination (always safe) *)
  Alcotest.(check bool) "uses unconditional null termination" 
    true (contains_substr c_code ".data[str_concat_");
  
  (* REGRESSION TEST: Should NOT use old incorrect bounds *)
  Alcotest.(check bool) "does NOT use incorrect bounds >= 10" 
    false (contains_substr c_code ">= 10");
  
  (* REGRESSION TEST: Should NOT use conditional null termination anymore *)
  Alcotest.(check bool) "does NOT use conditional null termination" 
    false (contains_substr c_code "if (str_concat_1.len <")

(**
 * Bug Fix Test 6: Function Call String Argument Bug
 * 
 * ISSUE: bpf_printk("%s", tmp_1) passed struct instead of .data field for non-str_lit variables
 * ROOT CAUSE: fix_string_arg only checked for "str_lit" prefix, not "tmp_" or "str_concat" prefixes
 * FIX: Extended detection logic to cover all string variable patterns
 *)
let test_function_call_string_arg_bug () =
  (* Create string concatenation result passed to function call *)
  let return_val = make_ir_value (IRLiteral (IntLit (2, None))) IRU32 test_pos in
  let left_str = make_ir_value (IRLiteral (StringLit "Hello")) (IRStr 5) test_pos in
  let right_str = make_ir_value (IRLiteral (StringLit " world")) (IRStr 6) test_pos in
  let concat_expr = make_ir_expr (IRBinOp (left_str, IRAdd, right_str)) (IRStr 11) test_pos in
  let result_var = make_ir_value (IRRegister 1) (IRStr 11) test_pos in
  let assign_instr = make_ir_instruction (IRAssign (result_var, concat_expr)) test_pos in
  let print_call = make_ir_instruction (IRCall (DirectCall "print", [result_var], Some (make_ir_value (IRRegister 2) IRU32 test_pos))) test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [assign_instr; print_call; return_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRContext XdpCtx)] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test_prog" Xdp main_func test_pos in
  
  let c_code = compile_to_c ir_prog in
  
  (* POSITIVE TEST: Should use .data field for string variables *)
  let has_string_data_access = 
    contains_substr c_code "tmp_1.data" ||
    contains_substr c_code "var_1.data" ||
    contains_substr c_code "val_1.data" ||
    contains_substr c_code "str_1.data" in
  Alcotest.(check bool) "uses .data field for tmp_ variables" 
    true has_string_data_access;
  
  (* REGRESSION TEST: Should NOT pass struct directly *)
  Alcotest.(check bool) "does NOT pass struct directly to bpf_printk" 
    false (contains_substr c_code "bpf_printk(\"%s\", tmp_1);");
  
  (* POSITIVE TEST: Generates proper bpf_printk call *)
  Alcotest.(check bool) "generates bpf_printk call" 
    true (contains_substr c_code "bpf_printk")

(**
 * Bug Fix Test 7: String Concatenation Loop Bounds Bug
 * 
 * ISSUE: Loop bounds used size-1 instead of size, causing character truncation
 * ROOT CAUSE: for (int i = 0; i < left_size - 1; i++) cut off last character of each string
 * FIX: Use full size since null termination check handles early exit
 *)
let test_string_concat_loop_bounds_bug () =
  (* Create exact "Hello" + " world" test case that was failing *)
  let return_val = make_ir_value (IRLiteral (IntLit (2, None))) IRU32 test_pos in
  let hello_str = make_ir_value (IRLiteral (StringLit "Hello")) (IRStr 5) test_pos in
  let world_str = make_ir_value (IRLiteral (StringLit " world")) (IRStr 6) test_pos in
  let concat_expr = make_ir_expr (IRBinOp (hello_str, IRAdd, world_str)) (IRStr 11) test_pos in
  let result_var = make_ir_value (IRVariable "full_result") (IRStr 11) test_pos in
  let assign_instr = make_ir_instruction (IRAssign (result_var, concat_expr)) test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [assign_instr; return_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRContext XdpCtx)] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test_prog" Xdp main_func test_pos in
  
  let c_code = compile_to_c ir_prog in
  
  (* POSITIVE TEST: Should use full loop bounds for 5-char string *)
  Alcotest.(check bool) "uses correct loop bound < 5 for Hello" 
    true (contains_substr c_code "< 5");
  
  (* POSITIVE TEST: Should use full loop bounds for 6-char string *)
  Alcotest.(check bool) "uses correct loop bound < 6 for world" 
    true (contains_substr c_code "< 6");
  
  (* REGRESSION TEST: Should NOT use truncated bounds *)
  Alcotest.(check bool) "does NOT use truncated bound < 4" 
    false (contains_substr c_code "< 4");
  
  (* The combination should now generate full concatenation capability *)
  Alcotest.(check bool) "generates proper string concatenation" 
    true (contains_substr c_code "str_concat_")

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
  
  (* Test single character - print should use string literal directly *)
  let ctx2 = create_c_context () in
  let single_char_val = make_ir_value (IRLiteral (StringLit "x")) (IRStr 1) test_pos in
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [single_char_val], None)) test_pos in
  generate_c_instruction ctx2 print_instr;
  let output2 = String.concat "\n" (List.rev ctx2.output_lines) in
  
  Alcotest.(check bool) "Single char: Uses string literal directly in print" 
    true (contains_substr output2 "bpf_printk(\"x\")");
  Alcotest.(check bool) "Single char: Does NOT use .data field for print" 
    false (contains_substr output2 "str_lit_1.data");
  
  (* Test empty string - print should use string literal directly *)
  let ctx3 = create_c_context () in
  let empty_val = make_ir_value (IRLiteral (StringLit "")) (IRStr 1) test_pos in
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [empty_val], None)) test_pos in
  generate_c_instruction ctx3 print_instr;
  let output3 = String.concat "\n" (List.rev ctx3.output_lines) in
  
  Alcotest.(check bool) "Empty string: Uses string literal directly in print" 
    true (contains_substr output3 "bpf_printk(\"\")");
  Alcotest.(check bool) "Empty string: Does NOT use .data field for print" 
    false (contains_substr output3 "str_lit_1.data")

(** Test suite for string literal bug fixes *)
let bug_fix_suite =
  [
    ("Bug Fix: Hello world truncation", `Quick, test_hello_world_truncation_bug);
    ("Bug Fix: bpf_printk .data field", `Quick, test_bpf_printk_data_field_bug);
    ("Bug Fix: Multi-arg .data field", `Quick, test_multi_arg_printk_data_field_bug);
    ("Bug Fix: Null terminator buffer size", `Quick, test_null_terminator_buffer_bug);
    ("Bug Fix: String concat bounds check", `Quick, test_string_concat_bounds_bug);
    ("Bug Fix: Function call string arg", `Quick, test_function_call_string_arg_bug);
    ("Bug Fix: String concat loop bounds", `Quick, test_string_concat_loop_bounds_bug);
    ("Integration: Combined bugs", `Quick, test_combined_bugs_integration);
    ("Edge cases for bugs", `Quick, test_edge_cases_for_bugs);
  ]

(** Run the bug fix tests *)
let () =
  Alcotest.run "String Literal Bug Fixes" [
    ("string_literal_bugs", bug_fix_suite);
  ] 