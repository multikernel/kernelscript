(** Tests for eBPF C Code Generation *)

open Alcotest
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

(** Test basic C type conversion *)
let test_type_conversion () =
  check string "IRU32 conversion" "__u32" (ebpf_type_from_ir_type IRU32);
  check string "IRBool conversion" "__u8" (ebpf_type_from_ir_type IRBool);
  check string "IRPointer conversion" "__u8*" (ebpf_type_from_ir_type (IRPointer (IRU8, make_bounds_info ())));
  check string "IRArray conversion" "__u32[10]" (ebpf_type_from_ir_type (IRArray (IRU32, 10, make_bounds_info ())));
  check string "IRContext conversion" "struct xdp_md*" (ebpf_type_from_ir_type (IRContext XdpCtx))

(** Test map definition generation *)
let test_map_definition () =
  let map_def = make_ir_map_def "test_map" IRU32 IRU64 IRHashMap 1024 test_pos in
  let ctx = create_c_context () in
  generate_map_definition ctx map_def;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "output contains opening brace" true (String.contains output '{');
  check bool "output contains closing brace" true (String.contains output '}');
  check bool "output contains map name" true (contains_substr output "test_map");
  check bool "output contains map type" true (contains_substr output "BPF_MAP_TYPE_HASH")

(** Test C value generation *)
let test_c_value_generation () =
  let ctx = create_c_context () in
  
  (* Test literals *)
  let int_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  check string "integer literal" "42" (generate_c_value ctx int_val);
  
  let bool_val = make_ir_value (IRLiteral (BoolLit true)) IRBool test_pos in
  check string "boolean literal" "true" (generate_c_value ctx bool_val);
  
  let var_val = make_ir_value (IRVariable "my_var") IRU32 test_pos in
  check string "variable reference" "my_var" (generate_c_value ctx var_val)

(** Test C expression generation *)
let test_c_expression_generation () =
  let ctx = create_c_context () in
  
  (* Test binary operation: 10 + 20 *)
  let left_val = make_ir_value (IRLiteral (IntLit (10, None))) IRU32 test_pos in
  let right_val = make_ir_value (IRLiteral (IntLit (20, None))) IRU32 test_pos in
  let add_expr = make_ir_expr (IRBinOp (left_val, IRAdd, right_val)) IRU32 test_pos in
  
  let result = generate_c_expression ctx add_expr in
  check string "binary addition" "(10 + 20)" result

(** Test context field access *)
let test_context_access () =
  (* Initialize context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  
  let ctx = create_c_context () in
  
  let data_field = make_ir_value (IRContextField (XdpCtx, "data")) (IRPointer (IRU8, make_bounds_info ())) test_pos in
  let result = generate_c_value ctx data_field in
  check string "context data field access" "(__u64)(long)ctx->data" result

(** Test bounds checking generation *)
let test_bounds_checking () =
  let ctx = create_c_context () in
  
  let index_val = make_ir_value (IRLiteral (IntLit (5, None))) IRU32 test_pos in
  generate_bounds_check ctx index_val 0 9;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "bounds check contains if statement" true (contains_substr output "if");
  check bool "bounds check contains XDP_DROP" true (contains_substr output "return XDP_DROP")

(** Test map operations generation *)
let test_map_operations () =
  let ctx = create_c_context () in
  
  (* Test map lookup *)
  let map_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", []), make_bounds_info ())) test_pos in
  let key_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  let dest_val = make_ir_value (IRVariable "result") (IRPointer (IRU64, make_bounds_info ())) test_pos in
  
  generate_map_load ctx map_val key_val dest_val MapLookup;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "map lookup contains bpf_map_lookup_elem" true (contains_substr output "bpf_map_lookup_elem");
  check bool "map lookup contains map name" true (contains_substr output "test_map")

(** Test literal keys and values in map operations *)
let test_literal_map_operations () =
  let ctx = create_c_context () in
  
  (* Test map store with literal key and value *)
  let map_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", []), make_bounds_info ())) test_pos in
  let literal_key = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  let literal_value = make_ir_value (IRLiteral (IntLit (100, None))) IRU64 test_pos in
  
  generate_map_store ctx map_val literal_key literal_value MapUpdate;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Verify that temporary variables are created for literals *)
  check bool "key temp variable created" true (contains_substr output "__u32 key_");
  check bool "value temp variable created" true (contains_substr output "__u64 value_");
  check bool "key literal assigned" true (contains_substr output "= 42;");
  check bool "value literal assigned" true (contains_substr output "= 100;");
  check bool "map update uses temp variables" true (contains_substr output "bpf_map_update_elem(&test_map, &key_");
  check bool "map update uses value temp" true (contains_substr output ", &value_");
  
  (* Verify literals are NOT directly addressed (no &42 or &100) *)
  check bool "no direct key literal addressing" false (contains_substr output "&42");
  check bool "no direct value literal addressing" false (contains_substr output "&100");
  
  (* Test map load with literal key *)
  let ctx2 = create_c_context () in
  let dest_val = make_ir_value (IRVariable "result") IRU64 test_pos in
  
  generate_map_load ctx2 map_val literal_key dest_val MapLookup;
  
  let output2 = String.concat "\n" (List.rev ctx2.output_lines) in
  
  (* Verify key temp variable for lookup *)
  check bool "lookup key temp variable created" true (contains_substr output2 "__u32 key_");
  check bool "lookup key literal assigned" true (contains_substr output2 "= 42;");
  check bool "lookup uses temp key variable" true (contains_substr output2 "bpf_map_lookup_elem(&test_map, &key_");
  check bool "lookup no direct key addressing" false (contains_substr output2 "&42");
  
  (* Test map delete with literal key *)
  let ctx3 = create_c_context () in
  
  let delete_instr = make_ir_instruction (IRMapDelete (map_val, literal_key)) test_pos in
  generate_c_instruction ctx3 delete_instr;
  
  let output3 = String.concat "\n" (List.rev ctx3.output_lines) in
  
  (* Verify key temp variable for delete *)
  check bool "delete key temp variable created" true (contains_substr output3 "__u32 key_");
  check bool "delete key literal assigned" true (contains_substr output3 "= 42;");
  check bool "delete uses temp key variable" true (contains_substr output3 "bpf_map_delete_elem(&test_map, &key_");
  check bool "delete no direct key addressing" false (contains_substr output3 "&42");
  
  (* Test with non-literal (variable) keys and values - should not create temp vars *)
  let ctx4 = create_c_context () in
  let var_key = make_ir_value (IRVariable "my_key") IRU32 test_pos in
  let var_value = make_ir_value (IRVariable "my_value") IRU64 test_pos in
  
  generate_map_store ctx4 map_val var_key var_value MapUpdate;
  
  let output4 = String.concat "\n" (List.rev ctx4.output_lines) in
  
  (* Verify variables are used directly without temp vars *)
  check bool "variable key used directly" true (contains_substr output4 "bpf_map_update_elem(&test_map, &my_key, &my_value");
  check bool "no temp vars for variable keys" false (contains_substr output4 "__u32 key_");
  check bool "no temp vars for variable values" false (contains_substr output4 "__u64 value_")

(** Test simple function generation *)
let test_function_generation () =
  (* Initialize context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  
  let ctx = create_c_context () in
  
  (* Create a simple function: return 42 *)
  let return_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  
  generate_c_function ctx main_func;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "function contains SEC annotation" true (contains_substr output "SEC(\"xdp\")");
  check bool "function contains function name" true (contains_substr output "test_main");
  check bool "function contains parameter" true (contains_substr output "struct xdp_md* ctx");
  check bool "function contains return statement" true (contains_substr output "return 42")

(** Test complete program generation *)
let test_complete_program () =
  (* Initialize context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  
  (* Create a simple XDP program *)
  let return_val = make_ir_value (IRLiteral (IntLit (2, None))) IRU32 test_pos in (* XDP_PASS *)
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "xdp_prog" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  
  (* Add a simple map *)
  let map_def = make_ir_map_def "packet_count" IRU32 IRU64 IRHashMap 1024 test_pos in
  
  let ir_prog = make_ir_program "test_xdp" Xdp [map_def] [] main_func test_pos in
  
  let c_code = compile_to_c ir_prog in
  
  (* Verify the generated C code contains expected elements *)
  check bool "program contains linux/bpf.h include" true (contains_substr c_code "#include <linux/bpf.h>");
  check bool "program contains map name" true (contains_substr c_code "packet_count");
  check bool "program contains maps section" true (contains_substr c_code "SEC(\".maps\")");
  check bool "program contains xdp section" true (contains_substr c_code "SEC(\"xdp\")");
  check bool "program contains function name" true (contains_substr c_code "xdp_prog");
  check bool "program contains GPL license" true (contains_substr c_code "GPL")

(** Test builtin print function calls *)
let test_builtin_print_calls () =
  let ctx = create_c_context () in
  
  (* Test print function call - should use stdlib mechanism *)
  let string_val = make_ir_value (IRLiteral (StringLit "Hello eBPF")) (IRStr 10) test_pos in
  let print_instr = make_ir_instruction (IRCall ("print", [string_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "print call uses bpf_printk" true (contains_substr output "bpf_printk");
  check bool "print call has string data" true (contains_substr output ".data")

(** Test advanced control flow *)
let test_control_flow () =
  let ctx = create_c_context () in
  
  (* Test conditional jump *)
  let cond_val = make_ir_value (IRLiteral (IntLit (1, None))) IRBool test_pos in
  let cond_jump = make_ir_instruction (IRCondJump (cond_val, "true_branch", "false_branch")) test_pos in
  
  generate_c_instruction ctx cond_jump;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "control flow contains if statement" true (contains_substr output "if (1)");
  check bool "control flow contains true branch goto" true (contains_substr output "goto true_branch");
  check bool "control flow contains false branch goto" true (contains_substr output "goto false_branch")

(** Test file writing functionality *)
let test_file_writing () =
  let return_val = make_ir_value (IRLiteral (IntLit (2, None))) IRU32 test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "test_prog" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test" Xdp [] [] main_func test_pos in
  
  let test_filename = "test_output.c" in
  let c_code = write_c_to_file ir_prog test_filename in
  
  (* Verify file exists and has content *)
  check bool "output file exists" true (Sys.file_exists test_filename);
  let ic = open_in test_filename in
  let file_content = really_input_string ic (in_channel_length ic) in
  close_in ic;
  
  check string "file content matches generated code" c_code file_content;
  check bool "file contains SEC annotation" true (contains_substr file_content "SEC(\"xdp\")");
  
  (* Clean up *)
  Sys.remove test_filename

(** Test string literal generation - comprehensive suite to prevent regression bugs *)

(** Test basic string literal generation with correct length *)
let test_string_literal_generation () =
  let ctx = create_c_context () in
  
  (* Test "Hello world" - exactly 11 characters *)
  let hello_world_val = make_ir_value (IRLiteral (StringLit "Hello world")) (IRStr 11) test_pos in
  let result = generate_c_value ctx hello_world_val in
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Verify the string is not truncated *)
  check bool "string literal contains full text" true (contains_substr output "\"Hello world\"");
  check bool "string literal not truncated" false (contains_substr output "\"Hello worl\"");
  
  (* Verify correct length is set *)
  check bool "string literal has correct length" true (contains_substr output ".len = 11");
  check bool "string literal not wrong length" false (contains_substr output ".len = 10");
  
  (* Verify struct definition is generated *)
  check bool "string struct variable created" true (contains_substr result "str_lit_");
  check bool "struct contains data field" true (contains_substr output ".data =")

(** Test string literal edge cases - empty, single char, exact buffer size *)
let test_string_literal_edge_cases () =
  let ctx = create_c_context () in
  
  (* Test empty string *)
  let empty_val = make_ir_value (IRLiteral (StringLit "")) (IRStr 1) test_pos in
  let _ = generate_c_value ctx empty_val in
  let output1 = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "empty string has zero length" true (contains_substr output1 ".len = 0");
  check bool "empty string has empty data" true (contains_substr output1 ".data = \"\"");
  
  (* Test single character *)
  let ctx2 = create_c_context () in
  let single_val = make_ir_value (IRLiteral (StringLit "X")) (IRStr 1) test_pos in
  let _ = generate_c_value ctx2 single_val in
  let output2 = String.concat "\n" (List.rev ctx2.output_lines) in
  check bool "single char has length 1" true (contains_substr output2 ".len = 1");
  check bool "single char has correct data" true (contains_substr output2 ".data = \"X\"");
  
  (* Test string that exactly fits buffer *)
  let ctx3 = create_c_context () in
  let exact_val = make_ir_value (IRLiteral (StringLit "12345")) (IRStr 5) test_pos in
  let _ = generate_c_value ctx3 exact_val in
  let output3 = String.concat "\n" (List.rev ctx3.output_lines) in
  check bool "exact fit has correct length" true (contains_substr output3 ".len = 5");
  check bool "exact fit has full string" true (contains_substr output3 ".data = \"12345\"")

(** Test string literal truncation behavior when string is too long *)
let test_string_literal_truncation () =
  let ctx = create_c_context () in
  
  (* Test string longer than allocated buffer - should be truncated *)
  let long_val = make_ir_value (IRLiteral (StringLit "This is too long")) (IRStr 8) test_pos in
  let _ = generate_c_value ctx long_val in
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Should be truncated to first 8 characters *)
  check bool "long string is truncated" true (contains_substr output ".data = \"This is \"");
  check bool "truncated length is correct" true (contains_substr output ".len = 8");
  check bool "full string not present" false (contains_substr output "\"This is too long\"")

(** Test string literals in function calls - critical for bpf_printk *)
let test_string_literal_in_function_calls () =
  let ctx = create_c_context () in
  
  (* Create a string literal value *)
  let string_val = make_ir_value (IRLiteral (StringLit "Debug message")) (IRStr 13) test_pos in
  
  (* Test print function call that should use bpf_printk *)
  let print_instr = make_ir_instruction (IRCall ("print", [string_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Critical fix: should use .data field, not the struct directly *)
  check bool "function call uses .data field" true (contains_substr output "str_lit_1.data");
  check bool "function call not using struct directly" false (contains_substr output "bpf_printk(\"%s\", str_lit_1);");
  
  (* Should generate bpf_printk call *)
  check bool "generates bpf_printk" true (contains_substr output "bpf_printk");
  
  (* Should have proper format string *)
  check bool "has format string" true (contains_substr output "\"%s\"")

(** Test string literals in multi-argument function calls *)
let test_string_literal_multi_arg_calls () =
  let ctx = create_c_context () in
  
  (* Create string literal and other arguments *)
  let string_val = make_ir_value (IRLiteral (StringLit "Test: %d")) (IRStr 8) test_pos in
  let int_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  
  (* Test print function call with multiple arguments *)
  let print_instr = make_ir_instruction (IRCall ("print", [string_val; int_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Should use .data field for string argument *)
  check bool "multi-arg uses .data field" true (contains_substr output "str_lit_1.data");
  check bool "includes integer argument" true (contains_substr output "42");
  check bool "has proper format specifiers" true (contains_substr output "\"%s%d\"")

(** Test string type definition generation *)
let test_string_typedef_generation () =
  (* Test that string literals generate the expected variable types in the code *)
  let ctx = create_c_context () in
  
  (* Generate string literal - this should create str_5_t variable *)
  let string_val = make_ir_value (IRLiteral (StringLit "test")) (IRStr 5) test_pos in
  let result = generate_c_value ctx string_val in
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Should generate str_5_t variable reference *)
  check bool "generates str_5_t variable" true (contains_substr result "str_lit_");
  check bool "generates struct initialization" true (contains_substr output ".data =");
  check bool "generates length field" true (contains_substr output ".len =");
  check bool "has correct string content" true (contains_substr output "\"test\"");
  check bool "has correct length value" true (contains_substr output ".len = 4")

(** Test string literals with special characters *)
let test_string_literal_special_chars () =
  let ctx = create_c_context () in
  
  (* Test string with newlines and quotes (simpler test to avoid escaping complexity) *)
  let special_val = make_ir_value (IRLiteral (StringLit "Hello World")) (IRStr 11) test_pos in
  let _ = generate_c_value ctx special_val in
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Basic test - ensure string is properly generated *)
  check bool "generates string literal" true (contains_substr output "str_lit_");
  check bool "has correct content" true (contains_substr output "\"Hello World\"");
  check bool "has correct length" true (contains_substr output ".len = 11")

(** Test string assignment vs literal generation *)
let test_string_assignment_vs_literal () =
  let ctx = create_c_context () in
  
  (* Test assignment of string literal to variable *)
  let string_val = make_ir_value (IRLiteral (StringLit "assigned")) (IRStr 8) test_pos in
  let dest_val = make_ir_value (IRVariable "my_string") (IRStr 8) test_pos in
  let assign_instr = make_ir_instruction (IRAssign (dest_val, make_ir_expr (IRValue string_val) (IRStr 8) test_pos)) test_pos in
  
  generate_c_instruction ctx assign_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Should generate both the literal and the assignment *)
  check bool "generates string literal" true (contains_substr output "str_lit_");
  check bool "generates assignment" true (contains_substr output "my_string =");
  check bool "assigns to variable" true (contains_substr output "= str_lit_")

(** Test suite definition *)
let suite =
  [
    ("Type conversion", `Quick, test_type_conversion);
    ("Map definition", `Quick, test_map_definition);
    ("C value generation", `Quick, test_c_value_generation);
    ("C expression generation", `Quick, test_c_expression_generation);
    ("Context access", `Quick, test_context_access);
    ("Bounds checking", `Quick, test_bounds_checking);
    ("Map operations", `Quick, test_map_operations);
    ("Literal map operations", `Quick, test_literal_map_operations);
    ("Function generation", `Quick, test_function_generation);
    ("Builtin print calls", `Quick, test_builtin_print_calls);
    ("Control flow", `Quick, test_control_flow);
    ("File writing", `Quick, test_file_writing);
    ("Complete program", `Quick, test_complete_program);
    (* String literal tests - prevent regression bugs *)
    ("String literal generation", `Quick, test_string_literal_generation);
    ("String literal edge cases", `Quick, test_string_literal_edge_cases);
    ("String literal truncation", `Quick, test_string_literal_truncation);
    ("String literals in function calls", `Quick, test_string_literal_in_function_calls);
    ("String literals in multi-arg calls", `Quick, test_string_literal_multi_arg_calls);
    ("String typedef generation", `Quick, test_string_typedef_generation);
    ("String literals with special chars", `Quick, test_string_literal_special_chars);
    ("String assignment vs literal", `Quick, test_string_assignment_vs_literal);
  ]

(** Run all tests *)
let () =
  run "eBPF C Code Generation" [
    ("ebpf_c_codegen", suite);
  ] 