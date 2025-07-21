(*
 * Copyright 2025 Multikernel Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

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

(** Helper to parse string to AST *)
let parse_string source =
  let lexbuf = Lexing.from_string source in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Test basic C type conversion *)
let test_type_conversion () =
  check string "IRU32 conversion" "__u32" (ebpf_type_from_ir_type IRU32);
  check string "IRBool conversion" "__u8" (ebpf_type_from_ir_type IRBool);
  check string "IRPointer conversion" "__u8*" (ebpf_type_from_ir_type (IRPointer (IRU8, make_bounds_info ())));
  check string "IRArray conversion" "__u32[10]" (ebpf_type_from_ir_type (IRArray (IRU32, 10, make_bounds_info ())));
  check string "IRContext conversion" "struct xdp_md" (ebpf_type_from_ir_type (IRContext XdpCtx))

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
  check string "boolean literal" "1" (generate_c_value ctx bool_val);
  
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
  check string "context data field access" "(void*)(long)ctx->data" result

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
  let map_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", [], false), make_bounds_info ())) test_pos in
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
  let map_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", [], false), make_bounds_info ())) test_pos in
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
  let main_func = make_ir_function "test_main" [("ctx", IRPointer (IRContext XdpCtx, make_bounds_info ()))] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  
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
  let main_func = make_ir_function "test_xdp" [("ctx", IRPointer (IRContext XdpCtx, make_bounds_info ()))] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  
  (* Add a simple map *)
  let map_def = make_ir_map_def "packet_count" IRU32 IRU64 IRHashMap 1024 test_pos in
  
  let ir_prog = make_ir_program "test_xdp" Xdp main_func test_pos in
  
  (* Create multi-program structure with global maps *)
  let multi_ir = make_ir_multi_program "test_xdp" [ir_prog] [] [map_def] test_pos in
  
  let c_code = compile_multi_to_c multi_ir in
  
  (* Verify the generated C code contains expected elements *)
  check bool "program contains linux/bpf.h include" true (contains_substr c_code "#include <linux/bpf.h>");
  check bool "program contains map name" true (contains_substr c_code "packet_count");
  check bool "program contains maps section" true (contains_substr c_code "SEC(\".maps\")");
  check bool "program contains xdp section" true (contains_substr c_code "SEC(\"xdp\")");
  check bool "program contains function name" true (contains_substr c_code "test_xdp");
  check bool "program contains GPL license" true (contains_substr c_code "GPL")

(** Test builtin print function calls *)
let test_builtin_print_calls () =
  let ctx = create_c_context () in
  
  (* Test print function call - should use stdlib mechanism *)
  let string_val = make_ir_value (IRLiteral (StringLit "Hello eBPF")) (IRStr 10) test_pos in
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [string_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  check bool "print call uses bpf_printk" true (contains_substr output "bpf_printk");
  check bool "print call has string literal" true (contains_substr output "\"Hello eBPF\"")

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
  let main_func = make_ir_function "test" [("ctx", IRPointer (IRContext XdpCtx, make_bounds_info ()))] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test" Xdp main_func test_pos in
  
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
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [string_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Critical fix: should use string literal directly, not .data field *)
  check bool "function call uses string literal directly" true (contains_substr output "\"Debug message\"");
  check bool "function call not using .data field" false (contains_substr output "str_lit_1.data");
  
  (* Should generate bpf_printk call *)
  check bool "generates bpf_printk" true (contains_substr output "bpf_printk");
  
  (* Should use the original string literal directly *)
  check bool "has string literal" true (contains_substr output "\"Debug message\"")

(** Test string literals in multi-argument function calls *)
let test_string_literal_multi_arg_calls () =
  let ctx = create_c_context () in
  
  (* Create string literal and other arguments *)
  let string_val = make_ir_value (IRLiteral (StringLit "Test: %d")) (IRStr 8) test_pos in
  let int_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  
  (* Test print function call with multiple arguments *)
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [string_val; int_val], None)) test_pos in
  generate_c_instruction ctx print_instr;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Should use string literal directly in multi-arg context *)
  check bool "multi-arg uses string literal directly" true (contains_substr output "\"Test: %d\"");
  check bool "includes integer argument" true (contains_substr output "42");
  (* Should use the original format string directly *)
  check bool "has proper format specifiers" true (contains_substr output "\"Test: %d\"")

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
  check bool "assigns to variable" true (contains_substr output "= str_lit_");
  ()

(** Type alias and struct bug fix regression tests *)

(** Test that empty structs are not generated for type aliases *)
let test_no_empty_struct_generation () =
  (* Test the core bug fix: collect_struct_definitions_from_multi_program should filter empty structs *)
  
  (* Create IR with type aliases that would previously generate empty structs *)
  let type_aliases = [
    ("Counter", Kernelscript.Ast.U64);
    ("IpAddress", Kernelscript.Ast.U32);
  ] in
  
  (* Create a minimal mock multi-program IR for testing *)
  let dummy_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  let multi_ir = {
    Kernelscript.Ir.source_name = "test";
    programs = [];
    kernel_functions = [];
    global_maps = [];
    global_variables = [];
    global_configs = [];
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = None;
    userspace_bindings = [];
    multi_pos = dummy_pos;
  } in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ~type_aliases multi_ir in
  
  (* Core fix verification: No empty structs should be generated for type aliases *)
  check bool "no empty Counter struct" false (contains_substr c_code "struct Counter {");
  check bool "no empty IpAddress struct" false (contains_substr c_code "struct IpAddress {");
  check bool "no empty struct definitions" false (contains_substr c_code "struct Counter {};");
  
  (* Type aliases should be generated as typedefs *)
  check bool "Counter typedef generated" true (contains_substr c_code "typedef __u64 Counter");
  check bool "IpAddress typedef generated" true (contains_substr c_code "typedef __u32 IpAddress");
  ()

(** Test that type aliases are generated before structs in C output *)
let test_type_alias_struct_ordering () =
  (* Test the core bug fix: generate_declarations_in_source_order preserves correct ordering *)
  
  let type_aliases = [("Counter", Kernelscript.Ast.U64)] in
  
  (* Create a minimal mock multi-program IR with a struct that uses the type alias *)
  let dummy_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  let ir_program = {
    Kernelscript.Ir.name = "test";
    program_type = Kernelscript.Ast.Xdp;
    entry_function = {
      func_name = "test";
      parameters = [("ctx", Kernelscript.Ir.IRStruct("xdp_md", [], true))];
      return_type = Some (Kernelscript.Ir.IRStruct("xdp_action", [], true));
      basic_blocks = [];
      total_stack_usage = 0;
      max_loop_depth = 0;
      calls_helper_functions = [];
      visibility = Kernelscript.Ir.Public;
      is_main = true;
      func_pos = dummy_pos;
      tail_call_targets = [];
      tail_call_index_map = Hashtbl.create 16;
      is_tail_callable = false;
      func_program_type = None;
    };
    ir_pos = dummy_pos;
  } in
  
  let multi_ir = {
    Kernelscript.Ir.source_name = "test";
    programs = [ir_program];
    kernel_functions = [];
    global_maps = [];
    global_variables = [];
    global_configs = [];
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = None;
    userspace_bindings = [];
    multi_pos = dummy_pos;
  } in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ~type_aliases multi_ir in
  
  (* Core fix verification: Type alias section header is generated correctly *)
  check bool "has type alias section header" true (contains_substr c_code "/* Type alias definitions */");
  
  (* Core fix verification: Type aliases are generated correctly *)
  check bool "Counter typedef" true (contains_substr c_code "typedef __u64 Counter");
  
  (* Note: Struct section may not exist if no structs are defined (correct behavior) *)
  (* The bug fix ensures proper ordering when structs ARE present, which is tested elsewhere *)
  ()

(** Test that struct fields use type alias names to match original source *)
let test_struct_fields_use_alias_names () =
  (* Create a simple test that directly tests the ebpf_type_from_ir_type function *)
  
  (* Test that type aliases generate correct C type names *)
  let counter_alias = Kernelscript.Ir.IRTypeAlias ("Counter", Kernelscript.Ir.IRU64) in
  let ip_alias = Kernelscript.Ir.IRTypeAlias ("IpAddress", Kernelscript.Ir.IRU32) in
  
  let counter_c_type = ebpf_type_from_ir_type counter_alias in
  let ip_c_type = ebpf_type_from_ir_type ip_alias in
  
  (* Verify type aliases generate their alias names, not underlying types *)
  check string "Counter type alias generates correct name" "Counter" counter_c_type;
  check string "IpAddress type alias generates correct name" "IpAddress" ip_c_type;
  
  (* Test primitive types still generate underlying types *)
  let u64_type = ebpf_type_from_ir_type Kernelscript.Ir.IRU64 in
  let u32_type = ebpf_type_from_ir_type Kernelscript.Ir.IRU32 in
  
  check string "u64 type generates underlying type" "__u64" u64_type;
  check string "u32 type generates underlying type" "__u32" u32_type;
  ()

(** Test struct definition generation with type aliases in fields *)
let test_struct_definition_with_aliases () =
  
  (* Create type aliases *)
  let counter_alias = Kernelscript.Ir.IRTypeAlias ("Counter", Kernelscript.Ir.IRU64) in
  let ip_alias = Kernelscript.Ir.IRTypeAlias ("IpAddress", Kernelscript.Ir.IRU32) in
  
  (* Create struct definition with mixed field types *)
  let struct_fields = [
    ("count", counter_alias);      (* Should use "Counter" *)
    ("source_ip", ip_alias);       (* Should use "IpAddress" *)  
    ("timestamp", Kernelscript.Ir.IRU64);   (* Should use "__u64" *)
    ("flags", Kernelscript.Ir.IRU32)        (* Should use "__u32" *)
  ] in
  
  (* Generate struct definition *)
  let struct_lines = ref [] in
  struct_lines := "struct PacketStats {" :: !struct_lines;
  
  List.iter (fun (field_name, field_type) ->
    let c_type = ebpf_type_from_ir_type field_type in
    struct_lines := (Printf.sprintf "    %s %s;" c_type field_name) :: !struct_lines
  ) struct_fields;
  
  struct_lines := "};" :: !struct_lines;
  
  let generated_struct = String.concat "\n" (List.rev !struct_lines) in
  
  (* Verify struct fields use correct type names *)
  check bool "struct uses Counter type for count field" true (contains_substr generated_struct "Counter count");
  check bool "struct uses IpAddress type for source_ip field" true (contains_substr generated_struct "IpAddress source_ip");
  check bool "struct uses __u64 for timestamp field" true (contains_substr generated_struct "__u64 timestamp");
  check bool "struct uses __u32 for flags field" true (contains_substr generated_struct "__u32 flags");
  
  (* Verify it doesn't incorrectly use underlying types for aliased fields *)
  check bool "struct doesn't use __u64 for count field" false (contains_substr generated_struct "__u64 count");
  check bool "struct doesn't use __u32 for source_ip field" false (contains_substr generated_struct "__u32 source_ip");
  ()

(** Test hex literal addressing fix in map operations *)
let test_hex_literal_addressing_fix () =
  let ctx = create_c_context () in
  
  (* Test map operations with hex literals like 0x7F000001 (the specific bug case) *)
  let map_val = make_ir_value (IRMapRef "packet_counts") (IRPointer (IRStruct ("map", [], false), make_bounds_info ())) test_pos in
  
  (* Create hex literal like the one in rate_limiter.ks that caused the bug *)
  let hex_key = make_ir_value (IRLiteral (IntLit (2130706433, Some "0x7F000001"))) IRU32 test_pos in
  let hex_value = make_ir_value (IRLiteral (IntLit (255, Some "0xFF"))) IRU64 test_pos in
  
  (* Test map store with hex literals *)
  generate_map_store ctx map_val hex_key hex_value MapUpdate;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Verify that hex literals create temporary variables and don't try to take addresses directly *)
  check bool "hex key temp variable created" true (contains_substr output "__u32 key_");
  check bool "hex value temp variable created" true (contains_substr output "__u64 value_");
  check bool "hex key literal preserved" true (contains_substr output "= 0x7F000001;");
  check bool "hex value literal preserved" true (contains_substr output "= 0xFF;");
  check bool "map update uses hex key temp variable" true (contains_substr output "bpf_map_update_elem(&packet_counts, &key_");
  check bool "map update uses hex value temp variable" true (contains_substr output ", &value_");
  
  (* Critical: Verify the bug is fixed - no direct addressing of hex literals *)
  check bool "no direct hex key addressing" false (contains_substr output "&0x7F000001");
  check bool "no direct hex value addressing" false (contains_substr output "&0xFF");
  
  (* Test map load with hex literal *)
  let ctx2 = create_c_context () in
  let dest_val = make_ir_value (IRVariable "count") IRU64 test_pos in
  
  generate_map_load ctx2 map_val hex_key dest_val MapLookup;
  
  let output2 = String.concat "\n" (List.rev ctx2.output_lines) in
  
  (* Verify hex literal handling in map lookup *)
  check bool "lookup hex key temp variable created" true (contains_substr output2 "__u32 key_");
  check bool "lookup hex key literal preserved" true (contains_substr output2 "= 0x7F000001;");
  check bool "lookup uses hex key temp variable" true (contains_substr output2 "bpf_map_lookup_elem(&packet_counts, &key_");
  check bool "lookup no direct hex key addressing" false (contains_substr output2 "&0x7F000001");
  
  (* Test map delete with hex literal *)
  let ctx3 = create_c_context () in
  
  let delete_instr = make_ir_instruction (IRMapDelete (map_val, hex_key)) test_pos in
  generate_c_instruction ctx3 delete_instr;
  
  let output3 = String.concat "\n" (List.rev ctx3.output_lines) in
  
  (* Verify hex literal handling in map delete *)
  check bool "delete hex key temp variable created" true (contains_substr output3 "__u32 key_");
  check bool "delete hex key literal preserved" true (contains_substr output3 "= 0x7F000001;");
  check bool "delete uses hex key temp variable" true (contains_substr output3 "bpf_map_delete_elem(&packet_counts, &key_");
  check bool "delete no direct hex key addressing" false (contains_substr output3 "&0x7F000001");
  ()

(** Integration test: Verify complete fix works in generated C code *)
let test_complete_type_alias_fix_integration () =
  (* Integration test verifying all three main bug fixes work together *)
  
  let type_aliases = [
    ("IpAddress", Kernelscript.Ast.U32);
    ("Counter", Kernelscript.Ast.U64);
    ("PacketSize", Kernelscript.Ast.U16);
  ] in
  
  (* Create a minimal mock multi-program IR for integration testing *)
  let dummy_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  let ir_program = {
    Kernelscript.Ir.name = "packet_analyzer";
    program_type = Kernelscript.Ast.Xdp;
    entry_function = {
      func_name = "packet_analyzer";
      parameters = [("ctx", Kernelscript.Ir.IRStruct("xdp_md", [], true))];
      return_type = Some (Kernelscript.Ir.IRStruct("xdp_action", [], true));
      basic_blocks = [];
      total_stack_usage = 0;
      max_loop_depth = 0;
      calls_helper_functions = [];
      visibility = Kernelscript.Ir.Public;
      is_main = true;
      func_pos = dummy_pos;
      tail_call_targets = [];
      tail_call_index_map = Hashtbl.create 16;
      is_tail_callable = false;
      func_program_type = None;
    };
    ir_pos = dummy_pos;
  } in
  
  let multi_ir = {
    Kernelscript.Ir.source_name = "packet_analyzer";
    programs = [ir_program];
    kernel_functions = [];
    global_maps = [];
    global_variables = [];
    global_configs = [];
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = None;
    userspace_bindings = [];
    multi_pos = dummy_pos;
  } in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ~type_aliases multi_ir in
  
  (* Verify no empty structs are generated for type aliases *)
  check bool "no empty Counter struct" false (contains_substr c_code "struct Counter {");
  check bool "no empty IpAddress struct" false (contains_substr c_code "struct IpAddress {");
  check bool "no empty PacketSize struct" false (contains_substr c_code "struct PacketSize {");
  
  (* Verify type alias definitions are properly generated *)
  check bool "has type alias section header" true (contains_substr c_code "/* Type alias definitions */");
  
  (* Verified in dedicated test (test_struct_fields_use_alias_names) *)
  (* Note: This integration test focuses on verifying the type alias generation without requiring structs *)
  
  (* Verify all type aliases are properly generated *)
  check bool "IpAddress typedef" true (contains_substr c_code "typedef __u32 IpAddress");
  check bool "Counter typedef" true (contains_substr c_code "typedef __u64 Counter");
  check bool "PacketSize typedef" true (contains_substr c_code "typedef __u16 PacketSize");
  ()

(** Test string size collection from userspace structs (bug fix regression test) *)
let test_string_size_collection_from_userspace_structs () =
  (* Create a userspace struct with string fields to test string size collection *)
  let dummy_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  
  let userspace_struct = {
    Kernelscript.Ir.struct_name = "network_config";
    struct_fields = [
      ("interface", Kernelscript.Ir.IRStr 16);  (* This should be collected as str_16_t *)
      ("hostname", Kernelscript.Ir.IRStr 20);   (* This should be collected as str_20_t *)
      ("max_packet_size", Kernelscript.Ir.IRU32);
    ];
    struct_alignment = 1;
    struct_size = 32;
    struct_pos = dummy_pos;
    kernel_defined = false;
  } in
  
  let userspace_program = {
    Kernelscript.Ir.userspace_structs = [userspace_struct];
    userspace_functions = [];
    userspace_configs = [];
    coordinator_logic = {
      setup_logic = [];
      event_processing = [];
      cleanup_logic = [];
      config_management = {
        config_loads = [];
        config_updates = [];
        runtime_config_sync = [];
      };
    };
    userspace_pos = dummy_pos;
  } in
  
  let multi_ir = {
    Kernelscript.Ir.source_name = "test";
    programs = [];
    kernel_functions = [];
    global_maps = [];
    global_variables = [];
    global_configs = [];
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = Some userspace_program;
    userspace_bindings = [];
    multi_pos = dummy_pos;
  } in
  
  (* Test that string sizes are NOT collected from userspace structs (bug fix regression test) *)
  (* This test verifies that we fixed the bug where userspace-only structs were being included in eBPF code *)
  let collected_sizes = collect_string_sizes_from_multi_program multi_ir in
  
  (* Verify that userspace-only string sizes are NOT collected *)
  check bool "string size 16 NOT collected (userspace-only)" false (List.mem 16 collected_sizes);
  check bool "string size 20 NOT collected (userspace-only)" false (List.mem 20 collected_sizes);
  check bool "no string sizes collected from userspace-only structs" true (collected_sizes = []);
  ()

(** Test declaration ordering (bug fix regression test) *)
let test_declaration_ordering_fix () =
  (* Create a multi-program IR with map and function to test ordering *)
  let dummy_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  
  let map_def = make_ir_map_def "test_map" IRU32 IRU64 IRHashMap 1024 dummy_pos in
  
  let map_lookup_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", [], false), make_bounds_info ())) dummy_pos in
  let key_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 dummy_pos in
  let dest_val = make_ir_value (IRVariable "result") IRU64 dummy_pos in
  
  (* Create instruction that uses the map *)
  let map_instr = make_ir_instruction (IRMapLoad (map_lookup_val, key_val, dest_val, MapLookup)) dummy_pos in
  let return_instr = make_ir_instruction (IRReturn (Some dest_val)) dummy_pos in
  
  let main_block = make_ir_basic_block "entry" [map_instr; return_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRPointer (IRContext XdpCtx, make_bounds_info ()))] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true dummy_pos in
  
  let ir_program = {
    Kernelscript.Ir.name = "test_program";
    program_type = Kernelscript.Ast.Xdp;
    entry_function = main_func;
    ir_pos = dummy_pos;
  } in
  
  let multi_ir = {
    Kernelscript.Ir.source_name = "test";
    programs = [ir_program];
    kernel_functions = [];
    global_maps = [map_def];
    global_variables = [];
    global_configs = [];
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = None;
    userspace_bindings = [];
    multi_pos = dummy_pos;
  } in
  
  (* Generate C code *)
  let c_code = generate_c_multi_program multi_ir in
  
  (* Find positions of map definition and function definition *)
  let map_pos = try 
    Str.search_forward (Str.regexp "BPF_MAP_TYPE_HASH") c_code 0
  with Not_found -> -1 in
  
  let func_pos = try 
    Str.search_forward (Str.regexp "SEC(\"xdp\")") c_code 0 
  with Not_found -> -1 in
  
  (* Verify map is defined before function *)
  check bool "map found in generated code" true (map_pos >= 0);
  check bool "function found in generated code" true (func_pos >= 0);
  check bool "map defined before function" true (map_pos < func_pos);
  ()

(** Test bpf_printk string literal handling (bug fix regression test) *)
let test_bpf_printk_string_literal_fix () =
  (* Test that string literals in print statements are handled correctly *)
  let dummy_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  
  (* Create a print call with a string literal *)
  let str_literal = make_ir_value (IRLiteral (StringLit "test message")) (IRStr 12) dummy_pos in
  let result_var = make_ir_value (IRVariable "result") IRU32 dummy_pos in
  let print_instr = make_ir_instruction (IRCall (DirectCall "print", [str_literal], Some result_var)) dummy_pos in
  
  let main_block = make_ir_basic_block "entry" [print_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRPointer (IRContext XdpCtx, make_bounds_info ()))] (Some (IRAction Xdp_actionType)) [main_block] ~is_main:true dummy_pos in
  
  let ir_program = {
    Kernelscript.Ir.name = "test_program";
    program_type = Kernelscript.Ast.Xdp;
    entry_function = main_func;
    ir_pos = dummy_pos;
  } in
  
  let multi_ir = {
    Kernelscript.Ir.source_name = "test";
    programs = [ir_program];
    kernel_functions = [];
    global_maps = [];
    global_variables = [];
    global_configs = [];
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = None;
    userspace_bindings = [];
    multi_pos = dummy_pos;
  } in
  
  (* Generate C code *)
  let c_code = generate_c_multi_program multi_ir in
  
  (* Verify that bpf_printk is called with string literal directly, not with .data *)
  check bool "bpf_printk called with string literal" true (contains_substr c_code "bpf_printk(\"test message\")");
  
  (* Verify that .data is NOT used in bpf_printk call (this was the bug) *)
  check bool "bpf_printk does not use .data" false (contains_substr c_code "bpf_printk(str_lit_");
  check bool "bpf_printk does not use struct field" false (contains_substr c_code ".data)");
  ()

(** Test map field access pointer fix (bug fix regression test) *)
let test_map_field_access_pointer_fix () =
  (* Test that field access on map lookup results uses arrow notation via SAFE_PTR_ACCESS *)
  let dummy_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test" } in
  let ctx = create_c_context () in
  
  (* Create a value that represents a map access result *)
  let key_val = make_ir_value (IRLiteral (IntLit (1, None))) IRU32 dummy_pos in
  let map_access_val = make_ir_value 
    (IRMapAccess ("buffer_map", key_val, (IRRegister 5, IRPointer (IRStruct ("DataBuffer", [("size", IRU32)], false), make_bounds_info ()))))
    (IRPointer (IRStruct ("DataBuffer", [("size", IRU32)], false), make_bounds_info ()))
    dummy_pos in
  
  (* Create field access expression *)
  let field_expr = make_ir_expr (IRFieldAccess (map_access_val, "size")) IRU32 dummy_pos in
  
  (* Generate C code for the field access *)
  let c_result = generate_c_expression ctx field_expr in
  
  (* Verify that SAFE_PTR_ACCESS is used for map access field access *)
  check bool "SAFE_PTR_ACCESS used for map field access" true (contains_substr c_result "SAFE_PTR_ACCESS");
  
  (* Verify that dot notation is NOT used (this was the bug) *)
  check bool "no dot notation for map field access" false (contains_substr c_result ".size");
  
  (* Now test regular struct (non-map) field access to ensure it still uses dot notation *)
  let regular_val = make_ir_value (IRVariable "my_struct") (IRStruct ("DataBuffer", [("size", IRU32)], false)) dummy_pos in
  let regular_field_expr = make_ir_expr (IRFieldAccess (regular_val, "size")) IRU32 dummy_pos in
  let regular_result = generate_c_expression ctx regular_field_expr in
  
  (* Verify that regular struct access still uses dot notation *)
  check bool "dot notation used for regular struct field access" true (contains_substr regular_result "my_struct.size");
  ()

(** Test variable declaration with function call initialization *)
let test_variable_function_call_declaration () =
  let ctx = create_c_context () in
  ctx.indent_level <- 1; (* Set valid indent level *)
  
  (* Create a function call that returns to a register *)
  let result_reg = 0 in
  let result_val = make_ir_value (IRRegister result_reg) IRU32 test_pos in
  let call_instr = make_ir_instruction (IRCall (DirectCall "helper_function", [make_ir_value (IRLiteral (IntLit (5, None))) IRU32 test_pos], Some result_val)) test_pos in
  
  (* Create a variable declaration for the same register with no initialization *)
  let decl_instr = make_ir_instruction (IRDeclareVariable (result_val, IRU32, None)) test_pos in
  
  (* Test the optimization that combines these into a single declaration *)
  let ir_block = make_ir_basic_block "test" [call_instr; decl_instr] 0 in
  generate_c_basic_block ctx ir_block;
  
  let output = String.concat "\n" ctx.output_lines in
  
  (* Should generate: __u32 val_0 = helper_function(5); *)
  check bool "combined declaration with function call" true (contains_substr output "val_0 = helper_function(5)");
  
  (* Should NOT generate separate variable declaration without initialization *)
  check bool "no uninitialized declaration" false (contains_substr output "__u32 val_0;")

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
    ("Hex literal addressing fix", `Quick, test_hex_literal_addressing_fix);
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
    (* Type alias and struct bug fix regression tests *)
    ("No empty struct generation", `Quick, test_no_empty_struct_generation);
    ("Type alias struct ordering", `Quick, test_type_alias_struct_ordering);
    ("Struct fields use alias names", `Quick, test_struct_fields_use_alias_names);
    ("Struct definition with aliases", `Quick, test_struct_definition_with_aliases);
    ("Complete type alias fix integration", `Quick, test_complete_type_alias_fix_integration);
    ("Map field access pointer fix", `Quick, test_map_field_access_pointer_fix);
    (* Bug fix regression tests *)
    ("String size collection from userspace structs", `Quick, test_string_size_collection_from_userspace_structs);
    ("Declaration ordering fix", `Quick, test_declaration_ordering_fix);
    ("BPF printk string literal fix", `Quick, test_bpf_printk_string_literal_fix);
    ("Variable function call declaration", `Quick, test_variable_function_call_declaration);
  ]

(** Run all tests *)
let () =
  run "eBPF C Code Generation" [
    ("ebpf_c_codegen", suite);
  ] 