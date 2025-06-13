(** Tests for eBPF C Code Generation *)

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
  Alcotest.(check string) "IRU32 conversion" "__u32" (ebpf_type_from_ir_type IRU32);
  Alcotest.(check string) "IRBool conversion" "__u8" (ebpf_type_from_ir_type IRBool);
  Alcotest.(check string) "IRPointer conversion" "__u8*" (ebpf_type_from_ir_type (IRPointer (IRU8, make_bounds_info ())));
  Alcotest.(check string) "IRArray conversion" "__u32[10]" (ebpf_type_from_ir_type (IRArray (IRU32, 10, make_bounds_info ())));
  Alcotest.(check string) "IRContext conversion" "struct xdp_md*" (ebpf_type_from_ir_type (IRContext XdpCtx))

(** Test map definition generation *)
let test_map_definition () =
  let map_def = make_ir_map_def "test_map" IRU32 IRU64 IRHashMap 1024 test_pos in
  let ctx = create_c_context () in
  generate_map_definition ctx map_def;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  Alcotest.(check bool) "output contains opening brace" true (String.contains output '{');
  Alcotest.(check bool) "output contains closing brace" true (String.contains output '}');
  Alcotest.(check bool) "output contains map name" true (contains_substr output "test_map");
  Alcotest.(check bool) "output contains map type" true (contains_substr output "BPF_MAP_TYPE_HASH")

(** Test C value generation *)
let test_c_value_generation () =
  let ctx = create_c_context () in
  
  (* Test literals *)
  let int_val = make_ir_value (IRLiteral (IntLit 42)) IRU32 test_pos in
  Alcotest.(check string) "integer literal" "42" (generate_c_value ctx int_val);
  
  let bool_val = make_ir_value (IRLiteral (BoolLit true)) IRBool test_pos in
  Alcotest.(check string) "boolean literal" "true" (generate_c_value ctx bool_val);
  
  let var_val = make_ir_value (IRVariable "my_var") IRU32 test_pos in
  Alcotest.(check string) "variable reference" "my_var" (generate_c_value ctx var_val)

(** Test C expression generation *)
let test_c_expression_generation () =
  let ctx = create_c_context () in
  
  (* Test binary operation: 10 + 20 *)
  let left_val = make_ir_value (IRLiteral (IntLit 10)) IRU32 test_pos in
  let right_val = make_ir_value (IRLiteral (IntLit 20)) IRU32 test_pos in
  let add_expr = make_ir_expr (IRBinOp (left_val, IRAdd, right_val)) IRU32 test_pos in
  
  let result = generate_c_expression ctx add_expr in
  Alcotest.(check string) "binary addition" "(10 + 20)" result

(** Test context field access *)
let test_context_access () =
  let ctx = create_c_context () in
  
  let data_field = make_ir_value (IRContextField (XdpCtx, "data")) (IRPointer (IRU8, make_bounds_info ())) test_pos in
  let result = generate_c_value ctx data_field in
  Alcotest.(check string) "context data field access" "(void*)(long)ctx->data" result

(** Test bounds checking generation *)
let test_bounds_checking () =
  let ctx = create_c_context () in
  
  let index_val = make_ir_value (IRLiteral (IntLit 5)) IRU32 test_pos in
  generate_bounds_check ctx index_val 0 9;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  Alcotest.(check bool) "bounds check contains if statement" true (contains_substr output "if");
  Alcotest.(check bool) "bounds check contains XDP_DROP" true (contains_substr output "return XDP_DROP")

(** Test map operations generation *)
let test_map_operations () =
  let ctx = create_c_context () in
  
  (* Test map lookup *)
  let map_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", []), make_bounds_info ())) test_pos in
  let key_val = make_ir_value (IRLiteral (IntLit 42)) IRU32 test_pos in
  let dest_val = make_ir_value (IRVariable "result") (IRPointer (IRU64, make_bounds_info ())) test_pos in
  
  generate_map_load ctx map_val key_val dest_val MapLookup;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  Alcotest.(check bool) "map lookup contains bpf_map_lookup_elem" true (contains_substr output "bpf_map_lookup_elem");
  Alcotest.(check bool) "map lookup contains map name" true (contains_substr output "test_map")

(** Test literal keys and values in map operations *)
let test_literal_map_operations () =
  let ctx = create_c_context () in
  
  (* Test map store with literal key and value *)
  let map_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", []), make_bounds_info ())) test_pos in
  let literal_key = make_ir_value (IRLiteral (IntLit 42)) IRU32 test_pos in
  let literal_value = make_ir_value (IRLiteral (IntLit 100)) IRU64 test_pos in
  
  generate_map_store ctx map_val literal_key literal_value MapUpdate;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  
  (* Verify that temporary variables are created for literals *)
  Alcotest.(check bool) "key temp variable created" true (contains_substr output "__u32 key_");
  Alcotest.(check bool) "value temp variable created" true (contains_substr output "__u64 value_");
  Alcotest.(check bool) "key literal assigned" true (contains_substr output "= 42;");
  Alcotest.(check bool) "value literal assigned" true (contains_substr output "= 100;");
  Alcotest.(check bool) "map update uses temp variables" true (contains_substr output "bpf_map_update_elem(&test_map, &key_");
  Alcotest.(check bool) "map update uses value temp" true (contains_substr output ", &value_");
  
  (* Verify literals are NOT directly addressed (no &42 or &100) *)
  Alcotest.(check bool) "no direct key literal addressing" false (contains_substr output "&42");
  Alcotest.(check bool) "no direct value literal addressing" false (contains_substr output "&100");
  
  (* Test map load with literal key *)
  let ctx2 = create_c_context () in
  let dest_val = make_ir_value (IRVariable "result") IRU64 test_pos in
  
  generate_map_load ctx2 map_val literal_key dest_val MapLookup;
  
  let output2 = String.concat "\n" (List.rev ctx2.output_lines) in
  
  (* Verify key temp variable for lookup *)
  Alcotest.(check bool) "lookup key temp variable created" true (contains_substr output2 "__u32 key_");
  Alcotest.(check bool) "lookup key literal assigned" true (contains_substr output2 "= 42;");
  Alcotest.(check bool) "lookup uses temp key variable" true (contains_substr output2 "bpf_map_lookup_elem(&test_map, &key_");
  Alcotest.(check bool) "lookup no direct key addressing" false (contains_substr output2 "&42");
  
  (* Test map delete with literal key *)
  let ctx3 = create_c_context () in
  
  let delete_instr = make_ir_instruction (IRMapDelete (map_val, literal_key)) test_pos in
  generate_c_instruction ctx3 delete_instr;
  
  let output3 = String.concat "\n" (List.rev ctx3.output_lines) in
  
  (* Verify key temp variable for delete *)
  Alcotest.(check bool) "delete key temp variable created" true (contains_substr output3 "__u32 key_");
  Alcotest.(check bool) "delete key literal assigned" true (contains_substr output3 "= 42;");
  Alcotest.(check bool) "delete uses temp key variable" true (contains_substr output3 "bpf_map_delete_elem(&test_map, &key_");
  Alcotest.(check bool) "delete no direct key addressing" false (contains_substr output3 "&42");
  
  (* Test with non-literal (variable) keys and values - should not create temp vars *)
  let ctx4 = create_c_context () in
  let var_key = make_ir_value (IRVariable "my_key") IRU32 test_pos in
  let var_value = make_ir_value (IRVariable "my_value") IRU64 test_pos in
  
  generate_map_store ctx4 map_val var_key var_value MapUpdate;
  
  let output4 = String.concat "\n" (List.rev ctx4.output_lines) in
  
  (* Verify variables are used directly without temp vars *)
  Alcotest.(check bool) "variable key used directly" true (contains_substr output4 "bpf_map_update_elem(&test_map, &my_key, &my_value");
  Alcotest.(check bool) "no temp vars for variable keys" false (contains_substr output4 "__u32 key_");
  Alcotest.(check bool) "no temp vars for variable values" false (contains_substr output4 "__u64 value_")

(** Test simple function generation *)
let test_function_generation () =
  let ctx = create_c_context () in
  
  (* Create a simple function: return 42; *)
  let return_val = make_ir_value (IRLiteral (IntLit 42)) IRU32 test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "test_main" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  
  generate_c_function ctx main_func;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  Alcotest.(check bool) "function contains SEC annotation" true (contains_substr output "SEC(\"xdp\")");
  Alcotest.(check bool) "function contains function name" true (contains_substr output "test_main");
  Alcotest.(check bool) "function contains parameter" true (contains_substr output "struct xdp_md* ctx");
  Alcotest.(check bool) "function contains return statement" true (contains_substr output "return 42")

(** Test complete program generation *)
let test_complete_program () =
  (* Create a simple XDP program *)
  let return_val = make_ir_value (IRLiteral (IntLit 2)) IRU32 test_pos in (* XDP_PASS *)
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "xdp_prog" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  
  (* Add a simple map *)
  let map_def = make_ir_map_def "packet_count" IRU32 IRU64 IRHashMap 1024 test_pos in
  
  let ir_prog = make_ir_program "test_xdp" Xdp [map_def] [] main_func test_pos in
  
  let c_code = compile_to_c ir_prog in
  
  (* Verify the generated C code contains expected elements *)
  Alcotest.(check bool) "program contains linux/bpf.h include" true (contains_substr c_code "#include <linux/bpf.h>");
  Alcotest.(check bool) "program contains map name" true (contains_substr c_code "packet_count");
  Alcotest.(check bool) "program contains maps section" true (contains_substr c_code "SEC(\".maps\")");
  Alcotest.(check bool) "program contains xdp section" true (contains_substr c_code "SEC(\"xdp\")");
  Alcotest.(check bool) "program contains function name" true (contains_substr c_code "xdp_prog");
  Alcotest.(check bool) "program contains GPL license" true (contains_substr c_code "GPL")

(** Test helper function calls *)
let test_helper_calls () =
  let ctx = create_c_context () in
  
  let pid_var = make_ir_value (IRVariable "pid") IRU64 test_pos in
  generate_helper_call ctx "get_current_pid_tgid" [] (Some pid_var);
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  Alcotest.(check bool) "helper call contains bpf function name" true (contains_substr output "bpf_get_current_pid_tgid");
  Alcotest.(check bool) "helper call contains assignment" true (contains_substr output "pid =")

(** Test advanced control flow *)
let test_control_flow () =
  let ctx = create_c_context () in
  
  (* Test conditional jump *)
  let cond_val = make_ir_value (IRLiteral (IntLit 1)) IRBool test_pos in
  let cond_jump = make_ir_instruction (IRCondJump (cond_val, "true_branch", "false_branch")) test_pos in
  
  generate_c_instruction ctx cond_jump;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  Alcotest.(check bool) "control flow contains if statement" true (contains_substr output "if (1)");
  Alcotest.(check bool) "control flow contains true branch goto" true (contains_substr output "goto true_branch");
  Alcotest.(check bool) "control flow contains false branch goto" true (contains_substr output "goto false_branch")

(** Test file writing functionality *)
let test_file_writing () =
  let return_val = make_ir_value (IRLiteral (IntLit 2)) IRU32 test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "test_prog" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test" Xdp [] [] main_func test_pos in
  
  let test_filename = "test_output.c" in
  let c_code = write_c_to_file ir_prog test_filename in
  
  (* Verify file exists and has content *)
  Alcotest.(check bool) "output file exists" true (Sys.file_exists test_filename);
  let ic = open_in test_filename in
  let file_content = really_input_string ic (in_channel_length ic) in
  close_in ic;
  
  Alcotest.(check string) "file content matches generated code" c_code file_content;
  Alcotest.(check bool) "file contains SEC annotation" true (contains_substr file_content "SEC(\"xdp\")");
  
  (* Clean up *)
  Sys.remove test_filename

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
    ("Helper calls", `Quick, test_helper_calls);
    ("Control flow", `Quick, test_control_flow);
    ("File writing", `Quick, test_file_writing);
    ("Complete program", `Quick, test_complete_program);
  ]

(** Run all tests *)
let () =
  Alcotest.run "eBPF C Code Generation" [
    ("ebpf_c_codegen", suite);
  ] 