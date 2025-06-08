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
  assert (ir_type_to_c_type IRU32 = "__u32");
  assert (ir_type_to_c_type IRBool = "bool");
  assert (ir_type_to_c_type (IRPointer (IRU8, make_bounds_info ())) = "__u8*");
  assert (ir_type_to_c_type (IRArray (IRU32, 10, make_bounds_info ())) = "__u32[10]");
  assert (ir_type_to_c_type (IRContext XdpCtx) = "struct xdp_md*");
  print_endline "✓ Type conversion test passed"

(** Test map definition generation *)
let test_map_definition () =
  let map_def = make_ir_map_def "test_map" IRU32 IRU64 IRHashMap 1024 test_pos in
  let ctx = create_c_context () in
  generate_map_definition ctx map_def;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  assert (String.contains output '{');
  assert (String.contains output '}');
  assert (contains_substr output "test_map");
  assert (contains_substr output "BPF_MAP_TYPE_HASH");
  print_endline "✓ Map definition test passed"

(** Test C value generation *)
let test_c_value_generation () =
  let ctx = create_c_context () in
  
  (* Test literals *)
  let int_val = make_ir_value (IRLiteral (IntLit 42)) IRU32 test_pos in
  assert (generate_c_value ctx int_val = "42");
  
  let bool_val = make_ir_value (IRLiteral (BoolLit true)) IRBool test_pos in
  assert (generate_c_value ctx bool_val = "true");
  
  let var_val = make_ir_value (IRVariable "my_var") IRU32 test_pos in
  assert (generate_c_value ctx var_val = "my_var");
  
  print_endline "✓ C value generation test passed"

(** Test C expression generation *)
let test_c_expression_generation () =
  let ctx = create_c_context () in
  
  (* Test binary operation: 10 + 20 *)
  let left_val = make_ir_value (IRLiteral (IntLit 10)) IRU32 test_pos in
  let right_val = make_ir_value (IRLiteral (IntLit 20)) IRU32 test_pos in
  let add_expr = make_ir_expr (IRBinOp (left_val, IRAdd, right_val)) IRU32 test_pos in
  
  let result = generate_c_expression ctx add_expr in
  assert (result = "(10 + 20)");
  
  print_endline "✓ C expression generation test passed"

(** Test context field access *)
let test_context_access () =
  let ctx = create_c_context () in
  
  let data_field = make_ir_value (IRContextField (XdpCtx, "data")) (IRPointer (IRU8, make_bounds_info ())) test_pos in
  let result = generate_c_value ctx data_field in
  assert (result = "(void*)(long)ctx->data");
  
  print_endline "✓ Context access test passed"

(** Test bounds checking generation *)
let test_bounds_checking () =
  let ctx = create_c_context () in
  
  let index_val = make_ir_value (IRLiteral (IntLit 5)) IRU32 test_pos in
  generate_bounds_check ctx index_val 0 9;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  assert (contains_substr output "if");
  assert (contains_substr output "return XDP_DROP");
  
  print_endline "✓ Bounds checking test passed"

(** Test map operations generation *)
let test_map_operations () =
  let ctx = create_c_context () in
  
  (* Test map lookup *)
  let map_val = make_ir_value (IRMapRef "test_map") (IRPointer (IRStruct ("map", []), make_bounds_info ())) test_pos in
  let key_val = make_ir_value (IRLiteral (IntLit 42)) IRU32 test_pos in
  let dest_val = make_ir_value (IRVariable "result") (IRPointer (IRU64, make_bounds_info ())) test_pos in
  
  generate_map_load ctx map_val key_val dest_val MapLookup;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  assert (contains_substr output "bpf_map_lookup_elem");
  assert (contains_substr output "test_map");
  
  print_endline "✓ Map operations test passed"

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
  assert (contains_substr output "SEC(\"xdp\")");
  assert (contains_substr output "test_main");
  assert (contains_substr output "struct xdp_md* ctx");
  assert (contains_substr output "return 42");
  
  print_endline "✓ Function generation test passed"

(** Test complete program generation *)
let test_complete_program () =
  (* Create a simple XDP program *)
  let return_val = make_ir_value (IRLiteral (IntLit 2)) IRU32 test_pos in (* XDP_PASS *)
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "xdp_prog" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  
  (* Add a simple map *)
  let map_def = make_ir_map_def "packet_count" IRU32 IRU64 IRHashMap 1024 test_pos in
  
  let ir_prog = make_ir_program "test_xdp" Xdp [map_def] [] [] main_func test_pos in
  
  let c_code = compile_to_c ir_prog in
  
  (* Verify the generated C code contains expected elements *)
  assert (contains_substr c_code "#include <linux/bpf.h>");
  assert (contains_substr c_code "packet_count");
  assert (contains_substr c_code "SEC(\"maps\")");
  assert (contains_substr c_code "SEC(\"xdp\")");
  assert (contains_substr c_code "xdp_prog");
  assert (contains_substr c_code "GPL");
  
  print_endline "Generated C code:";
  print_endline "==================";
  print_endline c_code;
  print_endline "==================";
  print_endline "✓ Complete program generation test passed"

(** Test helper function calls *)
let test_helper_calls () =
  let ctx = create_c_context () in
  
  let pid_var = make_ir_value (IRVariable "pid") IRU64 test_pos in
  generate_helper_call ctx "get_current_pid_tgid" [] (Some pid_var);
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  assert (contains_substr output "bpf_get_current_pid_tgid");
  assert (contains_substr output "pid =");
  
  print_endline "✓ Helper function calls test passed"

(** Test advanced control flow *)
let test_control_flow () =
  let ctx = create_c_context () in
  
  (* Test conditional jump *)
  let cond_val = make_ir_value (IRLiteral (IntLit 1)) IRBool test_pos in
  let cond_jump = make_ir_instruction (IRCondJump (cond_val, "true_branch", "false_branch")) test_pos in
  
  generate_c_instruction ctx cond_jump;
  
  let output = String.concat "\n" (List.rev ctx.output_lines) in
  assert (contains_substr output "if (1)");
  assert (contains_substr output "goto true_branch");
  assert (contains_substr output "goto false_branch");
  
  print_endline "✓ Control flow test passed"

(** Test file writing functionality *)
let test_file_writing () =
  let return_val = make_ir_value (IRLiteral (IntLit 2)) IRU32 test_pos in
  let return_instr = make_ir_instruction (IRReturn (Some return_val)) test_pos in
  let main_block = make_ir_basic_block "entry" [return_instr] 0 in
  let main_func = make_ir_function "test_prog" [("ctx", IRContext XdpCtx)] (Some (IRAction XdpActionType)) [main_block] ~is_main:true test_pos in
  let ir_prog = make_ir_program "test" Xdp [] [] [] main_func test_pos in
  
  let test_filename = "test_output.c" in
  let c_code = write_c_to_file ir_prog test_filename in
  
  (* Verify file exists and has content *)
  assert (Sys.file_exists test_filename);
  let ic = open_in test_filename in
  let file_content = really_input_string ic (in_channel_length ic) in
  close_in ic;
  
  assert (file_content = c_code);
  assert (contains_substr file_content "SEC(\"xdp\")");
  
  (* Clean up *)
  Sys.remove test_filename;
  
  print_endline "✓ File writing test passed"

(** Run all tests *)
let run_tests () =
  print_endline "Running eBPF C code generation tests...";
  test_type_conversion ();
  test_map_definition ();
  test_c_value_generation ();
  test_c_expression_generation ();
  test_context_access ();
  test_bounds_checking ();
  test_map_operations ();
  test_function_generation ();
  test_helper_calls ();
  test_control_flow ();
  test_file_writing ();
  test_complete_program ();
  print_endline "All eBPF C code generation tests passed! ✓"

let () = run_tests () 