open Alcotest
open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ebpf_c_codegen

(** Test for the pattern matching fixes in collect_string_sizes_from_instr *)

let test_collect_string_sizes_basic () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test basic IRAssign instruction *)
  let test_val = make_ir_value (IRLiteral (StringLit "test")) (IRStr 4) pos in
  let test_expr = make_ir_expr (IRValue test_val) (IRStr 4) pos in
  let assign_instr = make_ir_instruction (IRAssign (test_val, test_expr)) pos in
  
  let sizes = collect_string_sizes_from_instr assign_instr in
  check (list int) "Basic string size collection" [4; 4] sizes

let test_collect_string_sizes_config_access () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test IRConfigAccess instruction *)
  let result_val = make_ir_value (IRVariable "result") (IRStr 10) pos in
  let config_access_instr = make_ir_instruction (IRConfigAccess ("config", "field", result_val)) pos in
  
  let sizes = collect_string_sizes_from_instr config_access_instr in
  check (list int) "Config access string size collection" [10] sizes

let test_collect_string_sizes_context_access () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test IRContextAccess instruction *)
  let dest_val = make_ir_value (IRVariable "dest") (IRStr 8) pos in
  let ctx_access_instr = make_ir_instruction (IRContextAccess (dest_val, PacketData)) pos in
  
  let sizes = collect_string_sizes_from_instr ctx_access_instr in
  check (list int) "Context access string size collection" [8] sizes

let test_collect_string_sizes_bounds_check () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test IRBoundsCheck instruction *)
  let check_val = make_ir_value (IRLiteral (StringLit "bounds")) (IRStr 6) pos in
  let bounds_instr = make_ir_instruction (IRBoundsCheck (check_val, 0, 100)) pos in
  
  let sizes = collect_string_sizes_from_instr bounds_instr in
  check (list int) "Bounds check string size collection" [6] sizes

let test_collect_string_sizes_cond_jump () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test IRCondJump instruction *)
  let cond_val = make_ir_value (IRLiteral (StringLit "cond")) (IRStr 4) pos in
  let jump_instr = make_ir_instruction (IRCondJump (cond_val, "true_block", "false_block")) pos in
  
  let sizes = collect_string_sizes_from_instr jump_instr in
  check (list int) "Conditional jump string size collection" [4] sizes

let test_collect_string_sizes_bpf_loop () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test IRBpfLoop instruction *)
  let start_val = make_ir_value (IRLiteral (StringLit "start")) (IRStr 5) pos in
  let end_val = make_ir_value (IRLiteral (StringLit "end")) (IRStr 3) pos in
  let counter_val = make_ir_value (IRVariable "counter") IRU32 pos in
  let ctx_val = make_ir_value (IRVariable "ctx") (IRContext XdpCtx) pos in
  
  (* Body instruction with string literal *)
  let body_val = make_ir_value (IRLiteral (StringLit "body")) (IRStr 4) pos in
  let body_expr = make_ir_expr (IRValue body_val) (IRStr 4) pos in
  let body_instr = make_ir_instruction (IRAssign (body_val, body_expr)) pos in
  
  let loop_instr = make_ir_instruction (IRBpfLoop (start_val, end_val, counter_val, ctx_val, [body_instr])) pos in
  
  let sizes = collect_string_sizes_from_instr loop_instr in
  check (list int) "BPF loop string size collection" [5; 3; 4; 4] sizes

let test_collect_string_sizes_cond_return () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test IRCondReturn instruction *)
  let cond_val = make_ir_value (IRLiteral (StringLit "condition")) (IRStr 9) pos in
  let true_val = make_ir_value (IRLiteral (StringLit "true")) (IRStr 4) pos in
  let false_val = make_ir_value (IRLiteral (StringLit "false")) (IRStr 5) pos in
  
  let cond_ret_instr = make_ir_instruction (IRCondReturn (cond_val, Some true_val, Some false_val)) pos in
  
  let sizes = collect_string_sizes_from_instr cond_ret_instr in
  check (list int) "Conditional return string size collection" [9; 4; 5] sizes

let test_collect_string_sizes_try_defer () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test IRTry instruction *)
  let try_val = make_ir_value (IRLiteral (StringLit "try")) (IRStr 3) pos in
  let try_expr = make_ir_expr (IRValue try_val) (IRStr 3) pos in
  let try_instr = make_ir_instruction (IRAssign (try_val, try_expr)) pos in
  
  let try_block_instr = make_ir_instruction (IRTry ([try_instr], [])) pos in
  
  let sizes = collect_string_sizes_from_instr try_block_instr in
  check (list int) "Try block string size collection" [3; 3] sizes;
  
  (* Test IRDefer instruction *)
  let defer_val = make_ir_value (IRLiteral (StringLit "defer")) (IRStr 5) pos in
  let defer_expr = make_ir_expr (IRValue defer_val) (IRStr 5) pos in
  let defer_inner_instr = make_ir_instruction (IRAssign (defer_val, defer_expr)) pos in
  
  let defer_instr = make_ir_instruction (IRDefer ([defer_inner_instr])) pos in
  
  let defer_sizes = collect_string_sizes_from_instr defer_instr in
  check (list int) "Defer block string size collection" [5; 5] defer_sizes

let test_collect_string_sizes_no_op_instructions () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Test instructions that should return empty lists *)
  let jump_instr = make_ir_instruction (IRJump "target") pos in
  let break_instr = make_ir_instruction IRBreak pos in
  let continue_instr = make_ir_instruction IRContinue pos in
  let comment_instr = make_ir_instruction (IRComment "test comment") pos in
  let throw_instr = make_ir_instruction (IRThrow (IntErrorCode 42)) pos in
  
  check (list int) "Jump instruction returns empty" [] (collect_string_sizes_from_instr jump_instr);
  check (list int) "Break instruction returns empty" [] (collect_string_sizes_from_instr break_instr);
  check (list int) "Continue instruction returns empty" [] (collect_string_sizes_from_instr continue_instr);
  check (list int) "Comment instruction returns empty" [] (collect_string_sizes_from_instr comment_instr);
  check (list int) "Throw instruction returns empty" [] (collect_string_sizes_from_instr throw_instr)

(** Test for collect_in_expr IRStructLiteral pattern fix *)

let test_collect_registers_struct_literal () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Create a struct literal with register values *)
  let reg1 = make_ir_value (IRRegister 1) IRU32 pos in
  let reg2 = make_ir_value (IRRegister 2) IRU64 pos in
  
  let struct_expr = make_ir_expr (IRStructLiteral ("TestStruct", [("field1", reg1); ("field2", reg2)])) 
                                 (IRStruct ("TestStruct", [("field1", IRU32); ("field2", IRU64)])) pos in
  
  let dest_reg = make_ir_value (IRRegister 3) (IRStruct ("TestStruct", [("field1", IRU32); ("field2", IRU64)])) pos in
  let assign_instr = make_ir_instruction (IRAssign (dest_reg, struct_expr)) pos in
  
  let block = make_ir_basic_block "test_block" [assign_instr] 0 in
  let func = make_ir_function "test_func" [] None [block] pos in
  
  let registers = collect_registers_in_function func in
  
  (* Should collect all three registers *)
  check int "Number of registers collected" 3 (List.length registers);
  check bool "Should contain register 1" true (List.mem_assoc 1 registers);
  check bool "Should contain register 2" true (List.mem_assoc 2 registers);
  check bool "Should contain register 3" true (List.mem_assoc 3 registers)

let test_comprehensive_pattern_coverage () =
  let pos = { line = 1; column = 1; filename = "test.ks" } in
  
  (* Create instructions using all the patterns we fixed *)
  let str_val = make_ir_value (IRLiteral (StringLit "test")) (IRStr 4) pos in
  
  let config_field_update = make_ir_instruction (IRConfigFieldUpdate (str_val, str_val, "field", str_val)) pos in
  let config_access = make_ir_instruction (IRConfigAccess ("config", "field", str_val)) pos in
  let ctx_access = make_ir_instruction (IRContextAccess (str_val, PacketData)) pos in
  let bounds_check = make_ir_instruction (IRBoundsCheck (str_val, 0, 100)) pos in
  let cond_jump = make_ir_instruction (IRCondJump (str_val, "true", "false")) pos in
  let comment = make_ir_instruction (IRComment "test") pos in
  let break_instr = make_ir_instruction IRBreak pos in
  let continue_instr = make_ir_instruction IRContinue pos in
  let throw_instr = make_ir_instruction (IRThrow (IntErrorCode 1)) pos in
  
  let instructions = [config_field_update; config_access; ctx_access; bounds_check; 
                     cond_jump; comment; break_instr; continue_instr; throw_instr] in
  
  (* Test that all instructions can be processed without errors *)
  let all_sizes = List.fold_left (fun acc instr -> 
    acc @ (collect_string_sizes_from_instr instr)
  ) [] instructions in
  
  (* Should have collected sizes from all string-containing instructions *)
  check bool "Should have collected some string sizes" true (List.length all_sizes > 0)

let tests = [
  "test_collect_string_sizes_basic", `Quick, test_collect_string_sizes_basic;
  "test_collect_string_sizes_config_access", `Quick, test_collect_string_sizes_config_access;
  "test_collect_string_sizes_context_access", `Quick, test_collect_string_sizes_context_access;
  "test_collect_string_sizes_bounds_check", `Quick, test_collect_string_sizes_bounds_check;
  "test_collect_string_sizes_cond_jump", `Quick, test_collect_string_sizes_cond_jump;
  "test_collect_string_sizes_bpf_loop", `Quick, test_collect_string_sizes_bpf_loop;
  "test_collect_string_sizes_cond_return", `Quick, test_collect_string_sizes_cond_return;
  "test_collect_string_sizes_try_defer", `Quick, test_collect_string_sizes_try_defer;
  "test_collect_string_sizes_no_op_instructions", `Quick, test_collect_string_sizes_no_op_instructions;
  "test_collect_registers_struct_literal", `Quick, test_collect_registers_struct_literal;
  "test_comprehensive_pattern_coverage", `Quick, test_comprehensive_pattern_coverage;
]

let () = Alcotest.run "Pattern Matching Fixes Tests" [
  "pattern_matching_fixes", tests
] 