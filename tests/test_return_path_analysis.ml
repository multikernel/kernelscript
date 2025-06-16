open OUnit2
open Kernelscript.Ir
open Kernelscript.Ir_analysis

(** Helper functions for creating test IR structures *)

let make_test_position = {
  Kernelscript.Ast.filename = "test.ks";
  line = 1;
  column = 1;
}

let make_simple_ir_value value_desc val_type =
  {
    value_desc;
    val_type;
    stack_offset = None;
    bounds_checked = false;
    val_pos = make_test_position;
  }

let make_simple_instruction instr_desc =
  {
    instr_desc;
    instr_stack_usage = 0;
    bounds_checks = [];
    verifier_hints = [];
    instr_pos = make_test_position;
  }

let make_simple_basic_block label instructions =
  {
    label;
    instructions;
    successors = [];
    predecessors = [];
    stack_usage = 0;
    loop_depth = 0;
    reachable = true;
    block_id = 0;
  }

(** Test function with explicit return in all paths *)
let test_all_paths_return _ =
  let const_42 = make_simple_ir_value (IRLiteral (IntLit 42)) IRU32 in
  let return_instr = make_simple_instruction (IRReturn (Some const_42)) in
  let entry_block = make_simple_basic_block "entry" [return_instr] in
  
  let test_function = {
    func_name = "all_paths_return";
    parameters = [];
    return_type = Some IRU32;
    basic_blocks = [entry_block];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_position;
  } in
  
  let return_info = ReturnAnalysis.analyze_returns test_function in
  assert_bool "Function should have return" return_info.has_return;
  assert_bool "All paths should return" return_info.all_paths_return

(** Test function with missing return in one branch *)
let test_missing_return_branch _ =
  let var_x = make_simple_ir_value (IRVariable "x") IRU32 in
  let const_10 = make_simple_ir_value (IRLiteral (IntLit 10)) IRU32 in
  let const_1 = make_simple_ir_value (IRLiteral (IntLit 1)) IRU32 in
  let condition = make_simple_ir_value (IRVariable "condition") IRBool in
  
  (* Entry block: if (x > 10) goto then_block else goto else_block *)
  let check_gt = make_simple_instruction (IRCall ("greater_than", [var_x; const_10], Some condition)) in
  let branch_instr = make_simple_instruction (IRCondJump (condition, "then_block", "else_block")) in
  let entry_block = { (make_simple_basic_block "entry" [check_gt; branch_instr]) with successors = ["then_block"; "else_block"] } in
  
  (* Then block: no return statement (missing return) *)
  let assign_instr = make_simple_instruction (IRCall ("some_operation", [], None)) in
  let then_block = make_simple_basic_block "then_block" [assign_instr] in
  
  (* Else block: return 1 *)
  let return_instr = make_simple_instruction (IRReturn (Some const_1)) in
  let else_block = make_simple_basic_block "else_block" [return_instr] in
  
  let test_function = {
    func_name = "missing_return_branch";
    parameters = [("x", IRU32)];
    return_type = Some IRU32;
    basic_blocks = [entry_block; then_block; else_block];
    total_stack_usage = 4;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_position;
  } in
  
  let return_info = ReturnAnalysis.analyze_returns test_function in
  assert_bool "Function should have return" return_info.has_return;
  assert_bool "Not all paths should return" (not return_info.all_paths_return)

(** Test function with no return statements *)
let test_no_return _ =
  let assign_instr = make_simple_instruction (IRCall ("some_operation", [], None)) in
  let entry_block = make_simple_basic_block "entry" [assign_instr] in
  
  let test_function = {
    func_name = "no_return";
    parameters = [];
    return_type = Some IRU32;
    basic_blocks = [entry_block];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_position;
  } in
  
  let return_info = ReturnAnalysis.analyze_returns test_function in
  assert_bool "Function should not have return" (not return_info.has_return);
  assert_bool "Not all paths should return" (not return_info.all_paths_return)

(** Test function with multiple exit blocks all returning *)
let test_multiple_exit_blocks_all_return _ =
  let var_x = make_simple_ir_value (IRVariable "x") IRU32 in
  let const_5 = make_simple_ir_value (IRLiteral (IntLit 5)) IRU32 in
  let const_10 = make_simple_ir_value (IRLiteral (IntLit 10)) IRU32 in
  let const_42 = make_simple_ir_value (IRLiteral (IntLit 42)) IRU32 in
  let const_99 = make_simple_ir_value (IRLiteral (IntLit 99)) IRU32 in
  let condition1 = make_simple_ir_value (IRVariable "condition1") IRBool in
  let condition2 = make_simple_ir_value (IRVariable "condition2") IRBool in
  
  (* Entry: if (x < 5) goto path1 else goto check2 *)
  let check_lt = make_simple_instruction (IRCall ("less_than", [var_x; const_5], Some condition1)) in
  let branch1 = make_simple_instruction (IRCondJump (condition1, "path1", "check2")) in
  let entry_block = { (make_simple_basic_block "entry" [check_lt; branch1]) with successors = ["path1"; "check2"] } in
  
  (* Path1: return 42 *)
  let return1 = make_simple_instruction (IRReturn (Some const_42)) in
  let path1_block = make_simple_basic_block "path1" [return1] in
  
  (* Check2: if (x > 10) goto path2 else goto path3 *)
  let check_gt = make_simple_instruction (IRCall ("greater_than", [var_x; const_10], Some condition2)) in
  let branch2 = make_simple_instruction (IRCondJump (condition2, "path2", "path3")) in
  let check2_block = { (make_simple_basic_block "check2" [check_gt; branch2]) with successors = ["path2"; "path3"] } in
  
  (* Path2: return 99 *)
  let return2 = make_simple_instruction (IRReturn (Some const_99)) in
  let path2_block = make_simple_basic_block "path2" [return2] in
  
  (* Path3: return 0 *)
  let const_0 = make_simple_ir_value (IRLiteral (IntLit 0)) IRU32 in
  let return3 = make_simple_instruction (IRReturn (Some const_0)) in
  let path3_block = make_simple_basic_block "path3" [return3] in
  
  let test_function = {
    func_name = "multiple_exit_blocks";
    parameters = [("x", IRU32)];
    return_type = Some IRU32;
    basic_blocks = [entry_block; path1_block; check2_block; path2_block; path3_block];
    total_stack_usage = 4;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_position;
  } in
  
  let return_info = ReturnAnalysis.analyze_returns test_function in
  assert_bool "Function should have return" return_info.has_return;
  assert_bool "All paths should return" return_info.all_paths_return

(** Test suite *)
let suite =
  "Return Path Analysis Tests" >::: [
    "test_all_paths_return" >:: test_all_paths_return;
    "test_missing_return_branch" >:: test_missing_return_branch;
    "test_no_return" >:: test_no_return;
    "test_multiple_exit_blocks_all_return" >:: test_multiple_exit_blocks_all_return;
  ]

let () =
  run_test_tt_main suite 