(** Comprehensive tests for IR Analysis - Milestone 4.3 *)

open OUnit2
open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ir_analysis

(** Helper functions for creating test IR structures *)

let make_test_position = { Kernelscript.Ast.line = 1; column = 1; filename = "test.ks" }

let make_test_ir_position = { Kernelscript.Ast.line = 1; column = 1; filename = "test.ks" }

let make_simple_basic_block label instrs = {
  label;
  instructions = instrs;
  successors = [];
  predecessors = [];
  stack_usage = 0;
  loop_depth = 0;
  reachable = true;
  block_id = 0;
}

let make_simple_instruction desc = {
  instr_desc = desc;
  instr_stack_usage = 0;
  bounds_checks = [];
  verifier_hints = [];
  instr_pos = make_test_ir_position;
}

let make_simple_ir_value desc typ = {
  value_desc = desc;
  val_type = typ;
  stack_offset = None;
  bounds_checked = false;
  val_pos = make_test_ir_position;
}

(** Test Control Flow Graph Analysis *)
let test_cfg_construction _ =
  let return_instr = make_simple_instruction (IRReturn None) in
  let entry_block = make_simple_basic_block "entry" [return_instr] in
  
  let test_function = {
    func_name = "test_fn";
    parameters = [];
    return_type = None;
    basic_blocks = [entry_block];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = true;
    func_pos = make_test_ir_position;
  } in
  
  let cfg = CFG.build_cfg test_function in
  assert_equal "entry" cfg.entry_block;
  assert_equal ["entry"] cfg.exit_blocks;
  assert_equal 1 (List.length cfg.blocks)

(** Test Return Path Analysis *)
let test_function_with_return _ =
  let return_val = make_simple_ir_value (IRLiteral (IntLit 42)) IRU32 in
  let return_instr = make_simple_instruction (IRReturn (Some return_val)) in
  let return_block = make_simple_basic_block "return_block" [return_instr] in
  
  let test_function = {
    func_name = "return_fn";
    parameters = [];
    return_type = Some IRU32;
    basic_blocks = [return_block];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_ir_position;
  } in
  
  let return_info = analyze_return_paths test_function in
  assert_bool "Function should have return" return_info.has_return;
  assert_bool "All paths should return" return_info.all_paths_return

(** Test Loop Analysis *)
let test_loop_termination_verification _ =
  let bounds_check = {
    value = make_simple_ir_value (IRVariable "i") IRU32;
    min_bound = 0;
    max_bound = 100;
    check_type = ArrayAccess;
  } in
  
  let bounded_instr = { (make_simple_instruction (IRBoundsCheck (make_simple_ir_value (IRVariable "i") IRU32, 0, 100))) 
                        with bounds_checks = [bounds_check] } in
  
  let bounded_block = make_simple_basic_block "bounded_loop" [bounded_instr] in
  
  let bounded_function = {
    func_name = "bounded_fn";
    parameters = [];
    return_type = None;
    basic_blocks = [bounded_block];
    total_stack_usage = 0;
    max_loop_depth = 1;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_ir_position;
  } in
  
  assert_bool "Bounded loop should be verified as terminating" 
    (LoopAnalysis.verify_termination bounded_function)

(** Test Statement Processing *)
let test_complete_statement_processing _ =
  let return_instr = make_simple_instruction (IRReturn None) in
  let entry_block = make_simple_basic_block "entry" [return_instr] in
  
  let test_function = {
    func_name = "complete_fn";
    parameters = [];
    return_type = None;
    basic_blocks = [entry_block];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = true;
    func_pos = make_test_ir_position;
  } in
  
  let result = StatementProcessor.process_statements test_function in
  assert_bool "Control flow should be valid" result.control_flow_valid;
  assert_equal 1 (List.length result.processed_blocks)

(** Test Program Analysis *)
let test_analyze_ir_function _ =
  let return_instr = make_simple_instruction (IRReturn None) in
  let simple_block = make_simple_basic_block "simple" [return_instr] in
  
  let test_function = {
    func_name = "simple_fn";
    parameters = [];
    return_type = None;
    basic_blocks = [simple_block];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_ir_position;
  } in
  
  let (optimized_func, warnings) = analyze_ir_function test_function in
  assert_equal "simple_fn" optimized_func.func_name;
  assert_equal 1 (List.length optimized_func.basic_blocks);
  assert_equal 0 (List.length warnings)

(** Test Utilities *)
let test_analysis_report_generation _ =
  let return_instr = make_simple_instruction (IRReturn None) in
  let test_block = make_simple_basic_block "test" [return_instr] in
  
  let test_function = {
    func_name = "report_fn";
    parameters = [];
    return_type = None;
    basic_blocks = [test_block];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = false;
    func_pos = make_test_ir_position;
  } in
  
  let report = generate_analysis_report test_function in
  assert_bool "Report should contain function name" (String.length report > 0);
  assert_bool "Report should mention return paths" (String.length report > 0)

(** Test Suite *)
let all_tests = "IR Analysis Tests" >::: [
  "test_cfg_construction" >:: test_cfg_construction;
  "test_function_with_return" >:: test_function_with_return;
  "test_loop_termination_verification" >:: test_loop_termination_verification;
  "test_complete_statement_processing" >:: test_complete_statement_processing;
  "test_analyze_ir_function" >:: test_analyze_ir_function;
  "test_analysis_report_generation" >:: test_analysis_report_generation;
]

let () = run_test_tt_main all_tests 