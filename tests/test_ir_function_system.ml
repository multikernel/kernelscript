(** Test IR Function System *)

open OUnit2
open Kernelscript.Ir
open Kernelscript.Ir_function_system

(** Test data *)

let create_test_function name is_main params ret_type =
  {
    func_name = name;
    parameters = params;
    return_type = ret_type;
    basic_blocks = [
      {
        label = "entry";
        instructions = [
          {
            instr_desc = IRReturn None;
            instr_stack_usage = 0;
            bounds_checks = [];
            verifier_hints = [];
            instr_pos = { line = 1; column = 1; filename = "test" };
          }
        ];
        successors = [];
        predecessors = [];
        stack_usage = 0;
        loop_depth = 0;
        reachable = true;
        block_id = 0;
      }
    ];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main;
    func_pos = { line = 1; column = 1; filename = "test" };
  }

let create_test_program () =
  let main_func = create_test_function "main" true 
    [("ctx", IRContext XdpCtx)] 
    (Some (IRAction XdpActionType)) in
  let helper_func = create_test_function "helper" false 
    [("x", IRU32)] 
    (Some IRU32) in
  {
    name = "test_program";
    program_type = Xdp;
    global_maps = [];
    local_maps = [];
    functions = [helper_func];
    main_function = main_func;
    userspace_bindings = [];
    userspace_block = None;
    ir_pos = { line = 1; column = 1; filename = "test" };
  }

(** Test Function Signature Validation *)

let test_valid_main_signature _ =
  let main_func = create_test_function "main" true 
    [("ctx", IRContext XdpCtx)] 
    (Some (IRAction XdpActionType)) in
  let sig_info = validate_function_signature main_func in
  assert_bool "Main function should be valid" sig_info.is_valid;
  assert_equal "main" sig_info.func_name;
  assert_bool "Should be marked as main" sig_info.is_main

let test_invalid_main_signature _ =
  let invalid_main = create_test_function "main" true 
    [("x", IRU32); ("y", IRU32)] 
    (Some IRU32) in
  let sig_info = validate_function_signature invalid_main in
  assert_bool "Invalid main function should be invalid" (not sig_info.is_valid);
  assert_bool "Should have validation errors" (List.length sig_info.validation_errors > 0)

let test_too_many_parameters _ =
  let func_with_many_params = create_test_function "test" false 
    [("a", IRU32); ("b", IRU32); ("c", IRU32); ("d", IRU32); ("e", IRU32); ("f", IRU32)] 
    (Some IRU32) in
  let sig_info = validate_function_signature func_with_many_params in
  assert_bool "Function with too many params should be invalid" (not sig_info.is_valid);
  assert_bool "Should have parameter count error" 
    (List.exists (fun err -> String.length err > 0 && err.[0] = 'T') sig_info.validation_errors)

(** Test Complete Function System Analysis *)

let test_simple_analysis _ =
  let prog = create_test_program () in
  let analysis = analyze_ir_program_simple prog in
  
  assert_equal 2 (List.length analysis.signature_validations);
  assert_bool "Analysis should contain summary" (String.length analysis.analysis_summary > 0)

(** Test Suite *)

let function_system_tests = "IR Function System Tests" >::: [
  "test_valid_main_signature" >:: test_valid_main_signature;
  "test_invalid_main_signature" >:: test_invalid_main_signature;
  "test_too_many_parameters" >:: test_too_many_parameters;
  "test_simple_analysis" >:: test_simple_analysis;
]

let () = run_test_tt_main function_system_tests 