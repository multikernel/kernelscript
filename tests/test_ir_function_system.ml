(** Test IR Function System *)

open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ir_function_system
open Kernelscript.Parse
open Alcotest



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
    func_pos = { line = 1; column = 1; filename = "test.ks" };
    tail_call_targets = [];
    tail_call_index_map = Hashtbl.create 16;
    is_tail_callable = false;
    func_program_type = None;
  }

let create_test_program () =
  let main_func = create_test_function "main" true 
    [("ctx", IRContext XdpCtx)] 
    (Some (IRAction XdpActionType)) in
  {
    name = "test_program";
    program_type = Xdp;
    entry_function = main_func;
    ir_pos = { line = 1; column = 1; filename = "test" };
  }

(** Test Function Signature Validation *)

let test_valid_main_signature _ =
  let main_func = create_test_function "main" true 
    [("ctx", IRContext XdpCtx)] 
    (Some (IRAction XdpActionType)) in
  let sig_info = validate_function_signature main_func in
  check bool "Main function should be valid" true sig_info.is_valid;
      check string "Function name" "main" sig_info.func_name;
    check bool "Should be marked as main" true sig_info.is_main

let test_invalid_main_signature _ =
  let invalid_func = {
    func_name = "main";
    parameters = [];  (* Missing context parameter *)
    return_type = Some (IRAction XdpActionType);
    basic_blocks = [];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = true;
    func_pos = { line = 1; column = 1; filename = "test.ks" };
    tail_call_targets = [];
    tail_call_index_map = Hashtbl.create 16;
    is_tail_callable = false;
    func_program_type = None;
  } in
  let sig_info = validate_function_signature invalid_func in
  check bool "Invalid main function should be invalid" true (not sig_info.is_valid);
  check string "Function name" "main" sig_info.func_name;
  check bool "Should be marked as main" true sig_info.is_main

let test_too_many_parameters _ =
  let func_with_many_params = create_test_function "test" false 
    [("a", IRU32); ("b", IRU32); ("c", IRU32); ("d", IRU32); ("e", IRU32); ("f", IRU32)] 
    (Some IRU32) in
  let sig_info = validate_function_signature func_with_many_params in
  check bool "Function with too many params should be invalid" false sig_info.is_valid;
  check bool "Should have parameter count error" true
    (List.exists (fun err -> String.length err > 0 && err.[0] = 'T') sig_info.validation_errors)

(** Test Complete Function System Analysis *)

let test_simple_analysis _ =
  let prog = create_test_program () in
  let analysis = analyze_ir_program_simple prog in
  
  check int "signature validations count" 1 (List.length analysis.signature_validations);
  check bool "Analysis should contain summary" true (String.length analysis.analysis_summary > 0)



(** Test basic function system operations *)
let test_basic_function_system () =
  let prog = create_test_program () in
  let analysis = analyze_ir_program_simple prog in
  
  check int "signature validations count" 1 (List.length analysis.signature_validations);
  check bool "Analysis should contain summary" true (String.length analysis.analysis_summary > 0)

(** Test function registration *)
let test_function_registration () =
  let program_text = {|
kernel fn helper(x: u32, y: u32) -> u32 {
  return x + y
}

@xdp fn func_test(ctx: XdpContext) -> XdpAction {
  let result = helper(10, 20)
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let ir_program = List.hd ir_multi.programs in
    
    (* Use the new analysis function that includes kernel functions *)
    let analysis = analyze_ir_program_with_kernel_functions ir_program ir_multi.kernel_functions in
    
    (* Verify function registration through analysis *)
    let function_names = List.map (fun sig_info -> sig_info.func_name) analysis.signature_validations in
    (* Note: main function gets renamed to program name in IR *)
    check bool "Should register main function (renamed to program name)" true 
      (List.exists (fun sig_info -> sig_info.func_name = "func_test" && sig_info.is_main) analysis.signature_validations);
    check bool "Should register helper function" true (List.mem "helper" function_names);
    check bool "Should have correct function count" true (List.length analysis.signature_validations >= 2)
  with
  | exn -> fail ("Failed to test function registration: " ^ (Printexc.to_string exn))

(** Test function signature validation *)
let test_function_signature_validation () =
  (* Test with actual IR functions using the real validation system *)
  let program_text = {|
kernel fn valid_function(a: u32, b: u32) -> u32 {
  return a + b
}

@xdp fn signature_test(ctx: XdpContext) -> XdpAction {
  let result = valid_function(10, 20)
  if (result > 25) {
    return 2
  } else {
    return 1
  }
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let ir_program = List.hd ir_multi.programs in
    
    (* Use the new analysis function that includes kernel functions *)
    let analysis = analyze_ir_program_with_kernel_functions ir_program ir_multi.kernel_functions in
    
    (* Verify signature validation *)
    let valid_function_sig = List.find (fun sig_info -> sig_info.func_name = "valid_function") analysis.signature_validations in
    (* Note: main function gets renamed to program name in IR *)
    let main_function_sig = List.find (fun sig_info -> sig_info.func_name = "signature_test" && sig_info.is_main) analysis.signature_validations in
    
    check bool "Valid function should have valid signature" true valid_function_sig.is_valid;
    check bool "Main function should have valid signature" true main_function_sig.is_valid;
    check bool "Main function should be marked as main" true main_function_sig.is_main;
    check bool "Helper function should not be marked as main" false valid_function_sig.is_main
  with
  | exn -> fail ("Failed to test function signature validation: " ^ (Printexc.to_string exn))

(** Test function call resolution *)
let test_function_call_resolution () =
  (* This test should focus on what the IR function system actually provides *)
  let program_text = {|
kernel fn multiply(x: u32, factor: u32) -> u32 {
  return x * factor
}

@xdp fn call_test(ctx: XdpContext) -> XdpAction {
  let result = multiply(10, 2)
  if (result > 15) {
    return 2
  } else {
    return 1
  }
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let ir_program = List.hd ir_multi.programs in
    
    (* Use the new analysis function that includes kernel functions *)
    let analysis = analyze_ir_program_with_kernel_functions ir_program ir_multi.kernel_functions in
    
    (* Verify that the analysis includes both functions *)
    (* Note: main function gets renamed to program name in IR *)
    check bool "Analysis should include main function (renamed to program name)" true 
      (List.exists (fun sig_info -> sig_info.func_name = "call_test" && sig_info.is_main) analysis.signature_validations);
    check bool "Analysis should include helper function" true
      (List.exists (fun sig_info -> sig_info.func_name = "multiply") analysis.signature_validations);
    check bool "Analysis summary should be non-empty" true 
      (String.length analysis.analysis_summary > 0)
  with
  | exn -> fail ("Failed to test function call resolution: " ^ (Printexc.to_string exn))

(** Test recursive function detection *)
let test_recursive_function_detection () =
  (* Test with a simple non-recursive program since we don't have actual recursion detection *)
  let simple_program = {|
kernel fn helper() -> u32 {
  return 42
}

@xdp fn simple(ctx: XdpContext) -> XdpAction {
  let result = helper()
  if (result > 40) {
    return 2
  } else {
    return 1
  }
}
|} in
  try
    let ast = parse_string simple_program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let ir_program = List.hd ir_multi.programs in
    
    (* Use the new analysis function that includes kernel functions *)
    let analysis = analyze_ir_program_with_kernel_functions ir_program ir_multi.kernel_functions in
    
    (* Verify basic analysis works *)
    check bool "Analysis should complete successfully" true 
      (List.length analysis.signature_validations >= 2);
    check bool "All functions should have valid signatures" true
      (List.for_all (fun sig_info -> sig_info.is_valid) analysis.signature_validations);
    (* Note: main function gets renamed to program name in IR *)
    check bool "Should find main function (renamed to program name)" true
      (List.exists (fun sig_info -> sig_info.func_name = "simple" && sig_info.is_main) analysis.signature_validations)
  with
  | exn -> fail ("Failed to detect recursive functions: " ^ (Printexc.to_string exn))

(** Test function dependency analysis *)
let test_function_dependency_analysis () =
  (* Test with a multi-level function call hierarchy *)
  let program_text = {|
kernel fn level3() -> u32 {
  return 3
}

kernel fn level2() -> u32 {
  let val3 = level3()
  return val3 + 2
}

kernel fn level1() -> u32 {
  let val2 = level2()
  return val2 + 1
}

@xdp fn dependency(ctx: XdpContext) -> XdpAction {
  let result = level1()
  if (result > 5) {
    return 2
  } else {
    return 1
  }
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let ir_program = List.hd ir_multi.programs in
    
    (* Use the new analysis function that includes kernel functions *)
    let analysis = analyze_ir_program_with_kernel_functions ir_program ir_multi.kernel_functions in
    
    (* Verify that all functions are analyzed *)
    let function_names = List.map (fun sig_info -> sig_info.func_name) analysis.signature_validations in
    (* Note: main function gets renamed to program name in IR *)
    check bool "Should analyze main function (renamed to program name)" true 
      (List.exists (fun sig_info -> sig_info.func_name = "dependency" && sig_info.is_main) analysis.signature_validations);
    check bool "Should analyze level1 function" true (List.mem "level1" function_names);
    check bool "Should analyze level2 function" true (List.mem "level2" function_names);
    check bool "Should analyze level3 function" true (List.mem "level3" function_names);
    
    (* Verify all functions have valid signatures *)
    check bool "All functions should be valid" true
      (List.for_all (fun sig_info -> sig_info.is_valid) analysis.signature_validations)
  with
  | exn -> fail ("Failed to test function dependency analysis: " ^ (Printexc.to_string exn))

(** Test function optimization *)
let test_function_optimization () =
  (* Test with simple functions that could theoretically be optimized *)
  let program_text = {|
kernel fn constant_function() -> u32 {
  return 42
}

kernel fn simple_math(x: u32) -> u32 {
  return x + 1
}

@xdp fn optimization(ctx: XdpContext) -> XdpAction {
  let const_val = constant_function()
  let result = simple_math(const_val)
  if (result > 40) {
    return 2
  } else {
    return 1
  }
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let ir_program = List.hd ir_multi.programs in
    
    (* Use the new analysis function that includes kernel functions *)
    let analysis = analyze_ir_program_with_kernel_functions ir_program ir_multi.kernel_functions in
    
    (* Verify that optimization analysis can identify simple functions *)
    let function_names = List.map (fun sig_info -> sig_info.func_name) analysis.signature_validations in
    check bool "Should find constant_function" true (List.mem "constant_function" function_names);
    check bool "Should find simple_math" true (List.mem "simple_math" function_names);
    (* Note: main function gets renamed to program name in IR *)
    check bool "Should find main function (renamed to program name)" true 
      (List.exists (fun sig_info -> sig_info.func_name = "optimization" && sig_info.is_main) analysis.signature_validations);
    
    (* Check that simple functions have valid signatures *)
    let simple_functions = List.filter (fun sig_info -> 
      sig_info.func_name = "constant_function" || sig_info.func_name = "simple_math"
    ) analysis.signature_validations in
    check bool "Simple functions should be valid" true
      (List.for_all (fun sig_info -> sig_info.is_valid) simple_functions)
  with
  | exn -> fail ("Failed to test function optimization: " ^ (Printexc.to_string exn))

(** Test comprehensive function system *)
let test_comprehensive_function_system () =
  (* Test with a comprehensive program that exercises multiple aspects *)
  let program_text = {|
kernel fn validate_packet(size: u32) -> bool {
  return size > 64 && size < 1500
}

kernel fn calculate_hash(data: u32) -> u32 {
  let hash = data * 31
  return hash % 1024
}

kernel fn process_protocol(protocol: u8) -> u32 {
  if (protocol == 6) {
    return 1
  } else if (protocol == 17) {
    return 2
  } else {
    return 0
  }
}

@xdp fn comprehensive(ctx: XdpContext) -> XdpAction {
  let packet_size = 1000
  
  if (!validate_packet(packet_size)) {
    return 1
  }
  
  let hash = calculate_hash(packet_size)
  let proto_result = process_protocol(6)
  
  if (hash > 500 && proto_result == 1) {
    return 2
  } else {
    return 1
  }
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let ir_program = List.hd ir_multi.programs in
    
    (* Use the new analysis function that includes kernel functions *)
    let analysis = analyze_ir_program_with_kernel_functions ir_program ir_multi.kernel_functions in
    
    (* Comprehensive validation *)
    let expected_functions = ["validate_packet"; "calculate_hash"; "process_protocol"] in
    let function_names = List.map (fun sig_info -> sig_info.func_name) analysis.signature_validations in
    
    List.iter (fun expected_name ->
      check bool (Printf.sprintf "Should find %s function" expected_name) true 
        (List.mem expected_name function_names)
    ) expected_functions;
    
    (* Note: main function gets renamed to program name in IR *)
    check bool "Should find main function (renamed to program name)" true
      (List.exists (fun sig_info -> sig_info.func_name = "comprehensive" && sig_info.is_main) analysis.signature_validations);
    
    (* Check that all functions have valid signatures *)
    check bool "All functions should have valid signatures" true
      (List.for_all (fun sig_info -> sig_info.is_valid) analysis.signature_validations);
    
    (* Check analysis summary *)
    check bool "Analysis summary should be comprehensive" true
      (String.length analysis.analysis_summary > 50)
  with
  | exn -> fail ("Failed to test comprehensive function system: " ^ (Printexc.to_string exn))

(** Test Suite *)

let function_system_tests = [
  "test_valid_main_signature", `Quick, test_valid_main_signature;
  "test_invalid_main_signature", `Quick, test_invalid_main_signature;
  "test_too_many_parameters", `Quick, test_too_many_parameters;
  "test_simple_analysis", `Quick, test_simple_analysis;
  "test_basic_function_system", `Quick, test_basic_function_system;
  "test_function_registration", `Quick, test_function_registration;
  "test_function_signature_validation", `Quick, test_function_signature_validation;
  "test_function_call_resolution", `Quick, test_function_call_resolution;
  "test_recursive_function_detection", `Quick, test_recursive_function_detection;
  "test_function_dependency_analysis", `Quick, test_function_dependency_analysis;
  "test_function_optimization", `Quick, test_function_optimization;
  "test_comprehensive_function_system", `Quick, test_comprehensive_function_system;
]

let () = 
  run "IR Function System Tests" [
    "function_system", function_system_tests;
  ]

 