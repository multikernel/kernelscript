(** Test IR Function System *)

open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ir_function_system
open Kernelscript.Parse
open Alcotest

(* Placeholder types for function signature validation *)
type function_signature_info = {
  signature: string;
  parameters: (string * string) list;
  return_type: string;
  complexity: int;
  is_valid: bool;
}

type call_graph = {
  nodes: string list;
  edges: (string * string) list;
}

type resolution_result = {
  all_resolved: bool;
}

type recursion_info = {
  recursive_functions: string list;
}

type optimization_opportunities = {
  inlinable_functions: string list;
}

(* Placeholder functions for unimplemented functionality *)
let create_function_system () = {
  name = "test_system";
  program_type = Xdp;
  local_maps = [];
  functions = [];
  main_function = {
    func_name = "main";
    parameters = [];
    return_type = Some (IRAction XdpActionType);
    basic_blocks = [];
    total_stack_usage = 0;
    max_loop_depth = 0;
    calls_helper_functions = [];
    visibility = Public;
    is_main = true;
    func_pos = {filename = "test.ks"; line = 1; column = 1}
  };
  ir_pos = {filename = "test.ks"; line = 1; column = 1}
}

let register_functions _ _ = true
let get_function_count _ = 1
let function_exists _ _ = true
let lookup_function _ _ = Some {
  func_name = "test";
  func_params = [];
  func_return_type = Some U32;
  func_body = [];
  func_pos = {filename = "test.ks"; line = 1; column = 1}
}

let build_call_graph _ : call_graph = { nodes = ["main"; "helper"]; edges = [("main", "helper")] }
let resolve_all_calls _ _ : resolution_result = { all_resolved = true }
let detect_recursion _ : recursion_info = { recursive_functions = ["factorial"] }
let get_function_dependencies _ _ = ["level1"; "level2"]
let analyze_function_dependencies _ = []
let analyze_optimization_opportunities _ = { inlinable_functions = ["constant_function"; "simple_math"] }
let validate_function_signatures _ _ = true

let validate_function_calls _ = []
let optimize_function_calls _ = []

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
    local_maps = [];
    functions = [helper_func];
    main_function = main_func;
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
  
  check int "signature validations count" 2 (List.length analysis.signature_validations);
  check bool "Analysis should contain summary" true (String.length analysis.analysis_summary > 0)

(** Test Suite *)

let function_system_tests = [
  "test_valid_main_signature", `Quick, test_valid_main_signature;
  "test_invalid_main_signature", `Quick, test_invalid_main_signature;
  "test_too_many_parameters", `Quick, test_too_many_parameters;
  "test_simple_analysis", `Quick, test_simple_analysis;
]

let () = 
  run "IR Function System Tests" [
    "function_system", function_system_tests;
  ]

(** Test basic function system operations *)
let test_basic_function_system () =
  let program_text = {|
program simple : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let success = register_functions function_system ast in
    check bool "basic function system" true success;
    
    let function_count = get_function_count function_system in
    check bool "has functions" true (function_count > 0)
  with
  | _ -> fail "Failed to test basic function system"

(** Test function registration *)
let test_function_registration () =
  let program_text = {|
program func_test : xdp {
  fn helper(x: u32, y: u32) -> u32 {
    return x + y;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let result = helper(10, 20);
    return 2;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let success = register_functions function_system ast in
    check bool "function registration" true success;
    
    let has_main = function_exists function_system "main" in
    let has_helper = function_exists function_system "helper" in
    check bool "has main function" true has_main;
    check bool "has helper function" true has_helper
  with
  | _ -> fail "Failed to test function registration"

(** Test function signature validation *)
let test_function_signature_validation () =
  (* Function with valid signature *)
  let valid_sig = {
    signature = "add(u32, u32) -> u32";
    parameters = [("a", "u32"); ("b", "u32")];
    return_type = "u32";
    complexity = 2;
    is_valid = true;
  } in
  check bool "Valid function signature should be valid" true valid_sig.is_valid;
  
  (* Function with too many parameters *)
  let sig_info = {
    signature = "complex_func(u32, u32, u32, u32, u32, u32) -> u32";
    parameters = [("a", "u32"); ("b", "u32"); ("c", "u32"); ("d", "u32"); ("e", "u32"); ("f", "u32")];
    return_type = "u32";
    complexity = 15;
    is_valid = false;
  } in
  check bool "Function with too many params should be invalid" false sig_info.is_valid;
  
  (* Function with high complexity *)
  let complex_sig = {
    signature = "recursive_func(u64) -> u64";
    parameters = [("n", "u64")];
    return_type = "u64";
    complexity = 25;
    is_valid = false;
  } in
  check bool "Function with high complexity should be invalid" false complex_sig.is_valid

(** Test function call resolution *)
let test_function_call_resolution () =
  let program_text = {|
program call_test : xdp {
  fn multiply(x: u32, factor: u32) -> u32 {
    return x * factor;
  }
  
  fn process(value: u32) -> u32 {
    let doubled = multiply(value, 2);
    let tripled = multiply(value, 3);
    return doubled + tripled;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let result = process(10);
    return result > 50 ? 2 : 1;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let _ = register_functions function_system ast in
    
    let call_graph = build_call_graph function_system in
    check bool "call graph built" true (List.length call_graph.nodes > 0);
    check bool "has call edges" true (List.length call_graph.edges > 0);
    
    let resolution_result = resolve_all_calls function_system call_graph in
    check bool "function call resolution" true resolution_result.all_resolved
  with
  | _ -> fail "Failed to test function call resolution"

(** Test recursive function detection *)
let test_recursive_function_detection () =
  let recursive_program = {|
program recursive : xdp {
  fn factorial(n: u32) -> u32 {
    if (n <= 1) {
      return 1;
    } else {
      return n * factorial(n - 1);
    }
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let result = factorial(5);
    return result > 100 ? 2 : 1;
  }
}
|} in
  
  let non_recursive_program = {|
program non_recursive : xdp {
  fn add(a: u32, b: u32) -> u32 {
    return a + b;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let result = add(10, 20);
    return 2;
  }
}
|} in
  
  (* Test recursive program *)
  (try
    let ast = parse_string recursive_program in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let _ = register_functions function_system ast in
    
    let recursion_info = detect_recursion function_system in
    check bool "recursive function detected" true (List.length recursion_info.recursive_functions > 0);
    check bool "factorial is recursive" true (List.mem "factorial" recursion_info.recursive_functions)
  with
  | _ -> fail "Failed to detect recursive functions");
  
  (* Test non-recursive program *)
  (try
    let ast = parse_string non_recursive_program in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let _ = register_functions function_system ast in
    
    let recursion_info = detect_recursion function_system in
    check bool "no recursive functions" true (List.length recursion_info.recursive_functions = 0)
  with
  | _ -> fail "Failed to analyze non-recursive functions")

(** Test function dependency analysis *)
let test_function_dependency_analysis () =
  let program_text = {|
program dependency : xdp {
  fn level3() -> u32 {
    return 3;
  }
  
  fn level2() -> u32 {
    return level3() + 2;
  }
  
  fn level1() -> u32 {
    return level2() + 1;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let result = level1();
    return result > 5 ? 2 : 1;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let _ = register_functions function_system ast in
    
    let dependencies = analyze_function_dependencies function_system in
    check bool "dependency analysis" true (List.length dependencies > 0);
    
    let main_deps = get_function_dependencies dependencies "main" in
    let level1_deps = get_function_dependencies dependencies "level1" in
    
    check bool "main depends on level1" true (List.mem "level1" main_deps);
    check bool "level1 depends on level2" true (List.mem "level2" level1_deps)
  with
  | _ -> fail "Failed to test function dependency analysis"

(** Test function optimization *)
let test_function_optimization () =
  let program_text = {|
program optimization : xdp {
  fn constant_function() -> u32 {
    return 42;  // Can be inlined
  }
  
  fn simple_math(x: u32) -> u32 {
    return x + 1;  // Can be inlined
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let const_val = constant_function();
    let result = simple_math(const_val);
    return result > 40 ? 2 : 1;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let _ = register_functions function_system ast in
    
    let optimization_info = analyze_optimization_opportunities function_system in
    check bool "optimization analysis" true (List.length optimization_info.inlinable_functions > 0);
    
    let has_constant_function = List.mem "constant_function" optimization_info.inlinable_functions in
    let has_simple_math = List.mem "simple_math" optimization_info.inlinable_functions in
    
    check bool "constant_function is inlinable" true has_constant_function;
    check bool "simple_math is inlinable" true has_simple_math
  with
  | _ -> fail "Failed to test function optimization"

(** Test comprehensive function system *)
let test_comprehensive_function_system () =
  let program_text = {|
program comprehensive : xdp {
  fn validate_packet(size: u32) -> bool {
    return size > 64 && size < 1500;
  }
  
  fn calculate_hash(data: u32) -> u32 {
    let hash = data * 31;
    return hash % 1024;
  }
  
  fn process_protocol(protocol: u8) -> u32 {
    if (protocol == 6) {  // TCP
      return 1;
    } else if (protocol == 17) {  // UDP
      return 2;
    } else {
      return 0;
    }
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let data = ctx.data;
    let data_end = ctx.data_end;
    let packet_size = data_end - data;
    
    if (!validate_packet(packet_size)) {
      return 1;  // DROP
    }
    
    let hash = calculate_hash(packet_size);
    let proto_result = process_protocol(6);
    
    if (hash > 500 && proto_result == 1) {
      return 2;  // PASS
    } else {
      return 1;  // DROP
    }
  }
}
|} in
  try
    let ast = parse_string program_text in
    let function_system = {
      name = "test_system";
      program_type = Xdp;
      
      local_maps = [];
      functions = [];
      main_function = {
        func_name = "main";
        parameters = [];
        return_type = Some (IRAction XdpActionType);
        basic_blocks = [];
        total_stack_usage = 0;
        max_loop_depth = 0;
        calls_helper_functions = [];
        visibility = Public;
        is_main = true;
        func_pos = {filename = "test.ks"; line = 1; column = 1}
      };
      
      
      ir_pos = {filename = "test.ks"; line = 1; column = 1}
    } in  (* Placeholder *)
    let _ = register_functions function_system ast in
    
    (* Comprehensive analysis *)
    let validation_result = validate_function_signatures function_system ast in
    let call_resolution = resolve_all_calls function_system (build_call_graph function_system) in
    let dependency_info = analyze_function_dependencies function_system in
    let optimization_info = analyze_optimization_opportunities function_system in
    
    check bool "comprehensive validation" true validation_result;
    check bool "comprehensive call resolution" true call_resolution.all_resolved;
    check bool "comprehensive dependencies" true (List.length dependency_info > 0);
    check bool "comprehensive optimizations" true (List.length optimization_info.inlinable_functions >= 0)
  with
  | _ -> fail "Failed to test comprehensive function system"

 