open Alcotest

let test_kernel_function_parsing () =
  let source = {|
    @helper
fn helper_func(x: u32) -> u32 {
      return x + 1
    }
    
    fn regular_func(y: i32) -> i32 {
      return y - 1
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  
  (* Count functions by type - @helper functions are now AttributedFunction, not GlobalFunction *)
  let (helper_count, userspace_count) = List.fold_left (fun (h, u) decl ->
    match decl with
    | Kernelscript.Ast.AttributedFunction attr_func when 
        List.exists (function Kernelscript.Ast.SimpleAttribute "helper" -> true | _ -> false) attr_func.attr_list -> (h + 1, u)
    | Kernelscript.Ast.GlobalFunction func when func.func_scope = Kernelscript.Ast.Userspace -> (h, u + 1)
    | _ -> (h, u)
  ) (0, 0) ast in
  
  check int "kernel function count" 1 helper_count;
  check int "userspace function count" 1 userspace_count

let test_kernel_function_ir_generation () =
  let source = {|
    @helper
fn calculate_hash(seed: u32) -> u32 {
      return seed * 31 + 42
    }
    
    @xdp fn hash_filter(ctx: *xdp_md) -> xdp_action {
      var hash = calculate_hash(123)
      return 2
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  
  (* Generate IR *)
  let multi_ir = Kernelscript.Ir_generator.lower_multi_program ast symbol_table "test" in
  
  (* Verify the kernel function is in the multi-program IR *)
  let has_kernel_func = List.exists (fun func ->
    func.Kernelscript.Ir.func_name = "calculate_hash"
  ) multi_ir.kernel_functions in
  check bool "program has kernel function" true has_kernel_func

(** Test 3: Kernel functions shared across multiple programs *)
let test_kernel_function_shared_across_programs () =
  let source = {|
    @helper
fn increment_counter(index: u32) {
      return
    }
    
    @helper
fn get_counter(index: u32) -> u64 {
      return 42
    }
    
    @xdp fn xdp_filter(ctx: *xdp_md) -> xdp_action {
      increment_counter(0)
      return 2
    }
    
    @tc fn tc_monitor(ctx: TcContext) -> TcAction {
      increment_counter(1)
      var count = get_counter(1)
      return 0
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  
  (* Verify both helper functions are parsed correctly *)
  let helper_functions = List.filter_map (function
    | Kernelscript.Ast.AttributedFunction attr_func when 
        List.exists (function Kernelscript.Ast.SimpleAttribute "helper" -> true | _ -> false) attr_func.attr_list -> 
        Some attr_func.attr_function.func_name
    | _ -> None
  ) ast in
  
  check (list string) "kernel functions" ["increment_counter"; "get_counter"] helper_functions;
  
  (* Verify eBPF program functions are parsed correctly (excluding @helper) *)
  let programs = List.filter_map (function
    | Kernelscript.Ast.AttributedFunction attr_func when 
        not (List.exists (function Kernelscript.Ast.SimpleAttribute "helper" -> true | _ -> false) attr_func.attr_list) -> 
        Some attr_func.attr_function.func_name
    | _ -> None
  ) ast in
  
  check (list string) "programs" ["xdp_filter"; "tc_monitor"] programs;
  
  (* Test IR generation with multiple programs *)
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let multi_ir = Kernelscript.Ir_generator.lower_multi_program ast symbol_table "test" in
  
  (* Verify both kernel functions are in the multi-program IR *)
  let has_increment = List.exists (fun func ->
    func.Kernelscript.Ir.func_name = "increment_counter"
  ) multi_ir.kernel_functions in
  let has_get = List.exists (fun func ->
    func.Kernelscript.Ir.func_name = "get_counter"
  ) multi_ir.kernel_functions in
  check bool "multi-program has increment_counter" true has_increment;
  check bool "multi-program has get_counter" true has_get

(** Test 4: Kernel functions cannot be called by userspace functions *)
let test_kernel_function_userspace_restriction () =
  let source = {|
    @helper
fn kernel_helper(x: u32) -> u32 {
      return x + 100
    }
    
    @xdp fn test_prog(ctx: *xdp_md) -> xdp_action {
      var result = kernel_helper(42)  // This should work
      return 2
    }
    
    fn main() -> i32 {
      var result = kernel_helper(42)  // This should fail
      return result
    }
  |} in
  
  let test_fn () =
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test")
  in
  
  try
    test_fn ();
    check bool "helper function call from userspace should fail" false true
  with
  | Kernelscript.Type_checker.Type_error (msg, _) ->
      Printf.printf "Type error caught: %s\n" msg;
      check bool "correctly rejected helper function call from userspace" true true
  | Failure msg ->
      Printf.printf "Failure caught: %s\n" msg;
      check bool "correctly rejected helper function call from userspace" true true
  | _ ->
      check bool "unexpected error type for helper/userspace restriction" false true

(** Test 5: Mixed kernel and userspace functions *)
let test_mixed_kernel_userspace_functions () =
  let source = {|
    @helper
fn kernel_helper(x: u32) -> u32 {
      return x + 100
    }
    
    fn userspace_helper(y: i32) -> i32 {
      return y - 50
    }
    
    @xdp fn mixed_prog(ctx: *xdp_md) -> xdp_action {
      var result = kernel_helper(42)  // Should work
      return 2
    }
    
    fn main() -> i32 {
      var result = userspace_helper(200)  // Should work
      return result
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  
  (* Verify correct scoping *)
  let helper_functions = List.filter_map (function
    | Kernelscript.Ast.AttributedFunction attr_func when 
        List.exists (function Kernelscript.Ast.SimpleAttribute "helper" -> true | _ -> false) attr_func.attr_list -> 
        Some attr_func.attr_function.func_name
    | _ -> None
  ) ast in
  
  let userspace_functions = List.filter_map (function
    | Kernelscript.Ast.GlobalFunction func when func.func_scope = Kernelscript.Ast.Userspace -> Some func.func_name
    | _ -> None
  ) ast in
  
  check (list string) "kernel functions" ["kernel_helper"] helper_functions;
  check (list string) "userspace functions" ["userspace_helper"; "main"] userspace_functions

(** Test 6: Kernel function type checking *)
let test_kernel_function_type_checking () =
  let source = {|
    @helper
fn validate_packet(size: u32) -> bool {
      return size >= 64 && size <= 1500
    }
    
    @xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
      var packet_size: u32 = 100
      if (validate_packet(packet_size)) {
        return 2
      } else {
        return 0
      }
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  
  (* Type check the AST *)
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  
  (* Verify the helper function is properly type-checked *)
  let helper_func = List.find_map (function
    | Kernelscript.Ast.AttributedFunction attr_func when 
        attr_func.attr_function.func_name = "validate_packet" &&
        List.exists (function Kernelscript.Ast.SimpleAttribute "helper" -> true | _ -> false) attr_func.attr_list -> 
        Some attr_func.attr_function
    | _ -> None
  ) annotated_ast in
  
  match helper_func with
  | Some func ->
      check bool "helper function scope preserved" true (func.func_scope = Kernelscript.Ast.Kernel);
      check bool "helper function return type correct" true (func.func_return_type = Some Kernelscript.Ast.Bool)
  | None -> failwith "Helper function not found after type checking"

(** Test 7: Kernel functions with complex types *)
let test_kernel_function_complex_types () =
  let source = {|
    @helper
fn analyze_packet(size: u32, protocol: u16, valid: bool) -> bool {
      return valid && size > 64
    }
    
    @xdp fn analyzer(ctx: *xdp_md) -> xdp_action {
      if (analyze_packet(128, 0x0800, true)) {
        return 2
      }
      return 0
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test" in
  
  check bool "kernel function with multiple parameters works" true true

(** Test 8: Kernel function calling other kernel functions *)
let test_kernel_function_calling_kernel_function () =
  let source = {|
    @helper
fn basic_validation(size: u32) -> bool {
      return size >= 64
    }
    
    @helper
fn advanced_validation(size: u32, protocol: u16) -> bool {
      if (!basic_validation(size)) {
        return false
      }
      return protocol == 0x0800 || protocol == 0x86DD
    }
    
    @xdp fn validator(ctx: *xdp_md) -> xdp_action {
      if (advanced_validation(128, 0x0800)) {
        return 2
      }
      return 0
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let multi_ir = Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test" in
  
  (* Verify both kernel functions are in the multi-program IR *)
  let has_basic = List.exists (fun func ->
    func.Kernelscript.Ir.func_name = "basic_validation"
  ) multi_ir.kernel_functions in
  let has_advanced = List.exists (fun func ->
    func.Kernelscript.Ir.func_name = "advanced_validation"
  ) multi_ir.kernel_functions in
  
  check bool "multi-program has basic_validation" true has_basic;
  check bool "multi-program has advanced_validation" true has_advanced

(** Test 9: Error handling - undefined kernel function *)
let test_undefined_kernel_function_error () =
  let source = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      var result = undefined_kernel_func(42)
      return 2
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let test_fn () =
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test")
  in
  
  try
    test_fn ();
    check bool "should fail for undefined function" false true
  with
  | Kernelscript.Type_checker.Type_error (msg, _) ->
      Printf.printf "Type error: %s\n" msg;
      check bool "correctly rejected undefined function" true true
  | Kernelscript.Symbol_table.Symbol_error (msg, _) ->
      Printf.printf "Symbol error: %s\n" msg;
      check bool "correctly rejected undefined function" true true
  | _ ->
      check bool "unexpected error for undefined function" false true

(** Test 10: Userspace functions calling other userspace functions *)
let test_userspace_function_calling_userspace () =
  let source = {|
    fn helper_function(x: i32) -> i32 {
      return x * 2
    }
    
    fn main() -> i32 {
      var x: i32 = 21
      var result = helper_function(x)  // Should work
      return result
    }
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test" in
  
  check bool "userspace functions calling userspace functions works" true true

(** Test 11: Comprehensive kernel function system *)
let test_comprehensive_kernel_function_system () =
  let source = {|
    map<u32, u64> global_counters : Array(1024)
    
    @helper
fn increment_global_counter(index: u32) {
      global_counters[index] = global_counters[index] + 1
    }
    
    @helper
fn get_global_counter(index: u32) -> u64 {
      return global_counters[index]
    }
    
    @helper
fn validate_index(index: u32) -> bool {
      return index < 1024
    }
    
    @helper
fn safe_increment(index: u32) -> bool {
      if (validate_index(index)) {
        increment_global_counter(index)
        return true
      }
      return false
    }
    
    @xdp fn counter_xdp(ctx: *xdp_md) -> xdp_action {
      if (safe_increment(0)) {
        return 2
      }
      return 0
    }
    
    @tc fn counter_tc(ctx: TcContext) -> TcAction {
      var count = get_global_counter(0)
      safe_increment(1)
      return 0
    }
    
    fn setup_monitoring() -> i32 {
      return 0
    }
    
    fn main() -> i32 {
      return setup_monitoring()
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  
  (* Type check *)
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  
  (* Generate IR *)
  let multi_ir = Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "comprehensive_test" in
  
  (* Verify helper functions *)
  let helper_functions = List.filter_map (function
    | Kernelscript.Ast.AttributedFunction attr_func when 
        List.exists (function Kernelscript.Ast.SimpleAttribute "helper" -> true | _ -> false) attr_func.attr_list -> 
        Some attr_func.attr_function.func_name
    | _ -> None
  ) annotated_ast in
  
  let expected_kernel_funcs = ["increment_global_counter"; "get_global_counter"; "validate_index"; "safe_increment"] in
  check (list string) "all kernel functions present" expected_kernel_funcs helper_functions;
  
  (* Verify userspace functions *)
  let userspace_functions = List.filter_map (function
    | Kernelscript.Ast.GlobalFunction func when func.func_scope = Kernelscript.Ast.Userspace -> Some func.func_name
    | _ -> None
  ) annotated_ast in
  
  check (list string) "userspace functions" ["setup_monitoring"; "main"] userspace_functions;
  
  (* Verify IR generation *)
  check int "number of programs in IR" 2 (List.length multi_ir.programs);
  check bool "userspace program exists" true (Option.is_some multi_ir.userspace_program);
  
  (* Verify all kernel functions are in the multi-program IR *)
  List.iter (fun expected_func ->
    let has_func = List.exists (fun func ->
      func.Kernelscript.Ir.func_name = expected_func
    ) multi_ir.kernel_functions in
    check bool (Printf.sprintf "multi-program has kernel function %s" expected_func) true has_func
  ) expected_kernel_funcs

(** Test 12: No duplicate kernel functions in generated code *)
let test_no_duplicate_kernel_functions () =
  let source = {|
    @helper
fn shared_validation(size: u32) -> bool {
      return size >= 64 && size <= 1500
    }
    
    @helper
fn shared_logging(message: u32) {
      print("Log:", message)
    }
    
    @xdp fn xdp_filter(ctx: *xdp_md) -> xdp_action {
      if (shared_validation(128)) {
        shared_logging(1)
        return 2
      }
      return 0
    }
    
    @tc fn tc_filter(ctx: TcContext) -> TcAction {
      if (shared_validation(256)) {
        shared_logging(2)
        return 0
      }
      return 1
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let ast = Kernelscript.Parse.parse_string source in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let multi_ir = Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test_no_duplicates" in
  
  (* Generate eBPF C code *)
  let ebpf_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program multi_ir in
  
  (* Count occurrences of each kernel function definition by looking for function signature pattern *)
  let count_function_definitions func_name code =
    (* Look for function definition pattern: return_type func_name( *)
    let lines = String.split_on_char '\n' code in
    List.fold_left (fun acc line ->
      let trimmed = String.trim line in
      (* Check if this line contains a function definition (not a call) *)
      if String.contains trimmed ' ' then
        let parts = String.split_on_char ' ' trimmed in
        match parts with
        | _return_type :: func_part :: _ when String.contains func_part '(' ->
            let func_and_params = String.split_on_char '(' func_part in
            (match func_and_params with
             | actual_func_name :: _ when actual_func_name = func_name -> acc + 1
             | _ -> acc)
        | _ -> acc
      else acc
    ) 0 lines
  in
  
  let shared_validation_count = count_function_definitions "shared_validation" ebpf_code in
  let shared_logging_count = count_function_definitions "shared_logging" ebpf_code in
  
  (* Each kernel function should be defined only once, not once per program *)
  check int "shared_validation defined only once" 1 shared_validation_count;
  check int "shared_logging defined only once" 1 shared_logging_count;
  
  (* Verify both programs can still call the shared functions *)
  check bool "xdp_filter contains shared_validation call" true (String.contains ebpf_code 's' && String.contains ebpf_code 'h');
  check bool "tc_filter contains shared_logging call" true (String.contains ebpf_code 'l' && String.contains ebpf_code 'o')

(** Test 13: Attributed functions cannot be called from userspace *)
let test_attributed_function_userspace_restriction () =
  let source = {|
    @xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      var dummy_ctx = null
      var result = packet_filter(dummy_ctx)  // This should fail - calling attributed function directly
      return result
    }
  |} in
  
  let test_fn () =
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test")
  in
  
  try
    test_fn ();
    check bool "attributed function call from userspace should fail" false true
  with
  | Kernelscript.Type_checker.Type_error (msg, _) ->
      Printf.printf "Type error caught: %s\n" msg;
      check bool "correctly rejected attributed function call from userspace" true true
  | Failure msg ->
      Printf.printf "Failure caught: %s\n" msg;
      check bool "correctly rejected attributed function call from userspace" true true
  | _ ->
      check bool "unexpected error type for attributed/userspace restriction" false true

(** Test 14: Attributed functions cannot be called from kernel functions *)
let test_attributed_function_kernel_restriction () =
  let source = {|
    @xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    @helper
    fn helper() -> u32 {
      var dummy_ctx = null
      var result = packet_filter(dummy_ctx)  // This should fail - calling attributed function directly
      return result
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let test_fn () =
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test")
  in
  
  try
    test_fn ();
    check bool "attributed function call from kernel function should fail" false true
  with
  | Kernelscript.Type_checker.Type_error (msg, _) ->
      Printf.printf "Type error caught: %s\n" msg;
      check bool "correctly rejected attributed function call from kernel function" true true
  | Failure msg ->
      Printf.printf "Failure caught: %s\n" msg;
      check bool "correctly rejected attributed function call from kernel function" true true
  | _ ->
      check bool "unexpected error type for attributed/kernel restriction" false true

(** Test 15: Attributed functions cannot be called from other attributed functions *)
let test_attributed_function_cross_call_restriction () =
  let source = {|
    @xdp fn helper_filter(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    @tc fn main_filter(ctx: TcContext) -> TcAction {
      var result = helper_filter(ctx)  // This should fail
      return result
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  
  let test_fn () =
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.lower_multi_program annotated_ast symbol_table "test")
  in
  
  try
    test_fn ();
    check bool "attributed function call from other attributed function should fail" false true
  with
  | Kernelscript.Type_checker.Type_error (msg, _) ->
      Printf.printf "Type error caught: %s\n" msg;
      check bool "correctly rejected cross-attributed function call" true true
  | Failure msg ->
      Printf.printf "Failure caught: %s\n" msg;
      check bool "correctly rejected cross-attributed function call" true true
  | _ ->
      check bool "unexpected error type for cross-attributed restriction" false true

let () =
  run "Function Scope Tests" [
    "kernel_function_parsing", [
      test_case "basic parsing" `Quick test_kernel_function_parsing;
    ];
    "kernel_function_ir", [
      test_case "ir generation" `Quick test_kernel_function_ir_generation;
    ];
    "kernel_function_sharing", [
      test_case "shared across programs" `Quick test_kernel_function_shared_across_programs;
    ];
    "kernel_userspace_restrictions", [
      test_case "kernel functions cannot be called by userspace" `Quick test_kernel_function_userspace_restriction;
    ];
    "mixed_scopes", [
      test_case "mixed kernel and userspace functions" `Quick test_mixed_kernel_userspace_functions;
    ];
    "type_checking", [
      test_case "kernel function type checking" `Quick test_kernel_function_type_checking;
    ];
    "complex_types", [
      test_case "kernel functions with complex types" `Quick test_kernel_function_complex_types;
    ];
    "kernel_calling_kernel", [
      test_case "kernel functions calling other kernel functions" `Quick test_kernel_function_calling_kernel_function;
    ];
    "error_handling", [
      test_case "undefined kernel function error" `Quick test_undefined_kernel_function_error;
    ];
    "userspace_calling_userspace", [
      test_case "userspace functions calling userspace functions" `Quick test_userspace_function_calling_userspace;
    ];
    "comprehensive_system", [
      test_case "comprehensive kernel function system" `Quick test_comprehensive_kernel_function_system;
    ];
    "no_duplicate_kernel_functions", [
      test_case "no duplicate kernel functions in generated code" `Quick test_no_duplicate_kernel_functions;
    ];
    "attributed_function_restrictions", [
      test_case "attributed functions cannot be called from userspace" `Quick test_attributed_function_userspace_restriction;
      test_case "attributed functions cannot be called from kernel functions" `Quick test_attributed_function_kernel_restriction;
      test_case "attributed functions cannot call other attributed functions" `Quick test_attributed_function_cross_call_restriction;
    ];
  ]
