open Alcotest
open Kernelscript.Parse

(** Helper function to check if generated code contains a pattern *)
let contains_pattern code pattern =
  try
    let regex = Str.regexp pattern in
    ignore (Str.search_forward regex code 0);
    true
  with Not_found -> false

(** Helper function to generate userspace code from a program with proper IR generation *)
let generate_userspace_code_from_program program_text filename =
  let ast = parse_string program_text in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table filename in
  
  let temp_dir = Filename.temp_file "test_userspace_for" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
    ir ~output_dir:temp_dir filename in
  let generated_file = Filename.concat temp_dir (filename ^ ".c") in
  
  if Sys.file_exists generated_file then (
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
    content
  ) else (
    failwith "Failed to generate userspace code file"
  )

(** Test 1: Basic for loop with constant bounds generates ordinary C for loop *)
let test_basic_for_loop_constant_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn test_func() -> u32 {
  for i in 0..10 {
    let x = 42
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_basic_for" in
    
    (* Should generate ordinary C for loop, not unrolled or goto-based *)
    check bool "generates for keyword" true (contains_pattern result "for.*(");
    check bool "uses loop variable initialization" true (contains_pattern result "= 0");
    check bool "has loop condition" true (contains_pattern result "<= 10");
    check bool "has increment" true (contains_pattern result "\\+\\+");
    check bool "has curly braces" true (contains_pattern result "{");
    
    (* Should NOT contain unrolling patterns *)
    check bool "no manual unrolling" false (contains_pattern result "x_0.*x_1.*x_2");
    check bool "no eBPF loop_start labels" false (contains_pattern result "loop_start:");
    (* Note: goto statements are expected for cleanup and return value propagation *)
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 2: For loop with variable bounds generates ordinary C for loop *)
let test_for_loop_variable_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn main() -> i32 {
  let start = 1
  let end_val = 5
  for i in start..end_val {
    let temp = i * 2
  }
  return 0
}
|} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test_for_variable" in
    
    let temp_dir = Filename.temp_file "test_userspace_for" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
      ir ~output_dir:temp_dir "test_for_variable.ks" in
    let generated_file = Filename.concat temp_dir "test_for_variable.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      (* Verify ordinary C for loop generation *)
      check bool "generates C for loop" true (contains_pattern content "for.*(");
      check bool "no bounds checking macros" false (contains_pattern content "BPF_LOOP_BOUND_CHECK");
      check bool "no verifier annotations" false (contains_pattern content "__bounded");
      check bool "no eBPF goto-based loop implementation" false (contains_pattern content "goto.*loop_start");
      
      (* Should use variables in bounds (converted to registers by IR) *)
      check bool "uses variable bounds" true (contains_pattern content "var_.*var_");
    ) else (
      fail "Failed to generate userspace code file"
    );
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 3: For loop with complex expressions generates ordinary C *)
let test_for_loop_complex_expressions () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn test_func() -> u32 {
  for i in 0..10 {
    let doubled = i * 2
    let squared = i * i
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_complex_for" in
    
    (* Should handle complex expressions inside loop without transformation *)
    check bool "generates for loop" true (contains_pattern result "for.*(");
    check bool "includes doubled variable" true (contains_pattern result "var_.*=.*var_.*\\*.*2");
    check bool "includes squared variable" true (contains_pattern result "var_.*=.*var_.*\\*.*var_");
    check bool "has multiplication" true (contains_pattern result "\\*");
    
    (* Should not apply eBPF-specific transformations *)
    check bool "no verifier hints" false (contains_pattern result "__always_inline");
    check bool "no stack depth limits" false (contains_pattern result "BPF_STACK_LIMIT");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 4: For loop with single iteration still generates C for loop *)
let test_for_loop_single_iteration () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn test_func() -> u32 {
  for k in 5..5 {
    let single = 99
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_single_for" in
    
    (* Even single iteration should generate for loop, not be optimized away *)
    check bool "single iteration uses for loop" true (contains_pattern result "for.*(");
    check bool "condition is var <= 5" true (contains_pattern result "<= 5");
    check bool "not optimized to direct assignment" false (contains_pattern result "single.*=.*99.*//.*optimized");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 5: Large bounds should not trigger special handling *)
let test_for_loop_large_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn test_func() -> u32 {
  for big in 0..1000000 {
    let large = 1
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_large_for" in
    
    (* Large bounds should not trigger unrolling limits or special handling *)
    check bool "large bounds use ordinary for" true (contains_pattern result "for.*(");
    check bool "no unrolling limit warnings" false (contains_pattern result "UNROLL_LIMIT_EXCEEDED");
    check bool "no bounds reduction" false (contains_pattern result "Reduced bounds");
    check bool "preserves original bounds" true (contains_pattern result "1000000");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 6: Zero-iteration loop (start > end) generates valid C *)
let test_for_loop_zero_iterations () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn test_func() -> u32 {
  for empty in 10..5 {
    let never = 0
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_zero_for" in
    
    (* Should generate syntactically correct C even for impossible loops *)
    check bool "zero iteration generates for loop" true (contains_pattern result "for.*(");
    check bool "condition respects bounds" true (contains_pattern result "<= 5");
    check bool "no special case handling" false (contains_pattern result "Zero iterations");
    check bool "no context-specific handling" false (contains_pattern result "Main function");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 7: For loop in non-main function context *)
let test_for_loop_in_helper_function () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn helper() -> u32 {
  for i in 1..3 {
    let helper_var = i + 10
  }
  return 42
}

fn main() -> i32 {
  let result = helper()
  return 0
}
|} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test_helper" in
    
    let temp_dir = Filename.temp_file "test_userspace_helper" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
      ir ~output_dir:temp_dir "test_helper.ks" in
    let generated_file = Filename.concat temp_dir "test_helper.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      (* Should handle for loops in helper functions the same way *)
      check bool "helper function has for loop" true (contains_pattern content "for.*(");
      check bool "no context-specific handling" false (contains_pattern content "Main function");
      check bool "uses return statement" true (contains_pattern content "return 42");
      check bool "coordinator program structure" true (contains_pattern content "main");
    ) else (
      fail "Failed to generate userspace code file"
    );
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 8: Comparison with eBPF codegen - global functions should be different *)
let test_global_functions_vs_ebpf_for_loop_differences () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn test_func() -> u32 {
  for i in 0..100 {
    let test = 1
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_vs_ebpf" in
    
    (* Global functions should NOT have eBPF-specific patterns *)
    check bool "no BPF loop pragmas" false (contains_pattern result "#pragma unroll");
    check bool "no verifier annotations" false (contains_pattern result "__bounded");
    check bool "no BPF helper calls" false (contains_pattern result "bpf_for_each");
    check bool "no instruction counting" false (contains_pattern result "INSTRUCTION_COUNT");
    
    (* Should be plain C *)
    check bool "plain C for loop" true (contains_pattern result "for.*(");
    check bool "standard C increment" true (contains_pattern result "++");
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** All global function for statement codegen tests *)
let global_function_for_codegen_tests = [
  "basic_for_loop_constant_bounds", `Quick, test_basic_for_loop_constant_bounds;
  "for_loop_variable_bounds", `Quick, test_for_loop_variable_bounds;
  "for_loop_complex_expressions", `Quick, test_for_loop_complex_expressions;
  "for_loop_single_iteration", `Quick, test_for_loop_single_iteration;
  "for_loop_large_bounds", `Quick, test_for_loop_large_bounds;
  "for_loop_zero_iterations", `Quick, test_for_loop_zero_iterations;
  "for_loop_in_helper_function", `Quick, test_for_loop_in_helper_function;
  "global_functions_vs_ebpf_differences", `Quick, test_global_functions_vs_ebpf_for_loop_differences;
]

let () =
  run "KernelScript Global Function For Statement Codegen Tests" [
    "global_function_for_codegen", global_function_for_codegen_tests;
]
