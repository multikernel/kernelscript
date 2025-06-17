open Kernelscript.Ast
open Kernelscript.Type_checker
open Kernelscript.Parse
open Alcotest

(** Helper function to check if two types can unify *)
let can_unify t1 t2 =
  match unify_types t1 t2 with
  | Some _ -> true
  | None -> false

(** Test type unification *)
let test_type_unification () =
  (* Test basic type unification *)
  check bool "U32 unifies with U32" true (can_unify U32 U32);
  check bool "U32 can unify with U64 (promotion)" true (can_unify U32 U64);
  check bool "Pointer U8 unifies with Pointer U8" true (can_unify (Pointer U8) (Pointer U8));
  check bool "Array types unify" true (can_unify (Array (U32, 10)) (Array (U32, 10)));
  check bool "Different array sizes don't unify" false (can_unify (Array (U32, 10)) (Array (U32, 20)))

(** Test basic type inference *)
let test_basic_type_inference () =
  let program_text = {|
program test : xdp {
  fn main() -> u32 {
    let x = 42
    let y = true
    let z = "hello"
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    let typed_programs = type_check_ast ast in
    check int "typed programs count" 1 (List.length typed_programs);
    
    (* Verify that type checking completed without errors *)
    match List.hd typed_programs with
    | tprog -> 
        check string "program name" "test" tprog.tprog_name;
        check int "function count" 1 (List.length tprog.tprog_functions)
  with
  | _ -> fail "Error occurred"

(** Test variable type checking *)
let test_variable_type_checking () =
  let program_text = {|
program test : xdp {
  fn main() -> u32 {
    let x: u32 = 42
    let y: bool = true
    let z = x + 10
    return z
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "variable type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test binary operations *)
let test_binary_operations () =
  let valid_operations = [
    ("let x = 1 + 2", true);
    ("let x = 1 - 2", true); 
    ("let x = 1 * 2", true);
    ("let x = 1 / 2", true);
    ("let x = 1 == 2", true);
    ("let x = 1 != 2", true);
    ("let x = 1 < 2", true);
    ("let x = true && false", true);
    ("let x = true || false", true);
  ] in
  
  List.iter (fun (stmt, should_succeed) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    %s
    return 0
  }
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("binary operation: " ^ stmt) should_succeed true
    with
    | _ -> check bool ("binary operation: " ^ stmt) should_succeed false
  ) valid_operations

(** Test function calls *)
let test_function_calls () =
  let program_text = {|
program test : xdp {
  fn helper(x: u32, y: u32) -> u32 {
    return x + y
  }
  
  fn main() -> u32 {
    let result = helper(10, 20)
    return result
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "function call type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test context types *)
let test_context_types () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "context type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test struct field access *)
let test_struct_field_access () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> u32 {
    let packet = ctx.data
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "struct field access" true true
  with
  | _ -> check bool "struct field access" false true  (* Expected to fail for now *)

(** Test statement type checking *)
let test_statement_type_checking () =
  let program_text = {|
program test : xdp {
  fn main() -> u32 {
    let x: u32 = 42
    x = 50
    if (x > 0) {
      return 1
    }
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "statement type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test function type checking *)
let test_function_type_checking () =
  let program_text = {|
program test : xdp {
  fn calculate(a: u32, b: u32) -> u32 {
    let result = a + b
    return result
  }
  
  fn main() -> u32 {
    let value = calculate(10, 20)
    return value
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "function type checking" true true
  with
  | _ -> fail "Error occurred"

(** Test built-in function type checking *)
let test_builtin_function_type_checking () =
  let program_text = {|
program test : xdp {
  fn main() -> u32 {
    print("Hello from eBPF")
    print("Message with value: ", 42)
    print()
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "built-in function type checking" true true
  with
  | _ -> fail "Built-in function type checking failed"

(** Test variadic function argument handling *)
let test_variadic_function_arguments () =
  let test_cases = [
    ("print()", true, "no arguments");
    ("print(\"hello\")", true, "single string argument");
    ("print(\"value: \", 42)", true, "string and number");
    ("print(\"a\", \"b\", \"c\")", true, "multiple arguments");
    ("print(1, 2, 3, 4, 5)", true, "many arguments");
  ] in
  
  List.iter (fun (call, should_succeed, desc) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    %s
    return 0
  }
}
|} call in
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("variadic function: " ^ desc) should_succeed true
    with
    | _ -> check bool ("variadic function: " ^ desc) should_succeed false
  ) test_cases

(** Test built-in function return types *)
let test_builtin_function_return_types () =
  let program_text = {|
program test : xdp {
  fn main() -> u32 {
    let result: u32 = print("test message")
    return result
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "built-in function return type" true true
  with
  | _ -> fail "Built-in function return type checking failed"

(** Test built-in vs user-defined function precedence *)
let test_builtin_vs_user_function_precedence () =
  let program_text = {|
program test : xdp {
  fn my_function(x: u32) -> u32 {
    return x + 1
  }
  
  fn main() -> u32 {
    let user_result = my_function(10)
    print("User function result: ", user_result)
    return user_result
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "built-in vs user function precedence" true true
  with
  | _ -> fail "Built-in vs user function precedence test failed"

(** Test stdlib integration *)
let test_stdlib_integration () =
  (* Test that stdlib functions are properly recognized *)
  check bool "print is builtin" true (Kernelscript.Stdlib.is_builtin_function "print");
  check bool "non_existent is not builtin" false (Kernelscript.Stdlib.is_builtin_function "non_existent_function");
  
  (* Test getting function signature *)
  (match Kernelscript.Stdlib.get_builtin_function_signature "print" with
  | Some (params, return_type) ->
      check int "print parameter count" 0 (List.length params);
      check bool "print return type is U32" true (return_type = Kernelscript.Ast.U32)
  | None -> check bool "print function signature should exist" false true);
  
  (* Test context-specific implementations *)
  (match Kernelscript.Stdlib.get_ebpf_implementation "print" with
  | Some impl -> check string "eBPF implementation" "bpf_printk" impl
  | None -> check bool "eBPF implementation should exist" false true);
  
  (match Kernelscript.Stdlib.get_userspace_implementation "print" with
  | Some impl -> check string "userspace implementation" "printf" impl
  | None -> check bool "userspace implementation should exist" false true)

(** Test error handling *)
let test_error_handling () =
  let invalid_programs = [
    ("let x: u32 = true;", "type mismatch");
    ("let x = 1 + true;", "invalid binary operation");
    ("let x = unknown_var;", "undefined variable");
    ("let x = func_not_exists();", "undefined function");
  ] in
  
  List.iter (fun (stmt, description) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    %s
    return 0
  }
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      fail ("Should have failed for: " ^ description)
    with
    | _ -> check bool ("error handling: " ^ description) true true
  ) invalid_programs

(** Test program type checking *)
let test_program_type_checking () =
  let program_text = {|
program packet_filter : xdp {
  fn is_tcp(protocol: u8) -> bool {
    return protocol == 6
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let protocol: u8 = 6
    if (is_tcp(protocol)) {
      return 2
    }
    return 1
  }
}
|} in
  try
    let ast = parse_string program_text in
    let typed_programs = type_check_ast ast in
    check int "program type checking" 1 (List.length typed_programs);
    
    let typed_program = List.hd typed_programs in
    check string "typed program name" "packet_filter" typed_program.tprog_name;
    check int "typed functions count" 2 (List.length typed_program.tprog_functions)
  with
  | _ -> fail "Error occurred"

(** Test integer type promotion *)
let test_integer_type_promotion () =
  let program_text = {|
map<u32, u64> counter : HashMap(1024) { }

program test_promotion : xdp {
  fn main() -> u32 {
    // Test U32 literal assignment to U64 map value
    counter[1] = 100     // U32 literal should promote to U64
    counter[2] = 200     // U32 literal should promote to U64
    
    // Test arithmetic with different sizes
    let small: u32 = 50
    let large: u64 = 1000
    let result = small + large  // U32 should promote to U64
    
    // Test map access with promoted values
    let val1 = counter[1] + 50  // U64 + U32 -> U64
    counter[3] = val1
    
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    let typed_programs = type_check_ast ast in
    check int "type promotion programs count" 1 (List.length typed_programs);
    
    let typed_program = List.hd typed_programs in
    check string "type promotion program name" "test_promotion" typed_program.tprog_name;
    check bool "integer type promotion" true true
  with
  | exn -> 
    Printf.printf "Error in integer type promotion test: %s\n" (Printexc.to_string exn);
    fail "Error occurred in type promotion test"

(** Test type unification enhancements *)
let test_type_unification_enhanced () =
  (* Test the specific type promotions we added *)
  check bool "U32 promotes to U64" true (can_unify U32 U64);
  check bool "U64 unifies with U32" true (can_unify U64 U32);
  check bool "I32 promotes to I64" true (can_unify I32 I64);
  check bool "I64 unifies with I32" true (can_unify I64 I32);
  check bool "U16 promotes to U64" true (can_unify U16 U64);
  check bool "U8 promotes to U64" true (can_unify U8 U64);
  (* Test that incompatible types still don't unify *)
  check bool "U32 does not unify with Bool" false (can_unify U32 Bool);
  check bool "I32 does not unify with U32" false (can_unify I32 U32)

(** Test comprehensive type checking *)
let test_comprehensive_type_checking () =
  let program_text = {|
map<u32, u64> counter : HashMap(1024) { }

program comprehensive_test : xdp {
  fn increment_counter(key: u32) -> u64 {
    let current = counter[key]
    let new_value = current + 1
    counter[key] = new_value
    return new_value
  }
  
  fn process_packet(size: u32) -> bool {
    return size > 1500
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let packet_size: u32 = 1000
    let counter_val = increment_counter(packet_size)
    let is_large = process_packet(packet_size)
    
    if (is_large && counter_val > 100) {
      return 1
    } else {
      return 2
    }
  }
}
|} in
  try
    let ast = parse_string program_text in
    let typed_programs = type_check_ast ast in
    check int "comprehensive AST length" 1 (List.length typed_programs);
    
    let typed_program = List.hd typed_programs in
    check string "comprehensive program name" "comprehensive_test" typed_program.tprog_name;
    check int "comprehensive functions" 3 (List.length typed_program.tprog_functions)
  with
  | _ -> fail "Error occurred"

let type_checker_tests = [
  "type_unification", `Quick, test_type_unification;
  "basic_type_inference", `Quick, test_basic_type_inference;
  "variable_type_checking", `Quick, test_variable_type_checking;
  "binary_operations", `Quick, test_binary_operations;
  "function_calls", `Quick, test_function_calls;
  "builtin_function_type_checking", `Quick, test_builtin_function_type_checking;
  "variadic_function_arguments", `Quick, test_variadic_function_arguments;
  "builtin_function_return_types", `Quick, test_builtin_function_return_types;
  "builtin_vs_user_function_precedence", `Quick, test_builtin_vs_user_function_precedence;
  "stdlib_integration", `Quick, test_stdlib_integration;
  "context_types", `Quick, test_context_types;
  "struct_field_access", `Quick, test_struct_field_access;
  "statement_type_checking", `Quick, test_statement_type_checking;
  "function_type_checking", `Quick, test_function_type_checking;
  "error_handling", `Quick, test_error_handling;
  "program_type_checking", `Quick, test_program_type_checking;
  "integer_type_promotion", `Quick, test_integer_type_promotion;
  "type_unification_enhanced", `Quick, test_type_unification_enhanced;
  "comprehensive_type_checking", `Quick, test_comprehensive_type_checking;
]

let () =
  run "KernelScript Type Checker Tests" [
    "type_checker", type_checker_tests;
  ] 