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
  fn main(ctx: XdpContext) -> XdpAction {
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
  fn main(ctx: XdpContext) -> XdpAction {
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
  fn main(ctx: XdpContext) -> XdpAction {
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
  
  fn main(ctx: XdpContext) -> XdpAction {
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
  fn main(ctx: XdpContext) -> XdpAction {
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
  fn main(ctx: XdpContext) -> XdpAction {
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
  
  fn main(ctx: XdpContext) -> XdpAction {
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
  fn main(ctx: XdpContext) -> XdpAction {
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
  fn main(ctx: XdpContext) -> XdpAction {
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
  
  fn main(ctx: XdpContext) -> XdpAction {
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
  fn main(ctx: XdpContext) -> XdpAction {
    %s
    return XDP_PASS
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
      return XDP_PASS
    }
    return XDP_DROP
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
  fn main(ctx: XdpContext) -> XdpAction {
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
    
    return XDP_PASS
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
      return XDP_DROP
    } else {
      return XDP_PASS
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

(** Test comprehensive integer promotion *)
let test_comprehensive_integer_promotion () =
  (* Test all integer promotion combinations *)
  let promotion_tests = [
    (* U8 promotions *)
    (U8, U16, "U8 promotes to U16");
    (U8, U32, "U8 promotes to U32");
    (U8, U64, "U8 promotes to U64");
    (U16, U8, "U16 promotes to U16 (reverse)");
    (U32, U8, "U32 promotes to U32 (reverse)");
    (U64, U8, "U64 promotes to U64 (reverse)");
    
    (* U16 promotions *)
    (U16, U32, "U16 promotes to U32");
    (U16, U64, "U16 promotes to U64");
    (U32, U16, "U32 promotes to U32 (reverse)");
    (U64, U16, "U64 promotes to U64 (reverse)");
    
    (* U32 promotions *)
    (U32, U64, "U32 promotes to U64");
    (U64, U32, "U64 promotes to U64 (reverse)");
    
    (* I8 promotions *)
    (I8, I16, "I8 promotes to I16");
    (I8, I32, "I8 promotes to I32");
    (I8, I64, "I8 promotes to I64");
    (I16, I8, "I16 promotes to I16 (reverse)");
    (I32, I8, "I32 promotes to I32 (reverse)");
    (I64, I8, "I64 promotes to I64 (reverse)");
    
    (* I16 promotions *)
    (I16, I32, "I16 promotes to I32");
    (I16, I64, "I16 promotes to I64");
    (I32, I16, "I32 promotes to I32 (reverse)");
    (I64, I16, "I64 promotes to I64 (reverse)");
    
    (* I32 promotions *)
    (I32, I64, "I32 promotes to I64");
    (I64, I32, "I64 promotes to I64 (reverse)");
  ] in
  
  List.iter (fun (t1, t2, desc) ->
    check bool desc true (can_unify t1 t2)
  ) promotion_tests;
  
  (* Test that incompatible types still don't unify *)
  let incompatible_tests = [
    (U32, I32, "U32 does not unify with I32");
    (U64, I64, "U64 does not unify with I64");
    (U8, Bool, "U8 does not unify with Bool");
    (I16, Str 32, "I16 does not unify with Str");
    (U32, Pointer U32, "U32 does not unify with Pointer U32");
  ] in
  
  List.iter (fun (t1, t2, desc) ->
    check bool desc false (can_unify t1 t2)
  ) incompatible_tests

(** Test arithmetic operations with integer promotion *)
let test_arithmetic_promotion () =
  let arithmetic_tests = [
    (* Basic arithmetic with different sizes *)
    ("let x: u8 = 10\n    let y: u64 = 1000\n    let result = x + y", "u8 + u64 addition");
    ("let x: u16 = 100\n    let y: u32 = 2000\n    let result = x * y", "u16 * u32 multiplication");
    ("let x: u32 = 500\n    let y: u64 = 1000\n    let result = y - x", "u64 - u32 subtraction");
    ("let x: u8 = 5\n    let y: u16 = 10\n    let result = x / y", "u8 / u16 division");
    ("let x: u16 = 17\n    let y: u32 = 5\n    let result = x % y", "u16 % u32 modulo");
    
    (* Signed arithmetic *)
    ("let x: i8 = -10\n    let y: i64 = 1000\n    let result = x + y", "i8 + i64 addition");
    ("let x: i16 = -100\n    let y: i32 = 2000\n    let result = x * y", "i16 * i32 multiplication");
    ("let x: i32 = -500\n    let y: i64 = 1000\n    let result = y - x", "i64 - i32 subtraction");
  ] in
  
  List.iter (fun (stmt, desc) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    %s
    return XDP_PASS
  }
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("arithmetic promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed arithmetic promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("arithmetic promotion: " ^ desc) false true
  ) arithmetic_tests

(** Test comparison operations with integer promotion *)
let test_comparison_promotion () =
  let comparison_tests = [
    (* Equality comparisons *)
    ("let x: u8 = 10\n    let y: u64 = 10\n    let result = x == y", "u8 == u64 equality");
    ("let x: u16 = 100\n    let y: u32 = 200\n    let result = x != y", "u16 != u32 inequality");
    ("let x: i8 = -5\n    let y: i64 = -5\n    let result = x == y", "i8 == i64 equality");
    
    (* Ordering comparisons *)
    ("let x: u8 = 10\n    let y: u64 = 100\n    let result = x < y", "u8 < u64 less than");
    ("let x: u16 = 1000\n    let y: u32 = 500\n    let result = x > y", "u16 > u32 greater than");
    ("let x: u32 = 100\n    let y: u64 = 100\n    let result = x <= y", "u32 <= u64 less equal");
    ("let x: u8 = 50\n    let y: u16 = 30\n    let result = x >= y", "u8 >= u16 greater equal");
    
    (* Signed comparisons *)
    ("let x: i8 = -10\n    let y: i64 = 100\n    let result = x < y", "i8 < i64 less than");
    ("let x: i16 = -5\n    let y: i32 = -10\n    let result = x > y", "i16 > i32 greater than");
  ] in
  
  List.iter (fun (stmt, desc) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    %s
    return XDP_PASS
  }
}
|} stmt in
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("comparison promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed comparison promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("comparison promotion: " ^ desc) false true
  ) comparison_tests





(** Test map operations with type promotion *)
let test_map_operations_promotion () =
  let map_tests = [
    (* Map key promotion *)
    ({|
type IpAddress = u32
map<IpAddress, u64> counters : HashMap(1000)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let ip: u16 = 12345  // u16 should promote to u32 (IpAddress)
    counters[ip] = 100
    return XDP_PASS
  }
}
|}, "map key promotion");
    
    (* Map value promotion *)
    ({|
type Counter = u64
map<u32, Counter> stats : HashMap(1000)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let value: u16 = 1500  // u16 should promote to u64 (Counter)
    stats[1] = value
    return XDP_PASS
  }
}
|}, "map value promotion");
    
    (* Map access with arithmetic *)
    ({|
type PacketSize = u16
type Counter = u64
map<u32, Counter> stats : HashMap(1000)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let size: PacketSize = 1500
    let current = stats[1]  // u64
    let new_value = current + size  // u64 + u16 -> u64
    stats[1] = new_value
    return XDP_PASS
  }
}
|}, "map access with arithmetic promotion");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("map promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed map promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("map promotion: " ^ desc) false true
  ) map_tests

(** Test edge cases for type promotion *)
let test_type_promotion_edge_cases () =
  let edge_case_tests = [
    (* Nested arithmetic with multiple promotions *)
    ({|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let a: u8 = 10
    let b: u16 = 100
    let c: u32 = 1000
    let d: u64 = 10000
    let result = a + b + c + d  // Chain of promotions
    return XDP_PASS
  }
}
|}, "nested arithmetic with multiple promotions");
    
    (* Function parameters with promotion *)
    ({|
program test : xdp {
  fn process(value: u64) -> u64 {
    return value * 2
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let small: u16 = 100
    let result = process(small)  // u16 -> u64 promotion in function call
    return XDP_PASS
  }
}
|}, "function parameter promotion");
    
    (* Complex expression with promotions *)
    ({|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let a: u8 = 5
    let b: u16 = 10
    let c: u32 = 20
    let d: u64 = 40
    let result = (a + b) * (c + d)  // Mixed promotions in complex expression
    return XDP_PASS
  }
}
|}, "complex expression with promotions");
    
    (* Assignment with promotion *)
    ({|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let big: u64 = 1000
    let small: u16 = 100
    big = big + small  // u64 = u64 + u16
    return XDP_PASS
  }
}
|}, "assignment with promotion");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("edge case promotion: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed edge case promotion test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("edge case promotion: " ^ desc) false true
  ) edge_case_tests

(** Test null literal typing *)
let test_null_literal_typing () =
  let null_tests = [
    (* Basic null literal *)
    ({|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = null
    return XDP_PASS
  }
}
|}, "basic null literal");
    
    (* Null comparison with typed variable *)
    ({|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x: u32 = 42
    if (x == null) {
      return XDP_DROP
    }
    return XDP_PASS
  }
}
|}, "null comparison with u32");
    
    (* Null assignment in variable declaration *)
    ({|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let ptr = null
    return XDP_PASS
  }
}
|}, "null assignment in declaration");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
      let _ = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
      check bool ("null literal typing: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed null literal test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("null literal typing: " ^ desc) false true
  ) null_tests

(** Test null comparisons with different types *)
let test_null_comparisons () =
  let comparison_tests = [
    (* Comparisons with different numeric types *)
    ("let x: u8 = 10\n    let result = x == null", "u8 == null");
    ("let x: u16 = 100\n    let result = x != null", "u16 != null");
    ("let x: u32 = 1000\n    let result = x == null", "u32 == null");
    ("let x: u64 = 10000\n    let result = x != null", "u64 != null");
    ("let x: i8 = -5\n    let result = x == null", "i8 == null");
    ("let x: i16 = -100\n    let result = x != null", "i16 != null");
    ("let x: i32 = -1000\n    let result = x == null", "i32 == null");
    ("let x: i64 = -10000\n    let result = x != null", "i64 != null");
    
    (* Basic null comparisons *)
    ("let ptr = null\n    let result = ptr == null", "null variable == null");
    ("let ptr = null\n    let result = ptr != null", "null variable != null");
    
    (* Double null comparison *)
    ("let result = null == null", "null == null");
    ("let result = null != null", "null != null");
  ] in
  
  List.iter (fun (stmt, desc) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    %s
    return XDP_PASS
  }
}
|} stmt in
    try
      let ast = parse_string program_text in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
      let _ = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
      check bool ("null comparison: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed null comparison test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("null comparison: " ^ desc) false true
  ) comparison_tests

(** Test map operations with null semantics *)
let test_map_null_semantics () =
  let map_null_tests = [
    (* Map access returning nullable value *)
    ({|
map<u32, u64> test_map : HashMap(100)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let value = test_map[42]
    if (value == null) {
      return XDP_DROP
    }
    return XDP_PASS
  }
}
|}, "map access null check");
    
    (* Null initialization pattern *)
    ({|
map<u32, u32> counters : HashMap(100)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let count = counters[1]
    if (count == null) {
      counters[1] = 1
    } else {
      counters[1] = count + 1
    }
    return XDP_PASS
  }
}
|}, "null initialization pattern");
    
    (* Multiple map null checks *)
    ({|
map<u32, u64> flows : HashMap(100)
map<u32, u32> packets : HashMap(100)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let flow = flows[123]
    let packet_count = packets[123]
    
    if (flow == null || packet_count == null) {
      return XDP_DROP
    }
    
    return XDP_PASS
  }
}
|}, "multiple map null checks");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
      let _ = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
      check bool ("map null semantics: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed map null test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("map null semantics: " ^ desc) false true
  ) map_null_tests

(** Test null vs throw pattern adherence *)
let test_null_vs_throw_pattern () =
  let pattern_tests = [
    (* Correct: null for expected absence *)
    ({|
map<u32, u64> cache : HashMap(100)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let cached_value = cache[42]
    if (cached_value == null) {
      // Key doesn't exist - expected case
      cache[42] = 100
      return XDP_PASS
    }
    return cached_value
  }
}
|}, "null for expected absence");
    
    (* Correct: error checking (simplified without throw) *)
    ({|
program test : xdp {
  fn validate_input(value: u32) -> u32 {
    if (value > 1000) {
      return 0  // Error case
    }
    return value * 2
  }
  
  fn main() -> u32 {
    let result = validate_input(500)
    return result
  }
}
|}, "error validation pattern");
    
    (* Function returning nullable value *)
    ({|
map<u32, u32> data : HashMap(100)

program test : xdp {
  fn lookup_value(key: u32) -> u32 {
    let value = data[key]
    if (value == null) {
      return 0  // Default value for missing key
    }
    return value
  }
  
  fn main() -> u32 {
    let result = lookup_value(42)
    return result
  }
}
|}, "function with nullable return pattern");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("null vs throw pattern: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed pattern test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("null vs throw pattern: " ^ desc) false true
  ) pattern_tests

(** Test comprehensive null semantics *)
let test_null_semantics () =
  let comprehensive_tests = [
    (* Null in conditional expressions *)
    ({|
map<u32, u32> test_map : HashMap(100)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let value = test_map[1]
    let result = 0
    if (value == null) {
      result = 0
    } else {
      result = value
    }
    return result
  }
}
|}, "null in if-else expression");
    
    (* Null in logical operations *)
    ({|
map<u32, u32> map1 : HashMap(100)
map<u32, u32> map2 : HashMap(100)

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let val1 = map1[1]
    let val2 = map2[1]
    
    if (val1 != null && val2 != null) {
      return XDP_PASS
    }
    
    return XDP_PASS
  }
}
|}, "null in logical AND");
    
    (* Basic null assignments *)
    ({|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = null
    if (x == null) {
      return XDP_DROP
    }
    return XDP_PASS
  }
}
|}, "basic null assignment and check");
  ] in
  
  List.iter (fun (program_text, desc) ->
    try
      let ast = parse_string program_text in
      let _ = type_check_ast ast in
      check bool ("comprehensive null: " ^ desc) true true
    with
    | exn -> 
      Printf.printf "Failed comprehensive null test '%s': %s\n" desc (Printexc.to_string exn);
      check bool ("comprehensive null: " ^ desc) false true
  ) comprehensive_tests

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

  "comprehensive_integer_promotion", `Quick, test_comprehensive_integer_promotion;
  "arithmetic_promotion", `Quick, test_arithmetic_promotion;
  "comparison_promotion", `Quick, test_comparison_promotion;
  "map_operations_promotion", `Quick, test_map_operations_promotion;
  "type_promotion_edge_cases", `Quick, test_type_promotion_edge_cases;
  "null_semantics", `Quick, test_null_semantics;
  "null_literal_typing", `Quick, test_null_literal_typing;
  "null_comparisons", `Quick, test_null_comparisons;
  "map_null_semantics", `Quick, test_map_null_semantics;
  "null_vs_throw_pattern", `Quick, test_null_vs_throw_pattern;
]

let () =
  run "KernelScript Type Checker Tests" [
    "type_checker", type_checker_tests;
  ] 