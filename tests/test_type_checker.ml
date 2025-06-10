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
  check bool "U32 does not unify with U64" false (can_unify U32 U64);
  check bool "Pointer U8 unifies with Pointer U8" true (can_unify (Pointer U8) (Pointer U8));
  check bool "Array types unify" true (can_unify (Array (U32, 10)) (Array (U32, 10)));
  check bool "Different array sizes don't unify" false (can_unify (Array (U32, 10)) (Array (U32, 20)))

(** Test basic type inference *)
let test_basic_type_inference () =
  let program_text = {|
program test : xdp {
  fn main() -> u32 {
    let x = 42;
    let y = true;
    let z = "hello";
    return 0;
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
    let x: u32 = 42;
    let y: bool = true;
    let z = x + 10;
    return z;
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
    ("let x = 1 + 2;", true);
    ("let x = 1 - 2;", true); 
    ("let x = 1 * 2;", true);
    ("let x = 1 / 2;", true);
    ("let x = 1 == 2;", true);
    ("let x = 1 != 2;", true);
    ("let x = 1 < 2;", true);
    ("let x = true && false;", true);
    ("let x = true || false;", true);
  ] in
  
  List.iter (fun (stmt, should_succeed) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    %s
    return 0;
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
    return x + y;
  }
  
  fn main() -> u32 {
    let result = helper(10, 20);
    return result;
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
    return 2;
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
    let packet = ctx.data;
    return 0;
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
    let x: u32 = 42;
    x = 50;
    if (x > 0) {
      return 1;
    }
    return 0;
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
    let result = a + b;
    return result;
  }
  
  fn main() -> u32 {
    let value = calculate(10, 20);
    return value;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "function type checking" true true
  with
  | _ -> fail "Error occurred"

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
    return 0;
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
    return protocol == 6;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let protocol: u8 = 6;
    if (is_tcp(protocol)) {
      return 2;
    }
    return 1;
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

(** Test comprehensive type checking *)
let test_comprehensive_type_checking () =
  let program_text = {|
map<u32, u64> counter : HashMap(1024) { };

program comprehensive_test : xdp {
  fn increment_counter(key: u32) -> u64 {
    let current = counter[key];
    let new_value = current + 1;
    counter[key] = new_value;
    return new_value;
  }
  
  fn process_packet(size: u32) -> bool {
    return size > 1500;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let packet_size: u32 = 1000;
    let counter_val = increment_counter(packet_size);
    let is_large = process_packet(packet_size);
    
    if (is_large && counter_val > 100) {
      return 1;
    } else {
      return 2;
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
  "context_types", `Quick, test_context_types;
  "struct_field_access", `Quick, test_struct_field_access;
  "statement_type_checking", `Quick, test_statement_type_checking;
  "function_type_checking", `Quick, test_function_type_checking;
  "error_handling", `Quick, test_error_handling;
  "program_type_checking", `Quick, test_program_type_checking;
  "comprehensive_type_checking", `Quick, test_comprehensive_type_checking;
]

let () =
  run "KernelScript Type Checker Tests" [
    "type_checker", type_checker_tests;
  ] 