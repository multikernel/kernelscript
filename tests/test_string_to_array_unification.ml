open Kernelscript.Ast
open Kernelscript.Type_checker
open Kernelscript.Parse
open Alcotest

(** Helper function to create test symbol table *)
let create_test_symbol_table ast =
  Test_utils.Helpers.create_test_symbol_table ast

(** Test basic string to u8 array assignment *)
let test_string_to_u8_array_basic () =
  let program_text = {|
struct TestStruct {
    name: u8[16],
    id: u32,
}

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
    var obj = TestStruct {
        name: "test_name",  // String literal to u8[16] array
        id: 42,
    }
    return XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (_typed_ast, _typed_programs) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "String to u8 array basic assignment" true true
  with
  | exn -> fail ("String to u8 array basic test failed: " ^ Printexc.to_string exn)

(** Test string too long for array should fail *)
let test_string_too_long_for_array () =
  let program_text = {|
struct TestStruct {
    name: u8[4],  // Small array
    id: u32,
}

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
    var obj = TestStruct {
        name: "this_is_too_long",  // String longer than 4 chars
        id: 42,
    }
    return XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (_typed_ast, _typed_programs) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    fail "String too long for array should fail type checking"
  with
  | Type_error (_, _) -> 
      check bool "String too long for array correctly fails" true true
  | exn -> fail ("Unexpected error: " ^ Printexc.to_string exn)

(** Test string exactly fits in array *)
let test_string_exact_fit_array () =
  let program_text = {|
struct TestStruct {
    name: u8[5],  // Exactly 5 bytes
    id: u32,
}

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
    var obj = TestStruct {
        name: "hello",  // Exactly 5 chars
        id: 42,
    }
    return XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (_typed_ast, _typed_programs) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "String exact fit in array" true true
  with
  | exn -> fail ("String exact fit test failed: " ^ Printexc.to_string exn)

(** Test direct unify_types function *)
let test_unify_types_string_to_array () =
  (* Test that string can unify with larger u8 array *)
  let str_type = Str 10 in
  let array_type = Array (U8, 16) in
  (match unify_types str_type array_type with
   | Some (Array (U8, 16)) -> check bool "String unifies with larger u8 array" true true
   | _ -> fail "String should unify with larger u8 array");
  
  (* Test that larger string cannot unify with smaller array *)
  let large_str_type = Str 20 in
  let small_array_type = Array (U8, 16) in
  (match unify_types large_str_type small_array_type with
   | None -> check bool "Large string cannot unify with smaller array" true true
   | Some _ -> fail "Large string should not unify with smaller array");
  
  (* Test that string cannot unify with non-u8 array *)
  let str_type = Str 10 in
  let u32_array_type = Array (U32, 16) in
  (match unify_types str_type u32_array_type with
   | None -> check bool "String cannot unify with non-u8 array" true true
   | Some _ -> fail "String should not unify with non-u8 array")

(** Test multiple string assignments in same struct *)
let test_multiple_string_assignments () =
  let program_text = {|
struct Config {
    name: u8[16],
    description: u8[32],
    category: u8[8],
    version: u32,
}

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
    var cfg = Config {
        name: "test_config",
        description: "A test configuration",
        category: "test",
        version: 1,
    }
    return XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (_typed_ast, _typed_programs) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "Multiple string assignments in struct" true true
  with
  | exn -> fail ("Multiple string assignments test failed: " ^ Printexc.to_string exn)

(** Test string assignment in nested structs *)
let test_nested_struct_string_assignment () =
  let program_text = {|
struct Inner {
    name: u8[16],
    id: u32,
}

struct Outer {
    inner: Inner,
    label: u8[8],
}

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
    var obj = Outer {
        inner: Inner {
            name: "inner_name",
            id: 1,
        },
        label: "outer",
    }
    return XDP_PASS
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = create_test_symbol_table ast in
    let (_typed_ast, _typed_programs) = type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "Nested struct string assignment" true true
  with
  | exn -> fail ("Nested struct string assignment test failed: " ^ Printexc.to_string exn)

let tests = [
  "string to u8 array basic", `Quick, test_string_to_u8_array_basic;
  "string too long for array", `Quick, test_string_too_long_for_array;
  "string exact fit in array", `Quick, test_string_exact_fit_array;
  "unify_types string to array", `Quick, test_unify_types_string_to_array;
  "multiple string assignments", `Quick, test_multiple_string_assignments;
  "nested struct string assignment", `Quick, test_nested_struct_string_assignment;
]

let () = Alcotest.run "String to U8 Array Unification Tests" [
  "string_to_array_tests", tests;
] 