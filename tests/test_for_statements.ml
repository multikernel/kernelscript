open Alcotest
open Kernelscript.Parse
open Kernelscript.Type_checker

(** Helper function to create test positions *)

(** Test for loop with constant bounds *)
let test_for_constant_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 0..5) {
      let x = i * 2
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "constant bounds for loop parsed and type checked" true true
  with
  | e -> fail ("Failed for constant bounds: " ^ Printexc.to_string e)

(** Test for loop with variable bounds *)
let test_for_variable_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let start = 1
    let endval = 10
    for (i in start..endval) {
      let x = i
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "variable bounds for loop parsed and type checked" true true
  with
  | e -> fail ("Failed for variable bounds: " ^ Printexc.to_string e)

(** Test for loop with empty body *)
let test_for_empty_body () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 1..10) {
    }
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "empty body for loop parsed and type checked" true true
  with
  | e -> fail ("Failed for empty body: " ^ Printexc.to_string e)

(** Test for loop with single iteration (same bounds) *)
let test_for_single_iteration () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 5..5) {
      let y = 42
    }
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "single iteration for loop parsed and type checked" true true
  with
  | e -> fail ("Failed for single iteration: " ^ Printexc.to_string e)

(** Test for loop with simple arithmetic *)
let test_for_simple_arithmetic () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 1..3) {
      let temp = i * 2
    }
    return 1
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "simple arithmetic for loop parsed and type checked" true true
  with
  | e -> fail ("Failed for simple arithmetic: " ^ Printexc.to_string e)

(** Test for loop with break statement *)
let test_for_with_break () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 0..10) {
      if (i == 5) {
        break
      }
      let x = i
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "for loop with break parsed and type checked" true true
  with
  | e -> fail ("Failed for loop with break: " ^ Printexc.to_string e)

(** Test for loop with continue statement *)
let test_for_with_continue () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 0..10) {
      if (i % 2 == 0) {
        continue
      }
      let x = i
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "for loop with continue parsed and type checked" true true
  with
  | e -> fail ("Failed for loop with continue: " ^ Printexc.to_string e)

(** Test for loop with complex expressions in bounds *)
let test_for_complex_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let base = 5
    let multiplier = 2
    for (i in (base - 1)..(base + multiplier)) {
      let result = i * base
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "for loop with complex bounds parsed and type checked" true true
  with
  | e -> fail ("Failed for loop with complex bounds: " ^ Printexc.to_string e)

(** Test for loop with different integer types *)
let test_for_different_integer_types () =
  let test_cases = [
    ("u8", "u8");
    ("u16", "u16"); 
    ("u32", "u32");
    ("u64", "u64");
    (* Skip signed integer types as they might have different literal parsing rules *)
  ] in
  
  List.iter (fun (type_name, _) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let start: %s = 1
    let end_val: %s = 5
    for (i in start..end_val) {
      let x = i
    }
    return 2
  }
}
|} type_name type_name in
    try
      let ast = parse_string program_text in
      let _typed_ast = type_check_ast ast in
      check bool (type_name ^ " bounds for loop") true true
    with
    | e -> fail ("Failed for " ^ type_name ^ " bounds: " ^ Printexc.to_string e)
  ) test_cases

(** Test for loop with large bounds *)
let test_for_large_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 0..1000000) {
      let large = i
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "large bounds for loop parsed and type checked" true true
  with
  | e -> fail ("Failed for large bounds: " ^ Printexc.to_string e)

(** Test for loop with reverse bounds (start > end) *)
let test_for_reverse_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 10..5) {
      let never_executed = i
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "reverse bounds for loop parsed and type checked" true true
  with
  | e -> fail ("Failed for reverse bounds: " ^ Printexc.to_string e)

(** Test for loop variable scoping *)
let test_for_variable_scoping () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let i = 100
    for (i in 0..5) {
      let x = i * 2
    }
    let after_loop = i
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "for loop variable scoping parsed and type checked" true true
  with
  | e -> fail ("Failed for variable scoping: " ^ Printexc.to_string e)

(** Test for loop in global functions *)
let test_for_in_global_function () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}

fn helper() -> u32 {
  for (i in 1..3) {
    let helper_var = i + 10
  }
  return 0
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    check bool "for loop in global function parsed and type checked" true true
  with
  | e -> fail ("Failed for loop in global function: " ^ Printexc.to_string e)

(** Test error cases for for statements *)
let test_for_error_cases () =
  let error_cases = [
    (* Invalid range syntax *)
    ("for i in 0...5 { }", "should reject triple-dot syntax");
    
    (* Missing range operator *)
    ("for i in 0 5 { }", "should require .. range operator");
  ] in
  
  List.iter (fun (code, desc) ->
    let full_program = Printf.sprintf {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    %s
    return 0
  }
}
|} code in
    try
      let _ = parse_string full_program in
      fail ("Should have failed: " ^ desc)
    with
    | Parse_error (_, _) -> check bool ("error case: " ^ desc) true true
    | Type_error (_, _) -> check bool ("type error case: " ^ desc) true true
    | _ -> fail ("Expected parse or type error for: " ^ desc)
  ) error_cases

let for_statement_tests = [
  "for_constant_bounds", `Quick, test_for_constant_bounds;
  "for_variable_bounds", `Quick, test_for_variable_bounds;
  "for_empty_body", `Quick, test_for_empty_body;
  "for_single_iteration", `Quick, test_for_single_iteration;
  "for_simple_arithmetic", `Quick, test_for_simple_arithmetic;
  "for_with_break", `Quick, test_for_with_break;
  "for_with_continue", `Quick, test_for_with_continue;
  "for_complex_bounds", `Quick, test_for_complex_bounds;
  "for_different_integer_types", `Quick, test_for_different_integer_types;
  "for_large_bounds", `Quick, test_for_large_bounds;
  "for_reverse_bounds", `Quick, test_for_reverse_bounds;
  "for_variable_scoping", `Quick, test_for_variable_scoping;
  "for_in_global_function", `Quick, test_for_in_global_function;
  "for_error_cases", `Quick, test_for_error_cases;
]

let () =
  run "KernelScript For Statement Tests" [
    "for_statements", for_statement_tests;
  ] 