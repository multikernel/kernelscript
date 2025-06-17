open Alcotest
open Kernelscript.Parse
open Kernelscript.Type_checker

(** Helper function to create test positions *)

(** Test for loop with constant bounds *)
let test_for_constant_bounds () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for i in 0..5 {
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
    for i in start..endval {
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
    for i in 1..10 {
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
    for i in 5..5 {
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
    for i in 1..3 {
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
    | _ -> fail ("Expected parse error for: " ^ desc)
  ) error_cases

let for_statement_tests = [
  "for_constant_bounds", `Quick, test_for_constant_bounds;
  "for_variable_bounds", `Quick, test_for_variable_bounds;
  "for_empty_body", `Quick, test_for_empty_body;
  "for_single_iteration", `Quick, test_for_single_iteration;
  "for_simple_arithmetic", `Quick, test_for_simple_arithmetic;
  "for_error_cases", `Quick, test_for_error_cases;
]

let () =
  run "KernelScript For Statement Tests" [
    "for_statements", for_statement_tests;
  ] 