open Alcotest
open Kernelscript.Parse
open Kernelscript.Type_checker

(** Helper function to parse and evaluate a program with break/continue *)
let parse_and_check_break_continue program_text =
  try
    let ast = parse_string program_text in
    let typed_ast = type_check_ast ast in
    Ok typed_ast
  with
  | Parse_error (msg, _pos) -> Error ("Parse error: " ^ msg)
  | Type_error (msg, _pos) -> Error ("Type error: " ^ msg)
  | e -> Error ("Other error: " ^ Printexc.to_string e)

(** Test basic break statement parsing *)
let test_break_statement_parsing () =
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
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "break statement parsed and type checked" true true
  | Error msg -> fail ("Failed to parse break statement: " ^ msg)

(** Test basic continue statement parsing *)
let test_continue_statement_parsing () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 0..10) {
      if (i == 5) {
        continue
      }
      let x = i
    }
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "continue statement parsed and type checked" true true
  | Error msg -> fail ("Failed to parse continue statement: " ^ msg)

(** Test break in while loop *)
let test_break_in_while_loop () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let count = 0
    while (count < 100) {
      count = count + 1
      if (count == 50) {
        break
      }
    }
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "break in while loop parsed and type checked" true true
  | Error msg -> fail ("Failed to parse break in while loop: " ^ msg)

(** Test continue in while loop *)
let test_continue_in_while_loop () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let count = 0
    while (count < 10) {
      count = count + 1
      if (count == 5) {
        continue
      }
      let processed = count * 2
    }
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "continue in while loop parsed and type checked" true true
  | Error msg -> fail ("Failed to parse continue in while loop: " ^ msg)

(** Test break in ForIter loop *)
let test_break_in_for_iter () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let array = [1, 2, 3, 4, 5]
    for (i, val) in array.iter() {
      if (i == 3) {
        break
      }
      let processed = val * 2
    }
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "break in for-iter loop parsed and type checked" true true
  | Error msg -> fail ("Failed to parse break in for-iter loop: " ^ msg)

(** Test error case: break outside loop *)
let test_break_outside_loop_error () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 5
    break
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> fail "Should have failed with break outside loop error"
  | Error msg -> 
      check bool "break outside loop produces error" 
        (try ignore (Str.search_forward (Str.regexp "Break statement can only be used inside loops") msg 0); true with Not_found -> false) true

(** Test error case: continue outside loop *)
let test_continue_outside_loop_error () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 5
    continue
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> fail "Should have failed with continue outside loop error"
  | Error msg -> 
      check bool "continue outside loop produces error" 
        (try ignore (Str.search_forward (Str.regexp "Continue statement can only be used inside loops") msg 0); true with Not_found -> false) true

(** Test break and continue in nested conditional inside loop *)
let test_break_continue_in_nested_conditional () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 0..20) {
      if (i < 5) {
        continue
      } else {
        if (i > 15) {
          break
        }
      }
      let processed = i * 3
    }
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "break/continue in nested conditional parsed and type checked" true true
  | Error msg -> fail ("Failed to parse break/continue in nested conditional: " ^ msg)

(** Test multiple break/continue statements in same loop *)
let test_multiple_break_continue_statements () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 0..100) {
      if (i < 10) {
        continue
      }
      if (i == 50) {
        break
      }
      if (i > 80) {
        continue
      }
      let x = i * 2
    }
    return 2
  }
}
|} in
  match parse_and_check_break_continue program_text with
  | Ok _ -> check bool "multiple break/continue statements parsed and type checked" true true
  | Error msg -> fail ("Failed to parse multiple break/continue statements: " ^ msg)

(** Test evaluation of break statement (simple simulation) *)
let test_break_evaluation () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i in 1..3) {
      if (i == 2) {
        break
      }
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _typed_ast = type_check_ast ast in
    (* For this test, we just verify it parses and type checks correctly *)
    (* Full evaluation testing would require more complex setup *)
    check bool "break statement evaluation setup works" true true
  with
  | e -> fail ("Failed break evaluation test: " ^ Printexc.to_string e)

let break_continue_tests = [
  "break_statement_parsing", `Quick, test_break_statement_parsing;
  "continue_statement_parsing", `Quick, test_continue_statement_parsing;
  "break_in_while_loop", `Quick, test_break_in_while_loop;
  "continue_in_while_loop", `Quick, test_continue_in_while_loop;
  "break_in_for_iter", `Quick, test_break_in_for_iter;
  "break_outside_loop_error", `Quick, test_break_outside_loop_error;
  "continue_outside_loop_error", `Quick, test_continue_outside_loop_error;
  "break_continue_in_nested_conditional", `Quick, test_break_continue_in_nested_conditional;
  "multiple_break_continue_statements", `Quick, test_multiple_break_continue_statements;
  "break_evaluation", `Quick, test_break_evaluation;
]

let () =
  run "KernelScript Break/Continue Tests" [
    "break_continue", break_continue_tests;
  ] 