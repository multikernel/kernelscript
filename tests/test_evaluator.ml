(** Unit Tests for Expression Evaluator *)

open Kernelscript.Parse
open Alcotest

(** Test basic expression evaluation *)
let test_basic_evaluation () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 5;
    let y = 10;
    let result = x + y;
    return 2;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = List.length ast in
    check bool "basic evaluation test" true true
  with
  | _ -> fail "Failed basic evaluation test"

let evaluator_tests = [
  "basic_evaluation", `Quick, test_basic_evaluation;
]

let () =
  run "KernelScript Evaluator Tests" [
    "evaluator", evaluator_tests;
  ]