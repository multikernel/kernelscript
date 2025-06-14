open Kernelscript.Parse
open Kernelscript.Type_checker
open Alcotest

(** Test program reference type checking *)
let test_program_reference_type () =
  let program_text = {|
program packet_filter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main() -> i32 {
    let prog_fd = load_program(packet_filter);
    let result = attach_program(packet_filter, "eth0", 0);
    return 0;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "program reference type checking" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "program reference type checking" true false
  | _ -> 
      check bool "program reference type checking" true false

(** Test program reference with different program types *)
let test_different_program_types () =
  let program_text = {|
program kprobe_tracer : kprobe {
  fn main(ctx: KprobeContext) -> u32 {
    return 0;
  }
}

program tc_filter : tc {
  fn main(ctx: TcContext) -> TcAction {
    return TcAction::Pass;
  }
}

userspace {
  fn main() -> i32 {
    let kprobe_fd = load_program(kprobe_tracer);
    let tc_fd = load_program(tc_filter);
    
    let kprobe_result = attach_program(kprobe_tracer, "sys_read", 0);
    let tc_result = attach_program(tc_filter, "eth0", 1);
    
    return 0;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "different program types" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "different program types" true false
  | Parse_error (msg, _) ->
      Printf.printf "Parse error: %s\n" msg;
      check bool "different program types" true false
  | e -> 
      Printf.printf "Other error: %s\n" (Printexc.to_string e);
      check bool "different program types" true false

(** Test invalid program reference *)
let test_invalid_program_reference () =
  let program_text = {|
userspace {
  fn main() -> i32 {
    let prog_fd = load_program(non_existent_program);
    return 0;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "should fail for non-existent program" false true
  with
  | Type_error _ -> 
      check bool "should fail for non-existent program" true true
  | _ -> 
      check bool "should fail for non-existent program" false true

(** Test program reference as variable *)
let test_program_reference_as_variable () =
  let program_text = {|
program my_xdp : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main() -> i32 {
    let prog_ref = my_xdp;  // Should work - program reference as variable
    let prog_fd = load_program(prog_ref);
    return 0;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "program reference as variable" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "program reference as variable" true false
  | _ -> 
      check bool "program reference as variable" true false

(** Test wrong argument types for program functions *)
let test_wrong_argument_types () =
  let program_text = {|
program my_xdp : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main() -> i32 {
    let prog_fd = load_program("string_instead_of_program");  // Should fail
    return 0;
  }
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "should fail for wrong argument type" false true
  with
  | Type_error _ -> 
      check bool "should fail for wrong argument type" true true
  | _ -> 
      check bool "should fail for wrong argument type" false true

(** Test stdlib integration *)
let test_stdlib_integration () =
  (* Test that the new built-in functions are properly recognized *)
  check bool "load_program is builtin" true (Kernelscript.Stdlib.is_builtin_function "load_program");
  check bool "attach_program is builtin" true (Kernelscript.Stdlib.is_builtin_function "attach_program");
  
  (* Test getting function signatures *)
  (match Kernelscript.Stdlib.get_builtin_function_signature "load_program" with
  | Some (params, return_type) ->
      check int "load_program parameter count" 1 (List.length params);
      check bool "load_program return type is U32" true (return_type = Kernelscript.Ast.U32)
  | None -> check bool "load_program function signature should exist" false true);
  
  (match Kernelscript.Stdlib.get_builtin_function_signature "attach_program" with
  | Some (params, return_type) ->
      check int "attach_program parameter count" 3 (List.length params);
      check bool "attach_program return type is U32" true (return_type = Kernelscript.Ast.U32)
  | None -> check bool "attach_program function signature should exist" false true)

(** Test suite *)
let program_ref_tests = [
  "program_reference_type_checking", `Quick, test_program_reference_type;
  "different_program_types", `Quick, test_different_program_types;
  "invalid_program_reference", `Quick, test_invalid_program_reference;
  "program_reference_as_variable", `Quick, test_program_reference_as_variable;
  "wrong_argument_types", `Quick, test_wrong_argument_types;
  "stdlib_integration", `Quick, test_stdlib_integration;
]

let () =
  run "Program Reference Tests" [
    "program_ref", program_ref_tests;
  ] 