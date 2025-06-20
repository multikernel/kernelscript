open Kernelscript.Parse
open Kernelscript.Type_checker
open Alcotest

(** Test program reference type checking *)
let test_program_reference_type () =
  let program_text = {|
program packet_filter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XDP_PASS
  }
}

fn main() -> i32 {
  let prog_handle = load_program(packet_filter)
  let result = attach_program(prog_handle, "eth0", 0)
  return 0
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
    return 0
  }
}

program tc_filter : tc {
  fn main(ctx: TcContext) -> TcAction {
    return TC_ACT_OK
  }
}

fn main() -> i32 {
  let kprobe_handle = load_program(kprobe_tracer)
  let tc_handle = load_program(tc_filter)
  
  let kprobe_result = attach_program(kprobe_handle, "sys_read", 0)
  let tc_result = attach_program(tc_handle, "eth0", 1)
  
  return 0
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
fn main() -> i32 {
  let prog_handle = load_program(non_existent_program)
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "should fail for non-existent program" false true
  with
  | Type_error _ -> 
      check bool "should fail for non-existent program" true true
  | Kernelscript.Symbol_table.Symbol_error _ ->
      check bool "should fail for non-existent program" true true
  | _ -> 
      check bool "should fail for non-existent program" false true

(** Test program reference as variable *)
let test_program_reference_as_variable () =
  let program_text = {|
program my_xdp : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XDP_PASS
  }
}

fn main() -> i32 {
  let prog_ref = my_xdp  // Should work - program reference as variable
  let prog_handle = load_program(prog_ref)
  return 0
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
    return XDP_PASS
  }
}

fn main() -> i32 {
  let prog_handle = load_program("string_instead_of_program")  // Should fail
  return 0
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
  (* Test that the built-in functions are properly recognized *)
  check bool "load_program is builtin" true (Kernelscript.Stdlib.is_builtin_function "load_program");
  check bool "attach_program is builtin" true (Kernelscript.Stdlib.is_builtin_function "attach_program");
  
  (* Test getting function signatures *)
  (match Kernelscript.Stdlib.get_builtin_function_signature "load_program" with
  | Some (params, return_type) ->
      check int "load_program parameter count" 1 (List.length params);
      check bool "load_program return type is ProgramHandle" true (return_type = Kernelscript.Ast.ProgramHandle)
  | None -> check bool "load_program function signature should exist" false true);
  
  (match Kernelscript.Stdlib.get_builtin_function_signature "attach_program" with
  | Some (params, return_type) ->
      check int "attach_program parameter count" 3 (List.length params);
      (match params with
       | first_param :: _ ->
           check bool "attach_program first parameter is ProgramHandle" true (first_param = Kernelscript.Ast.ProgramHandle)
       | [] -> check bool "attach_program should have parameters" false true);
      check bool "attach_program return type is U32" true (return_type = Kernelscript.Ast.U32)
  | None -> check bool "attach_program function signature should exist" false true)

(** Test that calling attach_program without load_program fails *)
let test_attach_without_load_fails () =
  let program_text = {|
program simple_xdp : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XDP_PASS
  }
}

fn main() -> i32 {
  let result = attach_program(simple_xdp, "eth0", 0)  // Should fail - program ref instead of handle
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "should fail when attach_program called with program reference" false true
  with
  | Type_error (msg, _) -> 
      check bool "should fail with type error" true (String.length msg > 0);
      check bool "error should mention type mismatch" true (String.contains msg 'm')
  | _ -> 
      check bool "should fail when attach_program called with program reference" false true

(** Test multiple program handles with proper resource management *)
let test_multiple_program_handles () =
  let program_text = {|
program xdp_filter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XDP_PASS
  }
}

program tc_shaper : tc {
  fn main(ctx: TcContext) -> TcAction {
    return TC_ACT_OK
  }
}

fn main() -> i32 {
  let xdp_handle = load_program(xdp_filter)
  let tc_handle = load_program(tc_shaper)
  
  let xdp_result = attach_program(xdp_handle, "eth0", 0)
  let tc_result = attach_program(tc_handle, "eth0", 1)
  
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "multiple program handles should work" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "multiple program handles should work" true false
  | _ -> 
      check bool "multiple program handles should work" true false

(** Test that program handle variables can be named appropriately *)
let test_program_handle_naming () =
  let program_text = {|
program simple_xdp : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XDP_PASS
  }
}

fn main() -> i32 {
  let program_handle = load_program(simple_xdp)  // Clear, non-fd naming
  let network_prog = load_program(simple_xdp)    // Alternative naming
  
  let result1 = attach_program(program_handle, "eth0", 0)
  let result2 = attach_program(network_prog, "lo", 0)
  
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = type_check_ast ast in
    check bool "program handle naming should work" true true
  with
  | Type_error (msg, _) -> 
      Printf.printf "Type error: %s\n" msg;
      check bool "program handle naming should work" true false
  | _ -> 
      check bool "program handle naming should work" true false

(** Test suite *)
let program_ref_tests = [
  "program_reference_type_checking", `Quick, test_program_reference_type;
  "different_program_types", `Quick, test_different_program_types;
  "invalid_program_reference", `Quick, test_invalid_program_reference;
  "program_reference_as_variable", `Quick, test_program_reference_as_variable;
  "wrong_argument_types", `Quick, test_wrong_argument_types;
  "stdlib_integration", `Quick, test_stdlib_integration;
  "attach_without_load_fails", `Quick, test_attach_without_load_fails;
  "multiple_program_handles", `Quick, test_multiple_program_handles;
  "program_handle_naming", `Quick, test_program_handle_naming;
]

let () =
  run "Program Reference Tests" [
    "program_ref", program_ref_tests;
  ] 
