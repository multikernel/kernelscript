(** Tail Call Test Suite for KernelScript
    
    This module tests:
    - Tail call detection and analysis
    - Dependency tracking
    - ProgArray generation
    - Code generation for tail calls
*)

open Alcotest
open Kernelscript.Ast
open Kernelscript.Tail_call_analyzer

(** Test utilities *)
let make_test_position = { line = 1; column = 1; filename = "test.ks" }

let make_test_func name params return_type body =
  make_function name params return_type body make_test_position

let make_test_attr_func attrs func =
  make_attributed_function attrs func make_test_position

(** Test tail call detection *)
let test_tail_call_detection _ =
  let xdp_func1 = make_test_func "process_http" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("log_request", [])) make_test_position))) make_test_position
  ] in
  
  let xdp_func2 = make_test_func "log_request" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (2, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] xdp_func1 in
  let attr_func2 = make_test_attr_func [SimpleAttribute "xdp"] xdp_func2 in
  
  let ast = [AttributedFunction attr_func1; AttributedFunction attr_func2] in
  let analysis = analyze_tail_calls ast in
  
  check int "dependencies count" 1 (List.length analysis.dependencies);
  
  let dep = List.hd analysis.dependencies in
  check string "caller" "process_http" dep.caller;
  check string "target" "log_request" dep.target;
  check (module struct type t = program_type let pp fmt _ = Format.fprintf fmt "program_type" let equal = (=) end) 
        "caller_type" Xdp dep.caller_type;
  check (module struct type t = program_type let pp fmt _ = Format.fprintf fmt "program_type" let equal = (=) end) 
        "target_type" Xdp dep.target_type

(** Test program type compatibility *)
let test_program_type_compatibility _ =
  let xdp_func = make_test_func "xdp_handler" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("tc_handler", [])) make_test_position))) make_test_position
  ] in
  
  let tc_func = make_test_func "tc_handler" [("ctx", TcContext)] (Some TcAction) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (0, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] xdp_func in
  let attr_func2 = make_test_attr_func [SimpleAttribute "tc"] tc_func in
  
  let ast = [AttributedFunction attr_func1; AttributedFunction attr_func2] in
  let analysis = analyze_tail_calls ast in
  
  (* Should have no dependencies due to incompatible program types *)
  check int "dependencies count" 0 (List.length analysis.dependencies)

(** Test signature compatibility *)
let test_signature_compatibility _ =
  let func1 = make_test_func "handler1" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("handler2", [])) make_test_position))) make_test_position
  ] in
  
  (* Different signature - incompatible *)
  let func2 = make_test_func "handler2" [("ctx", XdpContext); ("data", U32)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (2, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] func1 in
  let attr_func2 = make_test_attr_func [SimpleAttribute "xdp"] func2 in
  
  let ast = [AttributedFunction attr_func1; AttributedFunction attr_func2] in
  let analysis = analyze_tail_calls ast in
  
  (* Should have no dependencies due to incompatible signatures *)
  check int "dependencies count" 0 (List.length analysis.dependencies)

(** Test ProgArray index mapping *)
let test_prog_array_mapping _ =
  let func1 = make_test_func "main_handler" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("process_tcp", [])) make_test_position))) make_test_position
  ] in
  
  let func2 = make_test_func "process_tcp" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("log_tcp", [])) make_test_position))) make_test_position
  ] in
  
  let func3 = make_test_func "log_tcp" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (2, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] func1 in
  let attr_func2 = make_test_attr_func [SimpleAttribute "xdp"] func2 in
  let attr_func3 = make_test_attr_func [SimpleAttribute "xdp"] func3 in
  
  let ast = [AttributedFunction attr_func1; AttributedFunction attr_func2; AttributedFunction attr_func3] in
  let analysis = analyze_tail_calls ast in
  
  (* Should have 2 unique targets *)
  check int "prog_array_size" 2 analysis.prog_array_size;
  
  (* Check index mapping *)
  check bool "process_tcp should be in mapping" true (Hashtbl.mem analysis.index_mapping "process_tcp");
  check bool "log_tcp should be in mapping" true (Hashtbl.mem analysis.index_mapping "log_tcp")

(** Test dependency chain analysis *)
let test_dependency_chains _ =
  let func1 = make_test_func "entry" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("stage1", [])) make_test_position))) make_test_position
  ] in
  
  let func2 = make_test_func "stage1" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("stage2", [])) make_test_position))) make_test_position
  ] in
  
  let func3 = make_test_func "stage2" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (2, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] func1 in
  let attr_func2 = make_test_attr_func [SimpleAttribute "xdp"] func2 in
  let attr_func3 = make_test_attr_func [SimpleAttribute "xdp"] func3 in
  
  let ast = [AttributedFunction attr_func1; AttributedFunction attr_func2; AttributedFunction attr_func3] in
  let analysis = analyze_tail_calls ast in
  
  (* Get all dependencies for entry function *)
  let all_deps = get_tail_call_dependencies "entry" analysis in
  
  (* Should include both direct and indirect dependencies *)
  check bool "Should include stage1" true (List.mem "stage1" all_deps);
  check bool "Should include stage2" true (List.mem "stage2" all_deps)

(** Test no tail calls *)
let test_no_tail_calls _ =
  let func1 = make_test_func "simple_handler" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (2, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] func1 in
  
  let ast = [AttributedFunction attr_func1] in
  let analysis = analyze_tail_calls ast in
  
  check int "dependencies count" 0 (List.length analysis.dependencies);
  check int "prog_array_size" 0 analysis.prog_array_size

(** Test validation errors *)
let test_validation_errors _ =
  let func1 = make_test_func "xdp_handler" [("ctx", XdpContext)] (Some XdpAction) [
    make_stmt (Return (Some (make_expr (FunctionCall ("tc_handler", [])) make_test_position))) make_test_position
  ] in
  
  let func2 = make_test_func "tc_handler" [("ctx", TcContext)] (Some TcAction) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (0, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] func1 in
  let attr_func2 = make_test_attr_func [SimpleAttribute "tc"] func2 in
  
  let attributed_functions = [attr_func1; attr_func2] in
  let analysis = analyze_tail_calls [AttributedFunction attr_func1; AttributedFunction attr_func2] in
  
  let errors = validate_tail_call_constraints analysis attributed_functions in
  (* Should have no errors since no valid dependencies were created *)
  check int "errors count" 0 (List.length errors)

let suite = [
  "test_tail_call_detection", `Quick, test_tail_call_detection;
  "test_program_type_compatibility", `Quick, test_program_type_compatibility;
  "test_signature_compatibility", `Quick, test_signature_compatibility;
  "test_prog_array_mapping", `Quick, test_prog_array_mapping;
  "test_dependency_chains", `Quick, test_dependency_chains;
  "test_no_tail_calls", `Quick, test_no_tail_calls;
  "test_validation_errors", `Quick, test_validation_errors;
]

let () = Alcotest.run "Tail Call Tests" [("main", suite)] 