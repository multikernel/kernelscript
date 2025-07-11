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
  let xdp_func1 = make_test_func "process_http" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "log_request") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  let xdp_func2 = make_test_func "log_request" [("ctx", Xdp_md)] (Some Xdp_action) [
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
  let xdp_func = make_test_func "xdp_handler" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "tc_handler") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  let tc_func = make_test_func "tc_handler" [("ctx", Pointer (Struct "__sk_buff"))] (Some I32) [
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
  let func1 = make_test_func "handler1" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "handler2") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  (* Different signature - incompatible *)
  let func2 = make_test_func "handler2" [("ctx", Xdp_md); ("data", U32)] (Some Xdp_action) [
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
  let func1 = make_test_func "main_handler" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "process_tcp") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  let func2 = make_test_func "process_tcp" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "log_tcp") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  let func3 = make_test_func "log_tcp" [("ctx", Xdp_md)] (Some Xdp_action) [
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
  let func1 = make_test_func "entry" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "stage1") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  let func2 = make_test_func "stage1" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "stage2") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  let func3 = make_test_func "stage2" [("ctx", Xdp_md)] (Some Xdp_action) [
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
  let func1 = make_test_func "simple_handler" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (2, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] func1 in
  
  let ast = [AttributedFunction attr_func1] in
  let analysis = analyze_tail_calls ast in
  
  check int "dependencies count" 0 (List.length analysis.dependencies);
  check int "prog_array_size" 0 analysis.prog_array_size

(** Test validation errors *)
let test_validation_errors _ =
  let func1 = make_test_func "xdp_handler" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Call (make_expr (Identifier "tc_handler") make_test_position, [])) make_test_position))) make_test_position
  ] in
  
  let func2 = make_test_func "tc_handler" [("ctx", Pointer (Struct "__sk_buff"))] (Some I32) [
    make_stmt (Return (Some (make_expr (Literal (IntLit (0, None))) make_test_position))) make_test_position
  ] in
  
  let attr_func1 = make_test_attr_func [SimpleAttribute "xdp"] func1 in
  let attr_func2 = make_test_attr_func [SimpleAttribute "tc"] func2 in
  
  let attributed_functions = [attr_func1; attr_func2] in
  let analysis = analyze_tail_calls [AttributedFunction attr_func1; AttributedFunction attr_func2] in
  
  let errors = validate_tail_call_constraints analysis attributed_functions in
  (* Should have no errors since no valid dependencies were created *)
  check int "errors count" 0 (List.length errors)

let test_tail_call_match_expressions _ =
  (* Create match expression with tail calls *)
  let protocol_var = make_expr (Identifier "protocol") make_test_position in
  let tcp_call = make_expr (Call (make_expr (Identifier "tcp_handler") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let udp_call = make_expr (Call (make_expr (Identifier "udp_handler") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let aborted_const = make_expr (Identifier "XDP_ABORTED") make_test_position in
  
  let match_arms = [
            { arm_pattern = IdentifierPattern "TCP"; arm_body = SingleExpr tcp_call; arm_pos = make_test_position };
        { arm_pattern = IdentifierPattern "UDP"; arm_body = SingleExpr udp_call; arm_pos = make_test_position };
        { arm_pattern = DefaultPattern; arm_body = SingleExpr aborted_const; arm_pos = make_test_position };
  ] in
  
  let match_expr = make_expr (Match (protocol_var, match_arms)) make_test_position in
  
  let tcp_handler = make_test_func "tcp_handler" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Identifier "XDP_PASS") make_test_position))) make_test_position
  ] in
  
  let udp_handler = make_test_func "udp_handler" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Identifier "XDP_DROP") make_test_position))) make_test_position
  ] in
  
  let packet_processor = make_test_func "packet_processor" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Declaration ("protocol", Some U32, Some (make_expr (Literal (IntLit (6, None))) make_test_position))) make_test_position;
    make_stmt (Return (Some match_expr)) make_test_position
  ] in
  
  let attr_tcp = make_test_attr_func [SimpleAttribute "xdp"] tcp_handler in
  let attr_udp = make_test_attr_func [SimpleAttribute "xdp"] udp_handler in
  let attr_processor = make_test_attr_func [SimpleAttribute "xdp"] packet_processor in
  
  let ast = [AttributedFunction attr_tcp; AttributedFunction attr_udp; AttributedFunction attr_processor] in
  let analysis = analyze_tail_calls ast in
  
  (* Should detect 2 tail call dependencies *)
  check int "tail call dependencies count" (List.length analysis.dependencies) 2;
  
  (* Should create prog_array with 2 entries *)
  check int "prog_array size" analysis.prog_array_size 2;
  
  (* Dependencies should be from packet_processor to tcp_handler and udp_handler *)
  let has_tcp_dependency = List.exists (fun dep -> 
    dep.caller = "packet_processor" && dep.target = "tcp_handler"
  ) analysis.dependencies in
  let has_udp_dependency = List.exists (fun dep -> 
    dep.caller = "packet_processor" && dep.target = "udp_handler"
  ) analysis.dependencies in
  
  check bool "has tcp tail call dependency" has_tcp_dependency true;
  check bool "has udp tail call dependency" has_udp_dependency true

let test_nested_match_tail_calls _ =
  (* Create nested match expression with tail calls *)
  let value_var = make_expr (Identifier "value") make_test_position in
  let handler_a_call = make_expr (Call (make_expr (Identifier "handler_a") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let handler_b_call = make_expr (Call (make_expr (Identifier "handler_b") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let handler_c_call = make_expr (Call (make_expr (Identifier "handler_c") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let xdp_tx_const = make_expr (Identifier "XDP_TX") make_test_position in
  
  (* Inner match expression *)
  let inner_match_arms = [
            { arm_pattern = ConstantPattern (IntLit (1, None)); arm_body = SingleExpr handler_a_call; arm_pos = make_test_position };
        { arm_pattern = DefaultPattern; arm_body = SingleExpr handler_b_call; arm_pos = make_test_position };
  ] in
  let inner_match = make_expr (Match (value_var, inner_match_arms)) make_test_position in
  
  (* Outer match expression *)
  let outer_match_arms = [
            { arm_pattern = ConstantPattern (IntLit (1, None)); arm_body = SingleExpr inner_match; arm_pos = make_test_position };
        { arm_pattern = ConstantPattern (IntLit (2, None)); arm_body = SingleExpr handler_c_call; arm_pos = make_test_position };
        { arm_pattern = DefaultPattern; arm_body = SingleExpr xdp_tx_const; arm_pos = make_test_position };
  ] in
  let outer_match = make_expr (Match (value_var, outer_match_arms)) make_test_position in
  
  let handler_a = make_test_func "handler_a" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Identifier "XDP_PASS") make_test_position))) make_test_position
  ] in
  
  let handler_b = make_test_func "handler_b" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Identifier "XDP_DROP") make_test_position))) make_test_position
  ] in
  
  let handler_c = make_test_func "handler_c" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Identifier "XDP_ABORTED") make_test_position))) make_test_position
  ] in
  
  let dispatcher = make_test_func "dispatcher" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Declaration ("value", Some U32, Some (make_expr (Literal (IntLit (1, None))) make_test_position))) make_test_position;
    make_stmt (Return (Some outer_match)) make_test_position
  ] in
  
  let attr_a = make_test_attr_func [SimpleAttribute "xdp"] handler_a in
  let attr_b = make_test_attr_func [SimpleAttribute "xdp"] handler_b in
  let attr_c = make_test_attr_func [SimpleAttribute "xdp"] handler_c in
  let attr_dispatcher = make_test_attr_func [SimpleAttribute "xdp"] dispatcher in
  
  let ast = [AttributedFunction attr_a; AttributedFunction attr_b; AttributedFunction attr_c; AttributedFunction attr_dispatcher] in
  let analysis = analyze_tail_calls ast in
  
  (* Should detect 3 tail call dependencies from nested match *)
  check int "nested match tail call dependencies" (List.length analysis.dependencies) 3;
  
  (* Should create prog_array with 3 entries *)
  check int "nested match prog_array size" analysis.prog_array_size 3

let test_match_with_mixed_tail_calls _ =
  (* Create match expression with mixed tail calls and direct returns *)
  let value_var = make_expr (Identifier "value") make_test_position in
  let tail_target_call1 = make_expr (Call (make_expr (Identifier "tail_target") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let tail_target_call2 = make_expr (Call (make_expr (Identifier "tail_target") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let xdp_drop_const = make_expr (Identifier "XDP_DROP") make_test_position in
  let xdp_aborted_const = make_expr (Identifier "XDP_ABORTED") make_test_position in
  
  let match_arms = [
            { arm_pattern = ConstantPattern (IntLit (1, None)); arm_body = SingleExpr tail_target_call1; arm_pos = make_test_position };
        { arm_pattern = ConstantPattern (IntLit (2, None)); arm_body = SingleExpr xdp_drop_const; arm_pos = make_test_position };
        { arm_pattern = ConstantPattern (IntLit (3, None)); arm_body = SingleExpr tail_target_call2; arm_pos = make_test_position };
        { arm_pattern = DefaultPattern; arm_body = SingleExpr xdp_aborted_const; arm_pos = make_test_position };
  ] in
  
  let match_expr = make_expr (Match (value_var, match_arms)) make_test_position in
  
  let tail_target = make_test_func "tail_target" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Identifier "XDP_PASS") make_test_position))) make_test_position
  ] in
  
  let mixed_dispatcher = make_test_func "mixed_dispatcher" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Declaration ("value", Some U32, Some (make_expr (Literal (IntLit (1, None))) make_test_position))) make_test_position;
    make_stmt (Return (Some match_expr)) make_test_position
  ] in
  
  let attr_target = make_test_attr_func [SimpleAttribute "xdp"] tail_target in
  let attr_dispatcher = make_test_attr_func [SimpleAttribute "xdp"] mixed_dispatcher in
  
  let ast = [AttributedFunction attr_target; AttributedFunction attr_dispatcher] in
  let analysis = analyze_tail_calls ast in
  
  (* Should detect 1 unique tail call dependency (deduplicated) *)
  check int "mixed match tail call dependencies" (List.length analysis.dependencies) 1;
  
  (* Should create prog_array with 1 entry *)
  check int "mixed match prog_array size" analysis.prog_array_size 1;
  
  (* Dependency should be from mixed_dispatcher to tail_target *)
  let has_dependency = List.exists (fun dep -> 
    dep.caller = "mixed_dispatcher" && dep.target = "tail_target"
  ) analysis.dependencies in
  check bool "has mixed match tail call dependency" has_dependency true

(** Test tail calls inside if statements - regression test for nested control flow bug *)
let test_tail_calls_in_if_statements _ =
  (* Create a function that has a tail call inside an if statement *)
  let condition_expr = make_expr (UnaryOp (Not, make_expr (Call (make_expr (Identifier "validate_packet") make_test_position, [make_expr (Identifier "size") make_test_position])) make_test_position)) make_test_position in
  let tail_call_expr = make_expr (Call (make_expr (Identifier "drop_handler") make_test_position, [make_expr (Identifier "ctx") make_test_position])) make_test_position in
  let return_stmt = make_stmt (Return (Some tail_call_expr)) make_test_position in
  let if_stmt = make_stmt (If (condition_expr, [return_stmt], None)) make_test_position in
  let final_return = make_stmt (Return (Some (make_expr (Identifier "XDP_PASS") make_test_position))) make_test_position in
  
  let packet_filter = make_test_func "packet_filter" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Declaration ("size", Some U32, Some (make_expr (Literal (IntLit (128, None))) make_test_position))) make_test_position;
    if_stmt;
    final_return
  ] in
  
  let drop_handler = make_test_func "drop_handler" [("ctx", Xdp_md)] (Some Xdp_action) [
    make_stmt (Return (Some (make_expr (Identifier "XDP_DROP") make_test_position))) make_test_position
  ] in
  
  let attr_packet_filter = make_test_attr_func [SimpleAttribute "xdp"] packet_filter in
  let attr_drop_handler = make_test_attr_func [SimpleAttribute "xdp"] drop_handler in
  
  let ast = [AttributedFunction attr_packet_filter; AttributedFunction attr_drop_handler] in
  let analysis = analyze_tail_calls ast in
  
  (* Should detect 1 tail call dependency from packet_filter to drop_handler *)
  check int "if statement tail call dependencies" (List.length analysis.dependencies) 1;
  
  (* Should create prog_array with 1 entry *)
  check int "if statement prog_array size" analysis.prog_array_size 1;
  
  (* Verify the specific dependency *)
  let dep = List.hd analysis.dependencies in
  check string "if statement caller" "packet_filter" dep.caller;
  check string "if statement target" "drop_handler" dep.target;
  
  (* Verify index mapping contains the target *)
  check bool "drop_handler should be in mapping" true (Hashtbl.mem analysis.index_mapping "drop_handler")

let suite = [
  "test_tail_call_detection", `Quick, test_tail_call_detection;
  "test_program_type_compatibility", `Quick, test_program_type_compatibility;
  "test_signature_compatibility", `Quick, test_signature_compatibility;
  "test_prog_array_mapping", `Quick, test_prog_array_mapping;
  "test_dependency_chains", `Quick, test_dependency_chains;
  "test_no_tail_calls", `Quick, test_no_tail_calls;
  "test_validation_errors", `Quick, test_validation_errors;
  "tail_call_match_expressions", `Quick, test_tail_call_match_expressions;
  "nested_match_tail_calls", `Quick, test_nested_match_tail_calls;
  "match_with_mixed_tail_calls", `Quick, test_match_with_mixed_tail_calls;
  "test_tail_calls_in_if_statements", `Quick, test_tail_calls_in_if_statements;
]

let () = Alcotest.run "Tail Call Tests" [("main", suite)] 