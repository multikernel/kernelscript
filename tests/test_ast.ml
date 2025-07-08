open Kernelscript.Ast
open Alcotest

let test_position = make_position 1 1 "test.ks"

(** Test position tracking *)
let test_position_tracking () =
  let pos = make_position 10 5 "test_file.ks" in
  check int "line number" 10 pos.line;
  check int "column number" 5 pos.column;
  check string "filename" "test_file.ks" pos.filename

(** Test literals *)
let test_literals () =
  let int_lit = IntLit (42, None) in
  let str_lit = StringLit "hello" in
  let bool_lit = BoolLit true in
  let char_lit = CharLit 'a' in
  
  check bool "int literal creation" true (match int_lit with IntLit (42, _) -> true | _ -> false);
  check bool "string literal creation" true (match str_lit with StringLit "hello" -> true | _ -> false);
  check bool "bool literal creation" true (match bool_lit with BoolLit true -> true | _ -> false);
  check bool "char literal creation" true (match char_lit with CharLit 'a' -> true | _ -> false)

(** Test BPF types *)
let test_bpf_types () =
  let u32_type = U32 in
  let u64_type = U64 in
  let pointer_type = Pointer U8 in
  let array_type = Array (U32, 10) in
  
  check bool "U32 type" true (u32_type = U32);
  check bool "U64 type" true (u64_type = U64);
  check bool "Pointer type" true (match pointer_type with Pointer U8 -> true | _ -> false);
  check bool "Array type" true (match array_type with Array (U32, 10) -> true | _ -> false)

(** Test expressions *)
let test_expressions () =
  let literal_expr = make_expr (Literal (IntLit (42, None))) test_position in
  let id_expr = make_expr (Identifier "x") test_position in
  let binary_expr = make_expr (BinaryOp (literal_expr, Add, id_expr)) test_position in
  
  check bool "literal expression" true (match literal_expr.expr_desc with Literal _ -> true | _ -> false);
  check bool "identifier expression" true (match id_expr.expr_desc with Identifier "x" -> true | _ -> false);
  check bool "binary expression" true (match binary_expr.expr_desc with BinaryOp (_, Add, _) -> true | _ -> false)

(** Test statements *)
let test_statements () =
  let expr = make_expr (Literal (IntLit (42, None))) test_position in
  let decl_stmt = make_stmt (Declaration ("x", Some U32, Some expr)) test_position in
  let return_stmt = make_stmt (Return (Some expr)) test_position in
  
  check bool "declaration statement" true (match decl_stmt.stmt_desc with Declaration ("x", Some U32, _) -> true | _ -> false);
  check bool "return statement" true (match return_stmt.stmt_desc with Return (Some _) -> true | _ -> false)

(** Test function definition *)
let test_function_definition () =
  let param = ("ctx", Xdp_md) in
  let body = [make_stmt (Return (Some (make_expr (Literal (IntLit (0, None))) test_position))) test_position] in
  let func = make_function "main" [param] (Some Xdp_action) body test_position in
  
  check string "function name" "main" func.func_name;
  check int "parameter count" 1 (List.length func.func_params);
  check bool "return type" true (match func.func_return_type with Some Xdp_action -> true | _ -> false);
  check int "body statements" 1 (List.length func.func_body)

(** Test attributed function definition *)
let test_attributed_function_definition () =
  let param = ("ctx", Xdp_md) in
  let func = make_function "packet_filter" [param] (Some Xdp_action) [] test_position in
  let attr_func = make_attributed_function [SimpleAttribute "xdp"] func test_position in
  
  check string "function name" "packet_filter" attr_func.attr_function.func_name;
  check int "parameter count" 1 (List.length attr_func.attr_function.func_params);
  check bool "return type" true (match attr_func.attr_function.func_return_type with Some Xdp_action -> true | _ -> false);
  check int "attributes" 1 (List.length attr_func.attr_list)

(** Test complete AST *)
let test_complete_ast () =
  let return_stmt = make_stmt (Return (Some (make_expr (Literal (IntLit (2, None))) test_position))) test_position in
  let func = make_function "packet_filter" [("ctx", Xdp_md)] (Some Xdp_action) [return_stmt] test_position in
  let attr_func = make_attributed_function [SimpleAttribute "xdp"] func test_position in
  let ast = [AttributedFunction attr_func] in
  
  check int "AST declarations" 1 (List.length ast);
  match List.hd ast with
  | AttributedFunction af -> check string "function name in AST" "packet_filter" af.attr_function.func_name
  | _ -> fail "Expected attributed function declaration"

(** Test operators *)
let test_operators () =
  let add_op = Add in
  let eq_op = Eq in
  let and_op = And in
  
  check bool "add operator" true (add_op = Add);
  check bool "equality operator" true (eq_op = Eq);
  check bool "logical and operator" true (and_op = And)

(** Test extended types *)
let test_extended_types () =
  let struct_type = Struct "MyStruct" in
  let ctx_type = Xdp_md in
  let action_type = Xdp_action in
  
  check bool "struct type" true (match struct_type with Struct "MyStruct" -> true | _ -> false);
  check bool "context type" true (ctx_type = Xdp_md);
  check bool "action type" true (action_type = Xdp_action)

let ast_tests = [
  "position_tracking", `Quick, test_position_tracking;
  "literals", `Quick, test_literals;
  "bpf_types", `Quick, test_bpf_types;
  "expressions", `Quick, test_expressions;
  "statements", `Quick, test_statements;
  "function_definition", `Quick, test_function_definition;
  "attributed_function_definition", `Quick, test_attributed_function_definition;
  "complete_ast", `Quick, test_complete_ast;
  "operators", `Quick, test_operators;
  "extended_types", `Quick, test_extended_types;
]

let () =
  run "KernelScript AST Tests" [
    "ast", ast_tests;
  ] 