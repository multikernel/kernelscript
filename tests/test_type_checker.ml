open Kernelscript.Ast
open Kernelscript.Type_checker

(** Test type unification *)
let test_type_unification () =
  let tests = [
    (* Identical types *)
    (U32, U32, Some U32);
    (Bool, Bool, Some Bool);
    
    (* Numeric promotions *)
    (U8, U16, Some U16);
    (U16, U32, Some U32);
    (U32, U64, Some U64);
    (I8, I16, Some I16);
    (I16, I32, Some I32);
    
    (* Array types *)
    (Array (U32, 10), Array (U32, 10), Some (Array (U32, 10)));
    (Array (U8, 5), Array (U16, 5), Some (Array (U16, 5)));
    
    (* Option types *)
    (Option U32, Option U32, Some (Option U32));
    (Option U8, Option U16, Some (Option U16));
    
    (* Incompatible types *)
    (U32, Bool, None);
    (Array (U32, 10), Array (U32, 20), None);
    (Option U32, U32, None);
  ] in
  
  let all_passed = List.for_all (fun (t1, t2, expected) ->
    let result = unify_types t1 t2 in
    result = expected
  ) tests in
  
  if all_passed then
    Printf.printf "✓ Type unification test passed\n"
  else
    Printf.printf "✗ Type unification test failed\n"

(** Test basic type inference *)
let test_basic_type_inference () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Test literal type inference *)
  let int_lit = make_expr (Literal (IntLit 42)) pos in
  let typed_int = type_check_expression ctx int_lit in
  
  let bool_lit = make_expr (Literal (BoolLit true)) pos in
  let typed_bool = type_check_expression ctx bool_lit in
  
  let string_lit = make_expr (Literal (StringLit "hello")) pos in
  let typed_string = type_check_expression ctx string_lit in
  
  let tests_passed = 
    typed_int.texpr_type = U32 &&
    typed_bool.texpr_type = Bool &&
    typed_string.texpr_type = Pointer U8 in
    
  if tests_passed then
    Printf.printf "✓ Basic type inference test passed\n"
  else (
    Printf.printf "✗ Basic type inference test failed\n";
    Printf.printf "  int: %s\n" (string_of_bpf_type typed_int.texpr_type);
    Printf.printf "  bool: %s\n" (string_of_bpf_type typed_bool.texpr_type);
    Printf.printf "  string: %s\n" (string_of_bpf_type typed_string.texpr_type)
  )

(** Test variable type checking *)
let test_variable_type_checking () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Add a variable to context *)
  Hashtbl.replace ctx.variables "x" U32;
  
  let var_expr = make_expr (Identifier "x") pos in
  let typed_var = type_check_expression ctx var_expr in
  
  (* Test undefined variable *)
  let undefined_expr = make_expr (Identifier "undefined") pos in
  let undefined_result = try
    let _ = type_check_expression ctx undefined_expr in
    false
  with Type_error _ -> true in
  
  let tests_passed = 
    typed_var.texpr_type = U32 &&
    undefined_result in
    
  if tests_passed then
    Printf.printf "✓ Variable type checking test passed\n"
  else
    Printf.printf "✗ Variable type checking test failed\n"

(** Test binary operation type checking *)
let test_binary_operations () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Arithmetic operations *)
  let left = make_expr (Literal (IntLit 10)) pos in
  let right = make_expr (Literal (IntLit 20)) pos in
  let add_expr = make_expr (BinaryOp (left, Add, right)) pos in
  let typed_add = type_check_expression ctx add_expr in
  
  (* Comparison operations *)
  let eq_expr = make_expr (BinaryOp (left, Eq, right)) pos in
  let typed_eq = type_check_expression ctx eq_expr in
  
  (* Logical operations *)
  let bool_left = make_expr (Literal (BoolLit true)) pos in
  let bool_right = make_expr (Literal (BoolLit false)) pos in
  let and_expr = make_expr (BinaryOp (bool_left, And, bool_right)) pos in
  let typed_and = type_check_expression ctx and_expr in
  
  let tests_passed = 
    typed_add.texpr_type = U32 &&
    typed_eq.texpr_type = Bool &&
    typed_and.texpr_type = Bool in
    
  if tests_passed then
    Printf.printf "✓ Binary operations test passed\n"
  else (
    Printf.printf "✗ Binary operations test failed\n";
    Printf.printf "  add: %s\n" (string_of_bpf_type typed_add.texpr_type);
    Printf.printf "  eq: %s\n" (string_of_bpf_type typed_eq.texpr_type);
    Printf.printf "  and: %s\n" (string_of_bpf_type typed_and.texpr_type)
  )

(** Test function call type checking *)
let test_function_calls () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Test built-in function *)
  let builtin_call = make_expr (FunctionCall ("bpf_ktime_get_ns", [])) pos in
  let typed_builtin = type_check_expression ctx builtin_call in
  
  (* Test user-defined function *)
  Hashtbl.replace ctx.functions "my_func" ([U32; Bool], U64);
  let arg1 = make_expr (Literal (IntLit 42)) pos in
  let arg2 = make_expr (Literal (BoolLit true)) pos in
  let user_call = make_expr (FunctionCall ("my_func", [arg1; arg2])) pos in
  let typed_user = type_check_expression ctx user_call in
  
  let tests_passed = 
    typed_builtin.texpr_type = U64 &&
    typed_user.texpr_type = U64 in
    
  if tests_passed then
    Printf.printf "✓ Function calls test passed\n"
  else (
    Printf.printf "✗ Function calls test failed\n";
    Printf.printf "  builtin: %s\n" (string_of_bpf_type typed_builtin.texpr_type);
    Printf.printf "  user: %s\n" (string_of_bpf_type typed_user.texpr_type)
  )

(** Test context type checking *)
let test_context_types () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Add context variable *)
  Hashtbl.replace ctx.variables "ctx" XdpContext;
  
  (* Test context field access *)
  let ctx_expr = make_expr (Identifier "ctx") pos in
  let data_access = make_expr (FieldAccess (ctx_expr, "data")) pos in
  let typed_data = type_check_expression ctx data_access in
  
  let ifindex_access = make_expr (FieldAccess (ctx_expr, "ingress_ifindex")) pos in
  let typed_ifindex = type_check_expression ctx ifindex_access in
  
  let tests_passed = 
    typed_data.texpr_type = Pointer U8 &&
    typed_ifindex.texpr_type = U32 in
    
  if tests_passed then
    Printf.printf "✓ Context types test passed\n"
  else (
    Printf.printf "✗ Context types test failed\n";
    Printf.printf "  data: %s\n" (string_of_bpf_type typed_data.texpr_type);
    Printf.printf "  ifindex: %s\n" (string_of_bpf_type typed_ifindex.texpr_type)
  )

(** Test struct field access *)
let test_struct_field_access () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Add struct definition *)
  let packet_info_def = StructDef ("PacketInfo", [
    ("src_ip", U32);
    ("dst_ip", U32);
    ("protocol", U8);
  ]) in
  Hashtbl.replace ctx.types "PacketInfo" packet_info_def;
  
  (* Add struct variable *)
  Hashtbl.replace ctx.variables "packet" (Struct "PacketInfo");
  
  (* Test field access *)
  let packet_expr = make_expr (Identifier "packet") pos in
  let src_ip_access = make_expr (FieldAccess (packet_expr, "src_ip")) pos in
  let typed_src_ip = type_check_expression ctx src_ip_access in
  
  let protocol_access = make_expr (FieldAccess (packet_expr, "protocol")) pos in
  let typed_protocol = type_check_expression ctx protocol_access in
  
  let tests_passed = 
    typed_src_ip.texpr_type = U32 &&
    typed_protocol.texpr_type = U8 in
    
  if tests_passed then
    Printf.printf "✓ Struct field access test passed\n"
  else (
    Printf.printf "✗ Struct field access test failed\n";
    Printf.printf "  src_ip: %s\n" (string_of_bpf_type typed_src_ip.texpr_type);
    Printf.printf "  protocol: %s\n" (string_of_bpf_type typed_protocol.texpr_type)
  )

(** Test statement type checking *)
let test_statement_type_checking () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Test declaration *)
  let init_expr = make_expr (Literal (IntLit 42)) pos in
  let decl_stmt = make_stmt (Declaration ("x", Some U32, init_expr)) pos in
  let _typed_decl = type_check_statement ctx decl_stmt in
  
  (* Test assignment *)
  let new_value = make_expr (Literal (IntLit 100)) pos in
  let assign_stmt = make_stmt (Assignment ("x", new_value)) pos in
  let _typed_assign = type_check_statement ctx assign_stmt in
  
  (* Test if statement *)
  let cond = make_expr (Literal (BoolLit true)) pos in
  let then_stmts = [assign_stmt] in
  let if_stmt = make_stmt (If (cond, then_stmts, None)) pos in
  let _typed_if = type_check_statement ctx if_stmt in
  
  (* Check that variable is in context *)
  let var_in_context = Hashtbl.mem ctx.variables "x" in
  
  if var_in_context then
    Printf.printf "✓ Statement type checking test passed\n"
  else
    Printf.printf "✗ Statement type checking test failed\n"

(** Test function type checking *)
let test_function_type_checking () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Create a simple function *)
  let params = [("x", U32); ("y", U32)] in
  let return_type = Some U32 in
  let body = [
    make_stmt (Declaration ("sum", None, 
      make_expr (BinaryOp (
        make_expr (Identifier "x") pos,
        Add,
        make_expr (Identifier "y") pos
      )) pos)) pos;
    make_stmt (Return (Some (make_expr (Identifier "sum") pos))) pos;
  ] in
  let func = make_function "add_numbers" params return_type body pos in
  
  let typed_func = type_check_function ctx func in
  
  (* Check that function is registered *)
  let func_in_context = Hashtbl.mem ctx.functions "add_numbers" in
  
  let tests_passed = 
    typed_func.tfunc_return_type = U32 &&
    func_in_context in
    
  if tests_passed then
    Printf.printf "✓ Function type checking test passed\n"
  else
    Printf.printf "✗ Function type checking test failed\n"

(** Test error handling *)
let test_error_handling () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Test type mismatch in binary operation *)
  let int_expr = make_expr (Literal (IntLit 42)) pos in
  let bool_expr = make_expr (Literal (BoolLit true)) pos in
  let bad_add = make_expr (BinaryOp (int_expr, Add, bool_expr)) pos in
  
  let error_caught = try
    let _ = type_check_expression ctx bad_add in
    false
  with Type_error _ -> true in
  
  (* Test undefined struct field *)
  let packet_info_def = StructDef ("PacketInfo", [("src_ip", U32)]) in
  Hashtbl.replace ctx.types "PacketInfo" packet_info_def;
  Hashtbl.replace ctx.variables "packet" (Struct "PacketInfo");
  
  let packet_expr = make_expr (Identifier "packet") pos in
  let bad_field = make_expr (FieldAccess (packet_expr, "nonexistent")) pos in
  
  let field_error_caught = try
    let _ = type_check_expression ctx bad_field in
    false
  with Type_error _ -> true in
  
  let tests_passed = error_caught && field_error_caught in
  
  if tests_passed then
    Printf.printf "✓ Error handling test passed\n"
  else
    Printf.printf "✗ Error handling test failed\n"

(** Test comprehensive program type checking *)
let test_program_type_checking () =
  let pos = make_position 1 1 "test.ks" in
  let ctx = create_context () in
  
  (* Create a complete program *)
  let main_params = [("ctx", XdpContext)] in
  let main_return = Some XdpAction in
  let main_body = [
    make_stmt (Declaration ("packet_size", Some U32,
      make_expr (Literal (IntLit 1500)) pos)) pos;
    make_stmt (Return (Some (make_expr (Identifier "XdpAction::Pass") pos))) pos;
  ] in
  let main_func = make_function "main" main_params main_return main_body pos in
  
  let program = make_program "test_program" Xdp [main_func] pos in
  let typed_program = type_check_program ctx program in
  
  let tests_passed = 
    typed_program.tprog_name = "test_program" &&
    List.length typed_program.tprog_functions = 1 in
    
  if tests_passed then
    Printf.printf "✓ Program type checking test passed\n"
  else
    Printf.printf "✗ Program type checking test failed\n"

(** Test comprehensive type inference and validation scenario *)
let test_comprehensive_type_checking () =
  let pos = make_position 1 1 "comprehensive_test.ks" in
  
  (* Create AST with type definitions *)
  let struct_def = TypeDef (StructDef ("PacketInfo", [
    ("src_ip", U32);
    ("dst_ip", U32);
    ("protocol", U8);
  ])) in
  
  let enum_def = TypeDef (EnumDef ("FilterAction", [
    ("Allow", Some 0);
    ("Block", Some 1);
  ])) in
  
  (* Create function with complex typing *)
  let func_params = [("ctx", XdpContext); ("info", Struct "PacketInfo")] in
  let func_return = Some XdpAction in
  let func_body = [
    make_stmt (Declaration ("action", Some (Enum "FilterAction"),
      make_expr (Identifier "FilterAction::Allow") pos)) pos;
    make_stmt (Declaration ("src_ip", None,
      make_expr (FieldAccess (make_expr (Identifier "info") pos, "src_ip")) pos)) pos;
    make_stmt (Return (Some (make_expr (Identifier "XdpAction::Pass") pos))) pos;
  ] in
  let func = make_function "process_packet" func_params func_return func_body pos in
  
  let program = make_program "packet_filter" Xdp [func] pos in
  
  let ast = [struct_def; enum_def; Program program] in
  
  (* Type check the complete AST *)
  let typed_programs = try
    let _ = type_check_ast ast in
    true
  with Type_error (msg, pos) ->
    Printf.printf "Type error: %s at %s\n" msg (string_of_position pos);
    false
  in
  
  if typed_programs then
    Printf.printf "✓ Comprehensive type checking test passed\n"
  else
    Printf.printf "✗ Comprehensive type checking test failed\n"

let run_tests () =
  Printf.printf "Running KernelScript Type Checker Tests\n";
  Printf.printf "========================================\n\n";
  test_type_unification ();
  test_basic_type_inference ();
  test_variable_type_checking ();
  test_binary_operations ();
  test_function_calls ();
  test_context_types ();
  test_struct_field_access ();
  test_statement_type_checking ();
  test_function_type_checking ();
  test_error_handling ();
  test_program_type_checking ();
  test_comprehensive_type_checking ();
  Printf.printf "\nType checker tests completed.\n"

let () = run_tests () 