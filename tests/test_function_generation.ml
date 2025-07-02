(** Unit tests for non-main function generation *)

open OUnit2
open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator
open Kernelscript.Ebpf_c_codegen

let test_pos = { line = 1; column = 1; filename = "test" }

(** Test function parameter handling in eBPF C generation *)
let test_function_parameters _ =
  (* Create a simple function: fn add(a: u32, b: u32) -> u32 { return a + b } *)
  let func_params = [("a", U32); ("b", U32)] in
  let return_expr = {
    expr_desc = BinaryOp (
      { expr_desc = Identifier "a"; expr_pos = test_pos; expr_type = Some U32 },
      Add,
      { expr_desc = Identifier "b"; expr_pos = test_pos; expr_type = Some U32 }
    );
    expr_pos = test_pos;
    expr_type = Some U32;
  } in
  let func_body = [{ stmt_desc = Return (Some return_expr); stmt_pos = test_pos }] in
  let func_def = {
    func_name = "add";
    func_params = func_params;
    func_return_type = Some U32;
    func_body = func_body;
    func_scope = Ast.Userspace;
    func_pos = test_pos;
  } in
  
  (* Create program containing this function *)
  let prog_def = {
    prog_name = "test_prog";
    prog_type = Xdp;
    prog_maps = [];
    prog_structs = [];
    prog_functions = [func_def];
    prog_pos = test_pos;
  } in
  
  (* Create symbol table and type check *)
  let symbol_table = create_symbol_table () in
  let ast = [Program prog_def] in
  build_symbol_table symbol_table ast;
  
  let ctx = create_type_context () in
  let _ = type_check_multi_program ctx ast in
  
  (* Generate IR *)
  let ir_ctx = create_context symbol_table in
  let ir_program = lower_single_program ir_ctx prog_def [] in
  
  (* Generate eBPF C code *)
  let c_code = generate_c_program ir_program in
  
  (* Verify the generated code uses parameter names correctly *)
  assert_bool "Function should use parameter 'a'" (String.contains c_code 'a');
  assert_bool "Function should use parameter 'b'" (String.contains c_code 'b');
  assert_bool "Function should be named 'add'" (Str.string_match (Str.regexp ".*__u32 add(__u32 a, __u32 b).*") c_code 0);
  assert_bool "Function should use 'a + b'" (Str.string_match (Str.regexp ".*(a + b).*") c_code 0)

(** Test program-scoped function calls *)
let test_program_function_calls _ =
  (* Create helper function *)
  let helper_params = [("value", U32)] in
  let helper_return = {
    expr_desc = BinaryOp (
      { expr_desc = Identifier "value"; expr_pos = test_pos; expr_type = Some U32 },
      Mul,
      { expr_desc = Literal (IntLit (2, None)); expr_pos = test_pos; expr_type = Some U32 }
    );
    expr_pos = test_pos;
    expr_type = Some U32;
  } in
  let helper_body = [{ stmt_desc = Return (Some helper_return); stmt_pos = test_pos }] in
  let helper_func = {
    func_name = "helper";
    func_params = helper_params;
    func_return_type = Some U32;
    func_body = helper_body;
    func_scope = Ast.Userspace;
    func_pos = test_pos;
  } in
  
  (* Create main function that calls helper *)
  let main_params = [("ctx", xdp_md)] in
  let helper_call = {
    expr_desc = FunctionCall ("helper", [
      { expr_desc = Literal (IntLit (10, None)); expr_pos = test_pos; expr_type = Some U32 }
    ]);
    expr_pos = test_pos;
    expr_type = Some U32;
  } in
  let main_stmt = { stmt_desc = Declaration ("result", Some U32, helper_call); stmt_pos = test_pos } in
  let main_return = { stmt_desc = Return (Some {
    expr_desc = Identifier "XDP_PASS"; expr_pos = test_pos; expr_type = Some xdp_action
  }); stmt_pos = test_pos } in
  let main_func = {
    func_name = "main";
    func_params = main_params;
    func_return_type = Some xdp_action;
    func_body = [main_stmt; main_return];
    func_scope = Ast.Userspace;
    func_pos = test_pos;
  } in
  
  (* Create program with both functions *)
  let prog_def = {
    prog_name = "test_prog";
    prog_type = Xdp;
    prog_maps = [];
    prog_structs = [];
    prog_functions = [helper_func; main_func];
    prog_pos = test_pos;
  } in
  
  (* Process and generate code *)
  let symbol_table = create_symbol_table () in
  let ast = [Program prog_def] in
  build_symbol_table symbol_table ast;
  
  let ctx = create_type_context () in
  let _ = type_check_multi_program ctx ast in
  
  let ir_ctx = create_context symbol_table in
  let ir_program = lower_single_program ir_ctx prog_def [] in
  let c_code = generate_c_program ir_program in
  
  (* Verify both functions are generated *)
  assert_bool "Should generate helper function" (Str.string_match (Str.regexp ".*__u32 helper(__u32 value).*") c_code 0);
  assert_bool "Should generate main function" (Str.string_match (Str.regexp ".*int test_prog(struct xdp_md\\* ctx).*") c_code 0);
  assert_bool "Helper should use parameter correctly" (Str.string_match (Str.regexp ".*(value \\* 2).*") c_code 0);
  assert_bool "Main should call helper" (Str.string_match (Str.regexp ".*helper(10).*") c_code 0)

(** Test functions with multiple parameters *)
let test_multiple_parameters _ =
  (* Create function with 3 parameters *)
  let func_params = [("a", U32); ("b", U32); ("c", U32)] in
  let expr1 = {
    expr_desc = BinaryOp (
      { expr_desc = Identifier "a"; expr_pos = test_pos; expr_type = Some U32 },
      Add,
      { expr_desc = Identifier "b"; expr_pos = test_pos; expr_type = Some U32 }
    );
    expr_pos = test_pos;
    expr_type = Some U32;
  } in
  let return_expr = {
    expr_desc = BinaryOp (expr1, Add, 
      { expr_desc = Identifier "c"; expr_pos = test_pos; expr_type = Some U32 });
    expr_pos = test_pos;
    expr_type = Some U32;
  } in
  let func_body = [{ stmt_desc = Return (Some return_expr); stmt_pos = test_pos }] in
  let func_def = {
    func_name = "add_three";
    func_params = func_params;
    func_return_type = Some U32;
    func_body = func_body;
    func_scope = Ast.Userspace;
    func_pos = test_pos;
  } in
  
  (* Create minimal program *)
  let main_func = {
    func_name = "main";
    func_params = [("ctx", xdp_md)];
    func_return_type = Some xdp_action;
    func_body = [{ stmt_desc = Return (Some {
      expr_desc = Identifier "XDP_PASS"; expr_pos = test_pos; expr_type = Some xdp_action
    }); stmt_pos = test_pos }];
    func_scope = Ast.Userspace;
    func_pos = test_pos;
  } in
  
  let prog_def = {
    prog_name = "test_prog";
    prog_type = Xdp;
    prog_maps = [];
    prog_structs = [];
    prog_functions = [func_def; main_func];
    prog_pos = test_pos;
  } in
  
  (* Process and generate *)
  let symbol_table = create_symbol_table () in
  let ast = [Program prog_def] in
  build_symbol_table symbol_table ast;
  
  let ctx = create_type_context () in
  let _ = type_check_multi_program ctx ast in
  
  let ir_ctx = create_context symbol_table in
  let ir_program = lower_single_program ir_ctx prog_def [] in
  let c_code = generate_c_program ir_program in
  
  (* Verify all parameters are used correctly *)
  assert_bool "Should use parameter 'a'" (String.contains c_code 'a');
  assert_bool "Should use parameter 'b'" (String.contains c_code 'b');
  assert_bool "Should use parameter 'c'" (String.contains c_code 'c');
  assert_bool "Function signature should be correct" 
    (Str.string_match (Str.regexp ".*__u32 add_three(__u32 a, __u32 b, __u32 c).*") c_code 0)

let suite = "Function Generation Tests" >::: [
  "test_function_parameters" >:: test_function_parameters;
  "test_program_function_calls" >:: test_program_function_calls;
  "test_multiple_parameters" >:: test_multiple_parameters;
]

let () = run_test_tt_main suite 