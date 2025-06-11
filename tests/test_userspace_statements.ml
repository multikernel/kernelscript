open Alcotest
open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Userspace_codegen

(** Helper function to create test expressions and statements *)
let dummy_loc = {
  line = 1;
  column = 1;
  filename = "test";
}

let make_test_pos () = dummy_loc

let make_int_literal value =
  { expr_desc = Literal (IntLit value); expr_pos = make_test_pos (); 
    expr_type = None; type_checked = false; program_context = None; map_scope = None }

let make_identifier name =
  { expr_desc = Identifier name; expr_pos = make_test_pos (); 
    expr_type = None; type_checked = false; program_context = None; map_scope = None }

let make_binary_op left op right =
  { expr_desc = BinaryOp (left, op, right); expr_pos = make_test_pos (); 
    expr_type = None; type_checked = false; program_context = None; map_scope = None }

let make_if_stmt condition then_stmts else_stmts_opt =
  { stmt_desc = If (condition, then_stmts, else_stmts_opt); stmt_pos = make_test_pos () }

let make_break_stmt () =
  { stmt_desc = Break; stmt_pos = make_test_pos () }

let make_continue_stmt () =
  { stmt_desc = Continue; stmt_pos = make_test_pos () }

let make_declaration name value =
  { stmt_desc = Declaration (name, Some U32, value); stmt_pos = make_test_pos () }

let make_assignment name value =
  { stmt_desc = Assignment (name, value); stmt_pos = make_test_pos () }

let make_for_stmt loop_var start_expr end_expr body =
  { stmt_desc = For (loop_var, start_expr, end_expr, body); stmt_pos = make_test_pos () }

(** Helper function to check if generated code contains a pattern *)
let contains_pattern code pattern =
  try
    let regex = Str.regexp pattern in
    ignore (Str.search_forward regex code 0);
    true
  with Not_found -> false

(** Generate userspace code from a statement *)
let get_userspace_statement_code stmt =
  let ctx = create_userspace_context () in
  generate_c_statement_with_context ctx stmt

(** Test 1: Basic If statement without else clause *)
let test_basic_if_statement () =
  let condition = make_binary_op (make_identifier "x") Eq (make_int_literal 5) in
  let then_body = [make_assignment "result" (make_int_literal 1)] in
  let if_stmt = make_if_stmt condition then_body None in
  let result = get_userspace_statement_code if_stmt in
  
  check bool "generates if keyword" true (contains_pattern result "if");
  check bool "has condition with equality" true (contains_pattern result "(x == 5)");
  check bool "has opening brace" true (contains_pattern result "{");
  check bool "has closing brace" true (contains_pattern result "}");
  check bool "contains then body" true (contains_pattern result "result = 1");
  check bool "no else clause" false (contains_pattern result "else");
  ()

(** Test 2: If statement with else clause *)
let test_if_else_statement () =
  let condition = make_binary_op (make_identifier "count") Gt (make_int_literal 10) in
  let then_body = [make_assignment "status" (make_int_literal 1)] in
  let else_body = [make_assignment "status" (make_int_literal 0)] in
  let if_stmt = make_if_stmt condition then_body (Some else_body) in
  let result = get_userspace_statement_code if_stmt in
  
  check bool "generates if keyword" true (contains_pattern result "if");
  check bool "has condition with greater than" true (contains_pattern result "(count > 10)");
  check bool "has then body" true (contains_pattern result "status = 1");
  check bool "has else keyword" true (contains_pattern result "else");
  check bool "has else body" true (contains_pattern result "status = 0");
  check bool "proper brace structure" true (contains_pattern result "} else {");
  ()

(** Test 3: Break statement generation *)
let test_break_statement () =
  let break_stmt = make_break_stmt () in
  let result = get_userspace_statement_code break_stmt in
  
  check string "generates break statement" "break;" result;
  ()

(** Test 4: Continue statement generation *)
let test_continue_statement () =
  let continue_stmt = make_continue_stmt () in
  let result = get_userspace_statement_code continue_stmt in
  
  check string "generates continue statement" "continue;" result;
  ()

(** Test 5: If statement with break inside for loop *)
let test_if_with_break_in_loop () =
  let condition = make_binary_op (make_identifier "i") Eq (make_int_literal 5) in
  let then_body = [make_break_stmt ()] in
  let if_stmt = make_if_stmt condition then_body None in
  let for_body = [if_stmt; make_assignment "count" (make_binary_op (make_identifier "count") Add (make_int_literal 1))] in
  let for_stmt = make_for_stmt "i" (make_int_literal 0) (make_int_literal 10) for_body in
  let result = get_userspace_statement_code for_stmt in
  
  check bool "generates for loop" true (contains_pattern result "for");
  check bool "has if condition" true (contains_pattern result "if.*i == 5");
  check bool "has break statement" true (contains_pattern result "break;");
  check bool "has assignment after if" true (contains_pattern result "count.*count.*1");
  ()

(** Test 6: If statement with continue inside for loop *)
let test_if_with_continue_in_loop () =
  let condition = make_binary_op (make_identifier "i") Mod (make_int_literal 2) in
  let condition_eq = make_binary_op condition Eq (make_int_literal 0) in
  let then_body = [make_continue_stmt ()] in
  let if_stmt = make_if_stmt condition_eq then_body None in
  let for_body = [if_stmt; make_assignment "sum" (make_binary_op (make_identifier "sum") Add (make_identifier "i"))] in
  let for_stmt = make_for_stmt "i" (make_int_literal 1) (make_int_literal 10) for_body in
  let result = get_userspace_statement_code for_stmt in
  
  check bool "generates for loop" true (contains_pattern result "for");
  check bool "has modulo condition" true (contains_pattern result "i % 2.*== 0");
  check bool "has continue statement" true (contains_pattern result "continue;");
  check bool "has sum assignment" true (contains_pattern result "sum.*sum.*i");
  ()

(** Test 7: Complex binary operators in if conditions *)
let test_complex_binary_operators () =
  let test_cases = [
    (Lt, "<", "less than");
    (Le, "<=", "less than or equal");
    (Gt, ">", "greater than");
    (Ge, ">=", "greater than or equal");
    (Ne, "!=", "not equal");
    (And, "&&", "logical and");
    (Or, "||", "logical or");
    (Div, "/", "division");
    (Mod, "%", "modulo");
  ] in
  
  List.iter (fun (op, expected_c, desc) ->
    let condition = make_binary_op (make_identifier "a") op (make_identifier "b") in
    let then_body = [make_assignment "result" (make_int_literal 1)] in
    let if_stmt = make_if_stmt condition then_body None in
    let result = get_userspace_statement_code if_stmt in
    
    check bool (desc ^ " operator") true (contains_pattern result ("a " ^ expected_c ^ " b"));
  ) test_cases;
  ()

(** Test 8: Nested if statements *)
let test_nested_if_statements () =
  let outer_condition = make_binary_op (make_identifier "x") Gt (make_int_literal 0) in
  let inner_condition = make_binary_op (make_identifier "y") Lt (make_int_literal 10) in
  let inner_then = [make_assignment "result" (make_int_literal 42)] in
  let inner_if = make_if_stmt inner_condition inner_then None in
  let outer_then = [inner_if] in
  let outer_if = make_if_stmt outer_condition outer_then None in
  let result = get_userspace_statement_code outer_if in
  
  check bool "has outer if" true (contains_pattern result "if.*x > 0");
  check bool "has inner if" true (contains_pattern result "if.*y < 10");
  check bool "has nested assignment" true (contains_pattern result "result = 42");
  check bool "has opening braces" true (contains_pattern result "{");
  check bool "has closing braces" true (contains_pattern result "}");
  ()

(** Test 9: Integration test with complete userspace program *)
let test_complete_userspace_program_with_if_break_continue () =
  let program_text = {|
map<u32, u64> test_map : HashMap(1024);

program test_prog : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2;
    }
}

userspace {
    fn main(argc: u32, argv: u64) -> i32 {
        let total: u32 = 0;
        let count: u32 = 0;
        
        for i in 0..20 {
            if i < 3 {
                continue;
            }
            
            if i % 2 == 0 {
                count = count + 1;
                continue;
            }
            
            if i > 15 {
                break;
            }
            
            total = total + i;
        }
        
        return 0;
    }
}
|} in
  
  try
    let ast = parse_string program_text in
    let temp_dir = Filename.temp_file "test_userspace_complete" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    let _output_file = generate_userspace_code_from_ast ast ~output_dir:temp_dir "test_complete.ks" in
    let generated_file = Filename.concat temp_dir "test_complete.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      (* Verify all statement types are properly generated *)
      check bool "has for loop" true (contains_pattern content "for.*i.*0.*20");
      check bool "has first if condition" true (contains_pattern content "if.*i < 3");
      check bool "has continue statement" true (contains_pattern content "continue;");
      check bool "has modulo condition" true (contains_pattern content "i % 2.*== 0");
      check bool "has break statement" true (contains_pattern content "break;");
      check bool "has assignment" true (contains_pattern content "total.*total.*i");
      
      (* Verify no TODO statements *)
      check bool "no unsupported statements" false (contains_pattern content "TODO: Unsupported statement");
      
      (* Verify proper C syntax *)
      check bool "proper if syntax" true (contains_pattern content "if.*{");
      check bool "proper break syntax" true (contains_pattern content "break;");
      check bool "proper continue syntax" true (contains_pattern content "continue;");
    ) else (
      fail "Failed to generate userspace code file"
    );
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 10: Error case - unsupported statement should still show TODO *)
let test_unsupported_statement_fallback () =
  (* Create a statement that should fall through to the TODO case *)
  (* We'll use While which might not be implemented *)
  let while_condition = make_binary_op (make_identifier "running") Eq (make_int_literal 1) in
  let while_body = [make_assignment "counter" (make_binary_op (make_identifier "counter") Add (make_int_literal 1))] in
  let while_stmt = { stmt_desc = While (while_condition, while_body); stmt_pos = make_test_pos () } in
  let result = get_userspace_statement_code while_stmt in
  
  (* While loops might not be implemented, so should show TODO *)
  check bool "unsupported statement shows TODO" true (contains_pattern result "TODO: Unsupported statement");
  ()

(** All userspace statement tests *)
let userspace_statement_tests = [
  "basic_if_statement", `Quick, test_basic_if_statement;
  "if_else_statement", `Quick, test_if_else_statement;
  "break_statement", `Quick, test_break_statement;
  "continue_statement", `Quick, test_continue_statement;
  "if_with_break_in_loop", `Quick, test_if_with_break_in_loop;
  "if_with_continue_in_loop", `Quick, test_if_with_continue_in_loop;
  "complex_binary_operators", `Quick, test_complex_binary_operators;
  "nested_if_statements", `Quick, test_nested_if_statements;
  "complete_userspace_program", `Quick, test_complete_userspace_program_with_if_break_continue;
  "unsupported_statement_fallback", `Quick, test_unsupported_statement_fallback;
]

let () =
  run "KernelScript Userspace Statement Codegen Tests" [
    "userspace_statements", userspace_statement_tests;
] 