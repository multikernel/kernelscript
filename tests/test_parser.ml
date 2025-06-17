open Kernelscript.Ast
open Kernelscript.Parse
open Alcotest

(** Helper functions for creating AST nodes in tests *)

let dummy_loc = {
  line = 1;
  column = 1;
  filename = "test";
}

let make_int_lit value =   {
  expr_desc = Literal (IntLit value);
  expr_type = Some U32;
  expr_pos = dummy_loc;
  type_checked = false;
  program_context = None;
  map_scope = None;
}

let make_id name = {
  expr_desc = Identifier name;
  expr_type = None;
  expr_pos = dummy_loc;
  type_checked = false;
  program_context = None;
  map_scope = None;
}

let make_binop left op right = {
  expr_desc = BinaryOp (left, op, right);
  expr_type = None;
  expr_pos = dummy_loc;
  type_checked = false;
  program_context = None;
  map_scope = None;
}

let make_call name args = {
  expr_desc = FunctionCall (name, args);
  expr_type = None;
  expr_pos = dummy_loc;
  type_checked = false;
  program_context = None;
  map_scope = None;
}

let make_decl name expr = {
  stmt_desc = Declaration (name, None, expr);
  stmt_pos = dummy_loc;
}

let make_for_stmt var start_expr end_expr body = {
  stmt_desc = For (var, start_expr, end_expr, body);
  stmt_pos = dummy_loc;
}

let make_for_iter_stmt index_var value_var expr body = {
  stmt_desc = ForIter (index_var, value_var, expr, body);
  stmt_pos = dummy_loc;
}

(** Helper function to test parsing statements *)
let test_parse_statements input expected =
  let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    %s
    return 0
  }
}
|} input in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let actual_stmts = List.rev (List.tl (List.rev main_func.func_body)) in
        check int "statement count" (List.length expected) (List.length actual_stmts)
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse statements: " ^ Printexc.to_string e)

(** Test simple program parsing *)
let test_simple_program () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    check int "AST length" 1 (List.length ast);
    match List.hd ast with
    | Program prog -> 
        check string "program name" "test" prog.prog_name;
        check bool "program type" true (prog.prog_type = Xdp);
        check int "function count" 1 (List.length prog.prog_functions)
    | _ -> fail "Expected program declaration"
  with
  | _ -> fail "Failed to parse simple program"

(** Test expression parsing *)
let test_expression_parsing () =
  let expressions = [
    ("42", true);
    ("x + y", true);
    ("func(a, b)", true);
    ("arr[index]", true);
    ("obj.field", true);
    ("(x + y) * z", true);
    ("!condition", true);
    ("-value", true);
  ] in
  
  List.iter (fun (expr_text, should_succeed) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    let result = %s
    return 0
  }
}
|} expr_text in
    try
      let _ = parse_string program_text in
      check bool ("expression parsing: " ^ expr_text) should_succeed true
    with
    | _ -> check bool ("expression parsing: " ^ expr_text) should_succeed false
  ) expressions

(** Test statement parsing *)
let test_statement_parsing () =
  let statements = [
    ("let x = 42", true);
    ("let y: u32 = 100", true);
    ("x = 50", true);
    ("return x", true);
    ("return", true);
    ("if condition { return 1 }", true);
    ("if x > 0 { return 1 } else { return 0 }", true);
  ] in
  
  List.iter (fun (stmt_text, should_succeed) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    %s
    return 0
  }
}
|} stmt_text in
    try
      let _ = parse_string program_text in
      check bool ("statement parsing: " ^ stmt_text) should_succeed true
    with
    | _ -> check bool ("statement parsing: " ^ stmt_text) should_succeed false
  ) statements

(** Test function declaration parsing *)
let test_function_declaration () =
  let program_text = {|
program test : xdp {
  fn helper(x: u32, y: u32) -> u32 {
    return x + y
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let result = helper(10, 20)
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        check int "function count" 2 (List.length prog.prog_functions);
        let helper_func = List.find (fun f -> f.func_name = "helper") prog.prog_functions in
        check int "helper parameters" 2 (List.length helper_func.func_params);
        check bool "helper return type" true (helper_func.func_return_type = Some U32)
    | _ -> fail "Expected program declaration"
  with
  | _ -> fail "Failed to parse function declarations"

(** Test program type parsing *)
let test_program_types () =
  let program_types = [
    ("xdp", Xdp);
    ("tc", Tc);
    ("kprobe", Kprobe);
    ("uprobe", Uprobe);
    ("tracepoint", Tracepoint);
  ] in
  
  List.iter (fun (type_text, expected_type) ->
    let program_text = Printf.sprintf {|
program test : %s {
  fn main() -> u32 {
    return 0
  }
}
|} type_text in
    try
      let ast = parse_string program_text in
      match List.hd ast with
      | Program prog -> 
          check bool ("program type: " ^ type_text) true (prog.prog_type = expected_type)
      | _ -> fail "Expected program declaration"
    with
    | _ -> fail ("Failed to parse program type: " ^ type_text)
  ) program_types

(** Test BPF type parsing *)
let test_bpf_type_parsing () =
  let types = [
    ("u8", U8);
    ("u32", U32);
    ("u64", U64);
    ("bool", Bool);
    ("char", Char);
  ] in
  
  List.iter (fun (type_text, expected_type) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    let x: %s = 0
    return 0
  }
}
|} type_text in
    try
      let ast = parse_string program_text in
      match List.hd ast with
      | Program prog -> 
          let main_func = List.hd prog.prog_functions in
          let decl_stmt = List.hd main_func.func_body in
          (match decl_stmt.stmt_desc with
           | Declaration (_, Some parsed_type, _) ->
               check bool ("BPF type: " ^ type_text) true (parsed_type = expected_type)
           | _ -> fail "Expected declaration statement")
      | _ -> fail "Expected program declaration"
    with
    | _ -> fail ("Failed to parse BPF type: " ^ type_text)
  ) types

(** Test control flow parsing *)
let test_control_flow_parsing () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 10
    
    if x > 5 {
      x = x + 1
    } else {
      x = x - 1
    }
    
    while x > 0 {
      x = x - 1
    }
    
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        check bool "control flow statements" true (List.length main_func.func_body >= 4)
    | _ -> fail "Expected program declaration"
  with
  | _ -> fail "Failed to parse control flow"

(** Test error handling *)
let test_error_handling () =
  let invalid_programs = [
    "invalid syntax";
    "program test { }";  (* missing type *)
    "program test : xdp { fn main() }";  (* missing return type *)
    "program test : xdp { fn main() -> u32 }";  (* missing body *)
  ] in
  
  List.iter (fun invalid_text ->
    try
      let _ = parse_string invalid_text in
      fail ("Should have failed to parse: " ^ invalid_text)
    with
    | _ -> check bool ("error handling: " ^ invalid_text) true true
  ) invalid_programs

(** Test operator precedence *)
let test_operator_precedence () =
  let program_text = {|
program test : xdp {
  fn main() -> u32 {
    let result = 1 + 2 * 3
    let comparison = x < y && a > b
    let complex = (a + b) * c - d / e
    return 0
  }
}
|} in
  try
    let _ = parse_string program_text in
    check bool "operator precedence parsing" true true
  with
  | _ -> fail "Failed to parse operator precedence"

(** Test complete program parsing *)
let test_complete_program_parsing () =
  let program_text = {|
map<u32, u64> packet_count : HashMap(1024) { }

program packet_filter : xdp {
  fn process_packet(src_ip: u32) -> u64 {
    let count = packet_count[src_ip]
    packet_count[src_ip] = count + 1
    return count
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let src_ip = 0x12345678
    let count = process_packet(src_ip)
    
    if count > 100 {
      return 1  // DROP
    }
    
    return 2  // PASS
  }
}
|} in
  try
    let ast = parse_string program_text in
    check int "complete program AST length" 2 (List.length ast);
    
    (* Check map declaration *)
    (match List.hd ast with
     | MapDecl map_decl -> 
         check string "map name" "packet_count" map_decl.name;
         check bool "map key type" true (map_decl.key_type = U32);
         check bool "map value type" true (map_decl.value_type = U64)
     | _ -> fail "Expected map declaration");
    
    (* Check program declaration *)
    (match List.nth ast 1 with
     | Program prog -> 
         check string "program name" "packet_filter" prog.prog_name;
         check int "program functions" 2 (List.length prog.prog_functions)
     | _ -> fail "Expected program declaration")
  with
  | _ -> fail "Failed to parse complete program"

(** Test simple if statement without else *)
let test_simple_if () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 10
    if x > 5 {
      return 1
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, None) ->
              check int "then branch has statements" 1 (List.length then_stmts);
              check bool "no else branch" true (None = None)
         | _ -> fail "Expected if statement without else")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse simple if: " ^ Printexc.to_string e)

(** Test if-else statement *)
let test_if_else () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 10
    if x > 15 {
      return 1
    } else {
      return 2
    }
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, Some else_stmts) ->
              check int "then branch has statements" 1 (List.length then_stmts);
              check int "else branch has statements" 1 (List.length else_stmts)
         | _ -> fail "Expected if-else statement")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse if-else: " ^ Printexc.to_string e)

(** Test if-else if-else chain *)
let test_if_else_if_else () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 10
    if x > 20 {
      return 1
    } else if x > 10 {
      return 2
    } else if x > 5 {
      return 3 
    } else {
      return 4
    }
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, Some else_stmts) ->
              check int "first then branch" 1 (List.length then_stmts);
              check int "else contains nested if" 1 (List.length else_stmts);
             (* Check that else contains another if statement *)
             (match (List.hd else_stmts).stmt_desc with
              | If (_, _, Some _) -> check bool "nested if-else" true true
              | _ -> fail "Expected nested if in else branch")
         | _ -> fail "Expected if-else chain")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse if-else-if-else: " ^ Printexc.to_string e)

(** Test nested if statements *)
let test_nested_if () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 10
    let y = 20
    if x > 5 {
      if y > 15 {
        return 1
      } else {
        return 2
      }
    } else {
      return 3
    }
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let if_stmt = List.nth main_func.func_body 2 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, Some _) ->
              check int "outer then branch" 1 (List.length then_stmts);
              (* Check nested if in then branch *)
              (match (List.hd then_stmts).stmt_desc with
               | If (_, nested_then, Some nested_else) -> 
                   check int "nested then" 1 (List.length nested_then);
                   check int "nested else" 1 (List.length nested_else)
               | _ -> fail "Expected nested if in then branch")
         | _ -> fail "Expected nested if statement")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse nested if: " ^ Printexc.to_string e)

(** Test if statements with multiple statements in branches *)
let test_multiple_statements_in_branches () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 10
    if x > 5 {
      let y = x + 1
      let z = y * 2
      x = z - 1
      return 1
    } else {
      x = x - 1
      let w = x / 2  
      return 2
    }
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, Some else_stmts) ->
              check int "then branch multiple statements" 4 (List.length then_stmts);
              check int "else branch multiple statements" 3 (List.length else_stmts)
         | _ -> fail "Expected if statement with multiple statements")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse multiple statements: " ^ Printexc.to_string e)

(** Test that SPEC-compliant syntax works correctly *)
let test_spec_compliant_syntax () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let x = 10
    let y = 20
    
    // SPEC-compliant syntax without parentheses around condition
    if x > 5 {
      return 1
    }
    
    // Complex conditions should also work without parens
    if x > 5 && y < 25 {
      return 2
    }
    
    // Parentheses for grouping expressions should still work
    if (x + y) > 25 {
      return 3
    }
    
    return 0
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        (* Should have multiple if statements *)
        check bool "SPEC-compliant syntax works" true (List.length main_func.func_body >= 6)
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse SPEC-compliant syntax: " ^ Printexc.to_string e)

(** Test if statement error cases *)
let test_if_error_cases () =
  let error_cases = [
    ("missing condition", {|
program test : xdp {
  fn main() -> u32 {
    if {
      return 1
    }
    return 0
  }
}
|});
    ("missing braces", {|
program test : xdp {
  fn main() -> u32 {
    if x > 5
      return 1
    return 0
  }
}
|});
  ] in
  
  List.iter (fun (desc, code) ->
    try
      let _ = parse_string code in
      fail ("Should have failed: " ^ desc)
    with
    | Parse_error (_, _) -> check bool ("error case: " ^ desc) true true
    | _ -> fail ("Expected parse error for: " ^ desc)
  ) error_cases

(** Test simple for loop *)
let test_simple_for_loop () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for i in 0..10 {
      return 1
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let for_stmt = List.hd main_func.func_body in
        (match for_stmt.stmt_desc with
         | For (var, _, _, body) ->
             check string "for loop variable" "i" var;
             check int "for loop body has statements" 1 (List.length body)
         | _ -> fail "Expected for loop")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse simple for loop: " ^ Printexc.to_string e)

(** Test for loop with expressions *)
let test_for_loop_with_expressions () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let count = 5
    for i in 0..count {
      let x = i * 2
      x = x + 1
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let for_stmt = List.nth main_func.func_body 1 in
        (match for_stmt.stmt_desc with
         | For (var, _, _, body) ->
             check string "for loop variable" "i" var;
             check int "for loop body has statements" 2 (List.length body)
         | _ -> fail "Expected for loop")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse for loop with expressions: " ^ Printexc.to_string e)

(** Test for iter syntax support *)
let test_for_iter_syntax () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for (i, v) in array.iter() {
      return v
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let for_stmt = List.hd main_func.func_body in
        (match for_stmt.stmt_desc with
         | ForIter (index_var, value_var, _, body) ->
             check string "for iter index variable" "i" index_var;
             check string "for iter value variable" "v" value_var;
             check int "for iter body has statements" 1 (List.length body)
         | _ -> fail "Expected for iter loop")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse for iter syntax: " ^ Printexc.to_string e)

(** Test nested for loops *)
let test_nested_for_loops () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    for i in 0..3 {
      for j in 0..2 {
        return 1
      }
    }
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let outer_for = List.hd main_func.func_body in
        (match outer_for.stmt_desc with
         | For (_, _, _, outer_body) ->
             check int "outer for loop body has statements" 1 (List.length outer_body);
             (* Check nested for loop *)
             let inner_for = List.hd outer_body in
             (match inner_for.stmt_desc with
              | For (_, _, _, inner_body) ->
                  check int "inner for loop body has statements" 1 (List.length inner_body)
              | _ -> fail "Expected nested for loop")
         | _ -> fail "Expected outer for loop")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse nested for loops: " ^ Printexc.to_string e)

(** Test for loop edge cases *)
let test_for_loop_edge_cases () =
  let test_cases = [
    (* Zero range - should work *)
    ("for i in 5..5 { let x = i }", 
     [make_for_stmt "i" (make_int_lit 5) (make_int_lit 5) [make_decl "x" (make_id "i")]]);
    
    (* Variable bounds - should work but be unbounded *)
    ("for j in start..(end + 1) { let y = j }", 
     [make_for_stmt "j" (make_id "start") 
       (make_binop (make_id "end") Add (make_int_lit 1)) [make_decl "y" (make_id "j")]]);
  ] in
  List.iter (fun (input, expected) ->
    test_parse_statements input expected
  ) test_cases

let test_for_comprehensive () =
  let input = "for i in 0..3 { let x = i } for j in start..end { let y = j } for (idx, val) in array.iter() { let z = val }" in
  let expected = [
    make_for_stmt "i" (make_int_lit 0) (make_int_lit 3) [make_decl "x" (make_id "i")];
    make_for_stmt "j" (make_id "start") (make_id "end") [make_decl "y" (make_id "j")];
    make_for_iter_stmt "idx" "val" (make_call "array.iter" []) [make_decl "z" (make_id "val")];
  ] in
  test_parse_statements input expected

let test_loop_bounds_analysis () =
  (* Test that we can parse different kinds of loop bounds *)
  let input = "for i in 0..5 { let x = i } for j in variable..end { let y = j }" in
  let expected = [
    make_for_stmt "i" (make_int_lit 0) (make_int_lit 5) [make_decl "x" (make_id "i")];
    make_for_stmt "j" (make_id "variable") (make_id "end") [make_decl "y" (make_id "j")];
  ] in
  test_parse_statements input expected

let parser_tests = [
  "simple_program", `Quick, test_simple_program;
  "expression_parsing", `Quick, test_expression_parsing;
  "statement_parsing", `Quick, test_statement_parsing;
  "function_declaration", `Quick, test_function_declaration;
  "program_types", `Quick, test_program_types;
  "bpf_type_parsing", `Quick, test_bpf_type_parsing;
  "control_flow_parsing", `Quick, test_control_flow_parsing;
  "simple_if", `Quick, test_simple_if;
  "if_else", `Quick, test_if_else;
  "if_else_if_else", `Quick, test_if_else_if_else;
  "nested_if", `Quick, test_nested_if;
  "multiple_statements_in_branches", `Quick, test_multiple_statements_in_branches;
  "spec_compliant_syntax", `Quick, test_spec_compliant_syntax;
  "if_error_cases", `Quick, test_if_error_cases;
  "error_handling", `Quick, test_error_handling;
  "operator_precedence", `Quick, test_operator_precedence;
  "complete_program_parsing", `Quick, test_complete_program_parsing;
  "simple_for_loop", `Quick, test_simple_for_loop;
  "for_loop_with_expressions", `Quick, test_for_loop_with_expressions;
  "for_iter_syntax", `Quick, test_for_iter_syntax;
  "nested_for_loops", `Quick, test_nested_for_loops;
  "for_loop_edge_cases", `Quick, test_for_loop_edge_cases;
  "test_for_comprehensive", `Quick, test_for_comprehensive;
  "test_loop_bounds_analysis", `Quick, test_loop_bounds_analysis;
]

let () =
  run "KernelScript Parser Tests" [
    "parser", parser_tests;
  ] 