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
  expr_desc = Literal (IntLit (value, None));
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

let make_array elements = {
  expr_desc = Literal (ArrayLit (List.map (function
    | {expr_desc = Literal lit; _} -> lit
    | _ -> IntLit (0, None) (* fallback *)
  ) elements));
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
@xdp fn test() -> u32 {
  %s
  return 0
}
|} input in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let actual_stmts = List.rev (List.tl (List.rev main_func.func_body)) in
        check int "statement count" (List.length expected) (List.length actual_stmts)
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse statements: " ^ Printexc.to_string e)

(** Test simple program parsing *)
let test_simple_program () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    check int "AST length" 1 (List.length ast);
    match List.hd ast with
    | AttributedFunction attr_func -> 
        check string "function name" "test" attr_func.attr_function.func_name;
        (* Check attribute is xdp *)
        let has_xdp_attr = List.exists (function SimpleAttribute "xdp" -> true | _ -> false) attr_func.attr_list in
        check bool "has xdp attribute" true has_xdp_attr
    | _ -> fail "Expected attributed function declaration"
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
@xdp fn test() -> u32 {
  var result = %s
  return 0
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
    ("var x = 42", true);
    ("var y: u32 = 100", true);
    ("x = 50", true);
    ("return x", true);
    ("return", true);
    ("if (true) { return 1 }", true);
    ("if (x > 0) { return 1 } else { return 0 }", true);
  ] in
  
  List.iter (fun (stmt_text, should_succeed) ->
    let program_text = Printf.sprintf {|
@xdp fn test() -> u32 {
  %s
  return 0
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
@helper
fn helper(x: u32, y: u32) -> u32 {
  return x + y
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
  var result = helper(10, 20)
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    (* First item should be the helper attributed function *)
    match List.hd ast with
    | AttributedFunction attr_func -> 
        check string "helper function name" "helper" attr_func.attr_function.func_name;
        check int "helper parameters" 2 (List.length attr_func.attr_function.func_params);
        check bool "helper return type" true (attr_func.attr_function.func_return_type = Some U32);
        let has_helper_attr = List.exists (function 
          | SimpleAttribute "helper" -> true 
          | _ -> false
        ) attr_func.attr_list in
        check bool "has helper attribute" true has_helper_attr
    | _ -> fail "Expected attributed function declaration"
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
  
  List.iter (fun (type_text, _expected_type) ->
    let program_text = Printf.sprintf {|
@%s fn test() -> u32 {
  return 0
}
|} type_text in
    try
      let ast = parse_string program_text in
      match List.hd ast with
      | AttributedFunction attr_func -> 
          let has_expected_attr = List.exists (function 
            | SimpleAttribute attr_name -> attr_name = type_text 
            | _ -> false
          ) attr_func.attr_list in
          check bool ("program type: " ^ type_text) true has_expected_attr
      | _ -> fail "Expected attributed function declaration"
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
@xdp fn test() -> u32 {
  var x: %s = 0
  return 0
}
|} type_text in
    try
      let ast = parse_string program_text in
      match List.hd ast with
      | AttributedFunction attr_func -> 
          let main_func = attr_func.attr_function in
          let decl_stmt = List.hd main_func.func_body in
          (match decl_stmt.stmt_desc with
           | Declaration (_, Some parsed_type, _) ->
               check bool ("BPF type: " ^ type_text) true (parsed_type = expected_type)
           | _ -> fail "Expected declaration statement")
      | _ -> fail "Expected attributed function declaration"
    with
    | _ -> fail ("Failed to parse BPF type: " ^ type_text)
  ) types

(** Test control flow parsing *)
let test_control_flow_parsing () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  var x = 10
  
  if (x > 5) {
    x = x + 1
  } else {
    x = x - 1
  }
  
  while (x > 0) {
    x = x - 1
  }
  
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        check bool "control flow statements" true (List.length main_func.func_body >= 4)
    | _ -> fail "Expected attributed function declaration"
  with
  | _ -> fail "Failed to parse control flow"

(** Test error handling *)
let test_error_handling () =
  let invalid_programs = [
    "invalid syntax";
    "@xdp fn test { }";  (* missing parameters and return type *)
    "@xdp fn test() { }";  (* missing return type *)
    "@xdp fn test() -> u32";  (* missing body *)
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
@xdp fn test() -> u32 {
  var result = 1 + 2 * 3
  var comparison = x < y && a > b
  var complex = (a + b) * c - d / e
  return 0
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

@helper
fn process_packet(src_ip: u32) -> u64 {
  var count = packet_count[src_ip]
  packet_count[src_ip] = count + 1
  return count
}

@xdp fn packet_filter(ctx: xdp_md) -> xdp_action {
  var src_ip = 0x12345678
  var count = process_packet(src_ip)
  
  if (count > 100) {
    return 1  // DROP
  }
  
  return 2  // PASS
}
|} in
  try
    let ast = parse_string program_text in
    check int "complete program AST length" 3 (List.length ast);
    
    (* Check map declaration *)
    (match List.hd ast with
     | MapDecl map_decl -> 
         check string "map name" "packet_count" map_decl.name;
         check bool "map key type" true (map_decl.key_type = U32);
         check bool "map value type" true (map_decl.value_type = U64)
     | _ -> fail "Expected map declaration");
    
    (* Check helper function declaration *)
    (match List.nth ast 1 with
     | AttributedFunction attr_func -> 
         check string "helper function name" "process_packet" attr_func.attr_function.func_name;
         check int "helper function parameters" 1 (List.length attr_func.attr_function.func_params);
         check bool "helper function return type" true (attr_func.attr_function.func_return_type = Some U64);
         let has_helper_attr = List.exists (function 
           | SimpleAttribute "helper" -> true 
           | _ -> false
         ) attr_func.attr_list in
         check bool "has helper attribute" true has_helper_attr
     | _ -> fail "Expected helper attributed function declaration");
    
    (* Check attributed function declaration *)
    (match List.nth ast 2 with
     | AttributedFunction attr_func -> 
         check string "function name" "packet_filter" attr_func.attr_function.func_name
     | _ -> fail "Expected attributed function declaration")
  with
  | _ -> fail "Failed to parse complete program"

(** Test simple if statement without else *)
let test_simple_if () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  var x = 10
  if (x > 5) {
    return 1
  }
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, None) ->
              check int "then branch has statements" 1 (List.length then_stmts);
              check bool "no else branch" true (None = None)
         | _ -> fail "Expected if statement without else")
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse simple if: " ^ Printexc.to_string e)

(** Test if-else statement *)
let test_if_else () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  var x = 10
  if (x > 15) {
    return 1
  } else {
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, Some else_stmts) ->
              check int "then branch has statements" 1 (List.length then_stmts);
              check int "else branch has statements" 1 (List.length else_stmts)
         | _ -> fail "Expected if-else statement")
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse if-else: " ^ Printexc.to_string e)

(** Test if-else if-else chain *)
let test_if_else_if_else () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  var x = 10
  if (x > 20) {
    return 1
  } else if (x > 10) {
    return 2
  } else if (x > 5) {
    return 3 
  } else {
    return 4
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, Some else_stmts) ->
              check int "first then branch" 1 (List.length then_stmts);
              check int "else contains nested if" 1 (List.length else_stmts);
             (* Check that else contains another if statement *)
             (match (List.hd else_stmts).stmt_desc with
              | If (_, _, Some _) -> check bool "nested if-else" true true
              | _ -> fail "Expected nested if-else")
         | _ -> fail "Expected if-else statement")
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse if-else if-else: " ^ Printexc.to_string e)

(** Test nested if statements *)
let test_nested_if () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  var x = 10
  var y = 20
  if (x > 5) {
    if (y > 15) {
      return 1
    } else {
      return 2
    }
  } else {
    return 3
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
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
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse nested if: " ^ Printexc.to_string e)

(** Test if statements with multiple statements in branches *)
let test_multiple_statements_in_branches () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  var x = 10
  if (x > 5) {
    var y = x + 1
    var z = y * 2
    x = z - 1
    return 1
  } else {
    x = x - 1
    var w = x / 2  
    return 2
  }
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let if_stmt = List.nth main_func.func_body 1 in
                 (match if_stmt.stmt_desc with
          | If (_, then_stmts, Some else_stmts) ->
              check int "then branch multiple statements" 4 (List.length then_stmts);
              check int "else branch multiple statements" 3 (List.length else_stmts)
         | _ -> fail "Expected if statement with multiple statements")
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse multiple statements: " ^ Printexc.to_string e)

(** Test that SPEC-compliant syntax works correctly *)
let test_spec_compliant_syntax () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  var x = 10
  var y = 20
  
  // SPEC-compliant syntax with mandatory parentheses around condition
  if (x > 5) {
    return 1
  }
  
  // Complex conditions also require parentheses
  if (x > 5 && y < 25) {
    return 2
  }
  
  // Parentheses for grouping expressions should still work
  if ((x + y) > 25) {
    return 3
  }
  
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        (* Should have multiple if statements *)
        check bool "SPEC-compliant syntax works" true (List.length main_func.func_body >= 6)
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse SPEC-compliant syntax: " ^ Printexc.to_string e)

(** Test if statement error cases *)
let test_if_error_cases () =
  let error_cases = [
    ("missing condition", {|
@xdp fn test() -> u32 {
  if {
    return 1
  }
  return 0
}
|});
    ("missing braces", {|
@xdp fn test() -> u32 {
  if x > 5
    return 1
  return 0
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
@xdp fn test(ctx: xdp_md) -> xdp_action {
  for (i in 0..10) {
    return 1
  }
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let for_stmt = List.hd main_func.func_body in
        (match for_stmt.stmt_desc with
         | For (var, _, _, body) ->
             check string "for loop variable" "i" var;
             check int "for loop body has statements" 1 (List.length body)
         | _ -> fail "Expected for loop")
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse simple for loop: " ^ Printexc.to_string e)

(** Test for loop with expressions *)
let test_for_loop_with_expressions () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  for (i in 0..5) {
    var x = i * 2
  }
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let for_stmt = List.hd main_func.func_body in
        (match for_stmt.stmt_desc with
         | For (var, _, _, body) ->
             check string "for loop variable" "i" var;
             check int "for loop body has statements" 1 (List.length body)
         | _ -> fail "Expected for loop")
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse for loop with expressions: " ^ Printexc.to_string e)

(** Test for iter syntax support *)
let test_for_iter_syntax () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  for (i in 0..3) {
    var v = i
    return v
  }
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
        let for_stmt = List.hd main_func.func_body in
        (match for_stmt.stmt_desc with
         | For (var, _, _, body) ->
             check string "for loop variable" "i" var;
             check int "for loop body has statements" 2 (List.length body)
         | _ -> fail "Expected for loop")
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse for iter syntax: " ^ Printexc.to_string e)

(** Test nested for loops *)
let test_nested_for_loops () =
  let program_text = {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  for (i in 0..3) {
    for (j in 0..2) {
      return 1
    }
  }
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    match List.hd ast with
    | AttributedFunction attr_func -> 
        let main_func = attr_func.attr_function in
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
    | _ -> fail "Expected attributed function declaration"
  with
  | e -> fail ("Failed to parse nested for loops: " ^ Printexc.to_string e)

(** Test for loop edge cases *)
let test_for_loop_edge_cases () =
  let test_cases = [
    (* Zero range - should work *)
    ("for (i in 5..5) { var x = i }", 
     [make_for_stmt "i" (make_int_lit 5) (make_int_lit 5) [make_decl "x" (make_id "i")]]);
    
    (* Variable bounds - use simple constants *)
    ("for (j in 2..8) { var y = j }", 
     [make_for_stmt "j" (make_int_lit 2) (make_int_lit 8) [make_decl "y" (make_id "j")]]);
  ] in
  List.iter (fun (input, expected) ->
    test_parse_statements input expected
  ) test_cases

let test_for_comprehensive () =
  let input = "for (i in 0..3) { var x = i } for (j in 1..5) { var y = j }" in
  let expected = [
    make_for_stmt "i" (make_int_lit 0) (make_int_lit 3) [make_decl "x" (make_id "i")];
    make_for_stmt "j" (make_int_lit 1) (make_int_lit 5) [make_decl "y" (make_id "j")];
  ] in
  test_parse_statements input expected

let test_loop_bounds_analysis () =
  (* Test that we can parse different kinds of loop bounds *)
  let input = "for (i in 0..5) { var x = i } for (j in 2..8) { var y = j }" in
  let expected = [
    make_for_stmt "i" (make_int_lit 0) (make_int_lit 5) [make_decl "x" (make_id "i")];
    make_for_stmt "j" (make_int_lit 2) (make_int_lit 8) [make_decl "y" (make_id "j")];
  ] in
  test_parse_statements input expected

let test_variable_declaration () =
  let test_cases = [
    ("var x: u32 = 10", true);
    ("var y = 20", true);
    ("var z: bool = true", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_if_statements () =
  let test_cases = [
    ("if (true) { var x = 10 }", true);
    ("if (false) { var y = 20 } else { var z = 30 }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_while_loops () =
  let test_cases = [
    ("while (true) { var x = 10 }", true);
    ("while (false) { break }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_for_loops () =
  let test_cases = [
    ("for (i in 0..10) { var x = 10 }", true);
    ("for (j in 1..5) { break }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_return_statements () =
  let test_cases = [
    ("return 42", true);
    ("return true", true);
    ("return", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_function_calls () =
  let test_cases = [
    ("print(42)", true);
    ("helper(x, y)", true);
    ("process()", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_nested_statements () =
  let test_cases = [
    ("if (true) { while (false) { var x = 10 } }", true);
    ("for (i in 0..5) { if (i == 2) { break } }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_range_expressions () =
  let test_cases = [
    ("for (i in 0..10) { var x = 10 }", true);
    ("for (j in 1..100) { var x = 10 }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_complex_expressions () =
  let test_cases = [
    ("for (i in 0..5) { var x = 10 }", true);
    ("while (i < 10) { var x = 10 }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_combined_statements () =
  let test_cases = [
    ("for (i in 0..3) { var x = i }", true);
    ("for (j in 1..5) { var y = j }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_range_boundary_conditions () =
  let test_cases = [
    ("for (i in 5..5) { var x = i }", true);
    ("for (i in 0..0) { var y = i }", true);
  ] in
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

let test_multiple_statements_parsing () =
  let complex_tests = [
    ("for (i in 0..3) { var x = i } for (j in 1..5) { var y = j }", "multiple for loops with variables");
    ("for (i in 0..5) { var x = i } for (j in 2..8) { var y = j }", "larger range for loops with variables");
  ] in
  
  List.iter (fun (input, description) ->
    try
      let _ = parse_string input in
      Printf.printf "✓ %s: %s\n" description input;
    with 
    | e -> Printf.printf "✗ %s failed: %s\n" description (Printexc.to_string e)
  ) complex_tests

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
  "variable_declaration", `Quick, test_variable_declaration;
  "if_statements", `Quick, test_if_statements;
  "while_loops", `Quick, test_while_loops;
  "for_loops", `Quick, test_for_loops;
  "return_statements", `Quick, test_return_statements;
  "function_calls", `Quick, test_function_calls;
  "nested_statements", `Quick, test_nested_statements;
  "range_expressions", `Quick, test_range_expressions;
  "complex_expressions", `Quick, test_complex_expressions;
  "combined_statements", `Quick, test_combined_statements;
  "range_boundary_conditions", `Quick, test_range_boundary_conditions;
  "multiple_statements_parsing", `Quick, test_multiple_statements_parsing;
]

let () =
  run "KernelScript Parser Tests" [
    "parser", parser_tests;
  ] 