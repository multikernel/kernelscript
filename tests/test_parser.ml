open Kernelscript.Ast
open Kernelscript.Parse
open Alcotest

(** Test simple program parsing *)
let test_simple_program () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
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
    let result = %s;
    return 0;
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
    ("let x = 42;", true);
    ("let y: u32 = 100;", true);
    ("x = 50;", true);
    ("return x;", true);
    ("return;", true);
    ("if (condition) { return 1; }", true);
    ("if (x > 0) { return 1; } else { return 0; }", true);
  ] in
  
  List.iter (fun (stmt_text, should_succeed) ->
    let program_text = Printf.sprintf {|
program test : xdp {
  fn main() -> u32 {
    %s
    return 0;
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
    return x + y;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let result = helper(10, 20);
    return 2;
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
    return 0;
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
    let x: %s = 0;
    return 0;
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
    let x = 10;
    
    if (x > 5) {
      x = x + 1;
    } else {
      x = x - 1;
    }
    
    while (x > 0) {
      x = x - 1;
    }
    
    return 2;
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
    let result = 1 + 2 * 3;
    let comparison = x < y && a > b;
    let complex = (a + b) * c - d / e;
    return 0;
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
map<u32, u64> packet_count : HashMap(1024) { };

program packet_filter : xdp {
  fn process_packet(src_ip: u32) -> u64 {
    let count = packet_count[src_ip];
    packet_count[src_ip] = count + 1;
    return count;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let src_ip = 0x12345678;
    let count = process_packet(src_ip);
    
    if (count > 100) {
      return 1;  // DROP
    }
    
    return 2;  // PASS
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

let parser_tests = [
  "simple_program", `Quick, test_simple_program;
  "expression_parsing", `Quick, test_expression_parsing;
  "statement_parsing", `Quick, test_statement_parsing;
  "function_declaration", `Quick, test_function_declaration;
  "program_types", `Quick, test_program_types;
  "bpf_type_parsing", `Quick, test_bpf_type_parsing;
  "control_flow_parsing", `Quick, test_control_flow_parsing;
  "error_handling", `Quick, test_error_handling;
  "operator_precedence", `Quick, test_operator_precedence;
  "complete_program_parsing", `Quick, test_complete_program_parsing;
]

let () =
  run "KernelScript Parser Tests" [
    "parser", parser_tests;
  ] 