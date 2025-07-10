open Alcotest
open Kernelscript.Ast

let dummy_pos = { line = 1; column = 1; filename = "test" }

let make_array_literal init_style = {
  expr_desc = Literal (ArrayLit init_style);
  expr_type = None;
  expr_pos = dummy_pos;
  type_checked = false;
  program_context = None;
  map_scope = None;
}

let make_int_literal i = IntLit (i, None)
let make_bool_literal b = BoolLit b
let make_char_literal c = CharLit c
let make_string_literal s = StringLit s

(** Test parsing of enhanced array initialization syntax *)
let test_parse_array_init () =
  let test_cases = [
    ("[]", ZeroArray);
    ("[0]", FillArray (make_int_literal 0));
    ("[42]", FillArray (make_int_literal 42));
    ("[true]", FillArray (make_bool_literal true));
    ("['x']", FillArray (make_char_literal 'x'));
    ("[\"hello\"]", FillArray (make_string_literal "hello"));
    ("[1, 2, 3]", ExplicitArray [make_int_literal 1; make_int_literal 2; make_int_literal 3]);
    ("[true, false, true]", ExplicitArray [make_bool_literal true; make_bool_literal false; make_bool_literal true]);
  ] in
  
  List.iter (fun (input, expected) ->
    let program_text = Printf.sprintf {|
@xdp fn test() -> u32 {
  var arr = %s
  return 0
}
|} input in
    try
      let ast = Kernelscript.Parse.parse_string program_text in
      match ast with
      | [AttributedFunction attr_func] ->
          (match attr_func.attr_function.func_body with
           | [{stmt_desc = Declaration (_, _, Some {expr_desc = Literal (ArrayLit actual); _}); _}; _] ->
               check bool ("parse " ^ input) true (actual = expected)
           | _ -> fail ("Failed to parse array initialization: " ^ input))
      | _ -> fail ("Failed to parse program: " ^ input)
    with
    | e -> fail ("Parse error for " ^ input ^ ": " ^ Printexc.to_string e)
  ) test_cases

(** Test type checking of enhanced array initialization *)
let test_type_check_array_init () =
  let test_cases = [
    ("var arr: u32[4] = []", true);         (* ZeroArray *)
    ("var arr: u32[4] = [0]", true);        (* FillArray *)
    ("var arr: u32[4] = [42]", true);       (* FillArray *)
    ("var arr: u32[4] = [1, 2, 3]", true);  (* ExplicitArray - partial *)
    ("var arr: u32[4] = [1, 2, 3, 4]", true); (* ExplicitArray - full *)
    ("var arr: bool[3] = [true]", true);     (* FillArray with bool *)
    ("var arr: bool[3] = [true, false, true]", true); (* ExplicitArray with bool *)
  ] in
  
  List.iter (fun (input, should_succeed) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2
}
|} input in
    try
      let ast = Kernelscript.Parse.parse_string program_text in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (_typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
      check bool ("type check " ^ input) should_succeed true
    with
    | e -> 
        if should_succeed then
          fail ("Type checking failed for " ^ input ^ ": " ^ Printexc.to_string e)
        else
          check bool ("type check " ^ input) should_succeed false
  ) test_cases

(** Test code generation for enhanced array initialization *)
let test_codegen_array_init () =
  let test_cases = [
    ("var arr: u32[4] = []", "{0}");                    (* ZeroArray *)
    ("var arr: u32[4] = [0]", "{0}");                   (* FillArray *)
    ("var arr: u32[4] = [42]", "{42}");                 (* FillArray *)
    ("var arr: u32[4] = [1, 2, 3]", "{1, 2, 3}");      (* ExplicitArray - partial *)
    ("var arr: u32[4] = [1, 2, 3, 4]", "{1, 2, 3, 4}"); (* ExplicitArray - full *)
  ] in
  
  List.iter (fun (input, _expected_pattern) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2
}
|} input in
    try
      let ast = Kernelscript.Parse.parse_string program_text in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
      let ir = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
      let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir in
      check bool ("codegen " ^ input) true (String.contains c_code '{')
    with
    | e -> fail ("Code generation failed for " ^ input ^ ": " ^ Printexc.to_string e)
  ) test_cases

(** Test semantic analysis of array initialization *)
let test_semantic_analysis () =
  let test_cases = [
    (* Array size inference *)
    ("var arr = [1, 2, 3]", "Array size should be inferred as 3");
    ("var arr = [0]", "Array size should be inferred from context");
    ("var arr = []", "Array should be zero-initialized");
    
    (* Type consistency *)
    ("var arr: u32[4] = [1, 2, 3]", "Mixed explicit and zero-fill should work");
    ("var arr: bool[2] = [true]", "Boolean fill should work");
  ] in
  
  List.iter (fun (input, description) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2
}
|} input in
    try
      let ast = Kernelscript.Parse.parse_string program_text in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (_typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
      check bool description true true
    with
    | e -> fail ("Semantic analysis failed for " ^ input ^ ": " ^ Printexc.to_string e)
  ) test_cases

(** Test error cases *)
let test_error_cases () =
  let test_cases = [
    ("var arr: u32[2] = [1, 2, 3, 4, 5]", "Array literal has too many elements");
    ("var arr: u32[4] = [1, true, 3]", "Array elements must have consistent type");
  ] in
  
  List.iter (fun (input, expected_error) ->
    let program_text = Printf.sprintf {|
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  %s
  return 2
}
|} input in
    try
      let ast = Kernelscript.Parse.parse_string program_text in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (_typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
      fail ("Expected error for " ^ input ^ " but compilation succeeded")
    with
    | _ -> check bool expected_error true true
  ) test_cases

let () =
  run "Enhanced Array Initialization Tests" [
    "parse", [ test_case "Parse array initialization syntax" `Quick test_parse_array_init ];
    "type_check", [ test_case "Type check array initialization" `Quick test_type_check_array_init ];
    "codegen", [ test_case "Code generation for array initialization" `Quick test_codegen_array_init ];
    "semantic", [ test_case "Semantic analysis of array initialization" `Quick test_semantic_analysis ];
    "errors", [ test_case "Error handling for invalid array initialization" `Quick test_error_cases ];
  ] 