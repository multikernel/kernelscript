open Alcotest
open Kernelscript
open Ast
open Ir

(** Test position for all tests *)
let test_pos = { line = 1; column = 1; filename = "test" }

let dummy_pos = { line = 1; column = 1; filename = "test.ks" }

let parse_program_string s =
  Parse.parse_string s

(** Test basic match construct parsing *)
let test_basic_match_parsing () =
  let input = {|
    fn test_match() -> u32 {
      var protocol = 6
      return match (protocol) {
        6: 1,
        17: 2,
        default: 0
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.nth func.func_body 1 in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (matched_expr, arms) ->
      (* Check matched expression *)
      check bool "matched expression is identifier" true 
        (match matched_expr.expr_desc with
         | Identifier "protocol" -> true
         | _ -> false);
      
      (* Check number of arms *)
      check int "number of arms" 3 (List.length arms)
  | _ -> failwith "Expected match expression"

(** Test match with enum constants *)
let test_match_with_enums () =
  let input = {|
    enum Protocol {
      TCP = 6,
      UDP = 17,
      ICMP = 1
    }
    
    fn test_protocol_match(proto: u32) -> u32 {
      return match (proto) {
        TCP: 100,
        UDP: 200,
        ICMP: 300,
        default: 0
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.nth ast 1 with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check that we have identifier patterns *)
      let first_arm = List.hd arms in
      check bool "first arm is TCP identifier pattern" true
        (match first_arm.arm_pattern with
         | IdentifierPattern "TCP" -> true
         | _ -> false)
  | _ -> failwith "Expected match expression"

(** Test packet matching scenario *)
let test_packet_matching () =
  let input = {|
    @helper
    fn get_protocol(ctx: *xdp_md) -> u32 {
      return 6
    }
    
    @xdp
    fn packet_classifier(ctx: *xdp_md) -> xdp_action {
      var protocol = get_protocol(ctx)
      
      return match (protocol) {
        6: XDP_PASS,
        17: XDP_PASS, 
        default: XDP_ABORTED
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let attr_func = match List.nth ast 1 with
    | AttributedFunction af -> af
    | _ -> failwith "Expected attributed function"
  in
  
  let func = attr_func.attr_function in
  let return_stmt = List.nth func.func_body 1 in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (matched_expr, arms) ->
      (* Check that matched expression is the protocol variable *)
      check bool "matched expression is protocol identifier" true
        (match matched_expr.expr_desc with
         | Identifier "protocol" -> true
         | _ -> false);
      
      (* Check that we have 3 arms *)
      check int "number of arms" 3 (List.length arms)
  | _ -> failwith "Expected match expression"

(** Test nested match expressions *)
let test_nested_match () =
  let input = {|
    fn test_nested(x: u32, y: u32) -> u32 {
      return match (x) {
        1: match (y) {
          10: 100,
          20: 200,
          default: 0
        },
        2: 50,
        default: 0
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check first arm has nested match *)
      let first_arm = List.hd arms in
              check bool "first arm has nested match" true
         (match first_arm.arm_body with
          | SingleExpr expr -> 
              (match expr.expr_desc with
               | Match (_, nested_arms) -> List.length nested_arms = 3
               | _ -> false)
          | Block _ -> false)
  | _ -> failwith "Expected match expression"

(** Test match with string patterns *)
let test_match_string_patterns () =
  let input = {|
    fn test_strings(name: str<10>) -> u32 {
      return match (name) {
        "tcp": 1,
        "udp": 2,
        "icmp": 3,
        default: 0
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check first arm has string pattern *)
      let first_arm = List.hd arms in
      check bool "first arm has string pattern tcp" true
        (match first_arm.arm_pattern with
         | ConstantPattern (StringLit "tcp") -> true
         | _ -> false)
  | _ -> failwith "Expected match expression"

(** Test match with boolean patterns *)
let test_match_boolean_patterns () =
  let input = {|
    fn test_bool(flag: bool) -> u32 {
      return match (flag) {
        true: 1,
        false: 0
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check boolean patterns *)
      let first_arm = List.hd arms in
      check bool "first arm has boolean pattern true" true
        (match first_arm.arm_pattern with
         | ConstantPattern (BoolLit true) -> true
         | _ -> false);
      
      let second_arm = List.nth arms 1 in
      check bool "second arm has boolean pattern false" true
        (match second_arm.arm_pattern with
         | ConstantPattern (BoolLit false) -> true
         | _ -> false)
  | _ -> failwith "Expected match expression"

(** Test match conditional control flow *)
let test_match_conditional_control_flow () =
  let source = {|
    @helper
    fn get_protocol(ctx: *xdp_md) -> u32 {
        return 6
    }

    @helper  
    fn get_tcp_port(ctx: *xdp_md) -> u32 {
        return 80
    }

    @helper
    fn get_udp_port(ctx: *xdp_md) -> u32 {
        return 53
    }

    @xdp
    fn packet_processor(ctx: *xdp_md) -> xdp_action {
        var protocol = get_protocol(ctx)
        
        return match (protocol) {
            6: {
                var tcp_port = get_tcp_port(ctx)
                return 2
            },
            17: {
                var udp_port = get_udp_port(ctx)
                return 1
            },
            default: 0
        }
    }
  |} in
  
  let parsed = parse_program_string source in
  let symbol_table = Symbol_table.build_symbol_table parsed in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) parsed in
  let multi_prog = Ir_generator.generate_ir typed_ast symbol_table "test" in
  
  (* Verify proper conditional structure was generated *)
  check int "number of programs" 1 (List.length multi_prog.programs);
  
  let prog = List.hd multi_prog.programs in
  let entry_function = prog.entry_function in
  let blocks = entry_function.basic_blocks in
  
  (* Find IRIf instructions that represent the match arms *)
  let has_conditional_structure = List.exists (fun block ->
    List.exists (fun instr ->
      match instr.instr_desc with
      | IRIf (_, then_body, else_body) -> 
          (* Verify that function calls are only in appropriate branches *)
          let has_tcp_call_in_then = List.exists (fun then_instr ->
            match then_instr.instr_desc with
            | IRCall (DirectCall "get_tcp_port", _, _) -> true
            | _ -> false
          ) then_body in
          
          let has_udp_call_in_else = match else_body with
            | Some else_instrs -> List.exists (fun else_instr ->
                match else_instr.instr_desc with
                | IRCall (DirectCall "get_udp_port", _, _) -> true
                | _ -> false
              ) else_instrs
            | None -> false
          in
          
          has_tcp_call_in_then || has_udp_call_in_else
      | _ -> false
    ) block.instructions
  ) blocks in
  
  check bool "match construct should generate proper conditional control flow" true has_conditional_structure

(** Test match no premature execution *)
let test_match_no_premature_execution () =
  let source = {|
    @helper
    fn expensive_operation_1() -> u32 {
        return 100
    }

    @helper
    fn expensive_operation_2() -> u32 {
        return 200
    }

    @xdp
    fn test_match(ctx: *xdp_md) -> xdp_action {
        var x = 1
        var result = match (x) {
            1: {
                var val1 = expensive_operation_1()
                return 2
            },
            2: {
                var val2 = expensive_operation_2()
                return 1
            },
            default: 0
        }
        return result
    }
  |} in
  
  let parsed = parse_program_string source in
  let symbol_table = Symbol_table.build_symbol_table parsed in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) parsed in
  let multi_prog = Ir_generator.generate_ir typed_ast symbol_table "test" in
  
  (* Verify that expensive operations are not executed unconditionally *)
  let prog = List.hd multi_prog.programs in
  let entry_function = prog.entry_function in
  let all_instructions = List.flatten (List.map (fun block -> block.instructions) entry_function.basic_blocks) in
  
  (* Count total function calls - should be inside conditional branches only *)
  let function_call_count = List.fold_left (fun acc instr ->
    match instr.instr_desc with
    | IRCall (DirectCall "expensive_operation_1", _, _) -> acc + 1
    | IRCall (DirectCall "expensive_operation_2", _, _) -> acc + 1  
    | _ -> acc
  ) 0 all_instructions in
  
  (* The expensive operations should only appear inside conditional branches, not at top level *)
  check bool "expensive operations should not be called unconditionally" true (function_call_count = 0);
  
  (* But they should appear inside IRIf instructions *)
  let conditional_calls = List.fold_left (fun acc instr ->
    match instr.instr_desc with
    | IRIf (_, then_body, else_body) ->
        let then_calls = List.fold_left (fun acc2 then_instr ->
          match then_instr.instr_desc with
          | IRCall (DirectCall "expensive_operation_1", _, _) | IRCall (DirectCall "expensive_operation_2", _, _) -> acc2 + 1
          | _ -> acc2
        ) 0 then_body in
        let else_calls = match else_body with
          | Some else_instrs -> List.fold_left (fun acc3 else_instr ->
              match else_instr.instr_desc with
              | IRCall (DirectCall "expensive_operation_1", _, _) | IRCall (DirectCall "expensive_operation_2", _, _) -> acc3 + 1
              | _ -> acc3
            ) 0 else_instrs
          | None -> 0
        in
        acc + then_calls + else_calls
    | _ -> acc
  ) 0 all_instructions in
  
  check bool "expensive operations should be in conditional branches" true (conditional_calls > 0)

(** Test nested match structures *)
let test_nested_match_structures () =
  let source = {|
    @helper
    fn get_protocol(ctx: *xdp_md) -> u32 {
        return 6
    }

    @helper  
    fn get_tcp_port(ctx: *xdp_md) -> u32 {
        return 80
    }

    @xdp  
    fn nested_match_test(ctx: *xdp_md) -> xdp_action {
        var protocol = get_protocol(ctx)
        var result = match (protocol) {
            6: {
                var tcp_port = get_tcp_port(ctx)
                return match (tcp_port) {
                    80: 2,
                    443: 2,
                    default: 1
                }
            },
            17: 2,
            default: 0
        }
        return result
    }
  |} in
  
  let parsed = parse_program_string source in
  let symbol_table = Symbol_table.build_symbol_table parsed in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) parsed in
  let multi_prog = Ir_generator.generate_ir typed_ast symbol_table "test" in
  
  (* Verify nested match structures generate nested conditional branches *)
  let prog = List.hd multi_prog.programs in
  let entry_function = prog.entry_function in
  let blocks = entry_function.basic_blocks in
  
  (* Look for nested IRIf structures *)
  let has_nested_conditionals = List.exists (fun block ->
    List.exists (fun instr ->
      match instr.instr_desc with
      | IRIf (_, then_body, _) -> 
          (* Check if then_body contains another IRIf (nested match) *)
          List.exists (fun then_instr ->
            match then_instr.instr_desc with
            | IRIf (_, _, _) -> true
            | _ -> false
          ) then_body
      | _ -> false
    ) block.instructions
  ) blocks in
  
  check bool "nested match should generate nested conditional structures" true has_nested_conditionals

let suite = [
  "test_basic_match_parsing", `Quick, test_basic_match_parsing;
  "test_match_with_enums", `Quick, test_match_with_enums;
  "test_packet_matching", `Quick, test_packet_matching;
  "test_nested_match", `Quick, test_nested_match;
  "test_match_string_patterns", `Quick, test_match_string_patterns;
  "test_match_boolean_patterns", `Quick, test_match_boolean_patterns;
  "test_match_conditional_control_flow", `Quick, test_match_conditional_control_flow;
  "test_match_no_premature_execution", `Quick, test_match_no_premature_execution;
  "test_nested_match_structures", `Quick, test_nested_match_structures;
]

let () = run "Match Construct Tests" [
  "match_tests", suite;
] 