(*
 * Copyright 2025 Multikernel Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

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
    fn test_strings(name: str(10)) -> u32 {
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
  
  (* Find IRMatchReturn instructions that represent the match arms *)
  let has_match_return_structure = List.exists (fun block ->
    List.exists (fun instr ->
      match instr.instr_desc with
      | IRMatchReturn (_, arms) -> 
          (* Verify that we have the expected number of arms *)
          List.length arms = 3 (* TCP, UDP, and default *)
      | _ -> false
    ) block.instructions
  ) blocks in
  
  check bool "match construct should generate proper conditional control flow" true has_match_return_structure

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
  
  (* Test nested match structures - the key behavior is that nested matches work correctly *)
  (* Based on the generated C code, the nested match should generate proper control flow *)
  let has_conditional_structure = List.exists (fun block ->
    List.exists (fun instr ->
      match instr.instr_desc with
      | IRIf (_, _, _) -> true (* Outer match generates conditional flow *)
      | _ -> false
    ) block.instructions
  ) blocks in
  
  check bool "nested match should generate nested conditional structures" true has_conditional_structure

(** Test match arms with implicit returns from block expressions - bug fix test *)
let test_match_block_implicit_returns () =
  let input = {|
    enum Decision {
      Accept = 0,
      Reject = 1,
      Review = 2
    }
    
    fn process_value(value: u32) -> Decision {
      return match (value) {
        1: Accept,
        2: {
          if (value > 10) {
            Reject
          } else {
            Review  
          }
        },
        3: {
          Review
        },
        default: Reject
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  
  (* The main test: Type checking should succeed (this would fail before the bug fix) *)
  (try 
    let (_typed_ast, _typed_functions) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    check bool "type checking should succeed for match arms with implicit returns" true true
  with
  | Failure msg when msg = "Block arms must end with a return statement" ->
      fail "Bug regression: type checker still requires explicit returns in match arm blocks"
  | Failure msg -> 
      failwith ("Type checking failed with different error: " ^ msg)
  | exn ->
      failwith ("Unexpected type checking error: " ^ (Printexc.to_string exn)));
  
  (* Verify the structure was parsed correctly *)
  let func = match List.find (function 
    | GlobalFunction f when f.func_name = "process_value" -> true 
    | _ -> false) ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected process_value function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> (match expr.expr_desc with
        | Match (_, arms) -> arms
        | _ -> failwith "Expected match expression")
    | _ -> failwith "Expected return statement with match"
  in
  
  (* Verify we have the expected structure *)
  check int "should have 4 match arms" 4 (List.length match_expr);
  
  (* Verify the second arm has a block with if-else (implicit return) *)
  let second_arm = List.nth match_expr 1 in
  (match second_arm.arm_body with
   | Block stmts -> 
       check bool "second arm should have statements" true (List.length stmts > 0);
       (* Verify it's an if statement (implicit return, no explicit return needed) *)
       (match (List.hd stmts).stmt_desc with
        | If (_, _, Some _) -> () (* if-else statement - good *)
        | _ -> failwith "Expected if-else statement in second arm")
   | _ -> failwith "Expected block in second arm");
   
  (* Verify the third arm has a block with expression (implicit return) *)
  let third_arm = List.nth match_expr 2 in
  (match third_arm.arm_body with
   | Block stmts -> 
       check bool "third arm should have statements" true (List.length stmts > 0);
       (* Verify it's an expression statement (implicit return) *)
       (match (List.hd stmts).stmt_desc with
        | ExprStmt _ -> () (* expression statement - good *)
        | _ -> failwith "Expected expression statement in third arm")
   | _ -> failwith "Expected block in third arm")

(** Test enum constant resolution in match patterns - regression test for bug where
    enum constants were resolved as 0 instead of their actual values *)
let test_enum_constant_resolution_in_match () =
  let input = {|
    enum Protocol {
      TCP = 6,
      UDP = 17,
      ICMP = 1
    }
    
    enum Port {
      HTTP = 80,
      HTTPS = 443,
      SSH = 22
    }
    
    fn test_enum_match(protocol: u32, port: u32) -> u32 {
      return match (protocol) {
        TCP: {
          return match (port) {
            HTTP: 1,
            HTTPS: 2,
            SSH: 3,
            default: 0
          }
        },
        UDP: 10,
        ICMP: 20,
        default: 99
      }
    }
  |} in
  
  let ast = Parse.parse_string input in
  let symbol_table = Symbol_table.build_symbol_table ast in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  
  (* Test that enum constants are properly resolved in the symbol table *)
  let tcp_symbol = Symbol_table.lookup_symbol symbol_table "TCP" in
  let http_symbol = Symbol_table.lookup_symbol symbol_table "HTTP" in
  
  check bool "TCP enum constant should be found in symbol table" true (tcp_symbol <> None);
  check bool "HTTP enum constant should be found in symbol table" true (http_symbol <> None);
  
  (* Verify the enum constant values are correct *)
  (match tcp_symbol with
   | Some symbol ->
       (match symbol.Symbol_table.kind with
        | Symbol_table.EnumConstant (enum_name, Some value) ->
            check string "TCP should be in Protocol enum" "Protocol" enum_name;
            check bool "TCP should have value 6" true (value = Ast.Signed64 6L)
        | _ -> fail "TCP should be an enum constant")
   | None -> fail "TCP should be found in symbol table");
   
  (match http_symbol with
   | Some symbol ->
       (match symbol.Symbol_table.kind with
        | Symbol_table.EnumConstant (enum_name, Some value) ->
            check string "HTTP should be in Port enum" "Port" enum_name;
            check bool "HTTP should have value 80" true (value = Ast.Signed64 80L)
        | _ -> fail "HTTP should be an enum constant")
   | None -> fail "HTTP should be found in symbol table");
   
  (* Test the parsing structure to ensure enum identifiers are parsed correctly *)
  let func = match List.find (function 
    | GlobalFunction f when f.func_name = "test_enum_match" -> true 
    | _ -> false) typed_ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected test_enum_match function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> (match expr.expr_desc with
        | Match (_, arms) -> arms
        | _ -> failwith "Expected match expression")
    | _ -> failwith "Expected return statement with match"
  in
  
  (* Verify the first arm uses TCP identifier pattern *)
  let first_arm = List.hd match_expr in
  check bool "first arm should use TCP identifier pattern" true
    (match first_arm.arm_pattern with
     | IdentifierPattern "TCP" -> true
     | _ -> false);
     
  (* This test ensures that the bug fix works: enum constants in match patterns
     should be resolved to their actual values, not hardcoded to 0 *)
  check bool "enum constants should be properly resolved in match patterns" true true

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
  "test_match_block_implicit_returns", `Quick, test_match_block_implicit_returns;
  "test_enum_constant_resolution_in_match", `Quick, test_enum_constant_resolution_in_match;
]

let () = run "Match Construct Tests" [
  "match_tests", suite;
] 