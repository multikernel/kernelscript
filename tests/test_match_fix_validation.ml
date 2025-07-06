open OUnit2
open Kernelscript
open Ast
open Ir

let dummy_pos = { line = 1; column = 1; filename = "test.ks" }

let parse_program_string s =
  Parse.parse_string s

let test_match_conditional_control_flow _ =
  let source = {|
    @helper
    fn get_protocol(ctx: xdp_md) -> u32 {
        return 6
    }

    @helper  
    fn get_tcp_port(ctx: xdp_md) -> u32 {
        return 80
    }

    @helper
    fn get_udp_port(ctx: xdp_md) -> u32 {
        return 53
    }

    @xdp
    fn packet_processor(ctx: xdp_md) -> xdp_action {
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
  assert_equal 1 (List.length multi_prog.programs);
  
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
            | IRCall ("get_tcp_port", _, _) -> true
            | _ -> false
          ) then_body in
          
          let has_udp_call_in_else = match else_body with
            | Some else_instrs -> List.exists (fun else_instr ->
                match else_instr.instr_desc with
                | IRCall ("get_udp_port", _, _) -> true
                | _ -> false
              ) else_instrs
            | None -> false
          in
          
          has_tcp_call_in_then || has_udp_call_in_else
      | _ -> false
    ) block.instructions
  ) blocks in
  
  assert_bool "Match construct should generate proper conditional control flow" has_conditional_structure

let test_match_no_premature_execution _ =
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
    fn test_match(ctx: xdp_md) -> xdp_action {
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
    | IRCall ("expensive_operation_1", _, _) -> acc + 1
    | IRCall ("expensive_operation_2", _, _) -> acc + 1  
    | _ -> acc
  ) 0 all_instructions in
  
  (* The expensive operations should only appear inside conditional branches, not at top level *)
  assert_bool "Expensive operations should not be called unconditionally" (function_call_count = 0);
  
  (* But they should appear inside IRIf instructions *)
  let conditional_calls = List.fold_left (fun acc instr ->
    match instr.instr_desc with
    | IRIf (_, then_body, else_body) ->
        let then_calls = List.fold_left (fun acc2 then_instr ->
          match then_instr.instr_desc with
          | IRCall ("expensive_operation_1", _, _) | IRCall ("expensive_operation_2", _, _) -> acc2 + 1
          | _ -> acc2
        ) 0 then_body in
        let else_calls = match else_body with
          | Some else_instrs -> List.fold_left (fun acc3 else_instr ->
              match else_instr.instr_desc with
              | IRCall ("expensive_operation_1", _, _) | IRCall ("expensive_operation_2", _, _) -> acc3 + 1
              | _ -> acc3
            ) 0 else_instrs
          | None -> 0
        in
        acc + then_calls + else_calls
    | _ -> acc
  ) 0 all_instructions in
  
  assert_bool "Expensive operations should be in conditional branches" (conditional_calls > 0)

let test_nested_match_structures _ =
  let source = {|
    @helper
    fn get_protocol(ctx: xdp_md) -> u32 {
        return 6
    }

    @helper  
    fn get_tcp_port(ctx: xdp_md) -> u32 {
        return 80
    }

    @xdp  
    fn nested_match_test(ctx: xdp_md) -> xdp_action {
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
  
  assert_bool "Nested match should generate nested conditional structures" has_nested_conditionals

let match_fix_validation_suite = 
  "Match Construct Fix Validation Tests" >::: [
    "conditional_control_flow" >:: test_match_conditional_control_flow;
    "no_premature_execution" >:: test_match_no_premature_execution;
    "nested_match_structures" >:: test_nested_match_structures;
  ]

let _ = run_test_tt_main match_fix_validation_suite 