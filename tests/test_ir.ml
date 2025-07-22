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

(** Test IR generation functionality *)

open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ir_generator
open Alcotest

(** Define test modules for custom types *)
module Program_type = struct
  type t = program_type
  let equal = (=)
  let pp fmt = function
    | Xdp -> Format.fprintf fmt "Xdp"
    | Tc -> Format.fprintf fmt "Tc"
    | Tracepoint -> Format.fprintf fmt "Tracepoint"
    | Kprobe -> Format.fprintf fmt "Kprobe"
    | Uprobe -> Format.fprintf fmt "Uprobe"
    | Lsm -> Format.fprintf fmt "Lsm"
    | CgroupSkb -> Format.fprintf fmt "CgroupSkb"
    | StructOps -> Format.fprintf fmt "StructOps"
end

(** Helper functions for creating test AST nodes *)

let make_test_position () = make_position 1 1 "test.ks"

let make_test_map_config max_entries =
  make_map_config max_entries ()

let make_test_global_map () =
  make_map_declaration 
    "global_counter" 
    U32 
    U64 
    Array 
    (make_test_map_config 256) 
    true 
    ~is_pinned:false
    (make_test_position ())

let make_test_global_map_2 () =
  make_map_declaration 
    "global_map_2" 
    U32 
    U32 
    HashMap 
    (make_test_map_config 100) 
    true 
    ~is_pinned:false
    (make_test_position ())

let make_test_main_function () =
  let return_stmt = make_stmt 
    (Return (Some (make_expr (Literal (IntLit (0, None))) (make_test_position ())))) 
    (make_test_position ()) in
  make_function 
    "test_xdp" 
    [("ctx", Xdp_md)] 
    (Some (make_unnamed_return Xdp_action)) 
    [return_stmt] 
    (make_test_position ())

let make_test_attributed_function () =
  let main_func = make_test_main_function () in
  let attributes = [SimpleAttribute "xdp"] in
  make_attributed_function attributes main_func (make_test_position ())

let make_test_ast () =
  [
    MapDecl (make_test_global_map ());
    AttributedFunction (make_test_attributed_function ());
  ]

(** Test functions matching the roadmap specifications *)

let test_program_lowering () =
  let ast = make_test_ast () in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ir_multi_prog = generate_ir ast symbol_table "test" in
  let ir_prog = List.hd ir_multi_prog.programs in (* Get first program *)

  (* Verify program structure *)
  check (module Program_type) "program type" Xdp ir_prog.program_type;
  check int "global maps count" 1 (List.length ir_multi_prog.global_maps);
  (* Attributed functions don't have local maps *)
  check bool "main function flag" true ir_prog.entry_function.is_main

let test_context_access_lowering () =
  let ctx_access = make_expr 
    (Call (make_expr (FieldAccess (make_expr (Identifier "ctx") (make_test_position ()), "packet")) (make_test_position ()), [])) 
    (make_test_position ()) in
  let ctx_access = { ctx_access with expr_type = Some (Pointer U8) } in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  let _ir_val = lower_expression ctx ctx_access in
  (* Should generate context access instruction *)
  check bool "instruction generated" true (List.length ctx.current_block > 0);
  match (List.hd ctx.current_block).instr_desc with
  | IRContextAccess (_, "xdp", "data") -> () (* Success *)
  | _ -> fail "Expected context access instruction"

let test_map_operation_lowering () =
  let map_access = make_expr 
    (ArrayAccess (
      make_expr (Identifier "global_map_2") (make_test_position ()),
      make_expr (Literal (IntLit (0, None))) (make_test_position ())
    )) 
    (make_test_position ()) in
  let map_access = { map_access with expr_type = Some U32 } in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  (* Add test map to context *)
  let test_map = make_ir_map_def 
    "global_map_2" 
    IRU32 
    IRU32 
    IRHashMap 
    100 
    ~flags:0
    (make_test_position ()) in
  Hashtbl.add ctx.maps "global_map_2" test_map;
  
  let _ir_val = lower_expression ctx map_access in
  (* Should generate map lookup with bounds checks *)
  let has_map_load = List.exists (fun instr ->
    match instr.instr_desc with
    | IRMapLoad (_, _, _, MapLookup) -> true
    | _ -> false
  ) ctx.current_block in
  
  check bool "map load instruction generated" true has_map_load

let test_bounds_check_insertion () =
  let array_decl = make_expr (Identifier "arr") (make_test_position ()) in
  let array_decl = { array_decl with expr_type = Some (Array (U32, 10)) } in
  let index_expr = make_expr (Literal (IntLit (5, None))) (make_test_position ()) in
  let array_access = make_expr 
    (ArrayAccess (array_decl, index_expr)) 
    (make_test_position ()) in
  let array_access = { array_access with expr_type = Some U32 } in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  let _ir_val = lower_expression ctx array_access in
  let bounds_checks = List.concat_map (fun instr -> instr.bounds_checks) ctx.current_block in
  
  check bool "bounds checks present" true (List.length bounds_checks > 0);
  let has_array_access_check = List.exists (fun bc -> 
    bc.check_type = ArrayAccess
  ) bounds_checks in
  check bool "array access bounds check" true has_array_access_check

let test_stack_usage_tracking () =
  let buffer_decl = make_stmt 
    (Declaration ("buffer", Some (Array (U8, 100)), Some (make_expr (Literal (IntLit (0, None))) (make_test_position ())))) 
    (make_test_position ()) in
  
  let test_func = make_function 
    "test" 
    [] 
    None 
    [buffer_decl] 
    (make_test_position ()) in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  let ir_func = lower_function ctx "test_program" test_func in
  
  check bool "sufficient stack usage" true (ir_func.total_stack_usage >= 100);
  let all_blocks_have_positive_usage = List.for_all (fun (bb : ir_basic_block) -> bb.stack_usage >= 0) ir_func.basic_blocks in
  check bool "positive stack usage in all blocks" true all_blocks_have_positive_usage

let test_userspace_binding_generation () =
  let ast = make_test_ast () in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = generate_ir ast symbol_table "test" in
  let c_bindings = List.find_opt (fun b -> b.language = C) ir_multi_prog.userspace_bindings in
  
  match c_bindings with
  | Some bindings ->
      check bool "map wrappers present" true (List.length bindings.map_wrappers > 0);
      let first_wrapper = List.hd bindings.map_wrappers in
      let has_lookup = List.exists (fun op -> op = OpLookup) first_wrapper.operations in
      check bool "lookup operation present" true has_lookup
  | None ->
      fail "No C bindings found"

let test_variable_function_call_initialization () =
  (* Test for the bug where function calls in variable initializers 
     return to wrong registers, causing uninitialized variable usage *)
  let input = {|
@xdp fn test_handler(ctx: *xdp_md) -> xdp_action {
    return 2  // XDP_PASS
}

fn main() -> i32 {
    var prog = load(test_handler)  // Should assign to same register as 'prog'
    var result = attach(prog, "eth0", 0)  // Should use 'prog' register correctly
    return result
}
|} in

  try
    let ast = Kernelscript.Parse.parse_string input in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir_multi_prog = generate_ir typed_ast symbol_table "test_var_func_init" in
    
    (* Extract the main function from userspace program *)
    let userspace_program = match ir_multi_prog.userspace_program with
      | Some prog -> prog
      | None -> failwith "No userspace program found"
    in
    let main_func = List.find (fun func -> func.func_name = "main") userspace_program.userspace_functions in
    
    (* Collect all instructions from all basic blocks *)
    let all_instructions = List.flatten (List.map (fun block -> block.instructions) main_func.basic_blocks) in
    
    (* Find variable declarations and function calls *)
    let declarations = List.filter_map (fun instr ->
      match instr.instr_desc with
      | IRDeclareVariable (dest_val, _, _) -> Some dest_val
      | _ -> None
    ) all_instructions in
    
    let function_calls = List.filter_map (fun instr ->
      match instr.instr_desc with
      | IRCall (_, _, Some result_val) -> Some result_val
      | _ -> None
    ) all_instructions in
    
    (* Verify we have the expected number of declarations and calls *)
    check int "Should have variable declarations" 2 (List.length declarations);
    check int "Should have function calls" 2 (List.length function_calls);
    
    (* The key test: verify that function call returns go to the same registers as variable declarations *)
    let get_register_from_value val_desc = match val_desc with
      | IRRegister reg -> Some reg
      | _ -> None
    in
    
    let declaration_registers = List.filter_map (fun val_desc -> get_register_from_value val_desc.value_desc) declarations in
    let call_result_registers = List.filter_map (fun val_desc -> get_register_from_value val_desc.value_desc) function_calls in
    
    (* Verify that function call results use the same registers as variable declarations *)
    (* This catches the bug where function calls returned to different registers *)
    check bool "Function call results should use declaration registers" true 
      (List.for_all (fun reg -> List.mem reg declaration_registers) call_result_registers);
    
    (* Verify register consistency - each variable should map to exactly one register *)
    let sorted_decl_regs = List.sort compare declaration_registers in
    let sorted_call_regs = List.sort compare call_result_registers in
    check (list int) "Declaration and call registers should match" sorted_decl_regs sorted_call_regs
    
  with
  | e -> failwith (Printf.sprintf "Variable function call initialization test failed: %s" (Printexc.to_string e))

(** Test that register() calls in variable declarations generate IRStructOpsRegister instructions.
 * This test prevents regression of a critical bug where register() calls in variable declarations
 * like "var result = register(minimal_test)" were not being properly converted to IRStructOpsRegister
 * instructions. Instead, they were being processed as simple variable references, causing compilation 
 * errors like "error: 'minimal_test' undeclared (first use in this function)".
 * 
 * The bug existed because register() handling was only implemented in the main lower_expression path,
 * but variable declarations with function call initialization go through a separate code path in 
 * resolve_declaration_type_and_init that bypassed the special register() processing.
 * 
 * This test ensures that ALL register() calls, regardless of context, generate the correct 
 * IRStructOpsRegister instruction for proper struct_ops integration.
 *)
let test_register_builtin_ir_generation () =
  let input = {|
// Simple struct_ops impl block for testing
@struct_ops("tcp_congestion_ops")
impl minimal_test {
    fn init() -> u32 {
        return 1
    }
}

fn main() -> i32 {
    var result = register(minimal_test)  // This should generate IRStructOpsRegister
    return result
}
|} in

  try
    let ast = Kernelscript.Parse.parse_string input in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
    let ir_multi_prog = generate_ir typed_ast symbol_table "test_register_ir" in
    
    (* Find the userspace program *)
    let userspace_program = match ir_multi_prog.userspace_program with
      | Some prog -> prog
      | None -> failwith "No userspace program found"
    in
    let main_func = List.find (fun func -> func.func_name = "main") userspace_program.userspace_functions in
    
    (* Collect all instructions from all basic blocks *)
    let all_instructions = List.flatten (List.map (fun block -> block.instructions) main_func.basic_blocks) in
    
    (* Check that there's at least one IRStructOpsRegister instruction *)
    let struct_ops_registers = List.filter_map (fun instr ->
      match instr.instr_desc with
      | IRStructOpsRegister (result_val, struct_val) -> Some (result_val, struct_val)
      | _ -> None
    ) all_instructions in
    
    (* Before the fix, this would fail because register() calls weren't generating IRStructOpsRegister *)
    check bool "IRStructOpsRegister instruction generated" true (List.length struct_ops_registers > 0);
    
    (* Verify the instruction has the correct structure *)
    if List.length struct_ops_registers > 0 then (
      let (result_val, struct_val) = List.hd struct_ops_registers in
      check bool "result is register" true (match result_val.value_desc with IRRegister _ -> true | _ -> false);
      check bool "struct is variable reference" true (match struct_val.value_desc with IRVariable _ -> true | _ -> false)
    )
    
  with exn ->
    Printf.printf "Register IR test failed with exception: %s\n" (Printexc.to_string exn);
    check bool "test should not fail" false true

let ir_tests = [
  "program_lowering", `Quick, test_program_lowering;
  "context_access_lowering", `Quick, test_context_access_lowering;
  "map_operation_lowering", `Quick, test_map_operation_lowering;
  "bounds_check_insertion", `Quick, test_bounds_check_insertion;
  "stack_usage_tracking", `Quick, test_stack_usage_tracking;
  "userspace_binding_generation", `Quick, test_userspace_binding_generation;
  "variable_function_call_initialization", `Quick, test_variable_function_call_initialization;
  "register_builtin_ir_generation", `Quick, test_register_builtin_ir_generation;
]

let () =
  run "KernelScript IR Generation Tests" [
    "ir_generation", ir_tests;
  ] 