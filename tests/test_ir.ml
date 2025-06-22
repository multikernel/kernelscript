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
end

(** Helper functions for creating test AST nodes *)

let make_test_position () = make_position 1 1 "test.ks"

let make_test_map_config max_entries =
  make_map_config max_entries []

let make_test_global_map () =
  make_map_declaration 
    "global_counter" 
    U32 
    U64 
    Array 
    (make_test_map_config 256) 
    true 
    (make_test_position ())

let make_test_global_map_2 () =
  make_map_declaration 
    "global_map_2" 
    U32 
    U32 
    HashMap 
    (make_test_map_config 100) 
    true 
    (make_test_position ())

let make_test_main_function () =
  let return_stmt = make_stmt 
    (Return (Some (make_expr (Literal (IntLit (0, None))) (make_test_position ())))) 
    (make_test_position ()) in
  make_function 
    "test_xdp" 
    [("ctx", XdpContext)] 
    (Some XdpAction) 
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
    (FunctionCall ("ctx.packet", [])) 
    (make_test_position ()) in
  let ctx_access = { ctx_access with expr_type = Some (Pointer U8) } in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  let _ir_val = lower_expression ctx ctx_access in
  (* Should generate context access instruction *)
  check bool "instruction generated" true (List.length ctx.current_block > 0);
  match (List.hd ctx.current_block).instr_desc with
  | IRContextAccess (_, PacketData) -> () (* Success *)
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
    (Declaration ("buffer", Some (Array (U8, 100)), make_expr (Literal (IntLit (0, None))) (make_test_position ()))) 
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

let ir_tests = [
  "program_lowering", `Quick, test_program_lowering;
  "context_access_lowering", `Quick, test_context_access_lowering;
  "map_operation_lowering", `Quick, test_map_operation_lowering;
  "bounds_check_insertion", `Quick, test_bounds_check_insertion;
  "stack_usage_tracking", `Quick, test_stack_usage_tracking;
  "userspace_binding_generation", `Quick, test_userspace_binding_generation;
]

let () =
  run "KernelScript IR Generation Tests" [
    "ir_generation", ir_tests;
  ] 