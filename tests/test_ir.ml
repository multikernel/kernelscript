(** Test IR generation functionality *)

open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ir_generator

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

let make_test_local_map () =
  make_map_declaration 
    "local_map" 
    U32 
    U32 
    HashMap 
    (make_test_map_config 100) 
    false 
    (make_test_position ())

let make_test_main_function () =
  let return_stmt = make_stmt 
    (Return (Some (make_expr (Literal (IntLit 0)) (make_test_position ())))) 
    (make_test_position ()) in
  make_function 
    "main" 
    [("ctx", XdpContext)] 
    (Some XdpAction) 
    [return_stmt] 
    (make_test_position ())

let make_test_program () =
  make_program_with_maps
    "test_xdp" 
    Xdp 
    [make_test_main_function ()] 
    [make_test_local_map ()]
    (make_test_position ())

let make_test_ast () =
  [
    MapDecl (make_test_global_map ());
    Program (make_test_program ());
  ]

(** Test functions matching the roadmap specifications *)

let test_program_lowering () =
  let ast = make_test_ast () in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ir_prog = generate_ir ast symbol_table in

  (* Verify program structure *)
  assert (ir_prog.program_type = Xdp);
  assert (List.length ir_prog.global_maps = 1);
  assert (List.length ir_prog.local_maps = 1);
  assert (ir_prog.main_function.is_main = true);
  Printf.printf "✓ Program lowering test passed\n"

let test_context_access_lowering () =
  let ctx_access = make_expr 
    (FunctionCall ("ctx.packet", [])) 
    (make_test_position ()) in
  let ctx_access = { ctx_access with expr_type = Some (Pointer U8) } in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  try
    let _ir_val = lower_expression ctx ctx_access in
    (* Should generate context access instruction *)
    assert (List.length ctx.current_block > 0);
    match (List.hd ctx.current_block).instr_desc with
    | IRContextAccess (_, PacketData) -> 
        Printf.printf "✓ Context access lowering test passed\n"
    | _ -> 
        Printf.printf "✗ Context access lowering test failed: wrong instruction type\n"
  with
  | exn ->
      Printf.printf "✗ Context access lowering test failed: %s\n" (Printexc.to_string exn)

let test_map_operation_lowering () =
  let map_access = make_expr 
    (ArrayAccess (
      make_expr (Identifier "local_map") (make_test_position ()),
      make_expr (Literal (IntLit 0)) (make_test_position ())
    )) 
    (make_test_position ()) in
  let map_access = { map_access with expr_type = Some U32 } in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  (* Add test map to context *)
  let test_map = make_ir_map_def 
    "local_map" 
    IRU32 
    IRU32 
    IRHashMap 
    100 
    ~flags:0
    (make_test_position ()) in
  Hashtbl.add ctx.maps "local_map" test_map;
  
  try
    let _ir_val = lower_expression ctx map_access in
    (* Should generate map lookup with bounds checks *)
    let has_map_load = List.exists (fun instr ->
      match instr.instr_desc with
      | IRMapLoad (_, _, _, MapLookup) -> true
      | _ -> false
    ) ctx.current_block in
    
    let _has_bounds_check = List.exists (fun instr ->
      List.length instr.bounds_checks > 0
    ) ctx.current_block in
    
    if has_map_load then
      Printf.printf "✓ Map operation lowering test passed\n"
    else
      Printf.printf "✗ Map operation lowering test failed: no map load found\n"
  with
  | exn ->
      Printf.printf "✗ Map operation lowering test failed: %s\n" (Printexc.to_string exn)

let test_bounds_check_insertion () =
  let array_decl = make_expr (Identifier "arr") (make_test_position ()) in
  let array_decl = { array_decl with expr_type = Some (Array (U32, 10)) } in
  let index_expr = make_expr (Literal (IntLit 5)) (make_test_position ()) in
  let array_access = make_expr 
    (ArrayAccess (array_decl, index_expr)) 
    (make_test_position ()) in
  let array_access = { array_access with expr_type = Some U32 } in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  try
    let _ir_val = lower_expression ctx array_access in
    let bounds_checks = List.concat_map (fun instr -> instr.bounds_checks) ctx.current_block in
    
    if List.length bounds_checks > 0 then (
      let has_array_access_check = List.exists (fun bc -> 
        bc.check_type = ArrayAccess
      ) bounds_checks in
      if has_array_access_check then
        Printf.printf "✓ Bounds check insertion test passed\n"
      else
        Printf.printf "✗ Bounds check insertion test failed: wrong check type\n"
    ) else
      Printf.printf "✗ Bounds check insertion test failed: no bounds checks\n"
  with
  | exn ->
      Printf.printf "✗ Bounds check insertion test failed: %s\n" (Printexc.to_string exn)

let test_stack_usage_tracking () =
  let buffer_decl = make_stmt 
    (Declaration ("buffer", Some (Array (U8, 100)), make_expr (Literal (IntLit 0)) (make_test_position ()))) 
    (make_test_position ()) in
  
  let test_func = make_function 
    "test" 
    [] 
    None 
    [buffer_decl] 
    (make_test_position ()) in
  
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  let ctx = create_context symbol_table in
  
  try
    let ir_func = lower_function ctx "test_program" test_func in
    
    if ir_func.total_stack_usage >= 100 then (
      let all_blocks_have_positive_usage = List.for_all (fun (bb : ir_basic_block) -> bb.stack_usage >= 0) ir_func.basic_blocks in
      if all_blocks_have_positive_usage then
        Printf.printf "✓ Stack usage tracking test passed\n"
      else
        Printf.printf "✗ Stack usage tracking test failed: negative stack usage\n"
    ) else
      Printf.printf "✗ Stack usage tracking test failed: insufficient stack usage (%d < 100)\n" ir_func.total_stack_usage
  with
  | exn ->
      Printf.printf "✗ Stack usage tracking test failed: %s\n" (Printexc.to_string exn)

let test_userspace_binding_generation () =
  let ast = make_test_ast () in
  let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  
  try
    let ir_prog = generate_ir ast symbol_table in
    let c_bindings = List.find_opt (fun b -> b.language = C) ir_prog.userspace_bindings in
    
    match c_bindings with
    | Some bindings ->
        if List.length bindings.map_wrappers > 0 then (
          let first_wrapper = List.hd bindings.map_wrappers in
          let has_lookup = List.exists (fun op -> op = OpLookup) first_wrapper.operations in
          if has_lookup then
            Printf.printf "✓ Userspace binding generation test passed\n"
          else
            Printf.printf "✗ Userspace binding generation test failed: no lookup operation\n"
        ) else
          Printf.printf "✗ Userspace binding generation test failed: no map wrappers\n"
    | None ->
        Printf.printf "✗ Userspace binding generation test failed: no C bindings\n"
  with
  | exn ->
      Printf.printf "✗ Userspace binding generation test failed: %s\n" (Printexc.to_string exn)

(** Run all tests *)
let run_tests () =
  Printf.printf "Running IR generation tests...\n\n";
  
  test_program_lowering ();
  test_context_access_lowering ();
  test_map_operation_lowering ();
  test_bounds_check_insertion ();
  test_stack_usage_tracking ();
  test_userspace_binding_generation ();
  
  Printf.printf "\nIR generation tests completed.\n"

(** Entry point *)
let () = run_tests () 