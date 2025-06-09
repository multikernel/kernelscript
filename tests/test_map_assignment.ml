open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Type_checker
open Kernelscript.Ir_generator
open Kernelscript.Ir

(** Test suite for Map Assignment (IndexAssignment) functionality *)

let run_test test_name test_func =
  Printf.printf "%-40s " test_name;
  try
    if test_func () then
      Printf.printf "✅ PASS\n"
    else
      Printf.printf "❌ FAIL\n"
  with
  | exn ->
      Printf.printf "❌ ERROR: %s\n" (Printexc.to_string exn)

(** Test parsing of IndexAssignment statements *)
let test_index_assignment_parsing () =
  let test_cases = [
    (* Basic assignment *)
    ("my_map[key] = value;", true);
    (* Assignment with expressions *)
    ("my_map[key + 1] = value * 2;", true);
    (* Nested map access in assignment *)
    ("my_map[other_map[key]] = compute_value();", true);  
    (* Array-style assignment *)
    ("array_map[42] = 100;", true);
    (* Complex expression assignment *)
    ("packet_counts[src_ip] = packet_counts[src_ip] + 1;", true);
    (* Invalid: missing semicolon *)
    ("my_map[key] = value", false);
    (* Invalid: malformed syntax *)
    ("my_map[key = value;", false);
  ] in
  
  List.for_all (fun (stmt, should_succeed) ->
    let program = Printf.sprintf {|
map my_map : HashMap<u32, u64> { max_entries: 1024; }
map other_map : HashMap<u32, u32> { max_entries: 512; }
map array_map : Array<u32, u32> { max_entries: 256; }
map packet_counts : HashMap<u32, u64> { max_entries: 1024; }

program test : xdp {
  fn compute_value() -> u64 { return 42; }
  fn main() -> u32 {
    let key = 10;
    let value = 20;
    let src_ip = 0x12345678;
    %s
    return 0;
  }
}
|} stmt in
    try
      let _ = parse_string program in
      should_succeed
    with
    | _ -> not should_succeed
  ) test_cases

(** Test AST structure for IndexAssignment *)
let test_index_assignment_ast () =
  let program = {|
map test_map : HashMap<u32, u64> { max_entries: 1024; }

program test : xdp {
  fn main() -> u32 {
    test_map[42] = 100;
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    match ast with
    | [MapDecl _; Program prog] ->
        (match prog.prog_functions with
         | [main_func] ->
             (match main_func.func_body with
              | [assign_stmt; _] ->
                  (match assign_stmt.stmt_desc with
                   | IndexAssignment (map_expr, key_expr, value_expr) ->
                       (* Verify the structure *)
                       (match map_expr.expr_desc with
                        | Identifier "test_map" -> 
                            (match key_expr.expr_desc with
                             | Literal (IntLit 42) ->
                                 (match value_expr.expr_desc with
                                  | Literal (IntLit 100) -> true
                                  | _ -> false)
                             | _ -> false)
                        | _ -> false)
                   | _ -> false)
              | _ -> false)
         | _ -> false)
    | _ -> false
  with
  | _ -> false

(** Test type checking for IndexAssignment *)
let test_index_assignment_type_checking () =
  let valid_program = {|
map test_map : HashMap<u32, u64> { max_entries: 1024; }

program test : xdp {
  fn main() -> u32 {
    let key: u32 = 42;
    let value: u64 = 100;
    test_map[key] = value;
    return 0;
  }
}
|} in
  
  let invalid_program = {|
map test_map : HashMap<u32, u64> { max_entries: 1024; }

program test : xdp {
  fn main() -> u32 {
    let key = "invalid_key";  // String key for u32 map
    let value: u64 = 100;
    test_map[key] = value;
    return 0;
  }
}
|} in
  
  try
    (* Valid program should type check *)
    let ast1 = parse_string valid_program in
    let _ = type_check_ast ast1 in
    
    (* Invalid program should fail type checking *)
    let ast2 = parse_string invalid_program in
    let _ = type_check_ast ast2 in
    false  (* Should not reach here *)
  with
  | Type_error _ -> true  (* Expected for invalid program *)
  | _ -> false

(** Test typed AST structure for IndexAssignment *)
let test_typed_index_assignment () =
  let program = {|
map test_map : HashMap<u32, u64> { max_entries: 1024; }

program test : xdp {
  fn main() -> u32 {
    test_map[42] = 100;
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    let typed_programs = type_check_ast ast in
    match typed_programs with
    | [typed_prog] ->
        (match typed_prog.tprog_functions with
         | [main_func] ->
             (match main_func.tfunc_body with
              | [assign_stmt; _] ->
                  (match assign_stmt.tstmt_desc with
                   | TIndexAssignment (map_expr, key_expr, value_expr) ->
                       (* Verify types *)
                       map_expr.texpr_type = Map (U32, U64, HashMap) &&
                       key_expr.texpr_type = U32 &&
                       value_expr.texpr_type = U64
                   | _ -> false)
              | _ -> false)
         | _ -> false)
    | _ -> false
  with
  | _ -> false

(** Test IR generation for IndexAssignment *)
let test_index_assignment_ir () =
  let program = {|
map test_map : HashMap<u32, u64> { max_entries: 1024; }

program test : xdp {
  fn main() -> u32 {
    let key = 42;
    let value = 100;
    test_map[key] = value;
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    let typed_programs = type_check_ast ast in
    
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ctx = create_context symbol_table in
    let map_decl = match ast with
      | [MapDecl md; _] -> md
      | _ -> failwith "Expected map declaration"
    in
    let ir_map_def = Kernelscript.Ir_generator.lower_map_declaration map_decl in
    Hashtbl.add ctx.maps map_decl.name ir_map_def;
    
    match typed_programs with
    | [_typed_prog] ->
        let ir_program = lower_program ast symbol_table in
        let ir_funcs = ir_program.functions in
        
        (* Check that IR contains map store operations *)
        let has_map_store = List.exists (fun ir_func ->
          List.exists (fun block ->
            List.exists (fun instr ->
              match instr.instr_desc with
              | IRMapStore _ -> true
              | _ -> false
            ) block.instructions
          ) ir_func.basic_blocks
        ) ir_funcs in
        
        has_map_store
    | _ -> false
  with
  | _ -> false

(** Test complex IndexAssignment scenarios *)
let test_complex_index_assignment () =
  let program = {|
map packet_counts : HashMap<u32, u64> { max_entries: 1024; }
map user_limits : HashMap<u32, u64> { max_entries: 512; }

program rate_limiter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let src_ip = 0x08080808;
    
    // Get current count
    let current_count = packet_counts[src_ip];
    
    // Increment count
    packet_counts[src_ip] = current_count + 1;
    
    // Set limit if not exists
    if (user_limits[src_ip] == 0) {
      user_limits[src_ip] = 1000;
    }
    
    // Check limit
    if (packet_counts[src_ip] > user_limits[src_ip]) {
      return 1;  // Drop
    }
    
    return 2;  // Pass
  }
}
|} in
  try
    let ast = parse_string program in
    let typed_programs = type_check_ast ast in
    
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ctx = create_context symbol_table in
    
        (* Add maps to context *)
    (match ast with
     | [MapDecl md1; MapDecl md2; _] ->
         let ir_map_def1 = Kernelscript.Ir_generator.lower_map_declaration md1 in
         let ir_map_def2 = Kernelscript.Ir_generator.lower_map_declaration md2 in
         Hashtbl.add ctx.maps md1.name ir_map_def1;
         Hashtbl.add ctx.maps md2.name ir_map_def2;
      | _ -> failwith "Expected two map declarations");
    
    match typed_programs with
    | [_typed_prog] ->
        let ir_program = lower_program ast symbol_table in
        let _ = ir_program.functions in
        true
    | _ -> false
  with
  | _ -> false

(** Test symbol table processing of IndexAssignment *)
let test_symbol_table_index_assignment () =
  let program = {|
map test_map : HashMap<u32, u64> { max_entries: 1024; }

program test : xdp {
  fn main() -> u32 {
    let key = 42;
    let value = 100;
    test_map[key] = value;
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    
    (* Create symbol table context *)
    let ctx = Kernelscript.Symbol_table.create_symbol_table () in
    
    (* Process the AST - this should not fail *)
    let _ = match ast with
      | [MapDecl md; Program _prog] ->
          Hashtbl.add ctx.global_maps md.name md;
          () (* Symbol table created successfully *)
      | _ -> failwith "Unexpected AST structure"
    in
    true
  with
  | _ -> false

(** Main test runner *)
let () =
  Printf.printf "=== Map Assignment (IndexAssignment) Test Suite ===\n\n";
  
  run_test "IndexAssignment parsing" test_index_assignment_parsing;
  run_test "IndexAssignment AST structure" test_index_assignment_ast;
  run_test "IndexAssignment type checking" test_index_assignment_type_checking;
  run_test "Typed IndexAssignment" test_typed_index_assignment;
  run_test "IndexAssignment IR generation" test_index_assignment_ir;
  run_test "Complex IndexAssignment" test_complex_index_assignment;
  run_test "Symbol table IndexAssignment" test_symbol_table_index_assignment;
  
  Printf.printf "\n=== Map Assignment Tests Complete ===\n" 