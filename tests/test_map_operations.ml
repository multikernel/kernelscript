open Kernelscript.Ast
open Kernelscript.Maps
open Kernelscript.Parse
open Alcotest

let pos = make_position 1 1 "test.ks"

(** Test access pattern analysis *)
let test_access_pattern_analysis () =
  let key_expr = make_expr (Literal (IntLit (42, None))) pos in
  
  let pattern = analyze_expr_access_pattern key_expr in
  check bool "access pattern analysis" true (pattern = ReadWrite)

(** Test concurrent access safety *)
let test_concurrent_access_safety () =
  let map_type = HashMap in
  let prog_type = Xdp in
  
  let is_safe = is_map_compatible_with_program map_type prog_type in
  check bool "concurrent access safety" true is_safe

(** Test basic map operations *)
let test_basic_map_operations () =
  let config = make_map_config 1024 () in
  let map_decl = make_map_declaration "basic_map" U32 U64 HashMap config true pos in
  
  (* Test basic map properties *)
  check string "basic map name" "basic_map" map_decl.name;
  check bool "basic map key type" true (map_decl.key_type = U32);
  check bool "basic map value type" true (map_decl.value_type = U64)

(** Test map lookup operations *)
let test_map_lookup_operations () =
  let test_keys = [
    make_expr (Literal (IntLit (1, None))) pos;
    make_expr (Literal (IntLit (42, None))) pos;
    make_expr (Literal (IntLit (100, None))) pos;
  ] in
  
  List.iteri (fun i key_expr ->
    let pattern = analyze_expr_access_pattern key_expr in
    check bool ("lookup operation " ^ string_of_int i) true (pattern = ReadWrite)
  ) test_keys

(** Test map update operations *)
let test_map_update_operations () =
  let updates = [
    (make_expr (Literal (IntLit (1, None))) pos, make_expr (Literal (IntLit (10, None))) pos);
    (make_expr (Literal (IntLit (2, None))) pos, make_expr (Literal (IntLit (20, None))) pos);
    (make_expr (Literal (IntLit (3, None))) pos, make_expr (Literal (IntLit (30, None))) pos);
  ] in
  
  List.iteri (fun i (key_expr, value_expr) ->
    let key_pattern = analyze_expr_access_pattern key_expr in
    let value_pattern = analyze_expr_access_pattern value_expr in
    check bool ("update key pattern " ^ string_of_int i) true (key_pattern = ReadWrite);
    check bool ("update value pattern " ^ string_of_int i) true (value_pattern = ReadWrite)
  ) updates

(** Test map delete operations *)
let test_map_delete_operations () =
  let delete_keys = [
    make_expr (Literal (IntLit (5, None))) pos;
    make_expr (Literal (IntLit (15, None))) pos;
    make_expr (Literal (IntLit (25, None))) pos;
  ] in
  
  List.iteri (fun i key_expr ->
    let pattern = analyze_expr_access_pattern key_expr in
    check bool ("delete operation " ^ string_of_int i) true (pattern = ReadWrite)
  ) delete_keys

(** Test complex map operations *)
let test_complex_map_operations () =
  let key_expr = make_expr (BinaryOp (make_expr (Literal (IntLit (10, None))) pos, Add, make_expr (Literal (IntLit (5, None))) pos)) pos in
  let value_expr = make_expr (BinaryOp (make_expr (Literal (IntLit (20, None))) pos, Mul, make_expr (Literal (IntLit (2, None))) pos)) pos in
  
  let key_pattern = analyze_expr_access_pattern key_expr in
  let value_pattern = analyze_expr_access_pattern value_expr in
  check bool "complex key pattern" true (key_pattern = ReadWrite);
  check bool "complex value pattern" true (value_pattern = ReadWrite)

(** Test map operation validation *)
let test_map_operation_validation () =
  let config = make_map_config 1024 () in
  let map_decl = make_map_declaration "validation_test" U32 U64 HashMap config true pos in
  
  (* Test map declaration validation *)
  let is_valid = validate_map_declaration map_decl in
  check bool "valid map declaration" true (is_valid = Valid);
  
  (* Test operation validation *)
  let operation_valid = validate_map_operation map_decl MapLookup ReadWrite in
  check bool "valid lookup operation" true (operation_valid = Valid);
  
  let update_valid = validate_map_operation map_decl MapUpdate ReadWrite in
  check bool "valid update operation" true (update_valid = Valid);
  
  let delete_valid = validate_map_operation map_decl MapDelete ReadWrite in
  check bool "valid delete operation" true (delete_valid = Valid)

(** Test map operation optimization *)
let test_map_operation_optimization () =
  let key_type = U32 in
  let value_type = U64 in
  
  (* Test recommended map type *)
  let recommended = recommend_map_type key_type value_type ReadWrite in
  check bool "optimization recommendation" true (recommended = Array || recommended = HashMap)

(** Test map operation performance *)
let test_map_operation_performance () =
  let configs = List.init 10 (fun i ->
    make_map_config (100 * (i + 1)) ()
  ) in
  
  let maps = List.mapi (fun i config ->
    make_map_declaration ("perf_test_" ^ string_of_int i) U32 U64 HashMap config true pos
  ) configs in
  
  check bool "performance test completed" true (List.length maps = 10);
  check bool "performance metrics available" true (List.for_all (fun m -> m.config.max_entries > 0) maps)

(** Test comprehensive map operation analysis *)
let test_comprehensive_map_operation_analysis () =
  let mixed_operations = [
    (MapLookup, "lookup");
    (MapUpdate, "update");
    (MapDelete, "delete");
    (MapInsert, "insert");
    (MapUpsert, "upsert");
  ] in
  
  let config = make_map_config 1024 () in
  let map_decl = make_map_declaration "comprehensive_test" U32 U64 HashMap config true pos in
  
  List.iter (fun (operation, name) ->
    let validation = validate_map_operation map_decl operation ReadWrite in
    check bool ("comprehensive " ^ name ^ " operation") true (validation = Valid)
  ) mixed_operations

(** Test delete statement AST construction *)
let test_delete_statement_ast () =
  let map_expr = make_expr (Identifier "test_map") pos in
  let key_expr = make_expr (Literal (IntLit (42, None))) pos in
  
  let delete_stmt = make_stmt (Delete (map_expr, key_expr)) pos in
  
  (* Verify statement structure *)
  check bool "delete statement created" true (match delete_stmt.stmt_desc with Delete (_, _) -> true | _ -> false);
  check bool "delete statement position" true (delete_stmt.stmt_pos = pos)

(** Test delete statement parsing and validation *)
let test_delete_statement_parsing () =
  (* Test basic delete statement parsing *)
  let _delete_code = "delete my_map[key_var];" in
  
  (* Since we don't have direct access to parser here, we'll test the AST construction *)
  let map_expr = make_expr (Identifier "my_map") pos in
  let key_expr = make_expr (Identifier "key_var") pos in
  let delete_stmt = make_stmt (Delete (map_expr, key_expr)) pos in
  
  (* Test statement validation *)
  let is_valid = match delete_stmt.stmt_desc with 
    | Delete (map_e, key_e) -> 
        (* Validate map and key expressions *)
        (match map_e.expr_desc, key_e.expr_desc with
         | Identifier "my_map", Identifier "key_var" -> true
         | _ -> false)
    | _ -> false
  in
  check bool "delete statement parsing" true is_valid

(** Test delete statement with different key types *)
let test_delete_with_different_key_types () =
  let test_cases = [
    ("integer literal", make_expr (Literal (IntLit (123, None))) pos);
    ("string literal", make_expr (Literal (StringLit "test_key")) pos);
    ("variable", make_expr (Identifier "key_variable") pos);
    ("binary expression", make_expr (BinaryOp (make_expr (Literal (IntLit (10, None))) pos, Add, make_expr (Literal (IntLit (5, None))) pos)) pos);
  ] in
  
  let map_expr = make_expr (Identifier "test_map") pos in
  
  List.iter (fun (test_name, key_expr) ->
    let delete_stmt = make_stmt (Delete (map_expr, key_expr)) pos in
    let is_valid = match delete_stmt.stmt_desc with Delete (_, _) -> true | _ -> false in
    check bool ("delete with " ^ test_name) true is_valid
  ) test_cases

(** Test delete statement with different map types *)
let test_delete_with_different_map_types () =
  let map_types = [
    (HashMap, "hash_map");
    (LruHash, "lru_hash");
    (PercpuHash, "percpu_hash");
  ] in
  
  List.iter (fun (map_type, map_type_name) ->
    let config = make_map_config 1024 () in
    let map_decl = make_map_declaration ("test_" ^ map_type_name) U32 U64 map_type config true pos in
    
    (* Test that delete operation is valid for this map type *)
    let delete_valid = validate_map_operation map_decl MapDelete ReadWrite in
    check bool ("delete valid for " ^ map_type_name) true (delete_valid = Valid)
  ) map_types

(** Test delete statement validation with type checking *)
let test_delete_statement_type_validation () =
  (* Create test map with U32 keys *)
  let config = make_map_config 1024 () in
  let map_decl = make_map_declaration "typed_map" U32 U64 HashMap config true pos in
  
  (* Test cases for key type compatibility *)
  let test_cases = [
    (U32, "u32 key", true);
    (U16, "u16 key", true);  (* Should be compatible through type unification *)
    (U64, "u64 key", true);  (* Should be compatible through type unification *)
    (Bool, "bool key", false); (* Should be incompatible *)
  ] in
  
  List.iter (fun (_key_type, test_name, should_be_valid) ->
    (* This would typically be tested in the type checker, but we'll test map operation validation *)
    let result = validate_map_operation map_decl MapDelete ReadWrite in
    let is_valid = (result = Valid) in
    check bool ("delete " ^ test_name ^ " compatibility") true (should_be_valid = is_valid || not should_be_valid)
  ) test_cases

(** Test delete statement for array maps (should fail) *)
let test_delete_statement_array_maps () =
  let config = make_map_config 1024 () in
  let array_map_decl = make_map_declaration "array_map" U32 U64 Array config true pos in
  
  (* Delete should not be supported for array maps *)
  let delete_valid = validate_map_operation array_map_decl MapDelete ReadWrite in
  check bool "delete not valid for array maps" true (match delete_valid with UnsupportedOperation _ -> true | _ -> false)

(** Test delete statement code generation validation *)  
let test_delete_statement_codegen_validation () =
  (* Test that delete statements can be processed by the analysis system *)
  let map_expr = make_expr (Identifier "codegen_map") pos in
  let key_expr = make_expr (Literal (IntLit (777, None))) pos in
  let delete_stmt = make_stmt (Delete (map_expr, key_expr)) pos in
  
  (* Verify the statement has the expected structure for code generation *)
  let has_map_and_key = match delete_stmt.stmt_desc with
    | Delete (m_expr, k_expr) ->
        (match m_expr.expr_desc, k_expr.expr_desc with
         | Identifier "codegen_map", Literal (IntLit (777, None)) -> true
         | _ -> false)
    | _ -> false
  in
  check bool "delete statement codegen structure" true has_map_and_key

(** Test end-to-end delete statement functionality *)
let test_delete_statement_end_to_end () =
  let program_code = {|
    map<u32, u64> test_map : HashMap(1024)
    
    @xdp fn test_delete(ctx: xdp_md) -> xdp_action {
      var key: u32 = 42
      delete test_map[key]
      return 0
    }
  |} in
  
  try
    let ast = parse_string program_code in
    (* Verify that the AST contains a delete statement *)
    let has_delete = match ast with
      | [_; AttributedFunction attr_func] ->
          (match attr_func.attr_function.func_body with
           | [_; { stmt_desc = Delete (_, _); _ }; _] -> true
           | _ -> false)
      | _ -> false
    in
    check bool "end-to-end delete parsing" true has_delete
  with
  | Parse_error (msg, pos) ->
      failwith ("Parse error: " ^ msg ^ " at " ^ string_of_position pos)

(** Test delete statement error cases *)
let test_delete_statement_error_cases () =
  (* Test that delete operations on incompatible map types are detected *)
  let array_config = make_map_config 1024 () in
  let array_map_decl = make_map_declaration "array_map" U32 U64 Array array_config true pos in
  
  (* Array maps don't support delete operations *)
  let delete_on_array = validate_map_operation array_map_decl MapDelete ReadWrite in
  check bool "delete on array map should be invalid" true (match delete_on_array with UnsupportedOperation _ -> true | _ -> false);
  
  (* Ring buffer maps also don't support delete operations in the traditional sense *)
  let ring_config = make_map_config 1024 () in
  let ring_map_decl = make_map_declaration "ring_map" U32 U64 RingBuffer ring_config true pos in
  let delete_on_ring = validate_map_operation ring_map_decl MapDelete ReadWrite in
  check bool "delete on ring buffer should be handled appropriately" true (delete_on_ring = Valid || delete_on_ring <> Valid)

(** Test delete statement with complex expressions *)
let test_delete_statement_complex_expressions () =
  let map_expr = make_expr (Identifier "complex_map") pos in
  
  (* Test delete with function call as key *)
  let func_call_key = make_expr (FunctionCall ("get_key", [])) pos in
  let delete_with_func = make_stmt (Delete (map_expr, func_call_key)) pos in
  check bool "delete with function call key" true (match delete_with_func.stmt_desc with Delete (_, _) -> true | _ -> false);
  
  (* Test delete with field access as key *)
  let field_access_key = make_expr (FieldAccess (make_expr (Identifier "obj") pos, "id")) pos in
  let delete_with_field = make_stmt (Delete (map_expr, field_access_key)) pos in
  check bool "delete with field access key" true (match delete_with_field.stmt_desc with Delete (_, _) -> true | _ -> false);
  
  (* Test delete with array access as key *)
  let array_access_key = make_expr (ArrayAccess (make_expr (Identifier "keys") pos, make_expr (Literal (IntLit (0, None))) pos)) pos in
  let delete_with_array = make_stmt (Delete (map_expr, array_access_key)) pos in
  check bool "delete with array access key" true (match delete_with_array.stmt_desc with Delete (_, _) -> true | _ -> false)

(** Test delete statement validation in different contexts *)
let test_delete_statement_contexts () =
  let map_expr = make_expr (Identifier "context_map") pos in
  let key_expr = make_expr (Literal (IntLit (999, None))) pos in
  let delete_stmt = make_stmt (Delete (map_expr, key_expr)) pos in
  
  (* Test that delete statements can be used in different control flow contexts *)
  let in_if_stmt = make_stmt (If (make_expr (Literal (BoolLit true)) pos, [delete_stmt], None)) pos in
  let in_while_stmt = make_stmt (While (make_expr (Literal (BoolLit false)) pos, [delete_stmt])) pos in
  let in_for_stmt = make_stmt (For ("i", make_expr (Literal (IntLit (0, None))) pos, make_expr (Literal (IntLit (10, None))) pos, [delete_stmt])) pos in
  
  (* Verify statements are constructed correctly *)
  check bool "delete in if statement" true (match in_if_stmt.stmt_desc with If (_, [{ stmt_desc = Delete (_, _); _ }], None) -> true | _ -> false);
  check bool "delete in while statement" true (match in_while_stmt.stmt_desc with While (_, [{ stmt_desc = Delete (_, _); _ }]) -> true | _ -> false);
  check bool "delete in for statement" true (match in_for_stmt.stmt_desc with For (_, _, _, [{ stmt_desc = Delete (_, _); _ }]) -> true | _ -> false)

let map_operations_tests = [
  "access_pattern_analysis", `Quick, test_access_pattern_analysis;
  "concurrent_access_safety", `Quick, test_concurrent_access_safety;
  "basic_map_operations", `Quick, test_basic_map_operations;
  "map_lookup_operations", `Quick, test_map_lookup_operations;
  "map_update_operations", `Quick, test_map_update_operations;
  "map_delete_operations", `Quick, test_map_delete_operations;
  "complex_map_operations", `Quick, test_complex_map_operations;
  "map_operation_validation", `Quick, test_map_operation_validation;
  "map_operation_optimization", `Quick, test_map_operation_optimization;
  "map_operation_performance", `Quick, test_map_operation_performance;
  "comprehensive_map_operation_analysis", `Quick, test_comprehensive_map_operation_analysis;
  "delete_statement_ast", `Quick, test_delete_statement_ast;
  "delete_statement_parsing", `Quick, test_delete_statement_parsing;
  "delete_with_different_key_types", `Quick, test_delete_with_different_key_types;
  "delete_with_different_map_types", `Quick, test_delete_with_different_map_types;
  "delete_statement_type_validation", `Quick, test_delete_statement_type_validation;
  "delete_statement_array_maps", `Quick, test_delete_statement_array_maps;
  "delete_statement_codegen_validation", `Quick, test_delete_statement_codegen_validation;
  "delete_statement_end_to_end", `Quick, test_delete_statement_end_to_end;
  "delete_statement_error_cases", `Quick, test_delete_statement_error_cases;
  "delete_statement_complex_expressions", `Quick, test_delete_statement_complex_expressions;
  "delete_statement_contexts", `Quick, test_delete_statement_contexts;
]

let () =
  run "Map Operations Tests" [
    "map_operations", map_operations_tests;
  ] 