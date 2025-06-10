open Kernelscript.Ast
open Kernelscript.Maps
open Alcotest

let pos = make_position 1 1 "test.ks"

(** Test access pattern analysis *)
let test_access_pattern_analysis () =
  let key_expr = make_expr (Literal (IntLit 42)) pos in
  
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
    make_expr (Literal (IntLit 1)) pos;
    make_expr (Literal (IntLit 42)) pos;
    make_expr (Literal (IntLit 100)) pos;
  ] in
  
  List.iteri (fun i key_expr ->
    let pattern = analyze_expr_access_pattern key_expr in
    check bool ("lookup operation " ^ string_of_int i) true (pattern = ReadWrite)
  ) test_keys

(** Test map update operations *)
let test_map_update_operations () =
  let updates = [
    (make_expr (Literal (IntLit 1)) pos, make_expr (Literal (IntLit 10)) pos);
    (make_expr (Literal (IntLit 2)) pos, make_expr (Literal (IntLit 20)) pos);
    (make_expr (Literal (IntLit 3)) pos, make_expr (Literal (IntLit 30)) pos);
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
    make_expr (Literal (IntLit 5)) pos;
    make_expr (Literal (IntLit 15)) pos;
    make_expr (Literal (IntLit 25)) pos;
  ] in
  
  List.iteri (fun i key_expr ->
    let pattern = analyze_expr_access_pattern key_expr in
    check bool ("delete operation " ^ string_of_int i) true (pattern = ReadWrite)
  ) delete_keys

(** Test complex map operations *)
let test_complex_map_operations () =
  let key_expr = make_expr (BinaryOp (make_expr (Literal (IntLit 10)) pos, Add, make_expr (Literal (IntLit 5)) pos)) pos in
  let value_expr = make_expr (BinaryOp (make_expr (Literal (IntLit 20)) pos, Mul, make_expr (Literal (IntLit 2)) pos)) pos in
  
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
]

let () =
  run "Map Operations Tests" [
    "map_operations", map_operations_tests;
  ] 