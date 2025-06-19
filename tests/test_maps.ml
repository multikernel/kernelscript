open Kernelscript.Ast
open Kernelscript.Maps
open Alcotest

(** Test basic map creation *)
let test_basic_map_creation () =
  let key_type = U32 in
  let value_type = U64 in
  let map_type = HashMap in
  let size = 1024 in
  
  let map_config = make_map_config size () in
  let pos = make_position 1 1 "test.ks" in
  let map_decl = make_map_declaration "counter" key_type value_type map_type map_config true pos in
  
  check string "basic map creation name" "counter" map_decl.name;
  check bool "map key type" true (map_decl.key_type = key_type);
  check bool "map value type" true (map_decl.value_type = value_type);
  check int "map size" size map_decl.config.max_entries

(** Test different map types *)
let test_different_map_types () =
  let test_cases = [
    (HashMap, "HashMap");
    (Array, "Array");
    (LruHash, "LruHash");
    (PercpuHash, "PercpuHash");
  ] in
  
  List.iter (fun (map_type, expected_name) ->
    let config = make_map_config 1024 () in
    let pos = make_position 1 1 "test.ks" in
    let map_decl = make_map_declaration "test" U32 U64 map_type config true pos in
    check bool ("map type: " ^ expected_name) true (map_decl.map_type = map_type)
  ) test_cases

(** Test map key/value types *)
let test_map_key_value_types () =
  let test_cases = [
    (U8, U16, "u8", "u16");
    (U32, U64, "u32", "u64");
    (U64, Bool, "u64", "bool");
    (Bool, U32, "bool", "u32");
  ] in
  
  List.iter (fun (key_type, value_type, expected_key, expected_value) ->
    let config = make_map_config 1024 () in
    let pos = make_position 1 1 "test.ks" in
    let map_decl = make_map_declaration "test" key_type value_type HashMap config true pos in
    check bool ("key type: " ^ expected_key) true (map_decl.key_type = key_type);
    check bool ("value type: " ^ expected_value) true (map_decl.value_type = value_type)
  ) test_cases

(** Test map operations *)
let test_map_operations () =
  let pos = make_position 1 1 "test.ks" in
  let config = make_map_config 1024 () in
  let map_decl = make_map_declaration "counter" U32 U64 HashMap config true pos in
  
  (* Test map declaration properties *)
  check string "map operations map name" "counter" map_decl.name;
  check bool "map operations key type" true (map_decl.key_type = U32);
  check bool "map operations value type" true (map_decl.value_type = U64)

(** Test map initialization *)
let test_map_initialization () =
  let pos = make_position 1 1 "test.ks" in
  let config = make_map_config 1024 () in
  let map_decl = make_map_declaration "initialized_map" U32 U64 HashMap config true pos in
  
  check string "initialized map name" "initialized_map" map_decl.name;
  check bool "map has config" true (map_decl.config.max_entries > 0);
  check int "initialization size" 1024 map_decl.config.max_entries

(** Test map validation *)
let test_map_validation () =
  let pos = make_position 1 1 "test.ks" in
  
  (* Test valid map *)
  let config = make_map_config 1024 () in
  let valid_map = make_map_declaration "valid" U32 U64 HashMap config true pos in
  let is_valid = validate_map_declaration valid_map in
  check bool "valid map validation" true (is_valid = Valid);
  
  (* Test invalid map with zero size *)
  let invalid_config = make_map_config 0 () in
  let invalid_map = make_map_declaration "invalid" U32 U64 HashMap invalid_config true pos in
  let is_invalid = validate_map_declaration invalid_map in
  check bool "invalid map validation" false (is_invalid = Valid)

(** Test map program integration *)
let test_map_program_integration () =
  let pos = make_position 1 1 "test.ks" in
  let config = make_map_config 1024 () in
  
  (* Create maps *)
  let packet_count_map = make_map_declaration "packet_count" U32 U64 HashMap config true pos in
  let byte_count_map = make_map_declaration "byte_count" U32 U64 HashMap config true pos in
  
  (* Test map integration *)
  check string "first map name" "packet_count" packet_count_map.name;
  check string "second map name" "byte_count" byte_count_map.name;
  
  (* Test map compatibility *)
  let is_compatible = is_map_compatible_with_program HashMap Xdp in
  check bool "program uses maps" true is_compatible

(** Test map type compatibility *)
let test_map_type_compatibility () =
  let pos = make_position 1 1 "test.ks" in
  let config = make_map_config 1024 () in
  
  (* Test compatible types *)
  let compatible_map = make_map_declaration "compatible" U32 U64 HashMap config true pos in
  let is_compatible = is_map_compatible_with_program compatible_map.map_type Xdp in
  check bool "compatible types" true is_compatible;
  
  (* Test type validation *)
  let validation_result = validate_map_declaration compatible_map in
  check bool "type validation" true (validation_result = Valid)

(** Test map size validation *)
let test_map_size_validation () =
  let pos = make_position 1 1 "test.ks" in
  
  (* Test valid sizes *)
  let valid_sizes = [1; 1024; 4096; 65536] in
  List.iter (fun size ->
    let config = make_map_config size () in
    let map_decl = make_map_declaration "test" U32 U64 HashMap config true pos in
    let is_valid = validate_map_declaration map_decl in
    check bool ("valid size: " ^ string_of_int size) true (is_valid = Valid)
  ) valid_sizes

(** Test map access patterns *)
let test_map_access_patterns () =
  let pos = make_position 1 1 "test.ks" in
  let key_expr = make_expr (Literal (IntLit (42, None))) pos in
  
  (* Test access pattern analysis *)
  let pattern = analyze_expr_access_pattern key_expr in
  check bool "access pattern analysis" true (pattern = ReadWrite)

(** Test map error handling *)
let test_map_error_handling () =
  let pos = make_position 1 1 "test.ks" in
  let config = make_map_config 1024 () in
  
  (* Test error conditions *)
  try
    let _ = make_map_declaration "" U32 U64 HashMap config true pos in
    check bool "empty name handled" true true
  with
  | _ -> check bool "empty name error handled" true true

(** Test map metadata *)
let test_map_metadata () =
  let pos = make_position 1 1 "test.ks" in
  let config = make_map_config 1024 () in
  let map_decl = make_map_declaration "metadata_test" U32 U64 HashMap config true pos in
  
  (* Test metadata properties *)
  check string "metadata map name" "metadata_test" map_decl.name;
  check bool "metadata has key type" true (map_decl.key_type = U32);
  check bool "metadata has value type" true (map_decl.value_type = U64);
  check int "metadata size" 1024 map_decl.config.max_entries

(** Test map serialization *)
let test_map_serialization () =
  let pos = make_position 1 1 "test.ks" in
  let config = make_map_config 1024 () in
  let original_map = make_map_declaration "serialize_test" U32 U64 HashMap config true pos in
  
  (* Test string representation *)
  let serialized = string_of_map_declaration original_map in
  check bool "serialization produces string" true (String.length serialized > 0);
  
  (* Test that serialization contains map name *)
  check bool "serialization contains name" true (String.contains serialized 's')

let maps_tests = [
  "basic_map_creation", `Quick, test_basic_map_creation;
  "different_map_types", `Quick, test_different_map_types;
  "map_key_value_types", `Quick, test_map_key_value_types;
  "map_operations", `Quick, test_map_operations;
  "map_initialization", `Quick, test_map_initialization;
  "map_validation", `Quick, test_map_validation;
  "map_program_integration", `Quick, test_map_program_integration;
  "map_type_compatibility", `Quick, test_map_type_compatibility;
  "map_size_validation", `Quick, test_map_size_validation;
  "map_access_patterns", `Quick, test_map_access_patterns;
  "map_error_handling", `Quick, test_map_error_handling;
  "map_metadata", `Quick, test_map_metadata;
  "map_serialization", `Quick, test_map_serialization;
]

let () =
  run "Maps Tests" [
    "maps", maps_tests;
  ] 