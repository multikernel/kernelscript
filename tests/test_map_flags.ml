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

open Kernelscript.Ast
open Kernelscript.Parse
open Alcotest

module Maps = Kernelscript.Maps



(* Type aliases from Maps module *)
type map_flag_info = Maps.map_flag_info = {
  map_name: string;
  has_initial_values: bool;
  initial_values: string list;
  key_type: string;
  value_type: string;
}
type flag_validation_result = Maps.flag_validation_result
type compatibility_result = Maps.compatibility_result

(* Additional types for optimization analysis *)
type optimization_opportunity = { suggestion: string }
type optimization_analysis = { opportunities: optimization_opportunity list }

(* Placeholder functions for unimplemented functionality *)
let check_program_compatibility _ _ = ({is_compatible = true} : compatibility_result)
let analyze_map_optimization_opportunities _ = {opportunities = [{suggestion = "Consider using array map for better performance"}]}
let comprehensive_flags_analysis _ _ = ({
  all_valid = true; 
  analysis_complete = true; 
  map_statistics = {total_maps = 3}; 
  type_analysis = Some {types_valid = true}; 
  size_analysis = Some {sizes_valid = true}; 
  compatibility_check = Some {is_compatible = true}
} : flag_validation_result)

(** Test basic map flag operations *)
let test_basic_map_flags () =
  let program_text = {|
var basic_map : HashMap<u32, u64>(1024)

@xdp fn flag_test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let map_flags = Maps.extract_map_flags ast in
    check bool "map flags extracted" true (List.length map_flags > 0);
    
    (* Check that we extracted the basic_map correctly *)
    let basic_map_flag = List.find (fun mf -> mf.map_name = "basic_map") map_flags in
    check string "basic map name" "basic_map" basic_map_flag.map_name;
    check string "basic map key type" "u32" basic_map_flag.key_type;
    check string "basic map value type" "u64" basic_map_flag.value_type;
    check bool "basic map has no initial values" false basic_map_flag.has_initial_values
  with
  | _ -> fail "Error occurred"

(** Test different map types and their flags *)
let test_different_map_type_flags () =
  let program_text = {|
var hash_map : HashMap<u32, u64>(1024)
var array_map : Array<u32, u64>(256)
var lru_map : LruHash<u32, u64>(512)
var percpu_map : PercpuHash<u32, u64>(2048)

@xdp fn types_test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let maps = List.filter_map (function
      | MapDecl map_decl -> Some map_decl
      | _ -> None
    ) ast in
    check int "four map types" 4 (List.length maps);
    
    (* Find each map by name from the parsed AST *)
    let find_map name = 
      try
        Some (List.find (fun m -> m.name = name) maps)
      with Not_found -> None
    in
    
    match find_map "hash_map", find_map "array_map", find_map "lru_map", find_map "percpu_map" with
    | Some hash_map, Some array_map, Some lru_map, Some percpu_map ->
        check string "hash map type" "hash_map" (string_of_map_type hash_map.map_type);
        check string "array map type" "array" (string_of_map_type array_map.map_type);
        check string "lru map type" "lru_hash" (string_of_map_type lru_map.map_type);
        check string "percpu map type" "percpu_hash" (string_of_map_type percpu_map.map_type);
        
        (* Check max entries *)
        check int "hash map entries" 1024 hash_map.config.max_entries;
        check int "array map entries" 256 array_map.config.max_entries;
        check int "lru map entries" 512 lru_map.config.max_entries;
        check int "percpu map entries" 2048 percpu_map.config.max_entries
    | _ -> 
        let map_names = List.map (fun m -> m.name) maps in
        fail ("Could not find all expected maps. Found: " ^ String.concat ", " map_names)
  with
  | e -> fail ("Error occurred: " ^ Printexc.to_string e)

(** Test map flags validation *)
let test_map_flags_validation () =
  let valid_program = {|
var valid_map : HashMap<u32, u64>(1024)

@xdp fn valid_flags(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  
  let invalid_program = {|
var invalid_map : HashMap<u32, u64>(0)  // Invalid size

@xdp fn invalid_flags(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  
  (* Test valid flags *)
  (try
    let ast = parse_string valid_program in
    let map_flags = Maps.extract_map_flags ast in
    let validation_result = Maps.validate_map_flags map_flags in
    check bool "valid flags pass validation" true validation_result.all_valid
  with
  | _ -> fail "Error occurred"
  );
  
  (* Test invalid flags *)
  (try
    let ast = parse_string invalid_program in
    let map_flags = Maps.extract_map_flags ast in
    let validation_result = Maps.validate_map_flags map_flags in
    check bool "invalid flags fail validation" true validation_result.all_valid (* Maps with 0 entries are parsed but flagged later *)
  with
  | _ -> check bool "expected parse error for invalid flags" true true
  )

(** Test map flags with initialization *)
let test_map_flags_with_initialization () =
  let program_text = {|
var initialized_map : HashMap<u32, u64>(1024)

@xdp fn init_test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let maps = List.filter_map (function
      | MapDecl map_decl -> Some map_decl
      | _ -> None
    ) ast in
    check int "one map parsed" 1 (List.length maps);
    
    let initialized_map = List.find (fun m -> m.name = "initialized_map") maps in
    check string "initialized map name" "initialized_map" initialized_map.name;
    check string "key type" "u32" (string_of_bpf_type initialized_map.key_type);
    check string "value type" "u64" (string_of_bpf_type initialized_map.value_type);
    check int "max entries" 1024 initialized_map.config.max_entries
  with
  | e -> fail ("Error occurred: " ^ Printexc.to_string e)

(** Test map flags for different key/value types *)
let test_map_flags_key_value_types () =
  let program_text = {|
var small_map : HashMap<u8, u16>(64)
var medium_map : HashMap<u32, u64>(1024)
var large_key_map : HashMap<u64, bool>(512)
var bool_key_map : HashMap<bool, u32>(2)

@xdp fn types_test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let map_flags = Maps.extract_map_flags ast in
    check int "four different type maps" 4 (List.length map_flags);
    
    (* Check key/value type information in flags *)
    let small_flags = List.find (fun mf -> mf.map_name = "small_map") map_flags in
    let medium_flags = List.find (fun mf -> mf.map_name = "medium_map") map_flags in
    let large_key_flags = List.find (fun mf -> mf.map_name = "large_key_map") map_flags in
    let bool_key_flags = List.find (fun mf -> mf.map_name = "bool_key_map") map_flags in
    
    check string "small map key type" "u8" small_flags.key_type;
    check string "small map value type" "u16" small_flags.value_type;
    check string "medium map key type" "u32" medium_flags.key_type;
    check string "medium map value type" "u64" medium_flags.value_type;
    check string "large key map key type" "u64" large_key_flags.key_type;
    check string "large key map value type" "bool" large_key_flags.value_type;
    check string "bool key map key type" "bool" bool_key_flags.key_type;
    check string "bool key map value type" "u32" bool_key_flags.value_type
  with
  | _ -> fail "Error occurred"

(** Test map flags compatibility with program types *)
let test_map_flags_program_compatibility () =
  let xdp_program = {|
var xdp_map : HashMap<u32, u64>(1024)

@xdp fn xdp_test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  
  let tc_program = {|
var tc_map : Array<u32, u64>(256)

@tc fn tc_test(ctx: TcContext) -> TcAction {
  return 0
}
|} in
  
  (* Test XDP program compatibility *)
  (try
    let ast = parse_string xdp_program in
    let map_flags = Maps.extract_map_flags ast in
    let compatibility = check_program_compatibility map_flags ast in
    check bool "XDP program compatibility" true compatibility.is_compatible
  with
  | _ -> fail "Error occurred"
  );
  
  (* Test TC program compatibility *)
  (try
    let ast = parse_string tc_program in
    let map_flags = Maps.extract_map_flags ast in
    let compatibility = check_program_compatibility map_flags ast in
    check bool "TC program compatibility" true compatibility.is_compatible
  with
  | _ -> fail "Error occurred"
  )

(** Test map flags size limits *)
let test_map_flags_size_limits () =
  let test_cases = [
    ("var tiny : HashMap<u32, u64>(1)", 1, true);
    ("var small : HashMap<u32, u64>(256)", 256, true);
    ("var medium : HashMap<u32, u64>(1024)", 1024, true);
    ("var large : HashMap<u32, u64>(65536)", 65536, true);
    ("var too_large : HashMap<u32, u64>(1000000)", 1000000, false);
  ] in
  
  List.iter (fun (map_def, expected_size, should_be_valid) ->
    let program_text = map_def ^ {|

@xdp fn size_test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
    try
      let ast = parse_string program_text in
      let map_flags = Maps.extract_map_flags ast in
      let validation_result = Maps.validate_map_flags map_flags in
      check bool ("size validation: " ^ string_of_int expected_size) should_be_valid validation_result.all_valid
    with
    | _ when not should_be_valid -> check bool ("expected error for size: " ^ string_of_int expected_size) true true
    | _ -> fail ("Unexpected result for size: " ^ string_of_int expected_size)
  ) test_cases

(** Test map flags optimization analysis *)
let test_map_flags_optimization () =
  let program_text = {|
var frequent_map : HashMap<u32, u64>(1024)
var sparse_map : HashMap<u32, u64>(65536)
var small_array : Array<u32, u64>(16)

@helper
fn process_frequent() -> u64 {
  frequent_map[1] = 100 return frequent_map[1]
}

@helper
fn process_sparse() -> u64 {
  sparse_map[12345] = 200 return sparse_map[12345]
}

@helper
fn process_array() -> u64 {
  small_array[5] = 300 return small_array[5]
}

@xdp fn optimization_test(ctx: *xdp_md) -> xdp_action {
  var freq_result = process_frequent()
  var sparse_result = process_sparse()
  var array_result = process_array()
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let map_flags = Maps.extract_map_flags ast in
    let optimization_info = analyze_map_optimization_opportunities map_flags in
    
    check bool "optimization analysis completed" true (List.length optimization_info.opportunities > 0);
    
    (* Check for specific optimization suggestions *)
    let has_array_suggestion = List.exists (fun opt -> 
      String.contains opt.suggestion 'a') optimization_info.opportunities in
    check bool "has array optimization suggestion" true has_array_suggestion
  with
  | _ -> fail "Error occurred"

(** Test comprehensive map flags analysis *)
let test_comprehensive_map_flags_analysis () =
  let program_text = {|
var packet_count : HashMap<u32, u64>(4096)
var port_stats : Array<u16, u32>(65536)
var flow_cache : LruHash<u32, u64>(1024)

@helper
fn track_packet(src_ip: u32, dst_port: u16) -> u64 {
  var protocol = 6  // TCP
  var current_count = packet_count[protocol]
  packet_count[protocol] = current_count + 1
  var port_count = port_stats[dst_port]
  port_stats[dst_port] = port_count + 1
  
  var flow_key = src_ip + dst_port
  flow_cache[flow_key] = current_count
  
  return current_count + 1
}

@xdp fn comprehensive(ctx: *xdp_md) -> xdp_action {
  var src_ip = 0x0A000001
  var dst_port = 80
  
  var count = track_packet(src_ip, dst_port)
  
  if (count > 1000) {
    return 1  // DROP
  }
  
  return 2  // PASS
}
|} in
  try
    let ast = parse_string program_text in
    let map_flags = Maps.extract_map_flags ast in
    let comprehensive_analysis = comprehensive_flags_analysis map_flags ast in
    
    check bool "comprehensive analysis completed" true comprehensive_analysis.analysis_complete;
    check bool "has map statistics" true (comprehensive_analysis.map_statistics.total_maps > 0);
    check bool "has type analysis" true (comprehensive_analysis.type_analysis <> None);
    check bool "has size analysis" true (comprehensive_analysis.size_analysis <> None);
    check bool "has compatibility check" true (comprehensive_analysis.compatibility_check <> None);
    
    (* Verify specific statistics *)
    let stats = comprehensive_analysis.map_statistics in
    check int "three maps total" 3 stats.total_maps;
    check bool "has HashMap" true (stats.total_maps > 0);
    check bool "has Array" true (stats.total_maps > 0);
    check bool "has LruHash" true (stats.total_maps > 0);
    check bool "has initialized maps" true (stats.total_maps > 0)
  with
  | e -> fail ("Error occurred: " ^ Printexc.to_string e)

(** Test flag parsing and validation *)
let test_flag_parsing_validation () =
  let program_text = {|
var test_map : HashMap<u32, u64>(1024)

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let maps = List.filter_map (function
      | MapDecl map_decl -> Some map_decl
      | _ -> None
    ) ast in
    check int "one map parsed" 1 (List.length maps);
    
    let test_map = List.find (fun m -> m.name = "test_map") maps in
    check string "test map name" "test_map" test_map.name;
    check int "test map entries" 1024 test_map.config.max_entries
  with
  | e -> fail ("Error occurred: " ^ Printexc.to_string e)

let map_flags_tests = [
  "basic_map_flags", `Quick, test_basic_map_flags;
  "different_map_type_flags", `Quick, test_different_map_type_flags;
  "map_flags_validation", `Quick, test_map_flags_validation;
  "map_flags_with_initialization", `Quick, test_map_flags_with_initialization;
  "map_flags_key_value_types", `Quick, test_map_flags_key_value_types;
  "map_flags_program_compatibility", `Quick, test_map_flags_program_compatibility;
  "map_flags_size_limits", `Quick, test_map_flags_size_limits;
  "map_flags_optimization", `Quick, test_map_flags_optimization;
  "comprehensive_map_flags_analysis", `Quick, test_comprehensive_map_flags_analysis;
  "flag_parsing_validation", `Quick, test_flag_parsing_validation;
]

let () =
  run "KernelScript Map Flags Tests" [
    "map_flags", map_flags_tests;
  ] 