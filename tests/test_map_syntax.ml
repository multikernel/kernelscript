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

(** Test suite for Map Syntax and Operations *)

let _test_position = make_position 1 1 "test.ks"

(** Helper function to parse string with builtin types loaded via symbol table *)
let parse_string_with_builtins code =
  let ast = parse_string code in
  (* Create symbol table with test builtin types *)
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  (* Run type checking with builtin types loaded *)
  let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  (typed_ast, symbol_table)

(** Helper function to check if string contains substring *)
let contains_substr str substr =
  try 
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in 
    true
  with Not_found -> false



(** Test map declaration parsing *)
let test_map_declaration_parsing () =
  let test_cases = [
    (* Basic HashMap *)
    ("map<u32, u64> test_map : HashMap(1024)", true);
    (* Array map *)
    ("map<u32, u32> array_map : Array(512)", true);
    (* PercpuHash *)
    ("map<u64, u64> percpu_map : PercpuHash(256)", true);
    (* Invalid syntax - wrong order *)
    ("map bad_map : HashMap<u32, u64>(1024)", false);
    (* Invalid syntax - missing max_entries *)
    ("map<u32, u64> default_map : HashMap()", false);
    (* Old syntax with blocks - should fail *)
    ("map<u32, u64> old_map : HashMap(1024) { }", false);
  ] in
  
  List.iter (fun (code, should_succeed) ->
    try
      let program = Printf.sprintf "%s\n@xdp fn test() -> u32 { return 0 }" code in
      let _ = parse_string program in
      check bool ("parsing: " ^ code) should_succeed true
    with
    | _ -> 
      check bool ("parsing: " ^ code) should_succeed false
  ) test_cases

(** Test new block-less map declaration syntax *)
let test_blockless_map_declaration () =
  let test_cases = [
    (* Basic block-less HashMap *)
    ("map<u32, u64> simple_map : HashMap(1024)", true);
    (* Block-less Array *)
    ("map<u32, u32> array_map : Array(512)", true);
    (* Block-less PercpuHash *)
    ("map<u64, u64> percpu_map : PercpuHash(256)", true);
    (* Block-less LruHash *)
    ("map<u32, u64> lru_map : LruHash(128)", true);
    (* Pinned map *)
    ("pin map<u32, u64> pinned_map : HashMap(1024)", true);
    (* Map with flags *)
    ("@flags(no_prealloc) map<u32, u64> flags_map : HashMap(1024)", true);
    (* Combined pin and flags *)
    ("@flags(rdonly) pin map<u32, u64> combined_map : HashMap(1024)", true);
    (* Invalid - old syntax with blocks *)
    ("map<u32, u64> invalid_map : HashMap(1024) { }", false);
  ] in
  
  List.iter (fun (code, should_succeed) ->
    try
      let program = Printf.sprintf "%s\n@xdp fn test() -> u32 { return 0 }" code in
      let _ = parse_string program in
      check bool ("blockless parsing: " ^ code) should_succeed true
    with
    | _ ->
      check bool ("blockless parsing: " ^ code) should_succeed false
  ) test_cases

(** Test map declarations with new attributes *)
let test_map_attributes_syntax () =
  let test_cases = [
    (* Pinned map *)
    ("pin map<u32, u64> pinned_map : HashMap(1024)", true);
    (* Map with flags *)
    ("@flags(no_prealloc) map<u32, u64> flags_map : HashMap(1024)", true);
    (* Combined attributes *)
    ("@flags(rdonly) pin map<u32, u64> combined_map : HashMap(1024)", true);
    (* Multiple flags *)
    ("@flags(no_prealloc | rdonly) map<u32, u64> multi_flags_map : HashMap(1024)", true);
    (* Regular map without attributes *)
    ("map<u32, u64> regular_map : HashMap(1024)", true);
    (* Invalid - old syntax with blocks *)
    ("map<u32, u64> invalid_map : HashMap(1024) { pinned: \"/path\" }", false);
    (* Invalid - old syntax with empty blocks *)
    ("map<u32, u64> invalid_map : HashMap(1024) { }", false);
  ] in
  
  List.iter (fun (code, should_succeed) ->
    try
      let program = Printf.sprintf "%s\n@xdp fn test() -> u32 { return 0 }" code in
      let _ = parse_string program in
      check bool ("attributes parsing: " ^ code) should_succeed true
    with
    | _ ->
      check bool ("attributes parsing: " ^ code) should_succeed false
  ) test_cases

(** Test comprehensive map syntax variations *)
let test_comprehensive_map_syntax () =
  let program = {|
// Block-less maps
map<u32, u64> simple_counter : HashMap(512)
map<u32, u32> lookup_array : Array(256)
map<u64, u64> percpu_stats : PercpuHash(128)

// Pinned maps
pin map<u32, u64> pinned_global : HashMap(2048)
pin map<u32, u64> pinned_local : HashMap(512)

// Maps with flags
@flags(no_prealloc) map<u32, u64> efficient_map : HashMap(1024)
@flags(rdonly) map<u32, u64> readonly_map : HashMap(256)

// Combined attributes
@flags(no_prealloc | rdonly) pin map<u32, u64> combined_map : HashMap(1024)

@xdp fn test_syntax(ctx: *xdp_md) -> xdp_action {
  // Test all map types can be used
  simple_counter[42] = 100
  lookup_array[10] = 200
  percpu_stats[123] = 300
  pinned_global[1] = 400
  pinned_local[2] = 500
  efficient_map[3] = 600
  readonly_map[4] = 700
  combined_map[5] = 800
  
  return XDP_PASS
}
|} in
  try
    let _ = parse_string_with_builtins program in
    check bool "comprehensive syntax parsing" true true
  with
  | exn ->
    Printf.printf "Comprehensive syntax parsing failed with: %s\n" (Printexc.to_string exn);
    check bool "comprehensive syntax parsing" true false

(** Test map syntax type checking *)
let test_new_syntax_type_checking () =
  let program = {|
map<u32, u64> blockless_map : HashMap(512)
pin map<u32, u64> pinned_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  // Test type checking works with new syntax
  var key: u32 = 42
  var value1: u64 = blockless_map[key]
  var value2: u64 = pinned_map[key]
  
  blockless_map[key] = value1 + 1
  pinned_map[key] = value2 + 1
  
  return XDP_PASS
}
|} in
  try
    let (_ast, _) = parse_string_with_builtins program in
    check bool "new syntax type checking" true true
  with
  | exn ->
    Printf.printf "New syntax type checking failed with: %s\n" (Printexc.to_string exn);
    check bool "new syntax type checking" true false

(** Test IR generation with new syntax *)
let test_new_syntax_ir_generation () =
  let program = {|
map<u32, u64> simple_map : HashMap(512)
pin map<u32, u64> pinned_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  simple_map[42] = 100
  pinned_map[42] = 200
  
  var val1 = simple_map[42]
  var val2 = pinned_map[42]
  
  return XDP_PASS
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let (typed_ast, symbol_table) = parse_string_with_builtins program in
    
    (* Test that IR generation completes without errors *)
    let _ir = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
    check bool "test passed" true true
  with
  | exn ->
    Printf.printf "IR generation failed with: %s\n" (Printexc.to_string exn);
    check bool "IR generation test failed" true false

(** Test C code generation with new syntax *)
let test_new_syntax_c_generation () =
  let program = {|
map<u32, u64> blockless_counter : HashMap(512)
pin map<u32, u64> pinned_stats : HashMap(1024)

@xdp fn counter(ctx: *xdp_md) -> xdp_action {
  var key = 42
  blockless_counter[key] = blockless_counter[key] + 1
  pinned_stats[key] = pinned_stats[key] + 1
  return XDP_PASS
}
|} in
  try
    let (typed_ast, symbol_table) = parse_string_with_builtins program in
    let ir = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir in
    
    (* Verify both maps are generated *)
    let has_blockless = contains_substr c_code "blockless_counter" in
    let has_pinned = contains_substr c_code "pinned_stats" in
    let has_map_ops = contains_substr c_code "bpf_map_lookup_elem" &&
                     contains_substr c_code "bpf_map_update_elem" in
    
    let _ = has_blockless && has_pinned && has_map_ops in
    check bool "C code generation test" true (has_blockless && has_pinned && has_map_ops)
  with
  | exn ->
    Printf.printf "C generation failed with: %s\n" (Printexc.to_string exn);
    check bool "C code generation test" true false

(** Test error cases for new syntax *)
let test_new_syntax_error_cases () =
  let invalid_cases = [
    (* Old syntax with blocks - should fail *)
    "map<u32, u64> invalid : HashMap(512) { }";
    (* Old syntax with attributes - should fail *)
    "map<u32, u64> invalid : HashMap(512) { pinned: \"/path\" }";
    (* Wrong type order *)
    "map bad_map : HashMap<u32, u64>(1024)";
    (* Missing colon *)
    "map<u32, u64> bad_map HashMap(1024)";
    (* Invalid flags *)
    "@flags(invalid_flag) map<u32, u64> invalid : HashMap(512)";
  ] in
  
  let all_failed_as_expected = List.for_all (fun invalid_code ->
    try
      let program = Printf.sprintf "%s\n@xdp fn test() -> u32 { return 0 }" invalid_code in
      let _ = parse_string program in
      false  (* Should have failed *)
    with
    | _ -> true  (* Expected to fail *)
  ) invalid_cases in
  check bool "all invalid cases failed as expected" true all_failed_as_expected

(** Test map operations parsing *)
let test_map_operations_parsing () =
  let test_cases = [
    ("map[key] = value", true);
    ("var result = map[key]", true);
    ("delete map[key]", true);
    ("var inner_key = inner_map[key]\nvar result = outer_map[inner_key]", true);
  ] in
  
  List.iter (fun (input, should_pass) ->
    try
      let _ = parse_string input in
      if not should_pass then
        Printf.printf "ERROR: Expected %s to fail\n" input
    with 
    | _ when should_pass -> 
        Printf.printf "ERROR: Expected %s to pass\n" input
    | _ -> () (* Expected failure *)
  ) test_cases

(** Test complete map program parsing *)
let test_complete_map_program_parsing () =
  let program = {|
map<u32, u64> packet_counts : HashMap(1024)

@xdp fn rate_limiter(ctx: *xdp_md) -> xdp_action {
  var src_ip = 0x08080808
  var current_count = packet_counts[src_ip]
  var new_count = current_count + 1
  packet_counts[src_ip] = new_count
  
  if (new_count > 100) {
    return XDP_DROP
  }
  
  return XDP_PASS
}
|} in
  try
    let _ = parse_string_with_builtins program in
    check bool "test passed" true true
  with
  | exn ->
    Printf.printf "Complete map program parsing failed with: %s\n" (Printexc.to_string exn);
    check bool "test passed" true false

(** Test map type checking *)
let test_map_type_checking () =
  let program = {|
map<u32, u64> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var key = 42
  var value = test_map[key]
  test_map[key] = value + 1
  return XDP_PASS
}
|} in
  try
    let (_ast, _) = parse_string_with_builtins program in
    check bool "test passed" true true
  with
  | exn ->
    Printf.printf "Type checking failed with: %s\n" (Printexc.to_string exn);
    check bool "test passed" true false

(** Test map type validation *)
let test_map_type_validation () =
  let test_cases = [
    (* Valid: u32 key with u32 access *)
    ({|
map<u32, u64> valid_map : HashMap(1024)
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var key: u32 = 42
  var value = valid_map[key]
  return XDP_PASS
}
|}, true);
    
    (* Invalid: string key with u32 map *)
    ({|
map<u32, u64> invalid_map : HashMap(1024)
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var key = "invalid"
  var value = invalid_map[key]
  return XDP_PASS
}
|}, false)
  ] in
  
  let all_validation_passed = List.for_all (fun (code, should_succeed) ->
    try
      let (_ast, _) = parse_string_with_builtins code in
      should_succeed
    with
    | _ -> not should_succeed
  ) test_cases in
  check bool "all map type validation cases passed" true all_validation_passed

(** Test map identifier resolution *)
let test_map_identifier_resolution () =
  let program = {|
map<u32, u64> global_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var value = global_map[42]
  return XDP_PASS
}
|} in
  try
    let (_typed_ast, _) = parse_string_with_builtins program in
    (* If we get here, the map identifier was resolved successfully *)
    check bool "map identifier resolution" true true
  with
  | _ ->
    check bool "map identifier resolution" true false

(** Test IR generation for maps *)
let test_map_ir_generation () =
  let program = {|
map<u32, u64> test_map : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var key = 42
  var value = test_map[key]
  test_map[key] = value + 1
  return XDP_PASS
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let (typed_ast, symbol_table) = parse_string_with_builtins program in
    
    (* Test that IR generation completes without errors *)
    let _ir = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
    check bool "test passed" true true
  with
  | exn ->
    Printf.printf "Map IR generation failed with: %s\n" (Printexc.to_string exn);
    check bool "IR generation test failed" true false

(** Test C code generation for maps *)
let test_map_c_generation () =
  let program = {|
map<u32, u64> packet_counter : HashMap(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var src_ip = 0x12345678
  var count = packet_counter[src_ip]
  packet_counter[src_ip] = count + 1
  return XDP_PASS
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let (typed_ast, symbol_table) = parse_string_with_builtins program in
    
    (* Test that C code generation completes and produces expected output *)
    let ir = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir in
    
    let contains_map_decl = contains_substr c_code "BPF_MAP_TYPE_HASH" &&
                           contains_substr c_code "packet_counter" in
    let contains_lookup = contains_substr c_code "bpf_map_lookup_elem" in
    let contains_update = contains_substr c_code "bpf_map_update_elem" in
    
    check bool "C code generation test" true (contains_map_decl && contains_lookup && contains_update)
  with
  | exn ->
    Printf.printf "Map C generation failed with: %s\n" (Printexc.to_string exn);
    check bool "C code generation test" true false

(** Test different map types *)
let test_different_map_types () =
  let map_types = [
    ("HashMap", "BPF_MAP_TYPE_HASH");
    ("Array", "BPF_MAP_TYPE_ARRAY");
    ("PercpuHash", "BPF_MAP_TYPE_PERCPU_HASH");
    ("PercpuArray", "BPF_MAP_TYPE_PERCPU_ARRAY");
    ("LruHash", "BPF_MAP_TYPE_LRU_HASH");
  ] in
  
  let all_map_types_work = List.for_all (fun (ks_type, c_type) ->
    let program = Printf.sprintf {|
map<u32, u64> test_map : %s(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var key = 42
  var value = test_map[key]
  return XDP_PASS
}
|} ks_type in
    try
      (* Follow the complete compiler pipeline *)
      let (typed_ast, symbol_table) = parse_string_with_builtins program in
      
      (* Test compilation and C code generation *)
      let ir = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
      let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir in
      contains_substr c_code c_type
    with
    | _ -> false
  ) map_types in
  check bool "all different map types work correctly" true all_map_types_work

let map_syntax_tests = [
  "map_declaration_parsing", `Quick, test_map_declaration_parsing;
  "blockless_map_declaration", `Quick, test_blockless_map_declaration;
  "map_attributes_syntax", `Quick, test_map_attributes_syntax;
  "comprehensive_map_syntax", `Quick, test_comprehensive_map_syntax;
  "new_syntax_type_checking", `Quick, test_new_syntax_type_checking;
  "new_syntax_ir_generation", `Quick, test_new_syntax_ir_generation;
  "new_syntax_c_generation", `Quick, test_new_syntax_c_generation;
  "new_syntax_error_cases", `Quick, test_new_syntax_error_cases;
  "map_operations_parsing", `Quick, test_map_operations_parsing;
  "complete_map_program_parsing", `Quick, test_complete_map_program_parsing;
  "map_type_checking", `Quick, test_map_type_checking;
  "map_type_validation", `Quick, test_map_type_validation;
  "map_identifier_resolution", `Quick, test_map_identifier_resolution;
  "map_ir_generation", `Quick, test_map_ir_generation;
  "map_c_generation", `Quick, test_map_c_generation;
  "different_map_types", `Quick, test_different_map_types;
]

let () =
  run "KernelScript Map Syntax Tests" [
    "map_syntax", map_syntax_tests;
  ] 