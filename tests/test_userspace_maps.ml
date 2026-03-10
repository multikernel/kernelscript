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

(** 
   Comprehensive unit tests for global function map-related functionality in KernelScript.
   
   This test suite covers:
   
   === Map Scope Tests ===
   - Global maps accessible from global functions
   - Local maps isolated to BPF programs
   - Map visibility and access control
   
   === Map Code Generation Tests ===
   - Map file descriptor generation
   - Map operation function generation (lookup, update, delete, get_next_key)
   - Map setup and cleanup code generation
   - Pinned map handling in global functions
   
   === Map Integration Tests ===
   - Multiple map types in global functions
   - Maps with flags in global function code
   - Complex map configurations
   - Map access patterns and error handling
   
   === Map Communication Tests ===
   - Global function-kernel map sharing
   - BPF object integration
   - Map-based event processing
*)

open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Userspace_codegen
open Alcotest

(** Helper function to parse string with builtin constants loaded *)
let parse_string_with_builtins code =
  let ast = parse_string code in
  (* Create symbol table with test builtin types *)
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  (* Run type checking with builtin types *)
  let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  typed_ast

(** Helper function for position printing *)
let _string_of_position pos =
  Printf.sprintf "line %d, column %d" pos.line pos.column

(** Helper function to check if a pattern exists in content (case-insensitive) *)
let contains_pattern content pattern =
  let content_lower = String.lowercase_ascii content in
  try 
    ignore (Str.search_forward (Str.regexp pattern) content_lower 0); 
    true
  with Not_found -> false

(** Helper function to extract maps from AST *)
let extract_maps_from_ast ast =
  List.filter_map (function
    | MapDecl map_decl -> Some map_decl
    | GlobalVarDecl global_var_decl -> 
        (* Convert global variables with map types to map declarations *)
        (match global_var_decl.global_var_type with
         | Some (Map (key_type, value_type, map_type, size)) ->
             let config = { max_entries = size; key_size = None; value_size = None; flags = [] } in
             Some { name = global_var_decl.global_var_name; key_type; value_type; map_type; config; 
                    is_global = true; is_pinned = global_var_decl.is_pinned; map_pos = global_var_decl.global_var_pos }
         | _ -> None)
    | _ -> None
  ) ast

(** Helper function to extract global functions from AST *)
let extract_global_functions_from_ast ast =
  List.fold_left (fun acc decl ->
    match decl with
    | GlobalFunction func -> func :: acc
    | _ -> acc
  ) [] ast

(** Helper function to generate userspace code and return content *)
let get_generated_userspace_code ast source_filename =
  let temp_dir = Filename.temp_file "test_userspace_maps" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  try
    (* Convert AST to IR properly for the new IR-based codegen *)
    (* Load builtin ASTs for symbol table *)
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let ir_multi_prog = Kernelscript.Ir_generator.generate_ir ast symbol_table source_filename in
    let _output_file = generate_userspace_code_from_ir ir_multi_prog ~output_dir:temp_dir source_filename in
    let generated_file = Filename.concat temp_dir (Filename.remove_extension source_filename ^ ".c") in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      Some content
    ) else (
      Unix.rmdir temp_dir;
      None
    )
  with
  | exn ->
    (* Cleanup on error *)
    (try Unix.rmdir temp_dir with _ -> ());
    raise exn

(** Test 1: Global maps are accessible from global functions *)
let test_global_map_accessibility () =
  let code = {|
var global_counter : hash<u32, u64>(1024)
var global_config : array<u32, u32>(256)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  global_counter[1] = 100  // This will trigger map operations generation
  var value = global_config[0]
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    let global_functions = extract_global_functions_from_ast ast in
    
    (* Verify we parsed the expected structure *)
    check int "two global maps parsed" 2 (List.length maps);
    check bool "global functions present" true (List.length global_functions > 0);
    
    (* Verify map types and names *)
    let global_counter = List.find (fun m -> m.name = "global_counter") maps in
    let global_config = List.find (fun m -> m.name = "global_config") maps in
    
    check string "global_counter key type" "u32" (Kernelscript.Ast.string_of_bpf_type global_counter.key_type);
    check string "global_counter value type" "u64" (Kernelscript.Ast.string_of_bpf_type global_counter.value_type);
    check string "global_config key type" "u32" (Kernelscript.Ast.string_of_bpf_type global_config.key_type);
    check string "global_config value type" "u32" (Kernelscript.Ast.string_of_bpf_type global_config.value_type);
    
    (* Generate userspace code and check for global map accessibility *)
    match get_generated_userspace_code ast "test_global_maps.ks" with
    | Some generated_content ->
        (* Check for global map file descriptors *)
        let has_global_counter_fd = contains_pattern generated_content "global_counter.*fd" in
        let has_global_config_fd = contains_pattern generated_content "global_config.*fd" in
        
        (* Check for map operation functions *)
        let has_counter_operations = contains_pattern generated_content "bpf_map.*elem.*global_counter_fd\\|global_counter_fd.*bpf_map" in
        let has_config_operations = contains_pattern generated_content "bpf_map.*elem.*global_config_fd\\|global_config_fd.*bpf_map" in
        
        check bool "global counter fd variable" true has_global_counter_fd;
        check bool "global config fd variable" true has_global_config_fd;
        check bool "counter operations present" true has_counter_operations;
        check bool "config operations present" true has_config_operations
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 2: Only global maps are accessible from global functions *)
let test_global_only_map_access () =
  let code = {|
var global_shared : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  global_shared[42] = 200  // Use the global map to trigger generation
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    
    (* Should only have global map, not local ones *)
    check int "only global maps accessible" 1 (List.length maps);
    
    let global_shared = List.find (fun m -> m.name = "global_shared") maps in
    check string "global_shared is present" "global_shared" global_shared.name;
    
    (* Generate userspace code and verify only global maps are accessible *)
    match get_generated_userspace_code ast "test_global_only.ks" with
    | Some generated_content ->
        let has_global_shared = contains_pattern generated_content "global_shared" in
        
        check bool "global map present in userspace" true has_global_shared
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 3: Map operation function generation *)
let test_map_operation_generation () =
  let code = {|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  test_map[123] = 456  // Use the map to trigger operations generation
  var lookup_result = test_map[123]
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    
    check int "one test map" 1 (List.length maps);
    let test_map = List.hd maps in
    check string "test map name" "test_map" test_map.name;
    check string "test map type" "hash" (string_of_map_type test_map.map_type);
    
    (* Generate userspace code and check for map operations *)
    match get_generated_userspace_code ast "test_operations.ks" with
    | Some generated_content ->
        (* Check for map operations that are actually used in the test code *)
        let operations = [
          ("lookup", "bpf_map_lookup_elem.*test_map_fd");
          ("update", "bpf_map_update_elem.*test_map_fd");
        ] in
        
        List.iter (fun (op_name, pattern) ->
          let has_operation = contains_pattern generated_content pattern in
          check bool ("map " ^ op_name ^ " operation") true has_operation
        ) operations;
        
        (* Check for BPF map helper functions *)
        let has_bpf_helpers = contains_pattern generated_content "bpf_map_lookup_elem\\|bpf_map_update_elem\\|bpf_map_delete_elem" in
        check bool "BPF map helper functions present" true has_bpf_helpers
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 4: Multiple map types in global functions *)
let test_multiple_map_types_global_functions () =
  let code = {|
var hash_map : hash<u32, u64>(1024)
var array_map : array<u32, u32>(256)
var lru_map : lru_hash<u32, u64>(512)
var percpu_map : percpu_hash<u64, u32>(128)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  // Use all maps to trigger operations generation
  hash_map[1] = 100
  array_map[2] = 200
  lru_map[3] = 300
  percpu_map[4] = 400
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    
    check int "four different map types" 4 (List.length maps);
    
    (* Verify each map type was parsed correctly *)
    let map_types = [
      ("hash_map", "hash", "u32", "u64", 1024);
      ("array_map", "array", "u32", "u32", 256);
      ("lru_map", "lru_hash", "u32", "u64", 512);
      ("percpu_map", "percpu_hash", "u64", "u32", 128);
    ] in
    
    List.iter (fun (name, expected_type, key_type, value_type, max_entries) ->
      let map = List.find (fun m -> m.name = name) maps in
      check string (name ^ " type") expected_type (string_of_map_type map.map_type);
      check string (name ^ " key type") key_type (string_of_bpf_type map.key_type);
      check string (name ^ " value type") value_type (string_of_bpf_type map.value_type);
      check int (name ^ " max entries") max_entries map.config.max_entries
    ) map_types;
    
    (* Generate userspace code and verify all maps are handled *)
    match get_generated_userspace_code ast "test_multiple_types.ks" with
    | Some generated_content ->
        List.iter (fun (map_name, _, _, _, _) ->
          let has_fd = contains_pattern generated_content (map_name ^ ".*fd") in
          let has_operations = contains_pattern generated_content ("bpf_map.*elem.*" ^ map_name ^ "_fd") in
          
          check bool ("map " ^ map_name ^ " fd variable") true has_fd;
          check bool ("map " ^ map_name ^ " operations") true has_operations
        ) map_types
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 5: Global function code structure and includes *)
let test_global_function_code_structure () =
  let code = {|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  test_map[1] = 42  // Use the map to trigger operations generation
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    
    (* Generate userspace code and check structure *)
    match get_generated_userspace_code ast "test_structure.ks" with
    | Some generated_content ->
        (* Check for required includes *)
        let has_stdio = contains_pattern generated_content "#include.*stdio" in
        let has_bpf_includes = contains_pattern generated_content "#include.*bpf" in
        
        (* Check for main function with correct signature *)
        let has_main_function = contains_pattern generated_content "int main" in
        
        (* Check for BPF skeleton usage (auto-generated when maps are used) *)
        let has_bpf_object = contains_pattern generated_content "\\.skel\\.h\\|bpf_object\\|struct bpf_object" in
        
        (* Check for signal handling functions (not just headers) *)
        let has_signal_handling = contains_pattern generated_content "setup_signal\\|signal(" in
        
        check bool "has stdio include" true has_stdio;
        check bool "has BPF includes" true has_bpf_includes;
        check bool "has main function" true has_main_function;
        check bool "has BPF object management (auto-generated when maps used)" true has_bpf_object;  (* Auto-generated BPF initialization for map operations *)
        check bool "has signal handling" false has_signal_handling;  (* No signal handling needed *)
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 6: Error handling for invalid global function programs *)
let test_global_function_error_handling () =
  let invalid_programs = [
    (* Missing main function *)
    ({|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn helper() -> i32 {
  return 0
}
|}, "missing main function");
    
    (* Invalid main signature *)
    ({|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main(wrong_param: u32) -> i32 {
  return 0
}
|}, "invalid main signature");
  ] in
  
  List.iter (fun (program, description) ->
    try
      let ast = parse_string program in
      (* Trigger validation by generating IR first, which validates global function main *)
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
      (* If we get here, validation passed but it shouldn't have *)
      fail ("Should have failed for: " ^ description)
    with
    | Parse_error _ ->
        ()
    | Failure msg when String.length msg > 0 ->
        (* Check that the error message is related to main function validation *)
        let is_main_function_error = 
          contains_pattern msg "main" || 
          contains_pattern msg "argc" || 
          contains_pattern msg "argv" in
        check bool ("correctly rejected with main function error: " ^ description) true is_main_function_error
    | _ ->
        check bool ("should have failed for: " ^ description) false true
  ) invalid_programs

(** Test 7: Map file descriptor generation for userspace *)
let test_map_fd_generation () =
  let code = {|
pin var shared_counter : hash<u32, u32>(1024)

@xdp fn packet_counter(ctx: *xdp_md) -> xdp_action {
  shared_counter[1] = 100
  return XDP_PASS
}

@tc("ingress") fn packet_filter(ctx: *__sk_buff) -> i32 {
  shared_counter[2] = 200
  return 0 // TC_ACT_OK
}

fn main() -> i32 {
  shared_counter[1] = 0
  shared_counter[2] = 0
  return 0
} 
|} in
  
  try
    let ast = parse_string_with_builtins code in
    let maps = extract_maps_from_ast ast in
    
    check int "one shared counter map" 1 (List.length maps);
    let shared_counter = List.hd maps in
    check string "shared_counter name" "shared_counter" shared_counter.name;
    
    (* Generate userspace code and verify map fd usage *)
    match get_generated_userspace_code ast "test_map_fd.ks" with
    | Some generated_content ->
        (* Check for file descriptor declaration - pinned maps use pinned_globals_map_fd *)
        let has_fd_declaration = contains_pattern generated_content "int.*_fd = -1\\|pinned_globals_map_fd" in
        check bool "map file descriptor declaration" true has_fd_declaration;
        
        (* Check that map operations use the file descriptor, not raw map name *)
        let has_fd_in_update = contains_pattern generated_content "bpf_map_update_elem.*_fd\\|pinned_globals_map_fd.*bpf_map" in
        check bool "bpf_map_update_elem uses file descriptor" true has_fd_in_update;
        
        (* Ensure raw map reference is NOT used in map operations *)
        let has_raw_map_ref = contains_pattern generated_content "bpf_map_update_elem.*&shared_counter[^_]" in
        check bool "bpf_map_update_elem does NOT use &shared_counter" false has_raw_map_ref;
        
        (* Check for map operation helper functions or direct bpf_map usage *)
        let has_helper_functions = contains_pattern generated_content "shared_counter_lookup\\|shared_counter_update\\|bpf_map.*elem" in
        check bool "map operations present" true has_helper_functions;
        
        (* Verify operations use file descriptors correctly *)
        let helper_uses_fd = contains_pattern generated_content "bpf_map.*elem.*_fd\\|pinned_globals_map_fd" in
        check bool "map operations use file descriptors" true helper_uses_fd
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 8: No map FD declarations when outer condition is false (no map ops, no exec, no pinned maps) *)
let test_map_fd_not_generated_without_usage () =
  (* Map used only in eBPF program (not in main), no pinned maps, no exec *)
  let code = {|
var ebpf_side_only : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  ebpf_side_only[1] = 100
  return XDP_PASS
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_no_fd.ks" with
    | Some generated_content ->
        (* uses_map_operations=false, uses_exec=false, has_pinned_maps=false
           → map_fd_declarations = "" → no "int ebpf_side_only_fd = -1" *)
        let has_fd_decl = contains_pattern generated_content "int ebpf_side_only_fd" in
        check bool "no fd declaration when no userspace map usage" false has_fd_decl
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 9: Only userspace-used maps get FD declarations when no pinned maps *)
let test_map_fd_only_for_userspace_used_maps () =
  (* used_map is referenced in main; ebpf_only_map is referenced only in @xdp fn *)
  let code = {|
var used_map : hash<u32, u64>(1024)
var ebpf_only_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  ebpf_only_map[1] = 100
  return XDP_PASS
}

fn main() -> i32 {
  used_map[1] = 42
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_used_maps_fd.ks" with
    | Some generated_content ->
        (* uses_map_operations=true, has_pinned_maps=false
           → maps_for_fd = used_global_maps_with_exec = [used_map] (not ebpf_only_map) *)
        let has_used_map_fd = contains_pattern generated_content "int used_map_fd" in
        let has_ebpf_only_fd = contains_pattern generated_content "int ebpf_only_map_fd" in
        check bool "used map gets fd declaration" true has_used_map_fd;
        check bool "ebpf-only map does NOT get fd declaration" false has_ebpf_only_fd
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 10: Pinned maps cause all global maps (including eBPF-only ones) to get FD declarations *)
let test_map_fd_pinned_includes_all_global_maps () =
  (* pinned_map is pinned and used in main; other_map is non-pinned and used only in @xdp fn *)
  let code = {|
pin var pinned_map : hash<u32, u64>(1024)
var other_map : hash<u32, u64>(512)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  other_map[1] = 100
  return XDP_PASS
}

fn main() -> i32 {
  pinned_map[1] = 10
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_pinned_fd.ks" with
    | Some generated_content ->
        (* has_pinned_maps=true → outer condition true, maps_for_fd = global_maps
           → BOTH pinned_map and other_map get int ..._fd = -1 declarations *)
        let has_pinned_map_fd = contains_pattern generated_content "int pinned_map_fd" in
        let has_other_map_fd = contains_pattern generated_content "int other_map_fd" in
        check bool "pinned map gets fd declaration" true has_pinned_map_fd;
        check bool "non-pinned ebpf-only map ALSO gets fd declaration (global_maps used)" true has_other_map_fd
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 11: Map setup code not generated when no userspace map usage, no exec, no pinned maps *)
let test_map_setup_not_generated_without_usage () =
  (* Map used only in eBPF program, no map access in main, no pinned maps, no exec *)
  let code = {|
var ebpf_only : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  ebpf_only[1] = 100
  return XDP_PASS
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_no_setup.ks" with
    | Some generated_content ->
        (* map_setup_code="" → all_setup_code="" → no bpf_object__find_map_by_name anywhere *)
        let has_find_map = contains_pattern generated_content "bpf_object__find_map_by_name" in
        check bool "no bpf_object__find_map_by_name when no userspace map usage" false has_find_map
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 12: Map setup code uses only userspace-used maps when no pinned maps *)
let test_map_setup_only_for_used_maps () =
  (* var count triggers skeleton loading (has_global_vars=true → needs_object_loading=true).
     used_map is referenced in main; ebpf_only_map is referenced only in @xdp fn. *)
  let code = {|
var count : u64 = 0
var used_map : hash<u32, u64>(1024)
var ebpf_only_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  ebpf_only_map[1] = 100
  return XDP_PASS
}

fn main() -> i32 {
  used_map[1] = 42
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_setup_used_maps.ks" with
    | Some generated_content ->
        (* has_pinned_maps=false, uses_map_operations=true
           → maps_for_setup = used_global_maps_with_exec = [used_map]
           setup_call injects all_setup_code; only used_map gets find_map_by_name *)
        let has_used_map_setup = contains_pattern generated_content "find_map_by_name.*used_map" in
        let has_ebpf_only_setup = contains_pattern generated_content "find_map_by_name.*ebpf_only_map" in
        check bool "used_map has setup code (find_map_by_name)" true has_used_map_setup;
        check bool "ebpf_only_map does NOT get setup code" false has_ebpf_only_setup
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 13: Map setup code includes all global maps when pinned maps exist *)
let test_map_setup_pinned_includes_all_global_maps () =
  (* var count triggers skeleton loading.
     pinned_map is pinned. other_map is non-pinned and eBPF-only (not accessed in main).
     Because has_pinned_maps=true, maps_for_setup = global_maps = [pinned_map, other_map]. *)
  let code = {|
var count : u64 = 0
pin var pinned_map : hash<u32, u64>(1024)
var other_map : hash<u32, u64>(512)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  other_map[1] = 100
  return XDP_PASS
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_setup_pinned.ks" with
    | Some generated_content ->
        (* has_pinned_maps=true → maps_for_setup = global_maps = [pinned_map, other_map]
           setup_call is triggered by has_pinned_maps; all_setup_code includes setup for BOTH maps *)
        let has_pinned_map_setup = contains_pattern generated_content "find_map_by_name.*pinned_map" in
        let has_other_map_setup = contains_pattern generated_content "find_map_by_name.*other_map" in
        check bool "pinned_map gets setup code (find_map_by_name)" true has_pinned_map_setup;
        check bool "eBPF-only other_map ALSO gets setup code (global_maps used)" true has_other_map_setup
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 14: Directory creation helper (ensure_bpf_dir) generated when pinned maps exist *)
let test_mkdir_helper_generated_with_pinned_maps () =
  let code = {|
pin var my_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  my_map[1] = 99
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_mkdir_pinned.ks" with
    | Some generated_content ->
        (* has_pinned_maps=true → mkdir_helper_function is the ensure_bpf_dir function *)
        let has_ensure_bpf_dir = contains_pattern generated_content "ensure_bpf_dir" in
        check bool "ensure_bpf_dir present when pinned maps exist" true has_ensure_bpf_dir
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 15: Directory creation helper (ensure_bpf_dir) not generated without pinned maps *)
let test_mkdir_helper_not_generated_without_pinned_maps () =
  let code = {|
var regular_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  regular_map[1] = 42
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_mkdir_no_pinned.ks" with
    | Some generated_content ->
        (* has_pinned_maps=false → mkdir_helper_function = "" *)
        let has_ensure_bpf_dir = contains_pattern generated_content "ensure_bpf_dir" in
        check bool "ensure_bpf_dir absent when no pinned maps" false has_ensure_bpf_dir
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 16: Pinned map setup emits bpf_obj_get / ensure_bpf_dir / bpf_map__pin logic *)
let test_pin_logic_pinned_map_setup () =
  let code = {|
var count : u64 = 0
pin var pinned_counter : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_pin_logic.ks" with
    | Some generated_content ->
        (* Some pin_path branch: generates bpf_obj_get to check existing pin *)
        let has_bpf_obj_get = contains_pattern generated_content "bpf_obj_get" in
        (* ... _existing_fd variable for the pinned map *)
        let has_existing_fd = contains_pattern generated_content "pinned_counter_existing_fd" in
        (* ... ensure_bpf_dir to create directory before pinning *)
        let has_ensure_bpf_dir = contains_pattern generated_content "ensure_bpf_dir" in
        (* ... bpf_map__pin to pin the map object *)
        let has_bpf_map_pin = contains_pattern generated_content "bpf_map__pin.*pinned_counter" in
        check bool "bpf_obj_get present for pinned map" true has_bpf_obj_get;
        check bool "_existing_fd variable present for pinned map" true has_existing_fd;
        check bool "ensure_bpf_dir called before pinning" true has_ensure_bpf_dir;
        check bool "bpf_map__pin called to pin the map" true has_bpf_map_pin
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 17: Non-pinned map setup uses plain bpf_map__fd only *)
let test_pin_logic_non_pinned_map_setup () =
  let code = {|
var count : u64 = 0
var regular_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return XDP_PASS
}

fn main() -> i32 {
  regular_map[1] = 42
  return 0
}
|} in
  try
    let ast = parse_string_with_builtins code in
    match get_generated_userspace_code ast "test_no_pin_logic.ks" with
    | Some generated_content ->
        (* None branch: plain fd fetch *)
        let has_bpf_map_fd = contains_pattern generated_content "bpf_map__fd.*regular_map" in
        (* None branch: no pinning machinery *)
        let has_bpf_obj_get = contains_pattern generated_content "bpf_obj_get" in
        let has_existing_fd = contains_pattern generated_content "regular_map_existing_fd" in
        let has_bpf_map_pin = contains_pattern generated_content "bpf_map__pin.*regular_map" in
        check bool "bpf_map__fd used for non-pinned map" true has_bpf_map_fd;
        check bool "bpf_obj_get NOT present for non-pinned map" false has_bpf_obj_get;
        check bool "_existing_fd NOT present for non-pinned map" false has_existing_fd;
        check bool "bpf_map__pin NOT called for non-pinned map" false has_bpf_map_pin
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

let global_function_maps_tests = [
  "global_map_accessibility", `Quick, test_global_map_accessibility;
  "global_only_map_access", `Quick, test_global_only_map_access;
  "map_operation_generation", `Quick, test_map_operation_generation;
  "multiple_map_types_global_functions", `Quick, test_multiple_map_types_global_functions;
  "global_function_code_structure", `Quick, test_global_function_code_structure;
  "global_function_error_handling", `Quick, test_global_function_error_handling;
  "map_fd_generation", `Quick, test_map_fd_generation;
  "map_fd_not_generated_without_usage", `Quick, test_map_fd_not_generated_without_usage;
  "map_fd_only_for_userspace_used_maps", `Quick, test_map_fd_only_for_userspace_used_maps;
  "map_fd_pinned_includes_all_global_maps", `Quick, test_map_fd_pinned_includes_all_global_maps;
  "mkdir_helper_generated_with_pinned_maps", `Quick, test_mkdir_helper_generated_with_pinned_maps;
  "mkdir_helper_not_generated_without_pinned_maps", `Quick, test_mkdir_helper_not_generated_without_pinned_maps;
  "map_setup_not_generated_without_usage", `Quick, test_map_setup_not_generated_without_usage;
  "map_setup_only_for_used_maps", `Quick, test_map_setup_only_for_used_maps;
  "map_setup_pinned_includes_all_global_maps", `Quick, test_map_setup_pinned_includes_all_global_maps;
  "pin_logic_pinned_map_setup", `Quick, test_pin_logic_pinned_map_setup;
  "pin_logic_non_pinned_map_setup", `Quick, test_pin_logic_non_pinned_map_setup;
]

let () =
  run "KernelScript Global Function Maps Tests" [
    "global_function_maps", global_function_maps_tests;
  ] 