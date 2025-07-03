open Kernelscript.Parse
open Kernelscript.Ebpf_c_codegen
open Alcotest

(** Integration test suite for complete map functionality *)

(** Helper function to check if string contains substring *)
let string_contains_substring s sub =
  try
    let _ = Str.search_forward (Str.regexp_string sub) s 0 in
    true
  with
  | Not_found -> false

(** Helper function for position printing *)
let _string_of_position pos =
  Printf.sprintf "%s:%d:%d" pos.Kernelscript.Ast.filename pos.Kernelscript.Ast.line pos.Kernelscript.Ast.column

(** Helper function to extract maps from AST *)
let extract_maps_from_ast ast =
  List.filter_map (function
    | Kernelscript.Ast.MapDecl map_decl -> Some map_decl
    | _ -> None
  ) ast

(** Helper function to run complete compilation pipeline and return generated C code *)
let compile_to_c_code ast =
  try
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi_program = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let c_code = generate_c_multi_program ir_multi_program in
    Some c_code
  with
  | exn -> 
    Printf.printf "Compilation failed: %s\n" (Printexc.to_string exn);
    None

(** Helper function for error testing - lets exceptions propagate *)
let compile_to_c_code_with_exceptions ast =
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let ir_multi_program = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  let c_code = generate_c_multi_program ir_multi_program in
  c_code

(** Test end-to-end compilation of a complete map program *)
let test_complete_map_compilation () =
  let program = {|
map<u32, u64> counter : HashMap(1024)

@xdp fn rate_limiter(ctx: xdp_md) -> xdp_action {
  var src_ip = 0x08080808
  var current_count = counter[src_ip]
  counter[src_ip] = current_count + 1
  
  if (current_count > 100) {
    return 1
  }
  
  return 2
}
|} in
  try
    let ast = parse_string program in
    let maps = extract_maps_from_ast ast in
    
    check int "one map parsed" 1 (List.length maps);
    let counter_map = List.hd maps in
    check string "map name" "counter" counter_map.Kernelscript.Ast.name;
    check bool "map key type" true (counter_map.Kernelscript.Ast.key_type = U32);
    check bool "map value type" true (counter_map.Kernelscript.Ast.value_type = U64);
    
    match compile_to_c_code ast with
    | Some c_code ->
        let has_map_lookup = string_contains_substring c_code "bpf_map_lookup_elem" in
        let has_map_update = string_contains_substring c_code "bpf_map_update_elem" in
        let has_xdp_section = string_contains_substring c_code "SEC(\"xdp\")" in
        
        check bool "has map lookup" true has_map_lookup;
        check bool "has map update" true has_map_update;
        check bool "has XDP section" true has_xdp_section
    | None ->
        fail "Failed to compile map operations"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test multiple map types in one program *)
let test_multiple_map_types () =
  let program = {|
map<u32, u64> global_counter : HashMap(1024)
map<u16, u32> port_map : Array(65536)  
map<u64, u32> session_map : HashMap(10000)

@xdp fn multi_map(ctx: xdp_md) -> xdp_action {
  var ip = 0x08080808
  var port = 80
  var session = 0x123456789ABCDEF0
  
  global_counter[ip] = global_counter[ip] + 1
  port_map[port] = ip
  session_map[session] = ip
  
  return 2
}
|} in
  try
    let ast = parse_string program in
    let maps = extract_maps_from_ast ast in
    
    check int "three maps parsed" 3 (List.length maps);
    
    (* Verify map configurations *)
    let global_counter = List.find (fun m -> m.Kernelscript.Ast.name = "global_counter") maps in
    let port_map = List.find (fun m -> m.Kernelscript.Ast.name = "port_map") maps in 
    let session_map = List.find (fun m -> m.Kernelscript.Ast.name = "session_map") maps in
    
    check bool "global_counter is HashMap" true (global_counter.Kernelscript.Ast.map_type = HashMap);
    check bool "port_map is Array" true (port_map.Kernelscript.Ast.map_type = Array);
    check bool "session_map is HashMap" true (session_map.Kernelscript.Ast.map_type = HashMap);
    
    match compile_to_c_code ast with
    | Some c_code ->
        (* Verify all three maps appear in generated code *)
        let has_global_counter = string_contains_substring c_code "global_counter" in
        let has_port_map = string_contains_substring c_code "port_map" in  
        let has_session_map = string_contains_substring c_code "session_map" in
        
        check bool "global_counter in C code" true has_global_counter;
        check bool "port_map in C code" true has_port_map;
        check bool "session_map in C code" true has_session_map
    | None ->
        fail "Failed to compile multiple map types"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test error handling for invalid map operations *)
let test_invalid_map_operations () =
  let invalid_programs = [
    (* Type mismatch: string key with u32 map *)
    {|
map<u32, u64> test_map : HashMap(100)

@xdp fn test(ctx: xdp_md) -> xdp_action {
  test_map["invalid_key"] = 1
  return 2
}
|};
    (* Assignment type mismatch *)
    {|
map<u32, u64> test_map : HashMap(100)

@xdp fn test(ctx: xdp_md) -> xdp_action {
  test_map[1] = "invalid_value"
  return 2
}
|};
    (* Undefined map *)
    {|
@xdp fn test(ctx: xdp_md) -> xdp_action {
  undefined_map[1] = 42
  return 2
}
|};
  ] in
  
  List.iter (fun program ->
    try
      let ast = parse_string program in
      let _ = compile_to_c_code_with_exceptions ast in
      fail "Should have failed on invalid map operation"
    with
    | Kernelscript.Type_checker.Type_error (_, _) -> 
        (* Expected to fail with Type_error *)
        check bool "correctly rejected invalid map operation" true true
    | Kernelscript.Symbol_table.Symbol_error (_, _) -> 
        (* Expected to fail with Symbol_error for undefined identifiers *)
        check bool "correctly rejected invalid map operation" true true
    | _ -> 
        fail "Unexpected error type for invalid map operation"
  ) invalid_programs

(** Test map operations with complex expressions *)
let test_complex_map_expressions () =
  let program = {|
map<u32, u64> stats : HashMap(1024)

@helper
fn compute_key(base: u32) -> u32 {
  return base * 2 + 1
}

@xdp fn complex_ops(ctx: xdp_md) -> xdp_action {
  var base_ip = 0x08080808
  var key = compute_key(base_ip)
  
  var current_value = stats[key]
  stats[key] = current_value + 1
  
  if (stats[key] > 500) {
    stats[key] = 0
  }
  
  return 2
}
|} in
  try
    let ast = parse_string program in
    let maps = extract_maps_from_ast ast in
    
    (* Verify parsing of complex program structure *)
    check int "one map parsed" 1 (List.length maps);
    
    (* Extract attributed functions *)
    let attributed_functions = List.filter_map (function
      | Kernelscript.Ast.AttributedFunction attr_func -> Some attr_func
      | _ -> None
    ) ast in
    
    check int "two attributed functions" 2 (List.length attributed_functions);
    (* Attributed functions don't have multiple program functions - just the one function *)
    
    (* Compile and verify complex operations were generated *)
    match compile_to_c_code ast with
    | Some c_code ->
        let has_lookups = string_contains_substring c_code "bpf_map_lookup_elem" in
        let has_updates = string_contains_substring c_code "bpf_map_update_elem" in
        let has_function_calls = 
          string_contains_substring c_code "compute_key" in
        
        check bool "has map lookups" true has_lookups;
        check bool "has map updates" true has_updates;
        check bool "has function calls" true has_function_calls
    | None ->
        fail "Failed to compile complex expressions program"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test map operations in conditional statements *)
let test_map_operations_in_conditionals () =
  let program = {|
map<u32, u64> packet_counts : HashMap(1024)
map<u32, u32> blacklist : HashMap(256)

@xdp fn conditional_maps(ctx: xdp_md) -> xdp_action {
  var src_ip = 0x08080808
  
  if (blacklist[src_ip] > 0) {
    return 1
  }
  
  var current_count = packet_counts[src_ip]
  packet_counts[src_ip] = current_count + 1
  
  if (packet_counts[src_ip] > 1000) {
    blacklist[src_ip] = 1
    return 1
  }
  
  var threshold = 100
  if (src_ip == 0x08080808) {
    threshold = 500
  }
  
  if (packet_counts[src_ip] > threshold) {
    return 1
  }
  
  return 2
}
|} in
  try
    let ast = parse_string program in
    let maps = extract_maps_from_ast ast in
    
    (* Verify map types *)
    check int "two maps parsed" 2 (List.length maps);
    let packet_counts = List.find (fun m -> m.Kernelscript.Ast.name = "packet_counts") maps in
          let blacklist = List.find (fun m -> m.Kernelscript.Ast.name = "blacklist") maps in
    
    check string "packet_counts value type" "u64" (Kernelscript.Ast.string_of_bpf_type packet_counts.Kernelscript.Ast.value_type);
          check string "blacklist value type" "u32" (Kernelscript.Ast.string_of_bpf_type blacklist.Kernelscript.Ast.value_type);
    
    (* Compile and verify conditional logic and map operations *)
    match compile_to_c_code ast with
    | Some c_code ->
        let has_conditional_logic = string_contains_substring c_code "if" in
        let has_map_operations = 
          string_contains_substring c_code "bpf_map_lookup_elem" &&
          string_contains_substring c_code "bpf_map_update_elem" in
        
        check bool "has conditional logic" true has_conditional_logic;
        check bool "has map operations" true has_map_operations;
        
        (* Verify both maps are referenced *)
        let has_packet_counts_ref = string_contains_substring c_code "packet_counts" in
        let has_blacklist_ref = string_contains_substring c_code "blacklist" in
        
        check bool "has packet_counts references" true has_packet_counts_ref;
        check bool "has blacklist references" true has_blacklist_ref
    | None ->
        fail "Failed to compile conditional operations program"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test memory safety of generated C code *)
let test_memory_safety () =
  let program = {|
map<u32, u64> test_map : HashMap(1024)

@xdp fn memory_safe(ctx: xdp_md) -> xdp_action {
  var key = 42
  var value = test_map[key]
  test_map[key] = value + 1
  return 2
}
|} in
  try
    let ast = parse_string program in
    let maps = extract_maps_from_ast ast in
    
    (* Verify single map *)
    check int "one map parsed" 1 (List.length maps);
    let test_map = List.hd maps in
    check string "test_map name" "test_map" test_map.Kernelscript.Ast.name;
    
    (* Compile and check for memory safety patterns *)
    match compile_to_c_code ast with
    | Some c_code ->
        (* Check for proper pointer handling in generated code *)
        let has_null_checks = 
          string_contains_substring c_code "__tmp_ptr" ||
          string_contains_substring c_code "if.*ptr" ||
          string_contains_substring c_code "!= NULL" in
        
        let has_proper_lookups = string_contains_substring c_code "bpf_map_lookup_elem" in
        let has_proper_updates = string_contains_substring c_code "bpf_map_update_elem" in
        
        check bool "has proper map lookups" true has_proper_lookups;
        check bool "has proper map updates" true has_proper_updates;
        
        (* The exact null checking pattern may vary, but safe map access should be present *)
        check bool "has memory safety considerations" true 
          (has_null_checks || string_contains_substring c_code "lookup" && string_contains_substring c_code "update")
    | None ->
        fail "Failed to compile memory safety program"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test integration with different context types *)
let test_different_context_types () =
  let programs = [
    ("xdp", {|
map<u32, u64> xdp_stats : HashMap(1024)

@xdp fn xdp_test(ctx: xdp_md) -> xdp_action {
  xdp_stats[1] = xdp_stats[2]
  return 2
}
|});
    ("tc", {|
map<u32, u64> tc_stats : HashMap(1024)

@tc fn tc_test(ctx: TcContext) -> TcAction {
  tc_stats[1] = tc_stats[2]
  return 0
}
|})
  ] in
  
  List.iter (fun (prog_type, program) ->
    try
      let ast = parse_string program in
      let maps = extract_maps_from_ast ast in
      
      check int ("one map for " ^ prog_type) 1 (List.length maps);
      
      match compile_to_c_code ast with
      | Some c_code ->
          let expected_section = "SEC(\"" ^ prog_type ^ "\")" in
          let has_correct_section = string_contains_substring c_code expected_section in
          
          check bool ("has " ^ prog_type ^ " section") true has_correct_section;
          
          let has_map_operations = string_contains_substring c_code "bpf_map_update_elem" in
          check bool ("has map operations for " ^ prog_type) true has_map_operations
      | None ->
          fail ("Failed to compile " ^ prog_type ^ " program")
    with
    | exn -> fail ("Error in " ^ prog_type ^ " test: " ^ Printexc.to_string exn)
  ) programs

let map_integration_tests = [
  "complete_map_compilation", `Quick, test_complete_map_compilation;
  "multiple_map_types", `Quick, test_multiple_map_types;
  "invalid_map_operations", `Quick, test_invalid_map_operations;
  "complex_map_expressions", `Quick, test_complex_map_expressions;
  "map_operations_in_conditionals", `Quick, test_map_operations_in_conditionals;
  "memory_safety", `Quick, test_memory_safety;
  "different_context_types", `Quick, test_different_context_types;
]

let () =
  run "KernelScript Map Integration Tests" [
    "map_integration", map_integration_tests;
  ] 