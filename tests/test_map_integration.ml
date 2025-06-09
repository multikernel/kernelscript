open Kernelscript.Parse
open Kernelscript.Type_checker

(** Integration test suite for complete map functionality *)

let run_test test_name test_func =
  Printf.printf "%-50s " test_name;
  try
    if test_func () then
      Printf.printf "✅ PASS\n"
    else
      Printf.printf "❌ FAIL\n"
  with
  | exn ->
      Printf.printf "❌ ERROR: %s\n" (Printexc.to_string exn)

(** Helper function to check if string contains substring *)
let string_contains_substring s sub =
  try
    let _ = Str.search_forward (Str.regexp_string sub) s 0 in
    true
  with
  | Not_found -> false

(** Test end-to-end compilation of a complete map program *)
let test_complete_map_compilation () =
  let program = {|
map<u32, u64> packet_counts : HashMap(1024) {
}

map<u32, u64> rate_limits : HashMap(512) {
}

program rate_limiter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let src_ip = 0x08080808;
    
    // Get current packet count
    let current_count = packet_counts[src_ip];
    
    // Increment packet count
    packet_counts[src_ip] = current_count + 1;
    
    // Get rate limit for this IP
    let limit = rate_limits[src_ip];
    let final_limit = 1000;
    if (limit == 0) {
      // Set default limit if not configured
      rate_limits[src_ip] = 1000;
    } else {
      final_limit = limit;
    }
    
    // Apply rate limiting
    if (packet_counts[src_ip] > final_limit) {
      return 1; // XDP_DROP
    }
    
    return 2; // XDP_PASS
  }
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let typed_programs = type_check_ast ast in
    let annotated_ast = Kernelscript.Type_checker.typed_ast_to_annotated_ast typed_programs ast in
    let ir_program = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_program in
    
    (* Verify C code contains expected elements *)
    let has_map_declarations = 
      string_contains_substring c_code "packet_counts" &&
      string_contains_substring c_code "rate_limits" &&
      string_contains_substring c_code "BPF_MAP_TYPE_HASH" in
    
    let has_map_operations =
      string_contains_substring c_code "bpf_map_lookup_elem" &&
      string_contains_substring c_code "bpf_map_update_elem" in
    
    let has_program_structure =
      string_contains_substring c_code "SEC(\"xdp\")" &&
      string_contains_substring c_code "rate_limiter" in
    
    has_map_declarations && has_map_operations && has_program_structure
  with
  | _ -> false

(** Test multiple map types in one program *)
let test_multiple_map_types () =
  let program = {|
map<u32, u64> hash_map : HashMap(1024) { }
map<u32, u32> array_map : Array(256) { }
map<u64, u64> percpu_map : PercpuHash(512) { }

program multi_map : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    // Use hash map
    hash_map[42] = 100;
    let hash_value = hash_map[42];
    
    // Use array map  
    array_map[10] = 200;
    let array_value = array_map[10];
    
    // Use percpu map
    percpu_map[123] = 300;
    let percpu_value = percpu_map[123];
    
    return 2;
  }
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let typed_programs = type_check_ast ast in
    let annotated_ast = Kernelscript.Type_checker.typed_ast_to_annotated_ast typed_programs ast in
    let ir_program = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_program in
    
    (* Check that all map types are present *)
    let has_hash = string_contains_substring c_code "BPF_MAP_TYPE_HASH" in
    let has_array = string_contains_substring c_code "BPF_MAP_TYPE_ARRAY" in
    let has_percpu = string_contains_substring c_code "BPF_MAP_TYPE_PERCPU_HASH" in
    
    has_hash && has_array && has_percpu
  with
  | _ -> false

(** Test error handling for invalid map operations *)
let test_invalid_map_operations () =
  let test_cases = [
    (* Invalid key type *)
    {|
map<u32, u64> test_map : HashMap(1024) { }
program test : xdp {
  fn main() -> u32 {
    test_map["invalid_key"] = 100;
    return 0;
  }
}
|};
    
    (* Invalid value type *)
    {|
map<u32, u64> test_map : HashMap(1024) { }
program test : xdp {
  fn main() -> u32 {
    test_map[42] = "invalid_value";
    return 0;
  }
}
|};
    
    (* Undefined map *)
    {|
program test : xdp {
  fn main() -> u32 {
    undefined_map[42] = 100;
    return 0;
  }
}
|};
  ] in
  
  (* All these should fail type checking *)
  List.for_all (fun program ->
    try
      let ast = parse_string program in
      let _ = type_check_ast ast in
      false  (* Should not succeed *)
    with
    | Type_error _ -> true  (* Expected error *)
    | _ -> false
  ) test_cases

(** Test map operations with complex expressions *)
let test_complex_map_expressions () =
  let program = {|
map<u32, u64> counters : HashMap(1024) { }
map<u32, u64> multipliers : HashMap(512) { }

program complex_ops : xdp {
  fn compute_key(base: u32) -> u32 {
    return base * 2 + 1;
  }
  
  fn compute_value(x: u64, y: u64) -> u64 {
    return x * y + 42;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let base_key = 10;
    let computed_key = compute_key(base_key);
    
    // Complex key expression
    let current = counters[computed_key];
    let multiplier = multipliers[base_key];
    
    // Complex value expression
    counters[computed_key] = compute_value(current, multiplier);
    
    // Nested map access
    let nested_key = counters[base_key];
    multipliers[nested_key] = 100;
    
    return 2;
  }
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let typed_programs = type_check_ast ast in
    let annotated_ast = Kernelscript.Type_checker.typed_ast_to_annotated_ast typed_programs ast in
    let ir_program = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_program in
    
    (* Check that complex operations were generated *)
    let has_lookups = string_contains_substring c_code "bpf_map_lookup_elem" in
    let has_updates = string_contains_substring c_code "bpf_map_update_elem" in
    let has_function_calls = string_contains_substring c_code "compute_" in
    
    has_lookups && has_updates && has_function_calls
  with
  | _ -> false

(** Test map operations in conditional statements *)
let test_map_operations_in_conditionals () =
  let program = {|
map<u32, u64> packet_counts : HashMap(1024) { }
map<u32, u32> blacklist : HashMap(256) { }

program conditional_maps : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let src_ip = 0x08080808;
    
    // Check if IP is blacklisted
    if (blacklist[src_ip] > 0) {
      return 1; // Drop blacklisted packets
    }
    
    // Increment packet count
    let current_count = packet_counts[src_ip];
    packet_counts[src_ip] = current_count + 1;
    
    // Add to blacklist if too many packets
    if (packet_counts[src_ip] > 1000) {
      blacklist[src_ip] = 1;
      return 1; // Drop
    }
    
    // Conditional map access
    let threshold = 100;
    if (src_ip == 0x08080808) {
      threshold = 500;
    }
    
    if (packet_counts[src_ip] > threshold) {
      return 1; // Drop if over threshold
    }
    
    return 2; // Pass
  }
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let typed_programs = type_check_ast ast in
    let annotated_ast = Kernelscript.Type_checker.typed_ast_to_annotated_ast typed_programs ast in
    let ir_program = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_program in
    
    (* Verify conditional logic and map operations *)
    let has_conditional_logic = string_contains_substring c_code "if" in
    let has_map_operations = 
      string_contains_substring c_code "bpf_map_lookup_elem" &&
      string_contains_substring c_code "bpf_map_update_elem" in
    
    has_conditional_logic && has_map_operations
  with
  | _ -> false

(** Test memory safety of generated C code *)
let test_memory_safety () =
  let program = {|
map<u32, u64> test_map : HashMap(1024) { }

program memory_safe : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let key = 42;
    let value = test_map[key];
    test_map[key] = value + 1;
    return 2;
  }
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let typed_programs = type_check_ast ast in
    let annotated_ast = Kernelscript.Type_checker.typed_ast_to_annotated_ast typed_programs ast in
    let ir_program = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_program in
    
    (* Check for null pointer checks in generated code *)
    let has_null_checks = string_contains_substring c_code "__tmp_ptr" in
    let has_proper_dereferencing = string_contains_substring c_code "if (__tmp_ptr)" in
    
    has_null_checks && has_proper_dereferencing
  with
  | _ -> false

(** Main test runner *)
let () =
  Printf.printf "=== Map Integration Test Suite ===\n\n";
  
  run_test "Complete map compilation" test_complete_map_compilation;
  run_test "Multiple map types" test_multiple_map_types;
  run_test "Invalid map operations" test_invalid_map_operations;
  run_test "Complex map expressions" test_complex_map_expressions;
  run_test "Map operations in conditionals" test_map_operations_in_conditionals;
  run_test "Memory safety" test_memory_safety;
  
  Printf.printf "\n=== Map Integration Tests Complete ===\n" 