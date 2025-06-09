open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Type_checker

(** Test suite for Map Syntax and Operations *)

let test_position = make_position 1 1 "test.ks"

(** Helper function to check if string contains substring *)
let string_contains_substring s sub =
  try
    let _ = Str.search_forward (Str.regexp_string sub) s 0 in
    true
  with
  | Not_found -> false

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

(** Test map declaration parsing *)
let test_map_declaration_parsing () =
  let test_cases = [
    (* Basic HashMap *)
    ("map test_map : HashMap<u32, u64> { max_entries: 1024; }", true);
    (* Array map *)
    ("map array_map : Array<u32, u32> { max_entries: 512; }", true);
    (* PercpuHash *)
    ("map percpu_map : PercpuHash<u64, u64> { max_entries: 256; }", true);
    (* Invalid syntax - parentheses instead of angle brackets *)
    ("map bad_map : HashMap(u32, u64) { max_entries: 1024; }", false);
    (* Empty config - should now be invalid (max_entries mandatory) *)
    ("map default_map : HashMap<u32, u64> { }", false);
  ] in
  
  List.for_all (fun (code, should_succeed) ->
    try
      let program = Printf.sprintf "%s\nprogram test : xdp { fn main() -> u32 { return 0; } }" code in
      let _ = parse_string program in
      should_succeed
    with
    | _ -> not should_succeed
  ) test_cases

(** Test map operations parsing *)
let test_map_operations_parsing () =
  let test_cases = [
    (* Map lookup *)
    ("let value = my_map[key];", true);
    (* Map assignment *)
    ("my_map[key] = value;", true);
    (* Nested map access *)
    ("let result = outer_map[inner_map[key]];", true);
    (* Invalid syntax - method style *)
    ("let value = my_map.lookup(key);", false);
  ] in
  
  List.for_all (fun (code, should_succeed) ->
    try
      let program = Printf.sprintf "map my_map : HashMap<u32, u64> { max_entries: 1024; }\nprogram test : xdp { fn main() -> u32 { %s return 0; } }" code in
      let _ = parse_string program in
      should_succeed
    with
    | _ -> not should_succeed
  ) test_cases

(** Test complete map program parsing *)
let test_complete_map_program_parsing () =
  let program = {|
map packet_counts : HashMap<u32, u64> {
  max_entries: 1024;
}

program rate_limiter : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let src_ip = 0x08080808;
    let current_count = packet_counts[src_ip];
    let new_count = current_count + 1;
    packet_counts[src_ip] = new_count;
    
    if (new_count > 100) {
      return 1;
    }
    
    return 2;
  }
}
|} in
  try
    let _ = parse_string program in
    true
  with
  | _ -> false

(** Test map type checking *)
let test_map_type_checking () =
  let program = {|
map test_map : HashMap<u32, u64> {
  max_entries: 1024;
}

program test : xdp {
  fn main() -> u32 {
    let key = 42;
    let value = test_map[key];
    test_map[key] = value + 1;
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    let _ = type_check_ast ast in
    true
  with
  | _ -> false

(** Test map type validation *)
let test_map_type_validation () =
  let test_cases = [
    (* Valid: u32 key with u32 access *)
    ({|
map valid_map : HashMap<u32, u64> { max_entries: 1024; }
program test : xdp {
  fn main() -> u32 {
    let key: u32 = 42;
    let value = valid_map[key];
    return 0;
  }
}
|}, true);
    
    (* Invalid: string key with u32 map *)
    ({|
map invalid_map : HashMap<u32, u64> { max_entries: 1024; }
program test : xdp {
  fn main() -> u32 {
    let key = "invalid";
    let value = invalid_map[key];
    return 0;
  }
}
|}, false);
  ] in
  
  List.for_all (fun (code, should_succeed) ->
    try
      let ast = parse_string code in
      let _ = type_check_ast ast in
      should_succeed
    with
    | Type_error _ -> not should_succeed
    | _ -> false
  ) test_cases

(** Test map identifier resolution *)
let test_map_identifier_resolution () =
  let program = {|
map global_map : HashMap<u32, u64> {
  max_entries: 1024;
}

program test : xdp {
  fn main() -> u32 {
    let value = global_map[42];
    return 0;
  }
}
|} in
  try
    let ast = parse_string program in
    let typed_programs = type_check_ast ast in
    (* Check that the map identifier was resolved and can be used in expressions *)
    match typed_programs with
    | [typed_prog] ->
        (match typed_prog.tprog_functions with
         | [main_func] ->
             (match main_func.tfunc_body with
              | [decl_stmt; _] ->
                  (match decl_stmt.tstmt_desc with
                   | TDeclaration (_, U64, _) -> true  (* Map lookup returns u64 *)
                   | _ -> false)
              | _ -> false)
         | _ -> false)
    | _ -> false
  with
  | _ -> false

(** Test IR generation for maps *)
let test_map_ir_generation () =
  let program = {|
map test_map : HashMap<u32, u64> {
  max_entries: 1024;
}

program test : xdp {
  fn main() -> u32 {
    let key = 42;
    let value = test_map[key];
    test_map[key] = value + 1;
    return 0;
  }
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let typed_programs = type_check_ast ast in
    let annotated_ast = Kernelscript.Type_checker.typed_ast_to_annotated_ast typed_programs ast in
    
    (* Test that IR generation completes without errors *)
    let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
    true
  with
  | _ -> false

(** Test C code generation for maps *)
let test_map_c_generation () =
  let program = {|
map packet_counter : HashMap<u32, u64> {
  max_entries: 1024;
}

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    let src_ip = 0x12345678;
    let count = packet_counter[src_ip];
    packet_counter[src_ip] = count + 1;
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
    
    (* Test that C code generation completes and produces expected output *)
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir in
    
    let contains_map_decl = string_contains_substring c_code "BPF_MAP_TYPE_HASH" &&
                           string_contains_substring c_code "packet_counter" in
    let contains_lookup = string_contains_substring c_code "bpf_map_lookup_elem" in
    let contains_update = string_contains_substring c_code "bpf_map_update_elem" in
    
    contains_map_decl && contains_lookup && contains_update
  with
  | _ -> false

(** Test different map types *)
let test_different_map_types () =
  let map_types = [
    ("HashMap", "BPF_MAP_TYPE_HASH");
    ("Array", "BPF_MAP_TYPE_ARRAY");
    ("PercpuHash", "BPF_MAP_TYPE_PERCPU_HASH");
    ("PercpuArray", "BPF_MAP_TYPE_PERCPU_ARRAY");
    ("LruHash", "BPF_MAP_TYPE_LRU_HASH");
  ] in
  
  List.for_all (fun (ks_type, c_type) ->
    let program = Printf.sprintf {|
map test_map : %s<u32, u64> {
  max_entries: 1024;
}

program test : xdp {
  fn main() -> u32 {
    let key = 42;
    let value = test_map[key];
    return 0;
  }
}
|} ks_type in
    try
      (* Follow the complete compiler pipeline *)
      let ast = parse_string program in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let typed_programs = type_check_ast ast in
      let annotated_ast = Kernelscript.Type_checker.typed_ast_to_annotated_ast typed_programs ast in
      
      (* Test compilation and C code generation *)
      let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table in
      let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir in
      string_contains_substring c_code c_type
    with
    | _ -> false
  ) map_types

(** Main test runner *)
let () =
  Printf.printf "=== Map Syntax and Operations Test Suite ===\n\n";
  
  run_test "Map declaration parsing" test_map_declaration_parsing;
  run_test "Map operations parsing" test_map_operations_parsing;
  run_test "Complete map program parsing" test_complete_map_program_parsing;
  run_test "Map type checking" test_map_type_checking;
  run_test "Map type validation" test_map_type_validation;
  run_test "Map identifier resolution" test_map_identifier_resolution;
  run_test "Map IR generation" test_map_ir_generation;
  run_test "Map C code generation" test_map_c_generation;
  run_test "Different map types" test_different_map_types;
  
  Printf.printf "\n=== Map Syntax Tests Complete ===\n" 