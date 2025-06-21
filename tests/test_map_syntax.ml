open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Type_checker
open Alcotest

(** Test suite for Map Syntax and Operations *)

let _test_position = make_position 1 1 "test.ks"

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
    ("map<u32, u64> test_map : HashMap(1024) { }", true);
    (* Array map *)
    ("map<u32, u32> array_map : Array(512) { }", true);
    (* PercpuHash *)
    ("map<u64, u64> percpu_map : PercpuHash(256) { }", true);
    (* Invalid syntax - wrong order *)
    ("map bad_map : HashMap<u32, u64>(1024) { }", false);
    (* Invalid syntax - missing max_entries *)
    ("map<u32, u64> default_map : HashMap() { }", false);
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
    (* Invalid - missing semicolon *)
    ("map<u32, u64> invalid_map : HashMap(1024)", false);
    (* Invalid - missing semicolon with block *)
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

(** Test map declarations with attributes *)
let test_map_attributes_syntax () =
  let test_cases = [
    (* Map with pinned attribute *)
    ("map<u32, u64> pinned_map : HashMap(1024) {\n    pinned: \"/sys/fs/bpf/test_map\"\n}", true);
    (* Map with pinned attribute (single line) *)
    ("map<u32, u64> pinned_map : HashMap(1024) { pinned: \"/path\" }", true);
    (* Empty block *)
    ("map<u32, u64> empty_map : HashMap(1024) { }", true);
    (* Map with multiline empty block *)
    ("map<u32, u64> multiline_map : HashMap(1024) {\n}", true);
    (* Invalid attribute *)
    ("map<u32, u64> invalid_map : HashMap(1024) { invalid_attr: \"value\" }", false);
    (* Invalid max_entries in block *)
    ("map<u32, u64> invalid_map : HashMap(1024) { max_entries: 512 }", false);
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

// Maps with empty blocks
map<u32, u64> empty_block_map : HashMap(1024) { }
map<u32, u32> multiline_empty : LruHash(256) {
}

// Maps with attributes
map<u32, u64> pinned_global : HashMap(2048) {
    pinned: "/sys/fs/bpf/global_map"
}

map<u32, u64> pinned_local : HashMap(512) {
    pinned: "/sys/fs/bpf/local_map"
}

@xdp fn test_syntax(ctx: XdpContext) -> XdpAction {
  // Test all map types can be used
  simple_counter[42] = 100
  lookup_array[10] = 200
  percpu_stats[123] = 300
  empty_block_map[1] = 400
  multiline_empty[2] = 500
  pinned_global[3] = 600
  pinned_local[4] = 700
  
  return 2
}
|} in
  try
    let _ = parse_string program in
    check bool "comprehensive syntax parsing" true true
  with
  | _ ->
    check bool "comprehensive syntax parsing" false true

(** Test map syntax type checking *)
let test_new_syntax_type_checking () =
  let program = {|
map<u32, u64> blockless_map : HashMap(512)
map<u32, u64> pinned_map : HashMap(1024) {
    pinned: "/sys/fs/bpf/test"
}

@xdp fn test(ctx: XdpContext) -> XdpAction {
  // Test type checking works with new syntax
  let key: u32 = 42
  let value1: u64 = blockless_map[key]
  let value2: u64 = pinned_map[key]
  
  blockless_map[key] = value1 + 1
  pinned_map[key] = value2 + 1
  
  return 2
}
|} in
  try
    let ast = parse_string program in
    let _ = type_check_ast ast in
    check bool "new syntax type checking" true true
  with
  | _ ->
    check bool "new syntax type checking" false true

(** Test IR generation with new syntax *)
let test_new_syntax_ir_generation () =
  let program = {|
map<u32, u64> simple_map : HashMap(512)
map<u32, u64> attr_map : HashMap(1024) {
    pinned: "/sys/fs/bpf/test_map"
}

@xdp fn test(ctx: XdpContext) -> XdpAction {
  simple_map[42] = 100
  attr_map[42] = 200
  
  let val1 = simple_map[42]
  let val2 = attr_map[42]
  
  return 2
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    
    (* Test that IR generation completes without errors *)
    let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    check bool "test passed" true true
  with
  | _ ->
    check bool "IR generation test failed" false true

(** Test C code generation with new syntax *)
let test_new_syntax_c_generation () =
  let program = {|
map<u32, u64> blockless_counter : HashMap(512)
map<u32, u64> pinned_stats : HashMap(1024) {
    pinned: "/sys/fs/bpf/stats"
}

@xdp fn counter(ctx: XdpContext) -> XdpAction {
  let key = 42
  blockless_counter[key] = blockless_counter[key] + 1
  pinned_stats[key] = pinned_stats[key] + 1
  return 2
}
|} in
  try
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir in
    
    (* Verify both maps are generated *)
    let has_blockless = contains_substr c_code "blockless_counter" in
    let has_pinned = contains_substr c_code "pinned_stats" in
    let has_map_ops = contains_substr c_code "bpf_map_lookup_elem" &&
                     contains_substr c_code "bpf_map_update_elem" in
    
    let _ = has_blockless && has_pinned && has_map_ops in
    check bool "C code generation test" true (has_blockless && has_pinned && has_map_ops)
  with
  | _ ->
    check bool "C code generation test" false true

(** Test error cases for new syntax *)
let test_new_syntax_error_cases () =
  let invalid_cases = [
    (* Invalid attribute *)
    "map<u32, u64> invalid : HashMap(512) { invalid_attr: \"val\" }";
    (* max_entries in attributes *)
    "map<u32, u64> invalid : HashMap(512) { max_entries: 1024 }";
    (* Permission attributes (should be rejected) *)
    "map<u32, u64> invalid : HashMap(512) { read_only: \"true\" }";
    (* Wrong type order *)
    "map bad_map : HashMap<u32, u64>(1024) { }";
    (* Missing colon *)
    "map<u32, u64> bad_map HashMap(1024) { }";
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
    (* Map lookup *)
    ("let value = my_map[key]", true);
    (* Map assignment *)
    ("my_map[key] = value", true);
    (* Simple nested access with correct types *)
    ("let inner_key = inner_map[key]\nlet result = outer_map[inner_key]", true);
  ] in
  
  let all_cases_passed = List.for_all (fun (code, should_succeed) ->
    try
      let program = Printf.sprintf "map<u32, u64> my_map : HashMap(1024) { }\nmap<u32, u32> outer_map : HashMap(1024) { }\nmap<u32, u32> inner_map : HashMap(1024) { }\n@xdp fn test() -> u32 { let key: u32 = 42\n let value: u64 = 100\n %s\n return 0 }" code in
      let _ = parse_string program in
      should_succeed
    with
    | _ -> not should_succeed
  ) test_cases in
  check bool "all map operations parsing cases passed" true all_cases_passed

(** Test complete map program parsing *)
let test_complete_map_program_parsing () =
  let program = {|
map<u32, u64> packet_counts : HashMap(1024) {
}

@xdp fn rate_limiter(ctx: XdpContext) -> XdpAction {
  let src_ip = 0x08080808
  let current_count = packet_counts[src_ip]
  let new_count = current_count + 1
  packet_counts[src_ip] = new_count
  
  if (new_count > 100) {
    return 1
  }
  
  return 2
}
|} in
  try
    let _ = parse_string program in
    check bool "test passed" true true
  with
  | _ ->
    check bool "test passed" false true

(** Test map type checking *)
let test_map_type_checking () =
  let program = {|
map<u32, u64> test_map : HashMap(1024) {
}

@xdp fn test() -> u32 {
  let key = 42
  let value = test_map[key]
  test_map[key] = value + 1
  return 0
}
|} in
  try
    let ast = parse_string program in
    let _ = type_check_ast ast in
    check bool "test passed" true true
  with
  | _ ->
    check bool "test passed" false true

(** Test map type validation *)
let test_map_type_validation () =
  let test_cases = [
    (* Valid: u32 key with u32 access *)
    ({|
map<u32, u64> valid_map : HashMap(1024) { }
@xdp fn test() -> u32 {
  let key: u32 = 42
  let value = valid_map[key]
  return 0
}
|}, true);
    
    (* Invalid: string key with u32 map *)
    ({|
map<u32, u64> invalid_map : HashMap(1024) { }
@xdp fn test() -> u32 {
  let key = "invalid"
  let value = invalid_map[key]
  return 0
}
|}, false)
  ] in
  
  let all_validation_passed = List.for_all (fun (code, should_succeed) ->
    try
      let ast = parse_string code in
      let _ = type_check_ast ast in
      should_succeed
    with
    | _ -> not should_succeed
  ) test_cases in
  check bool "all map type validation cases passed" true all_validation_passed

(** Test map identifier resolution *)
let test_map_identifier_resolution () =
  let program = {|
map<u32, u64> global_map : HashMap(1024) {
}

@xdp fn test(ctx: XdpContext) -> XdpAction {
  let value = global_map[42]
  return 2
}
|} in
  try
    let ast = parse_string program in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    (* If we get here, the map identifier was resolved successfully *)
    let _ = annotated_ast in
    check bool "map identifier resolution" true true
  with
  | _ ->
    check bool "map identifier resolution" true false

(** Test IR generation for maps *)
let test_map_ir_generation () =
  let program = {|
map<u32, u64> test_map : HashMap(1024) {
}

@xdp fn test(ctx: XdpContext) -> XdpAction {
  let key = 42
  let value = test_map[key]
  test_map[key] = value + 1
  return 0
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    
    (* Test that IR generation completes without errors *)
    let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    check bool "test passed" true true
  with
  | _ ->
    check bool "IR generation test failed" false true

(** Test C code generation for maps *)
let test_map_c_generation () =
  let program = {|
map<u32, u64> packet_counter : HashMap(1024) {
}

@xdp fn test(ctx: XdpContext) -> XdpAction {
  let src_ip = 0x12345678
  let count = packet_counter[src_ip]
  packet_counter[src_ip] = count + 1
  return 2
}
|} in
  try
    (* Follow the complete compiler pipeline *)
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    
    (* Test that C code generation completes and produces expected output *)
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir in
    
    let contains_map_decl = contains_substr c_code "BPF_MAP_TYPE_HASH" &&
                           contains_substr c_code "packet_counter" in
    let contains_lookup = contains_substr c_code "bpf_map_lookup_elem" in
    let contains_update = contains_substr c_code "bpf_map_update_elem" in
    
    check bool "C code generation test" true (contains_map_decl && contains_lookup && contains_update)
  with
  | _ ->
    check bool "C code generation test" false true

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
map<u32, u64> test_map : %s(1024) {
}

@xdp fn test(ctx: XdpContext) -> XdpAction {
  let key = 42
  let value = test_map[key]
  return 2
}
|} ks_type in
    try
      (* Follow the complete compiler pipeline *)
      let ast = parse_string program in
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
      
      (* Test compilation and C code generation *)
      let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
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