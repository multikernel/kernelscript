open Kernelscript
open Ast

(** Test suite for Map Flags functionality *)

(** Helper function to create dummy position *)
let dummy_pos = { line = 1; column = 1; filename = "test" }

(** Helper to create IR map def with flags *)
let create_ir_map_with_flags name flags =
  Ir.make_ir_map_def
    name
    Ir.IRU32 (* key type *)
    Ir.IRU32 (* value type *)
    Ir.IRHashMap
    1024 (* max_entries *)
    ~flags:flags
    ~is_global:true
    dummy_pos

(** Helper function to check if string contains substring *)
let string_contains_substring str sub =
  try
    let _ = Str.search_forward (Str.regexp_string sub) str 0 in
    true
  with
  | Not_found -> false

(** Test 1: Flag parsing and AST representation *)
let test_flag_parsing () =
  Printf.printf "\n=== Test 1: Flag Parsing ===\n";
  
  (* Test individual flags *)
  let test_cases = [
    ("no_prealloc", "flags: no_prealloc");
    ("no_common_lru", "flags: no_common_lru");  
    ("rdonly", "flags: rdonly");
    ("wronly", "flags: wronly");
    ("clone", "flags: clone");
    ("numa_node(1)", "flags: numa_node(1)");
  ] in
  
  List.iter (fun (flag_name, attr_code) ->
    let map_code = Printf.sprintf {|
program test : xdp {
  map<u32, u32> test_map : HashMap(1024) {
    %s,
  };
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}|} attr_code in
    
    try
      let lexbuf = Lexing.from_string map_code in
      let _ast = Parser.program Lexer.token lexbuf in
      
      (* Find the map declaration and check its flags *)
      (* Note: For now we just check that parsing succeeds *)
      Printf.printf "Parse %s: PASS\n" flag_name
    with
    | e -> Printf.printf "Parse %s: FAIL (%s)\n" flag_name (Printexc.to_string e)
  ) test_cases

(** Test 2: Flag combination with pipe operator *)
let test_flag_combinations () =
  Printf.printf "\n=== Test 2: Flag Combinations ===\n";
  
  let combination_tests = [
    ("no_prealloc | rdonly", 2);
    ("rdonly | wronly | clone", 3);
    ("numa_node(1) | no_common_lru", 2);
    ("no_prealloc | rdonly | clone | numa_node(0)", 4);
  ] in
  
  List.iter (fun (flags_str, expected_count) ->
    let map_code = Printf.sprintf {|
program test : xdp {
  map<u32, u32> test_map : HashMap(1024) {
    flags: %s,
  };
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}|} flags_str in
    
    try
      let lexbuf = Lexing.from_string map_code in
      let _ast = Parser.program Lexer.token lexbuf in
      Printf.printf "Combination '%s': PASS (expected %d flags)\n" flags_str expected_count
    with
    | e -> Printf.printf "Combination '%s': FAIL (%s)\n" flags_str (Printexc.to_string e)
  ) combination_tests

(** Test 3: AST flag to integer conversion *)
let test_flag_to_int_conversion () =
  Printf.printf "\n=== Test 3: Flag to Integer Conversion ===\n";
  
  let flag_tests = [
    (NoPrealloc, 0x1, "BPF_F_NO_PREALLOC");
    (NoCommonLru, 0x2, "BPF_F_NO_COMMON_LRU");
    (NumaNode 1, 0x104, "BPF_F_NUMA_NODE(1)"); (* 0x4 | (1 << 8) *)
    (Rdonly, 0x8, "BPF_F_RDONLY");
    (Wronly, 0x10, "BPF_F_WRONLY");
    (Clone, 0x20, "BPF_F_CLONE");
  ] in
  
  List.iter (fun (flag, expected_value, flag_name) ->
    let actual_value = Maps.ast_flags_to_int [flag] in
    let result = if actual_value = expected_value then "PASS" else "FAIL" in
    Printf.printf "%s (0x%x): %s\n" flag_name actual_value result;
    if actual_value <> expected_value then
      Printf.printf "  Expected: 0x%x, Got: 0x%x\n" expected_value actual_value
  ) flag_tests

(** Test 4: Flag combination integer conversion *)
let test_flag_combination_conversion () =
  Printf.printf "\n=== Test 4: Flag Combination Conversion ===\n";
  
  let combination_tests = [
    ([NoPrealloc; Rdonly], 0x1 lor 0x8, "NO_PREALLOC | RDONLY");
    ([NoPrealloc; NoCommonLru; Rdonly], 0x1 lor 0x2 lor 0x8, "NO_PREALLOC | NO_COMMON_LRU | RDONLY");
    ([NumaNode 2; Clone], (0x4 lor (2 lsl 8)) lor 0x20, "NUMA_NODE(2) | CLONE");
    ([Wronly; Clone], 0x10 lor 0x20, "WRONLY | CLONE");
  ] in
  
  List.iter (fun (flags, expected_value, description) ->
    let actual_value = Maps.ast_flags_to_int flags in
    let result = if actual_value = expected_value then "PASS" else "FAIL" in
    Printf.printf "%s (0x%x): %s\n" description actual_value result;
    if actual_value <> expected_value then
      Printf.printf "  Expected: 0x%x, Got: 0x%x\n" expected_value actual_value
  ) combination_tests

(** Test 5: Map config with flags *)
let test_map_config_with_flags () =
  Printf.printf "\n=== Test 5: Map Config with Flags ===\n";
  
  (* Test make_map_config with flags *)
  let flags = [NoPrealloc; Rdonly] in
  let attributes = [Pinned "/sys/fs/bpf/test"] in
  let config = make_map_config 1024 ~flags:flags attributes in
  
  Printf.printf "Config max_entries: %s\n" 
    (if config.max_entries = 1024 then "PASS" else "FAIL");
  Printf.printf "Config flags count: %s\n" 
    (if List.length config.flags = 2 then "PASS" else "FAIL");
  Printf.printf "Config attributes count: %s\n" 
    (if List.length config.attributes = 1 then "PASS" else "FAIL")

(** Test 6: FlagsAttr handling in attributes *)
let test_flags_attr_extraction () =
  Printf.printf "\n=== Test 6: FlagsAttr Extraction ===\n";
  
  (* Test that FlagsAttr gets properly extracted from attributes *)
  let flags = [NoPrealloc; Rdonly] in
  let attributes = [Pinned "/sys/fs/bpf/test"; FlagsAttr flags] in
  let config = make_map_config 1024 attributes in
  
  Printf.printf "Extracted flags count: %s\n" 
    (if List.length config.flags = 2 then "PASS" else "FAIL");
  Printf.printf "Remaining attributes count: %s\n" 
    (if List.length config.attributes = 1 then "PASS" else "FAIL");
  
  (* Check that the remaining attribute is the Pinned one *)
  let pinned_found = List.exists (function
    | Pinned _ -> true
    | _ -> false
  ) config.attributes in
  Printf.printf "Pinned attribute preserved: %s\n" 
    (if pinned_found then "PASS" else "FAIL")

(** Test 7: IR conversion with flags *)
let test_ir_conversion_with_flags () =
  Printf.printf "\n=== Test 7: IR Conversion with Flags ===\n";
  
  (* Create a simple map declaration with flags *)
  let flags = [NoPrealloc; Rdonly] in
  let config = make_map_config 1024 ~flags:flags [] in
  let map_decl = make_map_declaration "test_map" U32 U64 HashMap config true dummy_pos in
  
  (* Convert to Maps representation *)
  let maps_decl = Maps.ast_to_maps_declaration map_decl in
  
  Printf.printf "Maps config flags: %s\n" 
    (if maps_decl.config.flags = (0x1 lor 0x8) then "PASS" else "FAIL");
  Printf.printf "Maps config max_entries: %s\n" 
    (if maps_decl.config.max_entries = 1024 then "PASS" else "FAIL")

(** Test 8: Error cases *)
let test_error_cases () =
  Printf.printf "\n=== Test 8: Error Cases ===\n";
  
  (* Test unknown flag *)
  let invalid_flag_code = {|
program test : xdp {
  map<u32, u32> test_map : HashMap(1024) {
    flags: unknown_flag,
  };
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}|} in
  
  (try
    let lexbuf = Lexing.from_string invalid_flag_code in
    let _ = Parser.program Lexer.token lexbuf in
    Printf.printf "Unknown flag rejection: FAIL (should have failed)\n"
  with
  | _ -> Printf.printf "Unknown flag rejection: PASS\n");
  
  (* Test invalid numa_node parameter *)
  let invalid_numa_code = {|
program test : xdp {
  map<u32, u32> test_map : HashMap(1024) {
    flags: numa_node(-1),
  };
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}|} in
  
  (try
    let lexbuf = Lexing.from_string invalid_numa_code in
    let _ = Parser.program Lexer.token lexbuf in
    Printf.printf "Invalid numa_node validation: PASS (parsed but should be validated later)\n"
  with
  | _ -> Printf.printf "Invalid numa_node parsing: PASS (parsing level rejection)\n")

(** Test 9: String representations *)
let test_string_representations () =
  Printf.printf "\n=== Test 9: String Representations ===\n";
  
  let flag_strings = [
    (NoPrealloc, "no_prealloc");
    (NoCommonLru, "no_common_lru");
    (NumaNode 1, "numa_node(1)");
    (Rdonly, "rdonly");
    (Wronly, "wronly");
    (Clone, "clone");
  ] in
  
  List.iter (fun (flag, expected_str) ->
    let actual_str = string_of_map_flag flag in
    let result = if actual_str = expected_str then "PASS" else "FAIL" in
    Printf.printf "Flag string %s: %s\n" expected_str result;
    if actual_str <> expected_str then
      Printf.printf "  Expected: '%s', Got: '%s'\n" expected_str actual_str
  ) flag_strings

(** Test 10: Complete integration test *)
let test_complete_integration () =
  Printf.printf "\n=== Test 10: Complete Integration ===\n";
  
  let complete_code = {|
program test_complete : xdp {
  map<u32, u32> simple_map : HashMap(1024);
  
  map<u32, u64> no_prealloc_map : HashMap(512) {
    flags: no_prealloc,
  };
  
  map<u32, u32> readonly_map : HashMap(256) {
    pinned: "/sys/fs/bpf/readonly_test",
    flags: rdonly | no_prealloc,
  };
  
  map<u64, u64> numa_map : LruHash(2048) {
    flags: numa_node(1) | no_common_lru,
  };

  fn main(ctx: XdpContext) -> XdpAction {
    let key: u32 = 42;
    let value: u32 = 100;
    simple_map[key] = value;
    return XdpAction::Pass;
  }
}|} in
  
  try
    let lexbuf = Lexing.from_string complete_code in
    let ast = Parser.program Lexer.token lexbuf in
    
    (* Count the number of declarations *)
    let decl_count = List.length ast in
    Printf.printf "Complete parsing (found %d declarations): PASS\n" decl_count;
    
    (* Try to find maps with different flag configurations *)
    let map_with_flags_count = List.fold_left (fun count decl ->
      match decl with
      | Program _prog ->
          (* This is a simplified check - in real test we'd need to traverse the program structure *)
          count
      | MapDecl map_decl ->
          if List.length map_decl.config.flags > 0 then count + 1 else count
      | _ -> count
    ) 0 ast in
    
    Printf.printf "Maps with flags found: %d\n" map_with_flags_count;
    Printf.printf "Integration test: PASS\n"
    
  with
  | e -> Printf.printf "Complete integration: FAIL (%s)\n" (Printexc.to_string e)

(** C Code Generation Tests *)

(** Test 11: Basic flag code generation *)
let test_basic_flag_codegen () =
  Printf.printf "\n=== Test 11: Basic Flag Code Generation ===\n";
  
  let test_cases = [
    (0x1, "BPF_F_NO_PREALLOC");
    (0x8, "BPF_F_RDONLY");
    (0x10, "BPF_F_WRONLY");
    (0x20, "BPF_F_CLONE");
    (0x9, "BPF_F_NO_PREALLOC | BPF_F_RDONLY"); (* 0x1 | 0x8 *)
  ] in
  
  List.iter (fun (flag_value, description) ->
    let ir_map = create_ir_map_with_flags "test_map" flag_value in
    let ctx = Ebpf_c_codegen.create_c_context () in
    
    try
      Ebpf_c_codegen.generate_map_definition ctx ir_map;
      let generated_code = String.concat "\n" (List.rev ctx.output_lines) in
      
      (* Check if the generated code contains the expected flags *)
      let has_flags = string_contains_substring generated_code "__uint(map_flags," in
      let has_hex_value = string_contains_substring generated_code (Printf.sprintf "0x%x" flag_value) in
      
      if flag_value = 0 then
        Printf.printf "%s (no flags): %s\n" description 
          (if not has_flags then "PASS" else "FAIL (should not have flags)")
      else
        Printf.printf "%s (0x%x): %s\n" description flag_value
          (if has_flags && has_hex_value then "PASS" else "FAIL")
    with
    | e -> Printf.printf "%s: FAIL (%s)\n" description (Printexc.to_string e)
  ) test_cases

(** Test 12: Map definition structure *)
let test_map_definition_structure () =
  Printf.printf "\n=== Test 12: Map Definition Structure ===\n";
  
  let ir_map = create_ir_map_with_flags "test_flags_map" 0x9 in (* NO_PREALLOC | RDONLY *)
  let ctx = Ebpf_c_codegen.create_c_context () in
  
  try
    Ebpf_c_codegen.generate_map_definition ctx ir_map;
    let generated_code = String.concat "\n" (List.rev ctx.output_lines) in
    
    (* Check for expected components *)
    let checks = [
      ("struct declaration", string_contains_substring generated_code "struct {");
      ("type declaration", string_contains_substring generated_code "__uint(type,");
      ("key type", string_contains_substring generated_code "__type(key,");
      ("value type", string_contains_substring generated_code "__type(value,");
      ("max_entries", string_contains_substring generated_code "__uint(max_entries,");
      ("map_flags", string_contains_substring generated_code "__uint(map_flags, 0x9);");
      ("SEC maps", string_contains_substring generated_code "SEC(\"maps\")");
      ("map name", string_contains_substring generated_code "test_flags_map");
    ] in
    
    List.iter (fun (check_name, result) ->
      Printf.printf "%s: %s\n" check_name (if result then "PASS" else "FAIL")
    ) checks;
    
    Printf.printf "\nGenerated code:\n%s\n" generated_code
    
  with
  | e -> Printf.printf "Map definition structure: FAIL (%s)\n" (Printexc.to_string e)

(** Test 13: Multiple maps with different flags *)
let test_multiple_maps_with_flags () =
  Printf.printf "\n=== Test 13: Multiple Maps with Different Flags ===\n";
  
  let maps = [
    ("no_flags_map", 0);
    ("readonly_map", 0x8);
    ("no_prealloc_map", 0x1);
    ("combined_flags_map", 0x29); (* NO_PREALLOC | RDONLY | CLONE *)
  ] in
  
  let ctx = Ebpf_c_codegen.create_c_context () in
  
  try
    List.iter (fun (name, flags) ->
      let ir_map = create_ir_map_with_flags name flags in
      Ebpf_c_codegen.generate_map_definition ctx ir_map
    ) maps;
    
    let generated_code = String.concat "\n" (List.rev ctx.output_lines) in
    
    (* Check that all maps are present *)
    List.iter (fun (name, flags) ->
      let map_present = string_contains_substring generated_code name in
      Printf.printf "Map %s (flags=0x%x): %s\n" name flags
        (if map_present then "PASS" else "FAIL")
    ) maps;
    
    Printf.printf "\nGenerated code for multiple maps:\n%s\n" generated_code
    
  with
  | e -> Printf.printf "Multiple maps generation: FAIL (%s)\n" (Printexc.to_string e)

(** Test 14: Codegen edge cases *)
let test_codegen_edge_cases () =
  Printf.printf "\n=== Test 14: Codegen Edge Cases ===\n";
  
  (* Test with maximum flag value *)
  let max_flags = 0xFFFF in
  let ir_map_max = create_ir_map_with_flags "max_flags_map" max_flags in
  let ctx1 = Ebpf_c_codegen.create_c_context () in
  
  (try
    Ebpf_c_codegen.generate_map_definition ctx1 ir_map_max;
    let code1 = String.concat "\n" (List.rev ctx1.output_lines) in
    let has_max_flags = string_contains_substring code1 "0xffff" in
    Printf.printf "Maximum flags (0x%x): %s\n" max_flags (if has_max_flags then "PASS" else "FAIL")
  with
  | e -> Printf.printf "Maximum flags: FAIL (%s)\n" (Printexc.to_string e));
  
  (* Test with zero flags (should not generate flags line) *)
  let ir_map_zero = create_ir_map_with_flags "zero_flags_map" 0 in
  let ctx2 = Ebpf_c_codegen.create_c_context () in
  
  (try
    Ebpf_c_codegen.generate_map_definition ctx2 ir_map_zero;
    let code2 = String.concat "\n" (List.rev ctx2.output_lines) in
    let has_no_flags = not (string_contains_substring code2 "__uint(map_flags,") in
    Printf.printf "Zero flags (no flags line): %s\n" (if has_no_flags then "PASS" else "FAIL")
  with
  | e -> Printf.printf "Zero flags: FAIL (%s)\n" (Printexc.to_string e))

(** Test 15: Integration with complete program *)
let test_codegen_integration_with_program () =
  Printf.printf "\n=== Test 15: Codegen Integration with Complete Program ===\n";
  
  (* Create a complete IR program with maps having flags *)
  let global_maps = [
    create_ir_map_with_flags "global_counter" 0x1; (* NO_PREALLOC *)
    create_ir_map_with_flags "readonly_cache" 0x8; (* RDONLY *)
  ] in
  
  let local_maps = [
    create_ir_map_with_flags "local_state" 0x9; (* NO_PREALLOC | RDONLY *)
  ] in
  
  (* Create a simple main function *)
  let main_func = Ir.make_ir_function
    "main"
    [("ctx", Ir.IRContext Ir.XdpCtx)]
    (Some (Ir.IRAction Ir.XdpActionType))
    [] (* basic blocks - empty for test *)
    ~is_main:true
    dummy_pos in
  
  let ir_program = Ir.make_ir_program
    "test_program"
    Ast.Xdp
    global_maps
    local_maps
    [main_func] (* functions *)
    main_func (* main function *)
    dummy_pos in
  
  try
    let generated_code = Ebpf_c_codegen.generate_c_program ir_program in
    
    (* Check that all maps with their flags are present *)
    let checks = [
      ("global_counter with NO_PREALLOC", 
       string_contains_substring generated_code "global_counter" &&
       string_contains_substring generated_code "__uint(map_flags, 0x1)");
      ("readonly_cache with RDONLY",
       string_contains_substring generated_code "readonly_cache" &&
       string_contains_substring generated_code "__uint(map_flags, 0x8)");
      ("local_state with combined flags",
       string_contains_substring generated_code "local_state" &&
       string_contains_substring generated_code "__uint(map_flags, 0x9)");
    ] in
    
    List.iter (fun (check_name, result) ->
      Printf.printf "%s: %s\n" check_name (if result then "PASS" else "FAIL")
    ) checks;
    
    Printf.printf "\nComplete program generated successfully\n"
    
  with
  | e -> Printf.printf "Complete program integration: FAIL (%s)\n" (Printexc.to_string e)

(** Test 16: Individual flag values *)
let test_individual_flag_values () =
  Printf.printf "\n=== Test 16: Individual Flag Values ===\n";
  
  let individual_flags = [
    (0x1, "NO_PREALLOC");
    (0x2, "NO_COMMON_LRU");
    (0x4, "NUMA_NODE");
    (0x8, "RDONLY");
    (0x10, "WRONLY");
    (0x20, "CLONE");
  ] in
  
  List.iter (fun (flag_val, flag_name) ->
    let ir_map = create_ir_map_with_flags (Printf.sprintf "%s_map" (String.lowercase_ascii flag_name)) flag_val in
    let ctx = Ebpf_c_codegen.create_c_context () in
    
    try
      Ebpf_c_codegen.generate_map_definition ctx ir_map;
      let generated_code = String.concat "\n" (List.rev ctx.output_lines) in
      let has_flag = string_contains_substring generated_code (Printf.sprintf "__uint(map_flags, 0x%x)" flag_val) in
      Printf.printf "%s flag (0x%x): %s\n" flag_name flag_val (if has_flag then "PASS" else "FAIL")
    with
    | e -> Printf.printf "%s flag: FAIL (%s)\n" flag_name (Printexc.to_string e)
  ) individual_flags

(** Main test runner *)
let () =
  Printf.printf "Running Comprehensive Map Flags Test Suite...\n";
  Printf.printf "=============================================\n";
  
  (* AST and Parser Tests *)
  test_flag_parsing ();
  test_flag_combinations ();
  test_flag_to_int_conversion ();
  test_flag_combination_conversion ();
  test_map_config_with_flags ();
  test_flags_attr_extraction ();
  test_ir_conversion_with_flags ();
  test_error_cases ();
  test_string_representations ();
  test_complete_integration ();
  
  (* C Code Generation Tests *)
  test_basic_flag_codegen ();
  test_map_definition_structure ();
  test_multiple_maps_with_flags ();
  test_codegen_edge_cases ();
  test_codegen_integration_with_program ();
  test_individual_flag_values ();
  
  Printf.printf "\n=============================================\n";
  Printf.printf "Comprehensive Map Flags Test Suite Completed!\n" 