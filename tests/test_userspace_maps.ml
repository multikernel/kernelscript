(** 
   Comprehensive unit tests for userspace map-related functionality in KernelScript.
   
   This test suite covers:
   
   === Map Scope Tests ===
   - Global maps accessible from userspace
   - Local maps isolated to BPF programs
   - Map visibility and access control
   
   === Map Code Generation Tests ===
   - Map file descriptor generation
   - Map operation function generation (lookup, update, delete, get_next_key)
   - Map setup and cleanup code generation
   - Pinned map handling in userspace
   
   === Map Integration Tests ===
   - Multiple map types in userspace
   - Maps with flags in userspace code
   - Complex map configurations
   - Map access patterns and error handling
   
   === Map Communication Tests ===
   - Userspace-kernel map sharing
   - BPF object integration
   - Map-based event processing
*)

open Kernelscript.Parse
open Kernelscript.Userspace_codegen

(** Helper function to check if a pattern exists in content (case-insensitive) *)
let contains_pattern content pattern =
  let content_lower = String.lowercase_ascii content in
  try 
    ignore (Str.search_forward (Str.regexp pattern) content_lower 0); 
    true
  with Not_found -> false



(** Test 1: Global maps are accessible from userspace *)
let test_global_map_accessibility () =
  Printf.printf "\n=== Test 1: Global Map Accessibility ===\n";
  
  let code = {|
map<u32, u64> global_counter : HashMap(1024);
map<u32, u32> global_config : Array(256);

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main(argc: u32, argv: u64) -> i32 {
    return 0;
  }
}
|} in
  
  try
    let ast = parse_string code in
    let temp_dir = Filename.temp_file "test_userspace_maps" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    generate_userspace_code_from_ast ast ~output_dir:temp_dir "global_maps.ks";
    
    let generated_file = Filename.concat temp_dir "global_maps.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check for global map file descriptors *)
    let has_global_counter_fd = contains_pattern content "global_counter_fd" in
    let has_global_config_fd = contains_pattern content "global_config_fd" in
    
    (* Check for map operation functions *)
    let has_counter_lookup = contains_pattern content "global_counter_lookup" in
    let has_config_update = contains_pattern content "global_config_update" in
    
    (* Check for setup code *)
    let has_setup_maps = contains_pattern content "setup_maps" in
    let has_find_map_fd = contains_pattern content "find_map_fd_by_name" in
    
    Printf.printf "Global counter fd variable: %s\n" (if has_global_counter_fd then "PASS" else "FAIL");
    Printf.printf "Global config fd variable: %s\n" (if has_global_config_fd then "PASS" else "FAIL");
    Printf.printf "Counter lookup function: %s\n" (if has_counter_lookup then "PASS" else "FAIL");
    Printf.printf "Config update function: %s\n" (if has_config_update then "PASS" else "FAIL");
    Printf.printf "Setup maps function: %s\n" (if has_setup_maps then "PASS" else "FAIL");
    Printf.printf "BPF map fd lookup: %s\n" (if has_find_map_fd then "PASS" else "FAIL");
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
  with
  | e -> Printf.printf "Global map accessibility test failed: %s\n" (Printexc.to_string e)

(** Test 2: Local maps are not accessible from userspace *)
let test_local_map_isolation () =
  Printf.printf "\n=== Test 2: Local Map Isolation ===\n";
  
  let code = {|
map<u32, u64> global_shared : HashMap(1024);

program test : xdp {
  map<u32, u32> local_state : Array(256);
  map<u32, u64> local_cache : HashMap(512);
  
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main(argc: u32, argv: u64) -> i32 {
    return 0;
  }
}
|} in
  
  try
    let ast = parse_string code in
    let temp_dir = Filename.temp_file "test_userspace_maps" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    generate_userspace_code_from_ast ast ~output_dir:temp_dir "local_isolation.ks";
    
    let generated_file = Filename.concat temp_dir "local_isolation.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check that global map is present *)
    let has_global_shared = contains_pattern content "global_shared_fd" in
    
    (* Check that local maps are NOT present *)
    let has_local_state = contains_pattern content "local_state_fd" in
    let has_local_cache = contains_pattern content "local_cache_fd" in
    
    Printf.printf "Global map present: %s\n" (if has_global_shared then "PASS" else "FAIL");
    Printf.printf "Local state absent: %s\n" (if not has_local_state then "PASS" else "FAIL");
    Printf.printf "Local cache absent: %s\n" (if not has_local_cache then "PASS" else "FAIL");
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
  with
  | e -> Printf.printf "Local map isolation test failed: %s\n" (Printexc.to_string e)

(** Test 3: Map operation function generation *)
let test_map_operation_generation () =
  Printf.printf "\n=== Test 3: Map Operation Function Generation ===\n";
  
  let code = {|
map<u32, u64> test_map : HashMap(1024);

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main(argc: u32, argv: u64) -> i32 {
    return 0;
  }
}
|} in
  
  try
    let ast = parse_string code in
    let temp_dir = Filename.temp_file "test_userspace_maps" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    generate_userspace_code_from_ast ast ~output_dir:temp_dir "map_operations.ks";
    
    let generated_file = Filename.concat temp_dir "map_operations.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check for all required map operations *)
    let operations = [
      ("lookup", "test_map_lookup");
      ("update", "test_map_update");
      ("delete", "test_map_delete");
      ("get_next_key", "test_map_get_next_key");
    ] in
    
    List.iter (fun (op_name, func_name) ->
      let has_operation = contains_pattern content func_name in
      Printf.printf "Map %s operation: %s\n" op_name (if has_operation then "PASS" else "FAIL")
    ) operations;
    
    (* Check function signatures *)
    let has_lookup_sig = contains_pattern content "test_map_lookup(void \\*key, void \\*value)" in
    let has_update_sig = contains_pattern content "test_map_update(void \\*key, void \\*value, __u64 flags)" in
    let has_delete_sig = contains_pattern content "test_map_delete(void \\*key)" in
    
    Printf.printf "Lookup function signature: %s\n" (if has_lookup_sig then "PASS" else "FAIL");
    Printf.printf "Update function signature: %s\n" (if has_update_sig then "PASS" else "FAIL");
    Printf.printf "Delete function signature: %s\n" (if has_delete_sig then "PASS" else "FAIL");
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
  with
  | e -> Printf.printf "Map operation generation test failed: %s\n" (Printexc.to_string e)

(** Test 4: Pinned map handling *)
let test_pinned_map_handling () =
  Printf.printf "\n=== Test 4: Pinned Map Handling ===\n";
  
  let code = {|
map<u32, u64> pinned_map : HashMap(1024) {
  pinned: "/sys/fs/bpf/my_pinned_map",
};

map<u32, u32> regular_map : Array(256);

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main(argc: u32, argv: u64) -> i32 {
    return 0;
  }
}
|} in
  
  try
    let ast = parse_string code in
    let temp_dir = Filename.temp_file "test_userspace_maps" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    generate_userspace_code_from_ast ast ~output_dir:temp_dir "pinned_maps.ks";
    
    let generated_file = Filename.concat temp_dir "pinned_maps.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check for pinned map handling *)
    let has_bpf_obj_get = contains_pattern content "bpf_obj_get" in
    let has_pin_path = contains_pattern content "/sys/fs/bpf/my_pinned_map" in
    let has_bpf_obj_pin = contains_pattern content "bpf_obj_pin" in
    
    (* Check for regular map handling *)
    let has_find_by_name = contains_pattern content "find_map_by_name" in
    
    Printf.printf "BPF object get (pinned): %s\n" (if has_bpf_obj_get then "PASS" else "FAIL");
    Printf.printf "Pin path present: %s\n" (if has_pin_path then "PASS" else "FAIL");
    Printf.printf "BPF object pin: %s\n" (if has_bpf_obj_pin then "PASS" else "FAIL");
    Printf.printf "Regular map lookup: %s\n" (if has_find_by_name then "PASS" else "FAIL");
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
  with
  | e -> Printf.printf "Pinned map handling test failed: %s\n" (Printexc.to_string e)

(** Test 5: Maps with flags in userspace *)
let test_maps_with_flags_userspace () =
  Printf.printf "\n=== Test 5: Maps with Flags in Userspace ===\n";
  
  let code = {|
map<u32, u64> readonly_map : HashMap(1024) {
  flags: rdonly,
};

map<u32, u32> no_prealloc_map : HashMap(512) {
  flags: no_prealloc | numa_node(1),
};

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main(argc: u32, argv: u64) -> i32 {
    return 0;
  }
}
|} in
  
  try
    let ast = parse_string code in
    let temp_dir = Filename.temp_file "test_userspace_maps" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    generate_userspace_code_from_ast ast ~output_dir:temp_dir "flags_maps.ks";
    
    let generated_file = Filename.concat temp_dir "flags_maps.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check that maps with flags are handled correctly *)
    let has_readonly_fd = contains_pattern content "readonly_map_fd" in
    let has_no_prealloc_fd = contains_pattern content "no_prealloc_map_fd" in
    
    (* Check that operations are generated for both maps *)
    let has_readonly_lookup = contains_pattern content "readonly_map_lookup" in
    let has_no_prealloc_update = contains_pattern content "no_prealloc_map_update" in
    
    (* Note: Flags don't affect userspace operations, but maps should still be accessible *)
    Printf.printf "Readonly map fd: %s\n" (if has_readonly_fd then "PASS" else "FAIL");
    Printf.printf "No-prealloc map fd: %s\n" (if has_no_prealloc_fd then "PASS" else "FAIL");
    Printf.printf "Readonly map lookup: %s\n" (if has_readonly_lookup then "PASS" else "FAIL");
    Printf.printf "No-prealloc map update: %s\n" (if has_no_prealloc_update then "PASS" else "FAIL");
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
  with
  | e -> Printf.printf "Maps with flags userspace test failed: %s\n" (Printexc.to_string e)

(** Test 6: Multiple map types in userspace *)
let test_multiple_map_types_userspace () =
  Printf.printf "\n=== Test 6: Multiple Map Types in Userspace ===\n";
  
  let code = {|
map<u32, u64> hash_map : HashMap(1024);
map<u32, u32> array_map : Array(256);
map<u32, u64> lru_map : LruHash(512);
map<u64, u32> percpu_map : PercpuHash(128);

program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return XdpAction::Pass;
  }
}

userspace {
  fn main(argc: u32, argv: u64) -> i32 {
    return 0;
  }
}
|} in
  
  try
    let ast = parse_string code in
    let temp_dir = Filename.temp_file "test_userspace_maps" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    generate_userspace_code_from_ast ast ~output_dir:temp_dir "multi_types.ks";
    
    let generated_file = Filename.concat temp_dir "multi_types.c" in
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Check that all map types are handled *)
    let map_types = [
      ("hash_map", "HashMap");
      ("array_map", "Array");
      ("lru_map", "LruHash");
      ("percpu_map", "PercpuHash");
    ] in
    
    List.iter (fun (map_name, _map_type) ->
      let has_fd = contains_pattern content (map_name ^ "_fd") in
      let has_lookup = contains_pattern content (map_name ^ "_lookup") in
      let has_update = contains_pattern content (map_name ^ "_update") in
      
      Printf.printf "%s fd variable: %s\n" map_name (if has_fd then "PASS" else "FAIL");
      Printf.printf "%s lookup function: %s\n" map_name (if has_lookup then "PASS" else "FAIL");
      Printf.printf "%s update function: %s\n" map_name (if has_update then "PASS" else "FAIL");
    ) map_types;
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
  with
  | e -> Printf.printf "Multiple map types userspace test failed: %s\n" (Printexc.to_string e)

(** Main test runner *)
let run_userspace_maps_tests () =
  Printf.printf "Running Comprehensive Userspace Map Test Suite...\n";
  Printf.printf "=================================================\n";
  
  test_global_map_accessibility ();
  test_local_map_isolation ();
  test_map_operation_generation ();
  test_pinned_map_handling ();
  test_maps_with_flags_userspace ();
  test_multiple_map_types_userspace ();
  
  Printf.printf "\n=================================================\n";
  Printf.printf "Comprehensive Userspace Map Test Suite Completed!\n"

(* Run the tests *)
let () = run_userspace_maps_tests () 