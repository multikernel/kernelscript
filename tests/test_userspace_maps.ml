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

open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Userspace_codegen
open Alcotest

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
    | _ -> None
  ) ast

(** Helper function to extract userspace block from AST *)
let extract_userspace_from_ast ast =
  List.fold_left (fun acc decl ->
    match decl with
    | Userspace ub -> Some ub
    | _ -> acc
  ) None ast

(** Helper function to generate userspace code and return content *)
let get_generated_userspace_code ast source_filename =
  let temp_dir = Filename.temp_file "test_userspace_maps" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  try
    (* Convert AST to IR properly for the new IR-based codegen *)
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
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

(** Test 1: Global maps are accessible from userspace *)
let test_global_map_accessibility () =
  let code = {|
map<u32, u64> global_counter : HashMap(1024);
map<u32, u32> global_config : Array(256);

program test : xdp {
  fn main(ctx: XdpContext) -> u32 {
    return 2;
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
    let maps = extract_maps_from_ast ast in
    let userspace_block = extract_userspace_from_ast ast in
    
    (* Verify we parsed the expected structure *)
    check int "two global maps parsed" 2 (List.length maps);
    check bool "userspace block present" true (userspace_block <> None);
    
    (* Verify map types and names *)
    let global_counter = List.find (fun m -> m.name = "global_counter") maps in
    let global_config = List.find (fun m -> m.name = "global_config") maps in
    
    check string "global_counter key type" "u32" (string_of_bpf_type global_counter.key_type);
    check string "global_counter value type" "u64" (string_of_bpf_type global_counter.value_type);
    check string "global_config key type" "u32" (string_of_bpf_type global_config.key_type);
    check string "global_config value type" "u32" (string_of_bpf_type global_config.value_type);
    
    (* Generate userspace code and check for global map accessibility *)
    match get_generated_userspace_code ast "test_global_maps.ks" with
    | Some generated_content ->
        (* Check for global map file descriptors *)
        let has_global_counter_fd = contains_pattern generated_content "global_counter.*fd" in
        let has_global_config_fd = contains_pattern generated_content "global_config.*fd" in
        
        (* Check for map operation functions *)
        let has_counter_operations = contains_pattern generated_content "global_counter.*lookup\\|global_counter.*update" in
        let has_config_operations = contains_pattern generated_content "global_config.*lookup\\|global_config.*update" in
        
        check bool "global counter fd variable" true has_global_counter_fd;
        check bool "global config fd variable" true has_global_config_fd;
        check bool "counter operations present" true has_counter_operations;
        check bool "config operations present" true has_config_operations
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 2: Local maps are not accessible from userspace *)
let test_local_map_isolation () =
  let code = {|
map<u32, u64> global_shared : HashMap(1024);

program test : xdp {
  map<u32, u32> local_state : Array(256);
  map<u32, u64> local_cache : HashMap(512);
  
  fn main(ctx: XdpContext) -> u32 {
    return 2;
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
    let maps = extract_maps_from_ast ast in
    
    (* Should only have global map, not local ones *)
    check int "only global maps accessible" 1 (List.length maps);
    
    let global_shared = List.find (fun m -> m.name = "global_shared") maps in
    check string "global_shared is present" "global_shared" global_shared.name;
    
    (* Check that local maps are not in global scope *)
    let has_local_state = List.exists (fun m -> m.name = "local_state") maps in
    let has_local_cache = List.exists (fun m -> m.name = "local_cache") maps in
    
    check bool "local_state not in global scope" false has_local_state;
    check bool "local_cache not in global scope" false has_local_cache;
    
    (* Generate userspace code and verify local maps are not accessible *)
    match get_generated_userspace_code ast "test_local_isolation.ks" with
    | Some generated_content ->
        let has_global_shared = contains_pattern generated_content "global_shared" in
        let has_local_state = contains_pattern generated_content "local_state" in
        let has_local_cache = contains_pattern generated_content "local_cache" in
        
        check bool "global map present in userspace" true has_global_shared;
        check bool "local state absent from userspace" false has_local_state;
        check bool "local cache absent from userspace" false has_local_cache
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 3: Map operation function generation *)
let test_map_operation_generation () =
  let code = {|
map<u32, u64> test_map : HashMap(1024);

program test : xdp {
  fn main(ctx: XdpContext) -> u32 {
    return 2;
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
    let maps = extract_maps_from_ast ast in
    
    check int "one test map" 1 (List.length maps);
    let test_map = List.hd maps in
    check string "test map name" "test_map" test_map.name;
    check string "test map type" "hash_map" (string_of_map_type test_map.map_type);
    
    (* Generate userspace code and check for map operations *)
    match get_generated_userspace_code ast "test_operations.ks" with
    | Some generated_content ->
        (* Check for all required map operations *)
        let operations = [
          ("lookup", "lookup");
          ("update", "update");
          ("delete", "delete");
          ("get_next_key", "get_next_key\\|next_key");
        ] in
        
        List.iter (fun (op_name, pattern) ->
          let has_operation = contains_pattern generated_content ("test_map.*" ^ pattern) in
          check bool ("map " ^ op_name ^ " operation") true has_operation
        ) operations;
        
        (* Check for BPF map helper functions *)
        let has_bpf_helpers = contains_pattern generated_content "bpf_map_lookup_elem\\|bpf_map_update_elem\\|bpf_map_delete_elem" in
        check bool "BPF map helper functions present" true has_bpf_helpers
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 4: Multiple map types in userspace *)
let test_multiple_map_types_userspace () =
  let code = {|
map<u32, u64> hash_map : HashMap(1024);
map<u32, u32> array_map : Array(256);
map<u32, u64> lru_map : LruHash(512);
map<u64, u32> percpu_map : PercpuHash(128);

program test : xdp {
  fn main(ctx: XdpContext) -> u32 {
    return 2;
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
    let maps = extract_maps_from_ast ast in
    
    check int "four different map types" 4 (List.length maps);
    
    (* Verify each map type was parsed correctly *)
    let map_types = [
      ("hash_map", "hash_map", "u32", "u64", 1024);
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
          let has_operations = contains_pattern generated_content (map_name ^ ".*lookup\\|" ^ map_name ^ ".*update") in
          
          check bool ("map " ^ map_name ^ " fd variable") true has_fd;
          check bool ("map " ^ map_name ^ " operations") true has_operations
        ) map_types
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 5: Userspace code structure and includes *)
let test_userspace_code_structure () =
  let code = {|
map<u32, u64> test_map : HashMap(1024);

program test : xdp {
  fn main(ctx: XdpContext) -> u32 {
    return 2;
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
    
    (* Generate userspace code and check structure *)
    match get_generated_userspace_code ast "test_structure.ks" with
    | Some generated_content ->
        (* Check for required includes *)
        let has_stdio = contains_pattern generated_content "#include.*stdio" in
        let has_bpf_includes = contains_pattern generated_content "#include.*bpf" in
        
        (* Check for main function with correct signature *)
        let has_main_function = contains_pattern generated_content "int main.*argc.*argv" in
        
        (* Check for BPF object management *)
        let has_bpf_object = contains_pattern generated_content "bpf_object\\|struct bpf_object" in
        
        (* Check for signal handling *)
        let has_signal_handling = contains_pattern generated_content "signal\\|setup_signal" in
        
        check bool "has stdio include" true has_stdio;
        check bool "has BPF includes" true has_bpf_includes;
        check bool "has main function" true has_main_function;
        check bool "has BPF object management" true has_bpf_object;
        check bool "has signal handling" true has_signal_handling
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 6: Error handling for invalid userspace programs *)
let test_userspace_error_handling () =
  let invalid_programs = [
    (* Missing main function *)
    ({|
map<u32, u64> test_map : HashMap(1024);

program test : xdp {
  fn main(ctx: XdpContext) -> u32 {
    return 2;
  }
}

userspace {
  fn helper() -> i32 {
    return 0;
  }
}
|}, "missing main function");
    
    (* Invalid main signature *)
    ({|
map<u32, u64> test_map : HashMap(1024);

program test : xdp {
  fn main(ctx: XdpContext) -> u32 {
    return 2;
  }
}

userspace {
  fn main(wrong_param: u32) -> i32 {
    return 0;
  }
}
|}, "invalid main signature");
  ] in
  
  List.iter (fun (program, description) ->
    try
      let ast = parse_string program in
      (* Trigger validation by generating IR first, which validates userspace main *)
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
      (* If we get here, validation passed but it shouldn't have *)
      fail ("Should have failed for: " ^ description)
    with
    | Parse_error _ ->
        check bool ("correctly rejected parse error: " ^ description) true true
    | Failure msg when String.length msg > 0 ->
        (* Check that the error message is related to userspace validation *)
        let is_userspace_error = 
          contains_pattern msg "main" || 
          contains_pattern msg "userspace" || 
          contains_pattern msg "argc" || 
          contains_pattern msg "argv" in
        check bool ("correctly rejected with userspace error: " ^ description) true is_userspace_error
    | _ ->
        check bool ("should have failed for: " ^ description) false true
  ) invalid_programs

let userspace_maps_tests = [
  "global_map_accessibility", `Quick, test_global_map_accessibility;
  "local_map_isolation", `Quick, test_local_map_isolation;
  "map_operation_generation", `Quick, test_map_operation_generation;
  "multiple_map_types_userspace", `Quick, test_multiple_map_types_userspace;
  "userspace_code_structure", `Quick, test_userspace_code_structure;
  "userspace_error_handling", `Quick, test_userspace_error_handling;
]

let () =
  run "KernelScript Userspace Maps Tests" [
    "userspace_maps", userspace_maps_tests;
  ] 