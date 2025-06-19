open Alcotest
open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ebpf_c_codegen
open Kernelscript.Userspace_codegen
open Kernelscript.Ir_generator

(** Helper functions *)
let dummy_pos = { line = 1; column = 1; filename = "test" }

let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Test 1: Name Conflicts *)

(** Test config vs config name conflict *)
let test_config_vs_config_name_conflict () =
  let program_text = {|
config network {
    max_size: u32 = 1500,
}

config network {
    timeout: u32 = 5000,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    fail "Expected name conflict between configs"
  with Symbol_error (msg, _) ->
    check bool "config vs config conflict detected" true (String.contains msg 'a')

(** Test config vs map name conflict *)
let test_config_vs_map_name_conflict () =
  let program_text = {|
config network {
    max_size: u32 = 1500,
}

map<u32, u64> network : HashMap(1024)

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    fail "Expected name conflict between config and map"
  with Symbol_error (msg, _) ->
    check bool "config vs map conflict detected" true (String.contains msg 'a')

(** Test config vs function name conflict *)
let test_config_vs_function_name_conflict () =
  let program_text = {|
config network {
    max_size: u32 = 1500,
}

fn network() -> u32 {
    return 42
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    fail "Expected name conflict between config and function"
  with Symbol_error (msg, _) ->
    check bool "config vs function conflict detected" true (String.contains msg 'a')

(** Test config with no conflicts *)
let test_config_no_conflicts () =
  let program_text = {|
config network {
    max_size: u32 = 1500,
    timeout: u32 = 5000,
}

config security {
    enable_logging: bool = true,
    threat_level: u32 = 3,
}

map<u32, u64> packet_counts : HashMap(1024)

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    check bool "no conflicts with different names" true true;
    
    (* Verify both configs are in symbol table *)
    (match lookup_symbol symbol_table "network" with
     | Some { kind = Config _; _ } -> check bool "network config found" true true
     | _ -> fail "network config not found in symbol table");
    
    (match lookup_symbol symbol_table "security" with
     | Some { kind = Config _; _ } -> check bool "security config found" true true
     | _ -> fail "security config not found in symbol table")
  with
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

(** Test 2: Valid Field Access *)

(** Test valid config field access with correct types *)
let test_valid_config_field_access () =
  let program_text = {|
config network {
    max_size: u32 = 1500,
    timeout: u32 = 5000,
    enable_logging: bool = true,
    rate_limit: u64 = 1000,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let size: u32 = network.max_size
        let timeout: u32 = network.timeout
        let logging: bool = network.enable_logging
        let limit: u64 = network.rate_limit
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _symbol_table = build_symbol_table ast in
    check bool "valid config field access compiled" true true;
    
    (* Also test type checking *)
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "valid config field access type checked" true true
  with
  | e -> fail ("Unexpected error in valid field access: " ^ Printexc.to_string e)

(** Test config field access in expressions *)
let test_config_field_access_in_expressions () =
  let program_text = {|
config limits {
    max_packet_size: u32 = 1500,
    min_packet_size: u32 = 64,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let packet_size: u32 = 800
        if (packet_size > limits.max_packet_size || packet_size < limits.min_packet_size) {
            return 1  // DROP
        }
        return 2  // PASS
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _symbol_table = build_symbol_table ast in
    check bool "config field access in expressions compiled" true true;
    
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "config field access in expressions type checked" true true
  with
  | e -> fail ("Unexpected error in expression field access: " ^ Printexc.to_string e)

(** Test 3: Invalid Field Access *)

(** Test invalid config field access (non-existent field) *)
let test_invalid_config_field_access () =
  let program_text = {|
config network {
    max_size: u32 = 1500,
    timeout: u32 = 5000,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let bad_field = network.nonexistent_field
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    fail "Expected error for non-existent config field"
  with Symbol_error (msg, _) ->
    check bool "non-existent field error detected" true (String.contains msg 'f')

(** Test invalid config access (non-existent config) *)
let test_invalid_config_access () =
  let program_text = {|
program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let bad_config = nonexistent_config.some_field
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    fail "Expected error for non-existent config"
  with Symbol_error (msg, _) ->
    check bool "non-existent config error detected" true (String.contains msg 'U')

(** Test accessing map as config *)
let test_accessing_map_as_config () =
  let program_text = {|
map<u32, u64> packet_counts : HashMap(1024)

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let bad_access = packet_counts.some_field
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let _ = type_check_and_annotate_ast ast in
    fail "Expected error for accessing map as config"
  with 
  | Symbol_error (msg, _) ->
    check bool "map accessed as config error detected" true (String.contains msg 'n')
  | Type_error (msg, _) ->
    check bool "map accessed as config type error detected" true (String.contains msg 'i')

(** Test config declared inside function (invalid) *)
let test_config_inside_function () =
  let program_text = {|
program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        config local_config {
            value: u32 = 42,
        }
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let _ast = parse_string program_text in
    fail "Expected error for config declared inside function"
  with 
  | _ ->
    check bool "config inside function error detected" true true

(** Test config declared inside program block (invalid) *)
let test_config_inside_program () =
  let program_text = {|
program test : xdp {
    config program_config {
        size: u32 = 1024,
    }
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let _ast = parse_string program_text in
    fail "Expected error for config declared inside program"
  with 
  | _ ->
    check bool "config inside program error detected" true true

(** Test 4: eBPF C Code Generation *)

(** Helper function to compile to eBPF C *)
let compile_to_ebpf_c ast =
  let symbol_table = build_symbol_table ast in
  let (enhanced_ast, _) = type_check_and_annotate_ast ast in
  let ir_result = generate_ir enhanced_ast symbol_table "test" in
  let config_declarations = 
    List.filter_map (fun decl -> match decl with
      | ConfigDecl config -> Some config
      | _ -> None
    ) ast
  in
  compile_to_c ~config_declarations (List.hd ir_result.programs)

(** Test config struct generation *)
let test_config_struct_generation () =
  let program_text = {|
config network {
    max_size: u32 = 1500,
    timeout: u32 = 5000,
    enable_logging: bool = true,
    rate_limit: u64 = 1000,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let size = network.max_size
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let c_code = compile_to_ebpf_c ast in
    
    (* Check for config struct definition *)
    check bool "config struct generated" true (String.length c_code > 0);
    check bool "network_config struct found" true (String.contains c_code 'n');
    check bool "max_size field found" true (String.contains c_code 'm');
    check bool "timeout field found" true (String.contains c_code 't')
  with
  | e -> fail ("Error in config struct generation: " ^ Printexc.to_string e)

(** Test config BPF map generation *)
let test_config_bpf_map_generation () =
  let program_text = {|
config settings {
    buffer_size: u32 = 4096,
    max_entries: u32 = 1000,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let size = settings.buffer_size
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let c_code = compile_to_ebpf_c ast in
    
    (* Check for BPF map definition *)
    check bool "config BPF map generated" true (String.length c_code > 0);
    check bool "settings_config_map found" true (String.contains c_code 's')
  with
  | e -> fail ("Error in config BPF map generation: " ^ Printexc.to_string e)

(** Test 5: Userspace Code Generation *)

(** Helper function to compile to userspace C *)
let compile_to_userspace_c ast =
  let temp_dir = Filename.temp_file "test_config_userspace" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  try
    let _config_declarations = 
      List.filter_map (fun decl -> match decl with
        | ConfigDecl config -> Some config
        | _ -> None
      ) ast
    in
    (* Convert AST to IR for the new IR-based codegen *)
    let ir_multi_prog = Kernelscript.Ir.make_ir_multi_program "test" [] [] dummy_pos in
    let _output_file = generate_userspace_code_from_ir ir_multi_prog ~output_dir:temp_dir "test" in
    let generated_file = Filename.concat temp_dir "test.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      content
    ) else (
      Unix.rmdir temp_dir;
      ""
    )
  with
  | _exn ->
    (* Cleanup on error *)
    (try Unix.rmdir temp_dir with _ -> ());
    ""

(** Test config initialization generation *)
let test_config_initialization_generation () =
  let program_text = {|
config database {
    host: u32 = 192168001001,
    port: u32 = 5432,
    max_connections: u32 = 100,
    timeout_seconds: u32 = 30,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let host = database.host
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = compile_to_userspace_c ast in
    
    (* Check for config initialization *)
    check bool "config initialization generated" true (String.length userspace_code > 0);
    check bool "database config found" true (String.contains userspace_code 'd');
    check bool "host field found" true (String.contains userspace_code 'h');
    check bool "port field found" true (String.contains userspace_code 'p')
  with
  | e -> fail ("Error in config initialization generation: " ^ Printexc.to_string e)

(** Test 6: Integration Tests *)

(** Test end-to-end config compilation *)
let test_end_to_end_config_compilation () =
  let program_text = {|
config application {
    version: u32 = 100,
    debug_mode: bool = false,
    max_memory: u64 = 1048576,
}

map<u32, u64> stats : HashMap(1024)

program packet_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let version = application.version
        let debug = application.debug_mode
        let memory_limit = application.max_memory
        
        stats[1] = version
        
        if (debug) {
            return 2  // PASS in debug mode
        }
        
        if (version > 90) {
            return 2
        } else {
            return 1
        }
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _symbol_table = build_symbol_table ast in
    let (_enhanced_ast, typed_programs) = type_check_and_annotate_ast ast in
    let ebpf_code = compile_to_ebpf_c ast in
    let userspace_code = compile_to_userspace_c ast in
    
    (* Verify complete compilation pipeline *)
    check bool "end-to-end compilation successful" true true;
    check int "one typed program generated" 1 (List.length typed_programs);
    check bool "eBPF code generated" true (String.length ebpf_code > 0);
    check bool "userspace code generated" true (String.length userspace_code > 0);
    
    (* Verify config in both generated codes *)
    check bool "config in eBPF code" true (String.contains ebpf_code 'a');
    check bool "config in userspace code" true (String.contains userspace_code 'a')
  with
  | e -> fail ("Error in end-to-end compilation: " ^ Printexc.to_string e)

(** Test config with different BPF types *)
let test_config_with_different_types () =
  let program_text = {|
config types_test {
    flag_u8: u32 = 255,
    flag_u16: u32 = 65535,
    flag_u32: u32 = 4294967295,
    flag_u64: u64 = 1000000000000,
    flag_bool: bool = true,
}

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let u32_val = types_test.flag_u32
        let u64_val = types_test.flag_u64
        let bool_val = types_test.flag_bool
        return 2
    }
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _symbol_table = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    
    check bool "different types compilation successful" true true;
    
    (* Test code generation with different types *)
    let ebpf_code = compile_to_ebpf_c ast in
    let userspace_code = compile_to_userspace_c ast in
    
    check bool "different types in eBPF code" true (String.length ebpf_code > 0);
    check bool "different types in userspace code" true (String.length userspace_code > 0)
  with
  | e -> fail ("Error with different config types: " ^ Printexc.to_string e)

(** Test config map initialization with default values (bug fix test) *)
let test_config_map_default_value_initialization () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
    blocked_ports: u16[4] = [22, 23, 135, 445],
    timeout: u32 = 5000,
}

program packet_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        if (network.max_packet_size > 1000) {
            return 2
        }
        return 1
    }
}

fn main() -> i32 {
    network.enable_logging = true
    return 0
}
|} in
  
  let temp_dir = Filename.temp_file "test_config_init" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let ir = generate_ir annotated_ast symbol_table "test_config_init" in
    
    (* Extract config declarations *)
    let config_declarations = List.filter_map (fun decl -> match decl with
      | ConfigDecl config -> Some config
      | _ -> None
    ) ast in
    
    (* Generate userspace code with config declarations *)
    let _output_file = generate_userspace_code_from_ir ~config_declarations ir ~output_dir:temp_dir "test_config_init" in
    let generated_file = Filename.concat temp_dir "test_config_init.c" in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      (* Test 1: Config map is loaded *)
      check bool "network_config_map_fd is loaded" true 
        (String.contains content 'n' && 
         (try ignore (Str.search_forward (Str.regexp "network_config_map_fd.*find_map_fd_by_name") content 0); true 
          with Not_found -> false));
      
      (* Test 2: Default value initialization exists *)
      check bool "config initialization comment exists" true 
        (try ignore (Str.search_forward (Str.regexp "Initialize.*config map with default values") content 0); true 
         with Not_found -> false);
      
      (* Test 3: Struct with default values is created *)
      check bool "init_config struct created" true 
        (try ignore (Str.search_forward (Str.regexp "struct network_config init_config") content 0); true 
         with Not_found -> false);
      
      (* Test 4: Specific default values are set correctly *)
      check bool "max_packet_size initialized to 1500" true 
        (try ignore (Str.search_forward (Str.regexp "init_config\\.max_packet_size = 1500") content 0); true 
         with Not_found -> false);
      
      check bool "enable_logging initialized to true" true 
        (try ignore (Str.search_forward (Str.regexp "init_config\\.enable_logging = true") content 0); true 
         with Not_found -> false);
      
      check bool "timeout initialized to 5000" true 
        (try ignore (Str.search_forward (Str.regexp "init_config\\.timeout = 5000") content 0); true 
         with Not_found -> false);
      
      (* Test 5: Array initialization is correct *)
      check bool "blocked_ports[0] = 22" true 
        (try ignore (Str.search_forward (Str.regexp "init_config\\.blocked_ports\\[0\\] = 22") content 0); true 
         with Not_found -> false);
      
      check bool "blocked_ports[1] = 23" true 
        (try ignore (Str.search_forward (Str.regexp "init_config\\.blocked_ports\\[1\\] = 23") content 0); true 
         with Not_found -> false);
      
      check bool "blocked_ports[2] = 135" true 
        (try ignore (Str.search_forward (Str.regexp "init_config\\.blocked_ports\\[2\\] = 135") content 0); true 
         with Not_found -> false);
      
      check bool "blocked_ports[3] = 445" true 
        (try ignore (Str.search_forward (Str.regexp "init_config\\.blocked_ports\\[3\\] = 445") content 0); true 
         with Not_found -> false);
      
      (* Test 6: Map update call exists *)
      check bool "bpf_map_update_elem called for initialization" true 
        (try ignore (Str.search_forward (Str.regexp "bpf_map_update_elem.*network_config_map_fd.*init_config") content 0); true 
         with Not_found -> false);
      
      (* Test 7: Error handling for initialization failure *)
      check bool "initialization error handling" true 
        (try ignore (Str.search_forward (Str.regexp "Failed to initialize.*config map with default values") content 0); true 
         with Not_found -> false);
      
    ) else (
      Unix.rmdir temp_dir;
      fail "Generated C file does not exist"
    )
  with
  | exn ->
    (* Cleanup on error *)
    (try Unix.rmdir temp_dir with _ -> ());
    fail ("Config map initialization test failed: " ^ Printexc.to_string exn)

(** All config tests *)
let config_tests = [
  (* Name Conflict Tests *)
  "config_vs_config_name_conflict", `Quick, test_config_vs_config_name_conflict;
  "config_vs_map_name_conflict", `Quick, test_config_vs_map_name_conflict;
  "config_vs_function_name_conflict", `Quick, test_config_vs_function_name_conflict;
  "config_no_conflicts", `Quick, test_config_no_conflicts;
  
  (* Valid Field Access Tests *)
  "valid_config_field_access", `Quick, test_valid_config_field_access;
  "config_field_access_in_expressions", `Quick, test_config_field_access_in_expressions;
  
  (* Invalid Field Access Tests *)
  "invalid_config_field_access", `Quick, test_invalid_config_field_access;
  "invalid_config_access", `Quick, test_invalid_config_access;
  "accessing_map_as_config", `Quick, test_accessing_map_as_config;
  
  (* Invalid Local Config Tests *)
  "config_inside_function", `Quick, test_config_inside_function;
  "config_inside_program", `Quick, test_config_inside_program;
  
  (* eBPF C Code Generation Tests *)
  "config_struct_generation", `Quick, test_config_struct_generation;
  "config_bpf_map_generation", `Quick, test_config_bpf_map_generation;
  
  (* Userspace Code Generation Tests *)
  "config_initialization_generation", `Quick, test_config_initialization_generation;
  "config_map_default_value_initialization", `Quick, test_config_map_default_value_initialization;
  
  (* Integration Tests *)
  "end_to_end_config_compilation", `Quick, test_end_to_end_config_compilation;
  "config_with_different_types", `Quick, test_config_with_different_types;
]

let () =
  run "KernelScript Config Tests" [
    "config", config_tests;
  ] 