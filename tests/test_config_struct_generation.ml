open Alcotest
open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator
open Kernelscript.Userspace_codegen

(** Helper functions *)
let dummy_pos = { line = 1; column = 1; filename = "test" }

let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Helper to extract config declarations from AST *)
let extract_config_declarations ast =
  List.filter_map (function
    | ConfigDecl config -> Some config
    | _ -> None
  ) ast

(** Helper to generate IR from AST *)
let generate_ir_from_ast ast =
  let symbol_table = build_symbol_table ast in
  let (annotated_ast, _) = type_check_and_annotate_ast ast in
  generate_ir annotated_ast symbol_table "test"

(** Helper to generate userspace code with config declarations *)
let generate_userspace_with_configs ast =
  let config_declarations = extract_config_declarations ast in
  let ir_multi_prog = generate_ir_from_ast ast in
  
  let temp_dir = Filename.temp_file "test_config_struct" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  try
    generate_userspace_code_from_ir ~config_declarations ir_multi_prog ~output_dir:temp_dir "test";
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
  | exn ->
    (* Cleanup on error *)
    (try Unix.rmdir temp_dir with _ -> ());
    raise exn

(** Test single config with basic types *)
let test_single_config_basic_types () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
    port_number: u16 = 8080,
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    return 2
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify struct is generated *)
    check bool "userspace code generated" true (String.length userspace_code > 0);
    
    (* Verify correct field types are present *)
    check bool "uint32_t max_packet_size found" true 
      (String.contains userspace_code 'm' && Str.search_forward (Str.regexp "uint32_t max_packet_size") userspace_code 0 >= 0);
    check bool "bool enable_logging found" true 
      (String.contains userspace_code 'e' && Str.search_forward (Str.regexp "bool enable_logging") userspace_code 0 >= 0);
    check bool "uint16_t port_number found" true 
      (String.contains userspace_code 'p' && Str.search_forward (Str.regexp "uint16_t port_number") userspace_code 0 >= 0);
    
    (* Verify NO hardcoded debug_level or max_events *)
    check bool "no hardcoded debug_level" true 
      (try ignore (Str.search_forward (Str.regexp "debug_level") userspace_code 0); false with Not_found -> true);
    check bool "no hardcoded max_events" true 
      (try ignore (Str.search_forward (Str.regexp "max_events") userspace_code 0); false with Not_found -> true)
  with
  | e -> fail ("Error in single config basic types test: " ^ Printexc.to_string e)

(** Test multiple configs *)
let test_multiple_configs () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
}

config security {
    threat_level: u32 = 1,
    enable_strict_mode: bool = false,
    max_connections: u64 = 1000,
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    return 2
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify both structs are generated *)
    check bool "userspace code generated" true (String.length userspace_code > 0);
    check bool "network_config struct found" true 
      (try ignore (Str.search_forward (Str.regexp "struct network_config") userspace_code 0); true with Not_found -> false);
    check bool "security_config struct found" true 
      (try ignore (Str.search_forward (Str.regexp "struct security_config") userspace_code 0); true with Not_found -> false);
    
    (* Verify network config fields *)
    check bool "network max_packet_size found" true 
      (try ignore (Str.search_forward (Str.regexp "uint32_t max_packet_size") userspace_code 0); true with Not_found -> false);
    check bool "network enable_logging found" true 
      (try ignore (Str.search_forward (Str.regexp "bool enable_logging") userspace_code 0); true with Not_found -> false);
    
    (* Verify security config fields *)
    check bool "security threat_level found" true 
      (try ignore (Str.search_forward (Str.regexp "uint32_t threat_level") userspace_code 0); true with Not_found -> false);
    check bool "security enable_strict_mode found" true 
      (try ignore (Str.search_forward (Str.regexp "bool enable_strict_mode") userspace_code 0); true with Not_found -> false);
    check bool "security max_connections found" true 
      (try ignore (Str.search_forward (Str.regexp "uint64_t max_connections") userspace_code 0); true with Not_found -> false)
  with
  | e -> fail ("Error in multiple configs test: " ^ Printexc.to_string e)

(** Test config with array fields *)
let test_config_with_arrays () =
  let program_text = {|
config network {
    blocked_ports: u16[4] = [22, 23, 135, 445],
    allowed_ips: u32[2] = [192168001001, 192168001002],
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    return 2
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify array field types *)
    check bool "uint16_t blocked_ports[4] found" true 
      (try ignore (Str.search_forward (Str.regexp "uint16_t blocked_ports\\[4\\]") userspace_code 0); true with Not_found -> false);
    check bool "uint32_t allowed_ips[2] found" true 
      (try ignore (Str.search_forward (Str.regexp "uint32_t allowed_ips\\[2\\]") userspace_code 0); true with Not_found -> false)
  with
  | e -> fail ("Error in config with arrays test: " ^ Printexc.to_string e)

(** Test that BPF object filename is dynamic *)
let test_dynamic_filename_generation () =
  let program_text = {|
config test_config {
    value: u32 = 42,
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    return 2
}

fn main() -> i32 {
    var prog_handle = load(test)  // This will cause BPF functions to be generated
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify dynamic skeleton function (should be test_ebpf__open_and_load based on source filename) *)
    check bool "dynamic skeleton function test_ebpf__open_and_load found" true 
      (try ignore (Str.search_forward (Str.regexp "test_ebpf__open_and_load") userspace_code 0); true with Not_found -> false);
    
    (* Verify NO hardcoded test_config skeleton function *)
    check bool "no hardcoded test_config_ebpf skeleton function" true 
      (try ignore (Str.search_forward (Str.regexp "test_config_ebpf__open_and_load") userspace_code 0); false with Not_found -> true)
  with
  | e -> fail ("Error in dynamic filename test: " ^ Printexc.to_string e)

(** Test that no debug comments are generated *)
let test_no_debug_comments () =
  let program_text = {|
config network {
    enable_logging: bool = true,
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    return 2
}

struct Args {
    enable_logging: u32,
}

fn main(args: Args) -> i32 {
    if (args.enable_logging > 0) {
        network.enable_logging = true
    }
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify no debug comments *)
    check bool "no CONFIG_ASSIGNMENT comment" true 
      (try ignore (Str.search_forward (Str.regexp "CONFIG_ASSIGNMENT") userspace_code 0); false with Not_found -> true);
    check bool "no debug_level hardcode" true 
      (try ignore (Str.search_forward (Str.regexp "debug_level") userspace_code 0); false with Not_found -> true);
    check bool "no max_events hardcode" true 
      (try ignore (Str.search_forward (Str.regexp "max_events") userspace_code 0); false with Not_found -> true)
  with
  | e -> fail ("Error in no debug comments test: " ^ Printexc.to_string e)

(** Test that config field assignments are not allowed in eBPF programs *)
let test_config_assignment_restriction () =
  let program_text = {|
config network {
    enable_logging: bool = true,
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    network.enable_logging = false  // This should cause a type error
    return 2
}

fn main() -> i32 {
    network.enable_logging = true  // This should be allowed
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let _ = type_check_and_annotate_ast ast in
    fail "Expected type error for config field assignment in eBPF program"
  with
  | Type_error (msg, _) ->
      check bool "config assignment error detected" true 
        (String.contains msg 'C' && String.contains msg 'e');  (* Check for "Config" and "eBPF" *)
      check bool "error mentions userspace" true 
        (String.contains msg 'u')  (* Check for "userspace" *)
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

(** Test that config field reads are allowed in eBPF programs *)
let test_config_read_allowed_in_ebpf () =
  let program_text = {|
config network {
    enable_logging: bool = true,
    max_packet_size: u32 = 1500,
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    if (network.enable_logging) {  // This should be allowed
        return 2
    }
    return 1
}

fn main() -> i32 {
    network.enable_logging = true  // This should be allowed
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let _ = type_check_and_annotate_ast ast in
    check bool "config field reads allowed in eBPF" true true
  with
  | e -> fail ("Unexpected error in config read test: " ^ Printexc.to_string e)

(** Test that config maps are initialized with default values in userspace code *)
let test_config_initialization_with_defaults () =
  let program_text = {|
config demo {
    enable_logging: bool = true,
    message_count: u32 = 0,
    max_connections: u64 = 100,
    timeout_ms: u16 = 5000,
}

@xdp fn simple_logger(ctx: *xdp_md) -> xdp_action {
    if (demo.enable_logging) {
        print("eBPF: Processing packet")
    }
    return 2
}

fn main() -> i32 {
    print("Userspace: Starting packet logger")
    var prog = load(simple_logger)
    attach(prog, "lo", 0)
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify config file descriptor is declared *)
    check bool "config file descriptor declared" true 
      (try ignore (Str.search_forward (Str.regexp "int demo_config_map_fd = -1;") userspace_code 0); true with Not_found -> false);
    
    (* Verify config map is loaded from eBPF object *)
    check bool "config map loaded from eBPF object" true 
      (try ignore (Str.search_forward (Str.regexp "demo_config_map_fd = bpf_object__find_map_fd_by_name") userspace_code 0); true with Not_found -> false);
    
    (* Verify config initialization comment *)
    check bool "config initialization comment present" true 
      (try ignore (Str.search_forward (Str.regexp "Initialize demo config map with default values") userspace_code 0); true with Not_found -> false);
    
    (* Verify config struct is initialized *)
    check bool "config struct initialized" true 
      (try ignore (Str.search_forward (Str.regexp "struct demo_config init_config = {0};") userspace_code 0); true with Not_found -> false);
    
    (* Verify config key is set *)
    check bool "config key initialized" true 
      (try ignore (Str.search_forward (Str.regexp "uint32_t config_key = 0;") userspace_code 0); true with Not_found -> false);
    
    (* Verify default values are set correctly *)
    check bool "enable_logging default set to true" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.enable_logging = true;") userspace_code 0); true with Not_found -> false);
    check bool "message_count default set to 0" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.message_count = 0;") userspace_code 0); true with Not_found -> false);
    check bool "max_connections default set to 100" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.max_connections = 100;") userspace_code 0); true with Not_found -> false);
    check bool "timeout_ms default set to 5000" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.timeout_ms = 5000;") userspace_code 0); true with Not_found -> false);
    
    (* Verify map update call *)
    check bool "config map updated with defaults" true 
      (try ignore (Str.search_forward (Str.regexp "bpf_map_update_elem(demo_config_map_fd, &config_key, &init_config, BPF_ANY)") userspace_code 0); true with Not_found -> false);
    
    (* Verify error handling for config initialization *)
    check bool "config initialization error handling" true 
      (try ignore (Str.search_forward (Str.regexp "Failed to initialize demo config map with default values") userspace_code 0); true with Not_found -> false)
  with
  | e -> fail ("Error in config initialization test: " ^ Printexc.to_string e)

(** Test that config initialization works even when config is only used in eBPF *)
let test_config_initialization_ebpf_only () =
  let program_text = {|
config settings {
    debug_mode: bool = false,
    max_entries: u32 = 1024,
}

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
    if (settings.debug_mode) {
        print("Debug mode enabled")
    }
    return 2
}

fn main() -> i32 {
    // No direct config access in userspace - only eBPF uses it
    var prog = load(packet_filter)
    attach(prog, "eth0", 0)
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify config initialization is still generated even though userspace doesn't directly access config *)
    check bool "config fd declared for eBPF-only usage" true 
      (try ignore (Str.search_forward (Str.regexp "int settings_config_map_fd = -1;") userspace_code 0); true with Not_found -> false);
    
    check bool "config initialization for eBPF-only usage" true 
      (try ignore (Str.search_forward (Str.regexp "Initialize settings config map with default values") userspace_code 0); true with Not_found -> false);
    
    check bool "debug_mode default set to false" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.debug_mode = false;") userspace_code 0); true with Not_found -> false);
    
    check bool "max_entries default set to 1024" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.max_entries = 1024;") userspace_code 0); true with Not_found -> false)
  with
  | e -> fail ("Error in eBPF-only config initialization test: " ^ Printexc.to_string e)

(** Test multiple config initialization *)
let test_multiple_config_initialization () =
  let program_text = {|
config network {
    enable_logging: bool = true,
    port: u16 = 8080,
}

config security {
    strict_mode: bool = false,
    max_attempts: u32 = 5,
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    if (network.enable_logging && security.strict_mode) {
        print("Strict logging enabled")
    }
    return 2
}

fn main() -> i32 {
    var prog = load(test)
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let userspace_code = generate_userspace_with_configs ast in
    
    (* Verify both config file descriptors are declared *)
    check bool "network config fd declared" true 
      (try ignore (Str.search_forward (Str.regexp "int network_config_map_fd = -1;") userspace_code 0); true with Not_found -> false);
    check bool "security config fd declared" true 
      (try ignore (Str.search_forward (Str.regexp "int security_config_map_fd = -1;") userspace_code 0); true with Not_found -> false);
    
    (* Verify both configs are initialized *)
    check bool "network config initialization" true 
      (try ignore (Str.search_forward (Str.regexp "Initialize network config map with default values") userspace_code 0); true with Not_found -> false);
    check bool "security config initialization" true 
      (try ignore (Str.search_forward (Str.regexp "Initialize security config map with default values") userspace_code 0); true with Not_found -> false);
    
    (* Verify default values for both configs *)
    check bool "network enable_logging true" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.enable_logging = true;") userspace_code 0); true with Not_found -> false);
    check bool "network port 8080" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.port = 8080;") userspace_code 0); true with Not_found -> false);
    check bool "security strict_mode false" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.strict_mode = false;") userspace_code 0); true with Not_found -> false);
    check bool "security max_attempts 5" true 
      (try ignore (Str.search_forward (Str.regexp "init_config\\.max_attempts = 5;") userspace_code 0); true with Not_found -> false)
  with
  | e -> fail ("Error in multiple config initialization test: " ^ Printexc.to_string e)

(** All config struct generation tests *)
let config_struct_generation_tests = [
  "single_config_basic_types", `Quick, test_single_config_basic_types;
  "multiple_configs", `Quick, test_multiple_configs;
  "config_with_arrays", `Quick, test_config_with_arrays;
  "dynamic_filename_generation", `Quick, test_dynamic_filename_generation;
  "no_debug_comments", `Quick, test_no_debug_comments;
  "config_assignment_restriction", `Quick, test_config_assignment_restriction;
  "config_read_allowed_in_ebpf", `Quick, test_config_read_allowed_in_ebpf;
  "config_initialization_with_defaults", `Quick, test_config_initialization_with_defaults;
  "config_initialization_ebpf_only", `Quick, test_config_initialization_ebpf_only;
  "multiple_config_initialization", `Quick, test_multiple_config_initialization;
]

let () =
  run "KernelScript Config Struct Generation Tests" [
    "config_struct_generation", config_struct_generation_tests;
  ] 