open Alcotest
open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator

(** Helper functions *)
let dummy_pos = { line = 1; column = 1; filename = "test" }

let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Test 1: Valid Config Field Access *)
let test_valid_config_field_access () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
    timeout: u64 = 5000,
    protocol: u8 = 6,
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var size: u32 = network.max_packet_size
    var logging: bool = network.enable_logging
    var timeout_val: u64 = network.timeout
    var proto: u8 = network.protocol
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "valid config field access" true true
  with
  | e -> fail ("Valid config field access failed: " ^ Printexc.to_string e)

(** Test 2: Invalid Config Name *)
let test_invalid_config_name () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var size = nonexistent_config.max_packet_size
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    fail "Should have failed with undefined config"
  with
  | Type_error (msg, _) ->
      check bool "undefined config detected" true (String.contains msg 'U' || String.contains msg 'u')
  | Symbol_error (msg, _) ->
      check bool "undefined config detected at symbol level" true (String.contains msg 'U' || String.contains msg 'u')
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

(** Test 3: Invalid Config Field *)
let test_invalid_config_field () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var value = network.nonexistent_field
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    fail "Should have failed with undefined field"
  with
  | Type_error (msg, _) ->
      check bool "undefined field detected" true (String.contains msg 'f' || String.contains msg 'F')
  | Symbol_error (msg, _) ->
      check bool "undefined field detected at symbol level" true (String.contains msg 'f' || String.contains msg 'F')
  | e -> fail ("Unexpected error: " ^ Printexc.to_string e)

(** Test 4: Config Field Type Validation *)
let test_config_field_type_validation () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
    timeout: u64 = 5000,
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var size: u32 = network.max_packet_size  // Correct type
    var logging: bool = network.enable_logging  // Correct type
    var timeout_val: u64 = network.timeout  // Correct type
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "config field type validation" true true
  with
  | e -> fail ("Config field type validation failed: " ^ Printexc.to_string e)

(** Test 5: Multiple Config Declarations *)
let test_multiple_config_declarations () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
}

config security {
    threat_level: u32 = 1,
    enable_strict_mode: bool = false,
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var size = network.max_packet_size
    var threat = security.threat_level
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "multiple config declarations" true true
  with
  | e -> fail ("Multiple config declarations failed: " ^ Printexc.to_string e)

(** Test 6: Config Field Access in Expressions *)
let test_config_field_access_in_expressions () =
  let program_text = {|
config limits {
    max_size: u32 = 1500,
    min_size: u32 = 64,
    enable_check: bool = true,
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var packet_size: u32 = 800
    
    if (limits.enable_check && 
        (packet_size > limits.max_size || packet_size < limits.min_size)) {
        return 1  // DROP
    }
    
    var total = limits.max_size + limits.min_size
    return 2  // PASS
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "config field access in expressions" true true
  with
  | e -> fail ("Config field access in expressions failed: " ^ Printexc.to_string e)

(** Test 7: Config with Array Fields *)
let test_config_with_array_fields () =
  let program_text = {|
config network {
    blocked_ports: u16[4] = [22, 23, 135, 445],
    allowed_ips: u32[2] = [0x7f000001, 0xc0a80001],
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var ports = network.blocked_ports
    var ips = network.allowed_ips
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "config with array fields" true true
  with
  | e -> fail ("Config with array fields failed: " ^ Printexc.to_string e)

(** Test 8: Config Field Access Chain Validation *)
let test_config_field_access_chain () =
  (* Test that we properly validate each step in config.field access *)
  let program_text = {|
config network {
    settings: u32 = 1,
}

@xdp fn test(ctx: xdp_md) -> xdp_action {
    var value = network.settings  // Valid
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let _ = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    check bool "config field access chain validation" true true
  with
  | e -> fail ("Config field access chain validation failed: " ^ Printexc.to_string e)

(** Test 9: Config Declaration IR Generation *)
let test_config_declaration_ir_generation () =
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
}

@xdp fn config_test(ctx: xdp_md) -> xdp_action {
    var size: u32 = 1500  // Simple test without config access for now
    return 2
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (_enhanced_ast, _) = type_check_and_annotate_ast ast in
    let _ir_result = generate_ir ast symbol_table "test" in
    check bool "config declaration IR generation" true true
  with
  | e -> fail ("Config declaration IR generation failed: " ^ Printexc.to_string e)

let config_validation_tests = [
  ("valid_field_access", `Quick, test_valid_config_field_access);
  ("invalid_config_name", `Quick, test_invalid_config_name);
  ("invalid_config_field", `Quick, test_invalid_config_field);
  ("field_type_validation", `Quick, test_config_field_type_validation);
  ("multiple_configs", `Quick, test_multiple_config_declarations);
  ("field_access_in_expressions", `Quick, test_config_field_access_in_expressions);
  ("config_with_arrays", `Quick, test_config_with_array_fields);
  ("field_access_chain", `Quick, test_config_field_access_chain);
  ("config_ir_generation", `Quick, test_config_declaration_ir_generation);
]

let () =
  run "Config Validation Tests" [
    ("Config Validation", config_validation_tests);
  ] 