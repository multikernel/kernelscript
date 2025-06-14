open Alcotest
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator

(** Helper functions *)
let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Test 1: Top-level struct with eBPF function parameter field access *)
let test_toplevel_struct_ebpf_parameter () =
  let program_text = {|
struct GlobalConfig {
  max_packet_size: u32,
  timeout_ms: u32
}

program test : xdp {
  fn process_packet(cfg: GlobalConfig) -> u32 {
    let max_size = cfg.max_packet_size;
    let timeout = cfg.timeout_ms;
    if (max_size > 1500) {
      return 1;
    }
    return 0;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "top-level struct eBPF parameter" true true
  with
  | exn -> fail ("Top-level struct eBPF parameter test failed: " ^ Printexc.to_string exn)

(** Test 2: Local struct within eBPF program *)
let test_local_struct_ebpf_program () =
  let program_text = {|
program test : xdp {
  struct LocalConfig {
    threshold: u32,
    mode: u32
  }
  
  fn check_threshold(settings: LocalConfig) -> u32 {
    let val = settings.threshold;
    let m = settings.mode;
    if (val > 100 && m > 0) {
      return 1;
    }
    return 0;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "local struct eBPF program" true true
  with
  | exn -> fail ("Local struct eBPF program test failed: " ^ Printexc.to_string exn)

(** Test 3: Cross-scope struct access - top-level struct used in eBPF *)
let test_cross_scope_struct_access () =
  let program_text = {|
struct NetworkLimits {
  max_connections: u32,
  bandwidth_limit: u32
}

program monitor : xdp {
  fn enforce_limits(limits: NetworkLimits) -> u32 {
    let max_conn = limits.max_connections;
    let bandwidth = limits.bandwidth_limit;
    
    if (max_conn > 1000 || bandwidth > 10000) {
      return 1; // Drop
    }
    return 0; // Pass
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "monitor" in
    check bool "cross-scope struct access" true true
  with
  | exn -> fail ("Cross-scope struct access test failed: " ^ Printexc.to_string exn)

(** Test 4: Userspace struct parameter field access *)
let test_userspace_struct_parameter_field_access () =
  let program_text = {|
program test : xdp {
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

struct ServerConfig {
  max_connections: u32,
  port: u32,
  enable_debug: u32
}

fn setup_server(cfg: ServerConfig) -> i32 {
  let max_conn = cfg.max_connections;
  let port_num = cfg.port;
  if (cfg.enable_debug > 0) {
    return 1;
  }
  return 0;
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "userspace struct parameter field access" true true
  with
  | exn -> fail ("Userspace test failed: " ^ Printexc.to_string exn)

(** Test 5: Multiple struct parameters with field access *)
let test_multiple_struct_parameters () =
  let program_text = {|
struct Config1 {
  value1: u32
}

struct Config2 {
  value2: u32
}

program test : xdp {
  fn compare_configs(cfg1: Config1, cfg2: Config2) -> u32 {
    let val1 = cfg1.value1;
    let val2 = cfg2.value2;
    
    if (val1 > val2) {
      return 1;
    }
    return 0;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "multiple struct parameters" true true
  with
  | exn -> fail ("Multiple struct parameters test failed: " ^ Printexc.to_string exn)

(** Test 6: Struct field access in complex expressions *)
let test_struct_field_access_in_expressions () =
  let program_text = {|
struct PacketLimits {
  max_size: u32,
  min_size: u32,
  strict_mode: u32
}

program test : xdp {
  fn validate_packet(limits: PacketLimits) -> u32 {
    let packet_size: u32 = 800;
    
    if (packet_size > limits.max_size || packet_size < limits.min_size) {
      return 1;  // Invalid
    }
    
    let total_range = limits.max_size - limits.min_size;
    let middle_point = limits.min_size + (total_range / 2);
    
    if (packet_size > middle_point && limits.strict_mode > 0) {
      return 2;  // Warning
    }
    
    return 0;  // Valid
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "struct field access in expressions" true true
  with
  | exn -> fail ("Struct field access in expressions test failed: " ^ Printexc.to_string exn)

(** Test 7: Mixed top-level and local structs *)
let test_mixed_toplevel_local_structs () =
  let program_text = {|
struct GlobalSettings {
  global_limit: u32
}

program test : xdp {
  struct LocalSettings {
    local_limit: u32
  }
  
  fn process_settings(global: GlobalSettings, local: LocalSettings) -> u32 {
    let g_limit = global.global_limit;
    let l_limit = local.local_limit;
    return g_limit + l_limit;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "mixed top-level and local structs" true true
  with
  | exn -> fail ("Mixed structs test failed: " ^ Printexc.to_string exn)

(** Test 8: eBPF main calling helper function with struct parameter *)
let test_main_calling_helper_with_struct () =
  let program_text = {|
struct PacketInfo {
  size: u32,
  proto: u32
}

program test : xdp {
  fn should_drop(info: PacketInfo) -> u32 {
    let size = info.size;
    let proto = info.proto;
    if (size > 1500 || proto == 17) {
      return 1;
    }
    return 0;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    let packet_size = ctx.data_end - ctx.data;
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "main calling helper with struct" true true
  with
  | exn -> fail ("Main calling helper with struct test failed: " ^ Printexc.to_string exn)

(** Test 9: Error case - accessing non-existent field *)
let test_nonexistent_field_error () =
  let program_text = {|
struct SimpleConfig {
  value: u32
}

program test : xdp {
  fn helper(cfg: SimpleConfig) -> u32 {
    let value = cfg.nonexistent_field;  // Should cause error
    return value;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let _symbol_table = build_symbol_table ast in
    let (_annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    fail "Should have failed with nonexistent field error"
  with
  | Type_error (msg, _) ->
      check bool "nonexistent field error detected" true (String.contains msg 'F' || String.contains msg 'f')
  | _ -> fail "Wrong type of error detected"

(** Test 10: Error case - using undefined struct *)
let test_undefined_struct_error () =
  let program_text = {|
program test : xdp {
  fn helper(cfg: UndefinedStruct) -> u32 {
    return cfg.value;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let _symbol_table = build_symbol_table ast in
    let (_annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    fail "Should have failed with undefined struct error"
  with
  | Type_error (_, _) ->
      check bool "undefined struct error detected" true true
  | _ -> fail "Wrong type of error detected"

(** Test 11: Comprehensive test with userspace and eBPF struct usage *)
let test_comprehensive_struct_usage () =
  let program_text = {|
struct GlobalConfig {
  max_entries: u32,
  timeout: u32
}

program monitor : xdp {
  struct LocalStats {
    packet_count: u32,
    drop_count: u32
  }
  
  fn update_stats(stats: LocalStats, cfg: GlobalConfig) -> u32 {
    let packets = stats.packet_count;
    let drops = stats.drop_count;
    let max_entries = cfg.max_entries;
    
    if (packets > max_entries) {
      return drops + 1;
    }
    return drops;
  }
  
  fn main(ctx: XdpContext) -> XdpAction {
    return 2;
  }
}

struct UserConfig {
  log_level: u32,
  output_file: u32
}

fn process_user_config(user_cfg: UserConfig, global_cfg: GlobalConfig) -> i32 {
  let level = user_cfg.log_level;
  let file = user_cfg.output_file;
  let timeout = global_cfg.timeout;
  
  if (level > 0 && file > 0 && timeout > 0) {
    return 1;
  }
  return 0;
}

fn main() -> i32 {
  return 0;
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "monitor" in
    check bool "comprehensive struct usage" true true
  with
  | exn -> fail ("Comprehensive struct usage test failed: " ^ Printexc.to_string exn)

(** Test runner *)
let tests = [
  "top-level struct eBPF parameter", `Quick, test_toplevel_struct_ebpf_parameter;
  "local struct eBPF program", `Quick, test_local_struct_ebpf_program;
  "cross-scope struct access", `Quick, test_cross_scope_struct_access;
  "userspace struct parameter field access", `Quick, test_userspace_struct_parameter_field_access;
  "multiple struct parameters", `Quick, test_multiple_struct_parameters;
  "struct field access in expressions", `Quick, test_struct_field_access_in_expressions;
  "mixed top-level and local structs", `Quick, test_mixed_toplevel_local_structs;
  "main calling helper with struct", `Quick, test_main_calling_helper_with_struct;
  "nonexistent field error", `Quick, test_nonexistent_field_error;
  "undefined struct error", `Quick, test_undefined_struct_error;
  "comprehensive struct usage", `Quick, test_comprehensive_struct_usage;
]

let () = Alcotest.run "Struct Parameter Field Access Tests" [
  "struct_parameter_tests", tests;
] 