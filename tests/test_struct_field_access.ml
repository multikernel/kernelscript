(*
 * Copyright 2025 Multikernel Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

open Alcotest
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator

(* Initialize context codegens *)
let () = Kernelscript_context.Xdp_codegen.register ()

(** Helper function to check if string contains substring *)
let contains_substr str substr =
  try
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in
    true
  with Not_found -> false

(** Helper functions *)
let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Helper function to create symbol table with builtin types *)
let build_symbol_table_with_builtins ast =
  Test_utils.Helpers.create_test_symbol_table ast

(** Helper function to type check with builtin types *)
let type_check_and_annotate_ast_with_builtins ast =
  let symbol_table = build_symbol_table_with_builtins ast in
  Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast

(** Test 1: Top-level struct with eBPF function parameter field access *)
let test_toplevel_struct_ebpf_parameter () =
  let program_text = {|
struct GlobalConfig {
  max_packet_size: u32,
  timeout_ms: u32
}

@helper
fn process_packet(cfg: GlobalConfig) -> u32 {
  var max_size = cfg.max_packet_size
  var timeout = cfg.timeout_ms
  if (max_size > 1500) {
    return 1
  }
  return 0
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
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test" in
    check bool "top-level struct eBPF parameter" true true
  with
  | exn -> fail ("Top-level struct eBPF parameter test failed: " ^ Printexc.to_string exn)

(** Test 2: Local struct within eBPF program *)
let test_local_struct_ebpf_program () =
  let program_text = {|
struct LocalConfig {
  threshold: u32,
  mode: u32
}

@helper
fn check_threshold(settings: LocalConfig) -> u32 {
  var val = settings.threshold
  var m = settings.mode
  if (val > 100 && m > 0) {
    return 1
  }
  return 0
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

@helper
fn enforce_limits(limits: NetworkLimits) -> u32 {
  var max_conn = limits.max_connections
  var bandwidth = limits.bandwidth_limit
  
  if (max_conn > 1000 || bandwidth > 10000) {
    return 1 // Drop
  }
  return 0 // Pass
}

@xdp fn monitor(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  return 0
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
@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return 2
}

struct ServerConfig {
  max_connections: u32,
  port: u32,
  enable_debug: u32
}

fn setup_server(cfg: ServerConfig) -> i32 {
  var max_conn = cfg.max_connections
  var port_num = cfg.port
  if (cfg.enable_debug > 0) {
    return 1
  }
  return 0
}

fn main() -> i32 {
  return 0
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

@helper
fn compare_configs(cfg1: Config1, cfg2: Config2) -> u32 {
  var val1 = cfg1.value1
  var val2 = cfg2.value2
  
  if (val1 > val2) {
    return 1
  }
  return 0
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

@helper
fn validate_packet(limits: PacketLimits) -> u32 {
  var packet_size: u32 = 800
  
  if (packet_size > limits.max_size || packet_size < limits.min_size) {
    return 1  // Invalid
  }
    
  var total_range = limits.max_size - limits.min_size
  var middle_point = limits.min_size + (total_range / 2)
  
  if (packet_size > middle_point && limits.strict_mode > 0) {
    return 2  // Warning
  }
  
  return 0  // Valid
}

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "packet_filter" in
    check bool "struct field access in expressions" true true
  with
  | exn -> fail ("Struct field access in expressions test failed: " ^ Printexc.to_string exn)

(** Test 7: Mixed top-level and local structs *)
let test_mixed_toplevel_local_structs () =
  let program_text = {|
struct GlobalSettings {
  global_limit: u32
}

struct LocalSettings {
  local_limit: u32
}

@helper
fn process_settings(global: GlobalSettings, localSettings: LocalSettings) -> u32 {
  var g_limit = global.global_limit
  var l_limit = localSettings.local_limit
  return g_limit + l_limit
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

@helper
fn should_drop(info: PacketInfo) -> u32 {
  var size = info.size
  var proto = info.proto
  if (size > 1500 || proto == 17) {
    return 1
  }
  return 0
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
      var packet_size = ctx->data_end - ctx->data
  return 2
}

fn main() -> i32 {
  return 0
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table_with_builtins ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast_with_builtins ast in
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

@helper
fn helper(cfg: SimpleConfig) -> u32 {
  var value = cfg.nonexistent_field  // Should cause error
  return value
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
@helper
fn helper(cfg: UndefinedStruct) -> u32 {
  return cfg.value
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

struct LocalStats {
  packet_count: u32,
  drop_count: u32
}

@helper
fn update_stats(stats: LocalStats, cfg: GlobalConfig) -> u32 {
  var packets = stats.packet_count
  var drops = stats.drop_count
  var max_entries = cfg.max_entries
  
  if (packets > max_entries) {
    return drops + 1
  }
  return drops
}

@xdp fn monitor(ctx: *xdp_md) -> xdp_action {
  return 2
}

struct UserConfig {
  log_level: u32,
  output_file: u32
}

fn process_user_config(user_cfg: UserConfig, global_cfg: GlobalConfig) -> i32 {
  var level = user_cfg.log_level
  var file = user_cfg.output_file
  var timeout = global_cfg.timeout
  
  if (level > 0 && file > 0 && timeout > 0) {
    return 1
  }
  return 0
}

fn main() -> i32 {
  return 0
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

(** Test struct field assignment type checking *)
let test_struct_field_assignment_type_checking () =
  let source = {|
    struct TestStruct {
      count: u32,
      value: u64
    }
    
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      var test_data = TestStruct { count: 1, value: 100 }
      test_data.count = test_data.count + 1
      test_data.value = 200
      return 2
    }
  |} in
  
  try
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir = generate_ir annotated_ast symbol_table "test_program" in
    () (* Success - type checking passed *)
  with
  | Type_error (msg, _) -> 
      failwith ("Type checking should succeed for valid field assignment: " ^ msg)
  | e -> failwith ("Unexpected error: " ^ Printexc.to_string e)

(** Test struct field assignment IR generation *)
let test_struct_field_assignment_ir_generation () =
  let source = {|
    struct Stats {
      packets: u32,
      bytes: u64
    }
    
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
        var stats = Stats { packets: 1, bytes: 64 }
        stats.packets = stats.packets + 1
        return 2
    }
  |} in
  
  try
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir_multi_prog = generate_ir annotated_ast symbol_table "test_program" in
    
    (* If we reach here, IR generation succeeded, which means field assignment is working *)
    check bool "IR generation succeeded for field assignment" true true
  with
  | e -> failwith ("IR generation should succeed: " ^ Printexc.to_string e)

(** Test struct field assignment C code generation *)
let test_struct_field_assignment_c_generation () =
  let source = {|
    struct Stats {
      packets: u32,
      bytes: u64
    }
    
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      var stats = Stats { packets: 1, bytes: 64 }
      stats.packets = stats.packets + 1
      return 2
    }
  |} in
  
  try
    let ast = Kernelscript.Parse.parse_string source in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let _ir_multi_prog = generate_ir annotated_ast symbol_table "test_program" in
    
    (* If we reach here, C code generation would succeed, which means field assignment is working *)
    check bool "C code generation succeeded for field assignment" true true
  with
  | e -> failwith ("C code generation should succeed: " ^ Printexc.to_string e)

(** Test error cases for struct field assignment *)
let test_struct_field_assignment_errors () =
  (* Test assignment to non-existent field *)
  let source_bad_field = {|
    struct Stats {
      packets: u32
    }
    
    @xdp fn test_program(ctx: *xdp_md) -> xdp_action {
      var stats = Stats { packets: 1 }
      stats.nonexistent = 42
      return 2
    }
  |} in
  
  (try
    let ast = Kernelscript.Parse.parse_string source_bad_field in
    let _symbol_table = build_symbol_table ast in
    let (_annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    failwith "Type checking should fail for non-existent field"
  with
  | Type_error (_, _) -> () (* Expected error *)
  | e -> failwith ("Expected Type_error but got: " ^ Printexc.to_string e))

(** Test type alias field access code generation *)
let test_type_alias_field_access () =
  let program_text = {|
type Counter = u64

struct PacketStats {
  count: Counter,
  bytes: u64
}

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  var stats = PacketStats { count: 1, bytes: 100 }
  var count_val = stats.count
  return 2
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let ir = generate_ir annotated_ast symbol_table "test" in
    
    (* Test C code generation to ensure struct Counter doesn't appear *)
    let type_aliases = List.fold_left (fun acc decl ->
      match decl with
      | Kernelscript.Ast.TypeDef (Kernelscript.Ast.TypeAlias (name, typ, _)) -> (name, typ) :: acc
      | _ -> acc
    ) [] ast in
    
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ~type_aliases ir in
    
         (* Verify that type aliases generate typedef statements *)
     check bool "typedef Counter generated" true (contains_substr c_code "typedef __u64 Counter");
     
     (* Check that struct fields use the alias name correctly *)
     check bool "struct uses Counter type for count field" true (contains_substr c_code "Counter count");
     
     (* Most importantly: Check that no "struct Counter" declarations exist *)
     check bool "no struct Counter declarations" false (contains_substr c_code "struct Counter tmp_");
     
     (* Verify Counter type alias is used in variable declarations *)
     let has_counter_var = 
       contains_substr c_code "Counter var_" || 
       contains_substr c_code "Counter tmp_" ||
       contains_substr c_code "Counter cond_" ||
       contains_substr c_code "Counter val_" ||
       contains_substr c_code "Counter count_val" ||
       contains_substr c_code "Counter __field_access_" in
     check bool "Counter used in variable declarations" true has_counter_var;
    
    check bool "type alias field access test passed" true true
  with
  | exn -> fail ("Type alias field access test failed: " ^ Printexc.to_string exn)

(** Test 'type' keyword as field name - basic usage *)
let test_type_keyword_as_field_name () =
  let input = {|
    struct trace_entry {
        type: u16,
        flags: u8,
        pid: u32
    }
    
    fn test_function() -> i32 {
        var entry: trace_entry = trace_entry {
            type: 42,
            flags: 1,
            pid: 1234
        }
        
        var entry_type = entry.type
        return entry_type
    }
  |} in
  
  try
    let ast = parse_string input in
    
    (* Verify struct definition with 'type' field *)
    match ast with
    | [StructDecl struct_def; GlobalFunction func_def] ->
        (* Check struct has 'type' field *)
        let type_field_exists = List.exists (fun (field_name, _) -> 
          field_name = "type"
        ) struct_def.struct_fields in
        check bool "'type' field exists in struct" true type_field_exists;
        
        (* Verify we can access the symbol table without errors *)
        let symbol_table = create_symbol_table () in
        process_declaration symbol_table (StructDecl struct_def);
        process_declaration symbol_table (GlobalFunction func_def);
        
        check bool "'type' keyword successfully used as field name" true true
        
    | _ -> 
        fail "Expected struct declaration and function declaration"
  with
  | exn -> fail ("'type' keyword field name test failed: " ^ Printexc.to_string exn)

(** Test BTF trace_entry struct with 'type' field *)
let test_btf_trace_entry_struct () =
  let input = {|
    struct trace_entry {
        type: u16,
        flags: u8,
        preempt_count: u8,
        pid: u32
    }
  |} in
  
  try
    let ast = parse_string input in
    match ast with
    | [StructDecl struct_def] ->
        check string "struct name" "trace_entry" struct_def.struct_name;
        
        (* Verify all fields are present *)
        let field_names = List.map fst struct_def.struct_fields in
        check bool "'type' field present" true (List.mem "type" field_names);
        check bool "'flags' field present" true (List.mem "flags" field_names);
        check bool "'preempt_count' field present" true (List.mem "preempt_count" field_names);
        check bool "'pid' field present" true (List.mem "pid" field_names);
        
        check bool "BTF trace_entry struct with 'type' field parsed successfully" true true
    | _ ->
        fail "Expected single struct declaration"
  with
  | exn -> fail ("BTF trace_entry struct test failed: " ^ Printexc.to_string exn)

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
  "struct field assignment type checking", `Quick, test_struct_field_assignment_type_checking;
  "struct field assignment IR generation", `Quick, test_struct_field_assignment_ir_generation;
  "struct field assignment C generation", `Quick, test_struct_field_assignment_c_generation;
  "struct field assignment errors", `Quick, test_struct_field_assignment_errors;
  "type alias field access", `Quick, test_type_alias_field_access;
  "type keyword as field name", `Quick, test_type_keyword_as_field_name;
  "BTF trace_entry struct", `Quick, test_btf_trace_entry_struct;
]

let () = Alcotest.run "Struct Field Access and Assignment Tests" [
  "struct_field_tests", tests;
] 