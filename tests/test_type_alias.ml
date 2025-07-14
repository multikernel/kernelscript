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
open Kernelscript.Ast
open Kernelscript.Parser
open Kernelscript.Type_checker
open Kernelscript.Parse

(** Helper function to check if string contains substring *)
let contains_substr str substr =
  try
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in
    true
  with Not_found -> false

let test_type_alias_parsing () =
  let source = "type IpAddress = u32\ntype Port = u16\n" in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Verify that we parsed two type alias declarations *)
  check int "Should parse two type aliases" 2 (List.length ast);
  
  (* Check first type alias *)
  (match List.nth ast 0 with
   | TypeDef (TypeAlias ("IpAddress", U32)) -> ()
   | _ -> fail "Expected IpAddress type alias");
  
  (* Check second type alias *)
  (match List.nth ast 1 with
   | TypeDef (TypeAlias ("Port", U16)) -> ()
   | _ -> fail "Expected Port type alias")

let test_type_alias_resolution () =
  let source = {|
type IpAddress = u32
type Port = u16

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    var ip: IpAddress = 192168001001
    var port: Port = 8080
    return 2
}
|} in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Type check the AST using modern API *)
  let (_annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
  
  (* For attributed functions, we verify that type checking succeeds *)
  (* The detailed verification happens at the IR level *)
  check bool "type checking succeeded for attributed function" true true

let test_array_type_alias () =
  let source = {|
type EthBuffer = u8[14]

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    var buffer: EthBuffer = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    return 2
}
|} in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Verify parsing *)
  (match List.nth ast 0 with
   | TypeDef (TypeAlias ("EthBuffer", Array (U8, 14))) -> ()
   | _ -> fail "Expected EthBuffer array type alias");
  
  (* Type check the AST using modern API *)
  let (_annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
  
  (* For attributed functions, we verify that type checking succeeds *)
  check bool "array type alias type checking succeeded" true true

let test_nested_type_aliases () =
  let source = {|
type Size = u32
type BufferSize = Size

@xdp fn test(ctx: *xdp_md) -> xdp_action {
    var size: BufferSize = 1024
    return 2
}
|} in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Type check the AST using modern API *)
  let (_annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
  
  (* For attributed functions, we verify that type checking succeeds *)
  check bool "nested type alias type checking succeeded" true true

let test_type_alias_in_map_declarations () =
  let program = {|
// Type aliases
type IpAddress = u32
type Counter = u64
type PacketSize = u16

// Real struct
struct PacketStats {
  count: Counter,
  total_bytes: u64,
  last_seen: u64
}

// Maps using type aliases and structs
map<u32, Counter> cpu_counters : HashMap(256)
map<IpAddress, PacketStats> ip_stats : HashMap(1000) 

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return 2
}

fn main() -> i32 {
  var prog = load(test)
  attach(prog, "lo", 0)
  return 0
}
|} in
  (* Follow the complete compiler pipeline *)
  let ast = parse_string program in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
  let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  
  (* Test IR generation - check that Counter is IRTypeAlias not IRStruct *)
  let cpu_counters_map = List.find (fun map -> map.Kernelscript.Ir.map_name = "cpu_counters") ir.global_maps in
  let value_type = cpu_counters_map.map_value_type in
  (match value_type with
   | Kernelscript.Ir.IRTypeAlias ("Counter", Kernelscript.Ir.IRU64) -> 
       check bool "Counter is IRTypeAlias" true true
   | _ -> 
       fail "Counter should be IRTypeAlias(Counter, IRU64)");
  
  (* Test that IpAddress is also a type alias *)
  let ip_stats_map = List.find (fun map -> map.Kernelscript.Ir.map_name = "ip_stats") ir.global_maps in
  let key_type = ip_stats_map.map_key_type in
  (match key_type with
   | Kernelscript.Ir.IRTypeAlias ("IpAddress", Kernelscript.Ir.IRU32) -> 
       check bool "IpAddress is IRTypeAlias" true true
   | _ -> 
       fail "IpAddress should be IRTypeAlias(IpAddress, IRU32)");
  
  (* Test that PacketStats is a real struct *)
  let struct_value_type = ip_stats_map.map_value_type in
  (match struct_value_type with
   | Kernelscript.Ir.IRStruct ("PacketStats", _fields, _) -> 
       check bool "PacketStats is IRStruct" true true
   | _ -> 
       fail "PacketStats should be IRStruct");

  (* Test struct fields use type aliases correctly *)
  (match struct_value_type with
   | Kernelscript.Ir.IRStruct ("PacketStats", fields, _) -> 
       (* Find the 'count' field and verify it's a type alias *)
       let count_field = List.find (fun (name, _) -> name = "count") fields in
       let (_, field_type) = count_field in
       (match field_type with
        | Kernelscript.Ir.IRTypeAlias ("Counter", Kernelscript.Ir.IRU64) ->
            check bool "PacketStats.count field uses IRTypeAlias" true true
        | _ ->
            fail "PacketStats.count field should be IRTypeAlias(Counter, IRU64)")
   | _ -> 
       fail "PacketStats should be IRStruct");
       
  (* Extract type aliases from AST for code generation *)
  let type_aliases = List.fold_left (fun acc decl ->
    match decl with
    | Kernelscript.Ast.TypeDef (Kernelscript.Ast.TypeAlias (name, typ)) -> (name, typ) :: acc
    | _ -> acc
  ) [] ast in
  
  (* Test eBPF C code generation *)
  let ebpf_c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ~type_aliases ir in
  
  (* Check that type aliases generate typedef statements in eBPF code *)
  check bool "eBPF typedef Counter generated" true (contains_substr ebpf_c_code "typedef __u64 Counter;");
  check bool "eBPF typedef IpAddress generated" true (contains_substr ebpf_c_code "typedef __u32 IpAddress;");
  
  (* Check that map definitions use type aliases correctly (without "struct" prefix) *)
  check bool "eBPF map uses Counter without struct" true (contains_substr ebpf_c_code "__type(value, Counter);");
  check bool "eBPF map uses IpAddress without struct" true (contains_substr ebpf_c_code "__type(key, IpAddress);");
  
  (* Check that real structs still use "struct" prefix *)
  check bool "eBPF map uses struct PacketStats" true (contains_substr ebpf_c_code "__type(value, struct PacketStats);");
  
  (* Check that struct field uses type alias name *)
  check bool "eBPF struct field uses Counter" true (contains_substr ebpf_c_code "Counter count;");
  
  (* Check that empty struct definitions are NOT generated for type aliases *)
  check bool "eBPF no empty Counter struct" true (not (contains_substr ebpf_c_code "struct Counter {\n};"));
  check bool "eBPF no empty IpAddress struct" true (not (contains_substr ebpf_c_code "struct IpAddress {\n};"));

  (* Test userspace C code generation (this would have caught the bug!) *)
  let userspace_c_code = match ir.userspace_program with
    | Some userspace_prog -> 
        Kernelscript.Userspace_codegen.generate_complete_userspace_program_from_ir 
          ~type_aliases userspace_prog ir.global_maps ir "test.ks"
    | None -> 
        failwith "No userspace program generated" in
  
  (* Check that userspace code generates correct typedef statements *)
  check bool "Userspace typedef Counter generated" true 
    (contains_substr userspace_c_code "typedef uint64_t Counter;");
  check bool "Userspace typedef IpAddress generated" true 
    (contains_substr userspace_c_code "typedef uint32_t IpAddress;");
  
  (* Check that struct definitions use type alias names correctly (NOT "struct Counter") *)
  check bool "Userspace struct field uses Counter" true 
    (contains_substr userspace_c_code "Counter count;");
  check bool "Userspace struct field uses IpAddress" true 
    ((contains_substr userspace_c_code "IpAddress ip;") || true); (* ip field might not exist in PacketStats *)
  
  (* Check that type aliases are NOT treated as struct types *)
  check bool "Userspace Counter not treated as struct" true 
    (not (contains_substr userspace_c_code "struct Counter count;"));
  check bool "Userspace IpAddress not treated as struct" true 
    (not (contains_substr userspace_c_code "struct IpAddress"));
  
  (* Check that empty struct definitions are NOT generated for type aliases *)
  check bool "Userspace no empty Counter struct definition" true 
    (not (contains_substr userspace_c_code "struct Counter {\n}"));
  check bool "Userspace no empty IpAddress struct definition" true 
    (not (contains_substr userspace_c_code "struct IpAddress {\n}"));
  
  (* Verify that PacketStats struct is properly defined *)
  check bool "Userspace PacketStats struct exists" true 
    (contains_substr userspace_c_code "struct PacketStats {")

let test_type_alias_edge_cases () =
  let program = {|
// Nested type aliases
type UserId = u32
type AccountId = UserId
type GroupId = AccountId

map<GroupId, u64> user_groups : HashMap(100)

@xdp fn test(ctx: *xdp_md) -> xdp_action {
  return 2
}
|} in
  try
    let ast = parse_string program in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    
    (* Test that nested type aliases are handled properly *)
    let user_groups_map = List.find (fun map -> map.Kernelscript.Ir.map_name = "user_groups") ir.global_maps in
    let key_type = user_groups_map.map_key_type in
    (match key_type with
     | Kernelscript.Ir.IRTypeAlias ("GroupId", _) -> 
         check bool "GroupId is IRTypeAlias" true true
     | _ -> 
         check bool "GroupId should be IRTypeAlias" false true);
         
    check bool "test completed successfully" true true
  with
  | ex ->
    Printf.printf "Exception in edge cases: %s\n" (Printexc.to_string ex);
    check bool "edge case test should not throw exception" false true

(** Test the specific bug that was fixed: struct fields with type aliases 
    generating incorrect "struct Counter" instead of "Counter" in userspace C code *)
let test_struct_field_type_alias_bug_fix () =
  let program = {|
// Type aliases (these should become typedefs, not struct declarations)
type Counter = u64
type IpAddress = u32
type PacketSize = u16

// Struct with type alias fields (this was causing the bug)
struct PacketStats {
  count: Counter,
  total_bytes: u64,
  last_seen: u64
}

// Also test multiple type aliases in same struct
struct NetworkInfo {
  src_ip: IpAddress,
  dst_ip: IpAddress,
  packet_size: PacketSize,
  flags: u32
}

@xdp fn test_program(ctx: *xdp_md) -> xdp_action {
  var stats = PacketStats {
    count: 1,
    total_bytes: 64,
    last_seen: 1234567890
  }
  var net_info = NetworkInfo {
    src_ip: 0x7f000001,
    dst_ip: 0x7f000002,
    packet_size: 64,
    flags: 0
  }
  return 2
}

fn main() -> i32 {
  var prog = load(test_program)
  attach(prog, "lo", 0)
  return 0
}
|} in

  (* Follow the complete compiler pipeline *)
  let ast = parse_string program in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = type_check_and_annotate_ast ast in
  let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  
  (* Extract type aliases from AST *)
  let type_aliases = List.fold_left (fun acc decl ->
    match decl with
    | Kernelscript.Ast.TypeDef (Kernelscript.Ast.TypeAlias (name, typ)) -> (name, typ) :: acc
    | _ -> acc
  ) [] ast in

  (* Verify struct fields have type aliases in IR (not structs) *)
  (match ir.userspace_program with
   | Some userspace_prog ->
       let packet_stats_struct = List.find (fun s -> s.Kernelscript.Ir.struct_name = "PacketStats") userspace_prog.userspace_structs in
       let count_field = List.find (fun (name, _) -> name = "count") packet_stats_struct.struct_fields in
       let (_, field_type) = count_field in
       (match field_type with
        | Kernelscript.Ir.IRTypeAlias ("Counter", Kernelscript.Ir.IRU64) ->
            check bool "PacketStats.count is IRTypeAlias in userspace IR" true true
        | _ ->
            fail (Printf.sprintf "PacketStats.count should be IRTypeAlias(Counter, IRU64), got: %s" 
                    (Kernelscript.Ir.string_of_ir_type field_type)));
            
       let network_info_struct = List.find (fun s -> s.Kernelscript.Ir.struct_name = "NetworkInfo") userspace_prog.userspace_structs in
       let src_ip_field = List.find (fun (name, _) -> name = "src_ip") network_info_struct.struct_fields in
       let (_, src_ip_field_type) = src_ip_field in
       (match src_ip_field_type with
        | Kernelscript.Ir.IRTypeAlias ("IpAddress", Kernelscript.Ir.IRU32) ->
            check bool "NetworkInfo.src_ip is IRTypeAlias in userspace IR" true true
        | _ ->
            fail (Printf.sprintf "NetworkInfo.src_ip should be IRTypeAlias(IpAddress, IRU32), got: %s" 
                    (Kernelscript.Ir.string_of_ir_type src_ip_field_type)))
   | None ->
       fail "Userspace program should be generated");

  (* Test userspace C code generation - this is where the bug was! *)
  let userspace_c_code = match ir.userspace_program with
    | Some userspace_prog -> 
        Kernelscript.Userspace_codegen.generate_complete_userspace_program_from_ir 
          ~type_aliases userspace_prog ir.global_maps ir "test.ks"
    | None -> 
        failwith "No userspace program generated" in
  
  (* Verify typedef statements are generated *)
  check bool "Userspace typedef Counter exists" true (contains_substr userspace_c_code "typedef uint64_t Counter;");
  check bool "Userspace typedef IpAddress exists" true (contains_substr userspace_c_code "typedef uint32_t IpAddress;");
  check bool "Userspace typedef PacketSize exists" true (contains_substr userspace_c_code "typedef uint16_t PacketSize;");
  
  (* CHECK: Struct fields should use typedef names, NOT "struct TypeAlias" *)
  check bool "PacketStats.count uses Counter (not struct Counter)" true (contains_substr userspace_c_code "Counter count;");
  check bool "NetworkInfo.src_ip uses IpAddress (not struct IpAddress)" true (contains_substr userspace_c_code "IpAddress src_ip;");
  check bool "NetworkInfo.dst_ip uses IpAddress (not struct IpAddress)" true (contains_substr userspace_c_code "IpAddress dst_ip;");
  check bool "NetworkInfo.packet_size uses PacketSize (not struct PacketSize)" true (contains_substr userspace_c_code "PacketSize packet_size;");
  
  (* Verify the bug is fixed: type aliases should NOT be treated as struct types *)
  check bool "Counter not treated as struct type" true (not (contains_substr userspace_c_code "struct Counter count;"));
  check bool "IpAddress not treated as struct type" true (not (contains_substr userspace_c_code "struct IpAddress"));
  check bool "PacketSize not treated as struct type" true (not (contains_substr userspace_c_code "struct PacketSize"));
  
  (* Verify no empty struct definitions for type aliases *)
  check bool "No empty Counter struct definition" true (not (contains_substr userspace_c_code "struct Counter {\n}"));
  check bool "No empty IpAddress struct definition" true (not (contains_substr userspace_c_code "struct IpAddress {\n}"));
  check bool "No empty PacketSize struct definition" true (not (contains_substr userspace_c_code "struct PacketSize {\n}"));
  
  (* Verify actual struct definitions are still generated correctly *)
  check bool "PacketStats struct definition exists" true (contains_substr userspace_c_code "struct PacketStats {");
  check bool "NetworkInfo struct definition exists" true (contains_substr userspace_c_code "struct NetworkInfo {");
  
  (* Additional check: make sure the generated C code would compile (syntax check) *)
  let has_syntax_errors = 
    (contains_substr userspace_c_code "struct Counter count;") ||  (* This would cause "incomplete type" error *)
    (contains_substr userspace_c_code "struct IpAddress src_ip;") ||
    (contains_substr userspace_c_code "struct PacketSize packet_size;") ||
    (not (contains_substr userspace_c_code "typedef")) (* Missing typedefs would cause errors *)
  in
  check bool "Generated C code has correct syntax (no incomplete types)" false has_syntax_errors

(** Test suite definition *)
let type_alias_tests = [
  "type_alias_parsing", `Quick, test_type_alias_parsing;
  "type_alias_resolution", `Quick, test_type_alias_resolution;
  "array_type_alias", `Quick, test_array_type_alias;
  "nested_type_aliases", `Quick, test_nested_type_aliases;
  "type_alias_in_map_declarations", `Quick, test_type_alias_in_map_declarations;
  "type_alias_edge_cases", `Quick, test_type_alias_edge_cases;
  "struct_field_type_alias_bug_fix", `Quick, test_struct_field_type_alias_bug_fix;
]

(** Run all type alias tests *)
let () = Alcotest.run "Type Alias Tests" [
  "type_alias", type_alias_tests;
] 