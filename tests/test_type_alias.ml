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
       
  (* Extract type aliases from AST for code generation *)
  let type_aliases = List.fold_left (fun acc decl ->
    match decl with
    | Kernelscript.Ast.TypeDef (Kernelscript.Ast.TypeAlias (name, typ)) -> (name, typ) :: acc
    | _ -> acc
  ) [] ast in
  
  (* Test C code generation *)
  let c_code = Kernelscript.Ebpf_c_codegen.generate_c_multi_program ~type_aliases ir in
  
  (* Check that type aliases generate typedef statements *)
  check bool "typedef Counter generated" true (contains_substr c_code "typedef __u64 Counter;");
  check bool "typedef IpAddress generated" true (contains_substr c_code "typedef __u32 IpAddress;");
  
  (* Check that map definitions use type aliases correctly (without "struct" prefix) *)
  check bool "map uses Counter without struct" true (contains_substr c_code "__type(value, Counter);");
  check bool "map uses IpAddress without struct" true (contains_substr c_code "__type(key, IpAddress);");
  
  (* Check that real structs still use "struct" prefix *)
  check bool "map uses struct PacketStats" true (contains_substr c_code "__type(value, struct PacketStats);");
  
  (* Check that empty struct definitions are NOT generated for type aliases *)
  check bool "no empty Counter struct" true (not (contains_substr c_code "struct Counter {\n};"));
  check bool "no empty IpAddress struct" true (not (contains_substr c_code "struct IpAddress {\n};"))

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

(** Test suite definition *)
let type_alias_tests = [
  "type_alias_parsing", `Quick, test_type_alias_parsing;
  "type_alias_resolution", `Quick, test_type_alias_resolution;
  "array_type_alias", `Quick, test_array_type_alias;
  "nested_type_aliases", `Quick, test_nested_type_aliases;
  "type_alias_in_map_declarations", `Quick, test_type_alias_in_map_declarations;
  "type_alias_edge_cases", `Quick, test_type_alias_edge_cases;
]

(** Run all type alias tests *)
let () = Alcotest.run "Type Alias Tests" [
  "type_alias", type_alias_tests;
] 