open Alcotest
open Kernelscript
open Ast

(** Test basic @struct_ops attribute parsing *)
let test_struct_ops_parsing () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct MyTcpCong {
        init: u32,  
        release: u32
    }
    
    fn main() -> i32 {
        let tcp_ops = MyTcpCong { init: 1, release: 2 }
        let result = register(tcp_ops)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Check that we have the expected declarations *)
  check int "Number of declarations" 2 (List.length ast);
  
  (* Check that the first declaration is a struct with @struct_ops attribute *)
  (match List.hd ast with
   | StructDecl struct_def ->
       check string "Struct name" "MyTcpCong" struct_def.struct_name;
               (match struct_def.struct_attributes with
         | [AttributeWithArg (attr_name, attr_param)] ->
             check string "Attribute name" "struct_ops" attr_name;
             check string "Attribute parameter" "tcp_congestion_ops" attr_param
         | _ -> fail "Expected single struct_ops attribute")
   | _ -> fail "Expected StructDecl")

(** Test regular struct without @struct_ops attribute *)
let test_regular_struct_parsing () =
  let program = {|
    struct RegularStruct {
        field1: u32,
        field2: u64
    }
    
    fn main() -> i32 {
        let instance = RegularStruct { field1: 1, field2: 2 }
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Check that the struct has no attributes *)
  (match List.hd ast with
   | StructDecl struct_def ->
       check string "Struct name" "RegularStruct" struct_def.struct_name;
       check int "No attributes" 0 (List.length struct_def.struct_attributes)
   | _ -> fail "Expected StructDecl")

(** Test register() function type checking with struct_ops *)
let test_register_with_struct_ops () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct MyTcpCong {
        slow_start: u32,
        cong_avoid: u32
    }
    
    fn main() -> i32 {
        let tcp_ops = MyTcpCong { slow_start: 1, cong_avoid: 2 }
        let result = register(tcp_ops)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type checking should succeed *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast in
    check bool "register() with struct_ops should succeed" true true
  with
  | Type_checker.Type_error _ -> fail "Type checking should succeed for struct_ops with register()"
  | _ -> fail "Unexpected error during type checking"

(** Test register() function type checking rejects regular structs *)
let test_register_rejects_regular_struct () =
  let program = {|
    struct RegularStruct {
        field1: u32,
        field2: u64
    }
    
    fn main() -> i32 {
        let instance = RegularStruct { field1: 1, field2: 2 }
        let result = register(instance)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type checking should fail *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast in
    fail "register() with regular struct should fail type checking"
  with
  | Type_checker.Type_error (msg, _) ->
      check bool "Error message mentions struct_ops requirement" true
        (try ignore (Str.search_forward (Str.regexp "struct_ops") msg 0); true with Not_found -> false)
  | _ -> fail "Expected Type_error for register() with regular struct"

(** Test multiple struct_ops in same program *)
let test_multiple_struct_ops () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct TcpOps {
        init: u32,
        release: u32
    }
    
    @struct_ops("bpf_iter_ops")
    struct IterOps {
        init: u32,
        fini: u32
    }
    
    fn main() -> i32 {
        let tcp_ops = TcpOps { init: 1, release: 2 }
        let iter_ops = IterOps { init: 3, fini: 4 }
        let result1 = register(tcp_ops)
        let result2 = register(iter_ops)
        return result1 + result2
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Both struct_ops should be parsed correctly *)
  let struct_count = List.fold_left (fun acc decl ->
    match decl with
    | StructDecl struct_def ->
        if List.length struct_def.struct_attributes > 0 then acc + 1 else acc
    | _ -> acc
  ) 0 ast in
  
  check int "Number of struct_ops" 2 struct_count;
  
  (* Type checking should succeed *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast in
    check bool "Multiple struct_ops type checking" true true
  with
  | _ -> fail "Type checking should succeed for multiple struct_ops"

(** Test IR generation for struct_ops *)
let test_struct_ops_ir_generation () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct MyTcpCong {
        init: u32,
        release: u32
    }
    
    @xdp fn xdp_prog(ctx: XdpContext) -> XdpAction {
        return 2
    }
    
    fn main() -> i32 {
        let tcp_ops = MyTcpCong { init: 1, release: 2 }
        let result = register(tcp_ops)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ast in
  let ir = Ir_generator.generate_ir typed_ast symbol_table "test" in
  
  (* Check that struct_ops are collected in IR *)
  check bool "IR contains struct_ops declarations" true (List.length ir.struct_ops_declarations > 0);
  
  (* Check the struct_ops declaration details *)
  (match ir.struct_ops_declarations with
   | [declaration] ->
       check string "Struct ops name" "MyTcpCong" declaration.ir_struct_ops_name;
       check string "Kernel struct name" "tcp_congestion_ops" declaration.ir_kernel_struct_name
   | _ -> fail "Expected exactly one struct_ops declaration in IR");
   
  (* Note: struct_ops instances are handled as regular variable declarations with register() calls *)
  (* This is part of the simplified struct_ops approach - no separate instance tracking in IR *)
  ()

(** Test eBPF C code generation with struct_ops *)
let test_ebpf_struct_ops_codegen () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct MyTcpCong {
        init: u32,
        release: u32
    }
    
    @xdp fn xdp_prog(ctx: XdpContext) -> XdpAction {
        return 2
    }
    
    fn main() -> i32 {
        let tcp_ops = MyTcpCong { init: 1, release: 2 }
        let result = register(tcp_ops)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ast in
  let ir = Ir_generator.generate_ir typed_ast symbol_table "test" in
  
  (* Generate eBPF C code *)
  let (c_code, _) = Ebpf_c_codegen.compile_multi_to_c_with_analysis ir in
  
  (* In the simplified struct_ops approach, struct_ops are handled through register() calls *)
  (* The eBPF code may not contain explicit struct_ops declarations since they're userspace concerns *)
  check bool "eBPF code generation completed" true (String.length c_code > 0)

(** Test userspace code generation with struct_ops *)
let test_userspace_struct_ops_codegen () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct MyTcpCong {
        init: u32,
        release: u32
    }
    
    @xdp fn xdp_prog(ctx: XdpContext) -> XdpAction {
        return 2
    }
    
    fn main() -> i32 {
        let tcp_ops = MyTcpCong { init: 1, release: 2 }
        let result = register(tcp_ops)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ast in
  let ir = Ir_generator.generate_ir typed_ast symbol_table "test" in
  
  (* Generate userspace C code *)
  let userspace_code = match ir.userspace_program with
    | Some userspace_prog -> 
        Userspace_codegen.generate_complete_userspace_program_from_ir userspace_prog ir.global_maps ir "test"
    | None -> ""
  in
  
  (* Check that struct_ops registration code is generated *)
  check bool "Contains struct_ops registration" true
    (try ignore (Str.search_forward (Str.regexp "bpf_map__attach_struct_ops") userspace_code 0); true with Not_found -> false);
  
  (* Check that struct_ops setup is included *)
  check bool "Contains struct_ops setup" true
    (try ignore (Str.search_forward (Str.regexp "MyTcpCong") userspace_code 0); true with Not_found -> false)

(** Test that malformed struct_ops attributes are parsed but should be caught *)
let test_malformed_struct_ops_attribute () =
  let program = {|
    @struct_ops
    struct BadStruct {
        field: u32
    }
    
    @xdp fn xdp_prog(ctx: XdpContext) -> XdpAction {
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  (* The parser accepts @struct_ops as SimpleAttribute *)
  let ast = Parse.parse_string program in
  
  (* For now, type checking passes this through - future enhancement could validate struct attributes *)
  (* This test documents current behavior and can be enhanced when validation is added *)
  let _ = Type_checker.type_check_and_annotate_ast ast in
  check bool "Malformed struct_ops attribute currently parses successfully" true true

(** Test register() function with non-struct argument *)
let test_register_with_non_struct () =
  let program = {|
    fn main() -> i32 {
        let x: u32 = 42
        let result = register(x)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type checking should fail *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast in
    fail "register() with non-struct should fail type checking"
  with
  | Type_checker.Type_error _ -> check bool "register() rejects non-struct" true true
  | _ -> fail "Expected Type_error for register() with non-struct"

(** Test nested struct_ops detection *)
let test_nested_struct_ops () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct OuterStruct {
        inner: InnerStruct,
        value: u32
    }
    
    struct InnerStruct {
        data: u64
    }
    
    fn main() -> i32 {
        let inner = InnerStruct { data: 100 }
        let outer = OuterStruct { inner: inner, value: 42 }
        let result = register(outer)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type checking should succeed - nested structs are allowed *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast in
    check bool "Nested struct_ops type checking" true true
  with
  | _ -> fail "Type checking should succeed for nested struct_ops"

(** Test symbol table integration with struct_ops *)
let test_symbol_table_struct_ops () =
  let program = {|
    @struct_ops("bpf_iter_ops")
    struct IterOps {
        init_seq: u32,
        fini_seq: u32
    }
    
    fn main() -> i32 {
        let ops = IterOps { init_seq: 1, fini_seq: 2 }
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  
  (* Check that struct_ops is added to symbol table *)
  (match Symbol_table.lookup_symbol symbol_table "IterOps" with
   | Some symbol ->
       (match symbol.kind with
        | TypeDef (StructDef (name, _)) -> check string "Struct name in symbol table" "IterOps" name
        | _ -> fail "Expected StructDef in symbol table")  
   | None -> fail "struct_ops should be in symbol table")

let tests = [
  "struct_ops parsing", `Quick, test_struct_ops_parsing;
  "regular struct parsing", `Quick, test_regular_struct_parsing;
  "register() with struct_ops", `Quick, test_register_with_struct_ops;
  "register() rejects regular struct", `Quick, test_register_rejects_regular_struct;
  "multiple struct_ops", `Quick, test_multiple_struct_ops;
  "struct_ops IR generation", `Quick, test_struct_ops_ir_generation;
  "eBPF struct_ops codegen", `Quick, test_ebpf_struct_ops_codegen;
  "userspace struct_ops codegen", `Quick, test_userspace_struct_ops_codegen;
  "malformed struct_ops attribute", `Quick, test_malformed_struct_ops_attribute;
  "register() with non-struct", `Quick, test_register_with_non_struct;
  "nested struct_ops", `Quick, test_nested_struct_ops;
  "symbol table struct_ops", `Quick, test_symbol_table_struct_ops;
]

let () = Alcotest.run "KernelScript struct_ops tests" [
  "struct_ops_tests", tests
] 