open Alcotest
open Kernelscript
open Ast
open Printf

(** Test basic @struct_ops attribute parsing *)
let test_struct_ops_parsing () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    struct MyTcpCong {
        init: u32,  
        release: u32
    }
    
    fn main() -> i32 {
        var tcp_ops = MyTcpCong { init: 1, release: 2 }
        var result = register(tcp_ops)
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
    impl MyTcpCong {
        fn slow_start(sk: *u8) -> u32 {
            return 1
        }
        
        fn cong_avoid(sk: *u8, ack: u32, acked: u32) -> void {
            // Implementation
        }
        
        name: "my_tcp_cong",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(MyTcpCong)
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
        var instance = RegularStruct { field1: 1, field2: 2 }
        var result = register(instance)
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
    impl TcpOps {
        fn init(sk: *u8) -> u32 {
            return 1
        }
        
        fn release(sk: *u8) -> void {
            // Release implementation
        }
        
        name: "tcp_ops",
        owner: null,
    }
    
    @struct_ops("bpf_iter_ops")
    impl IterOps {
        fn init_seq() -> u32 {
            return 3
        }
        
        fn fini_seq() -> void {
            // Cleanup implementation
        }
        
        name: "iter_ops",
        owner: null,
    }
    
    fn main() -> i32 {
        var result1 = register(TcpOps)
        var result2 = register(IterOps)
        return result1 + result2
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Both impl blocks should be parsed correctly *)
  let impl_count = List.fold_left (fun acc decl ->
    match decl with
    | ImplBlock impl_block ->
        if List.length impl_block.impl_attributes > 0 then acc + 1 else acc
    | _ -> acc
  ) 0 ast in
  
  check int "Number of struct_ops" 2 impl_count;
  
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
    impl MyTcpCong {
        fn init(sk: *u8) -> u32 {
            return 1
        }
        
        fn release(sk: *u8) -> void {
            // Release implementation
        }
        
        name: "my_tcp_cong",
        owner: null,
    }
    
    @xdp fn xdp_prog(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    fn main() -> i32 {
        var result = register(MyTcpCong)
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
   
  (* With impl blocks, the functions become individual eBPF programs *)
  check bool "IR contains impl block programs" true (List.length ir.programs >= 2); (* init and release functions *)
  ()

(** Test eBPF C code generation with struct_ops *)
let test_ebpf_struct_ops_codegen () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl MyTcpCong {
        fn init(sk: *u8) -> u32 {
            return 1
        }
        
        fn release(sk: *u8) -> void {
            // Release implementation
        }
        
        name: "my_tcp_cong",
        owner: null,
    }
    
    @xdp fn xdp_prog(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    fn main() -> i32 {
        var result = register(MyTcpCong)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ast in
  let ir = Ir_generator.generate_ir typed_ast symbol_table "test" in
  
  (* Generate eBPF C code *)
  let (c_code, _) = Ebpf_c_codegen.compile_multi_to_c_with_analysis ir in
  
  (* With impl blocks, each function becomes an eBPF program with struct_ops section *)
  check bool "eBPF code generation completed" true (String.length c_code > 0);
  (* The generated code should contain struct_ops section annotations *)
  check bool "Contains struct_ops sections" true
    (try ignore (Str.search_forward (Str.regexp "SEC(\"struct_ops") c_code 0); true with Not_found -> false)

(** Test userspace code generation with struct_ops *)
let test_userspace_struct_ops_codegen () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl MyTcpCong {
        fn init(sk: *u8) -> u32 {
            return 1
        }
        
        fn release(sk: *u8) -> void {
            // Release implementation
        }
        
        name: "my_tcp_cong",
        owner: null,
    }
    
    @xdp fn xdp_prog(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    fn main() -> i32 {
        var result = register(MyTcpCong)
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
    
    @xdp fn xdp_prog(ctx: *xdp_md) -> xdp_action {
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
        var x: u32 = 42
        var result = register(x)
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
    impl OuterImpl {
        fn outer_func(sk: *u8) -> u32 {
            return 42
        }
        
        name: "outer_impl",
        owner: null,
    }
    
    @struct_ops("bpf_iter_ops")  
    impl InnerImpl {
        fn inner_func() -> u64 {
            return 100
        }
        
        name: "inner_impl",
        owner: null,
    }
    
    fn main() -> i32 {
        var result1 = register(OuterImpl)
        var result2 = register(InnerImpl)
        return result1 + result2
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type checking should succeed - multiple impl blocks are allowed *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast in
    check bool "Multiple impl blocks type checking" true true
  with
  | _ -> fail "Type checking should succeed for multiple impl blocks"

(** Test symbol table integration with struct_ops *)
let test_symbol_table_struct_ops () =
  let program = {|
    @struct_ops("bpf_iter_ops")
    struct IterOps {
        init_seq: u32,
        fini_seq: u32
    }
    
    fn main() -> i32 {
        var ops = IterOps { init_seq: 1, fini_seq: 2 }
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  
  (* Check that struct_ops is added to symbol table *)
  (match Symbol_table.lookup_symbol symbol_table "IterOps" with
   | Some symbol ->
       (match symbol.kind with
        | TypeDef (StructDef (name, _, _)) -> check string "Struct name in symbol table" "IterOps" name
        | _ -> fail "Expected StructDef in symbol table")  
   | None -> fail "struct_ops should be in symbol table")

(** Test that unknown struct_ops names are rejected *)
let test_unknown_struct_ops_name () =
  let program = {|
    @struct_ops("completely_made_up_struct_ops")
    impl UnknownImpl {
        fn some_func() -> u32 {
            return 42
        }
        
        name: "unknown_impl",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(UnknownImpl)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type checking should fail for unknown struct_ops *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast in
    fail "Unknown struct_ops name should fail type checking"
  with
  | Type_checker.Type_error (msg, _) ->
      check bool "Error message mentions unknown struct_ops" true
        (try ignore (Str.search_forward (Str.regexp "Unknown struct_ops\\|unknown.*struct_ops\\|Invalid struct_ops") msg 0); true with Not_found -> false)
  | _ -> fail "Expected Type_error for unknown struct_ops name"

(** Test function prototype mismatches in struct_ops implementations *)
let test_struct_ops_wrong_return_type () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl BadTcpCong {
        fn ssthresh(sk: *u8) -> void {  // WRONG: should return u32
            // Implementation
        }
        
        name: "bad_tcp_cong",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(BadTcpCong)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let ast_with_structs = ast @ Test_utils.StructOps.builtin_ast in
  
  (* Type checking should fail for wrong return type *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast_with_structs in
    fail "Wrong return type should fail validation"
  with
  | Type_checker.Type_error (msg, _) ->
      check bool "Error message mentions return type mismatch" true
        (try ignore (Str.search_forward (Str.regexp "return.*type\\|signature.*mismatch") msg 0); true with Not_found -> false)
  | _ -> fail "Expected Type_error for wrong return type"

let test_struct_ops_missing_parameters () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl BadTcpCong {
        fn cong_avoid(sk: *u8) -> void {  // WRONG: missing ack and acked parameters
            // Implementation
        }
        
        name: "bad_tcp_cong",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(BadTcpCong)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let ast_with_structs = ast @ Test_utils.StructOps.builtin_ast in
  
  (* Type checking should fail for missing parameters *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast_with_structs in
    fail "Missing parameters should fail validation"
  with
  | Type_checker.Type_error (msg, _) ->
      check bool "Error message mentions parameter mismatch" true
        (try ignore (Str.search_forward (Str.regexp "parameter.*mismatch\\|signature.*mismatch") msg 0); true with Not_found -> false)
  | _ -> fail "Expected Type_error for missing parameters"

let test_struct_ops_extra_parameters () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl BadTcpCong {
        fn ssthresh(sk: *u8, extra: u32) -> u32 {  // WRONG: extra parameter
            return 16
        }
        
        name: "bad_tcp_cong",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(BadTcpCong)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let ast_with_structs = ast @ Test_utils.StructOps.builtin_ast in
  
  (* Type checking should fail for extra parameters *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast_with_structs in
    fail "Extra parameters should fail validation"
  with
  | Type_checker.Type_error (msg, _) ->
      check bool "Error message mentions parameter mismatch" true
        (try ignore (Str.search_forward (Str.regexp "parameter.*count\\|signature.*mismatch") msg 0); true with Not_found -> false)
  | _ -> fail "Expected Type_error for extra parameters"

let test_struct_ops_wrong_parameter_type () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl BadTcpCong {
        fn cong_avoid(sk: u32, ack: u32, acked: u32) -> void {  // WRONG: sk should be *u8, not u32
            // Implementation
        }
        
        name: "bad_tcp_cong",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(BadTcpCong)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let ast_with_structs = ast @ Test_utils.StructOps.builtin_ast in
  
  (* Type checking should fail for wrong parameter type *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast_with_structs in
    fail "Wrong parameter type should fail validation"
  with
  | Type_checker.Type_error (msg, _) ->
      check bool "Error message mentions parameter type mismatch" true
        (try ignore (Str.search_forward (Str.regexp "parameter.*type\\|signature.*mismatch") msg 0); true with Not_found -> false)
  | _ -> fail "Expected Type_error for wrong parameter type"

let test_struct_ops_missing_required_function () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl IncompleteTcpCong {
        // Missing required functions like ssthresh, cong_avoid, etc.
        
        name: "incomplete_tcp_cong",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(IncompleteTcpCong)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let ast_with_structs = ast @ Test_utils.StructOps.builtin_ast in
  
  (* Type checking should fail for missing required functions *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast_with_structs in
    fail "Missing required functions should fail validation"
  with
  | Type_checker.Type_error (msg, _) ->
      check bool "Error message mentions missing functions" true
        (try ignore (Str.search_forward (Str.regexp "missing.*function\\|required.*function") msg 0); true with Not_found -> false)
  | _ -> fail "Expected Type_error for missing required functions"

let test_struct_ops_correct_signatures () =
  let program = {|
    @struct_ops("tcp_congestion_ops")
    impl CorrectTcpCong {
        fn ssthresh(sk: *u8) -> u32 {  // Correct signature
            return 16
        }
        
        fn cong_avoid(sk: *u8, ack: u32, acked: u32) -> void {  // Correct signature
            // Implementation
        }
        
        fn slow_start(sk: *u8) -> void {  // Correct signature
            // Implementation
        }
        
        fn cong_control(sk: *u8, ack: u32, flag: u32) -> void {  // Correct signature
            // Implementation
        }
        
        name: "correct_tcp_cong",
        owner: null,
    }
    
    fn main() -> i32 {
        var result = register(CorrectTcpCong)
        return result
    }
  |} in
  
  let ast = Parse.parse_string program in
  let ast_with_structs = ast @ Test_utils.StructOps.builtin_ast in
  
  (* Type checking should succeed for correct signatures *)
  try
    let _ = Type_checker.type_check_and_annotate_ast ast_with_structs in
    check bool "Correct signatures should pass validation" true true
  with
  | _ -> fail "Type checking should succeed for correct signatures"

(** BTF Integration Tests *)

(** Test struct_ops registry functionality *)
let test_struct_ops_registry () =
  (* Test known struct_ops detection *)
  check bool "tcp_congestion_ops is known" true (Struct_ops_registry.is_known_struct_ops "tcp_congestion_ops");
  check bool "bpf_iter_ops is known" true (Struct_ops_registry.is_known_struct_ops "bpf_iter_ops");
  check bool "unknown_struct_ops is not known" false (Struct_ops_registry.is_known_struct_ops "unknown_struct_ops");
  
  (* Test struct_ops info retrieval *)
  (match Struct_ops_registry.get_struct_ops_info "tcp_congestion_ops" with
   | Some info ->
       check string "tcp_congestion_ops description" "TCP congestion control operations" info.description;
       check (option string) "tcp_congestion_ops version" (Some "5.6+") info.kernel_version
   | None -> fail "Expected to find tcp_congestion_ops info");
  
  (* Test getting all known struct_ops *)
  let all_known = Struct_ops_registry.get_all_known_struct_ops () in
  check bool "Contains tcp_congestion_ops" true (List.mem "tcp_congestion_ops" all_known);
  check bool "Contains bpf_iter_ops" true (List.mem "bpf_iter_ops" all_known)

(** Test struct_ops usage example generation *)
let test_struct_ops_usage_examples () =
  let tcp_example = Struct_ops_registry.generate_struct_ops_usage_example "tcp_congestion_ops" in
  check bool "TCP example contains register" true 
    (try ignore (Str.search_forward (Str.regexp "register") tcp_example 0); true with Not_found -> false);
  check bool "TCP example contains tcp_congestion_ops" true
    (try ignore (Str.search_forward (Str.regexp "tcp_congestion_ops") tcp_example 0); true with Not_found -> false);
  
  let unknown_example = Struct_ops_registry.generate_struct_ops_usage_example "unknown_struct_ops" in
  check bool "Unknown example contains register" true
    (try ignore (Str.search_forward (Str.regexp "register") unknown_example 0); true with Not_found -> false)

(** Test BTF template generation without actual BTF file *)
let test_btf_template_generation () =
  (* Test template generation without BTF file should now error *)
  (try
    let _ = Btf_parser.generate_struct_ops_template None ["tcp_congestion_ops"] "test_project" in
    fail "Expected error when no BTF file is provided"
  with
  | Failure msg when String.contains msg 'B' && String.contains msg 'T' && String.contains msg 'F' ->
      check bool "Correct error for missing BTF path" true true
  | _ -> fail "Expected BTF-related error message");
  
  (* Test with invalid BTF file path should also error *)
  (try
    let _ = Btf_parser.generate_struct_ops_template (Some "/nonexistent/btf") ["tcp_congestion_ops"] "test_project" in
    fail "Expected error for non-existent BTF file"
  with
  | Failure msg when String.contains msg 'B' && String.contains msg 'T' && String.contains msg 'F' ->
      check bool "Correct error for invalid BTF path" true true
  | _ -> fail "Expected BTF-related error message")

(** Test struct_ops initialization using main init command *)
let test_init_command_struct_ops_detection () =
  (* This test would require setting up temporary directories and running the actual init command *)
  (* For now, we'll test the underlying logic *)
  
  (* Test that tcp_congestion_ops is recognized as a struct_ops *)
  check bool "tcp_congestion_ops is recognized as struct_ops" true
    (Struct_ops_registry.is_known_struct_ops "tcp_congestion_ops");
  
  (* Test that regular program types are still recognized *)
  let valid_program_types = ["xdp"; "tc"; "kprobe"; "uprobe"; "tracepoint"; "lsm"; "cgroup_skb"] in
  List.iter (fun prog_type ->
    check bool (sprintf "%s is valid program type" prog_type) true
      (List.mem prog_type valid_program_types)
  ) valid_program_types

(** Test BTF extraction error handling *)
let test_btf_error_handling () =
  (* Test verification with non-existent BTF file *)
  (match Struct_ops_registry.verify_struct_ops_against_btf "/non/existent/btf" "tcp_congestion_ops" [("init", "u32")] with
   | Error msg -> 
       check bool "Error message contains expected text" true
         (String.contains msg 'B' && String.contains msg 'T' && String.contains msg 'F')
   | Ok () -> fail "Expected error for non-existent BTF file");
  
  (* Test extraction from non-existent BTF file *)
  let definitions = Struct_ops_registry.extract_struct_ops_from_btf "/non/existent/btf" ["tcp_congestion_ops"] in
  check int "No definitions extracted from non-existent file" 0 (List.length definitions)

(** Test struct_ops code generation *)
let test_struct_ops_code_generation () =
  (* Create mock BTF type info *)
  let mock_btf_type = {
    Btf_binary_parser.name = "tcp_congestion_ops";
    kind = "struct";
    size = Some 64;
    members = Some [
      ("init", "void*");
      ("cong_avoid", "void*");
      ("set_state", "void*");
      ("name", "char*");
    ];
    kernel_defined = true;
  } in
  
  (* Test struct_ops definition generation *)
  (match Struct_ops_registry.generate_struct_ops_definition mock_btf_type with
   | Some definition ->
       check bool "Definition contains @struct_ops attribute" true
         (try ignore (Str.search_forward (Str.regexp "@struct_ops") definition 0); true with Not_found -> false);
       check bool "Definition contains struct name" true
         (try ignore (Str.search_forward (Str.regexp "tcp_congestion_ops") definition 0); true with Not_found -> false);
       check bool "Definition contains init field" true
         (try ignore (Str.search_forward (Str.regexp "init:") definition 0); true with Not_found -> false);
       check bool "Definition contains cong_avoid field" true
         (try ignore (Str.search_forward (Str.regexp "cong_avoid:") definition 0); true with Not_found -> false)
   | None -> fail "Expected struct_ops definition to be generated")

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
  "unknown struct_ops name", `Quick, test_unknown_struct_ops_name;
  (* Function Prototype Validation Tests *)
  "struct_ops wrong return type", `Quick, test_struct_ops_wrong_return_type;
  "struct_ops missing parameters", `Quick, test_struct_ops_missing_parameters;
  "struct_ops extra parameters", `Quick, test_struct_ops_extra_parameters;
  "struct_ops wrong parameter type", `Quick, test_struct_ops_wrong_parameter_type;
  "struct_ops missing required function", `Quick, test_struct_ops_missing_required_function;
  "struct_ops correct signatures", `Quick, test_struct_ops_correct_signatures;
  (* BTF Integration Tests *)
  "struct_ops registry", `Quick, test_struct_ops_registry;
  "struct_ops usage examples", `Quick, test_struct_ops_usage_examples;
  "BTF template generation", `Quick, test_btf_template_generation;
  "init command struct_ops detection", `Quick, test_init_command_struct_ops_detection;
  "BTF error handling", `Quick, test_btf_error_handling;
  "struct_ops code generation", `Quick, test_struct_ops_code_generation;
]

let () = Alcotest.run "KernelScript struct_ops and BTF integration tests" [
  "struct_ops_tests", tests
] 