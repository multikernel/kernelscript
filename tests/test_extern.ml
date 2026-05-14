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
open Kernelscript
open Ast

(** Test basic extern kfunc parsing *)
let test_extern_kfunc_parsing () =
  let program = {|
    extern bpf_ktime_get_ns() -> u64
    extern bpf_trace_printk(fmt: *u8, fmt_size: u32) -> i32
    extern simple_kfunc(arg: u32)
    
    @xdp
    fn test_program(ctx: *xdp_md) -> xdp_action {
        var timestamp = bpf_ktime_get_ns()
        var result = bpf_trace_printk(null, 0)
        simple_kfunc(42)
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Check that we have the expected declarations *)
  check int "Number of declarations" 5 (List.length ast);
  
  (* Check that the first three declarations are extern kfunc declarations *)
  (match List.nth ast 0 with
   | ExternKfuncDecl extern_decl ->
       check string "Function name" "bpf_ktime_get_ns" extern_decl.extern_name;
       check int "Parameter count" 0 (List.length extern_decl.extern_params);
       (match extern_decl.extern_return_type with
        | Some U64 -> ()
        | _ -> fail "Expected u64 return type")
   | _ -> fail "Expected ExternKfuncDecl");
   
  (match List.nth ast 1 with
   | ExternKfuncDecl extern_decl ->
       check string "Function name" "bpf_trace_printk" extern_decl.extern_name;
       check int "Parameter count" 2 (List.length extern_decl.extern_params);
       let (param1_name, param1_type) = List.nth extern_decl.extern_params 0 in
       let (param2_name, param2_type) = List.nth extern_decl.extern_params 1 in
       check string "Parameter 1 name" "fmt" param1_name;
       check string "Parameter 2 name" "fmt_size" param2_name;
       (match param1_type with
        | Pointer U8 -> ()
        | _ -> fail "Expected *u8 type for fmt parameter");
       (match param2_type with
        | U32 -> ()
        | _ -> fail "Expected u32 type for fmt_size parameter");
       (match extern_decl.extern_return_type with
        | Some I32 -> ()
        | _ -> fail "Expected i32 return type")
   | _ -> fail "Expected ExternKfuncDecl");
   
  (match List.nth ast 2 with
   | ExternKfuncDecl extern_decl ->
       check string "Function name" "simple_kfunc" extern_decl.extern_name;
       check int "Parameter count" 1 (List.length extern_decl.extern_params);
       (match extern_decl.extern_return_type with
        | None -> ()
        | _ -> fail "Expected no return type (void)")
   | _ -> fail "Expected ExternKfuncDecl")

(** Test extern kfunc type checking *)
let test_extern_kfunc_type_checking () =
  let program = {|
    extern test_kfunc(value: u32) -> u64
    
    @xdp
    fn test_program(ctx: *xdp_md) -> xdp_action {
        var result = test_kfunc(42)
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type check should pass - extern kfuncs should be callable from eBPF programs *)
  let type_check_result = try
    let _symbol_table = Symbol_table.build_symbol_table ast in
    ignore (Type_checker.type_check_and_annotate_ast ast);
    true
  with
  | _ -> false
  in
  check bool "Type checking should pass" true type_check_result

(** Test extern kfunc with userspace function - should fail *)
let test_extern_kfunc_userspace_restriction () =
  let program = {|
    extern test_kfunc(value: u32) -> u64
    
    fn userspace_function() -> u64 {
        return test_kfunc(42)  // Should fail - kfuncs only callable from eBPF programs
    }
    
    fn main() -> i32 {
        var result = userspace_function()
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Type check should fail when calling kfunc from userspace *)
  let type_check_result = try
    let _symbol_table = Symbol_table.build_symbol_table ast in
    ignore (Type_checker.type_check_and_annotate_ast ast);
    false (* Should not reach here *)
  with
  | Type_checker.Type_error _ -> true (* Expected error *)
  | _ -> false (* Unexpected error *)
  in
  check bool "Type checking should fail for userspace kfunc call" true type_check_result

(** Test extern kfunc AST string representation *)
let test_extern_kfunc_string_representation () =
  let program = {|
    extern bpf_ktime_get_ns() -> u64
    extern bpf_trace_printk(fmt: *u8, fmt_size: u32) -> i32
  |} in
  
  let ast = Parse.parse_string program in
  let ast_string = string_of_ast ast in
  
  (* Check that extern declarations are properly represented *)
  let regex1 = Str.regexp "extern bpf_ktime_get_ns() -> u64;" in
  let regex2 = Str.regexp "extern bpf_trace_printk(fmt: \\*u8, fmt_size: u32) -> i32;" in
  let contains_bpf_ktime = try ignore (Str.search_forward regex1 ast_string 0); true with Not_found -> false in
  let contains_bpf_trace = try ignore (Str.search_forward regex2 ast_string 0); true with Not_found -> false in
  check bool "Contains bpf_ktime_get_ns extern" true contains_bpf_ktime;
  check bool "Contains bpf_trace_printk extern" true contains_bpf_trace

(** Test extern kfunc declarations are emitted into generated eBPF C with __ksym *)
let test_extern_kfunc_ebpf_codegen () =
  let program = {|
    extern scx_bpf_select_cpu_dfl(p: *u8, prev_cpu: i32) -> u64
    extern scx_bpf_dsq_insert(p: *u8, dsq_id: u64, slice: u64, enq_flags: u64) -> void

    @xdp
    fn test_program(ctx: *xdp_md) -> xdp_action {
        var cpu = scx_bpf_select_cpu_dfl(null, 0)
        scx_bpf_dsq_insert(null, 0, cpu, 0)
        return 2
    }

    fn main() -> i32 {
        return 0
    }
  |} in

  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ast in
  let ir = Ir_generator.generate_ir typed_ast symbol_table "test" in

  (* Extern kfunc declarations are lowered into the IR; codegen needs no side-channel *)
  let (generated_code, _) =
    Ebpf_c_codegen.compile_multi_to_c_with_analysis ir in

  let contains substr =
    try ignore (Str.search_forward (Str.regexp_string substr) generated_code 0); true
    with Not_found -> false
  in
  check bool "Contains scx_bpf_select_cpu_dfl __ksym extern" true
    (contains "extern __u64 scx_bpf_select_cpu_dfl(__u8* p, __s32 prev_cpu) __ksym;");
  check bool "Contains scx_bpf_dsq_insert __ksym extern" true
    (contains "extern void scx_bpf_dsq_insert(__u8* p, __u64 dsq_id, __u64 slice, __u64 enq_flags) __ksym;")

(** Test that extern declarations naming standard BPF helpers are NOT re-declared
    as __ksym externs (libbpf's bpf_helpers.h already declares them; a __ksym extern
    would clash with the helper pointer definition). Real kfuncs still get __ksym. *)
let test_extern_bpf_helper_not_redeclared () =
  let program = {|
    extern bpf_ktime_get_ns() -> u64
    extern my_real_kfunc(x: u64) -> i32

    @xdp
    fn test_program(ctx: *xdp_md) -> xdp_action {
        var ts = bpf_ktime_get_ns()
        var r = my_real_kfunc(ts)
        if (r > 0) {
            return 1
        }
        return 2
    }

    fn main() -> i32 {
        return 0
    }
  |} in

  let ast = Parse.parse_string program in
  let symbol_table = Symbol_table.build_symbol_table ast in
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ast in
  let ir = Ir_generator.generate_ir typed_ast symbol_table "test" in
  let (generated_code, _) = Ebpf_c_codegen.compile_multi_to_c_with_analysis ir in

  let contains substr =
    try ignore (Str.search_forward (Str.regexp_string substr) generated_code 0); true
    with Not_found -> false
  in
  check bool "BPF helper bpf_ktime_get_ns is not re-declared as __ksym extern" false
    (contains "bpf_ktime_get_ns(void) __ksym;");
  check bool "Real kfunc my_real_kfunc is declared as __ksym extern" true
    (contains "extern __s32 my_real_kfunc(__u64 x) __ksym;")

(** Test extern keyword cannot be used in function definitions *)
let test_extern_in_function_definition_fails () =
  let program = {|
    extern fn invalid_function() -> u32 {
        return 42
    }
  |} in
  
  (* This should fail to parse since extern is only for declarations, not definitions *)
  let parse_result = try
    ignore (Parse.parse_string program);
    false (* Should not reach here *)
  with
  | Parse.Parse_error _ -> true (* Expected error *)
  | _ -> false (* Unexpected error *)
  in
  check bool "Parsing should fail for extern with function body" true parse_result

(** Test extern with implementation body should fail *)
let test_extern_with_body_fails () =
  let program = {|
    extern test_function(arg: u32) -> u64 {
        var result = arg * 2
        return result
    }
  |} in
  
  (* This should fail to parse - extern functions cannot have bodies *)
  let parse_result = try
    ignore (Parse.parse_string program);
    false (* Should not reach here *)
  with
  | Parse.Parse_error _ -> true (* Expected error *)
  | _ -> false (* Unexpected error *)
  in
  check bool "Parsing should fail for extern function with body" true parse_result

(** Test extern mixed with other keywords fails *)
let test_extern_mixed_keywords_fails () =
  let program = {|
    extern @xdp fn invalid_mixed() -> xdp_action {
        return 2
    }
  |} in
  
  (* This should fail to parse - extern cannot be mixed with attributes *)
  let parse_result = try
    ignore (Parse.parse_string program);
    false (* Should not reach here *)
  with
  | Parse.Parse_error _ -> true (* Expected error *)
  | _ -> false (* Unexpected error *)
  in
  check bool "Parsing should fail for extern mixed with attributes" true parse_result

(** Test multiple extern declarations with same name and signature should fail in symbol table *)
let test_duplicate_extern_declarations () =
  let program = {|
    extern test_function(arg: u32) -> u64
    extern test_function(arg: u32) -> u64
  |} in
  
  (* Parsing should succeed but symbol table building should fail due to duplicate identical declarations *)
  let ast = Parse.parse_string program in
  let symbol_result = try
    ignore (Symbol_table.build_symbol_table ast);
    false (* Should not reach here *)
  with
  | Symbol_table.Symbol_error _ -> true (* Expected error *)
  | _ -> false (* Unexpected error *)
  in
  check bool "Symbol table should reject duplicate identical extern declarations" true symbol_result

let tests = [
  "extern kfunc parsing", `Quick, test_extern_kfunc_parsing;
  "extern kfunc type checking", `Quick, test_extern_kfunc_type_checking;
  "extern kfunc userspace restriction", `Quick, test_extern_kfunc_userspace_restriction;
  "extern kfunc string representation", `Quick, test_extern_kfunc_string_representation;
  "extern kfunc ebpf codegen", `Quick, test_extern_kfunc_ebpf_codegen;
  "extern bpf helper not redeclared", `Quick, test_extern_bpf_helper_not_redeclared;
  "extern in function definition fails", `Quick, test_extern_in_function_definition_fails;
  "extern with body fails", `Quick, test_extern_with_body_fails;
  "extern mixed keywords fails", `Quick, test_extern_mixed_keywords_fails;
  "duplicate identical extern declarations", `Quick, test_duplicate_extern_declarations;
]

let () = Alcotest.run "KernelScript extern tests" [
  "extern_tests", tests
]