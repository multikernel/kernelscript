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

(** Test basic @kfunc attribute parsing *)
let test_kfunc_parsing () =
  let program = {|
    @kfunc
    fn custom_check(data: *u8, len: u32) -> i32 {
        return 0
    }
    
    @xdp
    fn test_program(ctx: *xdp_md) -> xdp_action {
        var result = custom_check(null, 100)
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Check that we have the expected declarations *)
  check int "Number of declarations" 3 (List.length ast);
  
  (* Check that the first declaration is an attributed function with @kfunc *)
  (match List.hd ast with
   | AttributedFunction attr_func ->
       check string "Function name" "custom_check" attr_func.attr_function.func_name;
       (match attr_func.attr_list with
        | [SimpleAttribute attr_name] ->
            check string "Attribute name" "kfunc" attr_name
        | _ -> fail "Expected single kfunc attribute")
   | _ -> fail "Expected AttributedFunction")

(** Test @kfunc type checking *)
let test_kfunc_type_checking () =
  let program = {|
    @kfunc
    fn packet_validator(data: *u8, size: u32) -> bool {
        return size > 64
    }
    
    @xdp 
    fn filter(ctx: *xdp_md) -> xdp_action {
        var valid = packet_validator(null, 1000)
        if (valid) {
            return 2
        }
        return 1
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  let _symbol_table = Symbol_table.build_symbol_table ast in
  
  (* Type check should succeed *)
  let typed_ast = Type_checker.type_check_ast ast in
  
  (* Verify the kfunc function is typed correctly *)
  check int "Typed AST length" (List.length ast) (List.length typed_ast)

(** Test kernel module generation *)
let test_kernel_module_generation () =
  let program = {|
    @kfunc
    fn advanced_filter(data: *u8, len: u32) -> i32 {
        if (len < 64) {
            return -1
        }
        return 0
    }
    
    @xdp
    fn test_xdp(ctx: *xdp_md) -> xdp_action {
        var result = advanced_filter(null, 100)
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Test kernel module generation *)
  let kernel_module_code = Kernel_module_codegen.generate_kernel_module_from_ast "test" ast in
  
     (match kernel_module_code with
    | Some code ->
        check bool "Module contains function implementation" true 
          (try ignore (Str.search_forward (Str.regexp "advanced_filter") code 0); true with Not_found -> false);
        check bool "Module contains BTF registration" true
          (try ignore (Str.search_forward (Str.regexp "BTF_ID") code 0); true with Not_found -> false);
        check bool "Module contains init function" true
          (try ignore (Str.search_forward (Str.regexp "module_init") code 0); true with Not_found -> false)
    | None -> fail "Expected kernel module code to be generated")

(** Test eBPF C code generation with kfunc declarations *)
let test_ebpf_kfunc_declarations () =
  let program = {|
    @kfunc
    fn security_check(addr: u64) -> bool {
        return addr != 0
    }
    
    @xdp
    fn security_filter(ctx: *xdp_md) -> xdp_action {
        var addr: u64 = 12345
        var safe = security_check(addr)
        if (!safe) {
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
  (* Use the full multi-program type checker for proper expression typing *)
  let (typed_ast, _) = Type_checker.type_check_and_annotate_ast ast in
  let ir = Ir_generator.generate_ir typed_ast symbol_table "test" in

  (* @kfunc declarations are lowered into the IR; codegen needs no side-channel *)
  let (generated_code, _) = Ebpf_c_codegen.compile_multi_to_c_with_analysis ir in

  let contains substr =
    try ignore (Str.search_forward (Str.regexp_string substr) generated_code 0); true
    with Not_found -> false
  in
  (* Local @kfuncs are external to the eBPF object - they live in the sibling
     kernel module - so they must be declared with __ksym, like vmlinux kfuncs.
     Without __ksym, bpftool gen skeleton fails with "failed to find BTF for
     extern" because libbpf looks for the symbol's BTF inside the .o file. *)
  check bool "Local @kfunc declared as __ksym extern" true
    (contains "extern bool security_check(__u64 addr) __ksym;");
  check bool "Contains kfunc call" true (contains "security_check(")

(** Test kernel module print function translation *)
let test_kernel_print_translation () =
  let program_text = {|
@kfunc
fn my_kfunc() -> u32 {
    print("Hello from kernel module")
    print("Value: ", 42)
    return 0
}
|} in
  try
    let ast = Parse.parse_string program_text in
    match Kernel_module_codegen.generate_kernel_module_from_ast "test_module" ast with
    | Some module_code ->
        (* Check that printk is used instead of print *)
        let contains_printk = try Str.search_forward (Str.regexp "printk") module_code 0 >= 0 with Not_found -> false in
        let contains_kern_info = try Str.search_forward (Str.regexp "KERN_INFO") module_code 0 >= 0 with Not_found -> false in
        let contains_raw_print = try Str.search_forward (Str.regexp "print(") module_code 0 >= 0 with Not_found -> false in
        check bool "Contains printk call" true contains_printk;
        check bool "Contains KERN_INFO prefix" true contains_kern_info;
        check bool "Doesn't contain raw print" true (not contains_raw_print)
    | None ->
        fail "Should generate kernel module code"
  with
  | e -> fail ("Failed to generate kernel module: " ^ Printexc.to_string e)

(** Test kernel module print with no arguments *)
let test_kernel_print_no_args () =
  let program_text = {|
@kfunc
fn test_empty_print() -> u32 {
    print()
    return 0
}
|} in
  try
    let ast = Parse.parse_string program_text in
    match Kernel_module_codegen.generate_kernel_module_from_ast "test_module" ast with
    | Some module_code ->
        (* Check for empty printk call with KERN_INFO *)
        let contains_empty_printk = try Str.search_forward (Str.regexp "printk") module_code 0 >= 0 with Not_found -> false in
        let contains_kern_info_empty = try Str.search_forward (Str.regexp "KERN_INFO") module_code 0 >= 0 with Not_found -> false in
        check bool "Contains empty printk" true contains_empty_printk;
        check bool "Contains KERN_INFO for empty call" true contains_kern_info_empty
    | None ->
        fail "Should generate kernel module code"
  with
  | e -> fail ("Failed to generate kernel module: " ^ Printexc.to_string e)

(** Test regular function calls are not affected *)
let test_regular_function_calls_printk () =
  let program_text = {|
@kfunc
fn helper_func() -> u32 {
    return 1
}

@kfunc  
fn main_kfunc() -> u32 {
    var result = helper_func()
    return result
}
|} in
  try
    let ast = Parse.parse_string program_text in
    match Kernel_module_codegen.generate_kernel_module_from_ast "test_module" ast with
    | Some module_code ->
        (* Check that regular function calls are preserved *)
        let contains_helper_func = try Str.search_forward (Str.regexp "helper_func(") module_code 0 >= 0 with Not_found -> false in
        let contains_printk_calls = try Str.search_forward (Str.regexp "printk") module_code 0 >= 0 with Not_found -> false in
        check bool "Contains helper_func call" true contains_helper_func;
        (* But no printk calls should be present *)
        check bool "No printk calls" true (not contains_printk_calls)
    | None ->
        fail "Should generate kernel module code"
  with
  | e -> fail ("Failed to generate kernel module: " ^ Printexc.to_string e)

let tests = [
  "kfunc parsing", `Quick, test_kfunc_parsing;
  "kfunc type checking", `Quick, test_kfunc_type_checking;
  "kernel module generation", `Quick, test_kernel_module_generation;
  "eBPF kfunc declarations", `Quick, test_ebpf_kfunc_declarations;
  "kernel print translation", `Quick, test_kernel_print_translation;
  "kernel print no args", `Quick, test_kernel_print_no_args;
  "regular function calls printk", `Quick, test_regular_function_calls_printk;
]

let () = Alcotest.run "KernelScript @kfunc attribute tests" [
  "kfunc_tests", tests
]