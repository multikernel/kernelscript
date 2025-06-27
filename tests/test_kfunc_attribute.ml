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
    fn test_program(ctx: XdpContext) -> XdpAction {
        let result = custom_check(null, 100)
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
    fn filter(ctx: XdpContext) -> XdpAction {
        let valid = packet_validator(null, 1000)
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
    fn test_xdp(ctx: XdpContext) -> XdpAction {
        let result = advanced_filter(null, 100)
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
    fn security_filter(ctx: XdpContext) -> XdpAction {
        let addr: u64 = 12345
        let safe = security_check(addr)
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
  
  (* Extract kfunc declarations *)
  let kfunc_declarations = List.filter_map (function
    | Ast.AttributedFunction attr_func ->
        (match attr_func.attr_list with
         | SimpleAttribute "kfunc" :: _ -> Some attr_func.attr_function
         | _ -> None)
    | _ -> None
  ) typed_ast in
  
  (* Generate eBPF C code *)
  let c_code = Ebpf_c_codegen.compile_multi_to_c_with_analysis ~kfunc_declarations ir in
  let (generated_code, _) = c_code in
  
  (* Check that kfunc declarations are generated *)
  check bool "Contains kfunc declaration" true
    (try ignore (Str.search_forward (Str.regexp "bool security_check") generated_code 0); true with Not_found -> false);
  check bool "Contains kfunc call" true
    (try ignore (Str.search_forward (Str.regexp "security_check(") generated_code 0); true with Not_found -> false)

let tests = [
  "kfunc parsing", `Quick, test_kfunc_parsing;
  "kfunc type checking", `Quick, test_kfunc_type_checking;
  "kernel module generation", `Quick, test_kernel_module_generation;
  "eBPF kfunc declarations", `Quick, test_ebpf_kfunc_declarations;
]

let () = Alcotest.run "KernelScript @kfunc attribute tests" [
  "kfunc_tests", tests
] 