open Alcotest
open Kernelscript
open Ast

let test_private_parsing () =
  let program = {|
    @private
    fn internal_helper(data: *u8, len: u32) -> bool {
        return len > 64
    }
    
    @kfunc
    fn public_filter(data: *u8, len: u32) -> i32 {
        if (!internal_helper(data, len)) {
            return -1
        }
        return 0
    }
    
    @xdp
    fn packet_filter(ctx: XdpContext) -> XdpAction {
        let result = public_filter(null, 100)
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  check int "Number of declarations" 4 (List.length ast);
  
  (match List.hd ast with
   | AttributedFunction attr_func ->
       check string "Function name" "internal_helper" attr_func.attr_function.func_name;
       (match attr_func.attr_list with
        | [SimpleAttribute attr_name] ->
            check string "Attribute name" "private" attr_name
        | _ -> fail "Expected single private attribute")
   | _ -> fail "Expected AttributedFunction")

let test_private_type_checking () =
  let program = {|
    @private
    fn validate_length(size: u32) -> bool {
        return size > 64
    }
    
    @kfunc 
    fn advanced_check(data: *u8, size: u32) -> i32 {
        if (!validate_length(size)) {
            return -1
        }
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  let typed_ast = Type_checker.type_check_ast ast in
  
  check int "Typed AST length" (List.length ast) (List.length typed_ast)

let test_kernel_module_generation () =
  let program = {|
    @private
    fn compute_hash(data: *u8, len: u32) -> u64 {
        return 0
    }
    
    @kfunc
    fn secure_filter(data: *u8, len: u32) -> i32 {
        let hash = compute_hash(data, len)
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  let kernel_module_code = Kernel_module_codegen.generate_kernel_module_from_ast "test" ast in
  
  (match kernel_module_code with
   | Some code ->
       check bool "Contains private function" true 
         (try ignore (Str.search_forward (Str.regexp "compute_hash") code 0); true with Not_found -> false);
       check bool "Contains kfunc" true 
         (try ignore (Str.search_forward (Str.regexp "secure_filter") code 0); true with Not_found -> false)
   | None -> fail "Expected kernel module code")

let tests = [
  "private parsing", `Quick, test_private_parsing;
  "private type checking", `Quick, test_private_type_checking;
  "kernel module generation", `Quick, test_kernel_module_generation;
]

let () = Alcotest.run "KernelScript @private attribute tests" [
  "private_tests", tests
] 