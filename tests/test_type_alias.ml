[@@@warning "-27"] (* Disable unused variable warnings *)
open OUnit2
open Kernelscript.Ast
open Kernelscript.Parser
open Kernelscript.Type_checker

let test_type_alias_parsing _ =
  let source = "type IpAddress = u32\ntype Port = u16\n" in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Verify that we parsed two type alias declarations *)
  assert_equal 2 (List.length ast);
  
  (* Check first type alias *)
  (match List.nth ast 0 with
   | TypeDef (TypeAlias ("IpAddress", U32)) -> ()
   | _ -> assert_failure "Expected IpAddress type alias");
  
  (* Check second type alias *)
  (match List.nth ast 1 with
   | TypeDef (TypeAlias ("Port", U16)) -> ()
   | _ -> assert_failure "Expected Port type alias")

let test_type_alias_resolution _ =
  let source = {|
type IpAddress = u32
type Port = u16

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let ip: IpAddress = 192168001001
        let port: Port = 8080
        return 2
    }
}
|} in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Type check the AST *)
  let typed_programs = type_check_ast ast in
  
  (* Verify that we have one typed program *)
  assert_equal 1 (List.length typed_programs);
  
  let typed_prog = List.hd typed_programs in
  assert_equal "test" typed_prog.tprog_name;
  assert_equal 1 (List.length typed_prog.tprog_functions);
  
  let typed_func = List.hd typed_prog.tprog_functions in
  assert_equal "main" typed_func.tfunc_name;
  
  (* Check that variable declarations use resolved types *)
  (match typed_func.tfunc_body with
   | [decl1; decl2; _ret] ->
       (match decl1.tstmt_desc with
        | TDeclaration ("ip", U32, _) -> ()
        | _ -> assert_failure "Expected ip variable with u32 type");
       (match decl2.tstmt_desc with
        | TDeclaration ("port", U16, _) -> ()
        | _ -> assert_failure "Expected port variable with u16 type")
   | _ -> assert_failure "Expected 3 statements in function body")

let test_array_type_alias _ =
  let source = {|
type EthBuffer = u8[14]

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let buffer: EthBuffer = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        return 2
    }
}
|} in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Verify parsing *)
  (match List.nth ast 0 with
   | TypeDef (TypeAlias ("EthBuffer", Array (U8, 14))) -> ()
   | _ -> assert_failure "Expected EthBuffer array type alias");
  
  (* Type check the AST *)
  let typed_programs = type_check_ast ast in
  let typed_prog = List.hd typed_programs in
  let typed_func = List.hd typed_prog.tprog_functions in
  
  (* Check that array type alias is resolved correctly *)
  (match typed_func.tfunc_body with
   | [decl; _ret] ->
       (match decl.tstmt_desc with
        | TDeclaration ("buffer", Array (U8, 14), _) -> ()
        | _ -> assert_failure "Expected buffer variable with u8[14] type")
   | _ -> assert_failure "Expected 2 statements in function body")

let test_nested_type_aliases _ =
  let source = {|
type Size = u32
type BufferSize = Size

program test : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        let size: BufferSize = 1024
        return 2
    }
}
|} in
  let lexbuf = Lexing.from_string source in
  let ast = program Kernelscript.Lexer.token lexbuf in
  
  (* Type check the AST *)
  let typed_programs = type_check_ast ast in
  let typed_prog = List.hd typed_programs in
  let typed_func = List.hd typed_prog.tprog_functions in
  
  (* Check that nested type alias is resolved to the final type *)
  (match typed_func.tfunc_body with
   | [decl; ret] ->
       (match decl.tstmt_desc with
        | TDeclaration ("size", U32, _) -> ()
        | _ -> assert_failure "Expected size variable with u32 type")
   | _ -> assert_failure "Expected 2 statements in function body")

let suite =
  "Type Alias Tests" >::: [
    "test_type_alias_parsing" >:: test_type_alias_parsing;
    "test_type_alias_resolution" >:: test_type_alias_resolution;
    "test_array_type_alias" >:: test_array_type_alias;
    "test_nested_type_aliases" >:: test_nested_type_aliases;
  ]

let () = run_test_tt_main suite 