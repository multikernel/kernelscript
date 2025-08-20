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

(** Test basic include parsing **)
let test_include_parsing () =
  let program = {|
    include "common_kfuncs.kh"
    include "xdp_kfuncs.kh"
    
    @xdp
    fn test_program(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  let ast = Parse.parse_string program in
  
  (* Check that we have the expected declarations *)
  check int "Number of declarations" 4 (List.length ast);
  
  (* Check that the first two declarations are includes *)
  match ast with
  | IncludeDecl include1 :: IncludeDecl include2 :: _ :: _ ->
      check string "First include path" "common_kfuncs.kh" include1.include_path;
      check string "Second include path" "xdp_kfuncs.kh" include2.include_path
  | _ ->
      fail "Expected first two declarations to be includes"

(** Test include string representation **)
let test_include_string_representation () =
  let program = {|
    include "test_header.kh"
  |} in
  
  let ast = Parse.parse_string program in
  let ast_string = string_of_ast ast in
  
  (* Check that include is properly represented *)
  let regex = Str.regexp "include \"test_header.kh\"" in
  let contains_include = try ignore (Str.search_forward regex ast_string 0); true with Not_found -> false in
  check bool "Contains include declaration" true contains_include

(** Test include with invalid extension should parse but validation can be added later **)
let test_include_any_extension () =
  let program = {|
    include "invalid_file.ks"
  |} in
  
  (* Should parse successfully - validation of .kh extension will be in file processing *)
  let ast = Parse.parse_string program in
  
  match ast with
  | [IncludeDecl include_decl] ->
      check string "Include path" "invalid_file.ks" include_decl.include_path
  | _ ->
      fail "Expected single include declaration"

(** Test type checking with includes **)
let test_include_type_checking () =
  let program = {|
    include "kfuncs.kh"
    
    @xdp
    fn test_program(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    fn main() -> i32 {
        return 0
    }
  |} in
  
  (* Type check should pass - includes should not break type checking *)
  let ast = Parse.parse_string program in
  let type_check_result = try
    let _symbol_table = Symbol_table.build_symbol_table ast in
    ignore (Type_checker.type_check_and_annotate_ast ast);
    true
  with
  | _ -> false
  in
  check bool "Type checking should pass with includes" true type_check_result

(** Test include processing with real file system operations **)
let test_include_file_processing () =
  (* Create temporary header file *)
  let temp_dir = Filename.get_temp_dir_name () in
  let header_file = Filename.concat temp_dir "test_header.kh" in
  let header_content = {|
// Test header file
extern test_kfunc(value: u32) -> u64
type TestType = u32
|} in
  
  let oc = open_out header_file in
  output_string oc header_content;
  close_out oc;
  
  (* Create main file that includes the header *)
  let main_file = Filename.concat temp_dir "test_main.ks" in  
  let main_content = Printf.sprintf {|
include "%s"

@xdp
fn test_program(ctx: *xdp_md) -> xdp_action {
    var result = test_kfunc(42)
    var test_val: TestType = 123
    return 2
}

fn main() -> i32 {
    return 0
}
|} (Filename.basename header_file) in
  
  let oc = open_out main_file in
  output_string oc main_content;
  close_out oc;
  
  (* Test include processing *)
  let result = try
    let ic = open_in main_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    let lexbuf = Lexing.from_string content in
    let ast = Parser.program Lexer.token lexbuf in
    
    (* Process includes *)
    let expanded_ast = Include_resolver.process_includes ast main_file in
    
    (* Check that AST was expanded *)
    check bool "AST expanded from includes" true (List.length expanded_ast > List.length ast);
    
    (* Check that extern kfunc is present in expanded AST *)
    let has_extern = List.exists (function
      | Ast.ExternKfuncDecl extern_decl -> extern_decl.extern_name = "test_kfunc"
      | _ -> false
    ) expanded_ast in
    check bool "Extern kfunc included" true has_extern;
    
    (* Check that type alias is present *)
    let has_type = List.exists (function
      | Ast.TypeDef (Ast.TypeAlias (name, _, _)) -> name = "TestType"
      | _ -> false
    ) expanded_ast in
    check bool "Type alias included" true has_type;
    
    true
  with
  | _ -> false
  in
  
  (* Clean up *)
  (try Sys.remove header_file with _ -> ());
  (try Sys.remove main_file with _ -> ());
  
  check bool "Include processing successful" true result

(** Test error handling for invalid header file **)
let test_include_validation_error () =
  (* Create temporary invalid header file *)
  let temp_dir = Filename.get_temp_dir_name () in
  let header_file = Filename.concat temp_dir "invalid_header.kh" in
  let header_content = {|
extern test_kfunc() -> u64

// Invalid: function implementation in header
fn invalid_impl() -> u32 {
    return 42
}
|} in
  
  let oc = open_out header_file in
  output_string oc header_content;
  close_out oc;
  
  (* Create main file that includes the invalid header *)
  let main_file = Filename.concat temp_dir "test_main.ks" in  
  let main_content = Printf.sprintf {|
include "%s"

fn main() -> i32 { return 0 }
|} (Filename.basename header_file) in
  
  let oc = open_out main_file in
  output_string oc main_content;
  close_out oc;
  
  (* Test that include processing fails *)
  let error_caught = try
    let ic = open_in main_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    let lexbuf = Lexing.from_string content in
    let ast = Parser.program Lexer.token lexbuf in
    
    (* This should throw an error *)
    let _ = Include_resolver.process_includes ast main_file in
    false (* Should not reach here *)
  with
  | Include_resolver.Include_error _ -> true (* Expected error *)
  | _ -> false (* Unexpected error *)
  in
  
  (* Clean up *)
  (try Sys.remove header_file with _ -> ());
  (try Sys.remove main_file with _ -> ());
  
  check bool "Include validation error caught" true error_caught

(** Test extension validation **)
let test_extension_validation () =
  (* Create temporary file with wrong extension *)
  let temp_dir = Filename.get_temp_dir_name () in
  let wrong_ext_file = Filename.concat temp_dir "wrong_ext.ks" in
  let content = "extern test_kfunc() -> u64" in
  
  let oc = open_out wrong_ext_file in
  output_string oc content;
  close_out oc;
  
  (* Create main file that includes file with wrong extension *)
  let main_file = Filename.concat temp_dir "test_main.ks" in  
  let main_content = Printf.sprintf {|
include "%s"

fn main() -> i32 { return 0 }
|} (Filename.basename wrong_ext_file) in
  
  let oc = open_out main_file in
  output_string oc main_content;
  close_out oc;
  
  (* Test that extension validation fails *)
  let error_caught = try
    let ic = open_in main_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    let lexbuf = Lexing.from_string content in
    let ast = Parser.program Lexer.token lexbuf in
    
    (* This should throw an error *)
    let _ = Include_resolver.process_includes ast main_file in
    false (* Should not reach here *)
  with
  | Include_resolver.Include_validation_error _ -> true (* Expected error *)
  | _ -> false (* Unexpected error *)
  in
  
  (* Clean up *)
  (try Sys.remove wrong_ext_file with _ -> ());
  (try Sys.remove main_file with _ -> ());
  
  check bool "Extension validation error caught" true error_caught

let tests = [
  "include parsing", `Quick, test_include_parsing;
  "include string representation", `Quick, test_include_string_representation;
  "include any extension", `Quick, test_include_any_extension;
  "include type checking", `Quick, test_include_type_checking;
  "include file processing", `Quick, test_include_file_processing;
  "include validation error", `Quick, test_include_validation_error;
  "extension validation", `Quick, test_extension_validation;
]

let () = Alcotest.run "KernelScript include tests" [
  "include_tests", tests
]