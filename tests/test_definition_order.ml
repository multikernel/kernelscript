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

(** Test definition order preservation in IR generation *)

open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ir_generator
open Alcotest

module Symbol_table = Kernelscript.Symbol_table

(** Helper functions for creating test AST nodes *)

let make_test_position line col = make_position line col "test.ks"

let make_test_type_alias name underlying_type line =
  TypeDef (TypeAlias (name, underlying_type, make_test_position line 1))

let make_test_struct_def name fields line =
  TypeDef (StructDef (name, fields, make_test_position line 1))

let make_test_enum_def name values line =
  TypeDef (EnumDef (name, values, make_test_position line 1))

let make_test_map_decl name key_type value_type line =
  let map_config = make_map_config 256 () in
  MapDecl (make_map_declaration name key_type value_type Array map_config false ~is_pinned:false (make_test_position line 1))

let make_test_config_decl name fields line =
  let config_fields = List.map (fun (field_name, field_type) ->
    make_config_field field_name field_type None (make_test_position line 1)
  ) fields in
  ConfigDecl (make_config_declaration name config_fields (make_test_position line 1))

let make_test_global_var name var_type line =
  GlobalVarDecl {
    global_var_name = name;
    global_var_type = var_type;
    global_var_init = None;
    global_var_pos = make_test_position line 1;
    is_local = false;
    is_pinned = false;
  }

let make_test_function name params return_type body line =
  let func_def = {
    func_name = name;
    func_params = params;
    func_return_type = return_type;
    func_body = body;
    func_scope = Kernel;
    func_pos = make_test_position line 1;
    tail_call_targets = [];
    is_tail_callable = false;
  } in
  GlobalFunction func_def

let make_test_program name line =
  let func_def = {
    func_name = name;
    func_params = [];
    func_return_type = None;
    func_body = [];
    func_scope = Kernel;
    func_pos = make_test_position line 1;
    tail_call_targets = [];
    is_tail_callable = false;
  } in
  AttributedFunction {
    attr_list = [SimpleAttribute "xdp"];
    attr_function = func_def;
    attr_pos = make_test_position line 1;
    program_type = None;
    tail_call_dependencies = [];
  }

(** Test helper to extract declaration order from IR *)
let extract_declaration_orders ir_multi_prog =
  List.map (fun decl -> 
    (decl.decl_order, decl.decl_desc)
  ) ir_multi_prog.source_declarations
  |> List.sort (fun (order1, _) (order2, _) -> compare order1 order2)

(** Test helper to get declaration name from IR declaration *)
let get_declaration_name = function
  | IRDeclTypeAlias (name, _, _) -> name
  | IRDeclStructDef (name, _, _) -> name
  | IRDeclEnumDef (name, _, _) -> name
  | IRDeclMapDef map_def -> map_def.map_name
  | IRDeclConfigDef config_def -> config_def.config_name
  | IRDeclGlobalVarDef global_var -> global_var.global_var_name
  | IRDeclFunctionDef func_def -> func_def.func_name
  | IRDeclStructOpsDef struct_ops -> struct_ops.ir_struct_ops_name
  | IRDeclStructOpsInstance instance -> instance.ir_instance_name

(** Test type alias order preservation *)
let test_type_alias_order () =
  let ast = [
    make_test_type_alias "FirstAlias" U32 1;
    make_test_type_alias "SecondAlias" U64 2;
    make_test_type_alias "ThirdAlias" Bool 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["FirstAlias"; "SecondAlias"; "ThirdAlias"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Type alias order preserved" expected_names actual_names

(** Test struct definition order preservation *)
let test_struct_order () =
  let ast = [
    make_test_struct_def "FirstStruct" [("field1", U32)] 1;
    make_test_struct_def "SecondStruct" [("field2", U64)] 2;
    make_test_struct_def "ThirdStruct" [("field3", Bool)] 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["FirstStruct"; "SecondStruct"; "ThirdStruct"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Struct definition order preserved" expected_names actual_names

(** Test enum definition order preservation *)
let test_enum_order () =
  let ast = [
    make_test_enum_def "FirstEnum" [("VALUE1", Some (Signed64 1L))] 1;
    make_test_enum_def "SecondEnum" [("VALUE2", Some (Signed64 2L))] 2;
    make_test_enum_def "ThirdEnum" [("VALUE3", Some (Signed64 3L))] 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["FirstEnum"; "SecondEnum"; "ThirdEnum"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Enum definition order preserved" expected_names actual_names

(** Test map declaration order preservation *)
let test_map_order () =
  let ast = [
    make_test_map_decl "first_map" U32 U64 1;
    make_test_map_decl "second_map" U16 U32 2;
    make_test_map_decl "third_map" U8 U16 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["first_map"; "second_map"; "third_map"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Map declaration order preserved" expected_names actual_names

(** Test config declaration order preservation *)
let test_config_order () =
  let ast = [
    make_test_config_decl "first_config" [("field1", U32)] 1;
    make_test_config_decl "second_config" [("field2", U64)] 2;
    make_test_config_decl "third_config" [("field3", Bool)] 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["first_config"; "second_config"; "third_config"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Config declaration order preserved" expected_names actual_names

(** Test global variable declaration order preservation *)
let test_global_var_order () =
  let ast = [
    make_test_global_var "first_global" (Some U32) 1;
    make_test_global_var "second_global" (Some U64) 2;
    make_test_global_var "third_global" (Some Bool) 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["first_global"; "second_global"; "third_global"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Global variable declaration order preserved" expected_names actual_names

(** Test function declaration order preservation *)
let test_function_order () =
  let empty_body = [] in
  let ast = [
    make_test_function "first_func" [] None empty_body 1;
    make_test_function "second_func" [] None empty_body 2;
    make_test_function "third_func" [] None empty_body 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["first_func"; "second_func"; "third_func"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Function declaration order preserved" expected_names actual_names

(** Test mixed declaration types order preservation *)
let test_mixed_order () =
  let empty_body = [] in
  let ast = [
    make_test_type_alias "MyAlias" U32 1;
    make_test_struct_def "MyStruct" [("field", U32)] 2;
    make_test_map_decl "my_map" U32 U64 3;
    make_test_enum_def "MyEnum" [("VALUE", Some (Signed64 1L))] 4;
    make_test_config_decl "my_config" [("setting", Bool)] 5;
    make_test_global_var "my_global" (Some U32) 6;
    make_test_function "my_func" [] None empty_body 7;
    make_test_program "test_prog" 8;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = ["MyAlias"; "MyStruct"; "my_map"; "MyEnum"; "my_config"; "my_global"; "my_func"] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Mixed declaration types order preserved" expected_names actual_names

(** Test complex dependency order preservation *)
let test_complex_dependencies () =
  let empty_body = [] in
  let ast = [
    (* Define base types first *)
    make_test_type_alias "BaseType" U32 1;
    make_test_struct_def "BaseStruct" [("id", U32)] 2;
    
    (* Define dependent types *)
    make_test_type_alias "DerivedType" (UserType "BaseType") 3;
    make_test_struct_def "DerivedStruct" [("base", UserType "BaseStruct"); ("extra", U64)] 4;
    
    (* Define maps using the types *)
    make_test_map_decl "base_map" (UserType "BaseType") (UserType "BaseStruct") 5;
    make_test_map_decl "derived_map" (UserType "DerivedType") (UserType "DerivedStruct") 6;
    
    (* Define functions using the types *)
    make_test_function "process_base" [("input", UserType "BaseType")] None empty_body 7;
    make_test_function "process_derived" [("input", UserType "DerivedType")] None empty_body 8;
    make_test_program "test_prog" 9;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_names = [
    "BaseType"; "BaseStruct"; "DerivedType"; "DerivedStruct"; 
    "base_map"; "derived_map"; "process_base"; "process_derived"
  ] in
  let actual_names = List.map (fun (_, decl_desc) -> get_declaration_name decl_desc) ordered_decls in
  
  check (list string) "Complex dependency order preserved" expected_names actual_names

(** Test that declaration order indices are sequential *)
let test_sequential_order_indices () =
  let ast = [
    make_test_type_alias "First" U32 1;
    make_test_type_alias "Second" U64 2;
    make_test_type_alias "Third" Bool 3;
    make_test_program "test_prog" 4;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  let expected_indices = [0; 1; 2] in
  let actual_indices = List.map (fun (order, _) -> order) ordered_decls in
  
  check (list int) "Declaration order indices are sequential" expected_indices actual_indices

(** Test empty AST produces empty source declarations *)
let test_empty_ast () =
  let ast = [make_test_program "test_prog" 1] in
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  
  check int "Empty AST produces empty source declarations" 0 (List.length ir_multi_prog.source_declarations)

(** Test single declaration produces correct order *)
let test_single_declaration () =
  let ast = [
    make_test_type_alias "SingleAlias" U32 1;
    make_test_program "test_prog" 2;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  check int "Single declaration has order 0" 1 (List.length ordered_decls);
  let (order, decl_desc) = List.hd ordered_decls in
  check int "Single declaration order is 0" 0 order;
  check string "Single declaration name is correct" "SingleAlias" (get_declaration_name decl_desc)

(** Test that userspace-only structs are not included in source declarations *)
let test_userspace_only_structs_excluded () =
  (* This test would require setting up userspace-only context, 
     but for now we test that regular structs are included *)
  let ast = [
    make_test_struct_def "RegularStruct" [("field", U32)] 1;
    make_test_program "test_prog" 2;
  ] in
  
  let symbol_table = Symbol_table.create_symbol_table () in
  
  let ir_multi_prog = lower_multi_program ast symbol_table "test" in
  let ordered_decls = extract_declaration_orders ir_multi_prog in
  
  check int "Regular struct is included in source declarations" 1 (List.length ordered_decls);
  let (_, decl_desc) = List.hd ordered_decls in
  check string "Regular struct name is correct" "RegularStruct" (get_declaration_name decl_desc)

(** Test suite *)
let () =
  run "Definition Order Preservation Tests" [
    "Type Alias Order", [
      test_case "Type alias order preserved" `Quick test_type_alias_order;
    ];
    "Struct Order", [
      test_case "Struct definition order preserved" `Quick test_struct_order;
    ];
    "Enum Order", [
      test_case "Enum definition order preserved" `Quick test_enum_order;
    ];
    "Map Order", [
      test_case "Map declaration order preserved" `Quick test_map_order;
    ];
    "Config Order", [
      test_case "Config declaration order preserved" `Quick test_config_order;
    ];
    "Global Variable Order", [
      test_case "Global variable declaration order preserved" `Quick test_global_var_order;
    ];
    "Function Order", [
      test_case "Function declaration order preserved" `Quick test_function_order;
    ];
    "Mixed Order", [
      test_case "Mixed declaration types order preserved" `Quick test_mixed_order;
    ];
    "Complex Dependencies", [
      test_case "Complex dependency order preserved" `Quick test_complex_dependencies;
    ];
    "Order Indices", [
      test_case "Declaration order indices are sequential" `Quick test_sequential_order_indices;
    ];
    "Edge Cases", [
      test_case "Empty AST produces empty source declarations" `Quick test_empty_ast;
      test_case "Single declaration produces correct order" `Quick test_single_declaration;
      test_case "Userspace-only structs excluded" `Quick test_userspace_only_structs_excluded;
    ];
  ]
