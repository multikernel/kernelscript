(** Unit tests for Symbol Table *)

open Kernelscript
open Ast
open Symbol_table

(** Helper functions for testing *)
let dummy_pos = { line = 1; column = 1; filename = "test.ks" }

let create_test_map_decl name is_global =
  let config = {
    max_entries = 256;
    key_size = None;
    value_size = None;
    attributes = [];
  } in
  {
    name;
    key_type = U32;
    value_type = U64;
    map_type = HashMap;
    config;
    is_global;
    map_pos = dummy_pos;
  }

let create_test_function name params return_type =
  {
    func_name = name;
    func_params = params;
    func_return_type = Some return_type;
    func_body = [];
    func_pos = dummy_pos;
  }

let create_test_program name functions =
  {
    prog_name = name;
    prog_type = Xdp;
    prog_functions = functions;

    prog_pos = dummy_pos;
  }

(** Test 1: Basic symbol table creation *)
let test_symbol_table_creation () =
  let table = create_symbol_table () in
  assert (Hashtbl.length table.symbols = 0);
  assert (Hashtbl.length table.global_maps = 0);
  assert (Hashtbl.length table.local_maps = 0);
  assert (table.scopes = [GlobalScope]);
  assert (table.current_program = None);
  assert (table.current_function = None);
  Printf.printf "✓ Symbol table creation test passed\n"

(** Test 2: Global map handling *)
let test_global_map_handling () =
  let table = create_symbol_table () in
  let global_map = create_test_map_decl "global_counter" true in
  add_map_decl table global_map;
  
  assert (is_global_map table "global_counter");
  assert (not (is_local_map table "test_prog" "global_counter"));
  
  (match get_map_declaration table "global_counter" with
  | Some map_decl -> assert (map_decl.name = "global_counter")
  | None -> ());
  assert (get_map_declaration table "global_counter" <> None);
  
  Printf.printf "✓ Global map handling test passed\n"

(** Test 3: Local map handling *)
let test_local_map_handling () =
  let table = create_symbol_table () in
  let table_with_prog = enter_scope table (ProgramScope "test_prog") in
  let local_map = create_test_map_decl "local_map" false in
  add_map_decl table_with_prog local_map;
  
  assert (is_local_map table_with_prog "test_prog" "local_map");
  assert (not (is_global_map table_with_prog "local_map"));
  
  (match get_map_declaration table_with_prog "local_map" with
  | Some map_decl -> assert (map_decl.name = "local_map")
  | None -> ());
  assert (get_map_declaration table_with_prog "local_map" <> None);
  
  Printf.printf "✓ Local map handling test passed\n"

(** Test 4: Scope management *)
let test_scope_management () =
  let table = create_symbol_table () in
  assert (table.scopes = [GlobalScope]);
  
  let table_with_prog = enter_scope table (ProgramScope "test_prog") in
  assert (table_with_prog.current_program = Some "test_prog");
  
  let table_with_func = enter_scope table_with_prog (FunctionScope ("test_prog", "main")) in
  assert (table_with_func.current_program = Some "test_prog");
  assert (table_with_func.current_function = Some "main");
  
  let table_back_to_prog = exit_scope table_with_func in
  assert (table_back_to_prog.current_program = Some "test_prog");
  assert (table_back_to_prog.current_function = None);
  
  let table_back_to_global = exit_scope table_back_to_prog in
  assert (table_back_to_global.current_program = None);
  assert (table_back_to_global.current_function = None);
  
  Printf.printf "✓ Scope management test passed\n"

(** Test 5: Symbol lookup and visibility *)
let test_symbol_lookup_and_visibility () =
  let table = create_symbol_table () in
  
  (* Add global function *)
  let global_func = create_test_function "global_func" [] U32 in
  add_function table global_func Public;
  
  (* Add global variable *)
  add_variable table "global_var" U32 dummy_pos;
  
  (* Enter program scope *)
  let table_with_prog = enter_scope table (ProgramScope "test_prog") in
  
  (* Add local function *)
  let local_func = create_test_function "local_func" [] U32 in
  add_function table_with_prog local_func Private;
  
  (* Test lookups from program scope *)
  (match lookup_symbol table_with_prog "global_func" with
   | Some symbol -> assert (symbol.name = "global_func")
   | None -> failwith "Expected to find global_func");
   
  (match lookup_symbol table_with_prog "local_func" with
   | Some symbol -> assert (symbol.name = "local_func")
   | None -> failwith "Expected to find local_func");
   
  (match lookup_symbol table_with_prog "nonexistent" with
   | Some _ -> failwith "Should not find nonexistent symbol"
   | None -> ());
   
  Printf.printf "✓ Symbol lookup and visibility test passed\n"

(** Test 6: Type definition handling *)
let test_type_definition_handling () =
  let table = create_symbol_table () in
  
  (* Add struct definition *)
  let struct_def = StructDef ("TestStruct", [("field1", U32); ("field2", U64)]) in
  add_type_def table struct_def dummy_pos;
  
  (* Add enum definition *)
  let enum_def = EnumDef ("TestEnum", [("Value1", Some 0); ("Value2", Some 1)]) in
  add_type_def table enum_def dummy_pos;
  
  (* Test lookups *)
  (match lookup_symbol table "TestStruct" with
   | Some { kind = TypeDef (StructDef (name, _)); _ } -> assert (name = "TestStruct")
   | _ -> failwith "Expected to find TestStruct");
   
  (match lookup_symbol table "TestEnum" with
   | Some { kind = TypeDef (EnumDef (name, _)); _ } -> assert (name = "TestEnum")
   | _ -> failwith "Expected to find TestEnum");
   
  (* Test enum constants *)
  (match lookup_symbol table "TestEnum::Value1" with
   | Some { kind = EnumConstant (enum_name, Some value); _ } -> 
       assert (enum_name = "TestEnum" && value = 0)
   | _ -> failwith "Expected to find TestEnum::Value1");
   
  Printf.printf "✓ Type definition handling test passed\n"

(** Test 7: Function parameter handling *)
let test_function_parameter_handling () =
  let table = create_symbol_table () in
  let table_with_prog = enter_scope table (ProgramScope "test_prog") in
  
  (* Create function with parameters *)
  let func_with_params = create_test_function "test_func" [("param1", U32); ("param2", U64)] U32 in
  add_function table_with_prog func_with_params Private;
  
  (* Enter function scope *)
  let table_with_func = enter_scope table_with_prog (FunctionScope ("test_prog", "test_func")) in
  
  (* Add parameters *)
  List.iter (fun (param_name, param_type) ->
    add_variable table_with_func param_name param_type dummy_pos
  ) func_with_params.func_params;
  
  (* Test parameter lookup *)
  (match lookup_symbol table_with_func "param1" with
   | Some { kind = Variable U32; _ } -> ()
   | _ -> failwith "Expected to find param1 with type U32");
   
  (match lookup_symbol table_with_func "param2" with
   | Some { kind = Variable U64; _ } -> ()
   | _ -> failwith "Expected to find param2 with type U64");
   
  Printf.printf "✓ Function parameter handling test passed\n"

(** Test 8: Global vs Local scoping from the roadmap example *)
let test_global_local_scoping () =
  let table = create_symbol_table () in
  
  (* Add global map *)
  let global_map = create_test_map_decl "global_counter" true in
  add_map_decl table global_map;
  
  (* Enter program scope *)
  let table_with_prog = enter_scope table (ProgramScope "test") in
  
  (* Add local map *)
  let local_map = create_test_map_decl "local_map" false in
  add_map_decl table_with_prog local_map;
  
  (* Test the assertions from the roadmap *)
  assert (is_global_map table_with_prog "global_counter");
  assert (is_local_map table_with_prog "test" "local_map");
  
  Printf.printf "✓ Global vs local scoping test passed\n"

(** Test 9: Map visibility rules *)
let test_map_visibility_rules () =
  let table = create_symbol_table () in
  
  (* Add global map *)
  let global_map = create_test_map_decl "global_counter" true in
  add_map_decl table global_map;
  
  (* Enter first program scope *)
  let table_prog1 = enter_scope table (ProgramScope "prog1") in
  let local_map1 = create_test_map_decl "local_map" false in
  add_map_decl table_prog1 local_map1;
  
  (* Exit and enter second program scope *)
  let table_back = exit_scope table_prog1 in
  let table_prog2 = enter_scope table_back (ProgramScope "prog2") in
  let local_map2 = create_test_map_decl "local_map" false in
  add_map_decl table_prog2 local_map2;
  
  (* Global map should be visible from both programs *)
  assert (is_global_map table_prog1 "global_counter");
  assert (is_global_map table_prog2 "global_counter");
  
  (* Local maps should only be visible within their program *)
  assert (is_local_map table_prog1 "prog1" "local_map");
  assert (not (is_local_map table_prog1 "prog2" "local_map"));
  assert (is_local_map table_prog2 "prog2" "local_map");
  assert (not (is_local_map table_prog2 "prog1" "local_map"));
  
  (* Test that local maps are not accessible from the wrong program context *)
  assert (not (is_local_map table_prog2 "prog1" "local_map"));
  assert (not (is_local_map table_prog1 "prog2" "local_map"));
  
  Printf.printf "✓ Map visibility rules test passed\n"

(** Test 10: Build symbol table from AST *)
let test_build_symbol_table_from_ast () =
  let global_map = create_test_map_decl "global_counter" true in
  
  let main_func = create_test_function "main" [("ctx", XdpContext)] XdpAction in
  let test_prog = create_test_program "test" [main_func] in
  
  let ast = [
    MapDecl global_map;
    Program test_prog;
  ] in
  
  let table = build_symbol_table ast in
  
  (* Verify global map was added *)
  assert (is_global_map table "global_counter");
  
  (* Verify program function was added *)
  let prog_functions = get_program_functions table "test" in
  assert (List.length prog_functions = 1);
  assert ((List.hd prog_functions).name = "main");
  
  Printf.printf "✓ Build symbol table from AST test passed\n"

(** Test 11: Error handling *)
let test_error_handling () =
  let table = create_symbol_table () in
  
  (* Test symbol redefinition error *)
  add_variable table "var1" U32 dummy_pos;
  (try
     add_variable table "var1" U64 dummy_pos;
     failwith "Expected Symbol_error exception"
   with Symbol_error (msg, _) ->
     assert (Str.search_forward (Str.regexp "already defined") msg 0 >= 0));
  
  (* Test undefined symbol lookup *)
  (match lookup_symbol table "undefined_var" with
   | None -> ()
   | Some _ -> failwith "Should not find undefined_var");
  
  (* Test local map outside program error *)
  let local_map = create_test_map_decl "invalid_local" false in
  (try
     add_map_decl table local_map;
     failwith "Expected Symbol_error exception"
   with Symbol_error (msg, _) ->
     assert (Str.search_forward (Str.regexp "inside a program") msg 0 >= 0));
  
  Printf.printf "✓ Error handling test passed\n"

(** Test 12: Complex integration scenario *)
let test_complex_integration () =
  let table = create_symbol_table () in
  
  (* Global declarations *)
  let global_map = create_test_map_decl "global_stats" true in
  add_map_decl table global_map;
  
  let struct_def = StructDef ("PacketInfo", [("size", U32); ("protocol", U16)]) in
  add_type_def table struct_def dummy_pos;
  
  let enum_def = EnumDef ("XdpAction", [("Pass", Some 0); ("Drop", Some 1)]) in
  add_type_def table enum_def dummy_pos;
  
  (* Program scope *)
  let table_prog = enter_scope table (ProgramScope "packet_filter") in
  let local_map = create_test_map_decl "local_cache" false in
  add_map_decl table_prog local_map;
  
  (* Function scope *)
  let main_func = create_test_function "main" [("ctx", XdpContext)] XdpAction in
  add_function table_prog main_func Private;
  
  let table_func = enter_scope table_prog (FunctionScope ("packet_filter", "main")) in
  add_variable table_func "ctx" XdpContext dummy_pos;
  add_variable table_func "packet_info" (Struct "PacketInfo") dummy_pos;
  
  (* Verify all symbols are accessible *)
  assert (is_global_map table_func "global_stats");
  assert (is_local_map table_func "packet_filter" "local_cache");
  
  (match lookup_symbol table_func "PacketInfo" with
   | Some { kind = TypeDef _; _ } -> ()
   | _ -> failwith "Expected to find PacketInfo type");
   
  (match lookup_symbol table_func "XdpAction::Pass" with
   | Some { kind = EnumConstant _; _ } -> ()
   | _ -> failwith "Expected to find XdpAction::Pass enum constant");
   
  (match lookup_symbol table_func "ctx" with
   | Some { kind = Variable XdpContext; _ } -> ()
   | _ -> failwith "Expected to find ctx variable");
   
  Printf.printf "✓ Complex integration test passed\n"

(** Run all tests *)
let run_all_tests () =
  Printf.printf "Running Symbol Table Tests...\n";
  Printf.printf "================================\n";
  
  test_symbol_table_creation ();
  test_global_map_handling ();
  test_local_map_handling ();
  test_scope_management ();
  test_symbol_lookup_and_visibility ();
  test_type_definition_handling ();
  test_function_parameter_handling ();
  test_global_local_scoping ();
  test_map_visibility_rules ();
  test_build_symbol_table_from_ast ();
  test_error_handling ();
  test_complex_integration ();
  
  Printf.printf "================================\n";
  Printf.printf "All Symbol Table tests passed! ✅\n\n"

(** Main function *)
let () = run_all_tests () 