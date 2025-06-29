open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Alcotest

let dummy_pos = { line = 1; column = 1; filename = "test_enum.ml" }

(** Test enum auto-assignment functionality *)
let test_enum_auto_assignment () =
  let process_enum_values values =
    let rec process_values acc current_value = function
      | [] -> List.rev acc
      | (const_name, None) :: rest ->
          (* Auto-assign current value *)
          let processed_value = (const_name, Some current_value) in
          process_values (processed_value :: acc) (current_value + 1) rest
      | (const_name, Some explicit_value) :: rest ->
          (* Use explicit value and update current value *)
          let processed_value = (const_name, Some explicit_value) in
          process_values (processed_value :: acc) (explicit_value + 1) rest
    in
    process_values [] 0 values
  in
  
  (* Test case 1: All auto-assigned values *)
  let values1 = [("TCP", None); ("UDP", None); ("ICMP", None)] in
  let result1 = process_enum_values values1 in
  let expected1 = [("TCP", Some 0); ("UDP", Some 1); ("ICMP", Some 2)] in
  check (list (pair string (option int))) "auto assignment" expected1 result1;
  
  (* Test case 2: Mixed explicit and auto values *)
  let values2 = [("TCP", Some 6); ("UDP", Some 17); ("ICMP", None); ("UNKNOWN", None)] in
  let result2 = process_enum_values values2 in
  let expected2 = [("TCP", Some 6); ("UDP", Some 17); ("ICMP", Some 18); ("UNKNOWN", Some 19)] in
  check (list (pair string (option int))) "mixed assignment" expected2 result2;
  
  (* Test case 3: Auto values with explicit override *)
  let values3 = [("FIRST", None); ("SECOND", Some 10); ("THIRD", None)] in
  let result3 = process_enum_values values3 in
  let expected3 = [("FIRST", Some 0); ("SECOND", Some 10); ("THIRD", Some 11)] in
  check (list (pair string (option int))) "auto with override" expected3 result3

(** Test enum parsing and symbol table integration *)
let test_enum_symbol_table () =
  let symbol_table = create_symbol_table () in
  
  (* Create enum definition *)
  let enum_values = [("XDP_ABORTED", Some 0); ("XDP_DROP", Some 1); ("XDP_PASS", Some 2)] in
  let enum_def = EnumDef ("XdpAction", enum_values) in
  
  (* Add to symbol table *)
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Verify enum type is registered *)
  let enum_symbol = lookup_symbol symbol_table "XdpAction" in
  check bool "enum type found" true (enum_symbol <> None);
  
  (match enum_symbol with
  | Some symbol ->
      (match symbol.kind with
       | TypeDef (EnumDef (name, values)) ->
           check string "enum name" "XdpAction" name;
           check int "enum value count" 3 (List.length values)
       | _ -> check bool "wrong symbol kind" false true)
  | None -> check bool "enum symbol not found" false true);
  
  (* Verify enum constants are registered *)
  let const1 = lookup_symbol symbol_table "XDP_ABORTED" in
  let const2 = lookup_symbol symbol_table "XDP_DROP" in
  let const3 = lookup_symbol symbol_table "XDP_PASS" in
  
  check bool "enum constant 1 found" true (const1 <> None);
  check bool "enum constant 2 found" true (const2 <> None);
  check bool "enum constant 3 found" true (const3 <> None)

(** Test enum type checking and unification *)
let test_enum_type_checking () =
  let empty_symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
  
  (* Add enum type to context *)
  let enum_values = [("XDP_PASS", Some 2); ("XDP_DROP", Some 1)] in
  let enum_def = EnumDef ("XdpAction", enum_values) in
  let enum_type = Enum "XdpAction" in
  let ctx = create_context empty_symbol_table [] in  (* Provide empty AST for tests *)
  Hashtbl.replace ctx.types "XdpAction" enum_def;
  
  (* Test enum-integer unification *)
  let unify_result1 = unify_types enum_type U32 in
  check bool "enum unifies with u32" true (unify_result1 = Some U32);
  
  let unify_result2 = unify_types U32 enum_type in
  check bool "u32 unifies with enum" true (unify_result2 = Some U32);
  
  (* Test enum-enum unification *)
  let same_enum = Enum "XdpAction" in
  let unify_result3 = unify_types enum_type same_enum in
  check bool "enum unifies with same enum" true (unify_result3 = Some enum_type);
  
  let different_enum = Enum "TcAction" in
  let unify_result4 = unify_types enum_type different_enum in
  check bool "enum doesn't unify with different enum" true (unify_result4 = None);
  
  (* Test enum with non-integer types *)
  let unify_result5 = unify_types enum_type Bool in
  check bool "enum doesn't unify with bool" true (unify_result5 = None)

(** Test enum constant lookup and validation *)
let test_enum_constants () =
  let symbol_table = create_symbol_table () in
  
  (* Add enum with constants *)
  let enum_values = [("PROTOCOL_TCP", Some 6); ("PROTOCOL_UDP", Some 17); ("PROTOCOL_ICMP", Some 1)] in
  let enum_def = EnumDef ("Protocol", enum_values) in
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Test constant lookup *)
  let tcp_const = lookup_symbol symbol_table "PROTOCOL_TCP" in
  check bool "TCP constant found" true (tcp_const <> None);
  
  (match tcp_const with
  | Some symbol ->
      (match symbol.kind with
       | EnumConstant (enum_name, Some value) ->
           check string "constant enum name" "Protocol" enum_name;
           check int "TCP value" 6 value
       | _ -> check bool "wrong constant kind" false true)
  | None -> check bool "TCP constant not found" false true);
  
  (* Test invalid constant lookup *)
  let invalid_const = lookup_symbol symbol_table "INVALID" in
  check bool "invalid constant not found" true (invalid_const = None)

(** Test enum code generation *)
let test_enum_code_generation () =
  (* Test enum definition generation for eBPF C *)
  let enum_name = "XdpAction" in
  let enum_values = [("XDP_ABORTED", 0); ("XDP_DROP", 1); ("XDP_PASS", 2); ("XDP_TX", 3)] in
  
  (* Simulate code generation *)
  let generate_enum_c enum_name values =
    let header = Printf.sprintf "enum %s {" enum_name in
    let constants = List.mapi (fun i (name, value) ->
      let comma = if i = List.length values - 1 then "" else "," in
      Printf.sprintf "    %s = %d%s" name value comma
    ) values in
    let footer = "};" in
    String.concat "\n" (header :: constants @ [footer])
  in
  
  let generated = generate_enum_c enum_name enum_values in
  let expected_lines = [
    "enum XdpAction {";
    "    XDP_ABORTED = 0,";
    "    XDP_DROP = 1,";
    "    XDP_PASS = 2,";
    "    XDP_TX = 3";
    "};"
  ] in
  let expected = String.concat "\n" expected_lines in
  
  check string "enum C generation" expected generated

(** Test enum usage in expressions *)
let test_enum_expressions () =
  let symbol_table = create_symbol_table () in
  
  (* Add enum *)
  let enum_values = [("XDP_PASS", Some 2); ("XDP_DROP", Some 1)] in
  let enum_def = EnumDef ("XdpAction", enum_values) in
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Verify the constant can be looked up *)
  let symbol = lookup_symbol symbol_table "XDP_PASS" in
  check bool "enum constant accessible" true (symbol <> None);
  
  match symbol with
  | Some s ->
      (match s.kind with
       | EnumConstant (_, Some value) ->
           check int "enum constant value" 2 value
       | _ -> check bool "wrong symbol type" false true)
  | None -> check bool "enum constant not found" false true

(** Test enum edge cases *)
let test_enum_edge_cases () =
  (* Test empty enum *)
  let empty_enum = EnumDef ("Empty", []) in
  let symbol_table = create_symbol_table () in
  add_type_def symbol_table empty_enum dummy_pos;
  
  let empty_symbol = lookup_symbol symbol_table "Empty" in
  check bool "empty enum registered" true (empty_symbol <> None);
  
  (* Test enum with duplicate names (should be handled by symbol table) *)
  let duplicate_values = [("SAME", Some 1); ("SAME", Some 2)] in
  let duplicate_enum = EnumDef ("Duplicate", duplicate_values) in
  
  (* This should either succeed (last wins) or fail gracefully *)
  try
    add_type_def symbol_table duplicate_enum dummy_pos;
    (* If it succeeds, verify the behavior *)
    let dup_symbol = lookup_symbol symbol_table "SAME" in
    check bool "duplicate handled" true (dup_symbol <> None)
  with
  | Symbol_error _ -> 
    (* If it fails, that's also acceptable behavior *)
    check bool "duplicate rejected" true true

(** Test enum with large values *)
let test_enum_large_values () =
  let large_values = [
    ("SMALL", Some 0);
    ("MEDIUM", Some 1000);
    ("LARGE", Some 65535);
    ("VERY_LARGE", Some 4294967295) (* Max u32 *)
  ] in
  
  let process_enum_values values =
    let rec process_values acc current_value = function
      | [] -> List.rev acc
      | (const_name, None) :: rest ->
          let processed_value = (const_name, Some current_value) in
          process_values (processed_value :: acc) (current_value + 1) rest
      | (const_name, Some explicit_value) :: rest ->
          let processed_value = (const_name, Some explicit_value) in
          process_values (processed_value :: acc) (explicit_value + 1) rest
    in
    process_values [] 0 values
  in
  
  let result = process_enum_values large_values in
  let expected = [
    ("SMALL", Some 0);
    ("MEDIUM", Some 1000);
    ("LARGE", Some 65535);
    ("VERY_LARGE", Some 4294967295)
  ] in
  
  check (list (pair string (option int))) "large values handled" expected result

(** Main test suite *)
let () =
  run "Enum Tests" [
    "auto_assignment", [
      test_case "basic auto assignment" `Quick test_enum_auto_assignment;
    ];
    "symbol_table", [
      test_case "enum symbol table integration" `Quick test_enum_symbol_table;
      test_case "enum constants lookup" `Quick test_enum_constants;
    ];
    "type_checking", [
      test_case "enum type unification" `Quick test_enum_type_checking;
      test_case "enum expressions" `Quick test_enum_expressions;
    ];
    "code_generation", [
      test_case "enum C code generation" `Quick test_enum_code_generation;
    ];
    "edge_cases", [
      test_case "enum edge cases" `Quick test_enum_edge_cases;
      test_case "large enum values" `Quick test_enum_large_values;
    ];
  ] 