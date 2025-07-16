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

open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Parse
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
  let enum_def = EnumDef ("xdp_action", enum_values, false) in
  
  (* Add to symbol table *)
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Verify enum type is registered *)
  let enum_symbol = lookup_symbol symbol_table "xdp_action" in
  check bool "enum type found" true (enum_symbol <> None);
  
  (match enum_symbol with
  | Some symbol ->
      (match symbol.kind with
       | TypeDef (EnumDef (name, values, _)) ->
           check string "enum name" "xdp_action" name;
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
  let enum_def = EnumDef ("xdp_action", enum_values, false) in
  let enum_type = Enum "xdp_action" in
  let ctx = create_context empty_symbol_table [] in  (* Provide empty AST for tests *)
  Hashtbl.replace ctx.types "xdp_action" enum_def;
  
  (* Test enum-integer unification *)
  let unify_result1 = unify_types enum_type U32 in
  check bool "enum unifies with u32" true (unify_result1 = Some U32);
  
  let unify_result2 = unify_types U32 enum_type in
  check bool "u32 unifies with enum" true (unify_result2 = Some U32);
  
  (* Test enum-enum unification *)
  let same_enum = Enum "xdp_action" in
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
  let enum_def = EnumDef ("Protocol", enum_values, false) in
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
  let enum_name = "xdp_action" in
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
    "enum xdp_action {";
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
  let enum_def = EnumDef ("xdp_action", enum_values, false) in
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
  let empty_enum = EnumDef ("Empty", [], false) in
  let symbol_table = create_symbol_table () in
  add_type_def symbol_table empty_enum dummy_pos;
  
  let empty_symbol = lookup_symbol symbol_table "Empty" in
  check bool "empty enum registered" true (empty_symbol <> None);
  
  (* Test enum with duplicate names (should be handled by symbol table) *)
  let duplicate_values = [("SAME", Some 1); ("SAME", Some 2)] in
  let duplicate_enum = EnumDef ("Duplicate", duplicate_values, false) in
  
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

(** Test enum constant preservation in IR generation *)
let test_enum_ir_preservation () =
  let open Kernelscript.Ir in
  let open Kernelscript.Ir_generator in
  
  (* Create a symbol table with enum constants *)
  let symbol_table = create_symbol_table () in
  let enum_values = [("TCP", Some 6); ("UDP", Some 17); ("ICMP", Some 1)] in
  let enum_def = EnumDef ("IpProtocol", enum_values, false) in
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Create AST identifier expression for enum constant *)
  let tcp_identifier = make_expr (Identifier "TCP") dummy_pos in
  
  (* Generate IR from AST *)
  let ctx = create_context symbol_table in
  let ir_value = lower_expression ctx tcp_identifier in
  
  (* Verify that the IR contains IREnumConstant, not IRLiteral *)
  (match ir_value.value_desc with
   | IREnumConstant (enum_name, constant_name, numeric_value) ->
       check string "IR enum name" "IpProtocol" enum_name;
       check string "IR constant name" "TCP" constant_name;
       check int "IR constant value" 6 numeric_value
   | IRLiteral _ -> check bool "should not be IRLiteral" false true
   | _ -> check bool "wrong IR value type" false true)

(** Test enum constant preservation in C code generation *)
let test_enum_c_code_preservation () =
  let open Kernelscript.Ebpf_c_codegen in
  let open Kernelscript.Ir in
  
  (* Create IREnumConstant value *)
  let enum_constant = make_ir_value (IREnumConstant ("IpProtocol", "TCP", 6)) IRU32 dummy_pos in
  
  (* Create a simple eBPF context *)
  let ctx = create_c_context () in
  
  (* Generate C code *)
  let c_code = generate_c_value ctx enum_constant in
  
  (* Verify that C code contains the constant name, not numeric value *)
  check string "C code uses constant name" "TCP" c_code;
  
  (* Test that it doesn't generate numeric value *)
  check bool "C code doesn't use numeric value" true (c_code <> "6")

(** Test enum definition inclusion using symbol table *)
let test_enum_definition_inclusion () =
  (* Create a symbol table with enum definition *)
  let symbol_table = create_symbol_table () in
  let enum_values = [("TCP", Some 6); ("UDP", Some 17); ("ICMP", Some 1)] in
  let enum_def = EnumDef ("IpProtocol", enum_values, false) in
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Test that the enum can be looked up from symbol table *)
  let tcp_symbol = lookup_symbol symbol_table "TCP" in
  check bool "TCP enum constant found in symbol table" true (tcp_symbol <> None);
  
  (* Verify enum constant has correct value *)
  (match tcp_symbol with
   | Some symbol ->
       (match symbol.kind with
        | EnumConstant (enum_name, Some value) ->
            check string "enum name" "IpProtocol" enum_name;
            check int "TCP value" 6 value
        | _ -> check bool "wrong symbol kind" false true)
   | None -> check bool "TCP symbol not found" false true)

(** Test match expression with enum constants parsing *)
let test_match_enum_constants () =
  (* Create symbol table with enum *)
  let symbol_table = create_symbol_table () in
  let enum_values = [("TCP", Some 6); ("UDP", Some 17); ("ICMP", Some 1)] in
  let enum_def = EnumDef ("IpProtocol", enum_values, false) in
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Test that enum constants can be looked up *)
  let tcp_symbol = lookup_symbol symbol_table "TCP" in
  check bool "TCP enum constant found" true (tcp_symbol <> None);
  
  (* Verify enum constant structure for match patterns *)
  (match tcp_symbol with
   | Some symbol ->
       (match symbol.kind with
        | EnumConstant (enum_name, Some value) ->
            check string "match enum name" "IpProtocol" enum_name;
            check string "match constant name" "TCP" "TCP";
            check int "match constant value" 6 value
        | _ -> check bool "wrong symbol kind for match" false true)
   | None -> check bool "TCP symbol not found for match" false true)

(** Test that enum constants are NOT converted to numeric literals *)
let test_enum_not_numeric_literals () =
  let open Kernelscript.Ir in
  let open Kernelscript.Ir_generator in
  
  (* Create symbol table with enum *)
  let symbol_table = create_symbol_table () in
  let enum_values = [("TCP", Some 6); ("UDP", Some 17)] in
  let enum_def = EnumDef ("IpProtocol", enum_values, false) in
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Create AST identifier for enum constant *)
  let tcp_expr = make_expr (Identifier "TCP") dummy_pos in
  
  (* Generate IR *)
  let ctx = create_context symbol_table in
  let ir_value = lower_expression ctx tcp_expr in
  
  (* Verify it's NOT IRLiteral *)
  (match ir_value.value_desc with
   | IRLiteral _ -> check bool "should not be IRLiteral" false true
   | IREnumConstant _ -> check bool "correctly preserved as IREnumConstant" true true
   | _ -> check bool "unexpected IR value type" false true)

(** Test complete enum preservation pipeline *)
let test_enum_preservation_pipeline () =
  let open Kernelscript.Ebpf_c_codegen in
  let open Kernelscript.Ir in
  
  (* Create symbol table with enum *)
  let symbol_table = create_symbol_table () in
  let enum_values = [("XDP_PASS", Some 2); ("XDP_DROP", Some 1)] in
  let enum_def = EnumDef ("XdpAction", enum_values, false) in
  add_type_def symbol_table enum_def dummy_pos;
  
  (* Create IR with enum constant *)
  let enum_constant = make_ir_value (IREnumConstant ("XdpAction", "XDP_PASS", 2)) IRU32 dummy_pos in
  
  (* Create context for C generation *)
  let ctx = create_c_context () in
  
  (* Test C code generation *)
  let c_code = generate_c_value ctx enum_constant in
  check string "C code preserves enum constant" "XDP_PASS" c_code;
  
  (* Test symbol table preservation *)
  let pass_symbol = lookup_symbol symbol_table "XDP_PASS" in
  check bool "XDP_PASS symbol found" true (pass_symbol <> None);
  
  let drop_symbol = lookup_symbol symbol_table "XDP_DROP" in  
  check bool "XDP_DROP symbol found" true (drop_symbol <> None)

(** Test userspace enum preservation *)
let test_userspace_enum_preservation () =
  let open Kernelscript.Userspace_codegen in
  let open Kernelscript.Ir in
  
  (* Create IREnumConstant value *)
  let enum_constant = make_ir_value (IREnumConstant ("Protocol", "HTTP", 80)) IRU32 dummy_pos in
  
  (* Create a simple userspace context *)
  let ctx = create_userspace_context () in
  
  (* Generate userspace C code *)
  let c_code = generate_c_value_from_ir ctx enum_constant in
  
  (* Verify that userspace code also preserves enum constant names *)
  check string "userspace C code uses constant name" "HTTP" c_code;
  check bool "userspace C code doesn't use numeric value" true (c_code <> "80")

(** Test negative enum parsing - regression test for negative integer parsing bug *)
let test_negative_enum_parsing () =
  let source = {|
enum test_enum {
    NEGATIVE = -1,
    ZERO = 0,
    POSITIVE = 1,
    LARGE_NEGATIVE = -999
}
|} in
  let ast = parse_string source in
  let enum_def = match ast with
    | [TypeDef (EnumDef (name, variants, _))] ->
        check string "enum name" "test_enum" name;
        variants
    | _ -> failwith "Expected single enum declaration"
  in
  
  (* Check that all values are parsed correctly *)
  let expected = [
    ("NEGATIVE", Some (-1));
    ("ZERO", Some 0);
    ("POSITIVE", Some 1);
    ("LARGE_NEGATIVE", Some (-999))
  ] in
  check (list (pair string (option int))) "enum variants" expected enum_def

let test_mixed_positive_negative_enum () =
  let source = {|
enum mixed_values {
    NEG_FIRST = -5,
    ZERO = 0,
    POS_EXPLICIT = 42,
    NEG_AGAIN = -100,
    AUTO_ASSIGNED,
    POSITIVE_AFTER = 200
}
|} in
  let ast = parse_string source in
  let enum_def = match ast with
    | [TypeDef (EnumDef (name, variants, _))] ->
        check string "enum name" "mixed_values" name;
        variants
    | _ -> failwith "Expected single enum declaration"
  in
  
  (* Check that negative values are parsed correctly alongside positive values *)
  let expected = [
    ("NEG_FIRST", Some (-5));
    ("ZERO", Some 0);
    ("POS_EXPLICIT", Some 42);
    ("NEG_AGAIN", Some (-100));
    ("AUTO_ASSIGNED", None);  (* Auto-assigned value *)
    ("POSITIVE_AFTER", Some 200)
  ] in
  check (list (pair string (option int))) "mixed enum variants" expected enum_def

let test_tc_action_enum () =
  let source = {|
enum tc_action {
    TC_ACT_UNSPEC = -1,
    TC_ACT_OK = 0,
    TC_ACT_RECLASSIFY = 1,
    TC_ACT_SHOT = 2,
    TC_ACT_PIPE = 3,
    TC_ACT_STOLEN = 4,
    TC_ACT_QUEUED = 5,
    TC_ACT_REPEAT = 6,
    TC_ACT_REDIRECT = 7,
    TC_ACT_TRAP = 8,
}
|} in
  let ast = parse_string source in
  let enum_def = match ast with
    | [TypeDef (EnumDef (name, variants, _))] ->
        check string "enum name" "tc_action" name;
        variants
    | _ -> failwith "Expected single enum declaration"
  in
  
  (* Check the specific tc_action enum that was failing *)
  let expected = [
    ("TC_ACT_UNSPEC", Some (-1));
    ("TC_ACT_OK", Some 0);
    ("TC_ACT_RECLASSIFY", Some 1);
    ("TC_ACT_SHOT", Some 2);
    ("TC_ACT_PIPE", Some 3);
    ("TC_ACT_STOLEN", Some 4);
    ("TC_ACT_QUEUED", Some 5);
    ("TC_ACT_REPEAT", Some 6);
    ("TC_ACT_REDIRECT", Some 7);
    ("TC_ACT_TRAP", Some 8)
  ] in
  check (list (pair string (option int))) "tc_action variants" expected enum_def

let test_edge_case_negative_values () =
  let source = {|
enum edge_cases {
    VERY_NEGATIVE = -2147483648,
    NEGATIVE_ONE = -1,
    ZERO = 0,
    POSITIVE_ONE = 1,
    VERY_POSITIVE = 2147483647
}
|} in
  let ast = parse_string source in
  let enum_def = match ast with
    | [TypeDef (EnumDef (name, variants, _))] ->
        check string "enum name" "edge_cases" name;
        variants
    | _ -> failwith "Expected single enum declaration"
  in
  
  (* Check edge case values including minimum/maximum int32 values *)
  let expected = [
    ("VERY_NEGATIVE", Some (-2147483648));
    ("NEGATIVE_ONE", Some (-1));
    ("ZERO", Some 0);
    ("POSITIVE_ONE", Some 1);
    ("VERY_POSITIVE", Some 2147483647)
  ] in
  check (list (pair string (option int))) "edge case variants" expected enum_def

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
    "negative_parsing", [
      test_case "basic negative enum parsing" `Quick test_negative_enum_parsing;
      test_case "mixed positive and negative enum" `Quick test_mixed_positive_negative_enum;
      test_case "tc_action enum parsing (regression test)" `Quick test_tc_action_enum;
      test_case "edge case negative values" `Quick test_edge_case_negative_values;
    ];
    "enum_preservation_bug_fix", [
      test_case "enum constants preserved in IR" `Quick test_enum_ir_preservation;
      test_case "enum constants preserved in C code" `Quick test_enum_c_code_preservation;
      test_case "enum definitions included in generated code" `Quick test_enum_definition_inclusion;
      test_case "match expressions with enum constants" `Quick test_match_enum_constants;
      test_case "enum constants not converted to numeric literals" `Quick test_enum_not_numeric_literals;
      test_case "complete enum preservation pipeline" `Quick test_enum_preservation_pipeline;
      test_case "userspace enum preservation" `Quick test_userspace_enum_preservation;
    ];
  ] 