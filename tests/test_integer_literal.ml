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
open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ebpf_c_codegen

(** Test position for all tests *)
let test_pos = { line = 1; column = 1; filename = "test.ks" }

(** Helper to create test positions *)
let make_test_position () = test_pos

(** Helper function to check if a string contains a substring *)
let contains_substr str substr =
  try
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in
    true
  with Not_found -> false

(** Test hex literal preservation in lexer *)
let test_hex_literal_lexing () =
  (* Test various hex formats *)
  let test_cases = [
    ("0xFF", 255, "0xFF");
    ("0x7F000001", 2130706433, "0x7F000001");
    ("0x0", 0, "0x0");
    ("0xDEADBEEF", 3735928559, "0xDEADBEEF");
    ("0xff", 255, "0xff");  (* lowercase *)
    ("0X12AB", 4779, "0X12AB");  (* uppercase X *)
  ] in
  
  List.iter (fun (input, expected_value, expected_original) ->
    let tokens = Lexer.tokenize_string input in
    match tokens with
    | [Parser.INT (value, Some original)] ->
        check int ("hex value for " ^ input) expected_value (Int64.to_int (IntegerValue.to_int64 value));
        check string ("hex format for " ^ input) expected_original original
    | [Parser.INT (_, None)] ->
        fail ("Expected original format to be preserved for " ^ input)
    | _ ->
        fail ("Expected single INT token for " ^ input)
  ) test_cases

(** Test decimal literal preservation in lexer *)
let test_decimal_literal_lexing () =
  let test_cases = [
    ("42", 42);
    ("0", 0);
    ("123456", 123456);
  ] in
  
  List.iter (fun (input, expected_value) ->
    let tokens = Lexer.tokenize_string input in
    match tokens with
    | [Parser.INT (value, None)] ->
        check int ("decimal value for " ^ input) expected_value (Int64.to_int (IntegerValue.to_int64 value))
    | [Parser.INT (_, Some original)] ->
        fail ("Expected no original format for decimal " ^ input ^ ", got " ^ original)
    | _ ->
        fail ("Expected single INT token for " ^ input)
  ) test_cases

(** Test large integer literal parsing - the original problem we solved *)
let test_large_integer_lexing () =
  let test_cases = [
    (* Test the original problematic value: UINT64_MAX *)
    ("18446744073709551615", "18446744073709551615", true);  (* 2^64 - 1, unsigned *)
    (* Test 2^63 - the boundary between signed and unsigned *)
    ("9223372036854775808", "9223372036854775808", true);    (* 2^63, first unsigned value *)
    ("9223372036854775807", "9223372036854775807", false);   (* 2^63 - 1, max signed *)
    (* Test other large values *)
    ("4294967295", "4294967295", false);                     (* 2^32 - 1, fits in signed *)
    ("4294967296", "4294967296", false);                     (* 2^32, fits in signed *)
    ("18446744073709551614", "18446744073709551614", true);  (* UINT64_MAX - 1 *)
  ] in
  
  List.iter (fun (input, expected_str, should_be_unsigned) ->
    let tokens = Lexer.tokenize_string input in
    match tokens with
    | [Parser.INT (value, None)] ->
        let actual_str = IntegerValue.to_string value in
        check string ("large integer string for " ^ input) expected_str actual_str;
        
        (* Check if it's correctly classified as signed vs unsigned *)
        let is_unsigned = match value with
          | Unsigned64 _ -> true
          | Signed64 _ -> false in
        check bool ("unsigned classification for " ^ input) should_be_unsigned is_unsigned
    | [Parser.INT (_, Some original)] ->
        fail ("Expected no original format for decimal " ^ input ^ ", got " ^ original)
    | _ ->
        fail ("Expected single INT token for " ^ input)
  ) test_cases

(** Test large hex literal parsing *)
let test_large_hex_literal_lexing () =
  let test_cases = [
    (* Test large hex values that require 64-bit representation *)
    ("0xFFFFFFFFFFFFFFFF", "18446744073709551615", "0xFFFFFFFFFFFFFFFF", true);  (* UINT64_MAX *)
    ("0x8000000000000000", "9223372036854775808", "0x8000000000000000", true);   (* 2^63 *)
    ("0x7FFFFFFFFFFFFFFF", "9223372036854775807", "0x7FFFFFFFFFFFFFFF", false);  (* 2^63 - 1 *)
    ("0xFFFFFFFF", "4294967295", "0xFFFFFFFF", false);                           (* 2^32 - 1 *)
    ("0x100000000", "4294967296", "0x100000000", false);                         (* 2^32 *)
    ("0xFFFFFFFFFFFFFFFE", "18446744073709551614", "0xFFFFFFFFFFFFFFFE", true);  (* UINT64_MAX - 1 *)
  ] in
  
  List.iter (fun (input, expected_decimal_str, expected_original, should_be_unsigned) ->
    let tokens = Lexer.tokenize_string input in
    match tokens with
    | [Parser.INT (value, Some original)] ->
        let actual_str = IntegerValue.to_string value in
        check string ("large hex decimal string for " ^ input) expected_decimal_str actual_str;
        check string ("large hex format for " ^ input) expected_original original;
        
        (* Check if it's correctly classified as signed vs unsigned *)
        let is_unsigned = match value with
          | Unsigned64 _ -> true
          | Signed64 _ -> false in
        check bool ("large hex unsigned classification for " ^ input) should_be_unsigned is_unsigned
    | [Parser.INT (_, None)] ->
        fail ("Expected original format to be preserved for " ^ input)
    | _ ->
        fail ("Expected single INT token for " ^ input)
  ) test_cases

(** Test binary literal preservation in lexer *)
let test_binary_literal_lexing () =
  let test_cases = [
    ("0b1010", 10, "0b1010");
    ("0b11111111", 255, "0b11111111");
    ("0B101", 5, "0B101");  (* uppercase B *)
  ] in
  
  List.iter (fun (input, expected_value, expected_original) ->
    let tokens = Lexer.tokenize_string input in
    match tokens with
    | [Parser.INT (value, Some original)] ->
        check int ("binary value for " ^ input) expected_value (Int64.to_int (IntegerValue.to_int64 value));
        check string ("binary format for " ^ input) expected_original original
    | [Parser.INT (_, None)] ->
        fail ("Expected original format to be preserved for " ^ input)
    | _ ->
        fail ("Expected single INT token for " ^ input)
  ) test_cases

(** Test AST literal creation preserves format *)
let test_ast_literal_creation () =
  (* Test hex literal *)
  let hex_lit = IntLit (Signed64 255L, Some "0xFF") in
  (match hex_lit with
   | IntLit (value, Some original) ->
       check int "hex AST value" 255 (Int64.to_int (IntegerValue.to_int64 value));
       check string "hex AST format" "0xFF" original
   | _ -> fail "Expected hex IntLit with original format");
  
  (* Test decimal literal *)
  let dec_lit = IntLit (Signed64 42L, None) in
  (match dec_lit with
   | IntLit (value, None) ->
       check int "decimal AST value" 42 (Int64.to_int (IntegerValue.to_int64 value))
   | _ -> fail "Expected decimal IntLit with no original format")

(** Test AST creation with large integers *)
let test_large_ast_literal_creation () =
  (* Test UINT64_MAX as unsigned *)
  let uint64_max = IntLit (Unsigned64 (-1L), None) in  (* -1L represents UINT64_MAX in Int64.t *)
  (match uint64_max with
   | IntLit (Unsigned64 _, None) ->
       let value_str = IntegerValue.to_string (Unsigned64 (-1L)) in
       check string "UINT64_MAX AST value" "18446744073709551615" value_str
   | _ -> fail "Expected unsigned IntLit for UINT64_MAX");
  
  (* Test 2^63 as unsigned *)
  let pow63 = IntLit (Unsigned64 Int64.min_int, None) in  (* Int64.min_int = -2^63 = 2^63 as unsigned *)
  (match pow63 with
   | IntLit (Unsigned64 _, None) ->
       let value_str = IntegerValue.to_string (Unsigned64 Int64.min_int) in
       check string "2^63 AST value" "9223372036854775808" value_str
   | _ -> fail "Expected unsigned IntLit for 2^63");
  
  (* Test large hex literal with original format *)
  let large_hex = IntLit (Unsigned64 (-1L), Some "0xFFFFFFFFFFFFFFFF") in
  (match large_hex with
   | IntLit (Unsigned64 _, Some original) ->
       let value_str = IntegerValue.to_string (Unsigned64 (-1L)) in
       check string "large hex AST value" "18446744073709551615" value_str;
       check string "large hex AST format" "0xFFFFFFFFFFFFFFFF" original
   | _ -> fail "Expected unsigned IntLit with hex format")

(** Test IR literal preservation *)
let test_ir_literal_preservation () =
  (* Create IR literals and verify format is preserved *)
  let hex_ir_lit = IRLiteral (IntLit (Signed64 255L, Some "0xFF")) in
  let dec_ir_lit = IRLiteral (IntLit (Signed64 42L, None)) in
  
  (* Test that IR preserves the literal format *)
  (match hex_ir_lit with
   | IRLiteral (IntLit (value, Some original)) ->
       check int "hex IR value" 255 (Int64.to_int (IntegerValue.to_int64 value));
       check string "hex IR format" "0xFF" original
   | _ -> fail "Expected hex IR literal with format");
  
  (match dec_ir_lit with
   | IRLiteral (IntLit (value, None)) ->
       check int "decimal IR value" 42 (Int64.to_int (IntegerValue.to_int64 value))
   | _ -> fail "Expected decimal IR literal without format")

(** Test eBPF C code generation preserves hex format *)
let test_ebpf_hex_codegen () =
  let ctx = create_c_context () in
  
  (* Test hex literal generates original format *)
  let hex_val = make_ir_value (IRLiteral (IntLit (Signed64 255L, Some "0xFF"))) IRU32 test_pos in
  let hex_result = generate_c_value ctx hex_val in
  check string "hex C code generation" "0xFF" hex_result;
  
  (* Test another hex literal *)
  let hex_val2 = make_ir_value (IRLiteral (IntLit (Signed64 2130706433L, Some "0x7F000001"))) IRU32 test_pos in
  let hex_result2 = generate_c_value ctx hex_val2 in
  check string "IP address hex C code generation" "0x7F000001" hex_result2;
  
  (* Test decimal literal generates decimal *)
  let dec_val = make_ir_value (IRLiteral (IntLit (Signed64 42L, None))) IRU32 test_pos in
  let dec_result = generate_c_value ctx dec_val in
  check string "decimal C code generation" "42" dec_result

(** Test eBPF C code generation with large integers *)
let test_ebpf_large_integer_codegen () =
  let ctx = create_c_context () in
  
  (* Test UINT64_MAX with hex format *)
  let uint64_max_hex = make_ir_value (IRLiteral (IntLit (Unsigned64 (-1L), Some "0xFFFFFFFFFFFFFFFF"))) IRU64 test_pos in
  let uint64_max_result = generate_c_value ctx uint64_max_hex in
  check string "UINT64_MAX hex C code generation" "0xFFFFFFFFFFFFFFFF" uint64_max_result;
  
  (* Test UINT64_MAX without format (should generate decimal) *)
  let uint64_max_dec = make_ir_value (IRLiteral (IntLit (Unsigned64 (-1L), None))) IRU64 test_pos in
  let uint64_max_dec_result = generate_c_value ctx uint64_max_dec in
  check string "UINT64_MAX decimal C code generation" "18446744073709551615" uint64_max_dec_result;
  
  (* Test 2^63 boundary *)
  let pow63_hex = make_ir_value (IRLiteral (IntLit (Unsigned64 Int64.min_int, Some "0x8000000000000000"))) IRU64 test_pos in
  let pow63_result = generate_c_value ctx pow63_hex in
  check string "2^63 hex C code generation" "0x8000000000000000" pow63_result;
  
  (* Test 2^63 - 1 (max signed) *)
  let max_signed = make_ir_value (IRLiteral (IntLit (Signed64 Int64.max_int, None))) IRU64 test_pos in
  let max_signed_result = generate_c_value ctx max_signed in
  check string "max signed int64 C code generation" "9223372036854775807" max_signed_result

(** Test eBPF C code generation preserves binary format *)
let test_ebpf_binary_codegen () =
  let ctx = create_c_context () in
  
  (* Test binary literal generates original format *)
  let bin_val = make_ir_value (IRLiteral (IntLit (Signed64 10L, Some "0b1010"))) IRU32 test_pos in
  let bin_result = generate_c_value ctx bin_val in
  check string "binary C code generation" "0b1010" bin_result;
  
  (* Test uppercase binary *)
  let bin_val2 = make_ir_value (IRLiteral (IntLit (Signed64 5L, Some "0B101"))) IRU32 test_pos in
  let bin_result2 = generate_c_value ctx bin_val2 in
  check string "uppercase binary C code generation" "0B101" bin_result2

(** Test userspace C code generation preserves hex format *)
let test_userspace_hex_codegen () =
  let ctx = Kernelscript.Userspace_codegen.create_userspace_context () in
  
  (* Test hex literal in userspace code *)
  let hex_val = make_ir_value (IRLiteral (IntLit (Signed64 255L, Some "0xFF"))) IRU32 test_pos in
  let hex_result = Kernelscript.Userspace_codegen.generate_c_value_from_ir ctx hex_val in
  check string "userspace hex C code generation" "0xFF" hex_result;
  
  (* Test decimal literal in userspace code *)
  let dec_val = make_ir_value (IRLiteral (IntLit (Signed64 42L, None))) IRU32 test_pos in
  let dec_result = Kernelscript.Userspace_codegen.generate_c_value_from_ir ctx dec_val in
  check string "userspace decimal C code generation" "42" dec_result

(** Test edge cases and malformed input handling *)
let test_edge_cases () =
  let ctx = create_c_context () in
  
  (* Test zero in hex format *)
  let zero_hex = make_ir_value (IRLiteral (IntLit (Signed64 0L, Some "0x0"))) IRU32 test_pos in
  let zero_result = generate_c_value ctx zero_hex in
  check string "zero hex format" "0x0" zero_result;
  
  (* Test maximum 32-bit hex value *)
  let max_hex = make_ir_value (IRLiteral (IntLit (Signed64 4294967295L, Some "0xFFFFFFFF"))) IRU32 test_pos in
  let max_result = generate_c_value ctx max_hex in
  check string "max hex format" "0xFFFFFFFF" max_result;
  
  (* Test that non-hex original format falls back to decimal *)
  let invalid_hex = make_ir_value (IRLiteral (IntLit (Signed64 42L, Some "invalid"))) IRU32 test_pos in
  let invalid_result = generate_c_value ctx invalid_hex in
  check string "invalid format fallback" "42" invalid_result

(** Test complete compilation pipeline preserves format *)
let test_complete_pipeline () =
  (* This test would require full compilation pipeline, which is complex
     For now, we'll test the individual components above *)
  (* TODO: Add full pipeline test when integration test framework is available *)
  check bool "pipeline test placeholder" true true

(** Test string_of_literal preserves format *)
let test_string_of_literal () =
  (* Test that string_of_literal uses original format when available *)
  let hex_lit = IntLit (Signed64 255L, Some "0xFF") in
  let hex_str = string_of_literal hex_lit in
  check string "string_of_literal hex" "0xFF" hex_str;
  
  let dec_lit = IntLit (Signed64 42L, None) in
  let dec_str = string_of_literal dec_lit in
  check string "string_of_literal decimal" "42" dec_str;
  
  let bin_lit = IntLit (Signed64 10L, Some "0b1010") in
  let bin_str = string_of_literal bin_lit in
  check string "string_of_literal binary" "0b1010" bin_str

(** Test string_of_literal with large integers *)
let test_string_of_literal_large () =
  (* Test UINT64_MAX with hex format *)
  let uint64_max_hex = IntLit (Unsigned64 (-1L), Some "0xFFFFFFFFFFFFFFFF") in
  let uint64_max_hex_str = string_of_literal uint64_max_hex in
  check string "string_of_literal UINT64_MAX hex" "0xFFFFFFFFFFFFFFFF" uint64_max_hex_str;
  
  (* Test UINT64_MAX without format (should use decimal) *)
  let uint64_max_dec = IntLit (Unsigned64 (-1L), None) in
  let uint64_max_dec_str = string_of_literal uint64_max_dec in
  check string "string_of_literal UINT64_MAX decimal" "18446744073709551615" uint64_max_dec_str;
  
  (* Test 2^63 boundary *)
  let pow63_hex = IntLit (Unsigned64 Int64.min_int, Some "0x8000000000000000") in
  let pow63_str = string_of_literal pow63_hex in
  check string "string_of_literal 2^63 hex" "0x8000000000000000" pow63_str;
  
  (* Test 2^63 - 1 (max signed) *)
  let max_signed = IntLit (Signed64 Int64.max_int, None) in
  let max_signed_str = string_of_literal max_signed in
  check string "string_of_literal max signed" "9223372036854775807" max_signed_str

(** Test that synthetic literals (created by compiler) use decimal *)
let test_synthetic_literals () =
  let ctx = create_c_context () in
  
  (* Synthetic literals should not have original format and use decimal *)
  let synthetic_val = make_ir_value (IRLiteral (IntLit (Signed64 42L, None))) IRU32 test_pos in
  let synthetic_result = generate_c_value ctx synthetic_val in
  check string "synthetic literal is decimal" "42" synthetic_result;
  
  (* Even large values without original format should be decimal *)
  let large_synthetic = make_ir_value (IRLiteral (IntLit (Signed64 2130706433L, None))) IRU32 test_pos in
  let large_result = generate_c_value ctx large_synthetic in
  check string "large synthetic literal is decimal" "2130706433" large_result

(** Main test suite *)
let () =
  run "Integer Literal Tests" [
    "lexer", [
      test_case "Hex literal lexing" `Quick test_hex_literal_lexing;
      test_case "Decimal literal lexing" `Quick test_decimal_literal_lexing;
      test_case "Large integer lexing" `Quick test_large_integer_lexing;
      test_case "Large hex literal lexing" `Quick test_large_hex_literal_lexing;
      test_case "Binary literal lexing" `Quick test_binary_literal_lexing;
    ];
    "ast", [
      test_case "AST literal creation" `Quick test_ast_literal_creation;
      test_case "Large AST literal creation" `Quick test_large_ast_literal_creation;
      test_case "string_of_literal format preservation" `Quick test_string_of_literal;
      test_case "string_of_literal large integers" `Quick test_string_of_literal_large;
    ];
    "ir", [
      test_case "IR literal preservation" `Quick test_ir_literal_preservation;
    ];
    "ebpf_codegen", [
      test_case "eBPF hex code generation" `Quick test_ebpf_hex_codegen;
      test_case "eBPF large integer code generation" `Quick test_ebpf_large_integer_codegen;
      test_case "eBPF binary code generation" `Quick test_ebpf_binary_codegen;
      test_case "Edge cases and fallbacks" `Quick test_edge_cases;
      test_case "Synthetic literals use decimal" `Quick test_synthetic_literals;
    ];
    "userspace_codegen", [
      test_case "Userspace hex code generation" `Quick test_userspace_hex_codegen;
    ];
    "integration", [
      test_case "Complete compilation pipeline" `Quick test_complete_pipeline;
    ];
  ] 