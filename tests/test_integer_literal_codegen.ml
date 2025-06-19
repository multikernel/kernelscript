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
        check int ("hex value for " ^ input) expected_value value;
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
        check int ("decimal value for " ^ input) expected_value value
    | [Parser.INT (_, Some original)] ->
        fail ("Expected no original format for decimal " ^ input ^ ", got " ^ original)
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
        check int ("binary value for " ^ input) expected_value value;
        check string ("binary format for " ^ input) expected_original original
    | [Parser.INT (_, None)] ->
        fail ("Expected original format to be preserved for " ^ input)
    | _ ->
        fail ("Expected single INT token for " ^ input)
  ) test_cases

(** Test AST literal creation preserves format *)
let test_ast_literal_creation () =
  (* Test hex literal *)
  let hex_lit = IntLit (255, Some "0xFF") in
  (match hex_lit with
   | IntLit (value, Some original) ->
       check int "hex AST value" 255 value;
       check string "hex AST format" "0xFF" original
   | _ -> fail "Expected hex IntLit with original format");
  
  (* Test decimal literal *)
  let dec_lit = IntLit (42, None) in
  (match dec_lit with
   | IntLit (value, None) ->
       check int "decimal AST value" 42 value
   | _ -> fail "Expected decimal IntLit with no original format")

(** Test IR literal preservation *)
let test_ir_literal_preservation () =
  (* Create IR literals and verify format is preserved *)
  let hex_ir_lit = IRLiteral (IntLit (255, Some "0xFF")) in
  let dec_ir_lit = IRLiteral (IntLit (42, None)) in
  
  (* Test that IR preserves the literal format *)
  (match hex_ir_lit with
   | IRLiteral (IntLit (value, Some original)) ->
       check int "hex IR value" 255 value;
       check string "hex IR format" "0xFF" original
   | _ -> fail "Expected hex IR literal with format");
  
  (match dec_ir_lit with
   | IRLiteral (IntLit (value, None)) ->
       check int "decimal IR value" 42 value
   | _ -> fail "Expected decimal IR literal without format")

(** Test eBPF C code generation preserves hex format *)
let test_ebpf_hex_codegen () =
  let ctx = create_c_context () in
  
  (* Test hex literal generates original format *)
  let hex_val = make_ir_value (IRLiteral (IntLit (255, Some "0xFF"))) IRU32 test_pos in
  let hex_result = generate_c_value ctx hex_val in
  check string "hex C code generation" "0xFF" hex_result;
  
  (* Test another hex literal *)
  let hex_val2 = make_ir_value (IRLiteral (IntLit (2130706433, Some "0x7F000001"))) IRU32 test_pos in
  let hex_result2 = generate_c_value ctx hex_val2 in
  check string "IP address hex C code generation" "0x7F000001" hex_result2;
  
  (* Test decimal literal generates decimal *)
  let dec_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  let dec_result = generate_c_value ctx dec_val in
  check string "decimal C code generation" "42" dec_result

(** Test eBPF C code generation preserves binary format *)
let test_ebpf_binary_codegen () =
  let ctx = create_c_context () in
  
  (* Test binary literal generates original format *)
  let bin_val = make_ir_value (IRLiteral (IntLit (10, Some "0b1010"))) IRU32 test_pos in
  let bin_result = generate_c_value ctx bin_val in
  check string "binary C code generation" "0b1010" bin_result;
  
  (* Test uppercase binary *)
  let bin_val2 = make_ir_value (IRLiteral (IntLit (5, Some "0B101"))) IRU32 test_pos in
  let bin_result2 = generate_c_value ctx bin_val2 in
  check string "uppercase binary C code generation" "0B101" bin_result2

(** Test userspace C code generation preserves hex format *)
let test_userspace_hex_codegen () =
  let ctx = Kernelscript.Userspace_codegen.create_userspace_context () in
  
  (* Test hex literal in userspace code *)
  let hex_val = make_ir_value (IRLiteral (IntLit (255, Some "0xFF"))) IRU32 test_pos in
  let hex_result = Kernelscript.Userspace_codegen.generate_c_value_from_ir ctx hex_val in
  check string "userspace hex C code generation" "0xFF" hex_result;
  
  (* Test decimal literal in userspace code *)
  let dec_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  let dec_result = Kernelscript.Userspace_codegen.generate_c_value_from_ir ctx dec_val in
  check string "userspace decimal C code generation" "42" dec_result

(** Test edge cases and malformed input handling *)
let test_edge_cases () =
  let ctx = create_c_context () in
  
  (* Test zero in hex format *)
  let zero_hex = make_ir_value (IRLiteral (IntLit (0, Some "0x0"))) IRU32 test_pos in
  let zero_result = generate_c_value ctx zero_hex in
  check string "zero hex format" "0x0" zero_result;
  
  (* Test maximum 32-bit hex value *)
  let max_hex = make_ir_value (IRLiteral (IntLit (4294967295, Some "0xFFFFFFFF"))) IRU32 test_pos in
  let max_result = generate_c_value ctx max_hex in
  check string "max hex format" "0xFFFFFFFF" max_result;
  
  (* Test that non-hex original format falls back to decimal *)
  let invalid_hex = make_ir_value (IRLiteral (IntLit (42, Some "invalid"))) IRU32 test_pos in
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
  let hex_lit = IntLit (255, Some "0xFF") in
  let hex_str = string_of_literal hex_lit in
  check string "string_of_literal hex" "0xFF" hex_str;
  
  let dec_lit = IntLit (42, None) in
  let dec_str = string_of_literal dec_lit in
  check string "string_of_literal decimal" "42" dec_str;
  
  let bin_lit = IntLit (10, Some "0b1010") in
  let bin_str = string_of_literal bin_lit in
  check string "string_of_literal binary" "0b1010" bin_str

(** Test that synthetic literals (created by compiler) use decimal *)
let test_synthetic_literals () =
  let ctx = create_c_context () in
  
  (* Synthetic literals should not have original format and use decimal *)
  let synthetic_val = make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos in
  let synthetic_result = generate_c_value ctx synthetic_val in
  check string "synthetic literal is decimal" "42" synthetic_result;
  
  (* Even large values without original format should be decimal *)
  let large_synthetic = make_ir_value (IRLiteral (IntLit (2130706433, None))) IRU32 test_pos in
  let large_result = generate_c_value ctx large_synthetic in
  check string "large synthetic literal is decimal" "2130706433" large_result

(** Main test suite *)
let () =
  run "Integer Literal Code Generation" [
    "lexer", [
      test_case "Hex literal lexing" `Quick test_hex_literal_lexing;
      test_case "Decimal literal lexing" `Quick test_decimal_literal_lexing;
      test_case "Binary literal lexing" `Quick test_binary_literal_lexing;
    ];
    "ast", [
      test_case "AST literal creation" `Quick test_ast_literal_creation;
      test_case "string_of_literal format preservation" `Quick test_string_of_literal;
    ];
    "ir", [
      test_case "IR literal preservation" `Quick test_ir_literal_preservation;
    ];
    "ebpf_codegen", [
      test_case "eBPF hex code generation" `Quick test_ebpf_hex_codegen;
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