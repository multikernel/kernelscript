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

(** Tests for Nested If Statement Code Generation Fix *)

open Alcotest
open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Ebpf_c_codegen

(** Helper to create test position *)
let test_pos = { line = 1; column = 1; filename = "test.ks" }

(** Helper to check if string contains substring *)
let contains_substr str substr =
  try 
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in 
    true
  with Not_found -> false

(** Test that IRIf instructions generate structured C code without goto *)
let test_irif_structured_generation () =
  let ctx = create_c_context () in
  
  (* Create nested IRIf instructions manually *)
  let inner_cond = make_ir_value (IRLiteral (BoolLit false)) IRBool test_pos in
  let inner_return = make_ir_instruction (IRReturn (Some (make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos))) test_pos in
  let inner_if = make_ir_instruction (IRIf (inner_cond, [inner_return], None)) test_pos in
  
  let outer_cond = make_ir_value (IRLiteral (BoolLit true)) IRBool test_pos in
  let outer_if = make_ir_instruction (IRIf (outer_cond, [inner_if], None)) test_pos in
  
  (* Generate C code *)
  generate_c_instruction ctx outer_if;
  let generated_c = String.concat "\n" ctx.output_lines in
  
  (* Test assertions *)
  check bool "No goto statements" false (contains_substr generated_c "goto");
  check bool "No then_ labels" false (contains_substr generated_c "then_");
  check bool "No else_ labels" false (contains_substr generated_c "else_");
  check bool "No merge_ labels" false (contains_substr generated_c "merge_");
  check bool "Contains if statements" true (contains_substr generated_c "if (");
  check bool "Contains braces" true (contains_substr generated_c "{");
  check bool "Contains return" true (contains_substr generated_c "return 42")

(** Test the original problematic case from examples/test_config.ks *)
let test_config_case () =
  (* Initialize XDP context *)
  Kernelscript_context.Xdp_codegen.register ();
  
  let program_text = {|
config network {
    max_packet_size: u32 = 1500,
    enable_logging: bool = true,
}

var packet_stats : hash<u32, u64>(1024)

@xdp fn packet_filter(ctx: *xdp_md) -> xdp_action {
    if (network.max_packet_size > 1000) {
        if (network.enable_logging) {
            print("Dropping big packets")
            return XDP_DROP
        }
    }
    packet_stats[0] = 1
    return XDP_PASS
}
|} in
  
  try
    let ast = Kernelscript.Parse.parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "packet_filter" in
    let generated_c = generate_c_multi_program ir in
    
    (* Test assertions *)
    check bool "No goto statements" false (contains_substr generated_c "goto");
    check bool "No cond_ labels" false (contains_substr generated_c "cond_");
    check bool "No then_ labels" false (contains_substr generated_c "then_");
    check bool "Contains structured if" true (contains_substr generated_c "if (");
    check bool "Contains print" true (contains_substr generated_c "bpf_printk");
    check bool "Contains message" true (contains_substr generated_c "Dropping big packets");
    check bool "Contains XDP_DROP" true (contains_substr generated_c "return XDP_DROP");
    check bool "Contains XDP_PASS" true (contains_substr generated_c "return XDP_PASS")
  with
  | exn -> fail ("Test failed: " ^ Printexc.to_string exn)

(** Test deeply nested if statements *)
let test_deep_nesting () =
  let ctx = create_c_context () in
  
  (* Create 3-level nested IRIf instructions *)
  let deepest_cond = make_ir_value (IRLiteral (BoolLit true)) IRBool test_pos in
  let deepest_return = make_ir_instruction (IRReturn (Some (make_ir_value (IRLiteral (IntLit (123, None))) IRU32 test_pos))) test_pos in
  let deepest_if = make_ir_instruction (IRIf (deepest_cond, [deepest_return], None)) test_pos in
  
  let middle_cond = make_ir_value (IRLiteral (BoolLit false)) IRBool test_pos in
  let middle_if = make_ir_instruction (IRIf (middle_cond, [deepest_if], None)) test_pos in
  
  let outer_cond = make_ir_value (IRLiteral (BoolLit true)) IRBool test_pos in
  let outer_if = make_ir_instruction (IRIf (outer_cond, [middle_if], None)) test_pos in
  
  (* Generate C code *)
  generate_c_instruction ctx outer_if;
  let generated_c = String.concat "\n" ctx.output_lines in
  
  (* Test assertions *)
  check bool "No goto in deep nesting" false (contains_substr generated_c "goto");
  check bool "No labels in deep nesting" false (contains_substr generated_c "then_");
  check bool "Contains return 123" true (contains_substr generated_c "return 123")

(** Test if-else statements *)
let test_if_else () =
  let ctx = create_c_context () in
  
  (* Create if-else with nested if in else branch *)
  let else_cond = make_ir_value (IRLiteral (BoolLit true)) IRBool test_pos in
  let else_return = make_ir_instruction (IRReturn (Some (make_ir_value (IRLiteral (IntLit (456, None))) IRU32 test_pos))) test_pos in
  let else_inner_if = make_ir_instruction (IRIf (else_cond, [else_return], None)) test_pos in
  
  let main_cond = make_ir_value (IRLiteral (BoolLit false)) IRBool test_pos in
  let then_return = make_ir_instruction (IRReturn (Some (make_ir_value (IRLiteral (IntLit (789, None))) IRU32 test_pos))) test_pos in
  let main_if = make_ir_instruction (IRIf (main_cond, [then_return], Some [else_inner_if])) test_pos in
  
  (* Generate C code *)
  generate_c_instruction ctx main_if;
  let generated_c = String.concat "\n" ctx.output_lines in
  
  (* Test assertions *)
  check bool "No goto in if-else" false (contains_substr generated_c "goto");
  check bool "Contains else keyword" true (contains_substr generated_c "} else {");
  check bool "Contains return 789" true (contains_substr generated_c "return 789");
  check bool "Contains return 456" true (contains_substr generated_c "return 456")

(** All tests *)
let tests = [
  "irif_structured_generation", `Quick, test_irif_structured_generation;
  "deep_nesting", `Quick, test_deep_nesting;
  "if_else", `Quick, test_if_else;
]

let () =
  run "Nested If Code Generation Tests" [
    "nested_if_codegen", tests;
  ] 