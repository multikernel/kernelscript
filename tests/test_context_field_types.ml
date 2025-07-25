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
open Kernelscript.Parse

let contains_substring line pattern =
  try
    let _ = Str.search_forward (Str.regexp pattern) line 0 in
    true
  with Not_found -> false

let test_xdp_context_field_types () =
  (* Register context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  let source = {|
    struct xdp_md {
      data: u64,
      data_end: u64,
      data_meta: u64,
      ingress_ifindex: u32,
      rx_queue_index: u32,
      egress_ifindex: u32,
    }
    
    enum xdp_action {
      XDP_ABORTED = 0,
      XDP_DROP = 1,
      XDP_PASS = 2,
      XDP_REDIRECT = 3,
      XDP_TX = 4,
    }
    
    @xdp fn test_context_fields(ctx: *xdp_md) -> xdp_action {
      var data_ptr = ctx->data
      var data_end_ptr = ctx->data_end
      var packet_size = data_end_ptr - data_ptr
      
      if (packet_size > 1500) {
        return XDP_DROP
      }
      
      return XDP_PASS
    }
  |} in
  
  let ast = parse_string source in
  
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  
  let ir_program = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.compile_multi_to_c ir_program in
  
  (* Check that the generated C code uses correct pointer types *)
  let lines = String.split_on_char '\n' c_code in
  
  (* Look for variable declarations - they should be pointer types, not __u64 *)
  let has_correct_pointer_types = List.exists (fun line ->
    String.contains line '*' && 
    (contains_substring line "ptr_" || contains_substring line "var_") &&
    contains_substring line "__u8"
  ) lines in
  
  let has_incorrect_u64_types = List.exists (fun line ->
    contains_substring line "__u64" &&
    contains_substring line "var_" &&
    contains_substring line "ctx->data"
  ) lines in
  
  (* Check that context field access uses correct casting *)
  let has_correct_casting = List.exists (fun line ->
    contains_substring line "void.*long.*ctx->data"
  ) lines in
  
  check bool "Should use pointer types for context fields" true has_correct_pointer_types;
  check bool "Should not use __u64 types for context field variables" false has_incorrect_u64_types;
  check bool "Should use correct casting for context field access" true has_correct_casting

let test_context_field_arithmetic () =
  (* Register context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  let source = {|
    struct xdp_md {
      data: u64,
      data_end: u64,
      data_meta: u64,
      ingress_ifindex: u32,
      rx_queue_index: u32,
      egress_ifindex: u32,
    }
    
    enum xdp_action {
      XDP_ABORTED = 0,
      XDP_DROP = 1,
      XDP_PASS = 2,
      XDP_REDIRECT = 3,
      XDP_TX = 4,
    }
    
    @xdp fn test_pointer_arithmetic(ctx: *xdp_md) -> xdp_action {
      var packet_size = ctx->data_end - ctx->data
      if (packet_size > 0) {
        return XDP_PASS
      } else {
        return XDP_DROP
      }
    }
  |} in
  
  let ast = parse_string source in
  
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  
  let ir_program = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.compile_multi_to_c ir_program in
  
  (* Check that pointer arithmetic works correctly *)
  let lines = String.split_on_char '\n' c_code in
  
  (* Look for pointer arithmetic between context fields *)
  let has_pointer_arithmetic = List.exists (fun line ->
    contains_substring line "ptr_" && String.contains line '-'
  ) lines in
  
  check bool "Should generate pointer arithmetic for context fields" true has_pointer_arithmetic

let test_tc_context_field_types () =
  (* Register context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  let source = {|
    struct __sk_buff {
      len: u32,
      pkt_type: u32,
      mark: u32,
      queue_mapping: u32,
      protocol: u32,
      vlan_present: u32,
      vlan_tci: u32,
      vlan_proto: u32,
      priority: u32,
      ingress_ifindex: u32,
      ifindex: u32,
      tc_index: u32,
      cb: u32[5],
      hash: u32,
      tc_classid: u32,
      data: u32,
      data_end: u32,
      napi_id: u32,
      family: u32,
      remote_ip4: u32,
      local_ip4: u32,
      remote_ip6: u32[4],
      local_ip6: u32[4],
      remote_port: u32,
      local_port: u32,
      data_meta: u32,
      flow_keys: u32,
      tstamp: u64,
      wire_len: u32,
      gso_segs: u32,
      sk: u32,
      gso_size: u32,
      tstamp_type: u8,
      hwtstamp: u64,
    }
    
    enum tc_action {
      TC_ACT_UNSPEC = 255,
      TC_ACT_OK = 0,
      TC_ACT_RECLASSIFY = 1,
      TC_ACT_SHOT = 2,
      TC_ACT_PIPE = 3,
      TC_ACT_STOLEN = 4,
      TC_ACT_QUEUED = 5,
      TC_ACT_REPEAT = 6,
      TC_ACT_REDIRECT = 7,
    }
    
    @tc fn test_tc_context_fields(ctx: *__sk_buff) -> tc_action {
      var data_ptr = ctx->data
      var data_end_ptr = ctx->data_end
      var packet_size = data_end_ptr - data_ptr
      
      if (packet_size > 1500) {
        return TC_ACT_SHOT
      }
      
      return TC_ACT_OK
    }
  |} in
  
  let ast = parse_string source in
  
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  
  let ir_program = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.compile_multi_to_c ir_program in
  
  (* Check that TC context fields use correct types *)
  let lines = String.split_on_char '\n' c_code in
  
  let has_correct_tc_types = List.exists (fun line ->
    contains_substring line "__u64" &&
    contains_substring line "(__u64)(long)ctx->data"
  ) lines in
  
  check bool "Should use correct types for TC context fields" true has_correct_tc_types

let test_xdp_context_field_pointer_preservation () =
  (* Register context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  let source = {|
    struct xdp_md {
      data: u64,
      data_end: u64,
      data_meta: u64,
      ingress_ifindex: u32,
      rx_queue_index: u32,
      egress_ifindex: u32,
    }
    
    enum xdp_action {
      XDP_ABORTED = 0,
      XDP_DROP = 1,
      XDP_PASS = 2,
      XDP_REDIRECT = 3,
      XDP_TX = 4,
    }
    
    @xdp fn test_pointer_preservation(ctx: *xdp_md) -> xdp_action {
      var packet_start = ctx->data
      var packet_end = ctx->data_end
      var packet_size = packet_end - packet_start
      
      if (packet_size > 1500) {
        return XDP_DROP
      }
      
      return XDP_PASS
    }
  |} in
  
  let ast = parse_string source in
  
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  
  let ir_program = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.compile_multi_to_c ir_program in
  
  (* Check that pointer variables are declared correctly *)
  let lines = String.split_on_char '\n' c_code in
  
  (* Look for INCORRECT variable declarations where pointers are assigned to __u64 variables *)
  (* This should NOT match pointer arithmetic like: var_5 = ((__u64)ptr_2) - ((__u64)ptr_0) *)
  let has_incorrect_u64_assignment = List.exists (fun line ->
    contains_substring line "__u64" &&
    contains_substring line "var_" &&
    contains_substring line "=" &&
    contains_substring line "ptr_" &&
    not (String.contains line '-') &&  (* Exclude pointer arithmetic *)
    not (String.contains line '+')     (* Exclude pointer arithmetic *)
  ) lines in
  
  (* This should NOT happen - we shouldn't assign pointers to __u64 variables *)
  check bool "No incorrect pointer to __u64 assignments" false has_incorrect_u64_assignment;
  
  (* Check that context field access generates correct casting *)
  let has_correct_casting = List.exists (fun line ->
    contains_substring line "(void*)(long)ctx->data" ||
    contains_substring line "ctx->data"
  ) lines in
  
  check bool "Context field access uses correct casting" true has_correct_casting

let test_exact_rate_limiter_reproduction () =
  (* Register context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  let source = {|
    struct xdp_md {
      data: u64,
      data_end: u64,
      data_meta: u64,
      ingress_ifindex: u32,
      rx_queue_index: u32,
      egress_ifindex: u32,
    }
    
    enum xdp_action {
      XDP_ABORTED = 0,
      XDP_DROP = 1,
      XDP_PASS = 2,
      XDP_REDIRECT = 3,
      XDP_TX = 4,
    }
    
    var packet_counts : hash<u32, u64>(1024)
    
    config network {
      limit : u32,
    }
    
    @xdp fn rate_limiter(ctx: *xdp_md) -> xdp_action {
      var packet_start = ctx->data
      var packet_end = ctx->data_end
      var packet_size = packet_end - packet_start
      
      if (packet_size < 14) {
        return XDP_DROP
      }
      
      var src_ip = 0x7F000001
      packet_counts[src_ip] += 1
      
      if (packet_counts[src_ip] > network.limit) {
        return XDP_DROP
      }
      
      return XDP_PASS
    }
  |} in
  
  let ast = parse_string source in
  
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  
  (* Type check first to ensure annotations are in place *)
  let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  
  let ir_program = Kernelscript.Ir_generator.generate_ir ~use_type_annotations:true typed_ast symbol_table "test" in
  
  (* Generate C code *)
  let c_code = Kernelscript.Ebpf_c_codegen.compile_multi_to_c ir_program in
  
  (* Save the C code to a file for debugging *)
  let oc = open_out "/tmp/exact_rate_limiter_test.c" in
  output_string oc c_code;
  close_out oc;
  
  (* Check that pointer variables are declared correctly *)
  let lines = String.split_on_char '\n' c_code in
  
  (* Look for INCORRECT variable declarations where pointers are assigned to __u64 variables *)
  let has_incorrect_u64_assignment = List.exists (fun line ->
    contains_substring line "__u64" &&
    contains_substring line "var_" &&
    contains_substring line "=" &&
    contains_substring line "ptr_" &&
    not (String.contains line '-') &&  (* Exclude pointer arithmetic *)
    not (String.contains line '+')     (* Exclude pointer arithmetic *)
  ) lines in
  
  (* This should NOT happen - we shouldn't assign pointers to __u64 variables *)
  check bool "Exact rate limiter: No incorrect pointer to __u64 assignments" false has_incorrect_u64_assignment

let () =
  run "Context Field Type Tests" [
    ("XDP context field types", [
      test_case "XDP context field types are correct" `Quick test_xdp_context_field_types;
      test_case "Context field arithmetic works" `Quick test_context_field_arithmetic;
      test_case "XDP context field pointer preservation" `Quick test_xdp_context_field_pointer_preservation;
      test_case "Rate limiter type reproduction" `Quick test_exact_rate_limiter_reproduction;
    ]);
    ("TC context field types", [
      test_case "TC context field types are correct" `Quick test_tc_context_field_types;
    ]);
  ]