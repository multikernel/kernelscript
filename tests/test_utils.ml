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

(** Test Utilities for KernelScript Unit Tests
    
    This module provides common types and helper functions for unit tests,
    replacing the need for parsing builtin .ks files. Since we now use BTF
    parsing in production, tests should use these hardcoded types for
    consistency and speed.
*)

open Kernelscript.Ast

(** Common test position for when position doesn't matter *)
let test_pos = make_position 1 1 "test.ks"

(** XDP-related test types and constants *)
module Xdp = struct
  (** XDP action enum values *)
  let action_constants = [
    ("XDP_ABORTED", Some (Signed64 0L));
    ("XDP_DROP", Some (Signed64 1L));
    ("XDP_PASS", Some (Signed64 2L));
    ("XDP_TX", Some (Signed64 3L));
    ("XDP_REDIRECT", Some (Signed64 4L));
  ]
  
  (** XDP context struct fields *)
  let context_fields = [
    ("data", Pointer U8);
    ("data_end", Pointer U8);
    ("data_meta", Pointer U8);
    ("ingress_ifindex", U32);
    ("rx_queue_index", U32);
    ("egress_ifindex", U32);
  ]
  
  (** Create XDP action enum AST *)
  let dummy_pos = { line = 1; column = 1; filename = "test" }
  let action_enum = TypeDef (EnumDef ("xdp_action", action_constants, dummy_pos))
  
  (** Create XDP context struct AST *)
  let context_struct = TypeDef (StructDef ("xdp_md", context_fields, dummy_pos))
  
  (** All XDP builtin AST declarations *)
  let builtin_ast = [action_enum; context_struct]
end

(** TC-related test types and constants *)
module Tc = struct
  (** TC action constants as enum values *)
  let action_constants = [
    ("TC_ACT_UNSPEC", Some (Signed64 (-1L)));
    ("TC_ACT_OK", Some (Signed64 0L));
    ("TC_ACT_RECLASSIFY", Some (Signed64 1L));
    ("TC_ACT_SHOT", Some (Signed64 2L));
    ("TC_ACT_PIPE", Some (Signed64 3L));
    ("TC_ACT_STOLEN", Some (Signed64 4L));
    ("TC_ACT_QUEUED", Some (Signed64 5L));
    ("TC_ACT_REPEAT", Some (Signed64 6L));
    ("TC_ACT_REDIRECT", Some (Signed64 7L));
    ("TC_ACT_TRAP", Some (Signed64 8L));
  ]
  
  (** TC context struct fields for __sk_buff *)
  let context_fields = [
    ("data", Pointer U8);
    ("data_end", Pointer U8);
    ("len", U32);
    ("pkt_type", U32);
    ("mark", U32);
    ("queue_mapping", U32);
    ("protocol", U32);
    ("vlan_present", U32);
    ("vlan_tci", U32);
    ("vlan_proto", U32);
    ("priority", U32);
    ("ingress_ifindex", U32);
    ("ifindex", U32);
    ("tc_index", U32);
    ("cb", Array (U32, 5));
    ("hash", U32);
    ("tc_classid", U32);
  ]
  
  (** Create TC action enum AST *)
  let dummy_pos = { line = 1; column = 1; filename = "test" }
  let action_enum = TypeDef (EnumDef ("tc_action", action_constants, dummy_pos))
  
  (** Create TC context struct AST for __sk_buff *)
  let context_struct = TypeDef (StructDef ("__sk_buff", context_fields, dummy_pos))
  
  (** All TC builtin AST declarations *)
  let builtin_ast = [action_enum; context_struct]
end

(** Struct_ops-related test types and constants *)
module StructOps = struct
  (** TCP congestion control operations struct fields *)
  let tcp_congestion_ops_fields = [
    ("ssthresh", Function ([Pointer U8], U32));
    ("cong_avoid", Function ([Pointer U8; U32; U32], Void));
    ("slow_start", Function ([Pointer U8], Void));
    ("cong_control", Function ([Pointer U8; U32; U32], Void));
    ("name", Pointer U8);
    ("owner", Pointer U8);
  ]
  
  (** BPF iterator operations struct fields *)
  let bpf_iter_ops_fields = [
    ("seq_start", Function ([Pointer U8; Pointer U64], Pointer U8));
    ("seq_next", Function ([Pointer U8; Pointer U8; Pointer U64], Pointer U8));
    ("seq_stop", Function ([Pointer U8; Pointer U8], Void));
    ("seq_show", Function ([Pointer U8; Pointer U8], I32));
  ]
  
  (** BPF struct_ops test operations struct fields *)
  let bpf_struct_ops_test_fields = [
    ("test_1", Function ([I32], I32));
    ("test_2", Function ([I32; I32], I32));
  ]
  
  (** Sched-ext operations struct fields *)
  let sched_ext_ops_fields = [
    ("select_cpu", Function ([Pointer U8; I32; U64], I32));
    ("enqueue", Function ([Pointer U8; U64], Void));
    ("dispatch", Function ([I32; Pointer U8], Void));
    ("runnable", Function ([Pointer U8; U64], Void));
    ("running", Function ([Pointer U8], Void));
    ("stopping", Function ([Pointer U8; Bool], Void));
    ("quiescent", Function ([Pointer U8; U64], Void));
    ("init_task", Function ([Pointer U8; Pointer U8], I32));
    ("exit_task", Function ([Pointer U8; Pointer U8], Void));
    ("enable", Function ([Pointer U8], Void));
    ("cancel", Function ([Pointer U8; Pointer U8], Bool));
    ("init", Function ([], I32));
    ("exit", Function ([Pointer U8], Void));
    ("name", Pointer U8);
    ("timeout_ms", U64);
    ("flags", U64);
  ]
  
  (** Create TCP congestion ops struct AST *)
  let tcp_congestion_ops_struct = 
    StructDecl {
      struct_name = "tcp_congestion_ops";
      struct_fields = tcp_congestion_ops_fields;
      struct_pos = test_pos;
      struct_attributes = [AttributeWithArg ("struct_ops", "tcp_congestion_ops")];
    }
  
  (** Create BPF iterator ops struct AST *)
  let bpf_iter_ops_struct = 
    StructDecl {
      struct_name = "bpf_iter_ops";
      struct_fields = bpf_iter_ops_fields;
      struct_pos = test_pos;
      struct_attributes = [AttributeWithArg ("struct_ops", "bpf_iter_ops")];
    }
  
  (** Create BPF struct_ops test struct AST *)
  let bpf_struct_ops_test_struct = 
    StructDecl {
      struct_name = "bpf_struct_ops_test";
      struct_fields = bpf_struct_ops_test_fields;
      struct_pos = test_pos;
      struct_attributes = [AttributeWithArg ("struct_ops", "bpf_struct_ops_test")];
    }
  
  (** Create sched-ext ops struct AST *)
  let sched_ext_ops_struct = 
    StructDecl {
      struct_name = "sched_ext_ops";
      struct_fields = sched_ext_ops_fields;
      struct_pos = test_pos;
      struct_attributes = [AttributeWithArg ("struct_ops", "sched_ext_ops")];
    }
  
  (** All struct_ops builtin AST declarations *)
  let builtin_ast = [
    tcp_congestion_ops_struct;
    bpf_iter_ops_struct;
    bpf_struct_ops_test_struct;
    sched_ext_ops_struct;
  ]
end

(** Helper functions for creating test AST nodes *)
module Helpers = struct
  (** Create a simple test function *)
  let make_test_function name params return_type body =
    {
      func_name = name;
      func_params = params;
      func_return_type = return_type;
      func_body = body;
      func_scope = Userspace;
      func_pos = test_pos;
      tail_call_targets = [];
      is_tail_callable = false;
    }
  
  (** Create a simple test program *)
  let make_test_program name prog_type main_func =
    {
      prog_name = name;
      prog_target = None;
      prog_type = prog_type;
      prog_functions = [main_func];
      prog_maps = [];
      prog_structs = [];
      prog_pos = test_pos;
    }
  
  (** Create symbol table with test builtin types *)
  let create_test_symbol_table ?(include_xdp=true) ?(include_tc=true) ?(include_struct_ops=true) ast =
    (* Register context codegens for tests *)
    if include_xdp then Kernelscript_context.Xdp_codegen.register ();
    if include_tc then Kernelscript_context.Tc_codegen.register ();
    
    let builtin_asts = 
      (if include_xdp then [Xdp.builtin_ast] else []) @
      (if include_tc then [Tc.builtin_ast] else []) @
      (if include_struct_ops then [StructOps.builtin_ast] else [])
    in
    let table = Kernelscript.Symbol_table.create_symbol_table () in
    (* Process builtin ASTs first *)
    List.iter (List.iter (Kernelscript.Symbol_table.process_declaration table)) builtin_asts;
    (* Then process the main AST *)
    List.iter (Kernelscript.Symbol_table.process_declaration table) ast;
    table
  
  (** Create a type checking context with test builtin types *)
  let create_test_type_context ?(include_xdp=true) ?(include_tc=true) ?(include_struct_ops=true) ast =
    let symbol_table = create_test_symbol_table ~include_xdp ~include_tc ~include_struct_ops ast in
    let combined_ast = ast @ (if include_struct_ops then StructOps.builtin_ast else []) in
    Kernelscript.Type_checker.create_context symbol_table combined_ast
end

(** All builtin AST declarations for comprehensive testing *)
let all_builtin_ast = Xdp.builtin_ast @ Tc.builtin_ast @ StructOps.builtin_ast

(** Get builtin AST for a specific program type *)
let get_builtin_ast_for_program_type = function
  | Xdp -> Xdp.builtin_ast
  | Tc -> Tc.builtin_ast
  | _ -> [] (* Other program types don't have builtin definitions yet *) 