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
    ("XDP_ABORTED", Some 0);
    ("XDP_DROP", Some 1);
    ("XDP_PASS", Some 2);
    ("XDP_TX", Some 3);
    ("XDP_REDIRECT", Some 4);
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
  let action_enum = TypeDef (EnumDef ("xdp_action", action_constants))
  
  (** Create XDP context struct AST *)
  let context_struct = TypeDef (StructDef ("xdp_md", context_fields))
  
  (** All XDP builtin AST declarations *)
  let builtin_ast = [action_enum; context_struct]
end

(** TC-related test types and constants *)
module Tc = struct
  (** TC action enum values *)
  let action_constants = [
    ("TC_ACT_UNSPEC", Some 255);
    ("TC_ACT_OK", Some 0);
    ("TC_ACT_RECLASSIFY", Some 1);
    ("TC_ACT_SHOT", Some 2);
    ("TC_ACT_PIPE", Some 3);
    ("TC_ACT_STOLEN", Some 4);
    ("TC_ACT_QUEUED", Some 5);
    ("TC_ACT_REPEAT", Some 6);
    ("TC_ACT_REDIRECT", Some 7);
  ]
  
  (** TC context struct fields *)
  let context_fields = [
    ("data", U32);
    ("data_end", U32);
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
  let action_enum = TypeDef (EnumDef ("TcAction", action_constants))
  
  (** Create TC context struct AST *)
  let context_struct = TypeDef (StructDef ("TcContext", context_fields))
  
  (** All TC builtin AST declarations *)
  let builtin_ast = [action_enum; context_struct]
end

(** Kprobe-related test types and constants *)
module Kprobe = struct
  (** Kprobe action enum values *)
  let action_constants = [
    ("KPROBE_CONTINUE", Some 0);
    ("KPROBE_FAULT", Some 1);
  ]
  
  (** Kprobe context struct fields *)
  let context_fields = [
    ("regs", Array (U64, 21));
    ("ip", U64);
    ("cs", U64);
    ("flags", U64);
    ("sp", U64);
    ("ss", U64);
  ]
  
  (** Create Kprobe action enum AST *)
  let action_enum = TypeDef (EnumDef ("KprobeAction", action_constants))
  
  (** Create Kprobe context struct AST *)
  let context_struct = TypeDef (StructDef ("KprobeContext", context_fields))
  
  (** All Kprobe builtin AST declarations *)
  let builtin_ast = [action_enum; context_struct]
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
      prog_type = prog_type;
      prog_functions = [main_func];
      prog_maps = [];
      prog_structs = [];
      prog_pos = test_pos;
    }
  
  (** Create symbol table with test builtin types *)
  let create_test_symbol_table ?(include_xdp=true) ?(include_tc=true) ?(include_kprobe=true) ast =
    let builtin_asts = 
      (if include_xdp then [Xdp.builtin_ast] else []) @
      (if include_tc then [Tc.builtin_ast] else []) @
      (if include_kprobe then [Kprobe.builtin_ast] else [])
    in
    let table = Kernelscript.Symbol_table.create_symbol_table () in
    (* Process builtin ASTs first *)
    List.iter (List.iter (Kernelscript.Symbol_table.process_declaration table)) builtin_asts;
    (* Then process the main AST *)
    List.iter (Kernelscript.Symbol_table.process_declaration table) ast;
    table
  
  (** Create a type checking context with test builtin types *)
  let create_test_type_context ?(include_xdp=true) ?(include_tc=true) ?(include_kprobe=true) ast =
    let symbol_table = create_test_symbol_table ~include_xdp ~include_tc ~include_kprobe ast in
    Kernelscript.Type_checker.create_context symbol_table ast
end

(** All builtin AST declarations for comprehensive testing *)
let all_builtin_ast = Xdp.builtin_ast @ Tc.builtin_ast @ Kprobe.builtin_ast

(** Get builtin AST for a specific program type *)
let get_builtin_ast_for_program_type = function
  | Xdp -> Xdp.builtin_ast
  | Tc -> Tc.builtin_ast
  | Kprobe -> Kprobe.builtin_ast
  | _ -> [] (* Other program types don't have builtin definitions yet *) 