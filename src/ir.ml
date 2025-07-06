(** Intermediate Representation for KernelScript
    This module defines the IR that serves as the bridge between the AST and
    both eBPF bytecode generation and userspace binding generation.
*)

open Ast

(** Position information preserved from AST *)
type ir_position = position

(** Multi-program IR - complete compilation unit with multiple eBPF programs *)
type ir_multi_program = {
  source_name: string; (* Base name of source file *)
  programs: ir_program list; (* List of eBPF programs *)
  kernel_functions: ir_function list; (* Kernel functions shared across all programs *)
  global_maps: ir_map_def list; (* Maps shared across programs *)
  global_configs: ir_global_config list; (* Named configuration blocks *)
  global_variables: ir_global_variable list; (* Global variables shared across programs *)
  struct_ops_declarations: ir_struct_ops_declaration list; (* Struct_ops type declarations *)
  struct_ops_instances: ir_struct_ops_instance list; (* Struct_ops instances *)
  userspace_program: ir_userspace_program option; (* IR-based userspace program *)
  userspace_bindings: ir_userspace_binding list; (* Generated bindings *)
  multi_pos: ir_position;
}

(** Program-level IR - single eBPF program representation *)
and ir_program = {
  name: string;
  program_type: program_type;
  entry_function: ir_function; (* The attributed function that serves as the entry point *)
  ir_pos: ir_position;
}

(** Userspace Program IR - complete userspace program with coordinator logic *)
and ir_userspace_program = {
  userspace_functions: ir_function list; (* All userspace functions including main *)
  userspace_structs: ir_struct_def list; (* Userspace struct definitions *)
  userspace_configs: ir_userspace_config list; (* Userspace configuration *)
  coordinator_logic: ir_coordinator_logic; (* BPF management and coordination logic *)
  userspace_pos: ir_position;
}

(** Simplified coordinator logic for BPF program management *)
and ir_coordinator_logic = {
  setup_logic: ir_instruction list; (* Combined setup: maps + programs *)
  event_processing: ir_instruction list; (* Simplified event loop *)
  cleanup_logic: ir_instruction list; (* Combined cleanup *)
  config_management: ir_config_management; (* Handle named configs *)
}

and ir_config_management = {
  config_loads: (string * ir_instruction list) list; (* config_name -> load instructions *)
  config_updates: (string * ir_instruction list) list; (* config_name -> update instructions *)
  runtime_config_sync: ir_instruction list; (* Sync configs between userspace/kernel *)
}

and ir_map_management = {
  setup_operations: ir_instruction list; (* Map initialization instructions *)
  access_patterns: (string * ir_map_access_pattern) list; (* Map access optimizations *)
  cleanup_operations: ir_instruction list; (* Map cleanup instructions *)
}

and ir_map_access_pattern = 
  | ReadHeavy of int (* Expected reads per second *)
  | WriteHeavy of int (* Expected writes per second *)
  | Mixed of int * int (* Reads, writes per second *)

and ir_program_lifecycle = {
  loading_sequence: ir_instruction list; (* BPF program loading logic *)
  attachment_logic: ir_instruction list; (* Program attachment logic *)
  detachment_logic: ir_instruction list; (* Program detachment logic *)
  error_handling: ir_instruction list; (* Error handling for lifecycle operations *)
}

and ir_event_processing = {
  event_loop: ir_instruction list; (* Main event processing loop *)
  ring_buffer_handling: ir_instruction list; (* Ring buffer event processing *)
  perf_event_handling: ir_instruction list; (* Perf event processing *)
  polling_strategy: ir_polling_strategy; (* Event polling configuration *)
}

and ir_polling_strategy =
  | Blocking (* Block waiting for events *)
  | NonBlocking of int (* Non-blocking with timeout in ms *)
  | Adaptive of int * int (* Adaptive polling: min_timeout, max_timeout *)

and ir_signal_handling = {
  setup_handlers: ir_instruction list; (* Signal handler setup *)
  cleanup_handlers: ir_instruction list; (* Signal cleanup logic *)
  graceful_shutdown: ir_instruction list; (* Graceful shutdown sequence *)
}

(** Userspace struct definition in IR *)
and ir_struct_def = {
  struct_name: string;
  struct_fields: (string * ir_type) list; (* IR types, not AST types *)
  struct_alignment: int; (* Memory alignment requirements *)
  struct_size: int; (* Total struct size in bytes *)
  struct_pos: ir_position;
  kernel_defined: bool; (* NEW: Mark if this struct is kernel-defined *)
}

(** Userspace configuration in IR *)
and ir_userspace_config = 
  | IRCustomConfig of string * ir_config_item list

and ir_config_item = {
  config_key: string;
  config_value: ir_value; (* Use IR values instead of AST literals *)
  config_type: ir_type; (* Explicit type information *)
}

(** Enhanced type system for IR with bounds and safety information *)
and ir_type = 
  | IRU8 | IRU16 | IRU32 | IRU64 | IRBool | IRChar
  | IRI8 | IRI16 | IRI32 | IRI64 | IRF32 | IRF64 (* Add signed integers and floating point *)
  | IRVoid (* Add explicit void type *)
  | IRStr of int (* Fixed-size string str<N> *)
  | IRPointer of ir_type * bounds_info
  | IRArray of ir_type * int * bounds_info
  | IRStruct of string * (string * ir_type) list * bool (* NEW: bool for kernel_defined *)
  | IREnum of string * (string * int) list * bool (* NEW: bool for kernel_defined *)
  | IRResult of ir_type * ir_type
  | IRContext of context_type
  | IRAction of action_type
  | IRTypeAlias of string * ir_type (* Simple type aliases *)
  | IRStructOps of string * ir_struct_ops_def (* Future: struct_ops support *)

and context_type = 
  | XdpCtx | TcCtx | KprobeCtx | UprobeCtx | TracepointCtx | LsmCtx | CgroupSkbCtx

and action_type =
  | Xdp_actionType | TcActionType | GenericActionType

and bounds_info = {
  min_size: int option;
  max_size: int option;
  alignment: int;
  nullable: bool;
}

and ir_struct_ops_def = {
  ops_name: string;
  ops_methods: (string * ir_type list * ir_type option) list; (* method_name, params, return *)
  target_kernel_struct: string; (* Which kernel struct this implements *)
}

(** IR struct_ops declarations and instances *)
and ir_struct_ops_declaration = {
  ir_struct_ops_name: string;
  ir_kernel_struct_name: string;
  ir_struct_ops_methods: ir_struct_ops_method list;
  ir_struct_ops_pos: ir_position;
}

and ir_struct_ops_method = {
  ir_method_name: string;
  ir_method_type: ir_type;
  ir_method_pos: ir_position;
}

and ir_struct_ops_instance = {
  ir_instance_name: string;
  ir_instance_type: string;
  ir_instance_fields: (string * ir_value) list;
  ir_instance_pos: ir_position;
}

(** Enhanced map representation with full eBPF map configuration *)
and ir_map_def = {
  map_name: string;
  map_key_type: ir_type;
  map_value_type: ir_type;
  map_type: ir_map_type;
  max_entries: int;
  attributes: ir_map_attr list;
  flags: int;
  is_global: bool;

  pin_path: string option;
  map_pos: ir_position;
}

and ir_map_type =
  | IRHashMap | IRMapArray | IRPercpuHash | IRPercpuArray
  | IRLruHash | IRRingBuffer | IRPerfEvent | IRDevMap

and ir_map_attr = 
  | Pinned of string

(** Values with type and safety information *)
and ir_value = {
  value_desc: ir_value_desc;
  val_type: ir_type;
  stack_offset: int option; (* for stack variables *)
  bounds_checked: bool;
  val_pos: ir_position;
}

and ir_value_desc =
  | IRLiteral of literal
  | IRVariable of string
  | IRRegister of int
  | IRContextField of context_type * string
  | IRMapRef of string
  | IREnumConstant of string * string * int  (* enum_name, constant_name, value *)

(** IR expressions with simplified operations *)
and ir_expr = {
  expr_desc: ir_expr_desc;
  expr_type: ir_type;
  expr_pos: ir_position;
}

and ir_expr_desc =
  | IRValue of ir_value
  | IRBinOp of ir_value * ir_binary_op * ir_value
  | IRUnOp of ir_unary_op * ir_value
  | IRCast of ir_value * ir_type
  | IRFieldAccess of ir_value * string
  | IRStructLiteral of string * (string * ir_value) list  (* struct_name, field_assignments *)
  | IRMatch of ir_value * ir_match_arm list  (* match (value) { arms } *)

(** Match arm for IR match expressions *)
and ir_match_arm = {
  ir_arm_pattern: ir_match_pattern;
  ir_arm_value: ir_value;
  ir_arm_pos: ir_position;
}

(** Match pattern for IR *)
and ir_match_pattern =
  | IRConstantPattern of ir_value  (* constant values *)
  | IRDefaultPattern               (* default case *)

(** Match arm for IRMatchReturn instruction - represents match arms that can contain function calls/tail calls *)
and ir_match_return_arm = {
  match_pattern: ir_match_pattern;
  return_action: ir_return_action;
  arm_pos: ir_position;
}

(** Return action for match arms in return position *)
and ir_return_action =
  | IRReturnValue of ir_value           (* return literal_value; *)
  | IRReturnCall of string * ir_value list  (* return function_call(args); - will be converted to tail call *)
  | IRReturnTailCall of string * ir_value list * int  (* explicit tail call with index *)

and ir_binary_op =
  | IRAdd | IRSub | IRMul | IRDiv | IRMod
  | IREq | IRNe | IRLt | IRLe | IRGt | IRGe
  | IRAnd | IROr
  | IRBitAnd | IRBitOr | IRBitXor | IRShiftL | IRShiftR

and ir_unary_op =
  | IRNot | IRNeg | IRBitNot | IRDeref | IRAddressOf

(** Instructions with verification hints and safety information *)
and ir_instruction = {
  instr_desc: ir_instr_desc;
  instr_stack_usage: int;
  bounds_checks: bounds_check list;
  verifier_hints: verifier_hint list;
  instr_pos: ir_position;
}

and ir_instr_desc =
  | IRAssign of ir_value * ir_expr
  | IRConstAssign of ir_value * ir_expr (* Dedicated const assignment instruction *)
  | IRCall of string * ir_value list * ir_value option
  | IRTailCall of string * ir_value list * int  (* function_name, args, prog_array_index *)
  | IRMapLoad of ir_value * ir_value * ir_value * map_load_type
  | IRMapStore of ir_value * ir_value * ir_value * map_store_type
  | IRMapDelete of ir_value * ir_value
  | IRConfigFieldUpdate of ir_value * ir_value * string * ir_value (* map, key, field, value *)
  | IRStructFieldAssignment of ir_value * string * ir_value (* object, field, value *)
  | IRConfigAccess of string * string * ir_value (* config_name, field_name, result_val *)
  | IRContextAccess of ir_value * context_access_type
  | IRBoundsCheck of ir_value * int * int (* value, min, max *)
  | IRJump of string
  | IRCondJump of ir_value * string * string
  | IRIf of ir_value * ir_instruction list * ir_instruction list option (* condition, then_body, else_body *)
  | IRIfElseChain of (ir_value * ir_instruction list) list * ir_instruction list option (* (condition, then_body) list, final_else_body *)
  | IRMatchReturn of ir_value * ir_match_return_arm list (* matched_value, match_arms - for match expressions in return position *)
  | IRReturn of ir_value option
  | IRComment of string (* for debugging and analysis comments *)
  | IRBpfLoop of ir_value * ir_value * ir_value * ir_value * ir_instruction list (* start, end, counter, ctx, body_instructions *)
  | IRBreak
  | IRContinue
  | IRCondReturn of ir_value * ir_value option * ir_value option (* condition, return_if_true, return_if_false *)
  | IRTry of ir_instruction list * ir_catch_clause list  (* try_block, catch_clauses *)
  | IRThrow of error_code  (* throw with error code *)
  | IRDefer of ir_instruction list  (* deferred instructions *)
  | IRStructOpsRegister of ir_value * ir_value  (* instance_value, struct_ops_type_name *)

(** Error handling types *)
and error_code = 
  | IntErrorCode of int  (* Integer error codes for bpf_throw() *)

and ir_catch_clause = {
  catch_pattern: ir_catch_pattern;
  catch_body: ir_instruction list;
}

and ir_catch_pattern =
  | IntCatchPattern of int     (* catch 42 { ... } *)
  | WildcardCatchPattern       (* catch _ { ... } *)

and map_load_type = DirectLoad | MapLookup | MapPeek
and map_store_type = DirectStore | MapUpdate | MapPush

and context_access_type = 
  | PacketData | PacketEnd | DataMeta | IngressIfindex
  | DataLen | MarkField | Priority | CbField

and bounds_check = {
  value: ir_value;
  min_bound: int;
  max_bound: int;
  check_type: bounds_check_type;
}

and bounds_check_type = ArrayAccess | PointerDeref | StackAccess | MapAccess

and verifier_hint =
  | LoopBound of int
  | StackUsage of int
  | NoRecursion
  | BoundsChecked
  | HelperCall of string

(** Enhanced basic blocks with control flow and analysis information *)
and ir_basic_block = {
  label: string;
  instructions: ir_instruction list;
  successors: string list;
  predecessors: string list;
  stack_usage: int;
  loop_depth: int;
  reachable: bool;
  block_id: int;
}

(** Enhanced function representation with analysis results *)
and ir_function = {
  func_name: string;
  parameters: (string * ir_type) list;
  return_type: ir_type option;
  basic_blocks: ir_basic_block list;
  total_stack_usage: int;
  max_loop_depth: int;
  calls_helper_functions: string list;
  visibility: visibility;
  is_main: bool;
  func_pos: ir_position;
  (* Tail call dependency tracking *)
  mutable tail_call_targets: string list; (* Functions this function tail calls *)
  mutable tail_call_index_map: (string, int) Hashtbl.t; (* Map function name to ProgArray index *)
  mutable is_tail_callable: bool; (* Whether this function can be tail-called *)
  mutable func_program_type: program_type option; (* For attributed functions *)
}

and visibility = Public | Private

(** Userspace binding generation information *)
and ir_userspace_binding = {
  language: binding_language;
  map_wrappers: ir_map_wrapper list;
  event_handlers: ir_event_handler list;
  config_structs: ir_config_struct list;
}

and binding_language = C | Rust | Go | Python

and ir_map_wrapper = {
  wrapper_map_name: string;
  operations: map_operation list;
  safety_checks: bool;
}

and map_operation = OpLookup | OpUpdate | OpDelete | OpIterate

and ir_event_handler = {
  event_type: string;
  callback_signature: string;
  buffer_management: buffer_type;
}

and buffer_type = RingBuffer | PerfEvent

and ir_config_struct = {
  config_struct_name: string;
  fields: (string * ir_type) list;
  serialization: serialization_type;
}

and serialization_type = Json | Binary | Custom of string

(** Global named configuration block *)
and ir_global_config = {
  config_name: string; (* e.g., "network", "security" *)
  config_fields: ir_config_field list;
  config_pos: ir_position;
}

and ir_config_field = {
  field_name: string;
  field_type: ir_type;
  field_default: ir_value option;
  is_mutable: bool; (* Support for 'mut' fields *)
  field_pos: ir_position;
}

(** Global variable declaration *)
and ir_global_variable = {
  global_var_name: string;
  global_var_type: ir_type;
  global_var_init: ir_value option;
  global_var_pos: ir_position;
  is_local: bool; (* true if declared with 'local' keyword *)
  is_pinned: bool; (* true if declared with 'pin' keyword *)
}

(** Utility functions for creating IR nodes *)

let make_bounds_info ?min_size ?max_size ?(alignment = 1) ?(nullable = false) () = {
  min_size;
  max_size; 
  alignment;
  nullable;
}

let make_ir_value desc typ ?stack_offset ?(bounds_checked = false) pos = {
  value_desc = desc;
  val_type = typ;
  stack_offset;
  bounds_checked;
  val_pos = pos;
}

let make_ir_expr desc typ pos = {
  expr_desc = desc;
  expr_type = typ;
  expr_pos = pos;
}

let make_ir_instruction desc ?(stack_usage = 0) ?(bounds_checks = []) ?(verifier_hints = []) pos = {
  instr_desc = desc;
  instr_stack_usage = stack_usage;
  bounds_checks;
  verifier_hints;
  instr_pos = pos;
}

let make_ir_basic_block label instrs ?(successors = []) ?(predecessors = []) 
                       ?(stack_usage = 0) ?(loop_depth = 0) ?(reachable = true) block_id = {
  label;
  instructions = instrs;
  successors;
  predecessors;
  stack_usage;
  loop_depth;
  reachable;
  block_id;
}

let make_ir_function name params return_type blocks ?(total_stack_usage = 0) 
                     ?(max_loop_depth = 0) ?(calls_helper_functions = []) 
                     ?(visibility = Public) ?(is_main = false) pos = {
  func_name = name;
  parameters = params;
  return_type;
  basic_blocks = blocks;
  total_stack_usage;
  max_loop_depth;
  calls_helper_functions;
  visibility;
  is_main;
  func_pos = pos;
  tail_call_targets = [];
  tail_call_index_map = Hashtbl.create 16;
  is_tail_callable = false;
  func_program_type = None;
}

let make_ir_map_def name key_type value_type map_type max_entries 
                    ?(attributes = []) ?(flags = 0) ?(is_global = false) ?pin_path pos = {
  map_name = name;
  map_key_type = key_type;
  map_value_type = value_type;
  map_type;
  max_entries;
  attributes;
  flags;
  is_global;
  pin_path;
  map_pos = pos;
}

let make_ir_program name prog_type entry_function pos = {
  name;
  program_type = prog_type;
  entry_function;
  ir_pos = pos;
}

let make_ir_multi_program source_name programs kernel_functions global_maps 
                          ?(global_configs = []) ?(global_variables = []) ?(struct_ops_declarations = []) ?(struct_ops_instances = []) 
                          ?userspace_program ?(userspace_bindings = []) pos = {
  source_name;
  programs;
  kernel_functions;
  global_maps;
  global_configs;
  global_variables;
  struct_ops_declarations;
  struct_ops_instances;
  userspace_program;
  userspace_bindings;
  multi_pos = pos;
}

let make_ir_userspace_program functions structs configs coordinator_logic pos = {
  userspace_functions = functions;
  userspace_structs = structs;
  userspace_configs = configs;
  coordinator_logic;
  userspace_pos = pos;
}

let make_ir_struct_def name fields alignment size pos = {
  struct_name = name;
  struct_fields = fields;
  struct_alignment = alignment;
  struct_size = size;
  struct_pos = pos;
  kernel_defined = false;
}

let make_ir_config_item key value config_type = {
  config_key = key;
  config_value = value;
  config_type;
}

let make_ir_coordinator_logic setup_logic event_processing cleanup_logic config_management = {
  setup_logic;
  event_processing;
  cleanup_logic;
  config_management;
}

let make_ir_global_config name fields pos = {
  config_name = name;
  config_fields = fields;
  config_pos = pos;
}

let make_ir_config_field name field_type default is_mutable pos = {
  field_name = name;
  field_type = field_type;
  field_default = default;
  is_mutable = is_mutable;
  field_pos = pos;
}

let make_ir_struct_ops_method name method_type pos = {
  ir_method_name = name;
  ir_method_type = method_type;
  ir_method_pos = pos;
}

let make_ir_struct_ops_declaration name kernel_name methods pos = {
  ir_struct_ops_name = name;
  ir_kernel_struct_name = kernel_name;
  ir_struct_ops_methods = methods;
  ir_struct_ops_pos = pos;
}

let make_ir_struct_ops_instance name instance_type fields pos = {
  ir_instance_name = name;
  ir_instance_type = instance_type;
  ir_instance_fields = fields;
  ir_instance_pos = pos;
}

let make_ir_config_management loads updates sync = {
  config_loads = loads;
  config_updates = updates;
  runtime_config_sync = sync;
}

let make_ir_global_variable name var_type init pos ?(is_local=false) ?(is_pinned=false) () = {
  global_var_name = name;
  global_var_type = var_type;
  global_var_init = init;
  global_var_pos = pos;
  is_local;
  is_pinned;
}

(** Utility functions for match expressions *)
let make_ir_match_arm pattern value pos = {
  ir_arm_pattern = pattern;
  ir_arm_value = value;
  ir_arm_pos = pos;
}

let make_ir_constant_pattern value = IRConstantPattern value
let make_ir_default_pattern () = IRDefaultPattern

let make_ir_match_expr matched_value arms result_type pos =
  make_ir_expr (IRMatch (matched_value, arms)) result_type pos

(** Type conversion utilities *)

let rec ast_type_to_ir_type = function
  | U8 -> IRU8
  | U16 -> IRU16
  | U32 -> IRU32
  | U64 -> IRU64
  | Bool -> IRBool
  | Char -> IRChar
  | Void -> IRVoid
  | I8 -> IRI8  (* Use proper signed type *)
  | I16 -> IRU16 (* For now, map to unsigned for eBPF compatibility *)
  | I32 -> IRU32
  | I64 -> IRU64
  | Str size -> IRStr size
  | Array (t, size) -> 
      let bounds = make_bounds_info ~min_size:size ~max_size:size () in
      IRArray (ast_type_to_ir_type t, size, bounds)
  | Pointer t -> 
      let bounds = make_bounds_info ~nullable:true () in
      IRPointer (ast_type_to_ir_type t, bounds)
  | Struct name -> IRStruct (name, [], false) (* Fields filled by symbol table, default to user-defined *)
  | Enum name -> IREnum (name, [], false)     (* Values filled by symbol table, default to user-defined *)
  | Option t -> 
      let bounds = make_bounds_info ~nullable:true () in
      IRPointer (ast_type_to_ir_type t, bounds)
  | Result (t1, t2) -> IRResult (ast_type_to_ir_type t1, ast_type_to_ir_type t2)
  | Xdp_md -> IRContext XdpCtx
  | TcContext -> IRContext TcCtx
  | KprobeContext -> IRContext KprobeCtx
  | UprobeContext -> IRContext UprobeCtx
  | TracepointContext -> IRContext TracepointCtx
  | LsmContext -> IRContext LsmCtx
  | CgroupSkbContext -> IRContext CgroupSkbCtx
  | Xdp_action -> IRAction Xdp_actionType
  | TcAction -> IRAction TcActionType
  | UserType name -> IRStruct (name, [], false) (* Resolved by type checker *)
  | Function (_, _) -> 
      (* For function types, we represent them as function pointers (string names in practice) *)
      IRStr 64  (* Function names as strings, max 64 chars *)
  | Map (_, _, _) -> failwith "Map types handled separately"
  | ProgramRef _ -> IRU32 (* Program references are represented as file descriptors (u32) in IR *)
  | ProgramHandle -> IRI32 (* Program handles are represented as file descriptors (i32) in IR to support error codes *)

(* Helper function that preserves type aliases when converting AST types to IR types *)
let rec ast_type_to_ir_type_with_context symbol_table ast_type =
  match ast_type with
  | UserType name | Struct name ->
      (* Check if this is a type alias or struct by looking up the symbol *)
      (match Symbol_table.lookup_symbol symbol_table name with
         | Some symbol ->
             (match symbol.kind with
              | Symbol_table.TypeDef (Ast.TypeAlias (_, underlying_type)) -> 
                  (* Create IRTypeAlias to preserve the alias name *)
                  IRTypeAlias (name, ast_type_to_ir_type underlying_type)
              | Symbol_table.TypeDef (Ast.StructDef (_, fields, kernel_defined)) ->
                  (* Resolve struct fields properly with type aliases preserved *)
                  let ir_fields = List.map (fun (field_name, field_type) ->
                    (field_name, ast_type_to_ir_type_with_context symbol_table field_type)
                  ) fields in
                  IRStruct (name, ir_fields, kernel_defined)
              | Symbol_table.TypeDef (Ast.EnumDef (_, values, kernel_defined)) -> 
                  let ir_values = List.map (fun (enum_name, opt_value) ->
                    (enum_name, Option.value ~default:0 opt_value)
                  ) values in
                  IREnum (name, ir_values, kernel_defined)
              | _ -> ast_type_to_ir_type ast_type)
         | None ->
             (* Fallback to regular conversion *)
             ast_type_to_ir_type ast_type)
  | Pointer inner_type ->
      (* Recursively handle pointer inner types with context *)
      let bounds = make_bounds_info ~nullable:true () in
      IRPointer (ast_type_to_ir_type_with_context symbol_table inner_type, bounds)
  | Array (elem_type, size) ->
      (* Recursively handle array element types with context *)
      let bounds = make_bounds_info ~min_size:size ~max_size:size () in
      IRArray (ast_type_to_ir_type_with_context symbol_table elem_type, size, bounds)
  | _ -> ast_type_to_ir_type ast_type

let ast_map_type_to_ir_map_type = function
  | HashMap -> IRHashMap
  | Array -> IRMapArray
  | PercpuHash -> IRPercpuHash
  | PercpuArray -> IRPercpuArray
  | LruHash -> IRLruHash
  | RingBuffer -> IRRingBuffer
  | PerfEvent -> IRPerfEvent

(* ast_map_attr_to_ir_map_attr function removed since old attribute system is gone *)

(** Pretty printing functions for debugging *)

let rec string_of_ir_type = function
  | IRU8 -> "u8"
  | IRU16 -> "u16" 
  | IRU32 -> "u32"
  | IRU64 -> "u64"
  | IRBool -> "bool"
  | IRChar -> "char"
  | IRVoid -> "void"
  | IRI8 -> "i8"
  | IRI16 -> "i16"
  | IRI32 -> "i32"
  | IRI64 -> "i64"
  | IRF32 -> "f32"
  | IRF64 -> "f64"
  | IRStr size -> Printf.sprintf "str<%d>" size
  | IRPointer (t, _) -> Printf.sprintf "*%s" (string_of_ir_type t)
  | IRArray (t, size, _) -> Printf.sprintf "[%s; %d]" (string_of_ir_type t) size
  | IRStruct (name, _, _) -> Printf.sprintf "struct %s" name
  | IREnum (name, _, _) -> Printf.sprintf "enum %s" name
  | IRResult (t1, t2) -> Printf.sprintf "result (%s, %s)" (string_of_ir_type t1) (string_of_ir_type t2)
  | IRTypeAlias (name, _) -> Printf.sprintf "type %s" name
  | IRStructOps (name, _) -> Printf.sprintf "struct_ops %s" name
  | IRContext ctx -> Printf.sprintf "context %s" (match ctx with
    | XdpCtx -> "xdp" | TcCtx -> "tc" | KprobeCtx -> "kprobe"
    | UprobeCtx -> "uprobe" | TracepointCtx -> "tracepoint"
    | LsmCtx -> "lsm" | CgroupSkbCtx -> "cgroup_skb")
  | IRAction action -> Printf.sprintf "action %s" (match action with
    | Xdp_actionType -> "xdp" | TcActionType -> "tc"
    | GenericActionType -> "generic")

let string_of_ir_value_desc = function
  | IRLiteral lit -> string_of_literal lit
  | IRVariable name -> name
  | IRRegister reg -> Printf.sprintf "r%d" reg
  | IRContextField (_, field) -> Printf.sprintf "ctx.%s" field
  | IRMapRef name -> Printf.sprintf "&%s" name
  | IREnumConstant (_enum_name, constant_name, _value) -> constant_name

let string_of_ir_value value =
  Printf.sprintf "%s: %s" 
    (string_of_ir_value_desc value.value_desc)
    (string_of_ir_type value.val_type)

let string_of_ir_binary_op = function
  | IRAdd -> "+" | IRSub -> "-" | IRMul -> "*" | IRDiv -> "/" | IRMod -> "%"
  | IREq -> "==" | IRNe -> "!=" | IRLt -> "<" | IRLe -> "<=" | IRGt -> ">" | IRGe -> ">="
  | IRAnd -> "&&" | IROr -> "||"
  | IRBitAnd -> "&" | IRBitOr -> "|" | IRBitXor -> "^"
  | IRShiftL -> "<<" | IRShiftR -> ">>"

let string_of_ir_unary_op = function
  | IRNot -> "!" | IRNeg -> "-" | IRBitNot -> "~" | IRDeref -> "*" | IRAddressOf -> "&"

let rec string_of_ir_expr expr =
  match expr.expr_desc with
  | IRValue value -> string_of_ir_value value
  | IRBinOp (left, op, right) ->
      Printf.sprintf "(%s %s %s)" 
        (string_of_ir_value left) (string_of_ir_binary_op op) (string_of_ir_value right)
  | IRUnOp (op, value) ->
      Printf.sprintf "(%s%s)" (string_of_ir_unary_op op) (string_of_ir_value value)
  | IRCast (value, typ) ->
      Printf.sprintf "(%s as %s)" (string_of_ir_value value) (string_of_ir_type typ)
  | IRFieldAccess (obj, field) ->
      Printf.sprintf "(%s.%s)" (string_of_ir_value obj) field
  | IRStructLiteral (struct_name, field_assignments) ->
      let field_strs = List.map (fun (field_name, value) ->
        Printf.sprintf "%s = %s" field_name (string_of_ir_value value)) field_assignments
      in
      Printf.sprintf "%s { %s }" struct_name (String.concat ", " field_strs)
  | IRMatch (matched_value, arms) ->
      let arms_str = String.concat ", " (List.map string_of_ir_match_arm arms) in
      Printf.sprintf "match (%s) { %s }" (string_of_ir_value matched_value) arms_str

and string_of_ir_match_pattern = function
  | IRConstantPattern value -> string_of_ir_value value
  | IRDefaultPattern -> "default"

and string_of_ir_match_arm arm =
  Printf.sprintf "%s: %s" 
    (string_of_ir_match_pattern arm.ir_arm_pattern) 
    (string_of_ir_value arm.ir_arm_value)

let rec string_of_ir_instruction instr =
  match instr.instr_desc with
  | IRAssign (dest, expr) ->
      Printf.sprintf "%s = %s" (string_of_ir_value dest) (string_of_ir_expr expr)
  | IRConstAssign (dest, expr) ->
      Printf.sprintf "const %s = %s" (string_of_ir_value dest) (string_of_ir_expr expr)
  | IRCall (name, args, ret_opt) ->
      let args_str = String.concat ", " (List.map string_of_ir_value args) in
      let ret_str = match ret_opt with
        | Some ret_val -> string_of_ir_value ret_val ^ " = "
        | None -> ""
      in
      Printf.sprintf "%s%s(%s)" ret_str name args_str
  | IRTailCall (name, args, index) ->
      let args_str = String.concat ", " (List.map string_of_ir_value args) in
      Printf.sprintf "bpf_tail_call(ctx, &prog_array, %d) /* %s(%s) */" index name args_str
  | IRMapLoad (map, key, dest, load_type) ->
      let type_str = match load_type with
        | DirectLoad -> "direct_load" | MapLookup -> "lookup" | MapPeek -> "peek"
      in
      Printf.sprintf "%s = %s(%s, %s)" 
        (string_of_ir_value dest) type_str (string_of_ir_value map) (string_of_ir_value key)
  | IRMapStore (map, key, value, store_type) ->
      let type_str = match store_type with
        | DirectStore -> "direct_store" | MapUpdate -> "update" | MapPush -> "push"
      in
      Printf.sprintf "%s(%s, %s, %s)" 
        type_str (string_of_ir_value map) (string_of_ir_value key) (string_of_ir_value value)
  | IRMapDelete (map, key) ->
      Printf.sprintf "delete(%s, %s)" (string_of_ir_value map) (string_of_ir_value key)
  | IRConfigFieldUpdate (map, key, field, value) ->
      Printf.sprintf "config_update(%s, %s, %s, %s)" 
        (string_of_ir_value map) (string_of_ir_value key) field (string_of_ir_value value)
  | IRStructFieldAssignment (obj, field, value) ->
      Printf.sprintf "%s.%s = %s" 
        (string_of_ir_value obj) field (string_of_ir_value value)
  | IRConfigAccess (config_name, field_name, result_val) ->
      Printf.sprintf "config_access(%s, %s, %s)" config_name field_name (string_of_ir_value result_val)
  | IRContextAccess (dest, access_type) ->
      let access_str = match access_type with
        | PacketData -> "packet_data" | PacketEnd -> "packet_end"
        | DataMeta -> "data_meta" | IngressIfindex -> "ingress_ifindex"
        | DataLen -> "data_len" | MarkField -> "mark" 
        | Priority -> "priority" | CbField -> "cb"
      in
      Printf.sprintf "%s = ctx.%s" (string_of_ir_value dest) access_str
  | IRBoundsCheck (value, min_bound, max_bound) ->
      Printf.sprintf "bounds_check(%s, %d, %d)" 
        (string_of_ir_value value) min_bound max_bound
  | IRJump label -> Printf.sprintf "goto %s" label
  | IRCondJump (cond, true_label, false_label) ->
      Printf.sprintf "if (%s) goto %s else goto %s" 
        (string_of_ir_value cond) true_label false_label
  | IRIf (cond, then_body, else_body) ->
      let then_str = String.concat "\n  " 
        (List.map string_of_ir_instruction then_body) in
      let else_str = match else_body with
        | None -> ""
        | Some body -> Printf.sprintf "else {\n%s\n}" (String.concat "\n  " 
          (List.map string_of_ir_instruction body))
      in
      Printf.sprintf "if (%s) {\n%s\n} %s" 
        (string_of_ir_value cond) then_str else_str
  | IRIfElseChain (conditions_and_bodies, final_else) ->
      let if_parts = List.mapi (fun i (cond, then_body) ->
        let cond_str = string_of_ir_value cond in
        let then_str = String.concat "\n  " (List.map string_of_ir_instruction then_body) in
        let keyword = if i = 0 then "if" else "else if" in
        Printf.sprintf "%s (%s) {\n%s\n}" keyword cond_str then_str
      ) conditions_and_bodies in
      let else_part = match final_else with
        | None -> ""
        | Some else_instrs -> 
            Printf.sprintf " else {\n%s\n}" (String.concat "\n  " (List.map string_of_ir_instruction else_instrs))
      in
      String.concat " " if_parts ^ else_part
  | IRMatchReturn (matched_val, arms) ->
      let matched_str = string_of_ir_value matched_val in
      let arms_str = List.map (fun arm ->
        let pattern_str = match arm.match_pattern with
          | IRConstantPattern const_val -> string_of_ir_value const_val
          | IRDefaultPattern -> "default"
        in
        let action_str = match arm.return_action with
          | IRReturnValue ret_val -> Printf.sprintf "return %s" (string_of_ir_value ret_val)
          | IRReturnCall (func_name, args) -> 
              let args_str = String.concat ", " (List.map string_of_ir_value args) in
              Printf.sprintf "return %s(%s)" func_name args_str
          | IRReturnTailCall (func_name, args, index) -> 
              let args_str = String.concat ", " (List.map string_of_ir_value args) in
              Printf.sprintf "tail_call %s(%s) [index=%d]" func_name args_str index
        in
        Printf.sprintf "%s: %s" pattern_str action_str
      ) arms in
      Printf.sprintf "match (%s) {\n  %s\n}" matched_str (String.concat ";\n  " arms_str)
  | IRReturn None -> "return"
  | IRReturn (Some value) -> Printf.sprintf "return %s" (string_of_ir_value value)
  | IRComment comment -> Printf.sprintf "/* %s */" comment
  | IRBpfLoop (start, end_, counter, ctx, body_instructions) ->
      let body_str = String.concat "\n  " 
        (List.map string_of_ir_instruction body_instructions) in
      Printf.sprintf "bpf_loop(%s, %s, %s, %s) { /* IR body */ }\n  %s" 
        (string_of_ir_value start) (string_of_ir_value end_) (string_of_ir_value counter) (string_of_ir_value ctx) body_str
  | IRBreak -> "break"
  | IRContinue -> "continue"
  | IRCondReturn (cond, ret_if_true, ret_if_false) ->
      let ret_if_true_str = match ret_if_true with
        | None -> ""
        | Some ret -> Printf.sprintf "return %s" (string_of_ir_value ret)
      in
      let ret_if_false_str = match ret_if_false with
        | None -> ""
        | Some ret -> Printf.sprintf "return %s" (string_of_ir_value ret)
      in
      Printf.sprintf "cond_return(%s, %s, %s)" 
        (string_of_ir_value cond) ret_if_true_str ret_if_false_str
  | IRTry (try_body, catch_clauses) ->
      let try_str = String.concat "\n  " 
        (List.map string_of_ir_instruction try_body) in
      let catch_str = String.concat "\n  " 
        (List.map (fun _clause -> "catch {...}") catch_clauses) in
      Printf.sprintf "try {\n%s\n} %s" try_str catch_str
  | IRThrow error_code ->
      let error_str = match error_code with
        | IntErrorCode code -> Printf.sprintf "%d" code
      in
      Printf.sprintf "throw %s" error_str
  | IRDefer instructions ->
      let instr_str = String.concat "\n  " 
        (List.map string_of_ir_instruction instructions) in
      Printf.sprintf "defer {\n%s\n}" instr_str
  | IRStructOpsRegister (instance_name, struct_ops_type) ->
      Printf.sprintf "struct_ops_register(%s, %s)" (string_of_ir_value instance_name) (string_of_ir_value struct_ops_type)

let string_of_ir_basic_block block =
  let instrs_str = String.concat "\n  " 
    (List.map string_of_ir_instruction block.instructions) in
  Printf.sprintf "%s:\n  %s" block.label instrs_str

let string_of_ir_function func =
  let params_str = String.concat ", " 
    (List.map (fun (name, typ) -> 
       Printf.sprintf "%s: %s" name (string_of_ir_type typ)) func.parameters) in
  let return_str = match func.return_type with
    | None -> ""
    | Some t -> " -> " ^ string_of_ir_type t
  in
  let blocks_str = String.concat "\n\n" 
    (List.map string_of_ir_basic_block func.basic_blocks) in
  Printf.sprintf "fn %s(%s)%s {\n%s\n}" 
    func.func_name params_str return_str blocks_str

let string_of_ir_program prog =
  let entry_function_str = string_of_ir_function prog.entry_function in
  Printf.sprintf "program %s : %s {\n%s\n}" 
    prog.name (string_of_program_type prog.program_type) entry_function_str

let string_of_ir_multi_program multi_prog =
  let programs_str = String.concat "\n\n" 
    (List.map string_of_ir_program multi_prog.programs) in
  Printf.sprintf "source %s {\n%s\n}" 
    multi_prog.source_name programs_str 