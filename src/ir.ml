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
  global_maps: ir_map_def list; (* Maps shared across programs *)
  userspace_block: Ast.userspace_block option; (* Userspace code block *)
  userspace_bindings: ir_userspace_binding list; (* Generated bindings *)
  multi_pos: ir_position;
}

(** Program-level IR - single eBPF program representation *)
and ir_program = {
  name: string;
  program_type: program_type;
  local_maps: ir_map_def list; (* Maps local to this program *)
  functions: ir_function list;
  main_function: ir_function;
  ir_pos: ir_position;
}

(** Enhanced type system for IR with bounds and safety information *)
and ir_type = 
  | IRU8 | IRU16 | IRU32 | IRU64 | IRBool | IRChar
  | IRPointer of ir_type * bounds_info
  | IRArray of ir_type * int * bounds_info
  | IRStruct of string * (string * ir_type) list
  | IREnum of string * (string * int) list
  | IROption of ir_type
  | IRResult of ir_type * ir_type
  | IRContext of context_type
  | IRAction of action_type

and context_type = 
  | XdpCtx | TcCtx | KprobeCtx | UprobeCtx | TracepointCtx | LsmCtx | CgroupSkbCtx

and action_type =
  | XdpActionType | TcActionType | GenericActionType

and bounds_info = {
  min_size: int option;
  max_size: int option;
  alignment: int;
  nullable: bool;
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

and ir_binary_op =
  | IRAdd | IRSub | IRMul | IRDiv | IRMod
  | IREq | IRNe | IRLt | IRLe | IRGt | IRGe
  | IRAnd | IROr
  | IRBitAnd | IRBitOr | IRBitXor | IRShiftL | IRShiftR

and ir_unary_op =
  | IRNot | IRNeg | IRBitNot

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
  | IRCall of string * ir_value list * ir_value option
  | IRMapLoad of ir_value * ir_value * ir_value * map_load_type
  | IRMapStore of ir_value * ir_value * ir_value * map_store_type
  | IRMapDelete of ir_value * ir_value
  | IRContextAccess of ir_value * context_access_type
  | IRBoundsCheck of ir_value * int * int (* value, min, max *)
  | IRJump of string
  | IRCondJump of ir_value * string * string
  | IRReturn of ir_value option
  | IRComment of string (* for debugging and analysis comments *)
  | IRBpfLoop of ir_value * ir_value * ir_value * ir_value * Ast.statement list (* start, end, counter, ctx, body *)
  | IRBreak
  | IRContinue

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
  struct_name: string;
  fields: (string * ir_type) list;
  serialization: serialization_type;
}

and serialization_type = Json | Binary | Custom of string

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

let make_ir_program name prog_type local_maps functions main_function pos = {
  name;
  program_type = prog_type;
  local_maps;
  functions;
  main_function;
  ir_pos = pos;
}

let make_ir_multi_program source_name programs global_maps 
                          ?userspace_block ?(userspace_bindings = []) pos = {
  source_name;
  programs;
  global_maps;
  userspace_block;
  userspace_bindings;
  multi_pos = pos;
}

(** Type conversion utilities *)

let rec ast_type_to_ir_type = function
  | U8 -> IRU8
  | U16 -> IRU16
  | U32 -> IRU32
  | U64 -> IRU64
  | Bool -> IRBool
  | Char -> IRChar
  | I8 -> IRU8  (* Simplified - eBPF treats signed as unsigned *)  
  | I16 -> IRU16
  | I32 -> IRU32
  | I64 -> IRU64
  | Array (t, size) -> 
      let bounds = make_bounds_info ~min_size:size ~max_size:size () in
      IRArray (ast_type_to_ir_type t, size, bounds)
  | Pointer t -> 
      let bounds = make_bounds_info ~nullable:true () in
      IRPointer (ast_type_to_ir_type t, bounds)
  | Struct name -> IRStruct (name, []) (* Fields filled by symbol table *)
  | Enum name -> IREnum (name, [])     (* Values filled by symbol table *)
  | Option t -> IROption (ast_type_to_ir_type t)
  | Result (t1, t2) -> IRResult (ast_type_to_ir_type t1, ast_type_to_ir_type t2)
  | XdpContext -> IRContext XdpCtx
  | TcContext -> IRContext TcCtx
  | KprobeContext -> IRContext KprobeCtx
  | UprobeContext -> IRContext UprobeCtx
  | TracepointContext -> IRContext TracepointCtx
  | LsmContext -> IRContext LsmCtx
  | CgroupSkbContext -> IRContext CgroupSkbCtx
  | XdpAction -> IRAction XdpActionType
  | TcAction -> IRAction TcActionType
  | UserType name -> IRStruct (name, []) (* Resolved by type checker *)
  | Function _ -> failwith "Function types not supported in IR yet"
  | Map (_, _, _) -> failwith "Map types handled separately"

let ast_map_type_to_ir_map_type = function
  | HashMap -> IRHashMap
  | Array -> IRMapArray
  | PercpuHash -> IRPercpuHash
  | PercpuArray -> IRPercpuArray
  | LruHash -> IRLruHash
  | RingBuffer -> IRRingBuffer
  | PerfEvent -> IRPerfEvent

let ast_map_attr_to_ir_map_attr = function
  | Ast.Pinned path -> Pinned path
  | Ast.FlagsAttr _ -> failwith "FlagsAttr should be handled separately in IR conversion"

(** Pretty printing functions for debugging *)

let rec string_of_ir_type = function
  | IRU8 -> "u8"
  | IRU16 -> "u16" 
  | IRU32 -> "u32"
  | IRU64 -> "u64"
  | IRBool -> "bool"
  | IRChar -> "char"
  | IRPointer (t, _) -> Printf.sprintf "*%s" (string_of_ir_type t)
  | IRArray (t, size, _) -> Printf.sprintf "[%s; %d]" (string_of_ir_type t) size
  | IRStruct (name, _) -> Printf.sprintf "struct %s" name
  | IREnum (name, _) -> Printf.sprintf "enum %s" name
  | IROption t -> Printf.sprintf "option %s" (string_of_ir_type t)
  | IRResult (t1, t2) -> Printf.sprintf "result (%s, %s)" (string_of_ir_type t1) (string_of_ir_type t2)
  | IRContext ctx -> Printf.sprintf "context %s" (match ctx with
    | XdpCtx -> "xdp" | TcCtx -> "tc" | KprobeCtx -> "kprobe"
    | UprobeCtx -> "uprobe" | TracepointCtx -> "tracepoint"
    | LsmCtx -> "lsm" | CgroupSkbCtx -> "cgroup_skb")
  | IRAction action -> Printf.sprintf "action %s" (match action with
    | XdpActionType -> "xdp" | TcActionType -> "tc"
    | GenericActionType -> "generic")

let string_of_ir_value_desc = function
  | IRLiteral lit -> string_of_literal lit
  | IRVariable name -> name
  | IRRegister reg -> Printf.sprintf "r%d" reg
  | IRContextField (_, field) -> Printf.sprintf "ctx.%s" field
  | IRMapRef name -> Printf.sprintf "&%s" name

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
  | IRNot -> "!" | IRNeg -> "-" | IRBitNot -> "~"

let string_of_ir_expr expr =
  match expr.expr_desc with
  | IRValue value -> string_of_ir_value value
  | IRBinOp (left, op, right) ->
      Printf.sprintf "(%s %s %s)" 
        (string_of_ir_value left) (string_of_ir_binary_op op) (string_of_ir_value right)
  | IRUnOp (op, value) ->
      Printf.sprintf "(%s%s)" (string_of_ir_unary_op op) (string_of_ir_value value)
  | IRCast (value, typ) ->
      Printf.sprintf "(%s as %s)" (string_of_ir_value value) (string_of_ir_type typ)

let string_of_ir_instruction instr =
  match instr.instr_desc with
  | IRAssign (dest, expr) ->
      Printf.sprintf "%s = %s" (string_of_ir_value dest) (string_of_ir_expr expr)
  | IRCall (name, args, ret_opt) ->
      let args_str = String.concat ", " (List.map string_of_ir_value args) in
      let ret_str = match ret_opt with
        | None -> ""
        | Some ret -> Printf.sprintf "%s = " (string_of_ir_value ret)
      in
      Printf.sprintf "%s%s(%s)" ret_str name args_str
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
  | IRReturn None -> "return"
  | IRReturn (Some value) -> Printf.sprintf "return %s" (string_of_ir_value value)
  | IRComment comment -> Printf.sprintf "/* %s */" comment
  | IRBpfLoop (start, end_, counter, ctx, _body) ->
      Printf.sprintf "bpf_loop(%s, %s, %s, %s) { /* AST body */ }" 
        (string_of_ir_value start) (string_of_ir_value end_) (string_of_ir_value counter) (string_of_ir_value ctx)
  | IRBreak -> "break"
  | IRContinue -> "continue"

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
  let functions_str = String.concat "\n\n" 
    (List.map string_of_ir_function prog.functions) in
  Printf.sprintf "program %s : %s {\n%s\n}" 
    prog.name (string_of_program_type prog.program_type) functions_str

let string_of_ir_multi_program multi_prog =
  let programs_str = String.concat "\n\n" 
    (List.map string_of_ir_program multi_prog.programs) in
  Printf.sprintf "source %s {\n%s\n}" 
    multi_prog.source_name programs_str 