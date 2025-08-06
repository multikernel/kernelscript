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

(** Abstract Syntax Tree for KernelScript *)

(** Position information for error reporting *)
type position = { 
  line: int; 
  column: int; 
  filename: string 
}

(** Catch pattern for integer-based error handling *)
type catch_pattern =
  | IntPattern of int     (* catch 42 { ... } *)
  | WildcardPattern       (* catch _ { ... } *)

(** Attribute types for eBPF program functions *)
type attribute =
  | SimpleAttribute of string  (* @xdp *)
  | AttributeWithArg of string * string  (* @kprobe("sys_read") *)

(** Probe types for distinguishing between fprobe and kprobe *)
type probe_type = 
  | Fprobe    (* Function entrance/exit probe - no offset *)
  | Kprobe    (* Kernel probe with offset support *)

(** Program types supported by KernelScript *)
type program_type = 
  | Xdp | Tc | Probe of probe_type | Tracepoint | StructOps

(** Map types for eBPF maps *)
type map_type =
  | Hash | Array | Percpu_hash | Percpu_array | Lru_hash

(** Map flags for eBPF map configuration *)
type map_flag =
  | NoPrealloc          (* BPF_F_NO_PREALLOC *)
  | NoCommonLru         (* BPF_F_NO_COMMON_LRU *)
  | NumaNode of int     (* BPF_F_NUMA_NODE with node ID *)
  | Rdonly              (* BPF_F_RDONLY *)
  | Wronly              (* BPF_F_WRONLY *)
  | Clone               (* BPF_F_CLONE *)

(** Type definitions for structs, enums, and type aliases *)
type type_def =
  | StructDef of string * (string * bpf_type) list
  | EnumDef of string * (string * int option) list
  | TypeAlias of string * bpf_type

(** BPF type system with extended type definitions *)
and bpf_type =
  (* Primitive types *)
  | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 | Bool | Char | Void
  | Str of int  (* Fixed-size string str<N> *)
  (* Composite types *)
  | Array of bpf_type * int
  | Pointer of bpf_type
  | UserType of string
  (* Extended types for advanced type system *)
  | Struct of string
  | Enum of string  
  | Option of bpf_type
  | Result of bpf_type * bpf_type
  | Function of bpf_type list * bpf_type
  | Map of bpf_type * bpf_type * map_type * int  (* key_type, value_type, map_type, size *)
  (* Built-in context types *)
  | Xdp_md
  | TracepointContext
  | Xdp_action
  (* Program reference types *)
  | ProgramRef of program_type
  (* Program handle type - represents a loaded program *)
  | ProgramHandle
  (* Ring buffer reference type - represents a ring buffer for dispatch *)
  | RingbufRef of bpf_type (* value type *)
  | Ringbuf of bpf_type * int (* value_type, size - ring buffer object *)
  (* None type - represents missing/absent values *)
  | NoneType

(** Map configuration *)
type map_config = {
  max_entries: int;
  key_size: int option;
  value_size: int option;
  flags: map_flag list;
}

(** Map declarations *)
type map_declaration = {
  name: string;
  key_type: bpf_type;
  value_type: bpf_type;
  map_type: map_type;
  config: map_config;
  is_global: bool;
  is_pinned: bool;
  map_pos: position;
}

(** Literal values *)
type literal =
  | IntLit of int * string option  (* value * original_representation *)
  | StringLit of string 
  | CharLit of char 
  | BoolLit of bool
  | ArrayLit of array_init_style   (* Enhanced array initialization *)
  | NullLit
  | NoneLit

(** Array initialization styles *)
and array_init_style =
  | FillArray of literal        (* [0] - fill entire array with single value *)
  | ExplicitArray of literal list (* [a,b,c] - explicit values, zero-fill rest *)
  | ZeroArray                   (* [] - zero initialize entire array *)

(** Binary operators *)
type binary_op =
  | Add | Sub | Mul | Div | Mod
  | Eq | Ne | Lt | Le | Gt | Ge
  | And | Or

(** Unary operators *)
type unary_op =
  | Not | Neg | Deref | AddressOf  (* Added Deref and AddressOf operators *)

(** Map scope for multi-program analysis *)
type map_scope =
  | Global          (* Globally accessible across all programs *)
  | Local           (* Local to current program only *)
  | CrossProgram    (* Shared between specific programs *)

(** Multi-program analysis context *)
type program_context = {
  current_program: program_type option;
  accessing_programs: program_type list;  (* Programs that access this expression *)
  data_flow_direction: data_flow_direction option;
}

and data_flow_direction =
  | Read | Write | ReadWrite

(** Enhanced expressions with multi-program analysis *)
type expr = {
  expr_desc: expr_desc;
  expr_pos: position;
  mutable expr_type: bpf_type option;       (* filled by type checker *)
  mutable type_checked: bool;               (* whether type checking completed *)
  mutable program_context: program_context option;  (* multi-program context *)
  mutable map_scope: map_scope option;      (* map access scope *)
}

and expr_desc =
  | Literal of literal
  | Identifier of string
  | ConfigAccess of string * string  (* config_name, field_name *)
  | Call of expr * expr list  (* Unified call: callee_expression * arguments *)
  | TailCall of string * expr list  (* function_name, arguments - for explicit tail calls *)
  | ModuleCall of module_call  (* module.function(args) calls *)
  | ArrayAccess of expr * expr
  | FieldAccess of expr * string
  | ArrowAccess of expr * string  (* pointer->field *)
  | BinaryOp of expr * binary_op * expr
  | UnaryOp of unary_op * expr
  | StructLiteral of string * (string * expr) list
  | Match of expr * match_arm list  (* match (expr) { arms } *)
  | New of bpf_type  (* new Type() - object allocation *)
  | NewWithFlag of bpf_type * expr  (* new Type(gfp_flag) - object allocation with flag *)

(** Module function call *)
and module_call = {
  module_name: string;
  function_name: string;
  args: expr list;
  call_pos: position;
}

(** Match pattern for basic match expressions *)
and match_pattern =
  | ConstantPattern of literal  (* 42, "string", true, etc. *)
  | IdentifierPattern of string (* CONST_VALUE, enum variants *)
  | DefaultPattern              (* default case *)

(** Match arm body - can be either a single expression or a block of statements *)
and match_arm_body = 
  | SingleExpr of expr
  | Block of statement list

(** Match arm: pattern : expression or block *)
and match_arm = {
  arm_pattern: match_pattern;
  arm_body: match_arm_body;
  arm_pos: position;
}

(** Statements with position tracking *)
and statement = {
  stmt_desc: stmt_desc;
  stmt_pos: position;
}

and stmt_desc =
  | ExprStmt of expr
  | Assignment of string * expr
  | CompoundAssignment of string * binary_op * expr  (* var op= expr *)
  | CompoundIndexAssignment of expr * expr * binary_op * expr  (* map[key] op= expr *)
  | FieldAssignment of expr * string * expr  (* object.field = value *)
  | ArrowAssignment of expr * string * expr  (* pointer->field = value *)
  | IndexAssignment of expr * expr * expr  (* map[key] = value *)
  | Declaration of string * bpf_type option * expr option
  | ConstDeclaration of string * bpf_type option * expr  (* const name : type = value *)
  | Return of expr option
  | If of expr * statement list * statement list option
  | For of string * expr * expr * statement list
  | ForIter of string * string * expr * statement list  (* for (index, value) in expr.iter() { ... } *)
  | While of expr * statement list
  | Delete of delete_target  (* Unified delete: map[key] or pointer *)
  | Break
  | Continue
  | Try of statement list * catch_clause list  (* try { statements } catch clauses *)
  | Throw of expr  (* throw integer_expression *)
  | Defer of expr  (* defer function_call *)

(** Delete target - either map entry or object pointer *)
and delete_target =
  | DeleteMapEntry of expr * expr  (* delete map[key] *)
  | DeletePointer of expr         (* delete ptr *)

(** Catch clause definition *)
and catch_clause = {
  catch_pattern: catch_pattern;
  catch_body: statement list;
  catch_pos: position;
}

(** Function scope modifiers *)
type function_scope = Userspace | Kernel

(** Return type specification - supports both unnamed and named returns *)
type return_type_spec = 
  | Unnamed of bpf_type          (* fn() -> u64 *)
  | Named of string * bpf_type   (* fn() -> result: u64 *)

(** Function definitions *)
type function_def = {
  func_name: string;
  func_params: (string * bpf_type) list;
  func_return_type: return_type_spec option;
  func_body: statement list;
  func_scope: function_scope;
  func_pos: position;
  (* Tail call dependency tracking *)
  mutable tail_call_targets: string list; (* Functions this function can tail call *)
  mutable is_tail_callable: bool; (* Whether this function can be tail-called *)
}

and struct_def = {
  struct_name: string;
  struct_fields: (string * bpf_type) list;
  struct_attributes: attribute list;  (* Added attributes for @struct_ops etc. *)
  struct_pos: position;
}

(** Program definition with local maps and structs *)
type program_def = {
  prog_name: string;
  prog_type: program_type;
  prog_functions: function_def list;
  prog_maps: map_declaration list; (* Maps local to this program *)
  prog_structs: struct_def list; (* Structs local to this program *)
  prog_target: string option; (* Target for kprobe/tracepoint programs *)
  prog_pos: position;
}

(** Attributed function - a function with eBPF attributes *)
type attributed_function = {
  attr_list: attribute list;
  attr_function: function_def;
  attr_pos: position;
  (* Tail call dependency analysis *)
  mutable program_type: program_type option; (* Extracted from attributes *)
  mutable tail_call_dependencies: string list; (* Other attributed functions this calls *)
}

(** Config field declaration *)
type config_field = {
  field_name: string;
  field_type: bpf_type;
  field_default: literal option;
  field_pos: position;
}

(** Named configuration block *)
type config_declaration = {
  config_name: string;
  config_fields: config_field list;
  config_pos: position;
}

(** Global variable declaration *)
type global_variable_declaration = {
  global_var_name: string;
  global_var_type: bpf_type option;
  global_var_init: expr option;
  global_var_pos: position;
  is_local: bool; (* true if declared with 'local' keyword *)
  is_pinned: bool; (* true if declared with 'pin' keyword *)
}

(** Impl block for struct_ops - Option 1 from proposal *)
type impl_block_item =
  | ImplFunction of function_def  (* Functions become eBPF functions with SEC("struct_ops/...") *)
  | ImplStaticField of string * expr  (* Static data fields like name: "minimal_cc" *)

type impl_block = {
  impl_name: string;  (* The struct_ops name like "tcp_congestion_ops" *)
  impl_attributes: attribute list;  (* @struct_ops("tcp_congestion_ops") *)
  impl_items: impl_block_item list;  (* Functions and static fields *)
  impl_pos: position;
}

(** Import source type - determined by file extension *)
type import_source_type = KernelScript | Python

(** Import declaration *)
type import_declaration = {
  module_name: string;        (* Local name for the imported module *)
  source_path: string;        (* File path *)
  source_type: import_source_type; (* Determined from file extension *)
  import_pos: position;
}

(** Extern kfunc declaration - for importing kernel functions *)
type extern_kfunc_declaration = {
  extern_name: string;
  extern_params: (string * bpf_type) list;
  extern_return_type: bpf_type option;
  extern_pos: position;
}

(** Include declaration - for KernelScript headers (.kh files) *)
type include_declaration = {
  include_path: string;        (* Path to .kh file *)
  include_pos: position;
}

(** Top-level declarations *)
type declaration =
  | AttributedFunction of attributed_function
  | GlobalFunction of function_def
  | TypeDef of type_def
  | MapDecl of map_declaration
  | ConfigDecl of config_declaration
  | StructDecl of struct_def
  | GlobalVarDecl of global_variable_declaration
  | ImplBlock of impl_block
  | ImportDecl of import_declaration
  | ExternKfuncDecl of extern_kfunc_declaration
  | IncludeDecl of include_declaration

(** Complete AST *)
type ast = declaration list

(** Utility functions for creating AST nodes *)

let make_position line col filename = { line; column = col; filename }

let make_expr desc pos = { 
  expr_desc = desc; 
  expr_pos = pos; 
  expr_type = None;
  type_checked = false;
  program_context = None;
  map_scope = None;
}

let make_stmt desc pos = { stmt_desc = desc; stmt_pos = pos }

(** Helper functions for creating return type specifications *)
let make_unnamed_return typ = Unnamed typ
let make_named_return name typ = Named (name, typ)

(** Helper functions for extracting information from return type specifications *)
let get_return_type = function
  | Some (Unnamed typ) -> Some typ
  | Some (Named (_, typ)) -> Some typ
  | None -> None

let get_return_variable_name = function
  | Some (Named (name, _)) -> Some name
  | Some (Unnamed _) | None -> None

let is_named_return = function
  | Some (Named _) -> true
  | Some (Unnamed _) | None -> false

let make_function name params return_type body ?(scope=Userspace) pos = {
  func_name = name;
  func_params = params;
  func_return_type = return_type;
  func_body = body;
  func_scope = scope;
  func_pos = pos;
  tail_call_targets = [];
  is_tail_callable = false;
}

let make_program name prog_type functions pos = {
  prog_name = name;
  prog_type = prog_type;
  prog_functions = functions;
  prog_maps = [];
  prog_structs = [];
  prog_target = None;
  prog_pos = pos;
}

let make_program_with_maps name prog_type functions maps pos = {
  prog_name = name;
  prog_type = prog_type;
  prog_functions = functions;
  prog_maps = maps;
  prog_structs = [];
  prog_target = None;
  prog_pos = pos;
}

let make_program_with_all name prog_type functions maps structs pos = {
  prog_name = name;
  prog_type = prog_type;
  prog_functions = functions;
  prog_maps = maps;
  prog_structs = structs;
  prog_target = None;
  prog_pos = pos;
}

let make_attributed_function attrs func pos = {
  attr_list = attrs;
  attr_function = func;
  attr_pos = pos;
  program_type = None;
  tail_call_dependencies = [];
}

let make_extern_kfunc_declaration name params return_type pos = {
  extern_name = name;
  extern_params = params;
  extern_return_type = return_type;
  extern_pos = pos;
}

let make_include_declaration path pos = {
  include_path = path;
  include_pos = pos;
}

let make_type_def def = def

let make_enum_def name values = EnumDef (name, values)

let make_kernel_enum_def name values = EnumDef (name, values)

let make_kernel_struct_def name fields = StructDef (name, fields)

let make_type_alias name bpf_type = TypeAlias (name, bpf_type)

let make_map_config max_entries ?key_size ?value_size ?(flags=[]) () = 
  {
    max_entries;
    key_size;
    value_size;
    flags;
  }

let make_map_declaration name key_type value_type map_type config is_global ~is_pinned pos = {
  name;
  key_type;
  value_type;
  map_type;
  config;
  is_global;
  is_pinned;
  map_pos = pos;
}

let make_struct_def ?(attributes=[]) name fields pos = {
  struct_name = name;
  struct_fields = fields;
  struct_attributes = attributes;
  struct_pos = pos;
}

let make_config_field name field_type default pos = {
  field_name = name;
  field_type = field_type;
  field_default = default;
  field_pos = pos;
}

let make_config_declaration name fields pos = {
  config_name = name;
  config_fields = fields;
  config_pos = pos;
}

let make_global_var_decl name typ init pos ?(is_local=false) ?(is_pinned=false) () = {
  global_var_name = name;
  global_var_type = typ;
  global_var_init = init;
  global_var_pos = pos;
  is_local;
  is_pinned;
}

let make_impl_block name attributes items pos = {
  impl_name = name;
  impl_attributes = attributes;
  impl_items = items;
  impl_pos = pos;
}

(** Utility functions for match expressions *)
let make_match_arm pattern body pos = {
  arm_pattern = pattern;
  arm_body = body;
  arm_pos = pos;
}

let make_match_arm_expr pattern expr pos = 
  make_match_arm pattern (SingleExpr expr) pos

let make_match_arm_block pattern stmts pos = 
  make_match_arm pattern (Block stmts) pos

let make_constant_pattern lit = ConstantPattern lit
let make_identifier_pattern name = IdentifierPattern name
let make_default_pattern () = DefaultPattern

let make_match_expr matched_expr arms pos =
  make_expr (Match (matched_expr, arms)) pos

(** Import-related helper functions *)
let detect_import_source_type file_path =
  let extension = Filename.extension file_path in
  match String.lowercase_ascii extension with
  | ".ks" -> KernelScript
  | ".py" -> Python
  | _ -> failwith ("Unsupported import file type: " ^ extension)

let make_import_declaration module_name source_path pos = {
  module_name;
  source_path;
  source_type = detect_import_source_type source_path;
  import_pos = pos;
}

let make_module_call module_name function_name args pos = {
  module_name;
  function_name;
  args;
  call_pos = pos;
}

let make_module_call_expr module_name function_name args pos =
  make_expr (ModuleCall (make_module_call module_name function_name args pos)) pos

(** Pretty-printing functions for debugging *)

let string_of_position pos =
  Printf.sprintf "%s:%d:%d" pos.filename pos.line pos.column

let string_of_program_type = function
  | Xdp -> "xdp"
  | Tc -> "tc"
  | Probe Fprobe -> "fprobe"
  | Probe Kprobe -> "kprobe"
  | Tracepoint -> "tracepoint"
  | StructOps -> "struct_ops"

let string_of_map_type = function
  | Hash -> "hash"
  | Array -> "array"
  | Percpu_hash -> "percpu_hash"
  | Percpu_array -> "percpu_array"
  | Lru_hash -> "lru_hash"

let string_of_map_flag = function
  | NoPrealloc -> "no_prealloc"
  | NoCommonLru -> "no_common_lru"
  | NumaNode n -> "numa_node(" ^ string_of_int n ^ ")"
  | Rdonly -> "rdonly"
  | Wronly -> "wronly"
  | Clone -> "clone"

let rec string_of_bpf_type = function
  | U8 -> "u8"
  | U16 -> "u16"
  | U32 -> "u32"
  | U64 -> "u64"
  | I8 -> "i8"
  | I16 -> "i16"
  | I32 -> "i32"
  | I64 -> "i64"
  | Bool -> "bool"
  | Char -> "char"
  | Void -> "void"
  | Str size -> Printf.sprintf "str(%d)" size
  | Array (t, size) -> Printf.sprintf "[%s; %d]" (string_of_bpf_type t) size
  | Pointer t -> Printf.sprintf "*%s" (string_of_bpf_type t)
  | UserType name -> name
  | Struct name -> Printf.sprintf "struct %s" name
  | Enum name -> Printf.sprintf "enum %s" name
  | Option t -> Printf.sprintf "option %s" (string_of_bpf_type t)
  | Result (t1, t2) -> Printf.sprintf "result (%s, %s)" (string_of_bpf_type t1) (string_of_bpf_type t2)
  | Function (params, return_type) ->
      Printf.sprintf "function (%s) -> %s"
        (String.concat ", " (List.map string_of_bpf_type params))
        (string_of_bpf_type return_type)
  | Map (key_type, value_type, map_type, size) ->
      Printf.sprintf "map (%s, %s, %s, %d)"
        (string_of_bpf_type key_type)
        (string_of_bpf_type value_type)
        (string_of_map_type map_type)
        size
  | Xdp_md -> "xdp_md"
  | TracepointContext -> "TracepointContext"
  | Xdp_action -> "xdp_action"
  | ProgramRef pt -> string_of_program_type pt
  | ProgramHandle -> "ProgramHandle"
  | RingbufRef value_type -> Printf.sprintf "ringbuf_ref<%s>" (string_of_bpf_type value_type)
  | Ringbuf (value_type, size) -> Printf.sprintf "ringbuf<%s>(%d)" (string_of_bpf_type value_type) size
  | NoneType -> "none"

let rec string_of_literal = function
  | IntLit (i, original_opt) -> 
      (match original_opt with
       | Some orig -> orig  (* Use original format if available *)
       | None -> string_of_int i)
  | StringLit s -> Printf.sprintf "\"%s\"" s
  | CharLit c -> Printf.sprintf "'%c'" c
  | BoolLit b -> string_of_bool b
  | ArrayLit (FillArray lit) -> Printf.sprintf "[%s]" (string_of_literal lit)
  | ArrayLit (ExplicitArray literals) ->
      Printf.sprintf "[%s]" (String.concat ", " (List.map string_of_literal literals))
  | ArrayLit (ZeroArray) -> "[]"
  | NullLit -> "null"
  | NoneLit -> "none"

let string_of_binary_op = function
  | Add -> "+"
  | Sub -> "-"
  | Mul -> "*"
  | Div -> "/"
  | Mod -> "%"
  | Eq -> "=="
  | Ne -> "!="
  | Lt -> "<"
  | Le -> "<="
  | Gt -> ">"
  | Ge -> ">="
  | And -> "&&"
  | Or -> "||"

let string_of_unary_op = function
  | Not -> "!"
  | Neg -> "-"
  | Deref -> "*"
  | AddressOf -> "&"

let rec string_of_expr expr =
  match expr.expr_desc with
  | Literal lit -> string_of_literal lit
  | Identifier name -> name
  | ConfigAccess (config_name, field_name) ->
      Printf.sprintf "%s.%s" config_name field_name
  | Call (callee_expr, args) ->
      Printf.sprintf "%s(%s)" (string_of_expr callee_expr)
        (String.concat ", " (List.map string_of_expr args))
  | TailCall (name, args) ->
      Printf.sprintf "%s(%s)" name 
        (String.concat ", " (List.map string_of_expr args))
  | ModuleCall module_call ->
      Printf.sprintf "%s.%s(%s)" 
        module_call.module_name 
        module_call.function_name
        (String.concat ", " (List.map string_of_expr module_call.args))
  | ArrayAccess (arr, idx) ->
      Printf.sprintf "%s[%s]" (string_of_expr arr) (string_of_expr idx)
  | FieldAccess (obj, field) ->
      Printf.sprintf "%s.%s" (string_of_expr obj) field
  | ArrowAccess (obj, field) ->
      Printf.sprintf "%s->%s" (string_of_expr obj) field
  | BinaryOp (left, op, right) ->
      Printf.sprintf "(%s %s %s)" 
        (string_of_expr left) (string_of_binary_op op) (string_of_expr right)
  | UnaryOp (op, expr) ->
      Printf.sprintf "(%s%s)" (string_of_unary_op op) (string_of_expr expr)
  | StructLiteral (struct_name, field_assignments) ->
      let field_strs = List.map (fun (field_name, expr) ->
        Printf.sprintf "%s = %s" field_name (string_of_expr expr)
      ) field_assignments in
      Printf.sprintf "struct %s {\n  %s\n}" struct_name (String.concat ",\n  " field_strs)
  | Match (expr, arms) ->
      let arms_str = String.concat ",\n    " (List.map string_of_match_arm arms) in
      Printf.sprintf "match (%s) {\n    %s\n}" (string_of_expr expr) arms_str
  | New typ -> Printf.sprintf "new %s()" (string_of_bpf_type typ)
  | NewWithFlag (typ, flag_expr) -> 
      Printf.sprintf "new %s(%s)" (string_of_bpf_type typ) (string_of_expr flag_expr)

and string_of_match_pattern = function
  | ConstantPattern lit -> string_of_literal lit
  | IdentifierPattern name -> name
  | DefaultPattern -> "default"

and string_of_match_arm arm =
  let body_str = match arm.arm_body with
    | SingleExpr expr -> string_of_expr expr
    | Block stmts -> 
        let stmt_strs = List.map string_of_stmt stmts in
        Printf.sprintf "{\n      %s\n    }" (String.concat "\n      " stmt_strs)
  in
  Printf.sprintf "%s: %s" 
    (string_of_match_pattern arm.arm_pattern) 
    body_str

and string_of_stmt stmt =
  match stmt.stmt_desc with
  | ExprStmt expr -> string_of_expr expr ^ ";"
  | Assignment (name, expr) -> 
      Printf.sprintf "%s = %s;" name (string_of_expr expr)
  | CompoundAssignment (name, op, expr) ->
      Printf.sprintf "%s %s= %s;" name (string_of_binary_op op) (string_of_expr expr)
  | CompoundIndexAssignment (map_expr, key_expr, op, value_expr) ->
      Printf.sprintf "%s[%s] %s= %s;" (string_of_expr map_expr) (string_of_expr key_expr) (string_of_binary_op op) (string_of_expr value_expr)
  | FieldAssignment (obj_expr, field, value_expr) ->
      Printf.sprintf "%s.%s = %s;" (string_of_expr obj_expr) field (string_of_expr value_expr)
  | ArrowAssignment (obj_expr, field, value_expr) ->
      Printf.sprintf "%s->%s = %s;" (string_of_expr obj_expr) field (string_of_expr value_expr)
  | IndexAssignment (map_expr, key_expr, value_expr) ->
      Printf.sprintf "%s[%s] = %s;" (string_of_expr map_expr) (string_of_expr key_expr) (string_of_expr value_expr)
  | Declaration (name, typ_opt, expr_opt) ->
      let typ_str = match typ_opt with
        | Some t -> ": " ^ string_of_bpf_type t
        | None -> ""
      in
      let init_str = match expr_opt with
        | Some expr -> " = " ^ string_of_expr expr
        | None -> ""
      in
      Printf.sprintf "var %s%s%s;" name typ_str init_str
  | ConstDeclaration (name, typ_opt, expr) ->
      let typ_str = match typ_opt with
        | Some t -> ": " ^ string_of_bpf_type t
        | None -> ""
      in
      Printf.sprintf "const %s%s = %s;" name typ_str (string_of_expr expr)
  | Return None -> "return;"
  | Return (Some expr) -> Printf.sprintf "return %s;" (string_of_expr expr)
  | If (cond, then_stmts, else_opt) ->
      let then_str = String.concat " " (List.map string_of_stmt then_stmts) in
      let else_str = match else_opt with
        | None -> ""
        | Some else_stmts -> 
            " else { " ^ String.concat " " (List.map string_of_stmt else_stmts) ^ " }"
      in
      Printf.sprintf "if (%s) { %s }%s" (string_of_expr cond) then_str else_str
  | For (var, start, end_, body) ->
      let body_str = String.concat " " (List.map string_of_stmt body) in
      Printf.sprintf "for (%s in %s..%s) { %s }" 
        var (string_of_expr start) (string_of_expr end_) body_str
  | ForIter (index_var, value_var, iterable, body) ->
      let body_str = String.concat " " (List.map string_of_stmt body) in
      Printf.sprintf "for (%s, %s) in %s.iter() { %s }" 
        index_var value_var (string_of_expr iterable) body_str
  | While (cond, body) ->
      let body_str = String.concat " " (List.map string_of_stmt body) in
      Printf.sprintf "while (%s) { %s }" (string_of_expr cond) body_str
  | Delete (DeleteMapEntry (map_expr, key_expr)) ->
      Printf.sprintf "delete %s[%s];" (string_of_expr map_expr) (string_of_expr key_expr)
  | Delete (DeletePointer ptr_expr) ->
      Printf.sprintf "delete %s;" (string_of_expr ptr_expr)
  | Break -> "break;"
  | Continue -> "continue;"
  | Try (statements, catch_clauses) ->
      let statements_str = String.concat " " (List.map string_of_stmt statements) in
      let catch_clauses_str = String.concat " " (List.map (fun _ -> "catch {...}") catch_clauses) in
      Printf.sprintf "try { %s } %s" statements_str catch_clauses_str
  | Throw expr ->
      Printf.sprintf "throw %s;" (string_of_expr expr)
  | Defer expr ->
      Printf.sprintf "defer %s;" (string_of_expr expr)

let string_of_function func =
  let params_str = String.concat ", " 
    (List.map (fun (name, typ) -> 
       Printf.sprintf "%s: %s" name (string_of_bpf_type typ)) func.func_params) in
  let return_str = match func.func_return_type with
    | None -> ""
    | Some (Unnamed t) -> " -> " ^ string_of_bpf_type t
    | Some (Named (name, t)) -> " -> " ^ name ^ ": " ^ string_of_bpf_type t
  in
  let body_str = String.concat "\n  " (List.map string_of_stmt func.func_body) in
  Printf.sprintf "fn %s(%s)%s {\n  %s\n}" 
    func.func_name params_str return_str body_str

let string_of_program prog =
  let functions_str = String.concat "\n\n  " 
    (List.map string_of_function prog.prog_functions) in
  Printf.sprintf "program %s : %s {\n  %s\n}" 
    prog.prog_name (string_of_program_type prog.prog_type) functions_str

let string_of_attribute = function
  | SimpleAttribute name -> "@" ^ name
  | AttributeWithArg (name, arg) -> "@" ^ name ^ "(\"" ^ arg ^ "\")"

let string_of_attributed_function attr_func =
  let attrs_str = String.concat " " (List.map string_of_attribute attr_func.attr_list) in
  attrs_str ^ " " ^ string_of_function attr_func.attr_function

let string_of_declaration = function
  | AttributedFunction attr_func -> string_of_attributed_function attr_func
  | GlobalFunction func -> string_of_function func
  | TypeDef td ->
      let type_str = match td with
        | StructDef (name, fields) ->
            Printf.sprintf "struct %s {\n  %s\n}" name
              (String.concat "\n  " (List.map (fun (name, typ) ->
                Printf.sprintf "%s: %s;" name (string_of_bpf_type typ)) fields))
        | EnumDef (name, values) ->
            Printf.sprintf "enum %s {\n  %s\n}" name
              (String.concat ",\n  " (List.map (fun (name, opt) ->
                match opt with
                | None -> name
                | Some v -> Printf.sprintf "%s = %d" name v) values))
        | TypeAlias (name, typ) ->
            Printf.sprintf "type %s = %s;" name (string_of_bpf_type typ)
      in
      type_str
  | MapDecl md ->
      let pin_str = if md.is_pinned then "pin " else "" in
      let flags_str = if md.config.flags = [] then "" else
        "@flags(" ^ (String.concat " | " (List.map string_of_map_flag md.config.flags)) ^ ") "
      in
      Printf.sprintf "%s%smap<%s, %s> %s : %s(%s)"
        flags_str
        pin_str
        (string_of_bpf_type md.key_type)
        (string_of_bpf_type md.value_type)
        md.name
        (string_of_map_type md.map_type)
        (string_of_int md.config.max_entries)
  | ConfigDecl config_decl ->
      let fields_str = String.concat ",\n    " (List.map (fun field ->
        let default_str = match field.field_default with
          | Some lit -> " = " ^ string_of_literal lit
          | None -> ""
        in
        Printf.sprintf "%s: %s%s" field.field_name (string_of_bpf_type field.field_type) default_str
      ) config_decl.config_fields) in
      Printf.sprintf "config %s {\n    %s\n}" config_decl.config_name fields_str
  | StructDecl struct_def ->
      let attrs_str = if struct_def.struct_attributes = [] then "" else
        (String.concat " " (List.map string_of_attribute struct_def.struct_attributes)) ^ "\n" in
      let fields_str = String.concat ",\n    " (List.map (fun (name, typ) ->
        Printf.sprintf "%s: %s" name (string_of_bpf_type typ)
      ) struct_def.struct_fields) in
      Printf.sprintf "%sstruct %s {\n    %s\n}" attrs_str struct_def.struct_name fields_str
  | GlobalVarDecl decl ->
      let pin_str = if decl.is_pinned then "pin " else "" in
      let local_str = if decl.is_local then "local " else "" in
      let type_str = match decl.global_var_type with
        | None -> ""
        | Some t -> ": " ^ string_of_bpf_type t
      in
      let init_str = match decl.global_var_init with
        | None -> ""
        | Some expr -> " = " ^ string_of_expr expr
      in
      Printf.sprintf "%s%svar %s%s%s;" pin_str local_str decl.global_var_name type_str init_str
  | ImplBlock impl_block ->
      let attrs_str = String.concat " " (List.map string_of_attribute impl_block.impl_attributes) in
      let items_str = String.concat "\n    " (List.map (function
        | ImplFunction func -> string_of_function func
        | ImplStaticField (name, expr) -> Printf.sprintf "%s: %s," name (string_of_expr expr)
      ) impl_block.impl_items) in
      Printf.sprintf "%s impl %s {\n    %s\n}" attrs_str impl_block.impl_name items_str
  | ImportDecl import_decl ->
      let source_type_str = match import_decl.source_type with
        | KernelScript -> "KernelScript"
        | Python -> "Python"
      in
      Printf.sprintf "import %s from \"%s\" // %s" 
        import_decl.module_name 
        import_decl.source_path 
        source_type_str
  | ExternKfuncDecl extern_decl ->
      let params_str = String.concat ", " (List.map (fun (name, typ) ->
        Printf.sprintf "%s: %s" name (string_of_bpf_type typ)
      ) extern_decl.extern_params) in
      let return_str = match extern_decl.extern_return_type with
        | Some typ -> " -> " ^ string_of_bpf_type typ
        | None -> ""
      in
      Printf.sprintf "extern %s(%s)%s;" extern_decl.extern_name params_str return_str
  | IncludeDecl include_decl ->
      Printf.sprintf "include \"%s\"" include_decl.include_path

let string_of_ast ast =
  String.concat "\n\n" (List.map string_of_declaration ast)

(** Debug printing functions *)

let print_position pos =
  print_endline (string_of_position pos)

let print_expr expr =
  print_endline (string_of_expr expr)

let print_stmt stmt =
  print_endline (string_of_stmt stmt)

let print_function func =
  print_endline (string_of_function func)

let print_program prog =
  print_endline (string_of_program prog)

let print_ast ast =
  print_endline (string_of_ast ast) 