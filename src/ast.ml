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

(** Program types supported by KernelScript *)
type program_type = 
  | Xdp | Tc | Kprobe | Uprobe | Tracepoint | Lsm | CgroupSkb

(** Map types for eBPF maps *)
type map_type =
  | HashMap | Array | PercpuHash | PercpuArray
  | LruHash | RingBuffer | PerfEvent

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
  | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 | Bool | Char
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
  | Map of bpf_type * bpf_type * map_type
  (* Built-in context types *)
  | XdpContext | TcContext | KprobeContext | UprobeContext 
  | TracepointContext | LsmContext | CgroupSkbContext
  | XdpAction | TcAction
  (* Program reference types *)
  | ProgramRef of program_type
  (* Program handle type - represents a loaded program *)
  | ProgramHandle

(** Map configuration and attributes *)
type map_attribute =
  | Pinned of string
  | FlagsAttr of map_flag list

type map_config = {
  max_entries: int;
  key_size: int option;
  value_size: int option;
  attributes: map_attribute list;
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
  map_pos: position;
}

(** Literal values *)
type literal =
  | IntLit of int 
  | StringLit of string 
  | CharLit of char 
  | BoolLit of bool
  | ArrayLit of literal list

(** Binary operators *)
type binary_op =
  | Add | Sub | Mul | Div | Mod
  | Eq | Ne | Lt | Le | Gt | Ge
  | And | Or

(** Unary operators *)
type unary_op =
  | Not | Neg

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
  | ConfigAccess of string * string  (* config_name.field_name *)
  | FunctionCall of string * expr list
  | ArrayAccess of expr * expr
  | FieldAccess of expr * string
  | BinaryOp of expr * binary_op * expr
  | UnaryOp of unary_op * expr

(** Statements with position tracking *)
type statement = {
  stmt_desc: stmt_desc;
  stmt_pos: position;
}

and stmt_desc =
  | ExprStmt of expr
  | Assignment of string * expr
  | FieldAssignment of expr * string * expr  (* object.field = value *)
  | IndexAssignment of expr * expr * expr  (* map[key] = value *)
  | Declaration of string * bpf_type option * expr
  | Return of expr option
  | If of expr * statement list * statement list option
  | For of string * expr * expr * statement list
  | ForIter of string * string * expr * statement list  (* for (index, value) in expr.iter() { ... } *)
  | While of expr * statement list
  | Delete of expr * expr  (* delete map[key] *)
  | Break
  | Continue
  | Try of statement list * catch_clause list  (* try { statements } catch clauses *)
  | Throw of expr  (* throw integer_expression *)
  | Defer of expr  (* defer function_call *)

(** Catch clause definition *)
and catch_clause = {
  catch_pattern: catch_pattern;
  catch_body: statement list;
  catch_pos: position;
}

(** Function definitions *)
type function_def = {
  func_name: string;
  func_params: (string * bpf_type) list;
  func_return_type: bpf_type option;
  func_body: statement list;
  func_pos: position;
}



and struct_def = {
  struct_name: string;
  struct_fields: (string * bpf_type) list;
  struct_pos: position;
}



(** Program definition *)
type program_def = {
  prog_name: string;
  prog_type: program_type;
  prog_functions: function_def list;
  prog_maps: map_declaration list; (* Maps local to this program *)
  prog_structs: struct_def list; (* Structs local to this program *)
  prog_pos: position;
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

(** Top-level declarations *)
type declaration =
  | Program of program_def
  | GlobalFunction of function_def
  | TypeDef of type_def
  | MapDecl of map_declaration
  | ConfigDecl of config_declaration
  | StructDecl of struct_def
  

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

let make_function name params return_type body pos = {
  func_name = name;
  func_params = params;
  func_return_type = return_type;
  func_body = body;
  func_pos = pos;
}

let make_program name prog_type functions pos = {
  prog_name = name;
  prog_type = prog_type;
  prog_functions = functions;
  prog_maps = [];
  prog_structs = [];
  prog_pos = pos;
}

let make_program_with_maps name prog_type functions maps pos = {
  prog_name = name;
  prog_type = prog_type;
  prog_functions = functions;
  prog_maps = maps;
  prog_structs = [];
  prog_pos = pos;
}

let make_program_with_all name prog_type functions maps structs pos = {
  prog_name = name;
  prog_type = prog_type;
  prog_functions = functions;
  prog_maps = maps;
  prog_structs = structs;
  prog_pos = pos;
}

let make_type_def def = def

let make_enum_def name values = EnumDef (name, values)

let make_type_alias name bpf_type = TypeAlias (name, bpf_type)

let make_map_config max_entries ?key_size ?value_size ?(flags=[]) attributes = 
  (* Extract flags from attributes and combine with explicit flags *)
  let (regular_attrs, extracted_flags) = List.fold_left (fun (attrs, flags_acc) attr ->
    match attr with
    | FlagsAttr flag_list -> (attrs, flag_list @ flags_acc)
    | other -> (other :: attrs, flags_acc)
  ) ([], flags) attributes in
  {
    max_entries;
    key_size;
    value_size;
    attributes = List.rev regular_attrs;
    flags = extracted_flags;
  }

let make_map_declaration name key_type value_type map_type config is_global pos = {
  name;
  key_type;
  value_type;
  map_type;
  config;
  is_global;
  map_pos = pos;
}



let make_struct_def name fields pos = {
  struct_name = name;
  struct_fields = fields;
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

(** Pretty-printing functions for debugging *)

let string_of_position pos =
  Printf.sprintf "%s:%d:%d" pos.filename pos.line pos.column

let string_of_program_type = function
  | Xdp -> "xdp"
  | Tc -> "tc"
  | Kprobe -> "kprobe"
  | Uprobe -> "uprobe"
  | Tracepoint -> "tracepoint"
  | Lsm -> "lsm"
  | CgroupSkb -> "cgroup_skb"

let string_of_map_type = function
  | HashMap -> "hash_map"
  | Array -> "array"
  | PercpuHash -> "percpu_hash"
  | PercpuArray -> "percpu_array"
  | LruHash -> "lru_hash"
  | RingBuffer -> "ring_buffer"
  | PerfEvent -> "perf_event"

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
  | Str size -> Printf.sprintf "str<%d>" size
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
  | Map (key_type, value_type, map_type) ->
      Printf.sprintf "map (%s, %s, %s)"
        (string_of_bpf_type key_type)
        (string_of_bpf_type value_type)
        (string_of_map_type map_type)
  | XdpContext -> "XdpContext"
  | TcContext -> "TcContext"
  | KprobeContext -> "KprobeContext"
  | UprobeContext -> "UprobeContext"
  | TracepointContext -> "TracepointContext"
  | LsmContext -> "LsmContext"
  | CgroupSkbContext -> "CgroupSkbContext"
  | XdpAction -> "XdpAction"
  | TcAction -> "TcAction"
  | ProgramRef pt -> string_of_program_type pt
  | ProgramHandle -> "ProgramHandle"

let rec string_of_literal = function
  | IntLit i -> string_of_int i
  | StringLit s -> Printf.sprintf "\"%s\"" s
  | CharLit c -> Printf.sprintf "'%c'" c
  | BoolLit b -> string_of_bool b
  | ArrayLit literals -> 
      Printf.sprintf "[%s]" (String.concat ", " (List.map string_of_literal literals))

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

let rec string_of_expr expr =
  match expr.expr_desc with
  | Literal lit -> string_of_literal lit
  | Identifier name -> name
  | ConfigAccess (config_name, field_name) ->
      Printf.sprintf "%s.%s" config_name field_name
  | FunctionCall (name, args) ->
      Printf.sprintf "%s(%s)" name 
        (String.concat ", " (List.map string_of_expr args))
  | ArrayAccess (arr, idx) ->
      Printf.sprintf "%s[%s]" (string_of_expr arr) (string_of_expr idx)
  | FieldAccess (obj, field) ->
      Printf.sprintf "%s.%s" (string_of_expr obj) field
  | BinaryOp (left, op, right) ->
      Printf.sprintf "(%s %s %s)" 
        (string_of_expr left) (string_of_binary_op op) (string_of_expr right)
  | UnaryOp (op, expr) ->
      Printf.sprintf "(%s%s)" (string_of_unary_op op) (string_of_expr expr)

let rec string_of_stmt stmt =
  match stmt.stmt_desc with
  | ExprStmt expr -> string_of_expr expr ^ ";"
  | Assignment (name, expr) -> 
      Printf.sprintf "%s = %s;" name (string_of_expr expr)
  | FieldAssignment (obj_expr, field, value_expr) ->
      Printf.sprintf "%s.%s = %s;" (string_of_expr obj_expr) field (string_of_expr value_expr)
  | IndexAssignment (map_expr, key_expr, value_expr) ->
      Printf.sprintf "%s[%s] = %s;" (string_of_expr map_expr) (string_of_expr key_expr) (string_of_expr value_expr)
  | Declaration (name, typ_opt, expr) ->
      let typ_str = match typ_opt with
        | Some t -> ": " ^ string_of_bpf_type t
        | None -> ""
      in
      Printf.sprintf "let %s%s = %s;" name typ_str (string_of_expr expr)
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
  | Delete (map_expr, key_expr) ->
      Printf.sprintf "delete %s[%s];" (string_of_expr map_expr) (string_of_expr key_expr)
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
    | Some t -> " -> " ^ string_of_bpf_type t
  in
  let body_str = String.concat "\n  " (List.map string_of_stmt func.func_body) in
  Printf.sprintf "fn %s(%s)%s {\n  %s\n}" 
    func.func_name params_str return_str body_str

let string_of_program prog =
  let functions_str = String.concat "\n\n  " 
    (List.map string_of_function prog.prog_functions) in
  Printf.sprintf "program %s : %s {\n  %s\n}" 
    prog.prog_name (string_of_program_type prog.prog_type) functions_str

let string_of_declaration = function
  | Program prog -> string_of_program prog
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
      let attr_strs = List.map (fun attr ->
        match attr with
        | Pinned path -> Printf.sprintf "pinned = \"%s\"" path
        | FlagsAttr flags -> Printf.sprintf "flags = %s" 
            (String.concat " | " (List.map string_of_map_flag flags))
      ) md.config.attributes in
      let config_str = Printf.sprintf "max_entries = %d" md.config.max_entries in
      let all_config = config_str :: attr_strs in
      Printf.sprintf "map<%s, %s> %s : %s(%s) {\n  %s\n}"
        (string_of_bpf_type md.key_type)
        (string_of_bpf_type md.value_type)
        md.name
        (string_of_map_type md.map_type)
        (string_of_int md.config.max_entries)
        (String.concat ";\n  " all_config)
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
      let fields_str = String.concat ",\n    " (List.map (fun (name, typ) ->
        Printf.sprintf "%s: %s" name (string_of_bpf_type typ)
      ) struct_def.struct_fields) in
      Printf.sprintf "struct %s {\n    %s\n}" struct_def.struct_name fields_str


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