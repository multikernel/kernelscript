(** Type checker for KernelScript 
    
    This module implements static type checking for the KernelScript language,
    including multi-program awareness for eBPF development.
*)

open Ast

(** Type checking exceptions *)
exception Type_error of string * position
exception Unification_error of bpf_type * bpf_type * position

(** Type checking context *)
type context = {
  symbol_table: Symbol_table.symbol_table;
  variables: (string, bpf_type) Hashtbl.t;
  types: (string, type_def) Hashtbl.t;
  functions: (string, bpf_type list * bpf_type) Hashtbl.t;
  function_scopes: (string, Ast.function_scope) Hashtbl.t;
  maps: (string, Ast.map_declaration) Hashtbl.t;
  configs: (string, Ast.config_declaration) Hashtbl.t;
  attributed_functions: (string, unit) Hashtbl.t; (* Track attributed functions that cannot be called directly *)
  attributed_function_map: (string, attributed_function) Hashtbl.t; (* Map for tail call analysis *)
  mutable current_function: string option;
  mutable current_program_type: program_type option;
  mutable multi_program_analysis: Multi_program_analyzer.multi_program_analysis option;
  in_tail_call_context: bool; (* Flag to indicate we're processing a potential tail call *)
}

(** Typed AST nodes *)
type typed_expr = {
  texpr_desc: typed_expr_desc;
  texpr_type: bpf_type;
  texpr_pos: position;
}

and typed_expr_desc =
  | TLiteral of literal
  | TIdentifier of string
  | TConfigAccess of string * string  (* config_name, field_name *)
  | TFunctionCall of string * typed_expr list
  | TTailCall of string * typed_expr list  (* Tail call detected in return position *)
  | TArrayAccess of typed_expr * typed_expr
  | TFieldAccess of typed_expr * string
  | TBinaryOp of typed_expr * binary_op * typed_expr
  | TUnaryOp of unary_op * typed_expr
  | TStructLiteral of string * (string * typed_expr) list

type typed_statement = {
  tstmt_desc: typed_stmt_desc;
  tstmt_pos: position;
}

and typed_stmt_desc =
  | TExprStmt of typed_expr
  | TAssignment of string * typed_expr
  | TFieldAssignment of typed_expr * string * typed_expr  (* object, field, value *)
  | TIndexAssignment of typed_expr * typed_expr * typed_expr
  | TDeclaration of string * bpf_type * typed_expr
  | TConstDeclaration of string * bpf_type * typed_expr
  | TReturn of typed_expr option
  | TIf of typed_expr * typed_statement list * typed_statement list option
  | TFor of string * typed_expr * typed_expr * typed_statement list
  | TForIter of string * string * typed_expr * typed_statement list
  | TWhile of typed_expr * typed_statement list
  | TDelete of typed_expr * typed_expr
  | TBreak
  | TContinue
  | TTry of typed_statement list * catch_clause list  (* try statements, catch clauses *)
  | TThrow of typed_expr  (* throw statements with expression *)
  | TDefer of typed_expr  (* defer expression *)

type typed_function = {
  tfunc_name: string;
  tfunc_params: (string * bpf_type) list;
  tfunc_return_type: bpf_type;
  tfunc_body: typed_statement list;
  tfunc_scope: Ast.function_scope;
  tfunc_pos: position;
}

type typed_program = {
  tprog_name: string;
  tprog_type: program_type;
  tprog_functions: typed_function list;
  tprog_maps: map_declaration list;
  tprog_pos: position;
}

(** Create type checking context *)
let create_context symbol_table = {
  variables = Hashtbl.create 32;
  functions = Hashtbl.create 16;
  function_scopes = Hashtbl.create 16;
  attributed_functions = Hashtbl.create 16;
  types = Hashtbl.create 16;
  maps = Hashtbl.create 16;
  configs = Hashtbl.create 16;
  symbol_table = symbol_table;
  current_function = None;
  current_program_type = None;
  multi_program_analysis = None;
  in_tail_call_context = false;
  attributed_function_map = Hashtbl.create 16;
}

(** Track loop nesting depth to prevent nested loops *)
let loop_depth = ref 0

(** Helper to create type error *)
let type_error msg pos = raise (Type_error (msg, pos))

(** Resolve user types to built-in types and type aliases *)
let rec resolve_user_type ctx = function
  | UserType "XdpContext" -> XdpContext
  | UserType "TcContext" -> TcContext
  | UserType "KprobeContext" -> KprobeContext
  | UserType "UprobeContext" -> UprobeContext
  | UserType "TracepointContext" -> TracepointContext
  | UserType "LsmContext" -> LsmContext
  | UserType "CgroupSkbContext" -> CgroupSkbContext
  | UserType "XdpAction" -> XdpAction
  | UserType "TcAction" -> TcAction
  | UserType name ->
      (* Look up type alias in the context *)
      (try
         let type_def = Hashtbl.find ctx.types name in
         match type_def with
         | TypeAlias (_, underlying_type) -> 
             (* Recursively resolve the underlying type in case it's also an alias *)
             resolve_user_type ctx underlying_type
         | StructDef (_, _) -> Struct name
         | EnumDef (_, _) -> Enum name
       with Not_found -> UserType name)
  | other_type -> other_type

(** C-style integer promotion - promotes to the larger type *)
let integer_promotion t1 t2 =
  match t1, t2 with
  (* Identical types *)
  | t1, t2 when t1 = t2 -> Some t1
  
  (* Unsigned integer promotions - promote to larger type *)
  | U8, U16 | U16, U8 -> Some U16
  | U8, U32 | U16, U32 | U32, U8 | U32, U16 -> Some U32
  | U8, U64 | U16, U64 | U32, U64 | U64, U8 | U64, U16 | U64, U32 -> Some U64
  
  (* Signed integer promotions - promote to larger type *)
  | I8, I16 | I16, I8 -> Some I16
  | I8, I32 | I16, I32 | I32, I8 | I32, I16 -> Some I32
  | I8, I64 | I16, I64 | I32, I64 | I64, I8 | I64, I16 | I64, I32 -> Some I64
  
  (* Mixed signed/unsigned promotions - like C allows *)
  | I8, U32 | I16, U32 | I32, U32 -> Some I32   (* U32 literals can be assigned to signed types if they fit *)
  | I64, U32 -> Some I64   (* U32 can always fit in I64 *)
  | I64, U64 -> Some I64   (* U64 literals to I64 (may truncate but allowed in C-style) *)
  
  (* No other unification possible *)
  | _ -> None

let rec unify_types t1 t2 =
  match t1, t2 with
  (* Identical types *)
  | t1, t2 when t1 = t2 -> Some t1
  
  (* String types - allow smaller strings to fit into larger ones *)
  | Str size1, Str size2 when size1 <= size2 -> Some (Str size2)
  | Str size1, Str size2 when size2 <= size1 -> Some (Str size1)
  
  (* Integer type promotions using C-style rules *)
  | t1, t2 when (match t1, t2 with 
                  | (U8|U16|U32|U64), (U8|U16|U32|U64) -> true
                  | (I8|I16|I32|I64), (I8|I16|I32|I64) -> true
                  | _ -> false) ->
      integer_promotion t1 t2
  
  (* Array types *)
  | Array (t1, s1), Array (t2, s2) when s1 = s2 ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Array (unified, s1))
       | None -> None)
  
  (* Pointer types - any pointer can be null *)
  | Pointer t1, Pointer t2 ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Pointer unified)
       | None -> None)
  
  (* Result types *)
  | Result (ok1, err1), Result (ok2, err2) ->
      (match unify_types ok1 ok2, unify_types err1 err2 with
       | Some unified_ok, Some unified_err -> Some (Result (unified_ok, unified_err))
       | _ -> None)
  
  (* Function types - allow any function to unify with any other function for parameter passing *)
  | Function (params1, ret1), Function (_, _) ->
      (* For function parameters, we're more flexible - any function can be passed as a function parameter *)
      (* This enables passing functions as parameters without strict signature matching *)
      Some (Function (params1, ret1))  (* Keep the original function type *)
  
  (* Map types *)
  | Map (k1, v1, mt1), Map (k2, v2, mt2) when mt1 = mt2 ->
      (match unify_types k1 k2, unify_types v1 v2 with
       | Some unified_k, Some unified_v -> Some (Map (unified_k, unified_v, mt1))
       | _ -> None)
  
  (* Program reference types *)
  | ProgramRef pt1, ProgramRef pt2 when pt1 = pt2 -> Some (ProgramRef pt1)
  
  (* Enum-integer compatibility: enums are represented as u32 *)
  | Enum _, U32 | U32, Enum _ -> Some U32
  | Enum enum_name, Enum other_name when enum_name = other_name -> Some (Enum enum_name)
  
  (* No unification possible *)
  | _ -> None

(** Check if we can assign from_type to to_type (for variable declarations) *)
let can_assign to_type from_type =
  match unify_types to_type from_type with
  | Some _ -> true
  | None ->
      (* Allow assignment if types can be promoted *)
      (match integer_promotion to_type from_type with
       | Some _ -> true
       | None -> false)

(** Get built-in function signatures *)
let get_builtin_function_signature name =
  (* First check stdlib for built-in functions *)
  match Stdlib.get_builtin_function_signature name with
  | Some signature -> Some signature
  | None ->
      (* Fallback to existing hardcoded built-ins for compatibility *)
      match name with
      (* XDP context methods *)
      | "ctx.packet" -> Some ([], Pointer U8)
      | "ctx.data_end" -> Some ([], Pointer U8)
      | "ctx.get_packet_id" -> Some ([], U32)
      | "ctx.log_packet" -> Some ([Struct "PacketInfo"], U32)
      
      (* Map operations *)
      | name when String.contains name '.' ->
          let parts = String.split_on_char '.' name in
          (match parts with
           | [_map_name; "lookup"] -> Some ([Pointer U8], Pointer U8)
           | [_map_name; "insert"] -> Some ([Pointer U8; Pointer U8], U32)
           | [_map_name; "update"] -> Some ([Pointer U8; Pointer U8], U32)
           | [_map_name; "delete"] -> Some ([Pointer U8], U32)
           | _ -> None)
      
      (* Type conversion functions *)
      | "Protocol.from_u8" -> Some ([U8], Pointer (Enum "Protocol"))
      
      | _ -> None

(** Type check literals *)
let type_check_literal lit pos =
  let typ = match lit with
    | IntLit (value, _) -> 
        (* Choose appropriate integer type based on the value *)
        if value < 0 then I32  (* Signed integers for negative values *)
        else U32  (* Unsigned integers for positive values *)
    | StringLit s -> 
        (* String literals are polymorphic - they can unify with any string type *)
        (* For now, we'll use a default size but this will be refined during unification *)
        let len = String.length s in
        Str (max 1 len)  (* At least size 1 to handle empty strings *)
    | CharLit _ -> Char
    | BoolLit _ -> Bool
    | NullLit -> Pointer U32  (* null literal as nullable pointer, can be unified with any pointer type *)
    | ArrayLit literals ->
        (* Implement proper array literal type checking *)
        (match literals with
         | [] -> Array (U32, 0)  (* Empty array defaults to u32 *)
         | first_lit :: rest_lits ->
             let first_type = match first_lit with
               | IntLit (value, _) -> if value < 0 then I32 else U32
               | BoolLit _ -> Bool
               | CharLit _ -> Char
               | StringLit s -> Str (max 1 (String.length s))
               | ArrayLit _ -> U32  (* Nested arrays default to u32 for now *)
               | NullLit -> Pointer U32  (* null in arrays as nullable pointer *)
             in
             (* Verify all elements have the same type *)
             let all_same_type = List.for_all (fun lit ->
               let lit_type = match lit with
                 | IntLit (value, _) -> if value < 0 then I32 else U32
                 | BoolLit _ -> Bool
                 | CharLit _ -> Char
                 | StringLit s -> Str (max 1 (String.length s))
                 | ArrayLit _ -> U32
                 | NullLit -> Pointer U32
               in
               lit_type = first_type
             ) rest_lits in
             if not all_same_type then
               type_error "All elements in array literal must have the same type" pos
             else
               Array (first_type, List.length literals))
  in
  { texpr_desc = TLiteral lit; texpr_type = typ; texpr_pos = pos }

(** Set multi-program context for an expression *)
let set_multi_program_context ctx expr =
  (* Set program context *)
  (match ctx.current_program_type with
   | Some prog_type ->
       expr.program_context <- Some {
         current_program = Some prog_type;
         accessing_programs = [prog_type];
         data_flow_direction = Some Read; (* Default to read, will be updated for writes *)
       }
   | None -> ());
  
  (* Set map scope if this is a map access *)
  (match expr.expr_desc with
   | Identifier name | ArrayAccess ({expr_desc = Identifier name; _}, _) ->
       if Hashtbl.mem ctx.maps name then (
         let map_decl = Hashtbl.find ctx.maps name in
         expr.map_scope <- Some (if map_decl.is_global then Global else Local)
       )
   | _ -> ());
  
  (* Mark as type checked *)
  expr.type_checked <- true

let type_check_identifier ctx name pos =
  (* Check for special constants first *)
  if String.contains name ':' then
    (* Handle double colon syntax Type::Value *)
    let parts = String.split_on_char ':' name in
    let filtered_parts = List.filter (fun s -> s <> "") parts in
    match filtered_parts with
    | ["XdpAction"; _] -> { texpr_desc = TIdentifier name; texpr_type = XdpAction; texpr_pos = pos }
    | ["TcAction"; _] -> { texpr_desc = TIdentifier name; texpr_type = TcAction; texpr_pos = pos }
    | [enum_name; _] ->
        (* Try to find enum type *)
        (try
           let _ = Hashtbl.find ctx.types enum_name in
           { texpr_desc = TIdentifier name; texpr_type = Enum enum_name; texpr_pos = pos }
         with Not_found ->
           type_error ("Undefined enum: " ^ enum_name) pos)
    | _ -> type_error ("Invalid constant: " ^ name) pos
  else
    try
      let typ = Hashtbl.find ctx.variables name in
      { texpr_desc = TIdentifier name; texpr_type = typ; texpr_pos = pos }
    with Not_found ->
      (* Check if it's a function that could be used as a reference *)
      if Hashtbl.mem ctx.functions name then
        let (param_types, return_type) = Hashtbl.find ctx.functions name in
        (* For attributed functions, we can create a function reference *)
        { texpr_desc = TIdentifier name; texpr_type = Function (param_types, return_type); texpr_pos = pos }
      (* Check if it's a map - but don't create a Map type for standalone identifiers *)
      else if Hashtbl.mem ctx.maps name then
        type_error ("Map '" ^ name ^ "' cannot be used as a standalone identifier. Use map[key] for map access.") pos
      else
        type_error ("Undefined variable: " ^ name) pos



(** Detect and validate tail calls in return statements *)
let detect_tail_call_in_return_expr ctx expr =
  match expr.expr_desc with
  | FunctionCall (name, args) ->
      (* Check if target is an attributed function *)
      if Hashtbl.mem ctx.attributed_function_map name then
        let target_func = Hashtbl.find ctx.attributed_function_map name in
        (match ctx.current_program_type with
         | Some current_type ->
             let target_type = Tail_call_analyzer.extract_program_type target_func.attr_list in
             (match target_type with
              | Some tt when Tail_call_analyzer.compatible_program_types current_type tt ->
                  (* Valid tail call - check signature compatibility *)
                  let current_func_name = match ctx.current_function with
                    | Some name -> name
                    | None -> "unknown"
                  in
                  if Hashtbl.mem ctx.attributed_function_map current_func_name then
                    let current_func = Hashtbl.find ctx.attributed_function_map current_func_name in
                    if Tail_call_analyzer.compatible_signatures
                        current_func.attr_function.func_params
                        current_func.attr_function.func_return_type
                        target_func.attr_function.func_params
                        target_func.attr_function.func_return_type then
                      Some (name, args) (* Valid tail call *)
                    else
                      type_error ("Tail call to '" ^ name ^ "' has incompatible signature") expr.expr_pos
                  else
                    None (* Not in attributed function context *)
              | Some _tt ->
                  type_error ("Tail call to '" ^ name ^ "' has incompatible program type") expr.expr_pos
              | None ->
                  type_error ("Tail call target '" ^ name ^ "' has invalid program type") expr.expr_pos)
         | None ->
             None (* Not in attributed function context - regular call *))
      else
        None (* Not an attributed function - regular call *)
  | _ -> None (* Not a function call *)

(** Type check array access *)
let rec type_check_array_access ctx arr idx pos =
  let typed_idx = type_check_expression ctx idx in
  
  (* Index must be integer type *)
  (match typed_idx.texpr_type with
   | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 -> ()
   | _ -> type_error "Array index must be integer type" pos);
  
  (* Check if this is map access first *)
  (match arr.expr_desc with
   | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
       (* This is map access *)
       let map_decl = Hashtbl.find ctx.maps map_name in
       (* Check key type compatibility *)
       let resolved_map_key_type = resolve_user_type ctx map_decl.key_type in
       let resolved_idx_type = resolve_user_type ctx typed_idx.texpr_type in
       (match unify_types resolved_map_key_type resolved_idx_type with
        | Some _ -> 
            (* Create a synthetic map type for the result *)
            let typed_arr = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.key_type, map_decl.value_type, map_decl.map_type); texpr_pos = arr.expr_pos } in
            (* Map access returns the value type directly, but can be null at runtime *)
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = map_decl.value_type; texpr_pos = pos }
        | None -> type_error ("Map key type mismatch") pos)
   | _ ->
       (* Regular array access *)
       let typed_arr = type_check_expression ctx arr in
       (match typed_arr.texpr_type with
        | Array (element_type, _) ->
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = element_type; texpr_pos = pos }
        | Pointer element_type ->
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = element_type; texpr_pos = pos }
        | Str _ ->
            (* String indexing returns char *)
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = Char; texpr_pos = pos }
        | Map (key_type, value_type, _) ->
            (* This shouldn't happen anymore, but handle it for safety *)
            (match unify_types key_type typed_idx.texpr_type with
             | Some _ -> { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = value_type; texpr_pos = pos }
             | None -> type_error ("Map key type mismatch") pos)
        | _ ->
            type_error "Cannot index non-array/non-map type" pos))

(** Type check field access *)
and type_check_field_access ctx obj field pos =
  (* First check if this is actually a config access (identifier.field) *)
  (match obj.expr_desc with
   | Identifier config_name when Hashtbl.mem ctx.configs config_name ->
       (* This is a config access - handle it as TConfigAccess *)
       let config_decl = Hashtbl.find ctx.configs config_name in
       (* Validate that field exists in config *)
       let field_type = try
         let config_field = List.find (fun f -> f.field_name = field) config_decl.config_fields in
         config_field.field_type
       with Not_found ->
         type_error (Printf.sprintf "Config '%s' has no field '%s'" config_name field) pos
       in
       { texpr_desc = TConfigAccess (config_name, field); texpr_type = field_type; texpr_pos = pos }
   | _ ->
       (* Regular field access - process normally *)
       let typed_obj = type_check_expression ctx obj in
       
       match typed_obj.texpr_type with
  | Struct struct_name | UserType struct_name ->
      (* Look up struct definition and field type *)
      (try
         let type_def = Hashtbl.find ctx.types struct_name in
         match type_def with
         | StructDef (_, fields) ->
             (try
                let field_type = List.assoc field fields in
                { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = field_type; texpr_pos = pos }
              with Not_found ->
                type_error ("Field not found: " ^ field ^ " in struct " ^ struct_name) pos)
         | _ ->
             type_error (struct_name ^ " is not a struct") pos
       with Not_found ->
         type_error ("Undefined struct: " ^ struct_name) pos)
  
  | XdpContext | TcContext | KprobeContext | UprobeContext | TracepointContext | LsmContext | CgroupSkbContext ->
      (* Built-in context field access *)
      (match field with
       | "data" | "data_end" -> { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = U64; texpr_pos = pos }
       | "ingress_ifindex" | "rx_queue_index" -> { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = U32; texpr_pos = pos }
       | _ -> type_error ("Unknown context field: " ^ field) pos)
  
  | _ ->
      type_error "Cannot access field of non-struct type" pos)

(** Type check binary operation *)
and type_check_binary_op ctx left op right pos =
  let typed_left = type_check_expression ctx left in
  let typed_right = type_check_expression ctx right in
  
  (* Resolve user types for both operands *)
  let resolved_left_type = resolve_user_type ctx typed_left.texpr_type in
  let resolved_right_type = resolve_user_type ctx typed_right.texpr_type in
  
  let result_type = match op with
    (* Arithmetic operations *)
    | Add ->
        (* Handle string concatenation *)
        (match resolved_left_type, resolved_right_type with
         | Str size1, Str size2 -> 
             (* String concatenation - we'll allow it and require explicit result sizing *)
             (* For now, return a placeholder size that will be refined by assignment context *)
             Str (size1 + size2)
         | _ ->
             (* Continue with regular arithmetic/pointer handling *)
             (match resolved_left_type, resolved_right_type with
              (* Pointer + Integer = Pointer (pointer offset) *)
              | Pointer t, (U8|U16|U32|U64|I8|I16|I32|I64) -> Pointer t
              (* Integer + Pointer = Pointer (pointer offset) *)
              | (U8|U16|U32|U64|I8|I16|I32|I64), Pointer t -> Pointer t
              (* Regular numeric arithmetic *)
              | _ ->
                  (* Try integer promotion for Add operations *)
                  (match integer_promotion resolved_left_type resolved_right_type with
                   | Some unified_type ->
                       (match unified_type with
                        | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 -> unified_type
                        | _ -> type_error "Arithmetic operations require numeric types" pos)
                   | None -> type_error "Cannot unify types for arithmetic operation" pos)))
    
    | Sub | Mul | Div | Mod ->
        (* Handle pointer arithmetic for subtraction *)
        (match resolved_left_type, resolved_right_type, op with
         (* Pointer - Pointer = size (pointer subtraction) *)
         | Pointer _, Pointer _, Sub -> U64  (* Return size type for pointer difference *)
         (* Pointer - Integer = Pointer (pointer offset) *)
         | Pointer t, (U8|U16|U32|U64|I8|I16|I32|I64), Sub -> Pointer t
         (* Regular numeric arithmetic *)
         | _ ->
             (* Try integer promotion for Sub/Mul/Div/Mod operations *)
             (match integer_promotion resolved_left_type resolved_right_type with
              | Some unified_type ->
                  (match unified_type with
                   | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 -> unified_type
                   | _ -> type_error "Arithmetic operations require numeric types" pos)
              | None -> type_error "Cannot unify types for arithmetic operation" pos))
    
    (* Comparison operations *)
    | Eq | Ne ->
        (* String equality/inequality comparison *)
        (match resolved_left_type, resolved_right_type with
         | Str _, Str _ -> Bool  (* Allow string comparison regardless of size *)
         (* Null comparisons - any type can be compared with null *)
         | _, Pointer _ | Pointer _, _ -> Bool
         | _ ->
             (match unify_types resolved_left_type resolved_right_type with
              | Some _ -> Bool
              | None ->
                  (* Try integer promotion for comparisons *)
                  (match integer_promotion resolved_left_type resolved_right_type with
                   | Some _ -> Bool
                   | None -> type_error "Cannot compare incompatible types" pos)))
    
    | Lt | Le | Gt | Ge ->
        (* Ordering comparisons - not supported for strings *)
        (match resolved_left_type, resolved_right_type with
         | Str _, Str _ -> type_error "Ordering comparisons (<, <=, >, >=) are not supported for strings" pos
         | _ ->
             (match unify_types resolved_left_type resolved_right_type with
              | Some _ -> Bool
              | None ->
                  (* Try integer promotion for ordering comparisons *)
                  (match integer_promotion resolved_left_type resolved_right_type with
                   | Some _ -> Bool
                   | None -> type_error "Cannot compare incompatible types" pos)))
    
    (* Logical operations *)
    | And | Or ->
        if resolved_left_type = Bool && resolved_right_type = Bool then
          Bool
        else
          type_error "Logical operations require boolean operands" pos
  in
  
  { texpr_desc = TBinaryOp (typed_left, op, typed_right); texpr_type = result_type; texpr_pos = pos }

(** Type check unary operation *)
and type_check_unary_op ctx op expr pos =
  let typed_expr = type_check_expression ctx expr in
  
  let result_type = match op with
    | Not ->
        if typed_expr.texpr_type = Bool then
          Bool
        else
          type_error "Logical not requires boolean operand" pos
    
    | Neg ->
        (match typed_expr.texpr_type with
         | I8 | I16 | I32 | I64 as t -> t
         | U8 -> I16  (* Promote to signed *)
         | U16 -> I32
         | U32 -> I64
         | _ -> type_error "Negation requires numeric type" pos)
  in
  
  { texpr_desc = TUnaryOp (op, typed_expr); texpr_type = result_type; texpr_pos = pos }

(** Type check struct literal *)
and type_check_struct_literal ctx struct_name field_assignments pos =
  (* Look up the struct definition *)
  try
    let type_def = Hashtbl.find ctx.types struct_name in
    match type_def with
    | StructDef (_, struct_fields) ->
        (* Type check each field assignment *)
        let typed_field_assignments = List.map (fun (field_name, field_expr) ->
          let typed_field_expr = type_check_expression ctx field_expr in
          (field_name, typed_field_expr)
        ) field_assignments in
        
        (* Verify all struct fields are provided *)
        let provided_fields = List.map fst field_assignments in
        let expected_fields = List.map fst struct_fields in
        
        (* Check for missing fields *)
        let missing_fields = List.filter (fun expected_field ->
          not (List.mem expected_field provided_fields)
        ) expected_fields in
        
        if missing_fields <> [] then
          type_error ("Missing fields in struct literal: " ^ String.concat ", " missing_fields) pos;
        
        (* Check for unknown fields *)
        let unknown_fields = List.filter (fun provided_field ->
          not (List.mem provided_field expected_fields)
        ) provided_fields in
        
        if unknown_fields <> [] then
          type_error ("Unknown fields in struct literal: " ^ String.concat ", " unknown_fields) pos;
        
        (* Check field types match *)
        List.iter (fun (field_name, typed_field_expr) ->
          try
            let expected_field_type = List.assoc field_name struct_fields in
            let resolved_expected_type = resolve_user_type ctx expected_field_type in
            let resolved_actual_type = resolve_user_type ctx typed_field_expr.texpr_type in
            match unify_types resolved_expected_type resolved_actual_type with
            | Some _ -> () (* Type matches *)
            | None -> 
                type_error ("Type mismatch for field '" ^ field_name ^ "': expected " ^ 
                           string_of_bpf_type resolved_expected_type ^ " but got " ^ 
                           string_of_bpf_type resolved_actual_type) pos
          with Not_found ->
            (* This should not happen as we already checked for unknown fields *)
            type_error ("Internal error: field '" ^ field_name ^ "' not found in struct definition") pos
        ) typed_field_assignments;
        
        (* Return the typed struct literal *)
        { texpr_desc = TStructLiteral (struct_name, typed_field_assignments); 
          texpr_type = Struct struct_name; 
          texpr_pos = pos }
    | _ ->
        type_error (struct_name ^ " is not a struct") pos
  with Not_found ->
    type_error ("Undefined struct: " ^ struct_name) pos

(** Type check expression *)
and type_check_expression ctx expr =
  match expr.expr_desc with
  | Literal lit -> type_check_literal lit expr.expr_pos
  | Identifier name -> type_check_identifier ctx name expr.expr_pos
  | ConfigAccess (config_name, field_name) ->
      (* Implement proper config validation *)
      (try
        let config_decl = Hashtbl.find ctx.configs config_name in
        (* Find the field in the config declaration *)
        (try
          let config_field = List.find (fun f -> f.field_name = field_name) config_decl.config_fields in
          let field_type = config_field.field_type in
          { texpr_desc = TConfigAccess (config_name, field_name); texpr_type = field_type; texpr_pos = expr.expr_pos }
        with Not_found ->
          type_error (Printf.sprintf "Config '%s' has no field '%s'" config_name field_name) expr.expr_pos)
      with Not_found ->
        type_error (Printf.sprintf "Undefined config: '%s'" config_name) expr.expr_pos)
  | FunctionCall (name, args) ->
      (* Type check arguments first *)
      let typed_args = List.map (type_check_expression ctx) args in
      let arg_types = List.map (fun e -> e.texpr_type) typed_args in
      
      (* Check if it's a built-in function *)
      (match get_builtin_function_signature name with
       | Some (expected_params, return_type) ->
           (* Check if this is a variadic function (indicated by empty parameter list) *)
           (match Stdlib.get_builtin_function name with
            | Some builtin_func when builtin_func.is_variadic ->
                (* Variadic function - accept any number of arguments *)
                { texpr_desc = TFunctionCall (name, typed_args); texpr_type = return_type; texpr_pos = expr.expr_pos }
            | _ ->
                (* Regular built-in function - check argument count and types *)
                if List.length expected_params = List.length arg_types then
                  let unified = List.map2 unify_types expected_params arg_types in
                  if List.for_all (function Some _ -> true | None -> false) unified then
                    { texpr_desc = TFunctionCall (name, typed_args); texpr_type = return_type; texpr_pos = expr.expr_pos }
                  else
                    type_error ("Type mismatch in function call: " ^ name) expr.expr_pos
                else
                  type_error ("Wrong number of arguments for function: " ^ name) expr.expr_pos)
       | None ->
           (* Check user-defined functions *)
           try
             let (expected_params, return_type) = Hashtbl.find ctx.functions name in
             
             (* Check attributed function call restrictions - attributed functions cannot be called directly *)
             if Hashtbl.mem ctx.attributed_functions name then
               type_error ("Attributed function '" ^ name ^ "' cannot be called directly. Use return " ^ name ^ "(...) for tail calls.") expr.expr_pos;
             
             (* Check kernel/userspace function call restrictions *)
             (try
               let target_scope = Hashtbl.find ctx.function_scopes name in
               (* Only restrict if target is a kernel function *)
               if target_scope = Ast.Kernel then
                 (* Check if we're in a context where kernel function calls are allowed *)
                 let in_ebpf_program = ctx.current_program_type <> None in
                 let current_scope = match ctx.current_function with
                   | Some current_func_name ->
                       (try 
                          Some (Hashtbl.find ctx.function_scopes current_func_name)
                        with Not_found -> 
                          (* If current function scope not found, treat as userspace *)
                          Some Ast.Userspace)
                   | None -> 
                       (* If no current function, we're in global scope (userspace) *)
                       Some Ast.Userspace
                 in
                 (* Kernel functions can be called from:
                    1. eBPF programs (current_program_type is Some _)
                    2. Other kernel functions (current_scope is Kernel)
                    But NOT from userspace functions or main() *)
                 (match current_scope, in_ebpf_program with
                  | Some Ast.Userspace, false ->
                      type_error ("Kernel function '" ^ name ^ "' cannot be called from userspace code") expr.expr_pos
                  | _ -> ())
             with Not_found -> 
               (* Target function scope not found, which shouldn't happen for defined functions *)
               ());
             
             if List.length expected_params = List.length arg_types then
               let unified = List.map2 unify_types expected_params arg_types in
               if List.for_all (function Some _ -> true | None -> false) unified then
                 { texpr_desc = TFunctionCall (name, typed_args); texpr_type = return_type; texpr_pos = expr.expr_pos }
               else
                 type_error ("Type mismatch in function call: " ^ name) expr.expr_pos
             else
               type_error ("Wrong number of arguments for function: " ^ name) expr.expr_pos
           with Not_found ->
             type_error ("Undefined function: " ^ name) expr.expr_pos)
  | ArrayAccess (arr, idx) -> type_check_array_access ctx arr idx expr.expr_pos
  | FieldAccess (obj, field) -> type_check_field_access ctx obj field expr.expr_pos
  | BinaryOp (left, op, right) -> type_check_binary_op ctx left op right expr.expr_pos
  | UnaryOp (op, expr) -> type_check_unary_op ctx op expr expr.expr_pos
  | StructLiteral (struct_name, field_assignments) -> type_check_struct_literal ctx struct_name field_assignments expr.expr_pos
  | TailCall (name, args) ->
      (* Type check arguments first *)
      let typed_args = List.map (type_check_expression ctx) args in
      let arg_types = List.map (fun e -> e.texpr_type) typed_args in
      
      (* Check if the target function is valid for tail calls *)
      (try
        let (expected_params, return_type) = Hashtbl.find ctx.functions name in
        
        (* Check that the target function is attributed (required for tail calls) *)
        if not (Hashtbl.mem ctx.attributed_functions name) then
          type_error ("Tail call target '" ^ name ^ "' must be an attributed function (e.g., @xdp, @tc)") expr.expr_pos;
        
        (* Check argument types *)
        if List.length expected_params = List.length arg_types then
          let unified = List.map2 unify_types expected_params arg_types in
          if List.for_all (function Some _ -> true | None -> false) unified then
            { texpr_desc = TFunctionCall (name, typed_args); texpr_type = return_type; texpr_pos = expr.expr_pos }
          else
            type_error ("Type mismatch in tail call: " ^ name) expr.expr_pos
        else
          type_error ("Wrong number of arguments for tail call: " ^ name) expr.expr_pos
      with Not_found ->
        type_error ("Undefined tail call target: " ^ name) expr.expr_pos)

(** Type check statement *)
let rec type_check_statement ctx stmt =
  match stmt.stmt_desc with
  | ExprStmt expr ->
      let typed_expr = type_check_expression ctx expr in
      { tstmt_desc = TExprStmt typed_expr; tstmt_pos = stmt.stmt_pos }
  
    | Assignment (name, expr) ->
      let typed_expr = type_check_expression ctx expr in
      (* Check if the variable is const by looking it up in the symbol table *)
      (match Symbol_table.lookup_symbol ctx.symbol_table name with
       | Some symbol when Symbol_table.is_const_variable symbol ->
           type_error ("Cannot assign to const variable: " ^ name) stmt.stmt_pos
       | _ ->
           (try
              let var_type = Hashtbl.find ctx.variables name in
              let resolved_var_type = resolve_user_type ctx var_type in
              let resolved_expr_type = resolve_user_type ctx typed_expr.texpr_type in
              (match unify_types resolved_var_type resolved_expr_type with
               | Some _ -> 
                   { tstmt_desc = TAssignment (name, typed_expr); tstmt_pos = stmt.stmt_pos }
               | None ->
                   type_error ("Cannot assign " ^ string_of_bpf_type resolved_expr_type ^ 
                              " to variable of type " ^ string_of_bpf_type resolved_var_type) stmt.stmt_pos)
            with Not_found ->
              type_error ("Undefined variable: " ^ name) stmt.stmt_pos))

  | FieldAssignment (obj_expr, field, value_expr) ->
      let typed_value = type_check_expression ctx value_expr in
      
      (* Check if this is a config field assignment *)
      (match obj_expr.expr_desc with
       | Identifier config_name when Hashtbl.mem ctx.configs config_name ->
           (* This is config field assignment - check if we're in an eBPF program *)
           (match ctx.current_program_type with
            | Some _ ->
                (* We're in an eBPF program - config field assignments are not allowed *)
                type_error ("Config field assignments are not allowed in eBPF programs. " ^
                           "Config fields can only be modified from userspace code.") stmt.stmt_pos
            | None ->
                (* We're in userspace or global context - config field assignment is allowed *)
                let config_decl = Hashtbl.find ctx.configs config_name in
                (try
                  let config_field = List.find (fun f -> f.field_name = field) config_decl.config_fields in
                  let field_type = config_field.field_type in
                  (* Check if the value type is compatible with the field type *)
                  (match unify_types field_type typed_value.texpr_type with
                   | Some _ ->
                       (* Create typed config access expression *)
                       let typed_obj = { texpr_desc = TIdentifier config_name; texpr_type = UserType config_name; texpr_pos = obj_expr.expr_pos } in
                       { tstmt_desc = TFieldAssignment (typed_obj, field, typed_value); tstmt_pos = stmt.stmt_pos }
                   | None ->
                       type_error ("Cannot assign " ^ string_of_bpf_type typed_value.texpr_type ^ 
                                  " to config field of type " ^ string_of_bpf_type field_type) stmt.stmt_pos)
                with Not_found ->
                  type_error ("Config '" ^ config_name ^ "' has no field '" ^ field ^ "'") stmt.stmt_pos))
       | _ ->
           (* Try to type check the object expression first *)
           let typed_obj = type_check_expression ctx obj_expr in
           
           (* Check if this is regular struct field assignment *)
           (match typed_obj.texpr_type with
            | Struct struct_name | UserType struct_name ->
                (* Look up struct definition and field type *)
                (try
                   let type_def = Hashtbl.find ctx.types struct_name in
                   match type_def with
                   | StructDef (_, fields) ->
                       (try
                          let field_type = List.assoc field fields in
                          let resolved_field_type = resolve_user_type ctx field_type in
                          let resolved_value_type = resolve_user_type ctx typed_value.texpr_type in
                          (* Check if the value type is compatible with the field type *)
                          (match unify_types resolved_field_type resolved_value_type with
                           | Some _ ->
                               { tstmt_desc = TFieldAssignment (typed_obj, field, typed_value); tstmt_pos = stmt.stmt_pos }
                           | None ->
                               type_error ("Cannot assign " ^ string_of_bpf_type resolved_value_type ^ 
                                          " to field of type " ^ string_of_bpf_type resolved_field_type) stmt.stmt_pos)
                        with Not_found ->
                          type_error ("Field not found: " ^ field ^ " in struct " ^ struct_name) stmt.stmt_pos)
                   | _ ->
                       type_error (struct_name ^ " is not a struct") stmt.stmt_pos
                 with Not_found ->
                   type_error ("Undefined struct: " ^ struct_name) stmt.stmt_pos)
            | _ ->
                type_error ("Field assignment can only be used on struct objects or config objects") stmt.stmt_pos))
  
  | IndexAssignment (map_expr, key_expr, value_expr) ->
      let typed_key = type_check_expression ctx key_expr in
      let typed_value = type_check_expression ctx value_expr in
      
      (* Check if this is map assignment *)
      (match map_expr.expr_desc with
       | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           (* This is map assignment *)
           let map_decl = Hashtbl.find ctx.maps map_name in
           (* Check key type compatibility *)
           let resolved_key_type = resolve_user_type ctx map_decl.key_type in
           let resolved_typed_key_type = resolve_user_type ctx typed_key.texpr_type in
           (match unify_types resolved_key_type resolved_typed_key_type with
            | Some _ -> ()
            | None -> type_error ("Map key type mismatch") stmt.stmt_pos);
           (* Check value type compatibility *)
           let resolved_value_type = resolve_user_type ctx map_decl.value_type in
           let resolved_typed_value_type = resolve_user_type ctx typed_value.texpr_type in
           (match unify_types resolved_value_type resolved_typed_value_type with
            | Some _ -> ()
            | None -> type_error ("Map value type mismatch") stmt.stmt_pos);
           (* Create a synthetic map type for the result *)
           let typed_map = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.key_type, map_decl.value_type, map_decl.map_type); texpr_pos = map_expr.expr_pos } in
           { tstmt_desc = TIndexAssignment (typed_map, typed_key, typed_value); tstmt_pos = stmt.stmt_pos }
       | _ ->
           (* Regular index assignment (arrays, etc.) *)
           let typed_map = type_check_expression ctx map_expr in
           (match typed_map.texpr_type with
            | Map (key_type, value_type, _) ->
                (* This shouldn't happen anymore, but handle it for safety *)
                (match unify_types key_type typed_key.texpr_type with
                 | Some _ -> ()
                 | None -> type_error ("Map key type mismatch") stmt.stmt_pos);
                (match unify_types value_type typed_value.texpr_type with
                 | Some _ -> ()
                 | None -> type_error ("Map value type mismatch") stmt.stmt_pos);
                { tstmt_desc = TIndexAssignment (typed_map, typed_key, typed_value); tstmt_pos = stmt.stmt_pos }
            | Array (element_type, _) ->
                (* Array element assignment *)
                (match unify_types element_type typed_value.texpr_type with
                 | Some _ -> ()
                 | None -> type_error ("Array element type mismatch") stmt.stmt_pos);
                { tstmt_desc = TIndexAssignment (typed_map, typed_key, typed_value); tstmt_pos = stmt.stmt_pos }
            | _ -> type_error ("Index assignment can only be used on maps or arrays") stmt.stmt_pos))
  
  | Declaration (name, type_opt, expr) ->
      let typed_expr = type_check_expression ctx expr in
      
      (* Check if trying to assign a map to a variable *)
      (match typed_expr.texpr_type with
       | Map (_, _, _) -> type_error ("Maps cannot be assigned to variables") stmt.stmt_pos
       | _ -> ());
      
      let var_type = match type_opt with
        | Some declared_type ->
            let resolved_declared_type = resolve_user_type ctx declared_type in
            (* For variable declarations, we should enforce the declared type *)
            (* and check if the expression type can be assigned to it *)
            if can_assign resolved_declared_type typed_expr.texpr_type then
              resolved_declared_type  (* Use the declared type, not the unified type *)
            else
              type_error ("Type mismatch in declaration") stmt.stmt_pos
        | None -> typed_expr.texpr_type
      in
      Hashtbl.replace ctx.variables name var_type;
      { tstmt_desc = TDeclaration (name, var_type, typed_expr); tstmt_pos = stmt.stmt_pos }
  
  | ConstDeclaration (name, type_opt, expr) ->
      let typed_expr = type_check_expression ctx expr in
      
      (* Check if trying to assign a map to a const *)
      (match typed_expr.texpr_type with
       | Map (_, _, _) -> type_error ("Maps cannot be assigned to const variables") stmt.stmt_pos
       | _ -> ());
      
      (* Validate that the expression is a compile-time constant (literals and negated literals) *)
      let const_value = match typed_expr.texpr_desc with
        | TLiteral lit -> lit
        | TUnaryOp (Neg, {texpr_desc = TLiteral (IntLit (n, Some sign)); _}) -> 
            IntLit (-n, Some sign)  (* Negated signed integer literal *)
        | TUnaryOp (Neg, {texpr_desc = TLiteral (IntLit (n, None)); _}) -> 
            IntLit (-n, None)  (* Negated integer literal *)
        | _ -> type_error ("Const variable must be initialized with a literal value") stmt.stmt_pos
      in
      
      (* Enforce that const variables can only hold integer types *)
      let var_type = match type_opt with
        | Some declared_type ->
            let resolved_declared_type = resolve_user_type ctx declared_type in
            (match resolved_declared_type with
             | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 ->
                 if can_assign resolved_declared_type typed_expr.texpr_type then
                   resolved_declared_type
                 else
                   type_error ("Type mismatch in const declaration") stmt.stmt_pos
             | _ -> type_error ("Const variables can only be integer types") stmt.stmt_pos)
        | None -> 
            (match typed_expr.texpr_type with
             | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 as t -> t
             | _ -> type_error ("Const variables can only be integer types") stmt.stmt_pos)
      in
      
      (* Add to variables table and symbol table *)
      Hashtbl.replace ctx.variables name var_type;
      Symbol_table.add_symbol ctx.symbol_table name (Symbol_table.ConstVariable (var_type, const_value)) Symbol_table.Private stmt.stmt_pos;
      
      { tstmt_desc = TConstDeclaration (name, var_type, typed_expr); tstmt_pos = stmt.stmt_pos }
  
  | Return expr_opt ->
      let typed_expr_opt = match expr_opt with
        | Some expr ->
            (* Set tail call context flag to allow attributed function calls in return position *)
            let ctx_with_tail_call = { ctx with in_tail_call_context = true } in
            
            (* Check if this is a potential tail call *)
            (match detect_tail_call_in_return_expr ctx_with_tail_call expr with
             | Some (name, args) ->
                 (* This is a valid tail call - type check the arguments with tail call context *)
                 let typed_args = List.map (type_check_expression ctx_with_tail_call) args in
                 let arg_types = List.map (fun e -> e.texpr_type) typed_args in
                 
                 (* Get the target function signature *)
                 (try
                   let (expected_params, return_type) = Hashtbl.find ctx.functions name in
                   if List.length expected_params = List.length arg_types then
                     let unified = List.map2 unify_types expected_params arg_types in
                     if List.for_all (function Some _ -> true | None -> false) unified then
                       (* Create a TTailCall expression instead of TFunctionCall *)
                       Some { texpr_desc = TTailCall (name, typed_args); texpr_type = return_type; texpr_pos = expr.expr_pos }
                     else
                       type_error ("Type mismatch in tail call: " ^ name) expr.expr_pos
                   else
                     type_error ("Wrong number of arguments for tail call: " ^ name) expr.expr_pos
                 with Not_found ->
                   type_error ("Undefined tail call target: " ^ name) expr.expr_pos)
                           | None ->
                  (* Regular return expression - type check normally *)
                  (* But first check if it's an attributed function being called directly *)
                  (match expr.expr_desc with
                   | FunctionCall (name, _) when Hashtbl.mem ctx.attributed_functions name ->
                       type_error ("Attributed function '" ^ name ^ "' cannot be called directly. Use return " ^ name ^ "(...) for tail calls.") expr.expr_pos
                   | _ ->
                       Some (type_check_expression ctx expr)))
        | None -> None
      in
      { tstmt_desc = TReturn typed_expr_opt; tstmt_pos = stmt.stmt_pos }
  
  | If (cond, then_stmts, else_opt) ->
      let typed_cond = type_check_expression ctx cond in
      if typed_cond.texpr_type <> Bool then
        type_error "If condition must be boolean" stmt.stmt_pos;
      let typed_then = List.map (type_check_statement ctx) then_stmts in
      let typed_else = Option.map (List.map (type_check_statement ctx)) else_opt in
      { tstmt_desc = TIf (typed_cond, typed_then, typed_else); tstmt_pos = stmt.stmt_pos }
  
  | For (var, start, end_, body) ->
      if !loop_depth > 0 then
        type_error "Nested loops are not currently supported" stmt.stmt_pos;
      
      let typed_start = type_check_expression ctx start in
      let typed_end = type_check_expression ctx end_ in
      (* Loop variable should be integer type *)
      (match unify_types typed_start.texpr_type typed_end.texpr_type with
       | Some loop_type when (match loop_type with U8|U16|U32|U64|I8|I16|I32|I64 -> true | _ -> false) ->
           Hashtbl.replace ctx.variables var loop_type;
           incr loop_depth;
           let typed_body = List.map (type_check_statement ctx) body in
           decr loop_depth;
           { tstmt_desc = TFor (var, typed_start, typed_end, typed_body); tstmt_pos = stmt.stmt_pos }
       | _ -> type_error "For loop bounds must be integer types" stmt.stmt_pos)
  
  | ForIter (index_var, value_var, iterable, body) ->
      if !loop_depth > 0 then
        type_error "Nested loops are not currently supported" stmt.stmt_pos;
        
      let typed_iterable = type_check_expression ctx iterable in
      (* Check that the expression is iterable (array or map) *)
      (match typed_iterable.texpr_type with
       | Array (element_type, _) ->
           (* For arrays: index is u32, value is element type *)
           Hashtbl.replace ctx.variables index_var U32;
           Hashtbl.replace ctx.variables value_var element_type;
           incr loop_depth;
           let typed_body = List.map (type_check_statement ctx) body in
           decr loop_depth;
           { tstmt_desc = TForIter (index_var, value_var, typed_iterable, typed_body); tstmt_pos = stmt.stmt_pos }
       | Map (key_type, value_type, _) ->
           (* For maps: index is key type, value is value type *)
           Hashtbl.replace ctx.variables index_var key_type;
           Hashtbl.replace ctx.variables value_var value_type;
           incr loop_depth;
           let typed_body = List.map (type_check_statement ctx) body in
           decr loop_depth;
           { tstmt_desc = TForIter (index_var, value_var, typed_iterable, typed_body); tstmt_pos = stmt.stmt_pos }
       | _ -> type_error "For-iter expression must be iterable (array or map)" stmt.stmt_pos)
  
  | While (cond, body) ->
      let typed_cond = type_check_expression ctx cond in
      if typed_cond.texpr_type <> Bool then
        type_error "While condition must be boolean" stmt.stmt_pos;
      incr loop_depth;
      let typed_body = List.map (type_check_statement ctx) body in
      decr loop_depth;
      { tstmt_desc = TWhile (typed_cond, typed_body); tstmt_pos = stmt.stmt_pos }

  | Delete (map_expr, key_expr) ->
      let typed_key = type_check_expression ctx key_expr in
      
      (* Check if this is map deletion *)
      (match map_expr.expr_desc with
       | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           (* This is map deletion *)
           let map_decl = Hashtbl.find ctx.maps map_name in
           (* Check key type compatibility *)
           (match unify_types map_decl.key_type typed_key.texpr_type with
            | Some _ -> ()
            | None -> type_error ("Map key type mismatch in delete statement") stmt.stmt_pos);
           (* Create a synthetic map type for the result *)
           let typed_map = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.key_type, map_decl.value_type, map_decl.map_type); texpr_pos = map_expr.expr_pos } in
           { tstmt_desc = TDelete (typed_map, typed_key); tstmt_pos = stmt.stmt_pos }
       | _ ->
           type_error ("Delete can only be used on maps") stmt.stmt_pos)
  
  | Break ->
      (* Break statements are only valid inside loops *)
      if !loop_depth = 0 then
        type_error "Break statement can only be used inside loops" stmt.stmt_pos;
      { tstmt_desc = TBreak; tstmt_pos = stmt.stmt_pos }
  
  | Continue ->
      (* Continue statements are only valid inside loops *)
      if !loop_depth = 0 then
        type_error "Continue statement can only be used inside loops" stmt.stmt_pos;
      { tstmt_desc = TContinue; tstmt_pos = stmt.stmt_pos }
      
  | Try (try_stmts, catch_clauses) ->
      (* Type check try block *)
      let typed_try_stmts = List.map (type_check_statement ctx) try_stmts in
      
      (* Type check catch clause bodies to set expr_type on expressions *)
      List.iter (fun clause ->

        (* Manually set expr_type on expressions in catch clause bodies *)
        let rec fix_expr_types expr =
          match expr.expr_desc with
          | Identifier name ->
              (* Set expr_type based on variable context *)
              (match Hashtbl.find_opt ctx.variables name with
               | Some bpf_type -> 
                   expr.expr_type <- Some bpf_type;
                   expr.type_checked <- true
               | None -> ())
          | ArrayAccess (arr_expr, idx_expr) ->
              fix_expr_types arr_expr;
              fix_expr_types idx_expr
          | BinaryOp (left, _, right) ->
              fix_expr_types left;
              fix_expr_types right
          | _ -> ()
        in
        
        let fix_stmt_types stmt =
          match stmt.stmt_desc with
          | IndexAssignment (map_expr, key_expr, value_expr) ->
              fix_expr_types map_expr;
              fix_expr_types key_expr;
              fix_expr_types value_expr
          | Return (Some expr) ->
              fix_expr_types expr
          | _ -> ()
        in
        
        List.iter fix_stmt_types clause.catch_body;
        
        (* Also run the regular type checker (but ignore the result for now) *)
        List.iter (fun stmt -> ignore (type_check_statement ctx stmt)) clause.catch_body
      ) catch_clauses;
      
      { tstmt_desc = TTry (typed_try_stmts, catch_clauses); tstmt_pos = stmt.stmt_pos }
      
  | Throw expr ->
      (* Type check the throw expression - must be integer type *)
      let typed_expr = type_check_expression ctx expr in
      (match typed_expr.texpr_type with
       | I8 | I16 | I32 | I64 | U8 | U16 | U32 | U64 -> 
           { tstmt_desc = TThrow typed_expr; tstmt_pos = stmt.stmt_pos }
       | other_type ->
           failwith (Printf.sprintf "throw expression must be integer type, got %s at %s" 
             (string_of_bpf_type other_type) (string_of_position stmt.stmt_pos)))
      
  | Defer expr ->
      (* Type check the deferred expression *)
      let typed_expr = type_check_expression ctx expr in
      { tstmt_desc = TDefer typed_expr; tstmt_pos = stmt.stmt_pos }

(** Type check function *)
let type_check_function ?(register_signature=true) ctx func =
  (* Save current state *)
  let old_variables = Hashtbl.copy ctx.variables in
  let old_function = ctx.current_function in
  ctx.current_function <- Some func.func_name;
  
  (* Register function scope early so it's available during type checking *)
  if register_signature then (
    Hashtbl.replace ctx.function_scopes func.func_name func.func_scope
  );
  
  (* Add parameters to scope with proper type resolution *)
  let resolved_params = List.map (fun (name, typ) -> 
    let resolved_type = resolve_user_type ctx typ in
    Hashtbl.replace ctx.variables name resolved_type;
    (name, resolved_type)
  ) func.func_params in
  
  (* Type check function body *)
  let typed_body = List.map (type_check_statement ctx) func.func_body in
  
  (* Determine return type *)
  let return_type = match func.func_return_type with
    | Some t -> resolve_user_type ctx t
    | None -> U32  (* Default return type *)
  in
  
  (* Restore scope *)
  Hashtbl.clear ctx.variables;
  Hashtbl.iter (Hashtbl.replace ctx.variables) old_variables;
  ctx.current_function <- old_function;
  
  let typed_func = {
    tfunc_name = func.func_name;
    tfunc_params = resolved_params;
    tfunc_return_type = return_type;
    tfunc_body = typed_body;
    tfunc_scope = func.func_scope;
    tfunc_pos = func.func_pos;
  } in
  
  (* Only register function signature if requested (for global functions) *)
  if register_signature then (
    let param_types = List.map snd resolved_params in
    Hashtbl.replace ctx.functions func.func_name (param_types, return_type);
    (* Also register the function scope *)
    Hashtbl.replace ctx.function_scopes func.func_name func.func_scope
  );
  
  typed_func

(** Type check program *)
let type_check_program ctx prog =
  
  (* Add program-scoped maps to context *)
  List.iter (fun map_decl ->
    Hashtbl.replace ctx.maps map_decl.name map_decl
  ) prog.prog_maps;
  
  (* Add program-scoped structs to context *)
  List.iter (fun struct_def ->
    let type_def = StructDef (struct_def.struct_name, struct_def.struct_fields) in
    Hashtbl.replace ctx.types struct_def.struct_name type_def
  ) prog.prog_structs;
  
  (* FIRST PASS: Register all function signatures so they can call each other *)
  List.iter (fun func ->
    let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) func.func_params in
    let return_type = match func.func_return_type with
      | Some t -> resolve_user_type ctx t
      | None -> U32  (* default return type *)
    in
    Hashtbl.replace ctx.functions func.func_name (param_types, return_type)
  ) prog.prog_functions;
  
  (* SECOND PASS: Type check all function bodies *)
  let typed_functions = List.map (type_check_function ~register_signature:false ctx) prog.prog_functions in
  
  (* Remove program-scoped maps from context (restore scope) *)
  List.iter (fun map_decl ->
    Hashtbl.remove ctx.maps map_decl.name
  ) prog.prog_maps;
  
  (* Remove program-scoped structs from context (restore scope) *)
  List.iter (fun struct_def ->
    Hashtbl.remove ctx.types struct_def.struct_name
  ) prog.prog_structs;
  
  (* Remove program function signatures from context (restore scope) *)
  List.iter (fun func ->
    Hashtbl.remove ctx.functions func.func_name
  ) prog.prog_functions;
  
  {
    tprog_name = prog.prog_name;
    tprog_type = prog.prog_type;
    tprog_functions = typed_functions;
    tprog_maps = prog.prog_maps; (* Include program-scoped maps *)
    tprog_pos = prog.prog_pos;
  }

(** Type check userspace block - validates and returns typed functions *)
let type_check_userspace _ctx _userspace_block =
  (* Userspace support has been removed - this function should not be called *)
  failwith "Userspace blocks are no longer supported"

(** Main type checking entry point *)
let type_check_ast ?builtin_path ast =
  (* Load builtin definitions from KernelScript files *)
  (* Create symbol table with builtin definitions *)
  let symbol_table = Builtin_loader.build_symbol_table_with_builtins ?builtin_path ast in
  let builtin_asts = Builtin_loader.load_standard_builtins ?builtin_path () in
  let ctx = create_context symbol_table in
  
  (* Process builtin types into type context *)
  List.iter (fun builtin_ast ->
    List.iter (function
      | TypeDef type_def ->
          (match type_def with
           | StructDef (name, _) | EnumDef (name, _) | TypeAlias (name, _) ->
               Hashtbl.replace ctx.types name type_def)
      | _ -> ()
    ) builtin_ast
  ) builtin_asts;
  
  (* Add enum constants as variables for all loaded enums *)
  Hashtbl.iter (fun _name type_def ->
    match type_def with
    | EnumDef (enum_name, enum_values) ->
        let enum_type = match enum_name with
          | "XdpAction" -> XdpAction
          | "TcAction" -> TcAction
          | _ -> UserType enum_name
        in
        List.iter (fun (const_name, _) ->
          Hashtbl.replace ctx.variables const_name enum_type
        ) enum_values
    | _ -> ()
  ) ctx.types;
  
  (* First pass: collect type definitions and map declarations *)
  List.iter (function
    | TypeDef type_def ->
        (match type_def with
         | StructDef (name, _) | EnumDef (name, _) | TypeAlias (name, _) ->
             Hashtbl.replace ctx.types name type_def)
    | MapDecl map_decl ->
        Hashtbl.replace ctx.maps map_decl.name map_decl

    | _ -> ()
  ) ast;
  
  (* Second pass: First register ALL global function signatures *)
  List.iter (function
    | GlobalFunction func ->
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) func.func_params in
        let return_type = match func.func_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> U32  (* default return type *)
        in
        Hashtbl.replace ctx.functions func.func_name (param_types, return_type);
        Hashtbl.replace ctx.function_scopes func.func_name func.func_scope
    | _ -> ()
  ) ast;
  
  (* Second-and-a-half pass: Type-check ALL global function bodies *)
  List.iter (function
    | GlobalFunction func ->
        let _ = type_check_function ~register_signature:false ctx func in
        ()
    | _ -> ()
  ) ast;
  
  (* Third pass: type check attributed functions now that global functions are registered *)
  List.iter (function
    | AttributedFunction attr_func ->
        let _ = type_check_function ~register_signature:false ctx attr_func.attr_function in
        ()
    | _ -> ()
  ) ast;
  
  (* Return empty list - this is a simple type checking function, not the full multi-program analysis *)
  []

(** Utility functions *)
let check_function_call name arg_types =
  match get_builtin_function_signature name with
  | Some (expected_params, return_type) ->
      if List.length expected_params = List.length arg_types then
        let unified = List.map2 unify_types expected_params arg_types in
        if List.for_all (function Some _ -> true | None -> false) unified then
          Some return_type
        else
          None
      else
        None
  | None -> None

(** Pretty printing for debugging *)
let string_of_type_error (msg, pos) =
  Printf.sprintf "Type error: %s at %s" msg (Ast.string_of_position pos)

let print_type_error (msg, pos) =
  Printf.eprintf "%s\n" (string_of_type_error (msg, pos))

(** Convert typed AST back to AST with type annotations *)
let rec typed_expr_to_expr texpr =
  let expr_desc =   match texpr.texpr_desc with
    | TLiteral lit -> Literal lit
    | TIdentifier name -> Identifier name
    | TConfigAccess (config_name, field_name) -> ConfigAccess (config_name, field_name)
    | TFunctionCall (name, args) -> FunctionCall (name, List.map typed_expr_to_expr args)
    | TTailCall (name, args) -> TailCall (name, List.map typed_expr_to_expr args)
    | TArrayAccess (arr, idx) -> ArrayAccess (typed_expr_to_expr arr, typed_expr_to_expr idx)
    | TFieldAccess (obj, field) -> FieldAccess (typed_expr_to_expr obj, field)
    | TBinaryOp (left, op, right) -> BinaryOp (typed_expr_to_expr left, op, typed_expr_to_expr right)
    | TUnaryOp (op, expr) -> UnaryOp (op, typed_expr_to_expr expr)
    | TStructLiteral (struct_name, field_assignments) -> 
        let converted_field_assignments = List.map (fun (field_name, typed_field_expr) ->
          (field_name, typed_expr_to_expr typed_field_expr)
        ) field_assignments in
        StructLiteral (struct_name, converted_field_assignments)
  in
  (* Handle special cases for type annotations *)
  let safe_expr_type = match texpr.texpr_desc, texpr.texpr_type with
    | TIdentifier _, Map (_, _, _) -> 
        (* Map identifiers used in expressions should be represented as pointers for IR generation *)
        Some (Pointer U8)
    | _, Map (_, _, _) -> 
        (* Don't set Map types in expr_type for other expressions *)
        None
    | _, other_type -> 
        Some other_type
  in
  let enhanced_expr = { expr_desc; expr_pos = texpr.texpr_pos; expr_type = safe_expr_type; 
    type_checked = true; program_context = None; map_scope = None } in
  enhanced_expr

let rec typed_stmt_to_stmt tstmt =
  let stmt_desc = match tstmt.tstmt_desc with
    | TExprStmt expr -> ExprStmt (typed_expr_to_expr expr)
    | TAssignment (name, expr) -> Assignment (name, typed_expr_to_expr expr)
    | TFieldAssignment (obj_expr, field, value_expr) ->
        FieldAssignment (typed_expr_to_expr obj_expr, field, typed_expr_to_expr value_expr)
    | TIndexAssignment (map_expr, key_expr, value_expr) -> 
        IndexAssignment (typed_expr_to_expr map_expr, typed_expr_to_expr key_expr, typed_expr_to_expr value_expr)
    | TDeclaration (name, typ, expr) -> Declaration (name, Some typ, typed_expr_to_expr expr)
  | TConstDeclaration (name, typ, expr) -> ConstDeclaration (name, Some typ, typed_expr_to_expr expr)
    | TReturn expr_opt -> Return (Option.map typed_expr_to_expr expr_opt)
    | TIf (cond, then_stmts, else_opt) -> 
        If (typed_expr_to_expr cond, 
            List.map typed_stmt_to_stmt then_stmts,
            Option.map (List.map typed_stmt_to_stmt) else_opt)
    | TFor (var, start, end_, body) ->
        For (var, typed_expr_to_expr start, typed_expr_to_expr end_, List.map typed_stmt_to_stmt body)
    | TForIter (index_var, value_var, iterable, body) ->
        ForIter (index_var, value_var, typed_expr_to_expr iterable, List.map typed_stmt_to_stmt body)
    | TWhile (cond, body) ->
        While (typed_expr_to_expr cond, List.map typed_stmt_to_stmt body)
    | TDelete (cond, body) ->
        Delete (typed_expr_to_expr cond, typed_expr_to_expr body)
    | TBreak -> Break
    | TContinue -> Continue
    | TTry (try_stmts, catch_clauses) ->
        Try (List.map typed_stmt_to_stmt try_stmts, catch_clauses)
    | TThrow expr ->
        Throw (typed_expr_to_expr expr)
    | TDefer expr ->
        Defer (typed_expr_to_expr expr)
  in
  { stmt_desc; stmt_pos = tstmt.tstmt_pos }

let typed_function_to_function tfunc =
  { func_name = tfunc.tfunc_name;
    func_params = tfunc.tfunc_params;
    func_return_type = Some tfunc.tfunc_return_type;
    func_body = List.map typed_stmt_to_stmt tfunc.tfunc_body;
    func_scope = tfunc.tfunc_scope;
    func_pos = tfunc.tfunc_pos;
    tail_call_targets = [];
    is_tail_callable = false }

let typed_program_to_program tprog original_prog =
  { prog_name = tprog.tprog_name;
    prog_type = tprog.tprog_type;
    prog_functions = List.map typed_function_to_function tprog.tprog_functions;
    prog_maps = original_prog.prog_maps;  (* Preserve original map declarations *)
    prog_structs = original_prog.prog_structs;  (* Preserve original struct declarations *)
    prog_pos = tprog.tprog_pos }

(** Convert typed AST back to annotated AST declarations *)
let typed_ast_to_annotated_ast typed_attributed_functions typed_userspace_functions original_ast =
  (* Create a mapping of typed attributed functions by name *)
  let typed_attr_func_map = List.fold_left (fun acc (attr_list, typed_func) ->
    (typed_func.tfunc_name, (attr_list, typed_func)) :: acc
  ) [] typed_attributed_functions in
  
  (* Create a mapping of typed userspace functions by name *)
  let typed_userspace_map = List.fold_left (fun acc typed_func ->
    (typed_func.tfunc_name, typed_func) :: acc
  ) [] typed_userspace_functions in
  
  (* Reconstruct the declarations list, preserving order and updating functions *)
  List.map (function
    | AttributedFunction attr_func -> 
        (* Find corresponding typed attributed function *)
        (try
          let (attr_list, typed_func) = List.assoc attr_func.attr_function.func_name typed_attr_func_map in
          let annotated_func = typed_function_to_function typed_func in
          AttributedFunction {
            attr_list = attr_list;
            attr_function = annotated_func;
            attr_pos = attr_func.attr_pos;
            program_type = attr_func.program_type;
            tail_call_dependencies = attr_func.tail_call_dependencies;
          }
        with Not_found ->
          (* If not found, return original *)
          AttributedFunction attr_func)

    | GlobalFunction orig_func ->
        (* Find corresponding typed userspace function *)
        (try
          let typed_func = List.assoc orig_func.func_name typed_userspace_map in
          let annotated_func = typed_function_to_function typed_func in
          GlobalFunction annotated_func
        with Not_found ->
          (* If not found, return original *)
          GlobalFunction orig_func)

    | other_decl -> other_decl  (* Keep maps, types, configs, etc. unchanged *)
  ) original_ast

(** PHASE 2: Type check and annotate AST with multi-program analysis *)
let rec type_check_and_annotate_ast ?builtin_path ast =
  (* STEP 1: Multi-program analysis *)
  let multi_prog_analysis = Multi_program_analyzer.analyze_multi_program_system ast in
  
  (* Print analysis results for debugging *)
  let debug_enabled = try 
    Sys.getenv "KERNELSCRIPT_DEBUG" = "1" 
  with Not_found -> false 
  in
  if debug_enabled then
    Multi_program_analyzer.print_analysis_results multi_prog_analysis;
  
  (* STEP 2: Type checking with multi-program context *)
  (* Load builtin definitions and create symbol table *)
  let symbol_table = Builtin_loader.build_symbol_table_with_builtins ?builtin_path ast in
  let builtin_asts = Builtin_loader.load_standard_builtins ?builtin_path () in
  let ctx = create_context symbol_table in
  
  (* Process builtin types into type context *)
  List.iter (fun builtin_ast ->
    List.iter (function
      | TypeDef type_def ->
          (match type_def with
           | StructDef (name, _) | EnumDef (name, _) | TypeAlias (name, _) ->
               Hashtbl.replace ctx.types name type_def)
      | _ -> ()
    ) builtin_ast
  ) builtin_asts;
  
  (* Add enum constants as variables for all loaded enums *)
  Hashtbl.iter (fun _name type_def ->
    match type_def with
    | EnumDef (enum_name, enum_values) ->
        let enum_type = match enum_name with
          | "XdpAction" -> XdpAction
          | "TcAction" -> TcAction
          | _ -> UserType enum_name
        in
        List.iter (fun (const_name, _) ->
          Hashtbl.replace ctx.variables const_name enum_type
        ) enum_values
    | _ -> ()
  ) ctx.types;
  ctx.multi_program_analysis <- Some multi_prog_analysis;
  
  (* First pass: collect type definitions, map declarations, config declarations, and ALL function signatures *)
  List.iter (function
    | TypeDef type_def ->
        (match type_def with
         | StructDef (name, _) | EnumDef (name, _) | TypeAlias (name, _) ->
             Hashtbl.replace ctx.types name type_def)
    | StructDecl struct_def ->
        let type_def = StructDef (struct_def.struct_name, struct_def.struct_fields) in
        Hashtbl.replace ctx.types struct_def.struct_name type_def
    | MapDecl map_decl ->
        Hashtbl.replace ctx.maps map_decl.name map_decl
    | ConfigDecl config_decl ->
        Hashtbl.replace ctx.configs config_decl.config_name config_decl
    | AttributedFunction attr_func ->
        (* Register attributed function signature in context *)
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) attr_func.attr_function.func_params in
        let return_type = match attr_func.attr_function.func_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> U32  (* default return type *)
        in
        Hashtbl.replace ctx.functions attr_func.attr_function.func_name (param_types, return_type);
        Hashtbl.replace ctx.function_scopes attr_func.attr_function.func_name attr_func.attr_function.func_scope
    | GlobalFunction func ->
        (* Register global function signature in context *)
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) func.func_params in
        let return_type = match func.func_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> U32  (* default return type *)
        in
        Hashtbl.replace ctx.functions func.func_name (param_types, return_type);
        Hashtbl.replace ctx.function_scopes func.func_name func.func_scope
  ) ast;
  
  (* Second pass: type check attributed functions and global functions with multi-program awareness *)
  let (typed_attributed_functions, typed_userspace_functions) = List.fold_left (fun (attr_acc, userspace_acc) decl ->
    match decl with
    | AttributedFunction attr_func ->
        (* Extract program type from attribute for context *)
        let prog_type = match attr_func.attr_list with
          | SimpleAttribute prog_type_str :: _ ->
              (match prog_type_str with
               | "xdp" -> Some Xdp
               | "tc" -> Some Tc  
               | "kprobe" -> Some Kprobe
               | "uprobe" -> Some Uprobe
               | "tracepoint" -> Some Tracepoint
               | "lsm" -> Some Lsm
               | "cgroup_skb" -> Some CgroupSkb
               | _ -> None)
          | _ -> None
        in
        
        (* Validate attributed function signatures based on program type *)
        (match prog_type with
         | Some Xdp ->
             let params = attr_func.attr_function.func_params in
             let resolved_param_type = if List.length params = 1 then 
               resolve_user_type ctx (snd (List.hd params)) 
             else UserType "invalid" in
             let resolved_return_type = match attr_func.attr_function.func_return_type with
               | Some ret_type -> Some (resolve_user_type ctx ret_type)
               | None -> None in
             
             if List.length params <> 1 ||
                resolved_param_type <> XdpContext ||
                resolved_return_type <> Some XdpAction then
               type_error ("@xdp attributed function must have signature (ctx: XdpContext) -> XdpAction") attr_func.attr_pos
         | Some Tc ->
             let params = attr_func.attr_function.func_params in
             let resolved_param_type = if List.length params = 1 then 
               resolve_user_type ctx (snd (List.hd params)) 
             else UserType "invalid" in
             let resolved_return_type = match attr_func.attr_function.func_return_type with
               | Some ret_type -> Some (resolve_user_type ctx ret_type)
               | None -> None in
             
             if List.length params <> 1 ||
                resolved_param_type <> TcContext ||
                resolved_return_type <> Some TcAction then
               type_error ("@tc attributed function must have signature (ctx: TcContext) -> TcAction") attr_func.attr_pos
         | Some Kprobe ->
             let params = attr_func.attr_function.func_params in
             let resolved_param_type = if List.length params = 1 then 
               resolve_user_type ctx (snd (List.hd params)) 
             else UserType "invalid" in
             let resolved_return_type = match attr_func.attr_function.func_return_type with
               | Some ret_type -> Some (resolve_user_type ctx ret_type)
               | None -> None in
             
             if List.length params <> 1 ||
                resolved_param_type <> KprobeContext ||
                resolved_return_type <> Some U32 then
               type_error ("@kprobe attributed function must have signature (ctx: KprobeContext) -> u32") attr_func.attr_pos
         | Some _ -> () (* Other program types - validation can be added later *)
         | None -> type_error ("Invalid or unsupported attribute") attr_func.attr_pos);
        
        (* Track this as an attributed function that cannot be called directly *)
        Hashtbl.add ctx.attributed_functions attr_func.attr_function.func_name ();
        
        (* Add to attributed function map for tail call detection *)
        Hashtbl.replace ctx.attributed_function_map attr_func.attr_function.func_name attr_func;
        
        (* Set current program type for context *)
        ctx.current_program_type <- prog_type;
        let typed_func = type_check_function ctx attr_func.attr_function in
        ctx.current_program_type <- None;
        ((attr_func.attr_list, typed_func) :: attr_acc, userspace_acc)
    | GlobalFunction func ->
        let typed_func = type_check_function ctx func in
        (attr_acc, typed_func :: userspace_acc)
    | _ -> (attr_acc, userspace_acc)
  ) ([], []) ast in
  let typed_attributed_functions = List.rev typed_attributed_functions in
  let typed_userspace_functions = List.rev typed_userspace_functions in
  
  (* STEP 3: Convert back to annotated AST with multi-program context *)
  let annotated_ast = typed_ast_to_annotated_ast typed_attributed_functions typed_userspace_functions ast in
  
  (* STEP 4: Post-process to populate multi-program fields *)
  let enhanced_ast = populate_multi_program_context annotated_ast multi_prog_analysis in
  
  (* Return enhanced AST and typed programs *)
  (enhanced_ast, typed_attributed_functions)

(** Populate multi-program context in annotated AST *)
and populate_multi_program_context ast multi_prog_analysis =
  let rec enhance_expr prog_type expr =
    (* Set program context *)
    expr.program_context <- Some {
      current_program = Some prog_type;
      accessing_programs = [prog_type];
      data_flow_direction = Some Read;
    };
    
    (* Set map scope if this expression accesses a map *)
    (match expr.expr_desc with
     | Identifier name ->
         if List.exists (fun (map_name, _) -> map_name = name) multi_prog_analysis.map_usage_patterns then
           expr.map_scope <- Some Global
     | ArrayAccess ({expr_desc = Identifier map_name; _}, _) ->
         if List.exists (fun (name, _) -> name = map_name) multi_prog_analysis.map_usage_patterns then
           expr.map_scope <- Some Global
     | _ -> ());
    
    (* Mark as type checked *)
    expr.type_checked <- true;
    
    (* Recursively enhance sub-expressions *)
    (match expr.expr_desc with
     | FunctionCall (_, args) ->
         List.iter (enhance_expr prog_type) args
     | ArrayAccess (arr_expr, idx_expr) ->
         enhance_expr prog_type arr_expr;
         enhance_expr prog_type idx_expr
     | BinaryOp (left, _, right) ->
         enhance_expr prog_type left;
         enhance_expr prog_type right
     | UnaryOp (_, sub_expr) ->
         enhance_expr prog_type sub_expr
     | FieldAccess (obj_expr, _) ->
         enhance_expr prog_type obj_expr
     | _ -> ())
  in
  
  let rec enhance_stmt prog_type stmt =
    match stmt.stmt_desc with
    | ExprStmt expr ->
        enhance_expr prog_type expr
    | Assignment (_, expr) ->
        enhance_expr prog_type expr
    | FieldAssignment (obj_expr, _, value_expr) ->
        enhance_expr prog_type obj_expr;
        enhance_expr prog_type value_expr
    | IndexAssignment (map_expr, key_expr, value_expr) ->
        (* This is a write operation *)
        enhance_expr prog_type map_expr;
        enhance_expr prog_type key_expr;
        enhance_expr prog_type value_expr;
        (* Update the map expression to indicate write access *)
        (match map_expr.program_context with
         | Some ctx -> map_expr.program_context <- Some { ctx with data_flow_direction = Some Write }
         | None -> ())
    | Declaration (_, _, expr) ->
        enhance_expr prog_type expr
    | ConstDeclaration (_, _, expr) ->
        enhance_expr prog_type expr
    | Return (Some expr) ->
        enhance_expr prog_type expr
    | If (cond_expr, then_stmts, else_stmts_opt) ->
        enhance_expr prog_type cond_expr;
        List.iter (enhance_stmt prog_type) then_stmts;
        (match else_stmts_opt with
         | Some else_stmts -> List.iter (enhance_stmt prog_type) else_stmts
         | None -> ())
    | For (_, start_expr, end_expr, body_stmts) ->
        enhance_expr prog_type start_expr;
        enhance_expr prog_type end_expr;
        List.iter (enhance_stmt prog_type) body_stmts
    | ForIter (_, _, iter_expr, body_stmts) ->
        enhance_expr prog_type iter_expr;
        List.iter (enhance_stmt prog_type) body_stmts
    | While (cond_expr, body_stmts) ->
        enhance_expr prog_type cond_expr;
        List.iter (enhance_stmt prog_type) body_stmts
    | Delete (map_expr, key_expr) ->
        enhance_expr prog_type map_expr;
        enhance_expr prog_type key_expr;
        (* Delete is a write operation *)
        (match map_expr.program_context with
         | Some ctx -> map_expr.program_context <- Some { ctx with data_flow_direction = Some Write }
         | None -> ())
    | Return None -> ()
    | Break -> ()
    | Continue -> ()
    | Try (try_stmts, catch_clauses) ->
        List.iter (enhance_stmt prog_type) try_stmts;
        List.iter (fun clause ->
          List.iter (enhance_stmt prog_type) clause.catch_body
        ) catch_clauses
    | Throw expr ->
        enhance_expr prog_type expr
    | Defer expr ->
        enhance_expr prog_type expr
  in

  (* Enhance userspace expressions and statements *)
  let rec enhance_userspace_expr expr =
    (* Set program context to None for userspace/global functions *)
    expr.program_context <- None;
    
    (* Set map scope if this expression accesses a map *)
    (match expr.expr_desc with
     | Identifier name ->
         if List.exists (fun (map_name, _) -> map_name = name) multi_prog_analysis.map_usage_patterns then
           expr.map_scope <- Some Global
     | ArrayAccess ({expr_desc = Identifier map_name; _}, _) ->
         if List.exists (fun (name, _) -> name = map_name) multi_prog_analysis.map_usage_patterns then
           expr.map_scope <- Some Global
     | _ -> ());
    
    (* Mark as type checked *)
    expr.type_checked <- true;
    
    (* Recursively enhance sub-expressions *)
    (match expr.expr_desc with
     | FunctionCall (_, args) ->
         List.iter enhance_userspace_expr args
     | ArrayAccess (arr_expr, idx_expr) ->
         enhance_userspace_expr arr_expr;
         enhance_userspace_expr idx_expr
     | BinaryOp (left, _, right) ->
         enhance_userspace_expr left;
         enhance_userspace_expr right
     | UnaryOp (_, sub_expr) ->
         enhance_userspace_expr sub_expr
     | FieldAccess (obj_expr, _) ->
         enhance_userspace_expr obj_expr
     | _ -> ())
  in
  
  let rec enhance_userspace_stmt stmt =
    match stmt.stmt_desc with
    | ExprStmt expr ->
        enhance_userspace_expr expr
    | Assignment (_, expr) ->
        enhance_userspace_expr expr
    | FieldAssignment (obj_expr, _, value_expr) ->
        enhance_userspace_expr obj_expr;
        enhance_userspace_expr value_expr
    | IndexAssignment (map_expr, key_expr, value_expr) ->
        (* This is a write operation *)
        enhance_userspace_expr map_expr;
        enhance_userspace_expr key_expr;
        enhance_userspace_expr value_expr;
        (* Update the map expression to indicate write access *)
        (match map_expr.program_context with
         | Some ctx -> map_expr.program_context <- Some { ctx with data_flow_direction = Some Write }
         | None -> ())
    | Declaration (_, _, expr) ->
        enhance_userspace_expr expr
    | ConstDeclaration (_, _, expr) ->
        enhance_userspace_expr expr
    | Return (Some expr) ->
        enhance_userspace_expr expr
    | If (cond_expr, then_stmts, else_stmts_opt) ->
        enhance_userspace_expr cond_expr;
        List.iter enhance_userspace_stmt then_stmts;
        (match else_stmts_opt with
         | Some else_stmts -> List.iter enhance_userspace_stmt else_stmts
         | None -> ())
    | For (_, start_expr, end_expr, body_stmts) ->
        enhance_userspace_expr start_expr;
        enhance_userspace_expr end_expr;
        List.iter enhance_userspace_stmt body_stmts
    | ForIter (_, _, iter_expr, body_stmts) ->
        enhance_userspace_expr iter_expr;
        List.iter enhance_userspace_stmt body_stmts
    | While (cond_expr, body_stmts) ->
        enhance_userspace_expr cond_expr;
        List.iter enhance_userspace_stmt body_stmts
    | Delete (map_expr, key_expr) ->
        enhance_userspace_expr map_expr;
        enhance_userspace_expr key_expr;
        (* Delete is a write operation *)
        (match map_expr.program_context with
         | Some ctx -> map_expr.program_context <- Some { ctx with data_flow_direction = Some Write }
         | None -> ())
    | Return None -> ()
    | Break -> ()
    | Continue -> ()
    | Try (try_stmts, catch_clauses) ->
        List.iter enhance_userspace_stmt try_stmts;
        List.iter (fun clause ->
          List.iter enhance_userspace_stmt clause.catch_body
        ) catch_clauses
    | Throw expr ->
        enhance_userspace_expr expr
    | Defer expr ->
        enhance_userspace_expr expr
  in

  (* Enhance attributed functions and global functions with multi-program context *)
  List.map (function
    | AttributedFunction attr_func ->
        (* Extract program type from attribute *)
        let prog_type = match attr_func.attr_list with
          | SimpleAttribute prog_type_str :: _ ->
              (match prog_type_str with
               | "xdp" -> Some Xdp
               | "tc" -> Some Tc
               | "kprobe" -> Some Kprobe
               | "uprobe" -> Some Uprobe
               | "tracepoint" -> Some Tracepoint
               | "lsm" -> Some Lsm
               | "cgroup_skb" -> Some CgroupSkb
               | _ -> None)
          | _ -> None
        in
        (match prog_type with
         | Some pt ->
             (* Enhance function body with program context *)
             List.iter (enhance_stmt pt) attr_func.attr_function.func_body;
             AttributedFunction attr_func
         | None ->
             (* Treat as userspace if no valid program type *)
             List.iter enhance_userspace_stmt attr_func.attr_function.func_body;
             AttributedFunction attr_func)

    | GlobalFunction func ->
        List.iter enhance_userspace_stmt func.func_body;
        GlobalFunction func

    | other_decl -> other_decl
        ) ast