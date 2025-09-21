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

(** Type checker for KernelScript *)

open Ast
open Printf

(** Expression context for void function validation *)
type expr_context = Statement | Expression

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
  helper_functions: (string, unit) Hashtbl.t; (* Track @helper functions *)
  test_functions: (string, unit) Hashtbl.t; (* Track @test functions *)
  maps: (string, Ir.ir_map_def) Hashtbl.t;
  configs: (string, Ast.config_declaration) Hashtbl.t;
  attributed_functions: (string, unit) Hashtbl.t; (* Track attributed functions that cannot be called directly *)
  attributed_function_map: (string, attributed_function) Hashtbl.t; (* Map for tail call analysis *)
  imports: (string, Import_resolver.resolved_import) Hashtbl.t; (* Track imported modules *)
  mutable current_function: string option;
  mutable current_program_type: program_type option;
  mutable multi_program_analysis: Multi_program_analyzer.multi_program_analysis option;
  mutable expr_context: expr_context; (* Track whether we're in statement or expression context *)
  in_tail_call_context: bool; (* Flag to indicate we're processing a potential tail call *)
  in_match_return_context: bool; (* Flag to indicate we're inside a match expression in return position *)
  ast_context: Ast.declaration list; (* Store original AST for struct_ops attribute checking *)
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
  | TCall of typed_expr * typed_expr list  (* Unified call: callee_expression * arguments *)
  | TTailCall of string * typed_expr list  (* Tail call detected in return position *)
  | TArrayAccess of typed_expr * typed_expr
  | TFieldAccess of typed_expr * string
  | TArrowAccess of typed_expr * string  (* pointer->field *)
  | TBinaryOp of typed_expr * binary_op * typed_expr
  | TUnaryOp of unary_op * typed_expr
  | TStructLiteral of string * (string * typed_expr) list
  | TMatch of typed_expr * typed_match_arm list  (* match (expr) { arms } *)
  | TNew of bpf_type  (* new Type() - object allocation *)
  | TNewWithFlag of bpf_type * typed_expr  (* new Type(gfp_flag) - object allocation with flag *)

(** Typed match arm *)
and typed_match_arm = {
  tarm_pattern: match_pattern;
  tarm_body: typed_match_arm_body;
  tarm_pos: position;
}

(** Typed match arm body *)
and typed_match_arm_body = 
  | TSingleExpr of typed_expr
  | TBlock of typed_statement list

and typed_statement = {
  tstmt_desc: typed_stmt_desc;
  tstmt_pos: position;
}

and typed_stmt_desc =
  | TExprStmt of typed_expr
  | TAssignment of string * typed_expr
  | TCompoundAssignment of string * binary_op * typed_expr  (* var op= expr *)
  | TCompoundIndexAssignment of typed_expr * typed_expr * binary_op * typed_expr  (* map[key] op= expr *)
  | TFieldAssignment of typed_expr * string * typed_expr  (* object, field, value *)
  | TArrowAssignment of typed_expr * string * typed_expr  (* pointer, field, value *)
  | TIndexAssignment of typed_expr * typed_expr * typed_expr
  | TDeclaration of string * bpf_type * typed_expr option
  | TConstDeclaration of string * bpf_type * typed_expr
  | TReturn of typed_expr option
  | TIf of typed_expr * typed_statement list * typed_statement list option
  | TFor of string * typed_expr * typed_expr * typed_statement list
  | TForIter of string * string * typed_expr * typed_statement list
  | TWhile of typed_expr * typed_statement list
  | TDelete of typed_delete_target
  | TBreak
  | TContinue
  | TTry of typed_statement list * catch_clause list  (* try statements, catch clauses *)
  | TThrow of typed_expr  (* throw statements with expression *)
  | TDefer of typed_expr  (* defer expression *)

(** Typed delete target - either map entry or object pointer *)
and typed_delete_target =
  | TDeleteMapEntry of typed_expr * typed_expr  (* delete map[key] *)
  | TDeletePointer of typed_expr                (* delete ptr *)

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
let create_context symbol_table ast = 
  let variables = Hashtbl.create 32 in
  let functions = Hashtbl.create 16 in
  let function_scopes = Hashtbl.create 16 in
  let helper_functions = Hashtbl.create 16 in
  let test_functions = Hashtbl.create 16 in
  let attributed_functions = Hashtbl.create 16 in
  let types = Hashtbl.create 16 in
  let maps = Hashtbl.create 16 in
  let configs = Hashtbl.create 16 in
  let imports = Hashtbl.create 16 in
  
  (* Extract enum constants, impl blocks, and type definitions from symbol table *)
  let global_symbols = Symbol_table.get_global_symbols symbol_table in
  List.iter (fun symbol ->
    match symbol.Symbol_table.kind with
    | Symbol_table.EnumConstant (enum_name, _value) ->
        (* Add enum constant as a U32 variable (standard for enum values) *)
        let enum_type = Enum enum_name in
        Hashtbl.replace variables symbol.Symbol_table.name enum_type
    | Symbol_table.TypeDef type_def ->
        (* Add type definition to types hashtable *)
        (match type_def with
         | StructDef (name, _, _) | EnumDef (name, _, _) | TypeAlias (name, _, _) ->
             Hashtbl.replace types name type_def);
        (* Check if this is an impl block by looking in the AST context *)
        (match type_def with
         | StructDef (name, _, _) ->
             let is_impl_block = List.exists (function
               | ImplBlock impl_block when impl_block.impl_name = name -> true
               | _ -> false
             ) ast in
             if is_impl_block then
               (* Add impl block as a struct_ops variable *)
               Hashtbl.replace variables name (Struct name)
         | _ -> ())
    | _ -> ()
  ) global_symbols;
  
  {
    variables = variables;
    functions = functions;
    function_scopes = function_scopes;
    helper_functions = helper_functions;
    test_functions = test_functions;
    attributed_functions = attributed_functions;
    types = types;
    maps = maps;
    configs = configs;
    imports = imports;
    symbol_table = symbol_table;
    current_function = None;
    current_program_type = None;
    multi_program_analysis = None;
    expr_context = Expression; (* Default to expression context for safety *)
    in_tail_call_context = false;
    in_match_return_context = false;
    attributed_function_map = Hashtbl.create 16;
    ast_context = ast;
  }

(** Track loop nesting depth to prevent nested loops *)
let loop_depth = ref 0

(** Helper to create type error *)
let type_error msg pos = raise (Type_error (msg, pos))

(** Validate void function usage in expression context *)
let validate_void_in_expression expr_type func_name context pos =
  match expr_type, context with
  | Void, Expression -> 
      type_error ("Void function '" ^ func_name ^ "' cannot be used in an expression") pos
  | _ -> ()

(** Check if a type represents an enum (either Enum _ or built-in enum-like types) *)
let is_enum_like_type = function
  | Enum _ -> true
  | Xdp_action -> true  (* Built-in enum-like type *)
  (* Add other built-in enum-like types here as needed *)
  | _ -> false

(** Resolve user types to built-in types and type aliases *)
let rec resolve_user_type ctx = function
  | UserType "xdp_md" -> Xdp_md
  | UserType "xdp_action" -> Xdp_action
  | UserType "__sk_buff" -> Struct "__sk_buff"
  | UserType name ->
      (* Look up type alias in the context *)
      (try
         let type_def = Hashtbl.find ctx.types name in
         match type_def with
         | TypeAlias (_, underlying_type, _) -> 
             (* Recursively resolve the underlying type in case it's also an alias *)
             resolve_user_type ctx underlying_type
         | StructDef (_, _, _) -> Struct name
         | EnumDef (_, _, _) -> Enum name
       with Not_found -> UserType name)
  | Pointer inner_type -> Pointer (resolve_user_type ctx inner_type)
  | Function (param_types, return_type) -> 
      (* Resolve parameter types and return type *)
      let resolved_params = List.map (resolve_user_type ctx) param_types in
      let resolved_return = resolve_user_type ctx return_type in
      Function (resolved_params, resolved_return)
  | Map (key_type, value_type, map_type, size) ->
      (* Resolve user types within map type *)
      let resolved_key_type = resolve_user_type ctx key_type in
      let resolved_value_type = resolve_user_type ctx value_type in
      
      Map (resolved_key_type, resolved_value_type, map_type, size)
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
  | U32, I8 | U32, I16 | U32, I32 -> Some I32   (* U32 can be assigned to signed types if they fit *)
  | I64, U32 | U32, I64 -> Some I64   (* U32 can always fit in I64 *)
  | I64, U64 | U64, I64 -> Some I64   (* U64 literals to I64 (may truncate but allowed in C-style) *)
  | I8, U8 | U8, I8 -> Some I8   (* Small integer promotions *)
  | I16, U16 | U16, I16 -> Some I16   (* Medium integer promotions *)
  
  (* No other unification possible *)
  | _ -> None

let rec unify_types t1 t2 =
  match t1, t2 with
  (* Identical types *)
  | t1, t2 when t1 = t2 -> Some t1
  
  (* String types - allow smaller strings to fit into larger ones *)
  | Str size1, Str size2 when size1 <= size2 -> Some (Str size2)
  | Str size1, Str size2 when size2 <= size1 -> Some (Str size1)
  
  (* String to u8 array conversion - string literals can be assigned to u8 arrays *)
  | Str str_size, Array (U8, array_size) when str_size <= array_size -> Some (Array (U8, array_size))
  | Array (U8, array_size), Str str_size when str_size <= array_size -> Some (Array (U8, array_size))
  
  (* Integer type promotions using C-style rules *)
  | t1, t2 when (match t1, t2 with 
                  | (U8|U16|U32|U64), (U8|U16|U32|U64) -> true
                  | (I8|I16|I32|I64), (I8|I16|I32|I64) -> true
                  | (U8|U16|U32|U64), (I8|I16|I32|I64) -> true  (* Mixed unsigned/signed *)
                  | (I8|I16|I32|I64), (U8|U16|U32|U64) -> true  (* Mixed signed/unsigned *)
                  | _ -> false) ->
      integer_promotion t1 t2
  
  (* Array types *)
  | Array (t1, s1), Array (t2, s2) when s1 = s2 ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Array (unified, s1))
       | None -> None)
  
  (* Special case: size-0 arrays (from enhanced array initialization) can unify with any sized array *)
  | Array (t1, 0), Array (t2, s2) ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Array (unified, s2))
       | None -> None)
  | Array (t1, s1), Array (t2, 0) ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Array (unified, s1))
       | None -> None)
  
  (* Null type unification - null can unify with any pointer or function type *)
  | Null, Pointer t -> Some (Pointer t)  (* null unifies with any pointer *)
  | Pointer t, Null -> Some (Pointer t)  (* any pointer unifies with null *)
  | Null, Function (params, ret) -> Some (Function (params, ret))  (* null unifies with functions *)
  | Function (params, ret), Null -> Some (Function (params, ret))  (* functions unify with null *)
  
  (* Pointer types *)
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
  | Map (k1, v1, mt1, s1), Map (k2, v2, mt2, s2) when mt1 = mt2 && s1 = s2 ->
      (match unify_types k1 k2, unify_types v1 v2 with
       | Some unified_k, Some unified_v -> Some (Map (unified_k, unified_v, mt1, s1))
       | _ -> None)
  
  (* Program reference types *)
  | ProgramRef pt1, ProgramRef pt2 when pt1 = pt2 -> Some (ProgramRef pt1)
  
  (* Enum-integer compatibility: enums are represented as u32 *)
  | Enum _, (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64) | (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64), Enum _ -> Some U32
  | Enum enum_name, Enum other_name when enum_name = other_name -> Some (Enum enum_name)
  

  
  (* All enum-like types (both Enum _ and built-in enum types) are compatible with integers *)
  | t1, (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64) when is_enum_like_type t1 -> Some t1
  | (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64), t2 when is_enum_like_type t2 -> Some t2

  (* No unification possible *)
  | _ -> None

(** Validate ring buffer object declaration *)
let validate_ringbuf_object ctx _name ringbuf_type pos =
  match ringbuf_type with
  | Ringbuf (value_type, size) ->
      (* Check value type is a struct *)
      let resolved_value_type = resolve_user_type ctx value_type in
      (match resolved_value_type with
       | Struct _ | UserType _ -> () (* Valid: struct or user-defined type *)
       | _ -> type_error ("Ring buffer value type must be a struct, got: " ^ string_of_bpf_type resolved_value_type) pos);
      
      (* Validate ring buffer size is power of 2 and reasonable *)
      if size <= 0 then
        type_error ("Ring buffer size must be positive, got: " ^ string_of_int size) pos;
      if size land (size - 1) != 0 then
        type_error ("Ring buffer size must be a power of 2, got: " ^ string_of_int size) pos;
      if size < 4096 then
        type_error ("Ring buffer size must be at least 4096 bytes, got: " ^ string_of_int size) pos;
      if size > 134217728 then (* 128MB *)
        type_error ("Ring buffer size must not exceed 128MB, got: " ^ string_of_int size) pos
  | _ -> () (* Not a ring buffer, no validation needed *)

(** Check if we can assign from_type to to_type (for variable declarations) *)
let can_assign to_type from_type =
  match unify_types to_type from_type with
  | Some _ -> true
  | None ->
      (* Special case: explicit arrays can be assigned to larger arrays (with implicit zero-fill) *)
      (match to_type, from_type with
       | Array (t1, s1), Array (t2, s2) when s2 <= s1 && s2 > 0 ->
           (match unify_types t1 t2 with
            | Some _ -> true
            | None -> false)
       | _ ->
           (* Allow assignment if types can be promoted *)
           (match integer_promotion to_type from_type with
            | Some _ -> true
            | None -> false))



(** Helper function to get the type of a literal *)
let get_literal_type lit =
  match lit with
  | IntLit (value, _) -> if Ast.IntegerValue.compare_with_zero value < 0 then I32 else U32
  | StringLit s -> Str (max 1 (String.length s))
  | CharLit _ -> Char
  | BoolLit _ -> Bool
  | NullLit -> Pointer U32
  | NoneLit -> NoneType
  | ArrayLit _ -> U32  (* Nested arrays default to u32 *)

(** Helper function to check type equality for array literals *)
let rec types_equal t1 t2 =
  match t1, t2 with
  | U32, U32 | I32, I32 | Bool, Bool | Char, Char -> true
  | Str s1, Str s2 -> s1 = s2
  | Pointer t1, Pointer t2 -> types_equal t1 t2
  | Array (t1, s1), Array (t2, s2) -> types_equal t1 t2 && s1 = s2
  | _ -> false

(** Type check literals *)
let type_check_literal lit pos =
  let typ = match lit with
    | IntLit (value, _) -> 
        (* Choose appropriate integer type based on the value *)
        if Ast.IntegerValue.compare_with_zero value < 0 then I32  (* Signed integers for negative values *)
        else U32  (* Unsigned integers for positive values *)
    | StringLit s -> 
        (* String literals are polymorphic - they can unify with any string type *)
        (* For now, we'll use a default size but this will be refined during unification *)
        let len = String.length s in
        Str (max 1 len)  (* At least size 1 to handle empty strings *)
    | CharLit _ -> Char
    | BoolLit _ -> Bool
    | NullLit -> Null  (* null literal - can unify with any pointer or function type *)
    | NoneLit -> NoneType  (* none literal represents missing/absent values *)
    | ArrayLit init_style ->
        (* Handle enhanced array literal type checking *)
        (match init_style with
         | ZeroArray -> Array (U32, 0)
         | FillArray fill_lit ->
             let fill_type = get_literal_type fill_lit in
             Array (fill_type, 0)
         | ExplicitArray literals ->
             (match literals with
              | [] -> Array (U32, 0)
              | first_lit :: rest_lits ->
                  let first_type = get_literal_type first_lit in
                  (* Check that all literals have the same type *)
                  List.iter (fun lit ->
                    let lit_type = get_literal_type lit in
                    if not (types_equal first_type lit_type) then
                      type_error ("Array literal contains mixed types: expected " ^ 
                                 (match first_type with
                                  | U32 -> "integer"
                                  | I32 -> "integer"
                                  | Bool -> "boolean"
                                  | Char -> "character"
                                  | Str _ -> "string"
                                  | Pointer _ -> "pointer"
                                  | Array _ -> "array"
                                  | _ -> "unknown") ^
                                 " but found " ^
                                 (match lit_type with
                                  | U32 -> "integer"
                                  | I32 -> "integer"
                                  | Bool -> "boolean"
                                  | Char -> "character"
                                  | Str _ -> "string"
                                  | Pointer _ -> "pointer"
                                  | Array _ -> "array"
                                  | _ -> "unknown")) pos
                  ) rest_lits;
                  Array (first_type, List.length literals)))
  in
  { texpr_desc = TLiteral lit; texpr_type = typ; texpr_pos = pos }

(** Get the type of a literal without creating a typed expression *)
let type_of_literal lit =
  match lit with
  | IntLit (value, _) -> 
      if Ast.IntegerValue.compare_with_zero value < 0 then I32 else U32
  | StringLit s -> 
      let len = String.length s in
      Str (max 1 len)
  | CharLit _ -> Char
  | BoolLit _ -> Bool
  | NullLit -> Pointer U32
  | NoneLit -> NoneType
  | ArrayLit init_style ->
      (* Handle enhanced array literal type checking *)
      (match init_style with
       | ZeroArray -> Array (U32, 0)
       | FillArray fill_lit ->
           let fill_type = get_literal_type fill_lit in
           Array (fill_type, 0)
       | ExplicitArray literals ->
           (match literals with
            | [] -> Array (U32, 0)
            | first_lit :: rest_lits ->
                let first_type = get_literal_type first_lit in
                (* Check that all literals have the same type *)
                List.iter (fun lit ->
                  let lit_type = get_literal_type lit in
                  if not (types_equal first_type lit_type) then
                    failwith ("Array literal contains mixed types")
                ) rest_lits;
                Array (first_type, List.length literals)))

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
    | ["xdp_action"; _] -> { texpr_desc = TIdentifier name; texpr_type = Xdp_action; texpr_pos = pos }
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
      (* Check if it's a map - allow ring buffers as standalone identifiers, reject others *)
      else if Hashtbl.mem ctx.maps name then
        let map_decl = Hashtbl.find ctx.maps name in
        (match map_decl.map_type with

         | _ -> type_error ("Map '" ^ name ^ "' cannot be used as a standalone identifier. Use map[key] for map access.") pos)
      else
        type_error ("Undefined variable: " ^ name) pos



(** Detect and validate tail calls in return statements *)
let detect_tail_call_in_return_expr ctx expr =
  match expr.expr_desc with
  | Call (callee_expr, args) ->
      (* Check if this is a simple function call that could be a tail call *)
      (match callee_expr.expr_desc with
       | Identifier name ->
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
       | _ ->
           None (* Function pointer call - cannot be tail call *))
  | Match (_matched_expr, _match_arms) ->
      (* Match expressions should preserve their structure even if they contain tail calls *)
      (* Individual function calls within arms will be converted to tail calls during type checking *)
      None  (* Don't collapse match expressions to single tail calls *)
  | _ -> None (* Not a function call *)

(** Helper to create typed identifier *)
let make_typed_identifier name pos =
  { texpr_desc = TIdentifier name; texpr_type = U32; texpr_pos = pos }

(** Type check a builtin function call *)
let type_check_builtin_call ctx name typed_args arg_types pos =
  (* Check if test() is only called from @test functions *)
  if name = "test" then (
    match ctx.current_function with
    | Some current_func_name ->
        if not (Hashtbl.mem ctx.test_functions current_func_name) then
          type_error ("test() builtin can only be called from functions with @test attribute") pos
    | None ->
        type_error ("test() builtin can only be called from functions with @test attribute") pos
  );
  
  match Stdlib.get_builtin_function_signature name with
  | Some (expected_params, return_type) ->
      (match Stdlib.get_builtin_function name with
       | Some builtin_func when builtin_func.is_variadic ->
           (* Variadic function - but still run validation if available *)
           let (validation_ok, validation_error) = Stdlib.validate_builtin_call name arg_types ctx.ast_context pos in
           if not validation_ok then
             (match validation_error with
              | Some error_msg -> type_error error_msg pos
              | None -> type_error ("Validation failed for function: " ^ name) pos)
           else
             (* Validation passed - accept any number of arguments *)
             Some { texpr_desc = TCall (make_typed_identifier name pos, typed_args); texpr_type = return_type; texpr_pos = pos }
         | Some _ ->
             (* Check if this function has custom validation *)
             let (validation_ok, validation_error) = Stdlib.validate_builtin_call name arg_types ctx.ast_context pos in
             if not validation_ok then
               (match validation_error with
                | Some error_msg -> type_error error_msg pos
                | None -> type_error ("Validation failed for function: " ^ name) pos)
                           else
                (* Regular builtin function validation passed - check argument count and types *)
                (* Skip standard type checking if param_types is empty (custom validation handles it) *)
                if List.length expected_params = 0 then
                  (* Custom validation handled type checking *)
                  Some { texpr_desc = TCall (make_typed_identifier name pos, typed_args); texpr_type = return_type; texpr_pos = pos }
                else if List.length expected_params = List.length arg_types then
                  let unified = List.map2 unify_types expected_params arg_types in
                  if List.for_all (function Some _ -> true | None -> false) unified then
                    Some { texpr_desc = TCall (make_typed_identifier name pos, typed_args); texpr_type = return_type; texpr_pos = pos }
                  else
                    type_error ("Type mismatch in function call: " ^ name) pos
                else
                  type_error ("Wrong number of arguments for function: " ^ name) pos
       | None -> type_error ("Unknown builtin function: " ^ name) pos)
  | None -> None

(** Convert any type to boolean for truthy/falsy evaluation *)
let is_truthy_type bpf_type =
  match bpf_type with
  | Bool -> true
  | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 -> true  (* numbers: 0 is falsy, non-zero is truthy *)
  | Char -> true                                          (* characters: '\0' is falsy, others truthy *)
  | Str _ -> true                                         (* strings: empty is falsy, non-empty is truthy *)
  | Pointer _ -> true                                     (* pointers: null is falsy, non-null is truthy *)
  | Enum _ -> true                                        (* enums: based on numeric value *)
  | Null -> true                                          (* null literal: always falsy but allowed in boolean context *)
  | _ -> false                                            (* other types not allowed in boolean context *)

(** Helper function to extract return type from a block of statements *)
let rec extract_block_return_type stmts arm_pos =
  let extract_type_from_stmt stmt =
    match stmt.tstmt_desc with
    | TReturn (Some return_expr) -> return_expr.texpr_type
    | TExprStmt expr -> expr.texpr_type
    | TIf (_, then_stmts, Some else_stmts) ->
        (* For if-else statements, both branches must return compatible types *)
        let then_type = extract_block_return_type then_stmts arm_pos in
        let else_type = extract_block_return_type else_stmts arm_pos in
        (match unify_types then_type else_type with
         | Some unified_type -> unified_type
         | None -> type_error ("If-else branches have incompatible types: " ^ 
                               string_of_bpf_type then_type ^ " vs " ^ 
                               string_of_bpf_type else_type) arm_pos)
    | TIf (_, _, None) ->
        (* If without else - this doesn't work as a return value *)
        type_error "If statement without else cannot be used as return value in match arm" arm_pos
    | _ -> 
        type_error "Block arms must end with a return statement, expression, or if-else statement" arm_pos
  in
  match List.rev stmts with
  | last_stmt :: _ -> extract_type_from_stmt last_stmt
  | [] -> type_error "Empty block in match arm" arm_pos

(** Type check a user function call *)
let rec type_check_user_function_call ctx name typed_args arg_types pos =
  try
    let (expected_params, return_type) = Hashtbl.find ctx.functions name in
    
    (* Check attributed function call restrictions *)
    if Hashtbl.mem ctx.attributed_functions name && not ctx.in_match_return_context then
      type_error ("Attributed function '" ^ name ^ "' cannot be called directly. Use return " ^ name ^ "(...) for tail calls.") pos;
    
    (* Check @helper function call restrictions *)
    if Hashtbl.mem ctx.helper_functions name then (
      let in_ebpf_program = ctx.current_program_type <> None in
      let in_helper_function = match ctx.current_function with
        | Some current_func_name -> Hashtbl.mem ctx.helper_functions current_func_name
        | None -> false
      in
      if not in_ebpf_program && not in_helper_function then
        type_error ("Helper function '" ^ name ^ "' can only be called from eBPF programs or other helper functions, not from userspace code") pos
    );
    
    (* Check kernel/userspace function call restrictions *)
    (try
      let target_scope = Hashtbl.find ctx.function_scopes name in
      if target_scope = Ast.Kernel then
        let in_ebpf_program = ctx.current_program_type <> None in
        let current_scope = match ctx.current_function with
          | Some current_func_name ->
              (try 
                 Some (Hashtbl.find ctx.function_scopes current_func_name)
               with Not_found -> 
                 Some Ast.Userspace)
          | None -> 
              Some Ast.Userspace
        in
        (match current_scope, in_ebpf_program with
         | Some Ast.Userspace, false ->
             type_error ("Kernel function '" ^ name ^ "' cannot be called from userspace code") pos
         | _ -> ())
    with Not_found -> ());
    
    (* Check argument types *)
    if List.length expected_params = List.length arg_types then
      let unified = List.map2 unify_types expected_params arg_types in
      if List.for_all (function Some _ -> true | None -> false) unified then
        Some { texpr_desc = TCall (make_typed_identifier name pos, typed_args); texpr_type = return_type; texpr_pos = pos }
      else
        type_error ("Type mismatch in function call: " ^ name) pos
    else
      type_error ("Wrong number of arguments for function: " ^ name) pos
  with Not_found -> None

(** Type check a function pointer call (for variables with function type) *)
and type_check_function_pointer_variable ctx name typed_args arg_types pos =
  try
    let var_symbol = Hashtbl.find ctx.variables name in
    let resolved_var_type = resolve_user_type ctx var_symbol in
    (match resolved_var_type with
     | Function (param_types, return_type) ->
         (* This is a function pointer call *)
         if List.length param_types = List.length arg_types then
           let unified = List.map2 unify_types param_types arg_types in
           if List.for_all (function Some _ -> true | None -> false) unified then
             Some { texpr_desc = TCall (make_typed_identifier name pos, typed_args); texpr_type = return_type; texpr_pos = pos }
           else
             type_error ("Type mismatch in function pointer call: expected " ^ 
                        String.concat ", " (List.map string_of_bpf_type param_types) ^ 
                        " but got " ^ 
                        String.concat ", " (List.map string_of_bpf_type arg_types)) pos
         else
           type_error ("Wrong number of arguments for function pointer call: expected " ^ 
                      string_of_int (List.length param_types) ^ 
                      " but got " ^ 
                      string_of_int (List.length arg_types)) pos
     | _ ->
         type_error ("'" ^ name ^ "' is not a function or function pointer") pos)
  with Not_found -> None

(** Type check a function pointer call (for complex expressions) *)
and type_check_function_pointer_call ctx typed_callee typed_args arg_types pos =
  let resolved_func_type = resolve_user_type ctx typed_callee.texpr_type in
  match resolved_func_type with
  | Function (param_types, return_type) ->
      if List.length param_types = List.length arg_types then
        let unified = List.map2 unify_types param_types arg_types in
        if List.for_all (function Some _ -> true | None -> false) unified then
          { texpr_desc = TCall (typed_callee, typed_args); texpr_type = return_type; texpr_pos = pos }
        else
          type_error ("Type mismatch in function pointer call") pos
      else
        type_error ("Wrong number of arguments for function pointer call") pos
  | _ ->
      type_error ("Cannot call non-function expression") pos

(** Type check array access *)
and type_check_array_access ctx arr idx pos =
  let typed_idx = type_check_expression ctx idx in
  
  (* Check if this is map access first *)
  (match arr.expr_desc with
   | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
       (* This is map access *)
       let map_decl = Hashtbl.find ctx.maps map_name in
       (* Check key type compatibility with promotion support *)
       let resolved_map_key_type = resolve_user_type ctx map_decl.ast_key_type in
       let resolved_idx_type = resolve_user_type ctx typed_idx.texpr_type in
       (match unify_types resolved_map_key_type resolved_idx_type with
        | Some _ -> 
            (* Create a synthetic map type for the result *)
            let typed_arr = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.ast_key_type, map_decl.ast_value_type, map_decl.ast_map_type, map_decl.max_entries); texpr_pos = arr.expr_pos } in
            (* Map access returns the actual value type *)
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = map_decl.ast_value_type; texpr_pos = pos }
        | None -> type_error ("Map key type mismatch") pos)
   | _ ->
       (* Regular array access - index must be integer type or enum *)
       let resolved_idx_type = resolve_user_type ctx typed_idx.texpr_type in
       (match resolved_idx_type with
        | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 -> ()
        | Enum _ -> ()  (* Enums are compatible with integers for array indexing *)
        | _ -> type_error "Array index must be integer type" pos);
       
       let typed_arr = type_check_expression ctx arr in
       (match typed_arr.texpr_type with
        | Array (element_type, _) ->
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = element_type; texpr_pos = pos }
        | Pointer element_type ->
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = element_type; texpr_pos = pos }
        | Str _ ->
            (* String indexing returns char *)
            { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = Char; texpr_pos = pos }
        | Map (key_type, value_type, _, _) ->
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
   | Identifier module_name when Hashtbl.mem ctx.imports module_name ->
       (* This is a module function access - handle it as a special module field access *)
       let resolved_import = Hashtbl.find ctx.imports module_name in
               (match resolved_import.source_type with
         | KernelScript ->
             (* Find the function in the imported module *)
             (match Import_resolver.find_kernelscript_symbol resolved_import field with
              | None ->
                  type_error (Printf.sprintf "Function '%s' not found in module '%s'" field module_name) pos
              | Some symbol ->
                  (* Return the function type so it can be called *)
                  { texpr_desc = TIdentifier (module_name ^ "." ^ field); 
                    texpr_type = symbol.symbol_type; 
                    texpr_pos = pos })
         | Python ->
             (* Python modules - return generic function type *)
             { texpr_desc = TIdentifier (module_name ^ "." ^ field); 
               texpr_type = Function ([], U64); (* Generic signature for Python *)
               texpr_pos = pos })
   | Identifier var_name when Hashtbl.mem ctx.variables var_name ->
       (* Check if this is a ring buffer variable *)
       let var_type = Hashtbl.find ctx.variables var_name in
       let resolved_var_type = resolve_user_type ctx var_type in
       (match resolved_var_type with
        | Ringbuf (value_type, _) ->
            (* Ring buffer object operations *)
            (match field with
             | "reserve" ->
                 (* reserve() returns a pointer to the value type *)
                 { texpr_desc = TFieldAccess (type_check_expression ctx obj, field); texpr_type = Pointer value_type; texpr_pos = pos }
             | "submit" | "discard" ->
                 (* submit() and discard() return i32 (success code) *)
                 { texpr_desc = TFieldAccess (type_check_expression ctx obj, field); texpr_type = I32; texpr_pos = pos }
             | "on_event" ->
                 (* on_event() returns i32 (success code) *)
                 { texpr_desc = TFieldAccess (type_check_expression ctx obj, field); texpr_type = I32; texpr_pos = pos }
             | _ ->
                 type_error ("Ring buffer operation '" ^ field ^ "' not supported. Valid operations: reserve, submit, discard, on_event") pos)
        | _ ->
            (* Not a ring buffer, fall through to regular field access *)
            let typed_obj = type_check_expression ctx obj in
            (* Continue to regular struct field access handling below *)
            (match typed_obj.texpr_type with
             | Struct struct_name | UserType struct_name ->
                 (* Look up struct definition and field type *)
                 (try
                    let type_def = Hashtbl.find ctx.types struct_name in
                    match type_def with
                    | StructDef (_, fields, _) ->
                        (try
                           let field_type = List.assoc field fields in
                           { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = field_type; texpr_pos = pos }
                         with Not_found ->
                           type_error ("Field not found: " ^ field ^ " in struct " ^ struct_name) pos)
                    | _ ->
                        type_error (struct_name ^ " is not a struct") pos
                  with Not_found ->
                    type_error ("Undefined struct: " ^ struct_name) pos)
             | _ -> 
                 type_error "Cannot access field of non-struct type" pos))
   | _ ->
       (* Regular field access - process normally *)
       let typed_obj = type_check_expression ctx obj in
       
       match typed_obj.texpr_type with
  | Ringbuf (value_type, _) ->
      (* Ring buffer object operations *)
      (match field with
       | "reserve" ->
           (* reserve() returns a pointer to the value type *)
           { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = Pointer value_type; texpr_pos = pos }
       | "submit" | "discard" ->
           (* submit() and discard() return i32 (success code) *)
           { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = I32; texpr_pos = pos }
       | "on_event" ->
           (* on_event() returns i32 (success code) *)
           { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = I32; texpr_pos = pos }
       | _ ->
           type_error ("Ring buffer operation '" ^ field ^ "' not supported. Valid operations: reserve, submit, discard, on_event") pos)
  | RingbufRef _value_type ->
      (* Ring buffer reference for dispatch() - limited operations *)
      (match field with
       | _ ->
           type_error ("Ring buffer references can only be used with dispatch(), not with method calls") pos)
  | Struct struct_name | UserType struct_name ->
      (* Look up struct definition and field type *)
      (try
                 let type_def = Hashtbl.find ctx.types struct_name in
        match type_def with
        | StructDef (_, fields, _) ->
             (try
                let field_type = List.assoc field fields in
                { texpr_desc = TFieldAccess (typed_obj, field); texpr_type = field_type; texpr_pos = pos }
              with Not_found ->
                type_error ("Field not found: " ^ field ^ " in struct " ^ struct_name) pos)
         | _ ->
             type_error (struct_name ^ " is not a struct") pos
       with Not_found ->
         type_error ("Undefined struct: " ^ struct_name) pos)
  | _ ->
      type_error "Cannot access field of non-struct type" pos)

(** Type check arrow access (pointer->field) *)
and type_check_arrow_access ctx obj field pos =
  let typed_obj = type_check_expression ctx obj in
  
  (* Extract struct name from pointer type uniformly *)
  let struct_name = match typed_obj.texpr_type with
    | Pointer (Struct name) | Pointer (UserType name) -> name
    (* Map context types to their corresponding struct names *)
    | Pointer Xdp_md -> "xdp_md"
    | _ -> 
        type_error ("Arrow access requires pointer-to-struct type, got " ^ string_of_bpf_type typed_obj.texpr_type) pos
  in
  
  (* Use context codegen as authoritative source for context struct fields *)
  let is_context_struct = match struct_name with
    | "xdp_md" | "__sk_buff" -> true
    | _ -> false
  in
  
  if is_context_struct then
    (* Use context codegen to get the correct field type *)
    let ctx_type_str = match struct_name with
      | "xdp_md" -> "xdp"
      | "__sk_buff" -> "tc"
      | _ -> failwith ("Unknown context struct: " ^ struct_name)
    in
    (match Kernelscript_context.Context_codegen.get_context_field_c_type ctx_type_str field with
     | Some c_type ->
         (* Convert C type to AST type for consistency with type checker *)
         let ast_field_type = match c_type with
           | "__u8*" | "void*" -> Pointer U8
           | "__u16*" -> Pointer U16 
           | "__u32*" -> Pointer U32
           | "__u64*" -> Pointer U64
           | "__u8" -> U8
           | "__u16" -> U16
           | "__u32" -> U32
           | "__u64" -> U64
           | _ -> failwith ("Unsupported context field C type: " ^ c_type)
         in
         { texpr_desc = TArrowAccess (typed_obj, field); texpr_type = ast_field_type; texpr_pos = pos }
     | None ->
         type_error ("Unknown context field: " ^ field ^ " for context type: " ^ ctx_type_str) pos)
  else
    (* Use regular struct field lookup for non-context types *)
    (try
             let type_def = Hashtbl.find ctx.types struct_name in
      match type_def with
      | StructDef (_, fields, _) ->
           (try
              let field_type = List.assoc field fields in
              { texpr_desc = TArrowAccess (typed_obj, field); texpr_type = field_type; texpr_pos = pos }
            with Not_found ->
              type_error ("Field not found: " ^ field ^ " in struct " ^ struct_name) pos)
       | _ ->
           type_error (struct_name ^ " is not a struct") pos
     with Not_found ->
       type_error ("Undefined struct: " ^ struct_name) pos)

(** Type check binary operation *)
and type_check_binary_op ctx left op right pos =
  let typed_left = type_check_expression ctx left in
  let typed_right = type_check_expression ctx right in
  
  (* Resolve user types for both operands *)
  let resolved_left_type = resolve_user_type ctx typed_left.texpr_type in
  let resolved_right_type = resolve_user_type ctx typed_right.texpr_type in
  

  
  let effective_left_type = resolved_left_type in
  let effective_right_type = resolved_right_type in
  
  let result_type = match op with
    (* Arithmetic operations *)
    | Add ->
        (* Handle string concatenation *)
        (match effective_left_type, effective_right_type with
         | Str size1, Str size2 -> 
             (* String concatenation - we'll allow it and require explicit result sizing *)
             (* For now, return a placeholder size that will be refined by assignment context *)
             Str (size1 + size2)
         | _ ->
             (* Continue with regular arithmetic/pointer handling *)
             (match effective_left_type, effective_right_type with
              (* Pointer + Integer = Pointer (pointer offset) *)
              | Pointer t, (U8|U16|U32|U64|I8|I16|I32|I64) -> Pointer t
              (* Integer + Pointer = Pointer (pointer offset) *)
              | (U8|U16|U32|U64|I8|I16|I32|I64), Pointer t -> Pointer t
              (* Regular numeric arithmetic *)
              | _ ->
                  (* Try integer promotion for Add operations *)
                  (match integer_promotion effective_left_type effective_right_type with
                   | Some unified_type ->
                       (match unified_type with
                        | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 -> unified_type
                        | _ -> type_error "Arithmetic operations require numeric types" pos)
                   | None -> type_error "Cannot unify types for arithmetic operation" pos)))
    
    | Sub | Mul | Div | Mod ->
        (* Handle pointer arithmetic for subtraction *)
        (match effective_left_type, effective_right_type, op with
         (* Pointer - Pointer = size (pointer subtraction) *)
         | Pointer _, Pointer _, Sub -> U64  (* Return size type for pointer difference *)
         (* Pointer - Integer = Pointer (pointer offset) *)
         | Pointer t, (U8|U16|U32|U64|I8|I16|I32|I64), Sub -> Pointer t
         (* Regular numeric arithmetic *)
         | _ ->
             (* Try integer promotion for Sub/Mul/Div/Mod operations *)
             (match integer_promotion effective_left_type effective_right_type with
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
         | Null, _ | _, Null -> Bool  (* Direct null comparisons *)
         | _, Pointer _ | Pointer _, _ -> Bool  (* Pointer comparisons (legacy) *)
         (* None comparisons - allow with map access expressions or variables that could contain map results *)
         | NoneType, _ | _, NoneType -> 
             (* Check if at least one operand is a map access or could reasonably be a map result *)
             let has_map_related_value = 
               (match left.expr_desc with
                | ArrayAccess (map_expr, _) -> 
                    (match map_expr.expr_desc with
                     | Identifier map_name -> Hashtbl.mem ctx.maps map_name
                     | _ -> false)
                | Identifier _ -> true  (* Variables can contain map lookup results *)
                | _ -> false) ||
               (match right.expr_desc with
                | ArrayAccess (map_expr, _) -> 
                    (match map_expr.expr_desc with
                     | Identifier map_name -> Hashtbl.mem ctx.maps map_name
                     | _ -> false)
                | Identifier _ -> true  (* Variables can contain map lookup results *)
                | _ -> false)
             in
             if has_map_related_value then
               Bool
             else
               type_error "'none' can only be compared with map access expressions or variables that may contain map results" pos
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
    
    | Deref ->
        (match typed_expr.texpr_type with
         | Pointer t -> t  (* Dereference pointer to get underlying type *)
         | _ -> type_error "Dereference requires pointer type" pos)
    
    | AddressOf ->
        (* Address-of operation creates a pointer to the operand type *)
        (* Resolve user types to ensure proper unification *)
        let resolved_type = resolve_user_type ctx typed_expr.texpr_type in
        Pointer resolved_type
  in
  
  { texpr_desc = TUnaryOp (op, typed_expr); texpr_type = result_type; texpr_pos = pos }

(** Type check struct literal *)
and type_check_struct_literal ctx struct_name field_assignments pos =
  (* Look up the struct definition *)
  try
    let type_def = Hashtbl.find ctx.types struct_name in
    match type_def with
    | StructDef (_, struct_fields, _) ->
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
  | Call (callee_expr, args) ->
      (* Type check arguments first *)
      let typed_args = List.map (type_check_expression ctx) args in
      let arg_types = List.map (fun e -> e.texpr_type) typed_args in
      
      (* Try different call types in order of priority *)
      (match callee_expr.expr_desc with
       | Identifier name ->

           (* Try builtin -> user function -> function pointer variable *)
           (match type_check_builtin_call ctx name typed_args arg_types expr.expr_pos with
            | Some result -> 
                validate_void_in_expression result.texpr_type name ctx.expr_context expr.expr_pos;
                result
            | None ->
                (match type_check_user_function_call ctx name typed_args arg_types expr.expr_pos with
                 | Some result -> 
                     validate_void_in_expression result.texpr_type name ctx.expr_context expr.expr_pos;
                     result
                 | None ->
                     (match type_check_function_pointer_variable ctx name typed_args arg_types expr.expr_pos with
                      | Some result -> 
                          validate_void_in_expression result.texpr_type name ctx.expr_context expr.expr_pos;
                          result
                      | None -> type_error ("Undefined function: " ^ name) expr.expr_pos)))
                      
       | FieldAccess ({expr_desc = Identifier var_name; _}, method_name) 
         when Hashtbl.mem ctx.variables var_name ->
           (* Check if this is a ring buffer method call *)
           let var_type = Hashtbl.find ctx.variables var_name in
           let resolved_var_type = resolve_user_type ctx var_type in
           (match resolved_var_type with
            | Ringbuf (value_type, _) ->
                (* Handle ring buffer method calls *)
                (match method_name with
                 | "reserve" ->
                     (* reserve() takes no arguments and returns pointer to value type *)
                     if List.length typed_args = 0 then
                       { texpr_desc = TCall (type_check_expression ctx callee_expr, typed_args); 
                         texpr_type = Pointer value_type; texpr_pos = expr.expr_pos }
                     else
                       type_error ("reserve() takes no arguments") expr.expr_pos
                 | "submit" | "discard" ->
                     (* submit(ptr) and discard(ptr) take one pointer argument and return i32 *)
                     if List.length typed_args = 1 then
                       let expected_ptr_type = Pointer value_type in
                       (match unify_types expected_ptr_type (List.hd typed_args).texpr_type with
                        | Some _ ->
                            { texpr_desc = TCall (type_check_expression ctx callee_expr, typed_args); 
                              texpr_type = I32; texpr_pos = expr.expr_pos }
                        | None ->
                            type_error ("Type mismatch: expected pointer to " ^ (string_of_bpf_type value_type)) expr.expr_pos)
                     else
                       type_error (method_name ^ "() takes exactly one argument") expr.expr_pos
                 | "on_event" ->
                     (* on_event(handler) takes one function argument and returns i32 *)
                     if List.length typed_args = 1 then
                       let handler_arg = List.hd typed_args in
                       (match handler_arg.texpr_type with
                        | Function ([expected_param_type], I32) ->
                            let resolved_value_type = resolve_user_type ctx value_type in
                            let expected_handler_param = Pointer resolved_value_type in
                            (match unify_types expected_handler_param expected_param_type with
                             | Some _ ->
                                 { texpr_desc = TCall (type_check_expression ctx callee_expr, typed_args); 
                                   texpr_type = I32; texpr_pos = expr.expr_pos }
                             | None ->
                                 type_error ("on_event() handler must have signature fn(event: *" ^ (string_of_bpf_type resolved_value_type) ^ ") -> i32") expr.expr_pos)
                        | _ ->
                            type_error ("on_event() handler must have signature fn(event: *" ^ (string_of_bpf_type value_type) ^ ") -> i32") expr.expr_pos)
                     else
                       type_error ("on_event() takes exactly one argument") expr.expr_pos
                 | _ ->
                     type_error ("Unknown ring buffer operation: " ^ method_name) expr.expr_pos)
            | _ ->
                (* Not a ring buffer, fall through to regular function pointer handling *)
                let typed_callee = type_check_expression ctx callee_expr in
                type_check_function_pointer_call ctx typed_callee typed_args arg_types expr.expr_pos)
       | _ ->
           (* Complex expression - must be function pointer, type check the callee *)
           let typed_callee = type_check_expression ctx callee_expr in
           type_check_function_pointer_call ctx typed_callee typed_args arg_types expr.expr_pos)

  | ArrayAccess (arr, idx) -> type_check_array_access ctx arr idx expr.expr_pos
  | FieldAccess (obj, field) -> type_check_field_access ctx obj field expr.expr_pos
  | ArrowAccess (obj, field) -> 
      (* Arrow access (pointer->field) - for pointer-to-struct access *)
      type_check_arrow_access ctx obj field expr.expr_pos
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
            let typed_name = { texpr_desc = TIdentifier name; texpr_type = Function (expected_params, return_type); texpr_pos = expr.expr_pos } in
            { texpr_desc = TCall (typed_name, typed_args); texpr_type = return_type; texpr_pos = expr.expr_pos }
          else
            type_error ("Type mismatch in tail call: " ^ name) expr.expr_pos
        else
          type_error ("Wrong number of arguments for tail call: " ^ name) expr.expr_pos
      with Not_found ->
        type_error ("Undefined tail call target: " ^ name) expr.expr_pos)
        
  | ModuleCall call ->
      (* Simplified module call type checking *)
      (match Hashtbl.find_opt ctx.imports call.module_name with
       | None ->
           type_error ("Unknown module: " ^ call.module_name) expr.expr_pos
       | Some resolved_import ->
                       (match resolved_import.source_type with
             | KernelScript ->
                 (* For KernelScript modules, we can do static type checking *)
                 (match Import_resolver.find_kernelscript_symbol resolved_import call.function_name with
                  | None ->
                      type_error ("Function not found in module " ^ call.module_name ^ ": " ^ call.function_name) expr.expr_pos
                  | Some symbol ->
                      (* Extract actual function signature and validate call *)
                                             (match symbol.symbol_type with
                        | Function (param_types, return_type) ->
                            (* Validate argument count *)
                            if List.length call.args <> List.length param_types then
                              type_error (Printf.sprintf "Wrong number of arguments in call to %s.%s: expected %d, got %d"
                                call.module_name call.function_name 
                                (List.length param_types) (List.length call.args)) expr.expr_pos;
                            
                            (* Type check arguments against expected parameters *)
                            let typed_args = List.map2 (fun arg expected_type ->
                              let typed_arg = type_check_expression ctx arg in
                              let resolved_expected = resolve_user_type ctx expected_type in
                              let resolved_actual = resolve_user_type ctx typed_arg.texpr_type in
                              if resolved_expected <> resolved_actual then
                                type_error (Printf.sprintf "Argument type mismatch in call to %s.%s: expected %s, got %s"
                                  call.module_name call.function_name 
                                  (Ast.string_of_bpf_type expected_type) 
                                  (Ast.string_of_bpf_type typed_arg.texpr_type)) arg.expr_pos;
                              typed_arg
                            ) call.args param_types in
                           
                           (* Return the actual return type from the function signature *)
                           { texpr_desc = TCall (
                               { texpr_desc = TIdentifier (call.module_name ^ "." ^ call.function_name);
                                 texpr_type = symbol.symbol_type;
                                 texpr_pos = expr.expr_pos },
                               typed_args);
                             texpr_type = return_type; (* Use actual return type! *)
                             texpr_pos = expr.expr_pos }
                       | _ ->
                           type_error ("Symbol " ^ call.function_name ^ " in module " ^ call.module_name ^ " is not a function") expr.expr_pos))
             | Python ->
                 (* For Python modules, all calls are dynamic - just validate module exists *)
                 (match Import_resolver.validate_python_module_import resolved_import with
                  | Error msg -> type_error msg expr.expr_pos
                  | Ok _ ->
                      (* Python calls are dynamic - return generic type *)
                      { texpr_desc = TCall (
                          { texpr_desc = TIdentifier (call.module_name ^ "." ^ call.function_name);
                            texpr_type = Function ([], U64); (* Generic signature *)
                            texpr_pos = expr.expr_pos },
                          []);
                        texpr_type = U64; (* Generic return type *)
                        texpr_pos = expr.expr_pos })))
        
  | Match (matched_expr, arms) ->
      (* Type check the matched expression *)
      let typed_matched_expr = type_check_expression ctx matched_expr in
      
      (* Type check all arms and ensure they have compatible types *)
      let typed_arms = List.map (fun arm ->
        (* Type check the arm body - can be either expression or statement block *)
        let typed_arm_body = match arm.arm_body with
          | SingleExpr expr ->
              let typed_expr = type_check_expression ctx expr in
              TSingleExpr typed_expr
          | Block stmts ->
              let typed_stmts = List.map (type_check_statement ctx) stmts in
              TBlock typed_stmts
        in
        
        (* Validate the pattern *)
        (match arm.arm_pattern with
         | ConstantPattern lit ->
             (* Check that the pattern literal type is compatible with matched expression type *)
             let pattern_type = type_of_literal lit in
             (match unify_types typed_matched_expr.texpr_type pattern_type with
              | Some _ -> () (* Compatible *)
              | None -> 
                  type_error ("Pattern type " ^ string_of_bpf_type pattern_type ^ 
                             " is not compatible with matched expression type " ^ 
                             string_of_bpf_type typed_matched_expr.texpr_type) arm.arm_pos)
         | IdentifierPattern name ->
             (* Check that the identifier exists and is compatible with matched expression type *)
             (match type_check_identifier ctx name arm.arm_pos with
              | texpr when (match unify_types typed_matched_expr.texpr_type texpr.texpr_type with
                           | Some _ -> true | None -> false) -> ()
              | texpr -> 
                  type_error ("Pattern identifier " ^ name ^ " of type " ^ string_of_bpf_type texpr.texpr_type ^ 
                             " is not compatible with matched expression type " ^ 
                             string_of_bpf_type typed_matched_expr.texpr_type) arm.arm_pos)
         | DefaultPattern -> () (* Default pattern is always valid *)
        );
        
        (* Return typed arm *)
        { tarm_pattern = arm.arm_pattern; tarm_body = typed_arm_body; tarm_pos = arm.arm_pos }
      ) arms in
      
      (* Determine the result type - all arms must have compatible types *)
      let result_type = match typed_arms with
        | [] -> type_error "Match expression must have at least one arm" expr.expr_pos
        | first_arm :: rest_arms ->
            let first_type = match first_arm.tarm_body with
              | TSingleExpr expr -> expr.texpr_type
              | TBlock stmts -> 
                  extract_block_return_type stmts first_arm.tarm_pos
            in
            List.iter (fun arm ->
              let arm_type = match arm.tarm_body with
                | TSingleExpr expr -> expr.texpr_type
                | TBlock stmts -> 
                    extract_block_return_type stmts arm.tarm_pos
              in
              match unify_types first_type arm_type with
              | Some _ -> () (* Compatible *)
              | None -> 
                  type_error ("All match arms must return compatible types. Expected " ^ 
                             string_of_bpf_type first_type ^ " but got " ^ 
                             string_of_bpf_type arm_type) arm.tarm_pos
            ) rest_arms;
            first_type
      in
      
      { texpr_desc = TMatch (typed_matched_expr, typed_arms); texpr_type = result_type; texpr_pos = expr.expr_pos }

  | New typ ->
      (* Type check object allocation *)
      let resolved_type = resolve_user_type ctx typ in
      (* The new expression returns a pointer to the allocated type *)
      let pointer_type = Pointer resolved_type in
      { texpr_desc = TNew resolved_type; texpr_type = pointer_type; texpr_pos = expr.expr_pos }

  | NewWithFlag (typ, flag_expr) ->
      (* Type check object allocation with GFP flag - only valid in kernel context *)
      
      (* First, validate execution context *)
      (* Check if we're in an eBPF program first (indicated by current_program_type being set) *)
      (match ctx.current_program_type with
       | Some _ -> 
           (* We're in an eBPF program context *)
           type_error "GFP allocation flags can only be used in @kfunc functions (kernel context), not in eBPF programs" expr.expr_pos
       | None ->
           (* Not in eBPF, check function scope *)
           let current_scope = match ctx.current_function with
             | Some func_name ->
                 (try Some (Hashtbl.find ctx.function_scopes func_name)
                  with Not_found -> Some Ast.Userspace)
             | None -> Some Ast.Userspace
           in
           
           (match current_scope with
            | Some Ast.Kernel -> 
                (* Valid context - continue with type checking *)
                ()
            | Some Ast.Userspace -> 
                type_error "GFP allocation flags can only be used in @kfunc functions (kernel context), not in userspace" expr.expr_pos
            | None -> 
                (* This shouldn't happen now that we check program_type first *)
                type_error "GFP allocation flags can only be used in @kfunc functions (kernel context)" expr.expr_pos));
      
      (* Type check the flag expression *)
      let typed_flag_expr = type_check_expression ctx flag_expr in
      
      (* Validate that flag expression is of type gfp_flag *)
      let resolved_flag_type = resolve_user_type ctx typed_flag_expr.texpr_type in
      (match resolved_flag_type with
       | Enum "gfp_flag" -> 
           (* Valid GFP flag *)
           ()
       | _ -> 
           type_error ("GFP allocation flag must be of type gfp_flag, got " ^ string_of_bpf_type resolved_flag_type) expr.expr_pos);
      
      (* Type check the allocated type *)
      let resolved_type = resolve_user_type ctx typ in
      let pointer_type = Pointer resolved_type in
      { texpr_desc = TNewWithFlag (resolved_type, typed_flag_expr); texpr_type = pointer_type; texpr_pos = expr.expr_pos }

(** Type check statement *)
and type_check_statement ctx stmt =
  match stmt.stmt_desc with
  | ExprStmt expr ->
      let old_context = ctx.expr_context in
      ctx.expr_context <- Statement; (* Allow void functions in statement context *)
      let typed_expr = type_check_expression ctx expr in
      ctx.expr_context <- old_context; (* Restore previous context *)
      { tstmt_desc = TExprStmt typed_expr; tstmt_pos = stmt.stmt_pos }
  
    | Assignment (name, expr) ->
      let typed_expr = type_check_expression ctx expr in
      (* Check if trying to assign none to a variable *)
      (match typed_expr.texpr_type with
       | NoneType -> type_error ("'none' cannot be assigned to variables. It can only be used in comparisons with map lookup results.") stmt.stmt_pos
       | _ -> ());
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
  
  | CompoundAssignment (name, op, expr) ->
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
              (* For compound assignment, both operands must be the same type *)
              (match unify_types resolved_var_type resolved_expr_type with
               | Some _ ->
                   (* Check if operator is valid for this type *)
                   (match op, resolved_var_type with
                    | (Add | Sub | Mul | Div | Mod), (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64) ->
                        { tstmt_desc = TCompoundAssignment (name, op, typed_expr); tstmt_pos = stmt.stmt_pos }
                    | _, _ ->
                        type_error ("Operator " ^ string_of_binary_op op ^ 
                                   " not supported for type " ^ string_of_bpf_type resolved_var_type) stmt.stmt_pos)
               | None ->
                   type_error ("Cannot apply " ^ string_of_binary_op op ^ 
                              " between " ^ string_of_bpf_type resolved_var_type ^ 
                              " and " ^ string_of_bpf_type resolved_expr_type) stmt.stmt_pos)
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
                  | StructDef (_, fields, _) ->
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
  
  | ArrowAssignment (obj_expr, field, value_expr) ->
      (* Arrow assignment (pointer->field = value) - similar to field assignment but for pointers *)
      let typed_value = type_check_expression ctx value_expr in
      let typed_obj = type_check_expression ctx obj_expr in
      
      (* Check if this is pointer field assignment *)
      (match typed_obj.texpr_type with
       | Pointer (Struct struct_name) | Pointer (UserType struct_name) ->
           (* Look up struct definition and field type *)
           (try
              let type_def = Hashtbl.find ctx.types struct_name in
              match type_def with
              | StructDef (_, fields, _) ->
                  (try
                     let field_type = List.assoc field fields in
                     let resolved_field_type = resolve_user_type ctx field_type in
                     let resolved_value_type = resolve_user_type ctx typed_value.texpr_type in
                     (* Check if the value type is compatible with the field type *)
                     (match unify_types resolved_field_type resolved_value_type with
                      | Some _ ->
                          { tstmt_desc = TArrowAssignment (typed_obj, field, typed_value); tstmt_pos = stmt.stmt_pos }
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
           type_error ("Arrow assignment can only be used on pointer-to-struct types") stmt.stmt_pos)
  
  | IndexAssignment (map_expr, key_expr, value_expr) ->
      let typed_key = type_check_expression ctx key_expr in
      let typed_value = type_check_expression ctx value_expr in
      
      (* Check if this is map assignment *)
      (match map_expr.expr_desc with
       | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           (* This is map assignment *)
           let map_decl = Hashtbl.find ctx.maps map_name in
           (* Check key type compatibility *)
           let resolved_key_type = resolve_user_type ctx map_decl.ast_key_type in
           let resolved_typed_key_type = resolve_user_type ctx typed_key.texpr_type in
           (match unify_types resolved_key_type resolved_typed_key_type with
            | Some _ -> ()
            | None -> type_error ("Map key type mismatch") stmt.stmt_pos);
           (* Check value type compatibility *)
           let resolved_value_type = resolve_user_type ctx map_decl.ast_value_type in
           let resolved_typed_value_type = resolve_user_type ctx typed_value.texpr_type in
           (match unify_types resolved_value_type resolved_typed_value_type with
            | Some _ -> ()
            | None -> type_error ("Map value type mismatch") stmt.stmt_pos);
           (* Create a synthetic map type for the result *)
           let typed_map = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.ast_key_type, map_decl.ast_value_type, map_decl.ast_map_type, map_decl.max_entries); texpr_pos = map_expr.expr_pos } in
           { tstmt_desc = TIndexAssignment (typed_map, typed_key, typed_value); tstmt_pos = stmt.stmt_pos }
       | _ ->
           (* Regular index assignment (arrays, etc.) *)
           let typed_map = type_check_expression ctx map_expr in
           (match typed_map.texpr_type with
            | Map (key_type, value_type, _, _) ->
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
  
  | CompoundIndexAssignment (map_expr, key_expr, op, value_expr) ->
      let typed_key = type_check_expression ctx key_expr in
      let typed_value = type_check_expression ctx value_expr in
      
      (* Check if this is map compound assignment *)
      (match map_expr.expr_desc with
       | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           (* This is map compound assignment *)
           let map_decl = Hashtbl.find ctx.maps map_name in
           (* Check key type compatibility *)
           let resolved_key_type = resolve_user_type ctx map_decl.ast_key_type in
           let resolved_typed_key_type = resolve_user_type ctx typed_key.texpr_type in
           (match unify_types resolved_key_type resolved_typed_key_type with
            | Some _ -> ()
            | None -> type_error ("Map key type mismatch") stmt.stmt_pos);
           (* Check value type compatibility and operator validity *)
           let resolved_value_type = resolve_user_type ctx map_decl.ast_value_type in
           let resolved_typed_value_type = resolve_user_type ctx typed_value.texpr_type in
           (match unify_types resolved_value_type resolved_typed_value_type with
            | Some _ -> ()
            | None -> type_error ("Map value type mismatch") stmt.stmt_pos);
           (* Check if operator is valid for the value type *)
           (match op, resolved_value_type with
            | (Add | Sub | Mul | Div | Mod), (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64) ->
                (* Create a synthetic map type for the result *)
                let typed_map = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.ast_key_type, map_decl.ast_value_type, map_decl.ast_map_type, map_decl.max_entries); texpr_pos = map_expr.expr_pos } in
                { tstmt_desc = TCompoundIndexAssignment (typed_map, typed_key, op, typed_value); tstmt_pos = stmt.stmt_pos }
            | _, _ ->
                type_error ("Operator " ^ string_of_binary_op op ^ 
                           " not supported for type " ^ string_of_bpf_type resolved_value_type) stmt.stmt_pos)
       | _ ->
           (* Regular compound index assignment (arrays, etc.) *)
           let typed_map = type_check_expression ctx map_expr in
           (match typed_map.texpr_type with
            | Map (key_type, value_type, _, _) ->
                (* This shouldn't happen anymore, but handle it for safety *)
                (match unify_types key_type typed_key.texpr_type with
                 | Some _ -> ()
                 | None -> type_error ("Map key type mismatch") stmt.stmt_pos);
                (match unify_types value_type typed_value.texpr_type with
                 | Some _ -> ()
                 | None -> type_error ("Map value type mismatch") stmt.stmt_pos);
                (* Check if operator is valid for the value type *)
                (match op, value_type with
                 | (Add | Sub | Mul | Div | Mod), (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64) ->
                     { tstmt_desc = TCompoundIndexAssignment (typed_map, typed_key, op, typed_value); tstmt_pos = stmt.stmt_pos }
                 | _, _ ->
                     type_error ("Operator " ^ string_of_binary_op op ^ 
                                " not supported for type " ^ string_of_bpf_type value_type) stmt.stmt_pos)
            | Array (element_type, _) ->
                (* Array element compound assignment *)
                (match unify_types element_type typed_value.texpr_type with
                 | Some _ -> ()
                 | None -> type_error ("Array element type mismatch") stmt.stmt_pos);
                (* Check if operator is valid for the element type *)
                (match op, element_type with
                 | (Add | Sub | Mul | Div | Mod), (U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64) ->
                     { tstmt_desc = TCompoundIndexAssignment (typed_map, typed_key, op, typed_value); tstmt_pos = stmt.stmt_pos }
                 | _, _ ->
                     type_error ("Operator " ^ string_of_binary_op op ^ 
                                " not supported for type " ^ string_of_bpf_type element_type) stmt.stmt_pos)
            | _ -> type_error ("Compound index assignment can only be used on maps or arrays") stmt.stmt_pos))
  
  | Declaration (name, type_opt, expr_opt) ->
      let typed_expr_opt = Option.map (type_check_expression ctx) expr_opt in
      
      (* Check if trying to assign a map to a variable *)
      (match typed_expr_opt with
       | Some typed_expr when (match typed_expr.texpr_type with Map (_, _, _, _) -> true | _ -> false) ->
           type_error ("Maps cannot be assigned to variables") stmt.stmt_pos
       | _ -> ());
      
      (* Check if trying to assign none to a variable *)
      (match typed_expr_opt with
       | Some typed_expr when (match typed_expr.texpr_type with NoneType -> true | _ -> false) ->
           type_error ("'none' cannot be assigned to variables. It can only be used in comparisons with map lookup results.") stmt.stmt_pos
       | _ -> ());
      
      let var_type = match type_opt with
        | Some declared_type ->
            let resolved_declared_type = resolve_user_type ctx declared_type in
            (* Validate ring buffer objects *)
            validate_ringbuf_object ctx name resolved_declared_type stmt.stmt_pos;
            (* For variable declarations, we should enforce the declared type *)
            (* and check if the expression type can be assigned to it *)
            (match typed_expr_opt with
             | Some typed_expr ->
                 if can_assign resolved_declared_type typed_expr.texpr_type then
                   resolved_declared_type  (* Use the declared type, not the unified type *)
                 else
                   type_error ("Type mismatch in declaration") stmt.stmt_pos
             | None -> resolved_declared_type) (* No initializer, just use declared type *)
        | None -> 
            (match typed_expr_opt with
             | Some typed_expr -> 
                 (* Validate ring buffer objects *)
                 validate_ringbuf_object ctx name typed_expr.texpr_type stmt.stmt_pos;
                 typed_expr.texpr_type
             | None -> type_error ("Variable declaration must have either a type annotation or an initializer") stmt.stmt_pos)
      in
      Hashtbl.replace ctx.variables name var_type;
      { tstmt_desc = TDeclaration (name, var_type, typed_expr_opt); tstmt_pos = stmt.stmt_pos }
  
  | ConstDeclaration (name, type_opt, expr) ->
      let typed_expr = type_check_expression ctx expr in
      
      (* Check if trying to assign a map to a const *)
      (match typed_expr.texpr_type with
       | Map (_, _, _, _) -> type_error ("Maps cannot be assigned to const variables") stmt.stmt_pos
       | _ -> ());
      
      (* Check if trying to assign none to a const *)
      (match typed_expr.texpr_type with
       | NoneType -> type_error ("'none' cannot be assigned to variables. It can only be used in comparisons with map lookup results.") stmt.stmt_pos
       | _ -> ());
      
      (* Validate that the expression is a compile-time constant (literals and negated literals) *)
      let const_value = match typed_expr.texpr_desc with
        | TLiteral lit -> lit
        | TUnaryOp (Neg, {texpr_desc = TLiteral (IntLit (n, Some sign)); _}) -> 
            IntLit (Ast.Signed64 (Int64.neg (Ast.IntegerValue.to_int64 n)), Some sign)  (* Negated signed integer literal *)
        | TUnaryOp (Neg, {texpr_desc = TLiteral (IntLit (n, None)); _}) -> 
            IntLit (Ast.Signed64 (Int64.neg (Ast.IntegerValue.to_int64 n)), None)  (* Negated integer literal *)
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
                   | Call (callee_expr, _) ->
                       (* Check if this is a direct call to an attributed function *)
                       (match callee_expr.expr_desc with
                        | Identifier name when Hashtbl.mem ctx.attributed_functions name && not ctx.in_match_return_context ->
                            (* This check already excludes kfuncs since they're not in attributed_functions *)
                            type_error ("Attributed function '" ^ name ^ "' cannot be called directly. Use return " ^ name ^ "(...) for tail calls.") expr.expr_pos
                        | _ ->
                            Some (type_check_expression ctx expr))
                   | Match (_, _) ->
                       (* For match expressions in return position, set the flag and type check normally *)
                       let ctx_with_match_return = { ctx with in_match_return_context = true } in
                       Some (type_check_expression ctx_with_match_return expr)
                   | _ ->
                       Some (type_check_expression ctx expr)))
        | None -> 
            (* Naked return - check if we have a named return variable *)
            (match ctx.current_function with
             | Some func_name ->
                 (* Find the function definition to check for named return *)
                 let has_named_return = ref false in
                 let named_return_var = ref None in
                 let ast_context = ctx.ast_context in
                 List.iter (function
                   | GlobalFunction func when func.func_name = func_name ->
                       (match get_return_variable_name func.func_return_type with
                        | Some var_name -> 
                            has_named_return := true;
                            named_return_var := Some var_name
                        | None -> ())
                   | AttributedFunction attr_func when attr_func.attr_function.func_name = func_name ->
                       (match get_return_variable_name attr_func.attr_function.func_return_type with
                        | Some var_name -> 
                            has_named_return := true;
                            named_return_var := Some var_name
                        | None -> ())
                   | _ -> ()
                 ) ast_context;
                 if !has_named_return then
                   (* Create an identifier expression for the named return variable *)
                   match !named_return_var with
                   | Some var_name ->
                       (* Properly resolve the named return variable type from the function definition *)
                       let return_type = (match ctx.current_function with
                         | Some func_name ->
                             (* Find the function definition to get the return type *)
                             let found_return_type = ref None in
                             List.iter (function
                               | GlobalFunction func when func.func_name = func_name ->
                                   found_return_type := get_return_type func.func_return_type
                               | AttributedFunction attr_func when attr_func.attr_function.func_name = func_name ->
                                   found_return_type := get_return_type attr_func.attr_function.func_return_type
                               | _ -> ()
                             ) ctx.ast_context;
                             !found_return_type
                         | None -> None) in
                       let var_expr = { 
                         expr_desc = Identifier var_name; 
                         expr_pos = stmt.stmt_pos; 
                         expr_type = return_type;  (* Provide proper type information *)
                         type_checked = false; 
                         program_context = None; 
                         map_scope = None 
                       } in
                       Some (type_check_expression ctx var_expr)
                   | None -> None
                 else
                   None
             | None -> None)
      in
      
      (* Elegant return validation: check compatibility with current function *)
      (match ctx.current_function with
       | Some func_name ->
           (try
             let (_, return_type) = Hashtbl.find ctx.functions func_name in
             let resolved_return_type = resolve_user_type ctx return_type in
             (match typed_expr_opt, resolved_return_type with
              | Some _, Void -> 
                  type_error ("Void function '" ^ func_name ^ "' cannot return a value") stmt.stmt_pos
              | None, t when t <> Void -> 
                  type_error ("Non-void function '" ^ func_name ^ "' must return a value of type " ^ 
                             string_of_bpf_type t) stmt.stmt_pos
              | Some typed_expr, _ ->
                  (* Check return type compatibility *)
                  let resolved_expr_type = resolve_user_type ctx typed_expr.texpr_type in
                  (match unify_types resolved_expr_type resolved_return_type with
                   | Some _ -> () (* Types can be unified *)
                   | None -> 
                       type_error ("Function '" ^ func_name ^ "' expects return type " ^ 
                                  string_of_bpf_type resolved_return_type ^ " but got " ^ 
                                  string_of_bpf_type resolved_expr_type) stmt.stmt_pos)
              | _ -> () (* Valid cases *))
           with Not_found -> () (* Function not in context *))
       | None -> () (* Not in function context *));
      
      { tstmt_desc = TReturn typed_expr_opt; tstmt_pos = stmt.stmt_pos }
  
  | If (cond, then_stmts, else_opt) ->
      let typed_cond = type_check_condition ctx cond in
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
       | Map (key_type, value_type, _, _) ->
           (* For maps: index is key type, value is value type *)
           Hashtbl.replace ctx.variables index_var key_type;
           Hashtbl.replace ctx.variables value_var value_type;
           incr loop_depth;
           let typed_body = List.map (type_check_statement ctx) body in
           decr loop_depth;
           { tstmt_desc = TForIter (index_var, value_var, typed_iterable, typed_body); tstmt_pos = stmt.stmt_pos }
       | _ -> type_error "For-iter expression must be iterable (array or map)" stmt.stmt_pos)
  
  | While (cond, body) ->
      let typed_cond = type_check_condition ctx cond in
      incr loop_depth;
      let typed_body = List.map (type_check_statement ctx) body in
      decr loop_depth;
      { tstmt_desc = TWhile (typed_cond, typed_body); tstmt_pos = stmt.stmt_pos }

  | Delete target ->
      (match target with
      | DeleteMapEntry (map_expr, key_expr) ->
          let typed_key = type_check_expression ctx key_expr in
          (* Check if this is map deletion *)
          (match map_expr.expr_desc with
           | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
               (* This is a regular map declaration *)
               let map_decl = Hashtbl.find ctx.maps map_name in
               (* Check key type compatibility *)
               let resolved_key_type = resolve_user_type ctx map_decl.ast_key_type in
               let resolved_typed_key_type = resolve_user_type ctx typed_key.texpr_type in
               (match unify_types resolved_key_type resolved_typed_key_type with
                | Some _ -> ()
                | None -> type_error ("Map key type mismatch in delete statement") stmt.stmt_pos);
               (* Create a synthetic map type for the result *)
               let typed_map = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.ast_key_type, map_decl.ast_value_type, map_decl.ast_map_type, map_decl.max_entries); texpr_pos = map_expr.expr_pos } in
               { tstmt_desc = TDelete (TDeleteMapEntry (typed_map, typed_key)); tstmt_pos = stmt.stmt_pos }
           | Identifier var_name when Hashtbl.mem ctx.variables var_name ->
               (* Check if this is a global variable with map type *)
               (match Hashtbl.find ctx.variables var_name with
                | Map (key_type, value_type, map_type, size) ->
                    (* This is a global variable with map type *)
                    let resolved_key_type = resolve_user_type ctx key_type in
                    let resolved_typed_key_type = resolve_user_type ctx typed_key.texpr_type in
                    (* Check key type compatibility *)
                    (match unify_types resolved_key_type resolved_typed_key_type with
                     | Some _ -> ()
                     | None -> type_error ("Map key type mismatch in delete statement") stmt.stmt_pos);
                    (* Create a synthetic map type for the result *)
                    let typed_map = { texpr_desc = TIdentifier var_name; texpr_type = Map (key_type, value_type, map_type, size); texpr_pos = map_expr.expr_pos } in
                    { tstmt_desc = TDelete (TDeleteMapEntry (typed_map, typed_key)); tstmt_pos = stmt.stmt_pos }
                | _ ->
                    type_error ("Delete map[key] can only be used on maps") stmt.stmt_pos)
           | _ ->
               type_error ("Delete map[key] can only be used on maps") stmt.stmt_pos)
      | DeletePointer ptr_expr ->
          let typed_ptr = type_check_expression ctx ptr_expr in
          (* Check that the expression is a pointer type *)
          (match typed_ptr.texpr_type with
           | Pointer _ ->
               { tstmt_desc = TDelete (TDeletePointer typed_ptr); tstmt_pos = stmt.stmt_pos }
           | _ ->
               type_error ("Delete pointer can only be used on pointer types") stmt.stmt_pos))
  
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

(** Type check boolean conversion for if/while conditions *)
and type_check_condition ctx expr =
  let typed_expr = type_check_expression ctx expr in
  let resolved_type = resolve_user_type ctx typed_expr.texpr_type in
  
  if is_truthy_type resolved_type then
    typed_expr
  else
    type_error ("Expression of type " ^ string_of_bpf_type resolved_type ^ 
               " cannot be used in boolean context") expr.expr_pos

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
  
  (* Add named return variable to scope if present *)
  (match get_return_variable_name func.func_return_type with
   | Some var_name ->
       let return_type = match get_return_type func.func_return_type with
         | Some t -> resolve_user_type ctx t
         | None -> U32
       in
       Hashtbl.replace ctx.variables var_name return_type
   | None -> ());
  
  (* Type check function body *)
  let typed_body = List.map (type_check_statement ctx) func.func_body in
  
  (* Determine return type *)
  let return_type = match get_return_type func.func_return_type with
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
    (* Convert AST map to IR map for type checking context *)
    let ir_key_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table map_decl.key_type in
    let ir_value_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table map_decl.value_type in
    let ir_map_type = Ir.ast_map_type_to_ir_map_type map_decl.map_type in
    let flags = Maps.ast_flags_to_int map_decl.config.flags in
    let ir_map_def = Ir.make_ir_map_def
      map_decl.name
      ir_key_type
      ir_value_type
      ir_map_type
      map_decl.config.max_entries
      ~ast_key_type:map_decl.key_type
      ~ast_value_type:map_decl.value_type
      ~ast_map_type:map_decl.map_type
      ~flags:flags
      ~is_global:map_decl.is_global
      map_decl.map_pos
    in
    Hashtbl.replace ctx.maps map_decl.name ir_map_def
  ) prog.prog_maps;
  
  (* Add program-scoped structs to context *)
  List.iter (fun struct_def ->
    let type_def = StructDef (struct_def.struct_name, struct_def.struct_fields, struct_def.struct_pos) in
    Hashtbl.replace ctx.types struct_def.struct_name type_def
  ) prog.prog_structs;
  
  (* FIRST PASS: Register all function signatures so they can call each other *)
  List.iter (fun func ->
    let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) func.func_params in
    let return_type = match get_return_type func.func_return_type with
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
let type_check_ast ?symbol_table:(provided_symbol_table=None) ast =
  let symbol_table = match provided_symbol_table with
    | Some st -> st
    | None -> Symbol_table.build_symbol_table ast
  in
  let ctx = create_context symbol_table ast in
  
  (* Add enum constants as variables for all loaded enums *)
  Hashtbl.iter (fun _name type_def ->
    match type_def with
    | EnumDef (enum_name, enum_values, _) ->
        let enum_type = match enum_name with
          | "xdp_action" -> Xdp_action
          | _ -> UserType enum_name
        in
        List.iter (fun (const_name, _) ->
          Hashtbl.replace ctx.variables const_name enum_type
        ) enum_values
    | _ -> ()
  ) ctx.types;
  
  (* First pass: collect type definitions, map declarations, and validate global variables *)
  List.iter (function
    | TypeDef type_def ->
        (match type_def with
         | StructDef (name, _, _) | EnumDef (name, _, _) | TypeAlias (name, _, _) ->
             Hashtbl.replace ctx.types name type_def)
    | MapDecl map_decl ->
        (* Convert AST map to IR map for type checking context *)
        let ir_key_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table map_decl.key_type in
        let ir_value_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table map_decl.value_type in
        let ir_map_type = Ir.ast_map_type_to_ir_map_type map_decl.map_type in
        let flags = Maps.ast_flags_to_int map_decl.config.flags in
        let ir_map_def = Ir.make_ir_map_def
          map_decl.name
          ir_key_type
          ir_value_type
          ir_map_type
          map_decl.config.max_entries
          ~ast_key_type:map_decl.key_type
          ~ast_value_type:map_decl.value_type
          ~ast_map_type:map_decl.map_type
          ~flags:flags
          ~is_global:map_decl.is_global
          map_decl.map_pos
        in
        Hashtbl.replace ctx.maps map_decl.name ir_map_def
    | GlobalVarDecl global_var_decl ->
        (* Validate pinning rules: cannot pin local variables *)
        if global_var_decl.is_pinned && global_var_decl.is_local then
          type_error "Cannot pin local variables - only shared variables can be pinned" global_var_decl.global_var_pos;
        
        (* Add global variable to type checker context *)
        let var_type = match global_var_decl.global_var_type with
          | Some t -> 
              let resolved_type = resolve_user_type ctx t in
              (* Validate ring buffer objects *)
              validate_ringbuf_object ctx global_var_decl.global_var_name resolved_type global_var_decl.global_var_pos;
              resolved_type
          | None -> U32  (* Default type if not specified *)
        in
        Hashtbl.replace ctx.variables global_var_decl.global_var_name var_type
    | _ -> ()
  ) ast;
  
  (* Second pass: First register ALL function signatures (global and attributed) *)
  List.iter (function
    | GlobalFunction func ->
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) func.func_params in
        let return_type = match get_return_type func.func_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> U32  (* default return type *)
        in
        Hashtbl.replace ctx.functions func.func_name (param_types, return_type);
        Hashtbl.replace ctx.function_scopes func.func_name func.func_scope
    | AttributedFunction attr_func ->
        (* Register attributed function signatures, including kfuncs *)
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) attr_func.attr_function.func_params in
        let return_type = match get_return_type attr_func.attr_function.func_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> U32  (* default return type *)
        in
        Hashtbl.replace ctx.functions attr_func.attr_function.func_name (param_types, return_type);
        
        (* Check if this is a @helper or @kfunc function and update scope accordingly *)
        let is_helper = List.exists (function
          | SimpleAttribute "helper" -> true
          | _ -> false
        ) attr_func.attr_list in
        let is_kfunc = List.exists (function
          | SimpleAttribute "kfunc" -> true
          | _ -> false
        ) attr_func.attr_list in
        let actual_scope = if is_helper || is_kfunc then Ast.Kernel else attr_func.attr_function.func_scope in
        Hashtbl.replace ctx.function_scopes attr_func.attr_function.func_name actual_scope;
        
        (* Track @helper functions separately *)
        if is_helper then
          Hashtbl.add ctx.helper_functions attr_func.attr_function.func_name ();
        
        (* Track non-kfunc, non-private, and non-helper attributed functions as non-callable *)
        let is_kfunc = List.exists (function
          | SimpleAttribute "kfunc" -> true
          | _ -> false
        ) attr_func.attr_list in
        let is_private = List.exists (function
          | SimpleAttribute "private" -> true
          | _ -> false
        ) attr_func.attr_list in
        if not is_kfunc && not is_private && not is_helper then
          Hashtbl.add ctx.attributed_functions attr_func.attr_function.func_name ()
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
        (* Extract program type from attribute for context *)
        let prog_type = match attr_func.attr_list with
          | SimpleAttribute prog_type_str :: _ ->
              (match prog_type_str with
               | "xdp" -> Some Xdp
               | "tc" -> Some Tc  

               | "tracepoint" -> Some Tracepoint
               | "kfunc" -> None  (* kfuncs don't have program types *)
               | "private" -> None  (* private functions don't have program types *)
               | "helper" -> None  (* helper functions don't have program types *)
               | "test" -> None  (* test functions don't have program types *)
               | _ -> None)
          | _ -> None
        in
        
        (* Set current program type for context *)
        ctx.current_program_type <- prog_type;
        let _ = type_check_function ~register_signature:false ctx attr_func.attr_function in
        ctx.current_program_type <- None;
        ()
    | _ -> ()
  ) ast;
  
  (* Return the original AST - this is a simple type checking function, not the full multi-program analysis *)
  ast

(** Utility functions *)
let check_function_call name arg_types =
  match Stdlib.get_builtin_function_signature name with
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
    | TCall (callee, args) -> Call (typed_expr_to_expr callee, List.map typed_expr_to_expr args)
    | TTailCall (name, args) -> TailCall (name, List.map typed_expr_to_expr args)
    | TArrayAccess (arr, idx) -> ArrayAccess (typed_expr_to_expr arr, typed_expr_to_expr idx)
    | TFieldAccess (obj, field) -> FieldAccess (typed_expr_to_expr obj, field)
    | TArrowAccess (obj, field) -> ArrowAccess (typed_expr_to_expr obj, field)
    | TBinaryOp (left, op, right) -> BinaryOp (typed_expr_to_expr left, op, typed_expr_to_expr right)
    | TUnaryOp (op, expr) -> UnaryOp (op, typed_expr_to_expr expr)
    | TStructLiteral (struct_name, field_assignments) -> 
        let converted_field_assignments = List.map (fun (field_name, typed_field_expr) ->
          (field_name, typed_expr_to_expr typed_field_expr)
        ) field_assignments in
        StructLiteral (struct_name, converted_field_assignments)
    | TMatch (typed_matched_expr, typed_arms) ->
        (* Convert typed match expression back to untyped AST *)
        let matched_expr = typed_expr_to_expr typed_matched_expr in
        let arms = List.map (fun tarm ->
          let arm_body = match tarm.tarm_body with
            | TSingleExpr expr -> SingleExpr (typed_expr_to_expr expr)
            | TBlock stmts -> Block (List.map typed_stmt_to_stmt stmts)
          in
          { arm_pattern = tarm.tarm_pattern; arm_body = arm_body; arm_pos = tarm.tarm_pos }
        ) typed_arms in
        Match (matched_expr, arms)
    | TNew typ -> New typ
    | TNewWithFlag (typ, flag_expr) -> NewWithFlag (typ, typed_expr_to_expr flag_expr)
  in
  (* Handle special cases for type annotations *)
  let safe_expr_type = match texpr.texpr_desc, texpr.texpr_type with
    | TIdentifier _, Map (_, _, _, _) -> 
        (* Map identifiers used in expressions should be represented as pointers for IR generation *)
        Some (Pointer U8)
    | _, Map (_, _, _, _) -> 
        (* Don't set Map types in expr_type for other expressions *)
        None
    | _, other_type -> 
        Some other_type
  in
  let enhanced_expr = { expr_desc; expr_pos = texpr.texpr_pos; expr_type = safe_expr_type; 
    type_checked = true; program_context = None; map_scope = None } in
  enhanced_expr

and typed_stmt_to_stmt tstmt =
  let stmt_desc = match tstmt.tstmt_desc with
    | TExprStmt expr -> ExprStmt (typed_expr_to_expr expr)
    | TAssignment (name, expr) -> Assignment (name, typed_expr_to_expr expr)
    | TCompoundAssignment (name, op, expr) -> CompoundAssignment (name, op, typed_expr_to_expr expr)
    | TCompoundIndexAssignment (map_expr, key_expr, op, value_expr) ->
        CompoundIndexAssignment (typed_expr_to_expr map_expr, typed_expr_to_expr key_expr, op, typed_expr_to_expr value_expr)
    | TFieldAssignment (obj_expr, field, value_expr) ->
        FieldAssignment (typed_expr_to_expr obj_expr, field, typed_expr_to_expr value_expr)
    | TArrowAssignment (obj_expr, field, value_expr) ->
        ArrowAssignment (typed_expr_to_expr obj_expr, field, typed_expr_to_expr value_expr)
    | TIndexAssignment (map_expr, key_expr, value_expr) -> 
        IndexAssignment (typed_expr_to_expr map_expr, typed_expr_to_expr key_expr, typed_expr_to_expr value_expr)
    | TDeclaration (name, typ, expr_opt) -> Declaration (name, Some typ, Option.map typed_expr_to_expr expr_opt)
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
    | TDelete target ->
        let delete_target = match target with
          | TDeleteMapEntry (map_expr, key_expr) ->
              DeleteMapEntry (typed_expr_to_expr map_expr, typed_expr_to_expr key_expr)
          | TDeletePointer ptr_expr ->
              DeletePointer (typed_expr_to_expr ptr_expr)
        in
        Delete delete_target
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
    func_return_type = Some (make_unnamed_return tfunc.tfunc_return_type);
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
    prog_target = original_prog.prog_target;  (* Preserve original target *)
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
let rec type_check_and_annotate_ast ?symbol_table:(provided_symbol_table=None) ?(imports=([] : Import_resolver.resolved_import list)) ast =
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
  let symbol_table = match provided_symbol_table with
    | Some st -> st
    | None -> Symbol_table.build_symbol_table ast
  in
  let ctx = create_context symbol_table ast in
  
  (* Populate imports in context *)
  List.iter (fun (resolved_import : Import_resolver.resolved_import) ->
    Hashtbl.replace ctx.imports resolved_import.module_name resolved_import;
    (* Also add module names as variables so they can be used in field access *)
    Hashtbl.replace ctx.variables resolved_import.module_name (UserType ("Module_" ^ resolved_import.module_name))
  ) imports;
  
  (* Add enum constants as variables for all loaded enums *)
  Hashtbl.iter (fun _name type_def ->
    match type_def with
    | EnumDef (enum_name, enum_values, _) ->
        let enum_type = match enum_name with
          | "xdp_action" -> Xdp_action
          | _ -> Enum enum_name
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
         | StructDef (name, _, _) | EnumDef (name, _, _) | TypeAlias (name, _, _) ->
             Hashtbl.replace ctx.types name type_def)
    | StructDecl struct_def ->
        let type_def = StructDef (struct_def.struct_name, struct_def.struct_fields, struct_def.struct_pos) in
        Hashtbl.replace ctx.types struct_def.struct_name type_def
    | MapDecl map_decl ->
        (* Convert AST map to IR map for type checking context *)
        let ir_key_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table map_decl.key_type in
        let ir_value_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table map_decl.value_type in
        let ir_map_type = Ir.ast_map_type_to_ir_map_type map_decl.map_type in
        let flags = Maps.ast_flags_to_int map_decl.config.flags in
        let ir_map_def = Ir.make_ir_map_def
          map_decl.name
          ir_key_type
          ir_value_type
          ir_map_type
          map_decl.config.max_entries
          ~ast_key_type:map_decl.key_type
          ~ast_value_type:map_decl.value_type
          ~ast_map_type:map_decl.map_type
          ~flags:flags
          ~is_global:map_decl.is_global
          map_decl.map_pos
        in
        Hashtbl.replace ctx.maps map_decl.name ir_map_def
    | ConfigDecl config_decl ->
        Hashtbl.replace ctx.configs config_decl.config_name config_decl
    | GlobalVarDecl global_var_decl ->
        (* Validate pinning rules: cannot pin local variables *)
        if global_var_decl.is_pinned && global_var_decl.is_local then
          type_error "Cannot pin local variables - only shared variables can be pinned" global_var_decl.global_var_pos;
        
        (* Add global variable to type checker context *)
        let var_type = match global_var_decl.global_var_type with
          | Some t -> 
              let resolved_type = resolve_user_type ctx t in
              (* Validate ring buffer objects *)
              validate_ringbuf_object ctx global_var_decl.global_var_name resolved_type global_var_decl.global_var_pos;
              (* If both type and initial value are present, check for type mismatch *)
              (match global_var_decl.global_var_init with
               | Some init_expr ->
                   let typed_init_expr = type_check_expression ctx init_expr in
                   let inferred_type = typed_init_expr.texpr_type in
                   if not (can_assign resolved_type inferred_type) then
                     type_error ("Type mismatch in global variable declaration: expected " ^ 
                                string_of_bpf_type resolved_type ^ ", got " ^ 
                                string_of_bpf_type inferred_type) global_var_decl.global_var_pos;
                   resolved_type
               | None -> resolved_type)
          | None -> 
              (* If no type specified, infer from initial value *)
              (match global_var_decl.global_var_init with
               | Some init_expr ->
                   let typed_init_expr = type_check_expression ctx init_expr in
                   let inferred_type = typed_init_expr.texpr_type in
                   (* Validate ring buffer objects *)
                   validate_ringbuf_object ctx global_var_decl.global_var_name inferred_type global_var_decl.global_var_pos;
                   inferred_type
               | None -> U32)  (* Default type when no type or value specified *)
        in
        (* If this is a map type, also register it as a map *)
        (match var_type with
         | Map (key_type, value_type, map_type, size) ->
             let ir_key_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table key_type in
             let ir_value_type = Ir.ast_type_to_ir_type_with_context ctx.symbol_table value_type in
             let ir_map_type = Ir.ast_map_type_to_ir_map_type map_type in
             let ir_map_def = Ir.make_ir_map_def
               global_var_decl.global_var_name
               ir_key_type
               ir_value_type
               ir_map_type
               size
               ~ast_key_type:key_type
               ~ast_value_type:value_type
               ~ast_map_type:map_type
               ~flags:0
               ~is_global:true
               global_var_decl.global_var_pos
             in
             Hashtbl.replace ctx.maps global_var_decl.global_var_name ir_map_def
         | _ -> ());
        Hashtbl.replace ctx.variables global_var_decl.global_var_name var_type
    | AttributedFunction attr_func ->
        (* Register attributed function signature in context *)
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) attr_func.attr_function.func_params in
        let return_type = match get_return_type attr_func.attr_function.func_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> U32  (* default return type *)
        in
        Hashtbl.replace ctx.functions attr_func.attr_function.func_name (param_types, return_type);
        
        (* Check if this is a @helper or @kfunc function and update scope accordingly *)
        let is_helper = List.exists (function
          | SimpleAttribute "helper" -> true
          | _ -> false
        ) attr_func.attr_list in
        let is_kfunc = List.exists (function
          | SimpleAttribute "kfunc" -> true
          | _ -> false
        ) attr_func.attr_list in
        let actual_scope = if is_helper || is_kfunc then Ast.Kernel else attr_func.attr_function.func_scope in
        Hashtbl.replace ctx.function_scopes attr_func.attr_function.func_name actual_scope;
        
        (* Track @helper functions separately *)
        if is_helper then
          Hashtbl.add ctx.helper_functions attr_func.attr_function.func_name ()
    | GlobalFunction func ->
        (* Register global function signature in context *)
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) func.func_params in
        let return_type = match get_return_type func.func_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> U32  (* default return type *)
        in
        Hashtbl.replace ctx.functions func.func_name (param_types, return_type);
        Hashtbl.replace ctx.function_scopes func.func_name func.func_scope
    | ImplBlock impl_block ->
        (* Validate struct_ops function signatures against the struct definition in the AST *)
        let struct_ops_name = List.fold_left (fun acc attr ->
          match attr with
          | AttributeWithArg ("struct_ops", name) -> Some name
          | _ -> acc
        ) None impl_block.impl_attributes in
        
        (* If this is a struct_ops impl block, validate function signatures *)
        (match struct_ops_name with
         | Some ops_name ->
             (* Find the corresponding struct definition in the AST *)
             let struct_def_opt = List.find_opt (function
               | StructDecl struct_def when struct_def.struct_name = ops_name -> true
               | _ -> false
             ) ctx.ast_context in
             
             (match struct_def_opt with
              | Some (StructDecl struct_def) ->
                  (* Validate each function in the impl block against the struct definition *)
                  List.iter (function
                    | ImplFunction func ->
                        (* Find the corresponding field in the struct definition *)
                        (match List.find_opt (fun (field_name, _) -> field_name = func.func_name) struct_def.struct_fields with
                         | Some (_, field_type) ->
                             (* Extract function signature from the field type *)
                             (match field_type with
                              | Function (param_types, return_type) ->
                                  (* Validate parameter count and types *)
                                  let actual_param_types = List.map (fun (_, param_type) -> 
                                    resolve_user_type ctx param_type
                                  ) func.func_params in
                                  
                                  if List.length actual_param_types <> List.length param_types then
                                    type_error 
                                      ("Function '" ^ func.func_name ^ "' parameter count mismatch. Expected " ^
                                       string_of_int (List.length param_types) ^ " parameters but got " ^
                                       string_of_int (List.length actual_param_types)) 
                                      func.func_pos
                                  else
                                    (* Check each parameter type *)
                                    List.iter2 (fun actual expected ->
                                      let resolved_expected = resolve_user_type ctx expected in
                                      if actual <> resolved_expected then
                                        type_error 
                                          ("Function '" ^ func.func_name ^ "' parameter type mismatch. Expected " ^
                                           Ast.string_of_bpf_type resolved_expected ^ " but got " ^ Ast.string_of_bpf_type actual) 
                                          func.func_pos
                                    ) actual_param_types param_types;
                                  
                                  (* Validate return type *)
                                  let actual_return = match get_return_type func.func_return_type with
                                    | Some ret_type -> resolve_user_type ctx ret_type
                                    | None -> U32  (* Default return type *)
                                  in
                                  let expected_return = resolve_user_type ctx return_type in
                                  if actual_return <> expected_return then
                                    type_error 
                                      ("Function '" ^ func.func_name ^ "' return type mismatch. Expected " ^
                                       Ast.string_of_bpf_type expected_return ^ " but got " ^ Ast.string_of_bpf_type actual_return) 
                                      func.func_pos
                              | _ ->
                                  (* Field is not a function - this might be a static field *)
                                  ())
                         | None ->
                             (* Function not found in struct definition - this might be an optional function *)
                             (* For now, we'll allow extra functions *)
                             ())
                    | ImplStaticField (field_name, _) -> 
                        (* Validate static fields against struct definition *)
                        (match List.find_opt (fun (fname, _) -> fname = field_name) struct_def.struct_fields with
                         | Some (_, _field_type) -> 
                             (* Static field exists in struct - good *)
                             ()
                         | None ->
                             (* Static field not found in struct definition *)
                             type_error 
                               ("Static field '" ^ field_name ^ "' not found in struct_ops '" ^ ops_name ^ "'") 
                               impl_block.impl_pos)
                  ) impl_block.impl_items;
                  
                  (* Check for missing required functions *)
                  let struct_function_fields = List.filter (fun (_field_name, field_type) ->
                    match field_type with
                    | Function (_, _) -> true
                    | _ -> false
                  ) struct_def.struct_fields in
                  
                  let impl_function_names = List.filter_map (function
                    | ImplFunction func -> Some func.func_name
                    | ImplStaticField (_, _) -> None
                  ) impl_block.impl_items in
                  
                  List.iter (fun (field_name, _) ->
                    if not (List.mem field_name impl_function_names) then
                      (* Most struct_ops functions are optional - only warn or allow missing functions *)
                      (* For now, we'll allow missing functions since they're typically optional *)
                      ()
                  ) struct_function_fields
              | _ ->
                  (* Struct definition not found - this could mean it's a kernel-defined struct_ops *)
                  (* without a local definition, which is valid *)
                  ())
         | None -> ()  (* Not a struct_ops impl block *)
        );
        
        (* Register impl block functions in context *)
        List.iter (function
          | ImplFunction func ->
              let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) func.func_params in
              let return_type = match get_return_type func.func_return_type with
                | Some t -> resolve_user_type ctx t
                | None -> U32  (* default return type *)
              in
              Hashtbl.replace ctx.functions func.func_name (param_types, return_type);
              Hashtbl.replace ctx.function_scopes func.func_name func.func_scope
          | ImplStaticField (_, _) -> ()  (* Static fields don't need function registration *)
        ) impl_block.impl_items
    | ImportDecl _import_decl ->
        (* Import declarations are handled elsewhere - no processing needed here *)
        ()
    | ExternKfuncDecl extern_decl ->
        (* Add extern kfunc to function table *)
        let param_types = List.map (fun (_, typ) -> resolve_user_type ctx typ) extern_decl.extern_params in
        let return_type = match extern_decl.extern_return_type with
          | Some t -> resolve_user_type ctx t
          | None -> Void
        in
        Hashtbl.replace ctx.functions extern_decl.extern_name (param_types, return_type);
        Hashtbl.replace ctx.function_scopes extern_decl.extern_name Kernel (* Extern kfuncs run in kernel space *);
    | IncludeDecl include_decl ->
        (* Include declarations are processed in main.ml Phase 1.6 before type checking *)
        (* By the time we reach this point, includes should already be expanded into the AST *)
        (* This case should rarely be hit, but we handle it gracefully *)
        let _ = include_decl in  (* Suppress unused variable warning *)
        ()
  ) ast;
  
  (* Second pass: type check attributed functions and global functions with multi-program awareness *)
  let (typed_attributed_functions, typed_userspace_functions) = List.fold_left (fun (attr_acc, userspace_acc) decl ->
    match decl with
    | AttributedFunction attr_func ->
        (* Check if this is a kfunc, private, or helper function - handle differently *)
        let is_kfunc = List.exists (function
          | SimpleAttribute "kfunc" -> true
          | _ -> false
        ) attr_func.attr_list in
        let is_private = List.exists (function
          | SimpleAttribute "private" -> true
          | _ -> false
        ) attr_func.attr_list in
        let is_helper = List.exists (function
          | SimpleAttribute "helper" -> true
          | _ -> false
        ) attr_func.attr_list in
        let is_test = List.exists (function
          | SimpleAttribute "test" -> true
          | _ -> false
        ) attr_func.attr_list in
        
        (* Track @test functions separately *)
        if is_test then
          Hashtbl.add ctx.test_functions attr_func.attr_function.func_name ();
        
        (* Extract program type from attribute for context *)
        let (prog_type, kprobe_target) = match attr_func.attr_list with
          | SimpleAttribute prog_type_str :: _ ->
              (match prog_type_str with
               | "xdp" -> (Some Xdp, None)
               | "tc" -> 
                   (* Reject old format: @tc without direction specification *)
                   type_error ("@tc requires direction specification. Use @tc(\"ingress\") or @tc(\"egress\") instead.") attr_func.attr_pos

               | "probe" -> 
                   (* Reject old format: @probe without target function *)
                   type_error ("@probe requires target function specification. Use @probe(\"function_name\") instead.") attr_func.attr_pos
               | "tracepoint" -> 
                   (* Reject old format: @tracepoint without category/event *)
                   type_error ("@tracepoint requires category/event specification. Use @tracepoint(\"category/event\") instead.") attr_func.attr_pos
               | "kfunc" -> (None, None)  (* kfuncs don't have program types *)
               | "private" -> (None, None)  (* private functions don't have program types *)
               | "helper" -> (None, None)  (* helper functions don't have program types *)
               | "test" -> (None, None)  (* test functions don't have program types *)
               | _ -> (None, None))
          | AttributeWithArg (attr_name, target_func) :: _ ->
              (match attr_name with
               | "tc" ->
                   (* Parse TC direction from string like "ingress" or "egress" *)
                   if target_func = "ingress" || target_func = "egress" then
                     (Some Tc, Some target_func)
                   else
                     type_error (sprintf "@tc requires direction \"ingress\" or \"egress\". Use @tc(\"ingress\") or @tc(\"egress\") instead of @tc(\"%s\")" target_func) attr_func.attr_pos
               | "probe" -> 
                   (* Determine probe type based on whether target contains offset *)
                   let probe_type = if String.contains target_func '+' then Kprobe else Fprobe in
                   (Some (Probe probe_type), Some target_func)
               | "tracepoint" -> 
                   (* Parse category/event from string like "syscalls/sys_enter_read" *)
                   if String.contains target_func '/' then
                     (Some Tracepoint, Some target_func)
                   else
                     type_error (sprintf "@tracepoint requires category/event format. Use @tracepoint(\"category/event\") instead of @tracepoint(\"%s\")" target_func) attr_func.attr_pos
               | _ -> (None, None))
          | _ -> (None, None)
        in
        
        (* Validate attributed function signatures based on program type *)
        if is_kfunc then
          (* For kfunc, we don't enforce specific context types - any valid C types are allowed *)
          ()
        else if is_private then
          (* For private functions, we don't enforce specific context types - any valid C types are allowed *)
          ()
        else if is_helper then
          (* For helper functions, we don't enforce specific context types - any valid eBPF types are allowed *)
          ()
        else if is_test then
          (* For test functions, we don't enforce specific context types - any valid userspace types are allowed *)
          ()
        else
          (match prog_type with
         | Some Xdp ->
             let params = attr_func.attr_function.func_params in
             let resolved_param_type = if List.length params = 1 then 
               resolve_user_type ctx (snd (List.hd params)) 
             else UserType "invalid" in
             let resolved_return_type = match get_return_type attr_func.attr_function.func_return_type with
               | Some ret_type -> Some (resolve_user_type ctx ret_type)
               | None -> None in
             
             if List.length params <> 1 ||
                resolved_param_type <> Pointer Xdp_md ||
                resolved_return_type <> Some Xdp_action then
               type_error ("@xdp attributed function must have signature (ctx: *xdp_md) -> xdp_action") attr_func.attr_pos
         | Some Tc ->
             let params = attr_func.attr_function.func_params in
             let resolved_param_type = if List.length params = 1 then 
               resolve_user_type ctx (snd (List.hd params)) 
             else UserType "invalid" in
             let resolved_return_type = match get_return_type attr_func.attr_function.func_return_type with
               | Some ret_type -> Some (resolve_user_type ctx ret_type)
               | None -> None in
             
             if List.length params <> 1 ||
                resolved_param_type <> Pointer (Struct "__sk_buff") ||
                resolved_return_type <> Some I32 then (
                   (* TC validation failed - detailed diagnostics available in error message *)
               type_error ("@tc attributed function must have signature (ctx: *__sk_buff) -> int") attr_func.attr_pos
             )
         | Some (Probe probe_type) ->
             let params = attr_func.attr_function.func_params in
             let resolved_return_type = match get_return_type attr_func.attr_function.func_return_type with
               | Some ret_type -> Some (resolve_user_type ctx ret_type)
               | None -> None in
             
             let probe_type_name = match probe_type with
               | Fprobe -> "fprobe"
               | Kprobe -> "kprobe"
             in
             
             (* Validate probe function - only modern format supported *)
             (match kprobe_target with
             | Some _target_func ->
                 (* Modern format with target function specified *)
                 (* Check for invalid pt_regs parameter usage *)
                 List.iter (fun (_, param_type) ->
                   match param_type with
                   | Pointer (UserType "pt_regs") ->
                       type_error (sprintf "@%s functions should not use pt_regs parameter. Use kernel function parameters directly." probe_type_name) attr_func.attr_pos
                   | _ -> ()
                 ) params;
                 (* Validate signature against BTF if available *)
                 if List.length params > 6 then
                   type_error (sprintf "%s functions support maximum 6 parameters" (String.capitalize_ascii probe_type_name)) attr_func.attr_pos
             | None ->
                 (* This case should never be reached due to earlier validation *)
                 failwith (sprintf "Internal error: %s without target function should have been rejected earlier" probe_type_name)
             );

             (* Require i32 return type for eBPF probe functions - BPF_PROG() always returns int *)
             let valid_return_type = match resolved_return_type with
               | Some I32 -> true   (* Standard eBPF probe return type *)
               | _ -> false
             in
             
             if not valid_return_type then
               type_error (sprintf "@%s attributed function must return i32" probe_type_name) attr_func.attr_pos
           | Some _ -> () (* Other program types - validation can be added later *)
           | None -> type_error ("Invalid or unsupported attribute") attr_func.attr_pos);
        
        (* Track this as an attributed function that cannot be called directly, but exclude kfuncs, private, helper, and test functions *)
        if not is_kfunc && not is_private && not is_helper && not is_test then
          Hashtbl.add ctx.attributed_functions attr_func.attr_function.func_name ();
        
        (* Add to attributed function map for tail call detection (exclude kfuncs, private, helper, and test functions) *)
        if not is_kfunc && not is_private && not is_helper && not is_test then
          Hashtbl.replace ctx.attributed_function_map attr_func.attr_function.func_name attr_func;
        
        (* Set current program type for context *)
        ctx.current_program_type <- prog_type;
        
        (* Update the function scope before type checking if it's a helper function *)
        let func_to_check = if is_helper then
          { attr_func.attr_function with func_scope = Ast.Kernel }
        else
          attr_func.attr_function
        in
        
        let typed_func = type_check_function ~register_signature:false ctx func_to_check in
        ctx.current_program_type <- None;
        ((attr_func.attr_list, typed_func) :: attr_acc, userspace_acc)
    | GlobalFunction func ->
        let typed_func = type_check_function ctx func in
        (attr_acc, typed_func :: userspace_acc)
    | ImplBlock impl_block ->
        (* Type check impl block functions - treat them as eBPF functions with struct_ops attributes *)
        (* Check if this is a struct_ops impl block *)
        let is_struct_ops = List.exists (function
          | AttributeWithArg ("struct_ops", _) -> true
          | _ -> false
        ) impl_block.impl_attributes in

        let typed_impl_functions = List.filter_map (function
          | ImplFunction func ->
              (* Set function scope to Kernel for struct_ops implementations *)
              let func_to_check = if is_struct_ops then
                { func with func_scope = Ast.Kernel }
              else
                func
              in
              let typed_func = type_check_function ctx func_to_check in
              Some (impl_block.impl_attributes, typed_func)
          | ImplStaticField (_, _) -> None  (* Static fields don't need type checking as functions *)
        ) impl_block.impl_items in
        (typed_impl_functions @ attr_acc, userspace_acc)
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
     | Call (_, args) ->
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
    | CompoundAssignment (_, _, expr) ->
        enhance_expr prog_type expr
    | CompoundIndexAssignment (map_expr, key_expr, _, value_expr) ->
        (* This is a compound write operation *)
        enhance_expr prog_type map_expr;
        enhance_expr prog_type key_expr;
        enhance_expr prog_type value_expr;
        (* Update the map expression to indicate write access *)
        (match map_expr.program_context with
         | Some ctx -> map_expr.program_context <- Some { ctx with data_flow_direction = Some Write }
         | None -> ())
    | FieldAssignment (obj_expr, _, value_expr) ->
        enhance_expr prog_type obj_expr;
        enhance_expr prog_type value_expr
    | ArrowAssignment (obj_expr, _, value_expr) ->
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
    | Declaration (_, _, expr_opt) ->
        (match expr_opt with
         | Some expr -> enhance_expr prog_type expr
         | None -> ())
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
    | Delete target ->
        (match target with
         | DeleteMapEntry (map_expr, key_expr) ->
             enhance_expr prog_type map_expr;
             enhance_expr prog_type key_expr;
             (* Delete is a write operation *)
             (match map_expr.program_context with
              | Some ctx -> map_expr.program_context <- Some { ctx with data_flow_direction = Some Write }
              | None -> ())
         | DeletePointer ptr_expr ->
             enhance_expr prog_type ptr_expr)
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

  (* For userspace functions, we don't have a program type, so create a simple enhancement *)
  let enhance_userspace_stmt stmt =
    let rec enhance_userspace_expr expr =
      expr.program_context <- None;
      expr.type_checked <- true;
      
      (* Recursively enhance sub-expressions *)
      (match expr.expr_desc with
       | Call (_, args) ->
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
    
    let rec enhance_userspace_stmt_inner stmt =
      match stmt.stmt_desc with
      | ExprStmt expr ->
          enhance_userspace_expr expr
      | Assignment (_, expr) ->
          enhance_userspace_expr expr
      | CompoundAssignment (_, _, expr) ->
          enhance_userspace_expr expr
      | CompoundIndexAssignment (map_expr, key_expr, _, value_expr) ->
          enhance_userspace_expr map_expr;
          enhance_userspace_expr key_expr;
          enhance_userspace_expr value_expr
      | FieldAssignment (obj_expr, _, value_expr) ->
          enhance_userspace_expr obj_expr;
          enhance_userspace_expr value_expr
      | ArrowAssignment (obj_expr, _, value_expr) ->
          enhance_userspace_expr obj_expr;
          enhance_userspace_expr value_expr
      | IndexAssignment (map_expr, key_expr, value_expr) ->
          enhance_userspace_expr map_expr;
          enhance_userspace_expr key_expr;
          enhance_userspace_expr value_expr
      | Declaration (_, _, expr_opt) ->
          (match expr_opt with
           | Some expr -> enhance_userspace_expr expr
           | None -> ())
      | ConstDeclaration (_, _, expr) ->
          enhance_userspace_expr expr
      | Return (Some expr) ->
          enhance_userspace_expr expr
      | If (cond_expr, then_stmts, else_stmts_opt) ->
          enhance_userspace_expr cond_expr;
          List.iter enhance_userspace_stmt_inner then_stmts;
          (match else_stmts_opt with
           | Some else_stmts -> List.iter enhance_userspace_stmt_inner else_stmts
           | None -> ())
      | For (_, start_expr, end_expr, body_stmts) ->
          enhance_userspace_expr start_expr;
          enhance_userspace_expr end_expr;
          List.iter enhance_userspace_stmt_inner body_stmts
      | ForIter (_, _, iter_expr, body_stmts) ->
          enhance_userspace_expr iter_expr;
          List.iter enhance_userspace_stmt_inner body_stmts
      | While (cond_expr, body_stmts) ->
          enhance_userspace_expr cond_expr;
          List.iter enhance_userspace_stmt_inner body_stmts
      | Delete target ->
          (match target with
           | DeleteMapEntry (map_expr, key_expr) ->
               enhance_userspace_expr map_expr;
               enhance_userspace_expr key_expr
           | DeletePointer ptr_expr ->
               enhance_userspace_expr ptr_expr)
      | Return None -> ()
      | Break -> ()
      | Continue -> ()
      | Try (try_stmts, catch_clauses) ->
          List.iter enhance_userspace_stmt_inner try_stmts;
          List.iter (fun clause ->
            List.iter enhance_userspace_stmt_inner clause.catch_body
          ) catch_clauses
      | Throw expr ->
          enhance_userspace_expr expr
      | Defer expr ->
          enhance_userspace_expr expr
    in
    enhance_userspace_stmt_inner stmt
  in

  (* Enhance attributed functions and global functions with multi-program context *)
  List.map (function
    | AttributedFunction attr_func ->
        (* Extract program type from attribute *)
        let prog_type = match attr_func.attr_list with
          | SimpleAttribute prog_type_str :: _ ->
              (match prog_type_str with
               | "xdp" -> Some Xdp
               | "tracepoint" -> Some Tracepoint
               | _ -> None)
          | AttributeWithArg (attr_name, _) :: _ ->
              (match attr_name with
               | "tc" -> Some Tc
               | "probe" -> Some (Probe Fprobe) (* Default to Fprobe for enhancement *)
               | "tracepoint" -> Some Tracepoint
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

    |       other_decl -> other_decl
          ) ast



