(** Type Checker for KernelScript *)

open Ast

(** Type checking exceptions *)
exception Type_error of string * position
exception Unification_error of bpf_type * bpf_type * position

(** Type checking context *)
type type_context = {
  variables: (string, bpf_type) Hashtbl.t;
  functions: (string, bpf_type list * bpf_type) Hashtbl.t;
  types: (string, type_def) Hashtbl.t;
  maps: (string, map_declaration) Hashtbl.t;
  mutable current_function: string option;
  mutable current_program: string option;
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
  | TFunctionCall of string * typed_expr list
  | TArrayAccess of typed_expr * typed_expr
  | TFieldAccess of typed_expr * string
  | TBinaryOp of typed_expr * binary_op * typed_expr
  | TUnaryOp of unary_op * typed_expr

type typed_statement = {
  tstmt_desc: typed_stmt_desc;
  tstmt_pos: position;
}

and typed_stmt_desc =
  | TExprStmt of typed_expr
  | TAssignment of string * typed_expr
  | TIndexAssignment of typed_expr * typed_expr * typed_expr
  | TDeclaration of string * bpf_type * typed_expr
  | TReturn of typed_expr option
  | TIf of typed_expr * typed_statement list * typed_statement list option
  | TFor of string * typed_expr * typed_expr * typed_statement list
  | TForIter of string * string * typed_expr * typed_statement list
  | TWhile of typed_expr * typed_statement list
  | TDelete of typed_expr * typed_expr

type typed_function = {
  tfunc_name: string;
  tfunc_params: (string * bpf_type) list;
  tfunc_return_type: bpf_type;
  tfunc_body: typed_statement list;
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
let create_context () = {
  variables = Hashtbl.create 32;
  functions = Hashtbl.create 16;
  types = Hashtbl.create 16;
  maps = Hashtbl.create 16;
  current_function = None;
  current_program = None;
}

(** Track loop nesting depth to prevent nested loops *)
let loop_depth = ref 0

(** Helper to create type error *)
let type_error msg pos = raise (Type_error (msg, pos))

(** Resolve user types to built-in types *)
let resolve_user_type = function
  | UserType "XdpContext" -> XdpContext
  | UserType "TcContext" -> TcContext
  | UserType "KprobeContext" -> KprobeContext
  | UserType "UprobeContext" -> UprobeContext
  | UserType "TracepointContext" -> TracepointContext
  | UserType "LsmContext" -> LsmContext
  | UserType "CgroupSkbContext" -> CgroupSkbContext
  | UserType "XdpAction" -> XdpAction
  | UserType "TcAction" -> TcAction
  | other_type -> other_type

(** Type unification algorithm *)
let rec unify_types t1 t2 =
  match t1, t2 with
  (* Identical types *)
  | t1, t2 when t1 = t2 -> Some t1
  
  (* Conservative numeric type promotions - only allow explicit cases that are safe *)
  | U8, U16 | U16, U8 -> Some U16
  | U8, U32 | U32, U8 | U16, U32 | U32, U16 -> Some U32
  | U8, U64 | U64, U8 | U16, U64 | U64, U16 | U32, U64 | U64, U32 -> Some U64
  | I8, I16 | I16, I8 -> Some I16  
  | I8, I32 | I32, I8 | I16, I32 | I32, I16 -> Some I32
  | I8, I64 | I64, I8 | I16, I64 | I64, I16 | I32, I64 | I64, I32 -> Some I64
  
  (* Array types *)
  | Array (t1, s1), Array (t2, s2) when s1 = s2 ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Array (unified, s1))
       | None -> None)
  
  (* Pointer types *)
  | Pointer t1, Pointer t2 ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Pointer unified)
       | None -> None)
  
  (* Option types *)
  | Option t1, Option t2 ->
      (match unify_types t1 t2 with
       | Some unified -> Some (Option unified)
       | None -> None)
  
  (* Result types *)
  | Result (ok1, err1), Result (ok2, err2) ->
      (match unify_types ok1 ok2, unify_types err1 err2 with
       | Some unified_ok, Some unified_err -> Some (Result (unified_ok, unified_err))
       | _ -> None)
  
  (* Function types *)
  | Function (params1, ret1), Function (params2, ret2) when List.length params1 = List.length params2 ->
      let unified_params = List.map2 unify_types params1 params2 in
      if List.for_all (function Some _ -> true | None -> false) unified_params then
        let params = List.map (function Some t -> t | None -> assert false) unified_params in
        match unify_types ret1 ret2 with
        | Some unified_ret -> Some (Function (params, unified_ret))
        | None -> None
      else None
  
  (* Map types *)
  | Map (k1, v1, mt1), Map (k2, v2, mt2) when mt1 = mt2 ->
      (match unify_types k1 k2, unify_types v1 v2 with
       | Some unified_k, Some unified_v -> Some (Map (unified_k, unified_v, mt1))
       | _ -> None)
  
  (* No unification possible *)
  | _ -> None

(** Get built-in function signatures *)
let get_builtin_function_signature name =
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
       | [_map_name; "lookup"] -> Some ([Pointer U8], Option (Pointer U8))
       | [_map_name; "insert"] -> Some ([Pointer U8; Pointer U8], U32)
       | [_map_name; "update"] -> Some ([Pointer U8; Pointer U8], U32)
       | [_map_name; "delete"] -> Some ([Pointer U8], U32)
       | _ -> None)
  
  (* Utility functions *)
  | "bpf_trace_printk" -> Some ([Pointer U8; U32], U32)
  | "bpf_get_current_pid_tgid" -> Some ([], U64)
  | "bpf_ktime_get_ns" -> Some ([], U64)
  
  (* Type conversion functions *)
  | "Protocol.from_u8" -> Some ([U8], Option (Enum "Protocol"))
  
  | _ -> None

(** Type check literals *)
let type_check_literal lit pos =
  let typ = match lit with
    | IntLit _ -> U32  (* Default integer type *)
    | StringLit _ -> Pointer U8  (* String is pointer to u8 *)
    | CharLit _ -> Char
    | BoolLit _ -> Bool
  in
  { texpr_desc = TLiteral lit; texpr_type = typ; texpr_pos = pos }

(** Type check identifier *)
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
      (* Check if it's a map - but don't create a Map type for standalone identifiers *)
      if Hashtbl.mem ctx.maps name then
        type_error ("Map '" ^ name ^ "' cannot be used as a standalone identifier. Use map[key] for map access.") pos
      else
        type_error ("Undefined variable: " ^ name) pos

(** Type check function call *)
let rec type_check_function_call ctx name args pos =
  (* Type check arguments first *)
  let typed_args = List.map (type_check_expression ctx) args in
  let arg_types = List.map (fun e -> e.texpr_type) typed_args in
  
  (* Check if it's a built-in function *)
  match get_builtin_function_signature name with
  | Some (expected_params, return_type) ->
      if List.length expected_params = List.length arg_types then
        let unified = List.map2 unify_types expected_params arg_types in
        if List.for_all (function Some _ -> true | None -> false) unified then
          { texpr_desc = TFunctionCall (name, typed_args); texpr_type = return_type; texpr_pos = pos }
        else
          type_error ("Type mismatch in function call: " ^ name) pos
      else
        type_error ("Wrong number of arguments for function: " ^ name) pos
  
  (* Check user-defined functions *)
  | None ->
      try
        let (expected_params, return_type) = Hashtbl.find ctx.functions name in
        if List.length expected_params = List.length arg_types then
          let unified = List.map2 unify_types expected_params arg_types in
          if List.for_all (function Some _ -> true | None -> false) unified then
            { texpr_desc = TFunctionCall (name, typed_args); texpr_type = return_type; texpr_pos = pos }
          else
            type_error ("Type mismatch in function call: " ^ name) pos
        else
          type_error ("Wrong number of arguments for function: " ^ name) pos
      with Not_found ->
        type_error ("Undefined function: " ^ name) pos

(** Type check array access *)
and type_check_array_access ctx arr idx pos =
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
       (match unify_types map_decl.key_type typed_idx.texpr_type with
        | Some _ -> 
            (* Create a synthetic map type for the result *)
            let typed_arr = { texpr_desc = TIdentifier map_name; texpr_type = Map (map_decl.key_type, map_decl.value_type, map_decl.map_type); texpr_pos = arr.expr_pos } in
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
        | Map (key_type, value_type, _) ->
            (* This shouldn't happen anymore, but handle it for safety *)
            (match unify_types key_type typed_idx.texpr_type with
             | Some _ -> { texpr_desc = TArrayAccess (typed_arr, typed_idx); texpr_type = value_type; texpr_pos = pos }
             | None -> type_error ("Map key type mismatch") pos)
        | _ ->
            type_error "Cannot index non-array/non-map type" pos))

(** Type check field access *)
and type_check_field_access ctx obj field pos =
  let typed_obj = type_check_expression ctx obj in
  
  match typed_obj.texpr_type with
  | Struct struct_name ->
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
      type_error "Cannot access field of non-struct type" pos

(** Type check binary operation *)
and type_check_binary_op ctx left op right pos =
  let typed_left = type_check_expression ctx left in
  let typed_right = type_check_expression ctx right in
  
  let result_type = match op with
    (* Arithmetic operations *)
    | Add | Sub | Mul | Div | Mod ->
        (* Handle pointer arithmetic *)
        (match typed_left.texpr_type, typed_right.texpr_type, op with
         (* Pointer - Pointer = size (pointer subtraction) *)
         | Pointer _, Pointer _, Sub -> U64  (* Return size type for pointer difference *)
         (* Pointer + Integer = Pointer (pointer offset) *)
         | Pointer t, (U8|U16|U32|U64|I8|I16|I32|I64), Add -> Pointer t
         (* Integer + Pointer = Pointer (pointer offset) *)
         | (U8|U16|U32|U64|I8|I16|I32|I64), Pointer t, Add -> Pointer t
         (* Pointer - Integer = Pointer (pointer offset) *)
         | Pointer t, (U8|U16|U32|U64|I8|I16|I32|I64), Sub -> Pointer t
         (* Regular numeric arithmetic *)
         | _ ->
             (* Try standard unification first *)
             (match unify_types typed_left.texpr_type typed_right.texpr_type with
              | Some unified_type ->
                  (match unified_type with
                   | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 -> unified_type
                   | _ -> type_error "Arithmetic operations require numeric types" pos)
              | None ->
                  (* Special case: allow U32 literals to be promoted to U64 in arithmetic *)
                  (match typed_left.texpr_type, typed_right.texpr_type with
                   | U64, U32 -> U64  (* Promote U32 to U64 *)
                   | U32, U64 -> U64  (* Promote U32 to U64 *)
                   | I64, I32 -> I64  (* Promote I32 to I64 *)
                   | I32, I64 -> I64  (* Promote I32 to I64 *)
                   | _ -> type_error "Cannot unify types for arithmetic operation" pos)))
    
    (* Comparison operations *)
    | Eq | Ne | Lt | Le | Gt | Ge ->
        (match unify_types typed_left.texpr_type typed_right.texpr_type with
         | Some _ -> Bool
         | None ->
             (* Special case: allow U32 literals to be compared with U64 *)
             (match typed_left.texpr_type, typed_right.texpr_type with
              | U64, U32 -> Bool  (* Allow U64 > U32 comparisons *)
              | U32, U64 -> Bool  (* Allow U32 > U64 comparisons *)
              | I64, I32 -> Bool  (* Allow I64 > I32 comparisons *)
              | I32, I64 -> Bool  (* Allow I32 > I64 comparisons *)
              | _ -> type_error "Cannot compare incompatible types" pos))
    
    (* Logical operations *)
    | And | Or ->
        if typed_left.texpr_type = Bool && typed_right.texpr_type = Bool then
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

(** Type check expression *)
and type_check_expression ctx expr =
  match expr.expr_desc with
  | Literal lit -> type_check_literal lit expr.expr_pos
  | Identifier name -> type_check_identifier ctx name expr.expr_pos
  | FunctionCall (name, args) -> type_check_function_call ctx name args expr.expr_pos
  | ArrayAccess (arr, idx) -> type_check_array_access ctx arr idx expr.expr_pos
  | FieldAccess (obj, field) -> type_check_field_access ctx obj field expr.expr_pos
  | BinaryOp (left, op, right) -> type_check_binary_op ctx left op right expr.expr_pos
  | UnaryOp (op, expr) -> type_check_unary_op ctx op expr expr.expr_pos

(** Type check statement *)
let rec type_check_statement ctx stmt =
  match stmt.stmt_desc with
  | ExprStmt expr ->
      let typed_expr = type_check_expression ctx expr in
      { tstmt_desc = TExprStmt typed_expr; tstmt_pos = stmt.stmt_pos }
  
  | Assignment (name, expr) ->
      let typed_expr = type_check_expression ctx expr in
      (try
         let var_type = Hashtbl.find ctx.variables name in
         (match unify_types var_type typed_expr.texpr_type with
          | Some _ -> 
              { tstmt_desc = TAssignment (name, typed_expr); tstmt_pos = stmt.stmt_pos }
          | None ->
              type_error ("Cannot assign " ^ string_of_bpf_type typed_expr.texpr_type ^ 
                         " to variable of type " ^ string_of_bpf_type var_type) stmt.stmt_pos)
       with Not_found ->
         type_error ("Undefined variable: " ^ name) stmt.stmt_pos)
  
  | IndexAssignment (map_expr, key_expr, value_expr) ->
      let typed_key = type_check_expression ctx key_expr in
      let typed_value = type_check_expression ctx value_expr in
      
      (* Check if this is map assignment *)
      (match map_expr.expr_desc with
       | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           (* This is map assignment *)
           let map_decl = Hashtbl.find ctx.maps map_name in
           (* Check key type compatibility *)
           (match unify_types map_decl.key_type typed_key.texpr_type with
            | Some _ -> ()
            | None -> type_error ("Map key type mismatch") stmt.stmt_pos);
           (* Check value type compatibility *)
           (match unify_types map_decl.value_type typed_value.texpr_type with
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
            (match unify_types declared_type typed_expr.texpr_type with
             | Some unified -> unified
             | None -> type_error ("Type mismatch in declaration") stmt.stmt_pos)
        | None -> typed_expr.texpr_type
      in
      Hashtbl.replace ctx.variables name var_type;
      { tstmt_desc = TDeclaration (name, var_type, typed_expr); tstmt_pos = stmt.stmt_pos }
  
  | Return expr_opt ->
      let typed_expr_opt = Option.map (type_check_expression ctx) expr_opt in
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
      let typed_body = List.map (type_check_statement ctx) body in
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

(** Type check function *)
let type_check_function ctx func =
  (* Save current state *)
  let old_variables = Hashtbl.copy ctx.variables in
  let old_function = ctx.current_function in
  ctx.current_function <- Some func.func_name;
  
  (* Add parameters to scope with proper type resolution *)
  let resolved_params = List.map (fun (name, typ) -> 
    let resolved_type = resolve_user_type typ in
    Hashtbl.replace ctx.variables name resolved_type;
    (name, resolved_type)
  ) func.func_params in
  
  (* Type check function body *)
  let typed_body = List.map (type_check_statement ctx) func.func_body in
  
  (* Determine return type *)
  let return_type = match func.func_return_type with
    | Some t -> resolve_user_type t
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
    tfunc_pos = func.func_pos;
  } in
  
  (* Register function signature *)
  let param_types = List.map snd func.func_params in
  Hashtbl.replace ctx.functions func.func_name (param_types, return_type);
  
  typed_func

(** Type check program *)
let type_check_program ctx prog =
  let old_program = ctx.current_program in
  ctx.current_program <- Some prog.prog_name;
  
  (* Add program-scoped maps to context *)
  List.iter (fun map_decl ->
    Hashtbl.replace ctx.maps map_decl.name map_decl
  ) prog.prog_maps;
  
  (* Type check all functions *)
  let typed_functions = List.map (type_check_function ctx) prog.prog_functions in
  
  (* Remove program-scoped maps from context (restore scope) *)
  List.iter (fun map_decl ->
    Hashtbl.remove ctx.maps map_decl.name
  ) prog.prog_maps;
  
  ctx.current_program <- old_program;
  
  {
    tprog_name = prog.prog_name;
    tprog_type = prog.prog_type;
    tprog_functions = typed_functions;
    tprog_maps = prog.prog_maps; (* Include program-scoped maps *)
    tprog_pos = prog.prog_pos;
  }

(** Type check userspace block - only validates, doesn't transform *)
let type_check_userspace ctx userspace_block =
  (* Userspace code should only have access to global maps, not program-scoped maps *)
  (* The global maps are already in ctx.maps from the first pass *)
  
  (* Type check all userspace functions for validation *)
  List.iter (fun func ->
    let _ = type_check_function ctx func in
    ()
  ) userspace_block.userspace_functions;
  
  () (* No return value needed - validation only *)

(** Main type checking entry point *)
let type_check_ast ast =
  let ctx = create_context () in
  
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
  
  (* Second pass: type check programs, functions, and userspace blocks *)
  List.fold_left (fun acc decl ->
    match decl with
    | Program prog ->
        let typed_prog = type_check_program ctx prog in
        typed_prog :: acc
    | GlobalFunction func ->
        let _ = type_check_function ctx func in
        acc
    | Userspace userspace_block ->
        let _ = type_check_userspace ctx userspace_block in
        acc
    | _ -> acc
  ) [] ast |> List.rev

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
  let expr_desc = match texpr.texpr_desc with
    | TLiteral lit -> Literal lit
    | TIdentifier name -> Identifier name
    | TFunctionCall (name, args) -> FunctionCall (name, List.map typed_expr_to_expr args)
    | TArrayAccess (arr, idx) -> ArrayAccess (typed_expr_to_expr arr, typed_expr_to_expr idx)
    | TFieldAccess (obj, field) -> FieldAccess (typed_expr_to_expr obj, field)
    | TBinaryOp (left, op, right) -> BinaryOp (typed_expr_to_expr left, op, typed_expr_to_expr right)
    | TUnaryOp (op, expr) -> UnaryOp (op, typed_expr_to_expr expr)
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
  { expr_desc; expr_pos = texpr.texpr_pos; expr_type = safe_expr_type }

let rec typed_stmt_to_stmt tstmt =
  let stmt_desc = match tstmt.tstmt_desc with
    | TExprStmt expr -> ExprStmt (typed_expr_to_expr expr)
    | TAssignment (name, expr) -> Assignment (name, typed_expr_to_expr expr)
    | TIndexAssignment (map_expr, key_expr, value_expr) -> 
        IndexAssignment (typed_expr_to_expr map_expr, typed_expr_to_expr key_expr, typed_expr_to_expr value_expr)
    | TDeclaration (name, typ, expr) -> Declaration (name, Some typ, typed_expr_to_expr expr)
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
  in
  { stmt_desc; stmt_pos = tstmt.tstmt_pos }

let typed_function_to_function tfunc =
  { func_name = tfunc.tfunc_name;
    func_params = tfunc.tfunc_params;
    func_return_type = Some tfunc.tfunc_return_type;
    func_body = List.map typed_stmt_to_stmt tfunc.tfunc_body;
    func_pos = tfunc.tfunc_pos }

let typed_program_to_program tprog original_prog =
  { prog_name = tprog.tprog_name;
    prog_type = tprog.tprog_type;
    prog_functions = List.map typed_function_to_function tprog.tprog_functions;
    prog_maps = original_prog.prog_maps;  (* Preserve original map declarations *)
    prog_pos = tprog.tprog_pos }

(** Convert typed AST back to annotated AST declarations *)
let typed_ast_to_annotated_ast typed_ast original_ast =
  (* Create a mapping of original programs by name *)
  let original_programs = List.fold_left (fun acc decl ->
    match decl with
    | Program prog -> (prog.prog_name, prog) :: acc
    | _ -> acc
  ) [] original_ast in
  
  let annotated_programs = List.map (fun tprog ->
    (* Find corresponding original program *)
    let original_prog = try 
      List.assoc tprog.tprog_name original_programs
    with Not_found -> 
      failwith ("No original program found for " ^ tprog.tprog_name)
    in
    typed_program_to_program tprog original_prog
  ) typed_ast in
  
  (* Create a mapping of annotated programs by name *)
  let annotated_prog_map = List.fold_left (fun acc prog ->
    (prog.prog_name, prog) :: acc
  ) [] annotated_programs in
  
  (* Reconstruct the declarations list, preserving order and non-program declarations *)
  List.map (function
    | Program orig_prog -> 
        (* Find corresponding annotated program *)
        let annotated_prog = try
          List.assoc orig_prog.prog_name annotated_prog_map
        with Not_found ->
          failwith ("No annotated program found for " ^ orig_prog.prog_name)
        in
        Program annotated_prog
    | other_decl -> other_decl  (* Keep maps, types, etc. unchanged *)
  ) original_ast 

(** PHASE 1: Type check and annotate AST - main entry point for IR generator *)
let type_check_and_annotate_ast ast =
  (* Perform type checking to get typed AST *)
  let typed_programs = type_check_ast ast in
  
  (* Convert back to annotated AST (original AST with expr_type fields populated) *)
  let annotated_ast = typed_ast_to_annotated_ast typed_programs ast in
  
  (* Return both the annotated AST (for IR generator) and typed programs (for other uses) *)
  (annotated_ast, typed_programs) 