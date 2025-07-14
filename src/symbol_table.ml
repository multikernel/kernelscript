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

(** Symbol Table for KernelScript *)

open Ast

(** Symbol kinds that can be stored in the symbol table *)
type symbol_kind =
  | Variable of bpf_type
  | ConstVariable of bpf_type * literal  (* Type and constant value *)
  | GlobalVariable of bpf_type * expr option  (* Type and optional initial value *)
  | Function of bpf_type list * bpf_type  (* Parameter types, return type *)
  | TypeDef of type_def
  | GlobalMap of map_declaration
  | Parameter of bpf_type
  | EnumConstant of string * int option  (* enum_name, value *)
  | Config of config_declaration

(** Symbol information *)
type symbol = {
  name: string;
  kind: symbol_kind;
  scope: string list;  (* scope path: ["program", "function"] *)
  visibility: visibility;
  position: position;
}

and visibility = Public | Private

(** Scope types *)
type scope_type =
  | GlobalScope
  | ProgramScope of string
  | FunctionScope of string * string  (* program_name, function_name *)
  | BlockScope

(** Symbol table structure *)
type symbol_table = {
  symbols: (string, symbol list) Hashtbl.t;  (* name -> symbols *)
  scopes: scope_type list;  (* current scope stack *)
  current_program: string option;
  current_function: string option;
  global_maps: (string, map_declaration) Hashtbl.t;
  project_name: string;  (* project name for pin path generation *)
}

(** Symbol table exceptions *)
exception Symbol_error of string * position
exception Scope_error of string * position
exception Visibility_error of string * position

(** Create new symbol table *)
let create_symbol_table ?(project_name = "kernelscript") () = {
  symbols = Hashtbl.create 128;
  scopes = [GlobalScope];
  current_program = None;
  current_function = None;
  global_maps = Hashtbl.create 32;
  project_name;
}

(** Helper functions *)
let symbol_error msg pos = raise (Symbol_error (msg, pos))
let scope_error msg pos = raise (Scope_error (msg, pos))
let visibility_error msg pos = raise (Visibility_error (msg, pos))

(** Get current scope path *)
let get_scope_path table =
  let rec build_path scopes acc block_depth =
    match scopes with
    | [] -> List.rev acc
    | GlobalScope :: rest -> build_path rest acc block_depth
    | ProgramScope name :: rest -> build_path rest (name :: acc) block_depth
    | FunctionScope (prog, func) :: rest -> build_path rest (func :: prog :: acc) block_depth
    | BlockScope :: rest -> 
        let block_id = "block" ^ string_of_int block_depth in
        build_path rest (block_id :: acc) (block_depth + 1)
  in
  build_path table.scopes [] 0

(** Add symbol to table *)
let add_symbol table name kind visibility pos =
  let scope_path = get_scope_path table in
  let symbol = {
    name;
    kind;
    scope = scope_path;
    visibility;
    position = pos;
  } in
  
  (* Get existing symbols with same name *)
  let existing = try Hashtbl.find table.symbols name with Not_found -> [] in
  
  (* Check for conflicts in same scope *)
  let same_scope_conflict = List.exists (fun s ->
    s.scope = scope_path && 
    match s.kind, kind with
    (* Allow function overloading with different signatures *)
    | Function (params1, ret1), Function (params2, ret2) ->
        params1 = params2 && ret1 = ret2
    (* No other conflicts allowed in same scope *)
    | _ -> true
  ) existing in
  
  if same_scope_conflict then
    symbol_error ("Symbol already defined in current scope: " ^ name) pos
  else
    Hashtbl.replace table.symbols name (symbol :: existing)

(** Enter new scope *)
let enter_scope table scope_type =
  let new_scopes = scope_type :: table.scopes in
  (* Create new hashtables to avoid sharing state *)
  let new_symbols = Hashtbl.copy table.symbols in
  let new_global_maps = Hashtbl.copy table.global_maps in
  let new_table = { 
    symbols = new_symbols;
    scopes = new_scopes;
    current_program = table.current_program;
    current_function = table.current_function;
    global_maps = new_global_maps;
    project_name = table.project_name;
  } in
  match scope_type with
  | ProgramScope name -> 
      { new_table with current_program = Some name }
  | FunctionScope (prog, func) -> 
      { new_table with current_program = Some prog; current_function = Some func }
  | _ -> new_table

(** Exit current scope *)
let exit_scope table =
  match table.scopes with
  | [] -> scope_error "Cannot exit global scope" { line = 0; column = 0; filename = "" }
  | [GlobalScope] -> scope_error "Cannot exit global scope" { line = 0; column = 0; filename = "" }
  | _scope :: rest ->
      (* Create new hashtables to avoid sharing state *)
      let new_symbols = Hashtbl.copy table.symbols in
      let new_global_maps = Hashtbl.copy table.global_maps in
      let new_table = { 
        symbols = new_symbols;
        scopes = rest;
        current_program = table.current_program;
        current_function = table.current_function;
        global_maps = new_global_maps;
        project_name = table.project_name;
      } in
      match rest with
      | ProgramScope name :: _ -> { new_table with current_program = Some name; current_function = None }
      | GlobalScope :: _ -> { new_table with current_program = None; current_function = None }
      | _ -> new_table

(** Lookup symbol with scope resolution *)
let lookup_symbol table name =
  try
    let symbols = Hashtbl.find table.symbols name in
    let current_path = get_scope_path table in
    
    (* Sort symbols by scope proximity (most specific first) *)
    let scored_symbols = List.map (fun symbol ->
      let score = 
        if symbol.scope = current_path then 1000  (* exact scope match *)
        else if List.length symbol.scope = 0 then 1  (* global scope *)
        else
          (* Calculate scope overlap *)
          let rec overlap s1 s2 acc =
            match s1, s2 with
            | h1 :: t1, h2 :: t2 when h1 = h2 -> overlap t1 t2 (acc + 1)
            | _ -> acc
          in
          overlap current_path symbol.scope 0
      in
      (score, symbol)
    ) symbols in
    
    let sorted_symbols = List.sort (fun (s1, _) (s2, _) -> compare s2 s1) scored_symbols in
    
    (* Return the best match *)
    match sorted_symbols with
    | (_, symbol) :: _ -> Some symbol
    | [] -> None
  with Not_found -> None

(** Check if symbol is visible from current scope *)
let is_visible table symbol =
  let current_path = get_scope_path table in
  match symbol.visibility with
  | Public -> true
  | Private ->
      (* Private symbols are visible within same program *)
      (* Extract the program name from scope paths, ignoring block scopes *)
      let extract_program_from_path path =
        List.find_opt (fun scope -> not (String.starts_with ~prefix:"block" scope)) path
      in
      match extract_program_from_path symbol.scope, extract_program_from_path current_path with
      | Some prog, Some current_prog -> prog = current_prog
      | None, _ -> true  (* global private symbols are visible *)
      | _ -> false

(** Check if a symbol is a const variable *)
let is_const_variable symbol =
  match symbol.kind with
  | ConstVariable _ -> true
  | _ -> false

(** Get the value of a const variable *)
let get_const_value symbol =
  match symbol.kind with
  | ConstVariable (_, value) -> Some value
  | _ -> None

(** Process enum values with automatic numbering *)
let process_enum_values values =
  let rec process_values acc current_value = function
    | [] -> List.rev acc
    | (const_name, None) :: rest ->
        (* Auto-assign current value *)
        let processed_value = (const_name, Some current_value) in
        process_values (processed_value :: acc) (current_value + 1) rest
    | (const_name, Some explicit_value) :: rest ->
        (* Use explicit value and update current value *)
        let processed_value = (const_name, Some explicit_value) in
        process_values (processed_value :: acc) (explicit_value + 1) rest
  in
  process_values [] 0 values

(** Add type definition to symbol table *)
let add_type_def table type_def pos =
  match type_def with
  | StructDef (name, _, _) | EnumDef (name, _, _) | TypeAlias (name, _) ->
      add_symbol table name (TypeDef type_def) Public pos;
      
      (* For enums, also add enum constants with auto-value assignment *)
      (match type_def with
       | EnumDef (enum_name, values, _) ->
           let processed_values = process_enum_values values in
           List.iter (fun (const_name, value) ->
             (* Add both namespaced and direct constant names *)
             let full_name = enum_name ^ "::" ^ const_name in
             add_symbol table full_name (EnumConstant (enum_name, value)) Public pos;
             add_symbol table const_name (EnumConstant (enum_name, value)) Public pos
           ) processed_values
       | _ -> ())

(** Add map declaration to symbol table *)
let add_map_decl table map_decl =
  let pos = map_decl.map_pos in
  if map_decl.is_global then (
    (* Global map *)
    Hashtbl.replace table.global_maps map_decl.name map_decl;
    add_symbol table map_decl.name (GlobalMap map_decl) Public pos
  ) else (
    symbol_error "All maps must be declared as global" pos
  )

(** Add function with enhanced validation *)
let add_function table func visibility =
  (* Special validation for main function *)
  if func.func_name = "main" then (
    (* Check if main function already exists *)
    let existing_main = List.filter_map (fun s ->
      match s.kind with
      | Function _ when s.name = "main" -> Some s
      | _ -> None
    ) (try
        let symbols = Hashtbl.find table.symbols "main" in
        symbols
      with Not_found -> []) in
    
    if List.length existing_main > 0 then
      symbol_error ("Duplicate main function - only one main function allowed per program") func.func_pos
  );
  
  let param_types = List.map snd func.func_params in
  let return_type = match func.func_return_type with
    | Some t -> t
    | None -> U32  (* default return type for functions without explicit return *)
  in
  add_symbol table func.func_name (Function (param_types, return_type)) visibility func.func_pos

(** Add variable to symbol table *)
let add_variable table name var_type pos =
  let kind = match table.scopes with
    | FunctionScope _ :: _ when List.exists (fun (param_name, _) -> param_name = name) 
        (match table.current_function with Some _ -> [] | None -> []) -> Parameter var_type
    | _ -> Variable var_type
  in
  add_symbol table name kind Private pos

(** Add config declaration to symbol table *)
let add_config_decl table config_decl =
  let pos = config_decl.config_pos in
  add_symbol table config_decl.config_name (Config config_decl) Public pos

(** Add global variable declaration to symbol table *)
let add_global_var_decl table global_var_decl =
  let pos = global_var_decl.global_var_pos in
  let var_type = match global_var_decl.global_var_type with
    | Some t -> t
    | None -> 
        (* If no type specified, infer from initial value *)
        (match global_var_decl.global_var_init with
         | Some expr -> 
             (match expr.expr_desc with
              | Literal (IntLit (_, _)) -> U32  (* Default integer type *)
              | Literal (StringLit s) -> Str (String.length s + 1)  (* String length + null terminator *)
              | Literal (BoolLit _) -> Bool
              | Literal (CharLit _) -> Char
              | Literal (NullLit) -> Pointer U8  (* Default pointer type *)
              | Literal (ArrayLit init_style) -> 
                  (* Infer array size from enhanced array initialization *)
                  (match init_style with
                   | ZeroArray -> Array (U32, 0)  (* Size must be inferred from context *)
                   | FillArray _ -> Array (U32, 0)  (* Size must be inferred from context *)
                   | ExplicitArray elems -> Array (U32, List.length elems)  (* Size from explicit elements *))
              | UnaryOp (Neg, _) -> I32  (* Negative expressions default to signed *)
              | _ -> U32)  (* Default to U32 for other expressions *)
         | None -> U32)  (* Default type when no type or value specified *)
  in
  add_symbol table global_var_decl.global_var_name (GlobalVariable (var_type, global_var_decl.global_var_init)) Public pos

(** Check if map is global *)
let is_global_map table name =
  Hashtbl.mem table.global_maps name

(** Get map declaration *)
let get_map_declaration table name =
  (* First check global maps *)
  if Hashtbl.mem table.global_maps name then
    Some (Hashtbl.find table.global_maps name)
  else
    None

(** Validate map access *)
let validate_map_access table map_name pos =
  match get_map_declaration table map_name with
  | Some map_decl -> map_decl
  | None -> symbol_error ("Undefined map: " ^ map_name) pos

(** Get all symbols in current scope *)
let get_current_scope_symbols table =
  let current_path = get_scope_path table in
  Hashtbl.fold (fun _name symbols acc ->
    let scope_symbols = List.filter (fun s -> s.scope = current_path) symbols in
    scope_symbols @ acc
  ) table.symbols []

(** Get all global symbols *)
let get_global_symbols table =
  Hashtbl.fold (fun _name symbols acc ->
    let global_symbols = List.filter (fun s -> s.scope = []) symbols in
    global_symbols @ acc
  ) table.symbols []

(** Build symbol table from AST with optional builtins *)
let rec build_symbol_table ?(project_name = "kernelscript") ?builtin_asts ast =
  let table = create_symbol_table ~project_name () in
  
  (* Load builtin definitions if provided *)
  (match builtin_asts with
   | Some builtins -> List.iter (List.iter (process_declaration table)) builtins
   | None -> ());
  
  List.iter (process_declaration table) ast;
  table

and process_declaration_accumulate table declaration =
  match declaration with
  | Ast.TypeDef type_def ->
      let pos = { line = 1; column = 1; filename = "" } in  (* TODO: get actual position *)
      add_type_def table type_def pos;
      table
      
  | Ast.MapDecl map_decl ->
      add_map_decl table map_decl;
      table
      
  | Ast.GlobalFunction func ->
      add_function table func Public;
      (* Enter function scope to process function body *)
      let table_with_func = enter_scope table (FunctionScope ("global", func.func_name)) in
      (* Add function parameters to scope *)
      List.iter (fun (param_name, param_type) ->
        add_variable table_with_func param_name param_type func.func_pos
      ) func.func_params;
      (* Process function body statements *)
      List.iter (process_statement table_with_func) func.func_body;
      let _ = exit_scope table_with_func in
      table
      
  | Ast.AttributedFunction attr_func ->
      (* Validate that main function is not used with attributes *)
      if attr_func.attr_function.func_name = "main" then
        symbol_error ("main function cannot have attributes (like @xdp) - use a different function name for eBPF programs") attr_func.attr_pos;
      
      (* Process attributed function as a global function *)
      add_function table attr_func.attr_function Public;
      
      let table_with_func = enter_scope table (FunctionScope ("global", attr_func.attr_function.func_name)) in
      
      (* Add function parameters to scope *)
      List.iter (fun (param_name, param_type) ->
        add_variable table_with_func param_name param_type attr_func.attr_function.func_pos
      ) attr_func.attr_function.func_params;
      
      (* Process function body statements *)
      List.iter (process_statement table_with_func) attr_func.attr_function.func_body;
      let _ = exit_scope table_with_func in
      table
      
  | Ast.ConfigDecl config_decl ->
      add_config_decl table config_decl;
      table
      
  | Ast.StructDecl struct_def ->
      let pos = { line = 1; column = 1; filename = "" } in
      let type_def = Ast.StructDef (struct_def.struct_name, struct_def.struct_fields, struct_def.kernel_defined) in
      add_type_def table type_def pos;
      table
      
  | Ast.GlobalVarDecl global_var_decl ->
      add_global_var_decl table global_var_decl;
      table
      
  | Ast.ImplBlock impl_block ->
      (* Add the impl block itself as a struct_ops symbol *)
      add_symbol table impl_block.impl_name (TypeDef (StructDef (impl_block.impl_name, [], true))) Public impl_block.impl_pos;
      
      (* Process impl block functions and add them to symbol table *)
      List.iter (fun item ->
        match item with
        | Ast.ImplFunction func ->
            add_function table func Public;
            let table_with_func = enter_scope table (FunctionScope ("global", func.func_name)) in
            List.iter (fun (param_name, param_type) ->
              add_variable table_with_func param_name param_type func.func_pos
            ) func.func_params;
            List.iter (process_statement table_with_func) func.func_body;
            let _ = exit_scope table_with_func in ()
        | Ast.ImplStaticField (_, _) -> ()  (* Static fields don't need symbol table processing *)
      ) impl_block.impl_items;
      table

and process_declaration table = function
  | Ast.TypeDef type_def ->
      let pos = { line = 1; column = 1; filename = "" } in  (* TODO: get actual position *)
      add_type_def table type_def pos
      
  | Ast.MapDecl map_decl ->
      add_map_decl table map_decl
      
  | Ast.GlobalFunction func ->
      add_function table func Public;
      (* Enter function scope to process function body *)
      let table_with_func = enter_scope table (FunctionScope ("global", func.func_name)) in
      (* Add function parameters to scope *)
      List.iter (fun (param_name, param_type) ->
        add_variable table_with_func param_name param_type func.func_pos
      ) func.func_params;
      (* Process function body statements *)
      List.iter (process_statement table_with_func) func.func_body;
      let _ = exit_scope table_with_func in ()
      
  | Ast.AttributedFunction attr_func ->
      (* Validate that main function is not used with attributes *)
      if attr_func.attr_function.func_name = "main" then
        symbol_error ("main function cannot have attributes (like @xdp) - use a different function name for eBPF programs") attr_func.attr_pos;
      
      (* Process attributed function as a global function *)
      add_function table attr_func.attr_function Public;
      (* Enter function scope to process function body *)
      let table_with_func = enter_scope table (FunctionScope ("global", attr_func.attr_function.func_name)) in
      (* Add function parameters to scope *)
      List.iter (fun (param_name, param_type) ->
        add_variable table_with_func param_name param_type attr_func.attr_function.func_pos
      ) attr_func.attr_function.func_params;
      (* Process function body statements *)
      List.iter (process_statement table_with_func) attr_func.attr_function.func_body;
      let _ = exit_scope table_with_func in ()
      
  | Ast.ConfigDecl config_decl ->
      add_config_decl table config_decl
      
  | Ast.StructDecl struct_def ->
      let pos = { line = 1; column = 1; filename = "" } in
      let type_def = Ast.StructDef (struct_def.struct_name, struct_def.struct_fields, struct_def.kernel_defined) in
      add_type_def table type_def pos
      
  | Ast.GlobalVarDecl global_var_decl ->
      add_global_var_decl table global_var_decl
      
  | Ast.ImplBlock impl_block ->
      (* Add the impl block itself as a struct_ops symbol *)
      add_symbol table impl_block.impl_name (TypeDef (StructDef (impl_block.impl_name, [], true))) Public impl_block.impl_pos;
      
      (* Process impl block functions and add them to symbol table *)
      List.iter (fun item ->
        match item with
        | Ast.ImplFunction func ->
            add_function table func Public;
            let table_with_func = enter_scope table (FunctionScope ("global", func.func_name)) in
            List.iter (fun (param_name, param_type) ->
              add_variable table_with_func param_name param_type func.func_pos
            ) func.func_params;
            List.iter (process_statement table_with_func) func.func_body;
            let _ = exit_scope table_with_func in ()
        | Ast.ImplStaticField (_, _) -> ()  (* Static fields don't need symbol table processing *)
      ) impl_block.impl_items

and process_statement table stmt =
  match stmt.stmt_desc with
  | Declaration (name, type_opt, expr_opt) ->
      (* Infer type from expression if not provided *)
      let var_type = match type_opt with
        | Some t -> t
        | None -> U32  (* TODO: implement expression type inference *)
      in
      add_variable table name var_type stmt.stmt_pos;
      (match expr_opt with
       | Some expr -> process_expression table expr
       | None -> ())
      
  | ConstDeclaration (name, type_opt, expr) ->
      (* Const declarations handled similarly but with const symbol kind *)
      let var_type = match type_opt with
        | Some t -> t
        | None -> U32  (* TODO: implement expression type inference *)
      in
      (* We'll need to extract the literal value from expr for const declarations *)
      let const_value = match expr.expr_desc with
        | Literal lit -> lit
        | _ -> IntLit (0, None) (* Default fallback *)
      in
      add_symbol table name (ConstVariable (var_type, const_value)) Private stmt.stmt_pos;
      process_expression table expr
      
  | Assignment (_name, expr) ->
      process_expression table expr
  | CompoundAssignment (_name, _, expr) ->
      process_expression table expr
  | CompoundIndexAssignment (map_expr, key_expr, _, value_expr) ->
      process_expression table map_expr;
      process_expression table key_expr;
      process_expression table value_expr
  | FieldAssignment (obj_expr, _field, value_expr) ->
      process_expression table obj_expr;
      process_expression table value_expr
      
  | ArrowAssignment (obj_expr, _field, value_expr) ->
      process_expression table obj_expr;
      process_expression table value_expr
      
  | IndexAssignment (map_expr, key_expr, value_expr) ->
      process_expression table map_expr;
      process_expression table key_expr;
      process_expression table value_expr
      
  | ExprStmt expr ->
      process_expression table expr
      
  | Return (Some expr) ->
      process_expression table expr
      
  | Return None -> ()
      
  | If (cond, then_stmts, else_opt) ->
      process_expression table cond;
      let table_with_block = enter_scope table BlockScope in
      List.iter (process_statement table_with_block) then_stmts;
      let _ = exit_scope table_with_block in
      (match else_opt with
       | Some else_stmts ->
           let table_with_else = enter_scope table BlockScope in
           List.iter (process_statement table_with_else) else_stmts;
           let _ = exit_scope table_with_else in ()
       | None -> ())
      
  | For (var_name, start_expr, end_expr, body) ->
      process_expression table start_expr;
      process_expression table end_expr;
      let table_with_loop = enter_scope table BlockScope in
      add_variable table_with_loop var_name U32 stmt.stmt_pos;  (* loop variable *)
      List.iter (process_statement table_with_loop) body;
      let _ = exit_scope table_with_loop in ()
      
  | ForIter (index_var, value_var, iterable_expr, body) ->
      process_expression table iterable_expr;
      let table_with_loop = enter_scope table BlockScope in
      add_variable table_with_loop index_var U32 stmt.stmt_pos;  (* index variable *)
      add_variable table_with_loop value_var U32 stmt.stmt_pos;  (* value variable - TODO: infer proper type *)
      List.iter (process_statement table_with_loop) body;
      let _ = exit_scope table_with_loop in ()
      
  | While (cond, body) ->
      process_expression table cond;
      let table_with_loop = enter_scope table BlockScope in
      List.iter (process_statement table_with_loop) body;
      let _ = exit_scope table_with_loop in ()

  | Delete (map_expr, key_expr) ->
      process_expression table map_expr;
      process_expression table key_expr
  
  | Break ->
      (* Break statements don't need symbol processing *)
      ()
  
  | Continue ->
      (* Continue statements don't need symbol processing *)
      ()
      
  | Try (try_stmts, catch_clauses) ->
      (* Process try block statements *)
      List.iter (process_statement table) try_stmts;
      (* Process catch clause bodies *)
      List.iter (fun clause ->
        List.iter (process_statement table) clause.catch_body
      ) catch_clauses
      
  | Throw _ ->
      (* Throw statements don't introduce new symbols *)
      ()
      
  | Defer expr ->
      (* Process the deferred expression for symbols *)
      process_expression table expr

and process_expression table expr =
  match expr.expr_desc with
  | Literal _ -> ()
  | Identifier name ->
      (* Validate that identifier is defined *)
      (match lookup_symbol table name with
       | Some symbol ->
           if not (is_visible table symbol) then
             visibility_error ("Symbol not visible: " ^ name) expr.expr_pos
       | None ->
           symbol_error ("Undefined symbol: " ^ name) expr.expr_pos)
           
  | Call (callee_expr, args) ->
      (* Unified call handling - process the callee expression and arguments *)
      (match callee_expr.expr_desc with
       | Identifier name ->
           (* Check if it's a built-in function, user-defined function, or function pointer variable *)
           (match Stdlib.is_builtin_function name with
            | true -> 
                (* This is a built-in function - it's always valid *)
                ()
            | false ->
                (* Check for user-defined function or function pointer variable *)
                (match lookup_symbol table name with
                 | Some { kind = Function _; _ } -> ()
                 | Some { kind = Variable _; _ } -> ()  (* Could be a function pointer - let type checker validate *)
                 | Some _ -> symbol_error (name ^ " is not a function or function pointer") expr.expr_pos
                 | None -> symbol_error ("Undefined function: " ^ name) expr.expr_pos))
       | _ ->
           (* Complex expression call (function pointer) - just process the expression *)
           process_expression table callee_expr);
      List.iter (process_expression table) args
      
  | TailCall (name, args) ->
      (* Validate tail call target exists (similar to function call) *)
      (match lookup_symbol table name with
       | Some { kind = Function _; _ } -> ()
       | Some _ -> symbol_error (name ^ " is not a function") expr.expr_pos
       | None -> symbol_error ("Undefined tail call target: " ^ name) expr.expr_pos);
      List.iter (process_expression table) args
      
  | ArrayAccess (arr, idx) ->
      process_expression table arr;
      process_expression table idx
      
  | FieldAccess (obj, field_name) ->
      (* Check if this is actually a config access *)
      (match obj.expr_desc with
       | Identifier config_name ->
           (* Check if it's a config first *)
           (match lookup_symbol table config_name with
            | Some { kind = Config config_decl; _ } ->
                (* This is a config access - validate the field *)
                let field_exists = List.exists (fun field ->
                  field.field_name = field_name
                ) config_decl.config_fields in
                if not field_exists then
                  symbol_error (Printf.sprintf "Config '%s' has no field '%s'" config_name field_name) expr.expr_pos
            | Some _ ->
                (* Not a config - treat as regular field access, just process the object *)
                process_expression table obj
            | None ->
                (* Undefined identifier *)
                symbol_error ("Undefined symbol: " ^ config_name) expr.expr_pos)
       | _ ->
           (* Not a simple identifier - regular field access *)
           process_expression table obj)
      
  | ArrowAccess (obj, _field) ->
      (* Arrow access (pointer->field) - just process the object *)
      process_expression table obj
      
  | BinaryOp (left, _op, right) ->
      process_expression table left;
      process_expression table right
      
  | UnaryOp (_op, expr) ->
      process_expression table expr
      
  | ConfigAccess (config_name, field_name) ->
      (* Validate that config exists and field is valid *)
      (match lookup_symbol table config_name with
       | Some { kind = Config config_decl; _ } ->
           (* Validate that field exists in config *)
           let field_exists = List.exists (fun field ->
             field.field_name = field_name
           ) config_decl.config_fields in
           if not field_exists then
             symbol_error (Printf.sprintf "Config '%s' has no field '%s'" config_name field_name) expr.expr_pos
       | Some _ -> 
           symbol_error (config_name ^ " is not a config") expr.expr_pos
       | None -> 
           symbol_error ("Undefined config: " ^ config_name) expr.expr_pos)
           
  | StructLiteral (struct_name, field_assignments) ->
      (* Validate that struct exists *)
      (match lookup_symbol table struct_name with
       | Some { kind = TypeDef (StructDef (_, _, _)); _ } ->
           (* Process field assignment expressions *)
           List.iter (fun (_, field_expr) -> process_expression table field_expr) field_assignments
       | Some _ -> 
           symbol_error (struct_name ^ " is not a struct") expr.expr_pos
       | None -> 
           symbol_error ("Undefined struct: " ^ struct_name) expr.expr_pos)
           
  | Match (matched_expr, arms) ->
      (* Process the matched expression *)
      process_expression table matched_expr;
      (* Process all arms *)
      List.iter (fun arm ->
        (* Process the arm body *)
        (match arm.arm_body with
         | SingleExpr expr -> process_expression table expr
         | Block stmts -> List.iter (process_statement table) stmts);
        (* Validate the pattern if it's an identifier *)
        (match arm.arm_pattern with
         | IdentifierPattern name ->
             (match lookup_symbol table name with
              | Some _ -> () (* Found, all good *)
              | None -> symbol_error ("Undefined identifier in pattern: " ^ name) arm.arm_pos)
         | ConstantPattern _ | DefaultPattern -> ())
      ) arms

(** Query functions for symbol table *)

(** Get all functions in a program *)
let get_program_functions table program_name =
  Hashtbl.fold (fun _name symbols acc ->
    let prog_functions = List.filter (fun s ->
      match s.kind, s.scope with
      | Function _, [prog] when prog = program_name -> true
      | _ -> false
    ) symbols in
    prog_functions @ acc
  ) table.symbols []

(** Get all variables in current function *)
let get_function_variables table =
  let current_path = get_scope_path table in
  Hashtbl.fold (fun _name symbols acc ->
    let func_vars = List.filter (fun s ->
      match s.kind with
      | Variable _ | Parameter _ when s.scope = current_path -> true
      | _ -> false
    ) symbols in
    func_vars @ acc
  ) table.symbols []

(** Get all type definitions *)
let get_type_definitions table =
  Hashtbl.fold (fun _name symbols acc ->
    let type_defs = List.filter (fun s ->
      match s.kind with
      | TypeDef _ -> true
      | _ -> false
    ) symbols in
    type_defs @ acc
  ) table.symbols []

(** Get all maps accessible from current scope *)
let get_accessible_maps table =
  let global_maps = Hashtbl.fold (fun name map_decl acc ->
    (name, map_decl) :: acc
  ) table.global_maps [] in
  
  global_maps

(** Lookup function by name *)
let lookup_function table func_name =
  match lookup_symbol table func_name with
  | Some { kind = Function (param_types, return_type); _ } ->
      (* Create a function record from the symbol information *)
      let params = List.mapi (fun i param_type -> ("param" ^ string_of_int i, param_type)) param_types in
      Some {
        func_name = func_name;
        func_params = params;
        func_return_type = Some return_type;
        func_body = [];
        func_scope = Ast.Userspace;
        func_pos = {filename = ""; line = 1; column = 1};
        tail_call_targets = [];
        is_tail_callable = false;
      }
  | _ -> None

(** Pretty printing for debugging *)
let string_of_symbol_kind = function
  | Variable t -> "variable:" ^ string_of_bpf_type t
  | ConstVariable (t, value) -> "const_variable:" ^ string_of_bpf_type t ^ "=" ^ string_of_literal value
  | GlobalVariable (t, _) -> "global_variable:" ^ string_of_bpf_type t
  | Function (params, ret) ->
      "function:(" ^ String.concat "," (List.map string_of_bpf_type params) ^ ")->" ^ string_of_bpf_type ret
  | TypeDef (StructDef (name, _, _)) -> "struct:" ^ name
  | TypeDef (EnumDef (name, _, _)) -> "enum:" ^ name
  | TypeDef (TypeAlias (name, t)) -> "alias:" ^ name ^ "=" ^ string_of_bpf_type t
  | GlobalMap _ -> "global_map"
  | Parameter t -> "param:" ^ string_of_bpf_type t
  | EnumConstant (enum_name, value) ->
      "enum_const:" ^ enum_name ^ "=" ^ (match value with Some v -> string_of_int v | None -> "auto")
  | Config config_decl -> "config:" ^ config_decl.config_name

let string_of_visibility = function
  | Public -> "pub"
  | Private -> "priv"

let string_of_symbol symbol =
  Printf.sprintf "%s [%s] %s (scope: %s)"
    symbol.name
    (string_of_visibility symbol.visibility)
    (string_of_symbol_kind symbol.kind)
    (String.concat "::" symbol.scope)

let print_symbol_table table =
  Printf.printf "Symbol Table:\n";
  Printf.printf "=============\n";
  Hashtbl.iter (fun _name symbols ->
    List.iter (fun symbol ->
      Printf.printf "%s\n" (string_of_symbol symbol)
    ) symbols
  ) table.symbols;
  
  Printf.printf "\nGlobal Maps:\n";
  Hashtbl.iter (fun name _map -> Printf.printf "  %s\n" name) table.global_maps