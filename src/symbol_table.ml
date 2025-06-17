(** Symbol Table for KernelScript *)

open Ast

(** Symbol kinds *)
type symbol_kind =
  | Variable of bpf_type
  | Function of bpf_type list * bpf_type  (* params, return *)
  | TypeDef of type_def
  | GlobalMap of map_declaration
  | LocalMap of map_declaration
  | Parameter of bpf_type
  | EnumConstant of string * int option  (* enum_name, value *)
  | Config of config_declaration
  | Program of program_def

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
  local_maps: (string * string, map_declaration) Hashtbl.t;  (* (program, map_name) -> map *)
}

(** Symbol table exceptions *)
exception Symbol_error of string * position
exception Scope_error of string * position
exception Visibility_error of string * position

(** Create new symbol table *)
let create_symbol_table () = {
  symbols = Hashtbl.create 128;
  scopes = [GlobalScope];
  current_program = None;
  current_function = None;
  global_maps = Hashtbl.create 32;
  local_maps = Hashtbl.create 64;
}

(** Helper functions *)
let symbol_error msg pos = raise (Symbol_error (msg, pos))
let scope_error msg pos = raise (Scope_error (msg, pos))
let visibility_error msg pos = raise (Visibility_error (msg, pos))

(** Get current scope path *)
let get_scope_path table =
  let rec build_path scopes acc =
    match scopes with
    | [] -> List.rev acc
    | GlobalScope :: rest -> build_path rest acc
    | ProgramScope name :: rest -> build_path rest (name :: acc)
    | FunctionScope (prog, func) :: rest -> build_path rest (func :: prog :: acc)
    | BlockScope :: rest -> build_path rest acc
  in
  build_path table.scopes []

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
  let new_local_maps = Hashtbl.copy table.local_maps in
  let new_table = { 
    symbols = new_symbols;
    scopes = new_scopes;
    current_program = table.current_program;
    current_function = table.current_function;
    global_maps = new_global_maps;
    local_maps = new_local_maps;
  } in
  match scope_type with
  | ProgramScope name -> 
      (* When entering a new program scope, filter out local maps from other programs *)
      let filtered_local_maps = Hashtbl.create 64 in
      Hashtbl.iter (fun (prog, map_name) map_decl ->
        if prog = name then
          Hashtbl.replace filtered_local_maps (prog, map_name) map_decl
      ) new_local_maps;
      { new_table with current_program = Some name; local_maps = filtered_local_maps }
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
      let new_local_maps = Hashtbl.copy table.local_maps in
      let new_table = { 
        symbols = new_symbols;
        scopes = rest;
        current_program = table.current_program;
        current_function = table.current_function;
        global_maps = new_global_maps;
        local_maps = new_local_maps;
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
      match symbol.scope, current_path with
      | prog :: _, current_prog :: _ -> prog = current_prog
      | [], _ -> true  (* global private symbols are visible *)
      | _ -> false

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
  | StructDef (name, _) | EnumDef (name, _) | TypeAlias (name, _) ->
      add_symbol table name (TypeDef type_def) Public pos;
      
      (* For enums, also add enum constants with auto-value assignment *)
      (match type_def with
       | EnumDef (enum_name, values) ->
           let processed_values = process_enum_values values in
           List.iter (fun (const_name, value) ->
             let full_name = enum_name ^ "::" ^ const_name in
             add_symbol table full_name (EnumConstant (enum_name, value)) Public pos
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
    (* Local map - must be inside a program *)
    match table.current_program with
    | Some prog_name ->
        let key = (prog_name, map_decl.name) in
        Hashtbl.replace table.local_maps key map_decl;
        add_symbol table map_decl.name (LocalMap map_decl) Private pos
    | None ->
        symbol_error "Local maps must be declared inside a program" pos
  )

(** Add function to symbol table *)
let add_function table func visibility =
  let param_types = List.map snd func.func_params in
  let return_type = match func.func_return_type with
    | Some t -> t
    | None -> U32  (* default return type *)
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

(** Add program declaration to symbol table *)
let add_program_decl table prog_decl =
  let pos = prog_decl.prog_pos in
  add_symbol table prog_decl.prog_name (Program prog_decl) Public pos

(** Check if map is global *)
let is_global_map table name =
  Hashtbl.mem table.global_maps name

(** Check if map is local to a program *)
let is_local_map table program_name map_name =
  Hashtbl.mem table.local_maps (program_name, map_name)

(** Get map declaration *)
let get_map_declaration table name =
  (* First check global maps *)
  if Hashtbl.mem table.global_maps name then
    Some (Hashtbl.find table.global_maps name)
  else
    (* Check local maps in current program *)
    match table.current_program with
    | Some prog_name ->
        let key = (prog_name, name) in
        if Hashtbl.mem table.local_maps key then
          Some (Hashtbl.find table.local_maps key)
        else None
    | None -> None

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

(** Build symbol table from AST *)
let rec build_symbol_table ast =
  let table = create_symbol_table () in
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
      
  | Ast.Program prog ->
      (* Add program as a symbol first *)
      add_program_decl table prog;
      
      let table_with_prog = enter_scope table (ProgramScope prog.prog_name) in
      
      (* Process program maps *)
      List.iter (fun map_decl ->
        add_map_decl table_with_prog map_decl
      ) prog.prog_maps;
      
      (* Process program functions and accumulate changes *)
      let final_table_prog = List.fold_left (fun acc_table func ->
        add_function acc_table func Private;
        acc_table
      ) table_with_prog prog.prog_functions in
      
      (* Merge the program-level symbols back to the main table *)
       Hashtbl.iter (fun name symbols ->
         let existing = try Hashtbl.find table.symbols name with Not_found -> [] in
         let prog_symbols = List.filter (fun s -> s.scope = [prog.prog_name]) symbols in
         if prog_symbols <> [] then
           Hashtbl.replace table.symbols name (existing @ prog_symbols)
       ) final_table_prog.symbols;
      
      table
      
  | Ast.ConfigDecl config_decl ->
      add_config_decl table config_decl;
      table
      
  | Ast.StructDecl struct_def ->
      let pos = { line = 1; column = 1; filename = "" } in
      let type_def = Ast.StructDef (struct_def.struct_name, struct_def.struct_fields) in
      add_type_def table type_def pos;
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
      
  | Ast.Program prog ->
      (* Add program as a symbol first *)
      add_program_decl table prog;
      
      let table_with_prog = enter_scope table (ProgramScope prog.prog_name) in
      
      (* Process program maps *)
      List.iter (fun map_decl ->
        add_map_decl table_with_prog map_decl
      ) prog.prog_maps;
      
      (* Process program structs *)
      List.iter (fun struct_def ->
        let pos = { line = 1; column = 1; filename = "" } in
        let type_def = Ast.StructDef (struct_def.struct_name, struct_def.struct_fields) in
        add_type_def table_with_prog type_def pos
      ) prog.prog_structs;
      
      (* Process program functions *)
      List.iter (fun func ->
        add_function table_with_prog func Private;
        (* Enter function scope to process function body *)
        let table_with_func = enter_scope table_with_prog (FunctionScope (prog.prog_name, func.func_name)) in
        (* Add function parameters to scope *)
        List.iter (fun (param_name, param_type) ->
          add_variable table_with_func param_name param_type func.func_pos
        ) func.func_params;
        (* Process function body statements *)
        List.iter (process_statement table_with_func) func.func_body;
        let _ = exit_scope table_with_func in ()
      ) prog.prog_functions;
      
      (* Manually merge symbols from program scope back to main table *)
      Hashtbl.iter (fun name symbols ->
        let prog_scoped_symbols = List.filter (fun s -> 
          s.scope = [prog.prog_name]
        ) symbols in
        if prog_scoped_symbols <> [] then (
          let existing = try Hashtbl.find table.symbols name with Not_found -> [] in
          Hashtbl.replace table.symbols name (existing @ prog_scoped_symbols)
        )
      ) table_with_prog.symbols
      
  | Ast.ConfigDecl config_decl ->
      add_config_decl table config_decl
      
  | Ast.StructDecl struct_def ->
      let pos = { line = 1; column = 1; filename = "" } in
      let type_def = Ast.StructDef (struct_def.struct_name, struct_def.struct_fields) in
      add_type_def table type_def pos

and process_statement table stmt =
  match stmt.stmt_desc with
  | Declaration (name, type_opt, expr) ->
      (* Infer type from expression if not provided *)
      let var_type = match type_opt with
        | Some t -> t
        | None -> U32  (* TODO: implement expression type inference *)
      in
      add_variable table name var_type stmt.stmt_pos;
      process_expression table expr
      
  | Assignment (_name, expr) ->
      process_expression table expr
      
  | FieldAssignment (obj_expr, _field, value_expr) ->
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
           
  | FunctionCall (name, args) ->
      (* Validate function exists - check built-ins first, then user-defined *)
      (match Stdlib.is_builtin_function name with
       | true -> 
           (* This is a built-in function - it's always valid *)
           ()
       | false ->
           (* Check for user-defined function *)
           (match lookup_symbol table name with
            | Some { kind = Function _; _ } -> ()
            | Some _ -> symbol_error (name ^ " is not a function") expr.expr_pos
            | None -> symbol_error ("Undefined function: " ^ name) expr.expr_pos));
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
  
  let local_maps = match table.current_program with
    | Some prog_name ->
        Hashtbl.fold (fun (prog, map_name) map_decl acc ->
          if prog = prog_name then (map_name, map_decl) :: acc else acc
        ) table.local_maps []
    | None -> []
  in
  
  global_maps @ local_maps

(** Pretty printing for debugging *)
let string_of_symbol_kind = function
  | Variable t -> "variable:" ^ string_of_bpf_type t
  | Function (params, ret) ->
      "function:(" ^ String.concat "," (List.map string_of_bpf_type params) ^ ")->" ^ string_of_bpf_type ret
  | TypeDef (StructDef (name, _)) -> "struct:" ^ name
  | TypeDef (EnumDef (name, _)) -> "enum:" ^ name
  | TypeDef (TypeAlias (name, t)) -> "alias:" ^ name ^ "=" ^ string_of_bpf_type t
  | GlobalMap _ -> "global_map"
  | LocalMap _ -> "local_map"
  | Parameter t -> "param:" ^ string_of_bpf_type t
  | EnumConstant (enum_name, value) ->
      "enum_const:" ^ enum_name ^ "=" ^ (match value with Some v -> string_of_int v | None -> "auto")
  | Config config_decl -> "config:" ^ config_decl.config_name
  | Program prog_decl -> "program:" ^ prog_decl.prog_name ^ ":" ^ string_of_program_type prog_decl.prog_type

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
  Hashtbl.iter (fun name _map -> Printf.printf "  %s\n" name) table.global_maps;
  
  Printf.printf "\nLocal Maps:\n";
  Hashtbl.iter (fun (prog, map_name) _map -> 
    Printf.printf "  %s::%s\n" prog map_name) table.local_maps 