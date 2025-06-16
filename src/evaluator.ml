(** Expression Evaluator for KernelScript *)

open Ast

(** Evaluation exceptions *)
exception Evaluation_error of string * position
exception Runtime_error of string * position
exception Unsupported_operation of string * position

(** Runtime values during evaluation *)
type runtime_value =
  | IntValue of int
  | StringValue of string
  | CharValue of char
  | BoolValue of bool
  | ArrayValue of runtime_value array
  | PointerValue of int  (* Address representation *)
  | StructValue of (string * runtime_value) list
  | EnumValue of string * int
  | MapHandle of string  (* Map identifier *)
  | ContextValue of string * (string * runtime_value) list
  | UnitValue

(** Additional exceptions that depend on runtime_value *)
exception Return_value of runtime_value
exception Break_loop
exception Continue_loop

(** Evaluation context *)
type eval_context = {
  variables: (string, runtime_value) Hashtbl.t;
  maps: (string, map_declaration) Hashtbl.t;
  functions: (string, function_def) Hashtbl.t;
  builtin_functions: (string, runtime_value list -> runtime_value) Hashtbl.t;
  current_context: runtime_value option;
  mutable call_depth: int;
  max_call_depth: int;
  (* Map storage: map_name -> (key -> value) hashtable *)
  map_storage: (string, (string, runtime_value) Hashtbl.t) Hashtbl.t;
}

(** Create evaluation context *)
let create_eval_context maps functions =
  let builtin_funcs = Hashtbl.create 32 in
  
  (* Built-in XDP context functions *)
  Hashtbl.add builtin_funcs "ctx.packet" (function
    | [] -> PointerValue 0x1000  (* Mock packet data pointer *)
    | _ -> raise (Evaluation_error ("ctx.packet takes no arguments", make_position 0 0 "")));
    
  Hashtbl.add builtin_funcs "ctx.data_end" (function
    | [] -> PointerValue 0x2000  (* Mock data end pointer *)
    | _ -> raise (Evaluation_error ("ctx.data_end takes no arguments", make_position 0 0 "")));
    
  Hashtbl.add builtin_funcs "ctx.get_packet_id" (function
    | [] -> IntValue 12345  (* Mock packet ID *)
    | _ -> raise (Evaluation_error ("ctx.get_packet_id takes no arguments", make_position 0 0 "")));
  
  (* Built-in utility functions *)
  Hashtbl.add builtin_funcs "bpf_trace_printk" (function
    | [StringValue msg; IntValue _len] -> 
        Printf.printf "[BPF]: %s\n" msg;
        IntValue 0
    | _ -> raise (Evaluation_error ("bpf_trace_printk requires string and length", make_position 0 0 "")));
    
  Hashtbl.add builtin_funcs "bpf_get_current_pid_tgid" (function
    | [] -> IntValue 0x12345678  (* Mock PID/TGID *)
    | _ -> raise (Evaluation_error ("bpf_get_current_pid_tgid takes no arguments", make_position 0 0 "")));
    
  Hashtbl.add builtin_funcs "bpf_ktime_get_ns" (function
    | [] -> IntValue 1234567890  (* Mock timestamp *)
    | _ -> raise (Evaluation_error ("bpf_ktime_get_ns takes no arguments", make_position 0 0 "")));
  
  let map_storage = Hashtbl.create 32 in
  (* Initialize storage for each map *)
  Hashtbl.iter (fun map_name _map_decl ->
    Hashtbl.add map_storage map_name (Hashtbl.create 64)
  ) maps;
  
  {
    variables = Hashtbl.create 64;
    maps = maps;
    functions = functions;
    builtin_functions = builtin_funcs;
    current_context = None;
    call_depth = 0;
    max_call_depth = 100;
    map_storage = map_storage;
  }

(** Helper to create evaluation error *)
let eval_error msg pos = raise (Evaluation_error (msg, pos))

(** Convert runtime value to string for debugging *)
let rec string_of_runtime_value = function
  | IntValue i -> string_of_int i
  | StringValue s -> "\"" ^ s ^ "\""
  | CharValue c -> "'" ^ String.make 1 c ^ "'"
  | BoolValue b -> string_of_bool b
  | ArrayValue arr -> 
      "[" ^ String.concat "; " (Array.to_list (Array.map string_of_runtime_value arr)) ^ "]"
  | PointerValue addr -> Printf.sprintf "0x%x" addr
  | StructValue fields ->
      "{" ^ String.concat "; " (List.map (fun (name, value) ->
        name ^ " = " ^ string_of_runtime_value value) fields) ^ "}"
  | EnumValue (name, value) -> Printf.sprintf "%s(%d)" name value
  | MapHandle name -> Printf.sprintf "map<%s>" name
  | ContextValue (ctx_type, fields) ->
      Printf.sprintf "%s_context{%s}" ctx_type
        (String.concat "; " (List.map (fun (name, value) ->
          name ^ " = " ^ string_of_runtime_value value) fields))
  | UnitValue -> "()"

(** Convert literal to runtime value *)
let runtime_value_of_literal = function
  | IntLit i -> IntValue i
  | StringLit s -> StringValue s
  | CharLit c -> CharValue c
  | BoolLit b -> BoolValue b
  | ArrayLit _literals -> 
      (* TODO: Implement array literal evaluation *)
      failwith "Array literal evaluation not implemented yet"

(** Extract integer value from runtime value *)
let int_of_runtime_value rv pos =
  match rv with
  | IntValue i -> i
  | _ -> eval_error ("Expected integer value, got " ^ string_of_runtime_value rv) pos

(** Extract boolean value from runtime value *)
let bool_of_runtime_value rv pos =
  match rv with
  | BoolValue b -> b
  | _ -> eval_error ("Expected boolean value, got " ^ string_of_runtime_value rv) pos

(** Evaluate binary operations with proper operator precedence *)
let eval_binary_op left_val op right_val pos =
  match op, left_val, right_val with
  (* Arithmetic operations *)
  | Add, IntValue l, IntValue r -> IntValue (l + r)
  | Sub, IntValue l, IntValue r -> IntValue (l - r)
  | Mul, IntValue l, IntValue r -> IntValue (l * r)
  | Div, IntValue l, IntValue r when r <> 0 -> IntValue (l / r)
  | Div, IntValue _, IntValue 0 -> eval_error "Division by zero" pos
  | Mod, IntValue l, IntValue r when r <> 0 -> IntValue (l mod r)
  | Mod, IntValue _, IntValue 0 -> eval_error "Modulo by zero" pos
  
  (* String concatenation for Add *)
  | Add, StringValue l, StringValue r -> StringValue (l ^ r)
  
  (* Comparison operations *)
  | Eq, IntValue l, IntValue r -> BoolValue (l = r)
  | Ne, IntValue l, IntValue r -> BoolValue (l <> r)
  | Lt, IntValue l, IntValue r -> BoolValue (l < r)
  | Le, IntValue l, IntValue r -> BoolValue (l <= r)
  | Gt, IntValue l, IntValue r -> BoolValue (l > r)
  | Ge, IntValue l, IntValue r -> BoolValue (l >= r)
  
  | Eq, BoolValue l, BoolValue r -> BoolValue (l = r)
  | Ne, BoolValue l, BoolValue r -> BoolValue (l <> r)
  
  | Eq, StringValue l, StringValue r -> BoolValue (String.equal l r)
  | Ne, StringValue l, StringValue r -> BoolValue (not (String.equal l r))
  
  (* Logical operations *)
  | And, BoolValue l, BoolValue r -> BoolValue (l && r)
  | Or, BoolValue l, BoolValue r -> BoolValue (l || r)
  
  (* Type mismatches *)
  | _ -> eval_error (Printf.sprintf "Cannot apply %s to %s and %s" 
                      (string_of_binary_op op) 
                      (string_of_runtime_value left_val)
                      (string_of_runtime_value right_val)) pos

(** Evaluate unary operations *)
let eval_unary_op op val_ pos =
  match op, val_ with
  | Not, BoolValue b -> BoolValue (not b)
  | Neg, IntValue i -> IntValue (-i)
  | Not, _ -> eval_error ("Cannot apply logical not to " ^ string_of_runtime_value val_) pos
  | Neg, _ -> eval_error ("Cannot negate " ^ string_of_runtime_value val_) pos

(** Evaluate function call *)
let rec eval_function_call ctx name args pos =
  (* Check call depth *)
  if ctx.call_depth >= ctx.max_call_depth then
    eval_error ("Maximum call depth exceeded: " ^ string_of_int ctx.max_call_depth) pos;
  
  (* Evaluate arguments *)
  let arg_values = List.map (eval_expression ctx) args in
  
  (* Check for built-in functions first *)
  if Hashtbl.mem ctx.builtin_functions name then
    let builtin_func = Hashtbl.find ctx.builtin_functions name in
    builtin_func arg_values
  else
    (* Handle map operations *)
    if String.contains name '.' then
      eval_map_operation ctx name arg_values pos
    else
      (* Check for user-defined functions *)
      try
        let func_def = Hashtbl.find ctx.functions name in
        ctx.call_depth <- ctx.call_depth + 1;
        let result = eval_user_function ctx func_def arg_values pos in
        ctx.call_depth <- ctx.call_depth - 1;
        result
      with Not_found ->
        eval_error ("Undefined function: " ^ name) pos

(** Evaluate map operations *)
and eval_map_operation ctx name arg_values pos =
  let parts = String.split_on_char '.' name in
  match parts with
  | [map_name; operation] ->
      let get_map_storage () =
        try Hashtbl.find ctx.map_storage map_name
        with Not_found -> eval_error ("Map not found: " ^ map_name) pos
      in
      
      (match operation with
       | "lookup" ->
           (match arg_values with
            | [key_val] ->
                let map_store = get_map_storage () in
                let key_str = string_of_runtime_value key_val in
                (try
                   let value = Hashtbl.find map_store key_str in
                   StructValue [("Some", value)]  (* Option::Some *)
                 with Not_found ->
                   StructValue [("None", UnitValue)])  (* Option::None *)
            | _ -> eval_error ("Map lookup requires 1 argument") pos)
       
       | "insert" | "update" ->
           (match arg_values with
            | [key_val; val_val] ->
                let map_store = get_map_storage () in
                let key_str = string_of_runtime_value key_val in
                Hashtbl.replace map_store key_str val_val;
                Printf.printf "[MAP %s]: %s[%s] = %s\n" 
                  operation map_name key_str (string_of_runtime_value val_val);
                IntValue 0  (* Success *)
            | _ -> eval_error (Printf.sprintf "Map %s requires 2 arguments" operation) pos)
       
       | "delete" ->
           (match arg_values with
            | [key_val] ->
                let map_store = get_map_storage () in
                let key_str = string_of_runtime_value key_val in
                let existed = Hashtbl.mem map_store key_str in
                if existed then
                  Hashtbl.remove map_store key_str;
                Printf.printf "[MAP DELETE]: %s[%s] (existed: %b)\n" 
                  map_name key_str existed;
                IntValue (if existed then 0 else -1)  (* Success or not found *)
            | _ -> eval_error ("Map delete requires 1 argument") pos)
       
       | _ -> eval_error ("Unknown map operation: " ^ operation) pos)
  
  | _ -> eval_error ("Invalid map operation format: " ^ name) pos

(** Evaluate user-defined function *)
and eval_user_function ctx func_def arg_values pos =
  (* Check parameter count *)
  if List.length func_def.func_params <> List.length arg_values then
    eval_error (Printf.sprintf "Function %s expects %d arguments, got %d"
                 func_def.func_name 
                 (List.length func_def.func_params)
                 (List.length arg_values)) pos;
  
  (* Save old variable values for parameters *)
  let old_param_values = List.map (fun (param_name, _) ->
    (param_name, try Some (Hashtbl.find ctx.variables param_name) with Not_found -> None)
  ) func_def.func_params in
  
  (* Bind parameters *)
  List.iter2 (fun (param_name, _) arg_value ->
    Hashtbl.replace ctx.variables param_name arg_value
  ) func_def.func_params arg_values;
  
  (* Execute function body *)
  let result = 
    try
      eval_statements ctx func_def.func_body;
      UnitValue  (* Default return value *)
    with
    | Return_value value -> value
  in
  
  (* Restore old parameter values *)
  List.iter (fun (param_name, old_value_opt) ->
    match old_value_opt with
    | Some old_value -> Hashtbl.replace ctx.variables param_name old_value
    | None -> Hashtbl.remove ctx.variables param_name
  ) old_param_values;
  
  result

(** Evaluate array access *)
and eval_array_access ctx arr_expr idx_expr pos =
  (* Check if this is a map access first *)
  (match arr_expr.expr_desc with
   | Identifier map_name when Hashtbl.mem ctx.maps map_name ->
       (* This is a map access: map[key] *)
       let key_val = eval_expression ctx idx_expr in
       let map_store = 
         try Hashtbl.find ctx.map_storage map_name
         with Not_found -> eval_error ("Map not found: " ^ map_name) pos
       in
       let key_str = string_of_runtime_value key_val in
       (try
          Hashtbl.find map_store key_str
        with Not_found ->
          (* For map access, return a default value or error based on map type *)
          IntValue 0)  (* Default value for missing keys *)
   | _ ->
       (* Regular array access *)
       let arr_val = eval_expression ctx arr_expr in
       let idx_val = eval_expression ctx idx_expr in
       
       let index = int_of_runtime_value idx_val pos in
       
       match arr_val with
       | ArrayValue arr ->
           if index >= 0 && index < Array.length arr then
             arr.(index)
           else
             eval_error (Printf.sprintf "Array index %d out of bounds (length %d)" 
                          index (Array.length arr)) pos
       
       | StringValue s ->
           if index >= 0 && index < String.length s then
             CharValue s.[index]
           else
             eval_error (Printf.sprintf "String index %d out of bounds (length %d)" 
                          index (String.length s)) pos
       
       | _ ->
           eval_error ("Cannot index " ^ string_of_runtime_value arr_val) pos)

(** Evaluate field access *)
and eval_field_access ctx obj_expr field pos =
  let obj_val = eval_expression ctx obj_expr in
  
  match obj_val with
  | StructValue fields ->
      (try
         List.assoc field fields
       with Not_found ->
         eval_error ("Field not found: " ^ field) pos)
  
  | ContextValue (_ctx_type, fields) ->
      (* Handle built-in context field access *)
      (match field with
       | "data" -> PointerValue 0x1000
       | "data_end" -> PointerValue 0x2000
       | "ingress_ifindex" -> IntValue 1
       | "rx_queue_index" -> IntValue 0
       | _ ->
           try
             List.assoc field fields
           with Not_found ->
             eval_error ("Unknown context field: " ^ field) pos)
  
  | _ ->
      eval_error ("Cannot access field of " ^ string_of_runtime_value obj_val) pos

(** Evaluate expression *)
and eval_expression ctx expr =
  match expr.expr_desc with
  | Literal lit -> runtime_value_of_literal lit
  
  | Identifier name ->
      (* Handle special constants *)
      if String.contains name ':' then
        let parts = String.split_on_char ':' name in
        let filtered_parts = List.filter (fun s -> s <> "") parts in
        (match filtered_parts with
         | ["XdpAction"; "Pass"] -> EnumValue ("XdpAction", 2)
         | ["XdpAction"; "Drop"] -> EnumValue ("XdpAction", 1)
         | ["XdpAction"; "Aborted"] -> EnumValue ("XdpAction", 0)
         | ["XdpAction"; "Redirect"] -> EnumValue ("XdpAction", 3)
         | ["XdpAction"; "Tx"] -> EnumValue ("XdpAction", 4)
         | ["TcAction"; "Ok"] -> EnumValue ("TcAction", 0)
         | ["TcAction"; "Shot"] -> EnumValue ("TcAction", 2)
         | [enum_name; _variant] -> EnumValue (enum_name, 0)  (* Default enum value *)
         | _ -> eval_error ("Invalid constant: " ^ name) expr.expr_pos)
      else
        (try
          Hashtbl.find ctx.variables name
        with Not_found ->
          eval_error ("Undefined variable: " ^ name) expr.expr_pos)
  
  | FunctionCall (name, args) -> eval_function_call ctx name args expr.expr_pos
  
  | ArrayAccess (arr, idx) -> eval_array_access ctx arr idx expr.expr_pos
  
  | FieldAccess (obj, field) -> eval_field_access ctx obj field expr.expr_pos
  
  | BinaryOp (left, op, right) ->
      let left_val = eval_expression ctx left in
      let right_val = eval_expression ctx right in
      eval_binary_op left_val op right_val expr.expr_pos
  
  | UnaryOp (op, expr) ->
      let val_ = eval_expression ctx expr in
      eval_unary_op op val_ expr.expr_pos
      
  | ConfigAccess (_config_name, _field_name) ->
      (* For evaluation purposes, return a mock value *)
      (* In real execution, this would access the config map *)
      IntValue 1500  (* Mock value for testing *)

(** Evaluate statements *)
and eval_statements ctx stmts =
  List.iter (eval_statement ctx) stmts

(** Evaluate single statement *)
and eval_statement ctx stmt =
  match stmt.stmt_desc with
  | ExprStmt expr ->
      let _ = eval_expression ctx expr in
      ()
  
  | Assignment (name, expr) ->
      let value = eval_expression ctx expr in
      Hashtbl.replace ctx.variables name value
  
  | FieldAssignment (obj_expr, field, value_expr) ->
      (* For evaluation purposes, treat config field assignment as no-op with debug output *)
      let value = eval_expression ctx value_expr in
      (match obj_expr.expr_desc with
       | Identifier config_name ->
           Printf.printf "[CONFIG ASSIGN]: %s.%s = %s\n" 
             config_name field (string_of_runtime_value value)
       | _ -> eval_error ("Field assignment only supported for config objects") stmt.stmt_pos)
  
  | IndexAssignment (map_expr, key_expr, value_expr) ->
      (* Handle map assignment: map[key] = value *)
      let map_name = match map_expr.expr_desc with
        | Identifier name when Hashtbl.mem ctx.maps name -> name
        | Identifier name -> eval_error ("Not a map: " ^ name) stmt.stmt_pos
        | _ -> eval_error ("Map assignment requires a map identifier") stmt.stmt_pos
      in
      let key_val = eval_expression ctx key_expr in
      let value_val = eval_expression ctx value_expr in
      
      let map_store = 
        try Hashtbl.find ctx.map_storage map_name
        with Not_found -> eval_error ("Map not found: " ^ map_name) stmt.stmt_pos
      in
      
      let key_str = string_of_runtime_value key_val in
      Hashtbl.replace map_store key_str value_val;
      Printf.printf "[MAP ASSIGN]: %s[%s] = %s\n" 
        map_name key_str (string_of_runtime_value value_val)
  
  | Declaration (name, _, expr) ->
      let value = eval_expression ctx expr in
      Hashtbl.add ctx.variables name value
  
  | Return None ->
      raise (Return_value UnitValue)
  
  | Return (Some expr) ->
      let value = eval_expression ctx expr in
      raise (Return_value value)
  
  | If (cond, then_stmts, else_opt) ->
      let cond_val = eval_expression ctx cond in
      let cond_bool = bool_of_runtime_value cond_val stmt.stmt_pos in
      if cond_bool then
        eval_statements ctx then_stmts
      else
        (match else_opt with
         | Some else_stmts -> eval_statements ctx else_stmts
         | None -> ())
  
  | For (var, start_expr, end_expr, body) ->
      let start_val = eval_expression ctx start_expr in
      let end_val = eval_expression ctx end_expr in
      let start_int = int_of_runtime_value start_val stmt.stmt_pos in
      let end_int = int_of_runtime_value end_val stmt.stmt_pos in
      
      (* Save old variable value if it exists *)
      let old_val = try Some (Hashtbl.find ctx.variables var) with Not_found -> None in
      
      for i = start_int to end_int do
        Hashtbl.replace ctx.variables var (IntValue i);
        (try
          eval_statements ctx body
        with
        | Break_loop -> raise Break_loop
        | Continue_loop -> ())
      done;
      
      (* Restore old variable value *)
      (match old_val with
       | Some v -> Hashtbl.replace ctx.variables var v
       | None -> Hashtbl.remove ctx.variables var)
  
  | ForIter (index_var, value_var, iterable_expr, body) ->
      (* For evaluation purposes, implement as a simple bounded iteration *)
      let _ = eval_expression ctx iterable_expr in
      
      (* Save old variable values if they exist *)
      let old_index = try Some (Hashtbl.find ctx.variables index_var) with Not_found -> None in
      let old_value = try Some (Hashtbl.find ctx.variables value_var) with Not_found -> None in
      
      (* For evaluation, iterate 0 to 9 as a simple example *)
      for i = 0 to 9 do
        Hashtbl.replace ctx.variables index_var (IntValue i);
        Hashtbl.replace ctx.variables value_var (IntValue (i * 10)); (* Mock value *)
        (try
          eval_statements ctx body
        with
        | Break_loop -> raise Break_loop
        | Continue_loop -> ())
      done;
      
      (* Restore old variable values *)
      (match old_index with
       | Some v -> Hashtbl.replace ctx.variables index_var v
       | None -> Hashtbl.remove ctx.variables index_var);
      (match old_value with
       | Some v -> Hashtbl.replace ctx.variables value_var v
       | None -> Hashtbl.remove ctx.variables value_var)
  
  | While (cond, body) ->
      let rec loop () =
        let cond_val = eval_expression ctx cond in
        let cond_bool = bool_of_runtime_value cond_val stmt.stmt_pos in
        if cond_bool then
          (try
             eval_statements ctx body;
             loop ()
           with
           | Break_loop -> ()
           | Continue_loop -> loop ())
      in
      loop ()

  | Delete (map_expr, key_expr) ->
      let map_name = match map_expr.expr_desc with
        | Identifier name -> name
        | _ -> eval_error ("Delete requires a map identifier") stmt.stmt_pos
      in
      let key_result = eval_expression ctx key_expr in
      
      (* Get the map storage *)
      let map_store = 
        try Hashtbl.find ctx.map_storage map_name
        with Not_found -> eval_error ("Map not found: " ^ map_name) stmt.stmt_pos
      in
      
      (* Perform the actual delete operation *)
      let key_str = string_of_runtime_value key_result in
      let existed = Hashtbl.mem map_store key_str in
      if existed then
        Hashtbl.remove map_store key_str;
      
      Printf.printf "[MAP DELETE]: %s[%s] (existed: %b)\n" 
        map_name key_str existed
  
  | Break ->
      raise Break_loop
  
  | Continue ->
      raise Continue_loop
      
  | Try (try_stmts, _catch_clauses) ->
      (* For evaluator, just execute try block - full error handling in codegen *)
      eval_statements ctx try_stmts
      
  | Throw expr ->
      (* For evaluator, evaluate the expression and print the error code *)
      let error_value = eval_expression ctx expr in
      let error_code = int_of_runtime_value error_value stmt.stmt_pos in
      Printf.printf "[THROW]: Error code %d\n" error_code;
      eval_error ("Unhandled error: " ^ string_of_int error_code) stmt.stmt_pos
      
  | Defer expr ->
      (* For evaluator, just evaluate the expression immediately *)
      let _ = eval_expression ctx expr in
      Printf.printf "[DEFER]: Deferred expression executed\n"

(** Evaluate a complete program *)
let eval_program ctx prog =
  (* Add program functions to context *)
  List.iter (fun func ->
    Hashtbl.add ctx.functions func.func_name func
  ) prog.prog_functions;
  
  (* Find and execute main function *)
  try
    let main_func = List.find (fun f -> f.func_name = "main") prog.prog_functions in
    
    (* Create mock context based on program type *)
    let mock_context = match prog.prog_type with
      | Xdp -> ContextValue ("xdp", [
          ("data", PointerValue 0x1000);
          ("data_end", PointerValue 0x2000);
          ("ingress_ifindex", IntValue 1);
        ])
      | Kprobe -> ContextValue ("kprobe", [
          ("ip", IntValue 0xdeadbeef);
          ("ax", IntValue 0);
        ])
      | _ -> ContextValue ("generic", [])
    in
    
    (* Execute main function with mock context *)
    eval_user_function ctx main_func [mock_context] main_func.func_pos
  with
  | Not_found -> eval_error ("Main function not found in program " ^ prog.prog_name) prog.prog_pos

(** Public API functions *)

(** Evaluate an expression with given context *)
let evaluate_expression ctx expr =
  try
    Ok (eval_expression ctx expr)
  with
  | Evaluation_error (msg, pos) -> Error (msg, pos)
  | Runtime_error (msg, pos) -> Error (msg, pos)
  | exn -> Error (Printexc.to_string exn, make_position 0 0 "")

(** Evaluate statements with given context *)
let evaluate_statements ctx stmts =
  try
    eval_statements ctx stmts;
    Ok ()
  with
  | Evaluation_error (msg, pos) -> Error (msg, pos)
  | Runtime_error (msg, pos) -> Error (msg, pos)
  | Return_value _ -> Ok ()  (* Functions can return *)
  | exn -> Error (Printexc.to_string exn, make_position 0 0 "")

(** Evaluate a complete program *)
let evaluate_program maps functions prog =
  let ctx = create_eval_context maps functions in
  try
    let result = eval_program ctx prog in
    Ok result
  with
  | Evaluation_error (msg, pos) -> Error (msg, pos)
  | Runtime_error (msg, pos) -> Error (msg, pos)
  | exn -> Error (Printexc.to_string exn, make_position 0 0 "")

(** Create a variable in context *)
let add_variable ctx name value =
  Hashtbl.replace ctx.variables name value

(** Get variable from context *)
let get_variable ctx name =
  try
    Some (Hashtbl.find ctx.variables name)
  with Not_found -> None

(** Debug: print context state *)
let print_context_state ctx =
  Printf.printf "=== Evaluation Context ===\n";
  Printf.printf "Variables:\n";
  Hashtbl.iter (fun name value ->
    Printf.printf "  %s = %s\n" name (string_of_runtime_value value)
  ) ctx.variables;
  Printf.printf "Call depth: %d\n" ctx.call_depth;
  Printf.printf "========================\n"