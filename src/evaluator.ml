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
  | NullValue  (* Simple null value representation *)
  | UnitValue
  | None  (* Sentinel value for map lookup failures and missing values *)

(** Additional exceptions that depend on runtime_value *)
exception Return_value of runtime_value
exception Break_loop
exception Continue_loop

(** Compare runtime values for equality *)
let rec runtime_values_equal v1 v2 =
  match v1, v2 with
  | IntValue i1, IntValue i2 -> i1 = i2
  | StringValue s1, StringValue s2 -> s1 = s2
  | CharValue c1, CharValue c2 -> c1 = c2
  | BoolValue b1, BoolValue b2 -> b1 = b2
  | EnumValue (name1, val1), EnumValue (name2, val2) -> name1 = name2 && val1 = val2
  | NullValue, NullValue -> true
  | UnitValue, UnitValue -> true
  | None, None -> true
  | PointerValue addr1, PointerValue addr2 -> addr1 = addr2
  | MapHandle name1, MapHandle name2 -> name1 = name2
  | ArrayValue arr1, ArrayValue arr2 -> 
      Array.length arr1 = Array.length arr2 && 
      Array.for_all2 runtime_values_equal arr1 arr2
  | StructValue fields1, StructValue fields2 ->
      List.length fields1 = List.length fields2 &&
      List.for_all2 (fun (name1, val1) (name2, val2) ->
        name1 = name2 && runtime_values_equal val1 val2
      ) fields1 fields2
  | ContextValue (name1, fields1), ContextValue (name2, fields2) ->
      name1 = name2 && 
      List.length fields1 = List.length fields2 &&
      List.for_all2 (fun (n1, v1) (n2, v2) ->
        n1 = n2 && runtime_values_equal v1 v2
      ) fields1 fields2
  | _ -> false  (* Different types are not equal *)

(** Memory region types for enhanced dynptr integration *)
type memory_region_type =
  | PacketDataRegion of int  (* Base address of packet data *)
  | MapValueRegion of string  (* Map name for map value regions *)
  | StackRegion  (* Local stack variables *)
  | ContextRegion of string  (* eBPF context regions *)
  | RegularMemoryRegion  (* Other memory regions *)

type memory_region_info = {
  region_type: memory_region_type;
  base_address: int;
  size: int;
  bounds_verified: bool;
}

type bounds_info = {
  min_offset: int;
  max_offset: int;
  verified: bool;
}

(** Enhanced evaluator context with mandatory symbol table
    
    The evaluator now requires a symbol table to properly resolve enum constants
    extracted from BTF or defined in user code instead of hardcoding them.
    This eliminates code duplication and ensures consistency.
    
    Usage:
    - Symbol table is created using Symbol_table.build_symbol_table with BTF-extracted types
    - All enum constants (XDP_PASS, TC_ACT_OK, etc.) are loaded from BTF extraction during init
    - No hardcoded fallback - all callers must provide proper symbol tables
*)
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
  (* Memory model for pointer operations *)
  memory: (int, runtime_value) Hashtbl.t;  (* address -> value *)
  variable_addresses: (string, int) Hashtbl.t;  (* variable_name -> address *)
  mutable next_address: int;  (* Next available memory address *)
  (* Memory region tracking for dynptr integration *)
  memory_regions: (int, memory_region_info) Hashtbl.t;  (* address -> region info *)
  region_bounds: (memory_region_type, bounds_info) Hashtbl.t;  (* region -> bounds *)
  symbol_table: Symbol_table.symbol_table option; (* Add symbol table *)
}

(** Create evaluation context *)
let create_eval_context symbol_table maps functions =
  let builtin_funcs = Hashtbl.create 32 in
  
  (* Initialize builtin functions *)
  Hashtbl.add builtin_funcs "bpf_trace_printk" (function
    | [StringValue msg; IntValue _len] -> 
        Printf.printf "[BPF]: %s\n" msg;
        IntValue 0
    | _ -> raise (Evaluation_error ("bpf_trace_printk requires string and length", make_position 0 0 "")));
  
  (* Initialize map storage for each map *)
  let map_storage = Hashtbl.create 16 in
  Hashtbl.iter (fun name _map_decl ->
    let storage = Hashtbl.create 32 in
    Hashtbl.add map_storage name storage
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
    memory = Hashtbl.create 256;  (* Memory storage for pointer operations *)
    variable_addresses = Hashtbl.create 32;  (* Variable address tracking *)
    next_address = 0x1000;  (* Next available address *)
    memory_regions = Hashtbl.create 64;  (* Memory region tracking *)
    region_bounds = Hashtbl.create 16;  (* Region bounds information *)
    symbol_table = Some symbol_table;
  }

(** Helper to create evaluation error *)
let eval_error msg pos = raise (Evaluation_error (msg, pos))

(** Memory region management helpers for dynptr integration *)

(** Initialize default memory regions for eBPF context *)
let initialize_default_memory_regions ctx =
  (* Only initialize if not already initialized *)
  if Hashtbl.length ctx.memory_regions = 0 then (
    (* Packet data region (XDP context) *)
    let packet_region = {
      region_type = PacketDataRegion 0x2000;
      base_address = 0x2000;
      size = 1500;  (* Typical packet size *)
      bounds_verified = true;
    } in
    Hashtbl.add ctx.memory_regions 0x2000 packet_region;
    Hashtbl.add ctx.region_bounds (PacketDataRegion 0x2000) { min_offset = 0; max_offset = 1500; verified = true };
    
    (* Context region *)
    let context_region = {
      region_type = ContextRegion "xdp";
      base_address = 0x3000;
      size = 64;  (* Size of context struct *)
      bounds_verified = true;
    } in
    Hashtbl.add ctx.memory_regions 0x3000 context_region;
    Hashtbl.add ctx.region_bounds (ContextRegion "xdp") { min_offset = 0; max_offset = 64; verified = true };
    
    (* Stack region starts from 0x1000 *)
    Hashtbl.add ctx.region_bounds StackRegion { min_offset = 0; max_offset = 4096; verified = true }
  )

(** Find memory region for a given address *)
let find_memory_region_by_address ctx addr =
  try
    Some (Hashtbl.find ctx.memory_regions addr)
  with Not_found ->
    (* Try to find region containing this address *)
    let regions = Hashtbl.to_seq_values ctx.memory_regions |> List.of_seq in
    List.find_opt (fun region ->
      addr >= region.base_address && addr < (region.base_address + region.size)
    ) regions

(** Register a new memory region *)
let register_memory_region ctx addr region_info =
  Hashtbl.replace ctx.memory_regions addr region_info;
  let bounds = { min_offset = 0; max_offset = region_info.size; verified = region_info.bounds_verified } in
  Hashtbl.replace ctx.region_bounds region_info.region_type bounds

(** Get bounds information for a memory region *)
let get_region_bounds ctx region_type =
  try
    Some (Hashtbl.find ctx.region_bounds region_type)
  with Not_found -> None

(** Analyze pointer bounds based on memory region *)
let analyze_pointer_bounds ctx addr =
  match find_memory_region_by_address ctx addr with
  | Some region_info ->
      let offset_from_base = addr - region_info.base_address in
      let remaining_size = region_info.size - offset_from_base in
      { min_offset = 0; max_offset = remaining_size; verified = region_info.bounds_verified }
  | None ->
      { min_offset = 0; max_offset = max_int; verified = false }

(** Memory management helpers for pointer operations *)

(** Allocate a new memory address for a variable *)
let allocate_variable_address ctx var_name value =
  let addr = ctx.next_address in
  let size = match value with
    | ArrayValue arr -> Array.length arr * 4  (* Estimate size *)
    | StructValue _ -> 64  (* Estimate struct size *)
    | StringValue s -> String.length s + 1
    | _ -> 4  (* Default size *)
  in
  ctx.next_address <- addr + size;
  Hashtbl.replace ctx.variable_addresses var_name addr;
  Hashtbl.replace ctx.memory addr value;
  
  (* Register memory region for this variable (stack region) *)
  let region_info = {
    region_type = StackRegion;
    base_address = addr;
    size = size;
    bounds_verified = true;
  } in
  register_memory_region ctx addr region_info;
  addr

(** Allocate address for context-derived values (packet data, map values) *)
let allocate_context_address ctx var_name value context_type =
  let (base_addr, region_type) = match context_type with
    | "packet_data" -> (0x2000, PacketDataRegion 0x2000)
    | "map_value" -> (ctx.next_address, MapValueRegion var_name)
    | _ -> (ctx.next_address, StackRegion)
  in
  
  let addr = match context_type with
    | "packet_data" -> base_addr  (* Use fixed packet data address *)
    | _ -> 
        let addr = ctx.next_address in
        ctx.next_address <- addr + 64;  (* Default allocation size *)
        addr
  in
  
  Hashtbl.replace ctx.variable_addresses var_name addr;
  Hashtbl.replace ctx.memory addr value;
  
  (* Register appropriate memory region *)
  let region_info = {
    region_type = region_type;
    base_address = addr;
    size = 64;  (* Default size *)
    bounds_verified = (context_type = "packet_data");
  } in
  register_memory_region ctx addr region_info;
  addr

(** Get the address of a variable, allocating if necessary *)
let get_variable_address ctx var_name =
  if Hashtbl.mem ctx.variable_addresses var_name then
    Hashtbl.find ctx.variable_addresses var_name
  else
    (* Variable doesn't have an address yet - this shouldn't happen in normal execution *)
    eval_error ("Cannot get address of undefined variable: " ^ var_name) (make_position 0 0 "")

(** Store a value at a memory address *)
let store_at_address ctx addr value =
  Hashtbl.replace ctx.memory addr value

(** Load a value from a memory address *)
let load_from_address ctx addr pos =
  try
    Hashtbl.find ctx.memory addr
  with Not_found ->
    eval_error (Printf.sprintf "Invalid memory access at address 0x%x" addr) pos

(** Update variable value and its memory location *)
let update_variable ctx var_name value =
  Hashtbl.replace ctx.variables var_name value;
  if Hashtbl.mem ctx.variable_addresses var_name then
    let addr = Hashtbl.find ctx.variable_addresses var_name in
    store_at_address ctx addr value

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
  | NullValue -> "null"
  | UnitValue -> "()"
  | None -> "none"

(** Convert literal to runtime value *)
let runtime_value_of_literal = function
  | IntLit (i, _) -> IntValue i
  | StringLit s -> StringValue s
  | CharLit c -> CharValue c
  | BoolLit b -> BoolValue b
  | NullLit -> NullValue  (* null is represented as simple null value *)
  | NoneLit -> None      (* none is represented as none sentinel value *)
  | ArrayLit _literals -> 
      (* TODO: Implement array literal evaluation *)
      failwith "Array literal evaluation not implemented yet"

(** Extract integer value from runtime value *)
let int_of_runtime_value rv pos =
  match rv with
  | IntValue i -> i
  | _ -> eval_error ("Expected integer value, got " ^ string_of_runtime_value rv) pos

(** Convert runtime value to boolean for truthy/falsy evaluation *)
let is_truthy_value rv =
  match rv with
  | BoolValue b -> b
  | IntValue i -> i <> 0                          (* 0 is falsy, non-zero is truthy *)
  | StringValue s -> String.length s > 0          (* empty string is falsy, non-empty is truthy *)
  | CharValue c -> c <> '\000'                    (* null character is falsy, others truthy *)
  | PointerValue addr -> addr <> 0                (* null pointer is falsy, non-null is truthy *)
  | EnumValue (_, value) -> value <> 0            (* enum based on numeric value *)
  | MapHandle _ -> true                           (* maps are always truthy *)
  | ContextValue (_, _) -> true                   (* context values are always truthy *)
  | NullValue -> false                            (* null is always falsy *)
  | UnitValue -> false                            (* unit value is falsy *)
  | None -> false                                 (* none is always falsy *)
  | ArrayValue _ -> failwith "Arrays cannot be used in boolean context"
  | StructValue _ -> failwith "Structs cannot be used in boolean context"

(** Extract boolean value from runtime value with truthy/falsy conversion *)
let bool_of_runtime_value rv _pos =
  match rv with
  | BoolValue b -> b
  | _ -> is_truthy_value rv  (* Use truthy/falsy conversion for non-boolean values *)

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
  
  (* Null comparisons *)
  | Eq, NullValue, NullValue -> BoolValue true
  | Ne, NullValue, NullValue -> BoolValue false
  | Eq, NullValue, _ -> BoolValue false
  | Ne, NullValue, _ -> BoolValue true
  | Eq, _, NullValue -> BoolValue false
  | Ne, _, NullValue -> BoolValue true
  
  (* None comparisons *)
  | Eq, None, None -> BoolValue true
  | Ne, None, None -> BoolValue false
  | Eq, None, _ -> BoolValue false
  | Ne, None, _ -> BoolValue true
  | Eq, _, None -> BoolValue false
  | Ne, _, None -> BoolValue true
  
  (* Logical operations *)
  | And, BoolValue l, BoolValue r -> BoolValue (l && r)
  | Or, BoolValue l, BoolValue r -> BoolValue (l || r)
  
  (* Type mismatches *)
  | _ -> eval_error (Printf.sprintf "Cannot apply %s to %s and %s" 
                      (string_of_binary_op op) 
                      (string_of_runtime_value left_val)
                      (string_of_runtime_value right_val)) pos

(** Evaluate unary operations *)
let eval_unary_op ctx op val_ pos =
  match op, val_ with
  | Not, BoolValue b -> BoolValue (not b)
  | Neg, IntValue i -> IntValue (-i)
  | Deref, PointerValue addr -> 
      (* Properly dereference pointer by loading value from memory *)
      if addr = 0 then
        eval_error "Cannot dereference null pointer" pos
      else
        load_from_address ctx addr pos
  | AddressOf, _ -> 
      (* AddressOf should be handled in expression evaluation, not here *)
      eval_error "AddressOf operation should be handled at expression level" pos
  | Not, _ -> eval_error ("Cannot apply logical not to " ^ string_of_runtime_value val_) pos
  | Neg, _ -> eval_error ("Cannot negate " ^ string_of_runtime_value val_) pos
  | Deref, _ -> eval_error ("Cannot dereference " ^ string_of_runtime_value val_) pos

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
    Hashtbl.replace ctx.variables param_name arg_value;
    let _ = allocate_variable_address ctx param_name arg_value in
    ()
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
          (* For map access, return sentinel value for missing keys *)
          None)
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
  (* Initialize memory regions if not already initialized *)
  initialize_default_memory_regions ctx;
  match expr.expr_desc with
  | Literal lit -> runtime_value_of_literal lit
  
  | Identifier name ->
      (* Dynamic enum constant lookup - uses builtin definitions only *)
      (match ctx.symbol_table with
       | Some symbol_table ->
           (* Look up enum constants from loaded builtin AST files *)
           (match Symbol_table.lookup_symbol symbol_table name with
            | Some { kind = Symbol_table.EnumConstant (enum_name, Some value); _ } ->
                EnumValue (enum_name, value)
            | _ ->
                (* Not an enum constant, try variables *)
                (try
                  Hashtbl.find ctx.variables name
                with Not_found ->
                  eval_error ("Undefined variable: " ^ name) expr.expr_pos))
       | None ->
           (* This should never happen since symbol_table is now mandatory *)
           eval_error ("Internal error: no symbol table available") expr.expr_pos)
  
  | Call (callee_expr, args) ->
      (* Handle both regular function calls and function pointer calls *)
      (match callee_expr.expr_desc with
       | Identifier name ->
           (* Regular function call *)
           eval_function_call ctx name args expr.expr_pos
       | _ ->
           (* Function pointer call - not supported in evaluation context *)
           eval_error "Function pointer calls cannot be evaluated in userspace context" expr.expr_pos)
  
  | TailCall (name, _args) ->
      (* Tail calls are not supported in evaluation context - they only exist in eBPF *)
      eval_error ("Tail call to " ^ name ^ " cannot be evaluated in userspace context") expr.expr_pos
  
  | ModuleCall module_call ->
      (* Module calls are not supported in evaluation context - they need FFI setup *)
      eval_error ("Module call to " ^ module_call.module_name ^ "." ^ module_call.function_name ^ " cannot be evaluated in userspace context") expr.expr_pos
  
  | ArrayAccess (arr, idx) -> eval_array_access ctx arr idx expr.expr_pos
  
  | FieldAccess (obj, field) -> eval_field_access ctx obj field expr.expr_pos
  
  | ArrowAccess (obj, field) ->
      (* Arrow access (pointer->field) - for evaluator, treat same as field access *)
      eval_field_access ctx obj field expr.expr_pos
  
  | BinaryOp (left, op, right) ->
      let left_val = eval_expression ctx left in
      let right_val = eval_expression ctx right in
      eval_binary_op left_val op right_val expr.expr_pos
  
  | UnaryOp (op, expr) ->
      (match op with
       | AddressOf ->
           (* Handle AddressOf specially to get variable address *)
           (match expr.expr_desc with
            | Identifier var_name ->
                if Hashtbl.mem ctx.variables var_name then
                  let addr = get_variable_address ctx var_name in
                  PointerValue addr
                else
                  eval_error ("Cannot get address of undefined variable: " ^ var_name) expr.expr_pos
            | _ ->
                eval_error "AddressOf operator can only be applied to variables" expr.expr_pos)
       | _ ->
           let val_ = eval_expression ctx expr in
           eval_unary_op ctx op val_ expr.expr_pos)
      
  | ConfigAccess (_config_name, _field_name) ->
      (* For evaluation purposes, return a mock value *)
      (* In real execution, this would access the config map *)
      IntValue 1500  (* Mock value for testing *)
      
  | StructLiteral (_struct_name, field_assignments) ->
      (* For evaluation, create a struct value *)
      let field_values = List.map (fun (field_name, field_expr) ->
        let field_value = eval_expression ctx field_expr in
        (field_name, field_value)
      ) field_assignments in
      StructValue field_values
      
  | Match (matched_expr, arms) ->
      let matched_value = eval_expression ctx matched_expr in
      let rec try_arms = function
        | [] -> eval_error "No matching pattern in match expression" expr.expr_pos
        | arm :: remaining_arms ->
            let pattern_matches = match arm.arm_pattern with
              | ConstantPattern lit ->
                  let literal_value = runtime_value_of_literal lit in
                  runtime_values_equal matched_value literal_value
              | IdentifierPattern name ->
                  (* Check if this is an enum constant *)
                  (match ctx.symbol_table with
                   | Some symbol_table ->
                       (match Symbol_table.lookup_symbol symbol_table name with
                        | Some { kind = Symbol_table.EnumConstant (_, Some value); _ } ->
                            (match matched_value with
                             | EnumValue (_, matched_val) -> matched_val = value
                             | IntValue matched_val -> matched_val = value
                             | _ -> false)
                        | _ -> false)
                   | None -> false)
              | DefaultPattern -> true
            in
            
            if pattern_matches then
              match arm.arm_body with
              | SingleExpr arm_expr -> eval_expression ctx arm_expr
              | Block arm_stmts ->
                  eval_statements ctx arm_stmts;
                  UnitValue  (* Default return for block *)
            else
              try_arms remaining_arms
      in
      try_arms arms

  | New _ ->
      (* For evaluator, object allocation returns a mock pointer value *)
      (* This is just for testing - real allocation happens in generated code *)
      PointerValue (Random.int 1000000)
      
  | NewWithFlag (_, _) ->
      (* For evaluator, object allocation with flag returns a mock pointer value *)
      (* This is just for testing - real allocation happens in generated code *)
      PointerValue (Random.int 1000000)

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
  
  | CompoundAssignment (name, op, expr) ->
      let right_value = eval_expression ctx expr in
      let left_value = try Hashtbl.find ctx.variables name 
                      with Not_found -> raise (Evaluation_error ("Undefined variable: " ^ name, stmt.stmt_pos)) in
      let result = eval_binary_op left_value op right_value stmt.stmt_pos in
      Hashtbl.replace ctx.variables name result
  
  | CompoundIndexAssignment (map_expr, key_expr, op, value_expr) ->
      (* Handle map compound assignment: map[key] op= value *)
      let map_name = match map_expr.expr_desc with
        | Identifier name when Hashtbl.mem ctx.maps name -> name
        | Identifier name -> eval_error ("Not a map: " ^ name) stmt.stmt_pos
        | _ -> eval_error ("Map compound assignment requires a map identifier") stmt.stmt_pos
      in
      let key_val = eval_expression ctx key_expr in
      let value_val = eval_expression ctx value_expr in
      
      let map_store = 
        try Hashtbl.find ctx.map_storage map_name
        with Not_found -> eval_error ("Map not found: " ^ map_name) stmt.stmt_pos
      in
      
      let key_str = string_of_runtime_value key_val in
      let current_val = 
        try Hashtbl.find map_store key_str
        with Not_found -> IntValue 0 (* Default to 0 for new keys *)
      in
      let result = eval_binary_op current_val op value_val stmt.stmt_pos in
      Hashtbl.replace map_store key_str result
  
  | FieldAssignment (obj_expr, _field, value_expr) ->
      (* For evaluation purposes, treat config field assignment as no-op *)
      let _ = eval_expression ctx obj_expr in
      let _ = eval_expression ctx value_expr in
      (match obj_expr.expr_desc with
       | Identifier _config_name ->
           (* Config field assignment handled during evaluation *)
           ()
       | _ -> eval_error ("Field assignment only supported for config objects") stmt.stmt_pos)
  
  | ArrowAssignment (obj_expr, _field, value_expr) ->
      (* Arrow assignment (pointer->field = value) - for evaluator, treat same as field assignment *)
      let _ = eval_expression ctx value_expr in
      (match obj_expr.expr_desc with
       | Identifier _name ->
           (* Arrow assignment handled during evaluation *)
           ()
       | _ -> eval_error ("Arrow assignment only supported for simple identifiers") stmt.stmt_pos)
  
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
      Hashtbl.replace map_store key_str value_val
  
  | Declaration (name, _, expr_opt) ->
      (match expr_opt with
       | Some expr ->
           let value = eval_expression ctx expr in
           Hashtbl.add ctx.variables name value;
           let _ = allocate_variable_address ctx name value in
           ()
       | None ->
           (* Uninitialized variable - assign default value *)
           let default_value = IntValue 0 in
           Hashtbl.add ctx.variables name default_value;
           let _ = allocate_variable_address ctx name default_value in
           ())
  
  | ConstDeclaration (name, _, expr) ->
      let value = eval_expression ctx expr in
      Hashtbl.add ctx.variables name value;
      let _ = allocate_variable_address ctx name value in
      ()
  
  | Return None ->
      raise (Return_value UnitValue)
  
  | Return (Some expr) ->
      let value = eval_expression ctx expr in
      raise (Return_value value)
  
  | If (cond, then_stmts, else_opt) ->
      let cond_val = eval_expression ctx cond in
      let cond_bool = is_truthy_value cond_val in  (* Use truthy/falsy conversion *)
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
        let cond_bool = is_truthy_value cond_val in  (* Use truthy/falsy conversion *)
        if cond_bool then
          (try
             eval_statements ctx body;
             loop ()
           with
           | Break_loop -> ()
           | Continue_loop -> loop ())
      in
      loop ()

  | Delete target ->
      (match target with
      | DeleteMapEntry (map_expr, key_expr) ->
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
            Hashtbl.remove map_store key_str
      | DeletePointer _ptr_expr ->
          (* For evaluator, pointer deletion is a no-op since we don't have real memory management *)
          ())
  
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
      eval_error ("Unhandled error: " ^ string_of_int error_code) stmt.stmt_pos
      
  | Defer expr ->
      (* For evaluator, just evaluate the expression immediately *)
      let _ = eval_expression ctx expr in
      ()

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
      | Probe _ -> ContextValue ("kprobe", [
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
let evaluate_program symbol_table maps functions prog =
  let ctx = create_eval_context symbol_table maps functions in
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
