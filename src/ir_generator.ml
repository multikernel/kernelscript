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

(** IR Generator - AST to IR Lowering
    This module implements the lowering from typed AST to IR, including:
    - Expression and statement lowering
    - Control flow graph construction  
    - Built-in function expansion
    - Safety check insertion
    - Map operation lowering
*)

open Ast
open Ir
open Maps
open Loop_analysis

(** Context for IR generation *)
type ir_context = {
  (* Next available temporary variable ID *)
  mutable next_temp_id: int;
  (* Current basic block being built *)
  mutable current_block: ir_instruction list;
  (* All basic blocks generated *)
  mutable blocks: ir_basic_block list;
  (* Next block ID *)
  mutable next_block_id: int;
  (* Current stack usage *)
  mutable stack_usage: int;
  (* Map declarations in scope *)
  maps: (string, ir_map_def) Hashtbl.t;
  (* Function being processed *)
  mutable current_function: string option;
  (* Symbol table reference *)
  symbol_table: Symbol_table.symbol_table;
  (* Helper function names to avoid tail call conversion *)
  helper_functions: (string, unit) Hashtbl.t;
  (* Assignment optimization info *)
  mutable assignment_optimizations: Map_assignment.optimization_info option;
  (* Constant environment for loop analysis *)
  mutable const_env: Loop_analysis.const_env option;
  mutable in_bpf_loop_callback: bool; (* New field to track bpf_loop context *)
  mutable is_userspace: bool; (* New field to track if the program is userspace *)
  mutable in_try_block: bool; (* New field to track if we're inside a try block *)

  (* Track variable names to their original declared type names *)
  variable_declared_types: (string, string) Hashtbl.t; (* variable_name -> original_type_name *)
  (* Track function parameters to avoid allocating registers for them *)
  function_parameters: (string, ir_type) Hashtbl.t; (* param_name -> param_type *)
  (* Track global variables for proper access *)
  global_variables: (string, ir_global_variable) Hashtbl.t; (* global_var_name -> global_var *)
  (* Track variables that originate from map accesses *)
  map_origin_variables: (string, (string * ir_value * (ir_value_desc * ir_type))) Hashtbl.t; (* var_name -> (map_name, key, underlying_info) *)
  (* Track inferred variable types for proper lookups *)
  variable_types: (string, ir_type) Hashtbl.t; (* var_name -> ir_type *)
}

(** Create new IR generation context *)
let create_context ?(global_variables = []) ?(helper_functions = []) symbol_table = {
  next_temp_id = 0;
  current_block = [];
  blocks = [];
  next_block_id = 0;
  stack_usage = 0;
  maps = Hashtbl.create 16;
  current_function = None;
  symbol_table;
  assignment_optimizations = None;
  const_env = None;
  in_bpf_loop_callback = false;
  is_userspace = false;
  in_try_block = false;
  variable_declared_types = Hashtbl.create 32;
  function_parameters = Hashtbl.create 32;
  global_variables = (let tbl = Hashtbl.create 16 in
                     List.iter (fun gv -> Hashtbl.add tbl gv.global_var_name gv) global_variables;
                     tbl);
  map_origin_variables = Hashtbl.create 32;
  variable_types = Hashtbl.create 32;
  helper_functions = (let tbl = Hashtbl.create 16 in
                     List.iter (fun helper_name -> Hashtbl.add tbl helper_name ()) helper_functions;
                     tbl);
}


(** Generate a new temporary variable name *)
let generate_temp_variable ctx base_name =
  let temp_name = Printf.sprintf "__%s_%d" base_name ctx.next_temp_id in
  ctx.next_temp_id <- ctx.next_temp_id + 1;
  temp_name

(** Helper function to generate temporary variable and create IR value in one step *)
let allocate_temp_variable ctx base_name ir_type pos =
  let temp_name = generate_temp_variable ctx base_name in
  make_ir_value (IRTempVariable temp_name) ir_type pos

(** Create new basic block *)
let create_basic_block ctx label =
  let block_id = ctx.next_block_id in
  ctx.next_block_id <- ctx.next_block_id + 1;
  let block = make_ir_basic_block label (List.rev ctx.current_block) block_id in
  ctx.blocks <- block :: ctx.blocks;
  ctx.current_block <- [];
  block

(** Analyze assignment patterns for optimization *)
let analyze_assignment_patterns ctx (ast: declaration list) =
  let assignments = Map_assignment.extract_map_assignments_from_ast ast in
  let optimization_info = Map_assignment.analyze_assignment_optimizations assignments in
  ctx.assignment_optimizations <- Some optimization_info;
  optimization_info

(** Add instruction to current block *)
let emit_instruction ctx instr =
  ctx.current_block <- instr :: ctx.current_block;
  ctx.stack_usage <- ctx.stack_usage + instr.instr_stack_usage

(** Emit variable declaration - new unified approach *)
let emit_variable_decl ctx var_name ir_type init_expr_opt pos =
  let instr = make_ir_instruction (IRVariableDecl (var_name, ir_type, init_expr_opt)) pos in
  emit_instruction ctx instr

(** Expand ring buffer operations to IR instructions *)
let expand_ringbuf_operation ctx ringbuf_name operation arg_vals pos =
  (* Get the ring buffer variable - could be local or global *)
  let (ringbuf_val, ringbuf_type) = 
    if Hashtbl.mem ctx.global_variables ringbuf_name then
      (* Global variable *)
      let global_var = Hashtbl.find ctx.global_variables ringbuf_name in
      (make_ir_value (IRVariable ringbuf_name) global_var.global_var_type pos, global_var.global_var_type)
    else
      (* Local variable - look up in symbol table *)
      (match Symbol_table.lookup_symbol ctx.symbol_table ringbuf_name with
       | Some symbol -> 
           (match symbol.kind with
            | Symbol_table.Variable var_ast_type -> 
                let ringbuf_type = ast_type_to_ir_type_with_context ctx.symbol_table var_ast_type in
                (make_ir_value (IRVariable ringbuf_name) ringbuf_type pos, ringbuf_type)
            | _ -> failwith ("Variable is not a ringbuf: " ^ ringbuf_name))
       | None -> failwith ("Ringbuf variable not found in symbol table: " ^ ringbuf_name))
  in
  
  match operation with
  | "reserve" ->
      (* reserve() returns a pointer to the value type *)
      let result_type = match ringbuf_type with
        | IRRingbuf (value_type, _) -> IRPointer (value_type, make_bounds_info ())
        | _ -> failwith ("Variable is not a ringbuf type")
      in
      (* Create a special IR expression that directly represents the ringbuf reserve call *)
      (* This will be converted to the proper C call without intermediate assignments *)
      let result_val = allocate_temp_variable ctx "ringbuf_reserve" result_type pos in
      let ringbuf_op = RingbufReserve result_val in
      let instr = make_ir_instruction (IRRingbufOp (ringbuf_val, ringbuf_op)) pos in
      emit_instruction ctx instr;
      result_val
  
  | "submit" ->
      (* submit(data_pointer) returns i32 success code *)
      let data_val = match arg_vals with
        | [data] -> data
        | _ -> failwith ("Ring buffer submit() requires exactly one argument")
      in
      let result_val = allocate_temp_variable ctx "ringbuf_submit" IRI32 pos in
      let ringbuf_op = RingbufSubmit data_val in
      let instr = make_ir_instruction (IRRingbufOp (ringbuf_val, ringbuf_op)) pos in
      emit_instruction ctx instr;
      result_val
  
  | "discard" ->
      (* discard(data_pointer) returns i32 success code *)
      let data_val = match arg_vals with
        | [data] -> data
        | _ -> failwith ("Ring buffer discard() requires exactly one argument")
      in
      let result_val = allocate_temp_variable ctx "ringbuf_discard" IRI32 pos in
      let ringbuf_op = RingbufDiscard data_val in
      let instr = make_ir_instruction (IRRingbufOp (ringbuf_val, ringbuf_op)) pos in
      emit_instruction ctx instr;
      result_val
  
  | "on_event" ->
      (* on_event(handler) returns i32 success code *)
      let handler_name = match arg_vals with
        | [handler_val] ->
            (* Extract function name from the handler value *)
            (match handler_val.value_desc with
             | IRFunctionRef name -> name
             | IRVariable name -> name  (* Function variable *)
             | _ -> failwith ("Ring buffer on_event() requires a function argument"))
        | _ -> failwith ("Ring buffer on_event() requires exactly one argument")
      in
      let result_val = allocate_temp_variable ctx "ringbuf_on_event" IRI32 pos in
      let ringbuf_op = RingbufOnEvent handler_name in
      let instr = make_ir_instruction (IRRingbufOp (ringbuf_val, ringbuf_op)) pos in
      emit_instruction ctx instr;
      result_val
  
  | _ ->
      failwith ("Unknown ring buffer operation: " ^ operation)

(** Generate bounds information for types *)
let generate_bounds_info ast_type = match ast_type with
  | Ast.Array (_, size) -> make_bounds_info ~min_size:size ~max_size:size ()
  | Ast.Pointer _ -> make_bounds_info ~nullable:true ()
  | _ -> make_bounds_info ()

(** Lower AST literals to IR values *)
let lower_literal lit pos =
  let ir_lit = IRLiteral lit in
  let ir_type = match lit with
    | IntLit (_, _) -> IRU32  (* Default integer type *)
    | StringLit s -> IRStr (max 1 (String.length s))  (* String literals get IRStr type *)
    | CharLit _ -> IRChar
    | BoolLit _ -> IRBool
    | NullLit -> 
        let bounds = make_bounds_info ~nullable:true () in
        IRPointer (IRU32, bounds)  (* null literal as nullable pointer to u32 *)
    | NoneLit -> IRU32  (* none literal as sentinel u32 value *)
    | ArrayLit init_style -> 
        (* Handle enhanced array literal lowering *)
        (match init_style with
         | ZeroArray ->
             (* [] - zero initialize, size determined by context *)
             IRArray (IRU32, 0, make_bounds_info ())
         | FillArray fill_lit ->
             (* [0] - fill entire array with single value, size from context *)
             let element_ir_type = match fill_lit with
               | IntLit _ -> IRU32
               | BoolLit _ -> IRBool
               | CharLit _ -> IRChar
               | StringLit _ -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
               | NullLit -> 
                   let bounds = make_bounds_info ~nullable:true () in
                   IRPointer (IRU32, bounds)
               | NoneLit -> IRU32  (* none literal as sentinel u32 value *)
               | ArrayLit _ -> IRU32  (* Nested arrays default to u32 *)
             in
             IRArray (element_ir_type, 0, make_bounds_info ())  (* Size resolved during type unification *)
         | ExplicitArray literals ->
             (* [a,b,c] - explicit values, zero-fill rest *)
             let element_count = List.length literals in
             if element_count = 0 then
               IRArray (IRU32, 0, make_bounds_info ())
             else
               let first_lit = List.hd literals in
               let element_ir_type = match first_lit with
                 | IntLit _ -> IRU32
                 | BoolLit _ -> IRBool
                 | CharLit _ -> IRChar
                 | StringLit _ -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
                 | ArrayLit _ -> IRU32  (* Nested arrays default to u32 *)
                 | NullLit -> 
                     let bounds = make_bounds_info ~nullable:true () in
                     IRPointer (IRU32, bounds)
                 | NoneLit -> IRU32  (* none literal as sentinel u32 value *)
               in
               let bounds_info = make_bounds_info ~min_size:element_count ~max_size:element_count () in
               IRArray (element_ir_type, element_count, bounds_info))
  in
  make_ir_value ir_lit ir_type pos

(** Lower AST binary operators to IR *)
let lower_binary_op = function
  | Add -> IRAdd | Sub -> IRSub | Mul -> IRMul | Div -> IRDiv | Mod -> IRMod
  | Eq -> IREq | Ne -> IRNe | Lt -> IRLt | Le -> IRLe | Gt -> IRGt | Ge -> IRGe
  | And -> IRAnd | Or -> IROr

(** Lower AST unary operators to IR *)
let lower_unary_op = function
  | Not -> IRNot
  | Neg -> IRNeg
  | Deref -> IRDeref
  | AddressOf -> IRAddressOf

(** Convert context field C type to IR type *)
let c_type_to_ir_type = function
  | "__u8*" -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
  | "__u16*" -> IRPointer (IRU16, make_bounds_info ~nullable:false ())
  | "__u32*" -> IRPointer (IRU32, make_bounds_info ~nullable:false ())
  | "__u64*" -> IRPointer (IRU64, make_bounds_info ~nullable:false ())
  | "__u8" -> IRU8
  | "__u16" -> IRU16
  | "__u32" -> IRU32
  | "__u64" -> IRU64
  | "void*" -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
  | c_type -> failwith ("Unsupported context field C type: " ^ c_type)

(** Unified AST literal to IR type conversion *)
let literal_to_ir_type = function
  | IntLit _ -> IRU32
  | BoolLit _ -> IRBool
  | CharLit _ -> IRChar
  | StringLit _ -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
  | NullLit -> IRPointer (IRU32, make_bounds_info ~nullable:true ())
  | NoneLit -> IRU32
  | ArrayLit _ -> IRU32  (* Default for arrays *)

(** Unified AST to IR type conversion for basic types *)
let ast_basic_type_to_ir_type = function
  | Ast.U8 -> IRU8
  | Ast.U16 -> IRU16
  | Ast.U32 -> IRU32
  | Ast.U64 -> IRU64
  | Ast.I8 -> IRI8
  | Ast.I16 -> IRI16
  | Ast.I32 -> IRI32
  | Ast.I64 -> IRI64
  | Ast.Bool -> IRBool
  | Ast.Char -> IRChar
  | _ -> failwith "Not a basic type"

(** Helper to add maps to context hashtable *)
let add_maps_to_context ctx maps =
  List.iter (fun (map_def : ir_map_def) -> 
    Hashtbl.add ctx.maps map_def.map_name map_def
  ) maps

(** Helper to copy maps between contexts *)
let copy_maps_to_context source_ctx target_ctx =
  Hashtbl.iter (fun map_name map_def -> 
    Hashtbl.add target_ctx.maps map_name map_def
  ) source_ctx.maps

(** Helper to extract kernel struct name from @struct_ops attribute **)
let extract_struct_ops_kernel_name attributes =
  List.fold_left (fun acc attr ->
    match attr with
    | Ast.AttributeWithArg ("struct_ops", name) -> name
    | _ -> acc
  ) "" attributes


(** Map struct names to their corresponding context types *)
let struct_name_to_context_type = function
  | "xdp_md" -> Some "xdp"
  | "__sk_buff" -> Some "tc"
  | "pt_regs" -> Some "kprobe"
  (* trace_event_raw_* structs are regular structs, not context types *)
  | _ -> None

(** Determine result type for arrow access expressions *)
let determine_arrow_access_type ctx obj_val field expr_type_opt =
  match obj_val.val_type with
  | IRPointer (IRStruct (struct_name, _), _) ->
      (* Check if this is a context struct *)
      (match struct_name_to_context_type struct_name with
       | Some ctx_type_str ->
           (* Use field mapping to get precise type information *)
           (match Kernelscript_context.Context_codegen.get_context_field_c_type ctx_type_str field with
            | Some c_type -> c_type_to_ir_type c_type
            | None -> failwith ("Unknown context field: " ^ field ^ " for context type: " ^ ctx_type_str))
       | None ->
           (* Regular struct field access *)
           (match expr_type_opt with
            | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
            | None -> IRU32))
  | _ ->
      (* Non-context types - use expression type annotation *)
      (match expr_type_opt with
       | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
       | None -> IRU32)

(** Generate bounds check for array access *)
let generate_array_bounds_check ctx array_val index_val pos =
  match array_val.val_type with
  | IRArray (_, size, _) ->
      let bounds_check = {
        value = index_val;
        min_bound = 0;
        max_bound = size - 1;
        check_type = ArrayAccess;
      } in
      let instr = make_ir_instruction
        (IRBoundsCheck (index_val, 0, size - 1))
        ~bounds_checks:[bounds_check]
        ~verifier_hints:[BoundsChecked]
        pos
      in
      emit_instruction ctx instr
  | _ -> ()



(** Map context field names to IR access types using BTF-integrated context codegen *)
(* No longer needed - we use BTF field names directly *)

(** Handle context field access with comprehensive BTF support *)
let handle_context_field_access_comprehensive ctx_type _obj_val field result_val expr_pos =
  (* Check if field exists in BTF-integrated context codegen *)
  match Kernelscript_context.Context_codegen.get_context_field_c_type ctx_type field with
  | Some _c_type ->
      (* Field exists in BTF - generate direct field access using BTF field name *)
      let instr = make_ir_instruction
        (IRContextAccess (result_val, ctx_type, field))
        expr_pos
      in
      Some instr
  | None ->
      (* Field doesn't exist in BTF *)
      None


(** Expand map operations *)
let expand_map_operation ctx map_name operation key_val value_val_opt pos =
  let map_def = Hashtbl.find ctx.maps map_name in
  let map_val = make_ir_value (IRMapRef map_name) 
    (IRPointer (IRStruct ("map", []), make_bounds_info ())) pos in
  
  match operation with
  | "lookup" ->
      (* Map lookup returns pointer to value type, not value type itself *)
      let result_val = allocate_temp_variable ctx "map_lookup" 
        (IRPointer (map_def.map_value_type, make_bounds_info ())) pos in
      let instr = make_ir_instruction
        (IRMapLoad (map_val, key_val, result_val, MapLookup))
        ~verifier_hints:[HelperCall "map_lookup_elem"]
        pos
      in
      emit_instruction ctx instr;
      result_val
  | "update" ->
      let value_val = match value_val_opt with
        | Some v -> v
        | None -> failwith "Map update requires value"
      in
      let instr = make_ir_instruction
        (IRMapStore (map_val, key_val, value_val, MapUpdate))
        ~verifier_hints:[HelperCall "map_update_elem"]
        pos
      in
      emit_instruction ctx instr;
      (* Return success value *)
      make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 pos
  | "delete" ->
      let instr = make_ir_instruction
        (IRMapDelete (map_val, key_val))
        ~verifier_hints:[HelperCall "map_delete_elem"]
        pos
      in
      emit_instruction ctx instr;
      make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 pos

  | _ -> failwith ("Unknown map operation: " ^ operation)

(** Lower AST expressions to IR values *)
let rec lower_expression ctx (expr : Ast.expr) =
  match expr.expr_desc with
  | Ast.Literal lit ->
      lower_literal lit expr.expr_pos
      
  | Ast.Identifier name ->
      (* Check if this is a map identifier *)
      if Hashtbl.mem ctx.maps name then
        (* For map identifiers, create a map reference *)
        let map_type = IRPointer (IRU8, make_bounds_info ()) in (* Maps are represented as pointers *)
        make_ir_value (IRMapRef name) map_type expr.expr_pos
      else
        (* Check if this variable originates from a map access *)
        (match Hashtbl.find_opt ctx.map_origin_variables name with
         | Some (map_name, key, underlying_info) ->
             (* This variable originates from a map access - recreate the IRMapAccess *)
             let map_def = Hashtbl.find ctx.maps map_name in
             { value_desc = IRMapAccess (map_name, key, underlying_info); 
               val_type = map_def.map_value_type; 
               stack_offset = None; 
               bounds_checked = false; 
               val_pos = expr.expr_pos }
         | None ->
             (* Regular variable or function reference *)
             (match expr.expr_type with
              | Some (Function (param_types, return_type)) ->
                  (* Function references should be converted to function references *)
                  let ir_param_types = List.map ast_type_to_ir_type param_types in
                  let ir_return_type = ast_type_to_ir_type return_type in
                  let func_type = IRFunctionPointer (ir_param_types, ir_return_type) in
                  make_ir_value (IRFunctionRef name) func_type expr.expr_pos
              | Some (ProgramRef _) ->
                  (* Program references should be converted to string literals containing the program name *)
                  make_ir_value (IRLiteral (StringLit name)) IRU32 expr.expr_pos
              | _ ->
                  (* Regular variable lookup *)
                  if Hashtbl.mem ctx.function_parameters name then
                    let param_type = Hashtbl.find ctx.function_parameters name in
                    make_ir_value (IRVariable name) param_type expr.expr_pos
                  else if Hashtbl.mem ctx.global_variables name then
                    let global_var = Hashtbl.find ctx.global_variables name in
                    make_ir_value (IRVariable name) global_var.global_var_type expr.expr_pos
                  else
                    (* Check symbol table for various types of identifiers *)
                    (match Symbol_table.lookup_symbol ctx.symbol_table name with
                     | Some symbol ->
                         (match symbol.kind with
                          | Symbol_table.EnumConstant (enum_name, Some value) ->
                              (* Preserve enum constants as identifiers *)
                              let ir_type = match expr.expr_type with
                                | Some ast_type -> ast_type_to_ir_type ast_type
                                | None -> IRU32
                              in
                              (* Use the inferred type directly - no special handling for action types *)
                              let final_ir_type = ir_type in
                              make_ir_value (IREnumConstant (enum_name, name, value)) final_ir_type expr.expr_pos
                          | Symbol_table.EnumConstant (_, None) ->
                              (* Enum constant without value - treat as variable *)
                              let ir_type = match expr.expr_type with
                                | Some ast_type -> ast_type_to_ir_type ast_type
                                | None -> failwith ("Untyped identifier: " ^ name)
                              in
                              make_ir_value (IRVariable name) ir_type expr.expr_pos
                          | Symbol_table.TypeDef _ ->
                              (* This is a type definition (like impl blocks) - treat as variable *)
                              let ir_type = match expr.expr_type with
                                | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
                                | None -> IRStruct (name, []) (* Default to struct type for impl blocks *)
                              in
                              make_ir_value (IRVariable name) ir_type expr.expr_pos
                          | _ ->
                              (* Other symbol types - treat as variable *)
                              let ir_type = match expr.expr_type with
                                | Some ast_type -> ast_type_to_ir_type ast_type
                                | None -> failwith ("Untyped identifier: " ^ name)
                              in
                              make_ir_value (IRVariable name) ir_type expr.expr_pos)
                     | None ->
                         (* Symbol not found - treat as regular variable *)

                         let ir_type = 
                           (* Always prioritize the tracked variable type from declaration *)
                           match Hashtbl.find_opt ctx.variable_types name with
                           | Some tracked_type -> tracked_type
                           | None ->
                               (* Fall back to expression type annotation *)
                               (match expr.expr_type with
                                | Some ast_type -> ast_type_to_ir_type ast_type
                                | None -> 
                                    (* Final fallback to symbol table lookup *)
                                    (match Symbol_table.lookup_symbol ctx.symbol_table name with
                                     | Some symbol -> 
                                         (match symbol.kind with
                                          | Symbol_table.Variable var_ast_type -> 
                                              ast_type_to_ir_type_with_context ctx.symbol_table var_ast_type
                                          | _ -> failwith ("Untyped identifier: " ^ name))
                                     | None -> failwith ("Untyped identifier: " ^ name)))
                         in
                         make_ir_value (IRVariable name) ir_type expr.expr_pos)))
      
  | Ast.ConfigAccess (config_name, field_name) ->
      (* Handle config access like config.field_name *)
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> IRU32 (* Default type for config fields *)
      in
      let result_val = allocate_temp_variable ctx "config_access" result_type expr.expr_pos in
      
      (* Generate new IRConfigAccess instruction *)
      let config_access_instr = make_ir_instruction
        (IRConfigAccess (config_name, field_name, result_val))
        expr.expr_pos
      in
      emit_instruction ctx config_access_instr;
      result_val
      
  | Ast.TailCall (name, _args) ->
      (* This shouldn't be reached during normal IR generation *)
      (* Tail calls are handled specifically in return statements *)
      failwith ("Tail call to " ^ name ^ " should only appear in return statements")
      
  | Ast.ModuleCall module_call ->
      (* Module calls are handled by userspace code generation, not IR *)
      failwith ("Module call to " ^ module_call.module_name ^ "." ^ module_call.function_name ^ " should be handled in userspace code generation")
      
  | Ast.Call (callee_expr, args) ->
      let arg_vals = List.map (lower_expression ctx) args in
      
      (* Check if this is a void function call *)
      let is_void_call = match expr.expr_type with
        | Some Ast.Void -> true
        | _ -> false
      in
      
      (* Determine call type based on callee expression *)
      (match callee_expr.expr_desc with
       | Ast.Identifier name ->
           (* Check if this is a variable holding a function pointer or a direct function call *)
           if name = "register" then
             (* Special handling for register() builtin function *)
              handle_register_builtin_call ctx args expr.expr_pos ()
           else if Hashtbl.mem ctx.function_parameters name || 
                   (Hashtbl.mem ctx.variable_types name && 
                    match Hashtbl.find ctx.variable_types name with 
                    | IRFunctionPointer _ -> true 
                    | _ -> false) then
             (* This is a variable holding a function pointer - use FunctionPointerCall *)
             let callee_val = lower_expression ctx callee_expr in
             if is_void_call then
               (* Void function pointer call - no return value *)
               let instr = make_ir_instruction
                 (IRCall (FunctionPointerCall callee_val, arg_vals, None))
                 expr.expr_pos
               in
               emit_instruction ctx instr;
               (* Return a dummy value for void calls - this should not be used *)
               make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 expr.expr_pos
             else
               (* Non-void function pointer call *)
               let result_type = match expr.expr_type with
                 | Some ast_type -> ast_type_to_ir_type ast_type
                 | None -> IRU32
               in
               let result_val = allocate_temp_variable ctx "func_ptr_call" result_type expr.expr_pos in
               let instr = make_ir_instruction
                 (IRCall (FunctionPointerCall callee_val, arg_vals, Some result_val))
                 expr.expr_pos
               in
               emit_instruction ctx instr;
               result_val
           else
             (* This is a direct function call *)
             if is_void_call then
               (* Void function call - no return value *)
               let instr = make_ir_instruction
                 (IRCall (DirectCall name, arg_vals, None))
                 expr.expr_pos
               in
               emit_instruction ctx instr;
               (* Return a dummy value for void calls - this should not be used *)
               make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 expr.expr_pos
             else
               (* Non-void function call *)
               let result_type = match expr.expr_type with
                 | Some ast_type -> ast_type_to_ir_type ast_type
                 | None -> IRU32
               in
               let result_val = allocate_temp_variable ctx "func_call" result_type expr.expr_pos in
               let instr = make_ir_instruction
                 (IRCall (DirectCall name, arg_vals, Some result_val))
                 expr.expr_pos
               in
               emit_instruction ctx instr;
               result_val
       | Ast.FieldAccess ({expr_desc = Ast.Identifier obj_name; _}, method_name) ->
           (* Method call (e.g., ringbuf.operation()) *)
           if Hashtbl.mem ctx.maps obj_name then
             (* Handle map operations *)
             let key_val = if List.length arg_vals > 0 then List.hd arg_vals 
                          else make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 expr.expr_pos in
             let value_val_opt = if List.length arg_vals > 1 then Some (List.nth arg_vals 1) else None in
             expand_map_operation ctx obj_name method_name key_val value_val_opt expr.expr_pos
           else
             (* Check if this is a local or global variable that supports method calls *)
             let var_type_opt = 
               (* First check tracked variable types *)
               match Hashtbl.find_opt ctx.variable_types obj_name with
               | Some ir_type -> Some ir_type
               | None ->
                   (* Check global variables *)
                   if Hashtbl.mem ctx.global_variables obj_name then
                     let global_var = Hashtbl.find ctx.global_variables obj_name in
                     Some global_var.global_var_type
                   else
                     (* Fall back to symbol table lookup *)
                     (match Symbol_table.lookup_symbol ctx.symbol_table obj_name with
                      | Some symbol -> 
                          (match symbol.kind with
                           | Symbol_table.Variable var_ast_type -> 
                               Some (ast_type_to_ir_type_with_context ctx.symbol_table var_ast_type)
                           | _ -> None)
                      | None -> None)
             in
             (match var_type_opt with
              | Some (IRRingbuf (_, _)) ->
                  (* This is a ringbuf object that supports method calls *)
                  expand_ringbuf_operation ctx obj_name method_name arg_vals expr.expr_pos
              | Some var_type ->
                  failwith ("Method call '" ^ method_name ^ "' not supported on variable '" ^ obj_name ^ "' of type: " ^ (string_of_ir_type var_type))
              | None ->
                  failwith ("Unknown method call: " ^ obj_name ^ "." ^ method_name))
       | _ ->
           (* Function pointer call - use FunctionPointerCall target *)
           let callee_val = lower_expression ctx callee_expr in
           (* Use the arg_vals that were already calculated at the beginning of the Call case *)
           if is_void_call then
             (* Void function pointer call - no return value *)
             let instr = make_ir_instruction
               (IRCall (FunctionPointerCall callee_val, arg_vals, None))
               expr.expr_pos
             in
             emit_instruction ctx instr;
             (* Return a dummy value for void calls - this should not be used *)
             make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 expr.expr_pos
           else
             (* Non-void function pointer call *)
             let result_type = match expr.expr_type with
               | Some ast_type -> ast_type_to_ir_type ast_type
               | None -> IRU32
             in
             let result_val = allocate_temp_variable ctx "func_ptr_call" result_type expr.expr_pos in
             let instr = make_ir_instruction
               (IRCall (FunctionPointerCall callee_val, arg_vals, Some result_val))
               expr.expr_pos
             in
             emit_instruction ctx instr;
             result_val)
        
  | Ast.ArrayAccess (array_expr, index_expr) ->
      (* Check if this is map access first, before calling lower_expression on array *)
      (match array_expr.expr_desc with
       | Ast.Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           (* This is map access - handle it specially *)
           let index_val = lower_expression ctx index_expr in
           let lookup_result = expand_map_operation ctx map_name "lookup" index_val None expr.expr_pos in
           (* Use the pointer type returned by expand_map_operation, not the value type *)
           { value_desc = IRMapAccess (map_name, index_val, (lookup_result.value_desc, lookup_result.val_type)); 
             val_type = lookup_result.val_type;  (* Use the pointer type from lookup_result *)
             stack_offset = None; 
             bounds_checked = false; 
             val_pos = expr.expr_pos }
       | _ ->
           (* Regular array access *)
           let array_val = lower_expression ctx array_expr in
           let index_val = lower_expression ctx index_expr in
           
           (* Generate bounds check *)
           generate_array_bounds_check ctx array_val index_val expr.expr_pos;
           
           let element_type = match array_val.val_type with
             | IRArray (elem_type, _, _) -> elem_type
             | IRStr _ -> IRChar  (* String indexing returns char *)
             | _ -> failwith "Array access on non-array type"
           in
           let result_val = allocate_temp_variable ctx "array_access" element_type expr.expr_pos in
           
           (match array_val.val_type with
            | IRStr _ ->
                (* For strings, generate direct indexing: str.data[index] *)
                let index_expr = make_ir_expr (IRBinOp (array_val, IRAdd, index_val)) element_type expr.expr_pos in
                (* For strings, we need to emit a variable declaration and assignment *)
                emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") element_type (Some index_expr) expr.expr_pos
            | _ ->
                (* For arrays, generate pointer arithmetic and load *)
                let ptr_val = allocate_temp_variable ctx "array_ptr" 
                  (IRPointer (element_type, make_bounds_info ())) expr.expr_pos in
                
                (* ptr = &array[index] *)
                let ptr_expr = make_ir_expr (IRBinOp (array_val, IRAdd, index_val)) 
                  ptr_val.val_type expr.expr_pos in
                emit_variable_decl ctx (match ptr_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") ptr_val.val_type (Some ptr_expr) expr.expr_pos;
                
                (* result = *ptr *)
                let load_expr = make_ir_expr (IRValue ptr_val) element_type expr.expr_pos in
                emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") element_type (Some load_expr) expr.expr_pos);
           
           result_val)
           
  | Ast.FieldAccess (obj_expr, field) ->
      let obj_val = lower_expression ctx obj_expr in
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
        | None -> IRU32
      in
      let result_val = allocate_temp_variable ctx "field_access" result_type expr.expr_pos in
      
      (* Handle field access for different types *)
      (match obj_val.val_type with
       | IRStruct (struct_name, _) ->
           (* Check if this is a context struct *)
           (match struct_name_to_context_type struct_name with
            | Some ctx_type_str ->
                (* Handle context field access using centralized mapping *)
                (match handle_context_field_access_comprehensive ctx_type_str obj_val field result_val expr.expr_pos with
                 | Some instr -> 
                     emit_instruction ctx instr;
                     result_val
                 | None ->
                     failwith ("Unknown context field: " ^ field ^ " for context type: " ^ ctx_type_str))
            | None ->
                (* Handle regular struct field access *)
                let field_expr = make_ir_expr (IRFieldAccess (obj_val, field)) result_type expr.expr_pos in
                emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_type (Some field_expr) expr.expr_pos;
                result_val)
       | IRRingbuf (_, _) ->
           (* Handle ring buffer field access - convert to method calls *)
           (match field with
            | "reserve" ->
                (* reserve() - generate ring buffer reserve operation *)
                let ringbuf_op = RingbufReserve result_val in
                let instr = make_ir_instruction (IRRingbufOp (obj_val, ringbuf_op)) expr.expr_pos in
                emit_instruction ctx instr;
                result_val
            | "submit" | "discard" | "on_event" ->
                (* These operations require arguments, so should be handled as function calls, not field access *)
                failwith ("Ring buffer operation '" ^ field ^ "' requires arguments and should be called as a function")
            | _ ->
                failwith ("Unknown ring buffer operation: " ^ field))
       | _ ->
           (* For userspace code, allow field access on other types (assuming it will be handled by C compilation) *)
           if ctx.is_userspace then
             let field_expr = make_ir_expr (IRFieldAccess (obj_val, field)) result_type expr.expr_pos in
             emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_type (Some field_expr) expr.expr_pos;
             result_val
           else
             failwith ("Field access on type " ^ (string_of_ir_type obj_val.val_type) ^ " not supported in eBPF context"))
           
  | Ast.ArrowAccess (obj_expr, field) ->
      (* Arrow access (pointer->field) - similar to field access but for pointers *)
      let obj_val = lower_expression ctx obj_expr in
      (* Determine result type using dedicated type resolution *)
      let result_type = determine_arrow_access_type ctx obj_val field expr.expr_type in
      let result_val = allocate_temp_variable ctx "arrow_access" result_type expr.expr_pos in
      
      (* Handle arrow access for different pointer types *)
      (match obj_val.val_type with
       | IRPointer (IRStruct (struct_name, _), _) ->
           (* Check if this is a context struct pointer *)
           (match struct_name_to_context_type struct_name with
            | Some ctx_type_str ->
                (* Handle context pointer field access *)
                let corrected_result_val = result_val in
                (match handle_context_field_access_comprehensive ctx_type_str obj_val field corrected_result_val expr.expr_pos with
                 | Some instr -> 
                     emit_instruction ctx instr;
                     corrected_result_val
                 | None ->
                     failwith ("Unknown context field: " ^ field ^ " for context type: " ^ ctx_type_str))
            | None ->
                (* Regular struct pointer - use field access *)
                let field_expr = make_ir_expr (IRFieldAccess (obj_val, field)) result_type expr.expr_pos in
                emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_type (Some field_expr) expr.expr_pos;
                result_val)
       | _ ->
           (* For userspace code, allow arrow access on other types *)
           if ctx.is_userspace then
             let field_expr = make_ir_expr (IRFieldAccess (obj_val, field)) result_type expr.expr_pos in
             emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_type (Some field_expr) expr.expr_pos;
             result_val
           else
             failwith ("Arrow access on type " ^ (string_of_ir_type obj_val.val_type) ^ " not supported in eBPF context"))
           
  | Ast.BinaryOp (left_expr, op, right_expr) ->
      let left_val = lower_expression ctx left_expr in
      let right_val = lower_expression ctx right_expr in
      let ir_op = lower_binary_op op in
      
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> 
             (* For pointer arithmetic, determine the correct result type *)
             (match left_val.val_type, ir_op, right_val.val_type with
              (* Pointer - Pointer = size (pointer subtraction) *)
              | IRPointer _, IRSub, IRPointer _ -> IRU64
              (* Pointer + Integer = Pointer (pointer offset) *)
              | IRPointer (t, bounds), (IRAdd | IRSub), _ -> IRPointer (t, bounds)
              (* Integer + Pointer = Pointer (pointer offset) *)
              | _, IRAdd, IRPointer (t, bounds) -> IRPointer (t, bounds)
              (* Default to left operand type *)
              | _ -> left_val.val_type)
      in
      let result_val = allocate_temp_variable ctx "binop" result_type expr.expr_pos in
      
      let bin_expr = make_ir_expr (IRBinOp (left_val, ir_op, right_val)) result_type expr.expr_pos in
      emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_type (Some bin_expr) expr.expr_pos;
      result_val
      
  | Ast.UnaryOp (op, operand_expr) ->
      let operand_val = lower_expression ctx operand_expr in
      let ir_op = lower_unary_op op in
      
      (* Calculate the correct result type based on the operation *)
      let result_type = match op with
        | AddressOf -> 
            (* &T -> *T (pointer to the operand type) *)
            (* Special handling for map access: the result is a pointer to the map value type *)
            (match operand_val.value_desc with
             | IRMapAccess (_, _, _) -> 
                 (* Map access: &stats should return a pointer to the map value type *)
                 IRPointer (operand_val.val_type, make_bounds_info ~nullable:true ())
             | _ -> IRPointer (operand_val.val_type, make_bounds_info ~nullable:false ()))
        | Deref ->
            (* *T -> T (dereference the pointer to get the pointed-to type) *)
            (match operand_val.val_type with
             | IRPointer (inner_type, _) -> inner_type
             | _ -> failwith ("Cannot dereference non-pointer type"))
        | _ -> 
            (* For other unary ops (Not, Neg), result type is same as operand *)
            operand_val.val_type
      in
      let result_val = allocate_temp_variable ctx "unop" result_type expr.expr_pos in
      
      (* Handle all unary operations uniformly to avoid register reference issues *)
      let un_expr = make_ir_expr (IRUnOp (ir_op, operand_val)) result_type expr.expr_pos in
      emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_type (Some un_expr) expr.expr_pos;
       result_val
      
  | Ast.StructLiteral (struct_name, field_assignments) ->
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
        | None -> IRStruct (struct_name, [])
      in
      let result_val = allocate_temp_variable ctx "struct_literal" result_type expr.expr_pos in
      
      (* Lower each field assignment expression *)
      let lowered_field_assignments = List.map (fun (field_name, field_expr) ->
        let field_val = lower_expression ctx field_expr in
        (field_name, field_val)
      ) field_assignments in
      
      (* Generate struct literal instruction *)
      let struct_expr = make_ir_expr (IRStructLiteral (struct_name, lowered_field_assignments)) result_type expr.expr_pos in
      emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_type (Some struct_expr) expr.expr_pos;
      result_val

  | Ast.Match (matched_expr, arms) ->
      let matched_val = lower_expression ctx matched_expr in
      
      (* Check if any arms have Block bodies - if so, we need special handling *)
      let has_block_arms = List.exists (fun arm -> 
        match arm.arm_body with Block _ -> true | _ -> false) arms in
      
      if has_block_arms then
        (* For match expressions with block arms, generate conditional statements *)
        let result_val = allocate_temp_variable ctx "match_result" IRU32 expr.expr_pos in
        
        (* Generate if-else chain for the match arms *)
        let rec generate_conditions arms_remaining =
          match arms_remaining with
          | [] -> ()
          | arm :: rest_arms ->
              let condition_val = match arm.arm_pattern with
                | ConstantPattern lit ->
                    let const_val = lower_literal lit arm.arm_pos in
                    let eq_val = allocate_temp_variable ctx "match_eq" IRBool arm.arm_pos in
                    let eq_expr = make_ir_expr (IRBinOp (matched_val, IREq, const_val)) IRBool arm.arm_pos in
                    emit_variable_decl ctx (match eq_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") IRBool (Some eq_expr) arm.arm_pos;
                    eq_val
                | DefaultPattern ->
                    (* Default pattern always matches - create a true condition *)
                    make_ir_value (IRLiteral (BoolLit true)) IRBool arm.arm_pos
                | IdentifierPattern name ->
                    (* Look up enum constant value and create comparison *)
                    let enum_val = match Symbol_table.lookup_symbol ctx.symbol_table name with
                      | Some symbol ->
                          (match symbol.kind with
                           | Symbol_table.EnumConstant (enum_name, Some value) ->
                               make_ir_value (IREnumConstant (enum_name, name, value)) IRU32 arm.arm_pos
                           | _ -> failwith ("Unknown identifier in match pattern: " ^ name))
                      | None -> failwith ("Undefined identifier in match pattern: " ^ name)
                    in
                    (* Create equality comparison *)
                    let eq_val = allocate_temp_variable ctx "match_enum_eq" IRBool arm.arm_pos in
                    let eq_expr = make_ir_expr (IRBinOp (matched_val, IREq, enum_val)) IRBool arm.arm_pos in
                    emit_variable_decl ctx (match eq_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") IRBool (Some eq_expr) arm.arm_pos;
                    eq_val
              in
              
              (* Process the arm body *)
              let then_instructions = ref [] in
              let old_block = ctx.current_block in
              ctx.current_block <- [];
              
              (match arm.arm_body with
               | SingleExpr expr ->
                   let expr_val = lower_expression ctx expr in
                   emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") expr_val.val_type (Some (make_ir_expr (IRValue expr_val) expr_val.val_type arm.arm_pos)) arm.arm_pos
               | Block stmts ->
                   (* Process block statements - they will be executed conditionally *)
                   List.iter (lower_statement ctx) stmts;
                   (* If no explicit assignment to result, use default value *)
                   let default_val = make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 arm.arm_pos in
                   emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") IRU32 (Some (make_ir_expr (IRValue default_val) IRU32 arm.arm_pos)) arm.arm_pos);
              
              then_instructions := List.rev ctx.current_block;
              ctx.current_block <- old_block;
              
              (* Generate conditional execution for this arm *)
              let else_instructions = ref [] in
              if rest_arms <> [] then (
                ctx.current_block <- [];
                generate_conditions rest_arms;
                else_instructions := List.rev ctx.current_block;
                ctx.current_block <- old_block
              );
              
              let if_instr = make_ir_instruction 
                (IRIf (condition_val, !then_instructions, 
                       if !else_instructions = [] then None else Some !else_instructions))
                arm.arm_pos in
              emit_instruction ctx if_instr
        in
        
        generate_conditions arms;
        result_val
      else
        (* Original simple match expression handling for arms without blocks *)
        let ir_arms = List.map (fun arm ->
          let ir_pattern = match arm.arm_pattern with
            | ConstantPattern lit -> 
                let lit_val = lower_literal lit arm.arm_pos in
                IRConstantPattern lit_val
            | IdentifierPattern name ->
                (* Look up enum constant value *)
                let enum_val = match Symbol_table.lookup_symbol ctx.symbol_table name with
                  | Some symbol ->
                      (match symbol.kind with
                       | Symbol_table.EnumConstant (enum_name, Some value) ->
                           make_ir_value (IREnumConstant (enum_name, name, value)) IRU32 arm.arm_pos
                       | _ -> failwith ("Unknown identifier in match pattern: " ^ name))
                  | None -> failwith ("Undefined identifier in match pattern: " ^ name)
                in
                IRConstantPattern enum_val
            | DefaultPattern -> IRDefaultPattern
          in
          let ir_value = match arm.arm_body with
            | SingleExpr expr -> lower_expression ctx expr
            | Block _ -> failwith "Block arms should be handled above"
          in
          { ir_arm_pattern = ir_pattern; ir_arm_value = ir_value; ir_arm_pos = arm.arm_pos }
        ) arms in
        
        (* Infer result type from first arm *)
        let result_type = match ir_arms with
          | first_arm :: _ -> first_arm.ir_arm_value.val_type
          | [] -> IRU32  (* Default type for empty match *)
        in
        
        let result_val = allocate_temp_variable ctx "match_result" result_type expr.expr_pos in
        
        let match_expr = make_ir_expr (IRMatch (matched_val, ir_arms)) result_type expr.expr_pos in
        emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") result_val.val_type (Some match_expr) expr.expr_pos;
        
        result_val

  | Ast.New typ ->
      (* Object allocation using bpf_obj_new() or malloc() depending on context *)
      let ir_type = ast_type_to_ir_type typ in
      let result_val = allocate_temp_variable ctx "new_obj" (IRPointer (ir_type, make_bounds_info ())) expr.expr_pos in
      
      let alloc_instr = make_ir_instruction (IRObjectNew (result_val, ir_type)) expr.expr_pos in
      emit_instruction ctx alloc_instr;
      
      result_val
      
  | Ast.NewWithFlag (typ, flag_expr) ->
      (* Object allocation with GFP flag - only valid in kernel context *)
      let ir_type = ast_type_to_ir_type typ in
      let result_val = allocate_temp_variable ctx "new_obj_flag" (IRPointer (ir_type, make_bounds_info ())) expr.expr_pos in
      
      (* Lower the flag expression *)
      let flag_val = lower_expression ctx flag_expr in
      
      let alloc_instr = make_ir_instruction (IRObjectNewWithFlag (result_val, ir_type, flag_val)) expr.expr_pos in
      emit_instruction ctx alloc_instr;
      
      result_val

(** Helper function to handle register() builtin function calls *)
and handle_register_builtin_call ctx args expr_pos ?target_type () =
  if List.length args = 1 then
    let struct_arg = List.hd args in
    (* Handle impl block references specially *)
    let struct_val = match struct_arg.Ast.expr_desc with
      | Ast.Identifier impl_name ->
          (* Check if this is an impl block name in the symbol table *)
          (match Symbol_table.lookup_symbol ctx.symbol_table impl_name with
           | Some symbol -> 
               (match symbol.kind with
                | Symbol_table.TypeDef _ ->
                    (* This is an impl block - use the name directly *)
                    let ir_type = IRStruct (impl_name, []) in
                    make_ir_value (IRVariable impl_name) ir_type struct_arg.Ast.expr_pos
                | _ ->
                    (* Regular variable - use normal processing *)
                    lower_expression ctx struct_arg)
           | None ->
               (* Not found in symbol table - use normal processing *)
               lower_expression ctx struct_arg)
      | _ ->
          (* Not an identifier - use normal processing *)
          lower_expression ctx struct_arg
    in
    (* Create result value - always use proper temp variable allocation *)
    let result_val = match target_type with
      | Some typ -> allocate_temp_variable ctx "struct_ops_reg" typ expr_pos
      | None -> allocate_temp_variable ctx "struct_ops_reg" IRU32 expr_pos
    in
    let instr = make_ir_instruction (IRStructOpsRegister (result_val, struct_val)) expr_pos in
    emit_instruction ctx instr;
    result_val
  else
    failwith "register() takes exactly one argument"

(** Helper function to resolve type aliases and track them *)
and resolve_type_alias ctx _reg ast_type =
  match ast_type with
  | UserType alias_name ->
      (match Symbol_table.lookup_symbol ctx.symbol_table alias_name with
       | Some symbol ->
           (match symbol.kind with
            | Symbol_table.TypeDef (Ast.TypeAlias (_, underlying_type, _)) -> 
                let underlying_ir_type = ast_type_to_ir_type underlying_type in
                IRTypeAlias (alias_name, underlying_ir_type)
            | _ -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type)
        | None -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type)
  | _ -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type

(** Helper function to calculate stack usage for a type *)
and calculate_stack_usage = function
  | IRI8 | IRU8 | IRChar -> 1
  | IRI16 | IRU16 -> 2
  | IRI32 | IRU32 | IRBool -> 4
  | IRI64 | IRU64 -> 8
  | IRArray (_, count, _) -> count * 4 (* Simplified *)
  | IRStr size -> size + 2 (* String data + length field *)
  | _ -> 8 (* Conservative estimate *)

(** Helper function to track map origin variables *)
and track_map_origin ctx name = function
  | IRMapAccess (map_name, key, underlying_info) ->
      Hashtbl.replace ctx.map_origin_variables name (map_name, key, underlying_info)
  | _ -> 
      Hashtbl.remove ctx.map_origin_variables name

(** Helper function to resolve declaration type and initialization *)
and resolve_declaration_type_and_init ctx typ_opt expr_opt =
  match typ_opt, expr_opt with
  | Some ast_type, Some expr ->
      (* Use explicitly declared type, but process initialization expression *)
      let target_type = ast_type_to_ir_type_with_context ctx.symbol_table ast_type in
      (* For function calls, manually handle them to use the target register *)
      (match expr.Ast.expr_desc with
       | Ast.Call (callee_expr, args) ->
           (* Handle function call that should return to the target register *)
           (* Special handling for register() builtin function *)
           (match callee_expr.Ast.expr_desc with
            | Ast.Identifier "register" ->
              let _ = handle_register_builtin_call ctx args expr.Ast.expr_pos ~target_type:target_type () in
                (target_type, None)
            | _ ->
                (* Regular function call handling *)
                let arg_vals = List.map (lower_expression ctx) args in
                let call_target = match callee_expr.Ast.expr_desc with
                  | Ast.Identifier name ->
                      if Hashtbl.mem ctx.function_parameters name || 
                         (Hashtbl.mem ctx.variable_types name && 
                          match Hashtbl.find ctx.variable_types name with 
                          | IRFunctionPointer _ -> true 
                          | _ -> false) then
                        let callee_val = lower_expression ctx callee_expr in
                        FunctionPointerCall callee_val
                      else
                        DirectCall name
                  | _ ->
                      let callee_val = lower_expression ctx callee_expr in
                      FunctionPointerCall callee_val
                in
                let result_val = allocate_temp_variable ctx "func_call" target_type expr.Ast.expr_pos in
                let instr = make_ir_instruction (IRCall (call_target, arg_vals, Some result_val)) expr.Ast.expr_pos in
                emit_instruction ctx instr;
                (target_type, None))
       | _ ->
           (* Non-function call - use normal processing *)
           let value = lower_expression ctx expr in
           (target_type, Some value))
  | None, Some expr ->
             (* No declared type - use type checker annotation if available, otherwise infer from expression *)
      (match expr.Ast.expr_desc with
       | Ast.Call (callee_expr, args) ->
           (* Handle function call in type inference *)
           let inferred_type = match expr.Ast.expr_type with
             | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
             | None -> IRU32 (* Default fallback *)
           in
           (* Special handling for register() builtin function *)
           (match callee_expr.Ast.expr_desc with
            | Ast.Identifier "register" ->
                let _ = handle_register_builtin_call ctx args expr.Ast.expr_pos ~target_type:inferred_type () in
                (inferred_type, None)
            | _ ->
                (* Regular function call handling *)
                let arg_vals = List.map (lower_expression ctx) args in
                let call_target = match callee_expr.Ast.expr_desc with
                  | Ast.Identifier name ->
                      if Hashtbl.mem ctx.function_parameters name then
                        let callee_val = lower_expression ctx callee_expr in
                        FunctionPointerCall callee_val
                      else
                        DirectCall name
                  | _ ->
                      let callee_val = lower_expression ctx callee_expr in
                      FunctionPointerCall callee_val
                in
                let result_val = allocate_temp_variable ctx "func_call_inferred" inferred_type expr.Ast.expr_pos in
                let instr = make_ir_instruction (IRCall (call_target, arg_vals, Some result_val)) expr.Ast.expr_pos in
                emit_instruction ctx instr;
                (inferred_type, None))
       | _ ->
           (* Non-function call - use normal processing *)
           let value = lower_expression ctx expr in
           let inferred_type = match expr.Ast.expr_type with
             | Some ast_type -> 
                 (* Prioritize type checker annotation as single source of truth *)
                 ast_type_to_ir_type_with_context ctx.symbol_table ast_type
             | None -> 
                 (* Fallback to IR type inference only when type checker didn't provide annotation *)
                 value.val_type
           in
           (inferred_type, Some value))
  | Some ast_type, None ->
      (* Declared type, no initialization *)
      let target_type = ast_type_to_ir_type_with_context ctx.symbol_table ast_type in
      (target_type, None)
  | None, None ->
      (* No type and no expression - default *)
      (IRU32, None)

(** Helper function to resolve const declaration type *)
and resolve_const_type ctx typ_opt expr =
  let value = lower_expression ctx expr in
  match typ_opt with
  | Some ast_type -> ast_type_to_ir_type ast_type
  | None -> value.val_type

(** Helper function to declare a variable *)
and declare_variable ctx name target_type init_value_opt pos =
  let size = calculate_stack_usage target_type in
  ctx.stack_usage <- ctx.stack_usage + size;
  
  (* Track the variable type for later lookups *)
  Hashtbl.replace ctx.variable_types name target_type;
  
  (* Handle optional initialization expression *)
  let init_expr_opt = match init_value_opt with
    | Some value -> 
        track_map_origin ctx name value.value_desc;
        (* Use the target type for consistency with variable declaration *)
        Some (make_ir_expr (IRValue value) target_type pos)
    | None -> None
  in
  
  (* Use IRRegisterDef for clean SSA-style register allocation *)
  let init_expr = match init_expr_opt with
    | Some expr -> expr
    | None -> 
        (* Create a default initialization expression based on type *)
        let default_value = match target_type with
          | IRU32 | IRI32 -> make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 pos
          | IRU64 | IRI64 -> make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU64 pos
          | IRBool -> make_ir_value (IRLiteral (BoolLit false)) IRBool pos
          | _ -> make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) target_type pos
        in
        make_ir_expr (IRValue default_value) target_type pos
  in
  let instr = make_ir_instruction 
    (IRVariableDecl (name, target_type, Some init_expr)) 
    ~stack_usage:size
    pos in
  emit_instruction ctx instr

(** Helper function to declare a const variable *)
and declare_const_variable ctx name target_type expr pos =
  let value = lower_expression ctx expr in
  let size = calculate_stack_usage target_type in
  ctx.stack_usage <- ctx.stack_usage + size;
  
  let target_val = make_ir_value (IRVariable name) target_type pos in
  let coerced_value = 
    if target_type <> value.val_type then
      make_ir_value value.value_desc target_type value.val_pos
    else
      value
  in
  
  let value_expr = make_ir_expr (IRValue coerced_value) target_type pos in
  let instr = make_ir_instruction 
    (IRConstAssign (target_val, value_expr)) 
    ~stack_usage:size
    pos in
  emit_instruction ctx instr

(** Lower AST statements to IR instructions *)
and lower_statement ctx stmt =
  match stmt.stmt_desc with
  | Ast.ExprStmt expr ->
      (* Handle expression statements elegantly - check for void-returning function calls *)
      (match expr.expr_desc with
       | Ast.Call (callee_expr, args) ->
           (* Check if this is a void-returning function call *)
           (match expr.expr_type with
            | Some Ast.Void ->
                (* Void-returning function - generate call without result assignment *)
                (match callee_expr.expr_desc with
                 | Ast.Identifier name ->
                     let arg_vals = List.map (lower_expression ctx) args in
                     let instr = make_ir_instruction (IRCall (DirectCall name, arg_vals, None)) expr.expr_pos in
                     emit_instruction ctx instr
                 | _ ->
                     (* Complex callee (function pointer) - use normal expression handling *)
                     let _ = lower_expression ctx expr in
                     ())
            | _ ->
                (* Non-void function - use normal expression handling *)
                let _ = lower_expression ctx expr in
                ())
       | _ ->
           (* Non-function call expression - use normal handling *)
           let _ = lower_expression ctx expr in
           ())
      
  | Ast.Assignment (name, expr) ->
      let value = lower_expression ctx expr in
      
      (* Track if this assignment is from a map access *)
      (match value.value_desc with
       | IRMapAccess (map_name, key, underlying_info) ->
           (* Store map origin information for this variable *)
           Hashtbl.replace ctx.map_origin_variables name (map_name, key, underlying_info)
       | _ -> 
           (* Remove any previous map origin information *)
           Hashtbl.remove ctx.map_origin_variables name);
      
      (* Check if this is a global variable assignment *)
      if Hashtbl.mem ctx.global_variables name then
        (* Global variable assignment *)
        let global_var = Hashtbl.find ctx.global_variables name in
        let target_val = make_ir_value (IRVariable name) global_var.global_var_type stmt.stmt_pos in
        
        (* If the target type is different from the value type, create a cast expression *)
        let value_expr = 
          if global_var.global_var_type <> value.val_type then
            make_ir_expr (IRCast (value, global_var.global_var_type)) global_var.global_var_type stmt.stmt_pos
          else
            make_ir_expr (IRValue value) global_var.global_var_type stmt.stmt_pos
        in
        let instr = make_ir_instruction (IRAssign (target_val, value_expr)) stmt.stmt_pos in
        emit_instruction ctx instr
      else
        (* Local variable assignment - use register definition for clean SSA *)
        (* Use variable name directly in new architecture *)
        (* Get the target variable's actual type from the symbol table *)
        let target_type = match Symbol_table.lookup_symbol ctx.symbol_table name with
          | Some symbol -> 
              (match symbol.kind with
               | Symbol_table.Variable var_type -> ast_type_to_ir_type_with_context ctx.symbol_table var_type
               | _ -> value.val_type)
          | None -> value.val_type (* Fallback to value type if not found *)
        in
        
        (* If the target type is different from the value type, create a cast expression *)
        let value_expr = 
          if target_type <> value.val_type then
            make_ir_expr (IRCast (value, target_type)) target_type stmt.stmt_pos
          else
            make_ir_expr (IRValue value) target_type stmt.stmt_pos
        in
        (* Emit variable assignment using new architecture *)
        let target_val = make_ir_value (IRVariable name) target_type stmt.stmt_pos in
        let assign_instr = make_ir_instruction (IRAssign (target_val, value_expr)) stmt.stmt_pos in
        emit_instruction ctx assign_instr
  
  | Ast.CompoundAssignment (name, op, expr) ->
      let value = lower_expression ctx expr in
      
      (* Check if this is a global variable assignment *)
      if Hashtbl.mem ctx.global_variables name then
        (* Global variable compound assignment *)
        let global_var = Hashtbl.find ctx.global_variables name in
        (* Create binary operation: target = target op value *)
        let current_val = make_ir_value (IRVariable name) global_var.global_var_type stmt.stmt_pos in
        let ir_op = lower_binary_op op in
        let bin_expr = make_ir_expr (IRBinOp (current_val, ir_op, value)) global_var.global_var_type stmt.stmt_pos in
        let target_val = make_ir_value (IRVariable name) global_var.global_var_type stmt.stmt_pos in
        let instr = make_ir_instruction (IRAssign (target_val, bin_expr)) stmt.stmt_pos in
        emit_instruction ctx instr
      else
        (* Local variable compound assignment *)
        (* Use variable name directly in new architecture *)
        (* Get the target variable's actual type from the symbol table *)
        let target_type = match Symbol_table.lookup_symbol ctx.symbol_table name with
          | Some symbol -> 
              (match symbol.kind with
               | Symbol_table.Variable var_type -> ast_type_to_ir_type_with_context ctx.symbol_table var_type
               | _ -> value.val_type)
          | None -> value.val_type (* Fallback to value type if not found *)
        in
        (* Create binary operation: target = target op value *)
        let current_val = make_ir_value (IRVariable name) target_type stmt.stmt_pos in
        let ir_op = lower_binary_op op in
        let bin_expr = make_ir_expr (IRBinOp (current_val, ir_op, value)) target_type stmt.stmt_pos in
        
        (* Emit variable assignment using new architecture *)
        let target_val = make_ir_value (IRVariable name) target_type stmt.stmt_pos in
        let assign_instr = make_ir_instruction (IRAssign (target_val, bin_expr)) stmt.stmt_pos in
        emit_instruction ctx assign_instr
      
  | Ast.CompoundIndexAssignment (map_expr, key_expr, op, value_expr) ->
      let key_val = lower_expression ctx key_expr in
      let value_val = lower_expression ctx value_expr in
      
      (match map_expr.expr_desc with
       | Ast.Identifier map_name ->
           (* Handle map compound assignment *)
           let map_def = Hashtbl.find ctx.maps map_name in
           let map_val = make_ir_value (IRMapRef map_name) (IRPointer (IRU8, make_bounds_info ())) stmt.stmt_pos in
           (* Generate: map[key] = map[key] op value *)
           (* First, load the current value - use map value type, not operand type *)
           let current_val = allocate_temp_variable ctx "map_current" 
             (IRPointer (map_def.map_value_type, make_bounds_info ())) stmt.stmt_pos in
           let load_instr = make_ir_instruction (IRMapLoad (map_val, key_val, current_val, MapLookup)) stmt.stmt_pos in
           emit_instruction ctx load_instr;
           
           (* Then, perform the operation - current_val is pointer, so dereference for operation *)
           let ir_op = lower_binary_op op in
           let deref_current_val = allocate_temp_variable ctx "map_deref" map_def.map_value_type stmt.stmt_pos in
           emit_variable_decl ctx (match deref_current_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") map_def.map_value_type (Some (make_ir_expr (IRUnOp (IRDeref, current_val)) map_def.map_value_type stmt.stmt_pos)) stmt.stmt_pos;
           let bin_expr = make_ir_expr (IRBinOp (deref_current_val, ir_op, value_val)) map_def.map_value_type stmt.stmt_pos in
           
           (* Create a temporary variable for the result *)
           let result_val = allocate_temp_variable ctx "map_result" map_def.map_value_type stmt.stmt_pos in
           emit_variable_decl ctx (match result_val.value_desc with IRTempVariable name -> name | _ -> failwith "Expected temp variable") map_def.map_value_type (Some bin_expr) stmt.stmt_pos;
           
           (* Finally, store the result back *)
           let store_instr = make_ir_instruction (IRMapStore (map_val, key_val, result_val, MapUpdate)) stmt.stmt_pos in
           emit_instruction ctx store_instr
       | _ ->
           (* For non-map expressions, currently not supported - could be extended for arrays *)
           failwith "Compound index assignment is currently only supported for maps")
      
  | Ast.IndexAssignment (map_expr, key_expr, value_expr) ->
      let map_val = lower_expression ctx map_expr in
      let key_val = lower_expression ctx key_expr in
      let value_val = lower_expression ctx value_expr in
      
      (* Check for optimization opportunities *)
      let hints = match ctx.assignment_optimizations with
        | Some opt_info when opt_info.constant_folding && Map_assignment.is_constant_expression value_expr ->
            [HelperCall "map_update_elem"; BoundsChecked]  (* Mark as optimizable *)
        | Some _opt_info ->
            [HelperCall "map_update_elem"]
        | _ -> [HelperCall "map_update_elem"]
      in
      
      (* Generate map store instruction with optimization hints *)
      let instr = make_ir_instruction
        (IRMapStore (map_val, key_val, value_val, MapUpdate))
        ~verifier_hints:hints
        stmt.stmt_pos
      in
      emit_instruction ctx instr
      
  | Ast.Delete target ->
      (match target with
      | DeleteMapEntry (map_expr, key_expr) ->
          let map_val = lower_expression ctx map_expr in
          let key_val = lower_expression ctx key_expr in
          
          (* Generate map delete instruction *)
          let instr = make_ir_instruction
            (IRMapDelete (map_val, key_val))
            ~verifier_hints:[HelperCall "map_delete_elem"]
            stmt.stmt_pos
          in
          emit_instruction ctx instr
      | DeletePointer ptr_expr ->
          let ptr_val = lower_expression ctx ptr_expr in
          
          (* Generate object delete instruction *)
          let instr = make_ir_instruction
            (IRObjectDelete ptr_val)
            stmt.stmt_pos
          in
          emit_instruction ctx instr)
      
  | Ast.Declaration (name, typ_opt, expr_opt) ->
      
      (* Handle function call and new expression declarations elegantly by proper instruction ordering *)
      (match expr_opt with
       | Some expr when (match expr.expr_desc with Ast.Call _ | Ast.New _ | Ast.NewWithFlag _ -> true | _ -> false) ->
           (* For function calls and new expressions: handle directly without separate declaration *)
           let target_type = match typ_opt with
             | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
             | None ->
                 (* Infer type from expression if no explicit type *)
                 (match expr.expr_type with
                  | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
                  | None -> 
                      (match expr.expr_desc with
                       | Ast.New typ -> 
                           let ir_type = ast_type_to_ir_type typ in
                           IRPointer (ir_type, make_bounds_info ())
                       | Ast.NewWithFlag (typ, _) ->
                           let ir_type = ast_type_to_ir_type typ in
                           IRPointer (ir_type, make_bounds_info ())
                       | _ -> IRU32))
           in
           
           (* Track the variable type for later lookups *)
           Hashtbl.replace ctx.variable_types name target_type;
           
           (* Handle the operation directly with IRRegisterDef *)
           (match expr.Ast.expr_desc with
            | Ast.Call (callee_expr, args) ->
                (* Special handling for register() builtin function *)
                (match callee_expr.Ast.expr_desc with
                 | Ast.Identifier "register" ->
                     let _ = handle_register_builtin_call ctx args expr.Ast.expr_pos ~target_type:target_type () in
                     ()
                 | _ ->
                     (* Regular function call handling *)
                     let arg_vals = List.map (lower_expression ctx) args in
                     (* Check if this is a method call and handle it specially *)
                     (match callee_expr.Ast.expr_desc with
                      | Ast.FieldAccess (_, _) ->
                          (* This is a method call - emit variable declaration first, then assignment *)
                          let target_val = make_ir_value (IRVariable name) target_type expr.Ast.expr_pos in
                          (* Emit variable declaration without initializer *)
                          emit_variable_decl ctx name target_type None expr.Ast.expr_pos;
                          (* Evaluate the method call expression *)
                          let result_val = lower_expression ctx expr in
                          (* Emit assignment to ensure the result gets to the correct target variable *)
                          let assign_expr = make_ir_expr (IRValue result_val) target_type expr.Ast.expr_pos in
                          let assign_instr = make_ir_instruction (IRAssign (target_val, assign_expr)) expr.Ast.expr_pos in
                          emit_instruction ctx assign_instr
                      | _ ->
                          (* Regular function call handling *)
                          let call_target = match callee_expr.Ast.expr_desc with
                            | Ast.Identifier name ->
                                if Hashtbl.mem ctx.function_parameters name || 
                                   (Hashtbl.mem ctx.variable_types name && 
                                    match Hashtbl.find ctx.variable_types name with 
                                    | IRFunctionPointer _ -> true 
                                    | _ -> false) then
                                  let callee_val = lower_expression ctx callee_expr in
                                  FunctionPointerCall callee_val
                                else
                                  DirectCall name
                            | _ ->
                                let callee_val = lower_expression ctx callee_expr in
                                FunctionPointerCall callee_val
                          in
                          (* Generate variable declaration first, then function call *)
                          let result_val = make_ir_value (IRVariable name) target_type expr.Ast.expr_pos in
                          (* Emit variable declaration without initializer *)
                          emit_variable_decl ctx name target_type None expr.Ast.expr_pos;
                          (* Then emit function call that assigns to the variable *)
                          let instr = make_ir_instruction (IRCall (call_target, arg_vals, Some result_val)) expr.Ast.expr_pos in
                          emit_instruction ctx instr))
            | Ast.New typ ->
                (* Handle new expression: emit variable declaration first, then allocation instruction *)
                let ir_type = ast_type_to_ir_type typ in
                let result_val = make_ir_value (IRVariable name) target_type expr.Ast.expr_pos in
                (* Emit variable declaration without initializer *)
                emit_variable_decl ctx name target_type None expr.Ast.expr_pos;
                (* Then emit allocation instruction *)
                let alloc_instr = make_ir_instruction (IRObjectNew (result_val, ir_type)) expr.Ast.expr_pos in
                emit_instruction ctx alloc_instr
            | Ast.NewWithFlag (typ, flag_expr) ->
                (* Handle new expression with flag: emit variable declaration first, then allocation instruction with flag *)
                let ir_type = ast_type_to_ir_type typ in
                let result_val = make_ir_value (IRVariable name) target_type expr.Ast.expr_pos in
                (* Emit variable declaration without initializer *)
                emit_variable_decl ctx name target_type None expr.Ast.expr_pos;
                (* Then emit allocation instruction with flag *)
                let flag_val = lower_expression ctx flag_expr in
                let alloc_instr = make_ir_instruction (IRObjectNewWithFlag (result_val, ir_type, flag_val)) expr.Ast.expr_pos in
                emit_instruction ctx alloc_instr
            | _ -> ()) (* Shouldn't happen due to our guard *)
       | _ ->
           (* Non-function call declarations: use existing logic *)
           let (target_type, init_value_opt) = 
             resolve_declaration_type_and_init ctx typ_opt expr_opt in
           declare_variable ctx name target_type init_value_opt stmt.stmt_pos)
      
  | Ast.ConstDeclaration (name, typ_opt, expr) ->
      let target_type = resolve_const_type ctx typ_opt expr in
      
      declare_const_variable ctx name target_type expr stmt.stmt_pos
      
    | Ast.Return expr_opt ->
      let return_val = match expr_opt with
        | Some expr ->
            (* Check if this is a match expression in return position *)
            (match expr.expr_desc with
             | Ast.Match (matched_expr, arms) ->
                 (* ALL match expressions in return position should generate IRMatchReturn *)
                 (* The distinction is in the return_action field (literal vs function call) *)
                 let matched_val = lower_expression ctx matched_expr in
                 
                 let ir_arms = List.map (fun arm ->
                   let ir_pattern = match arm.arm_pattern with
                     | ConstantPattern lit ->
                         let const_val = lower_literal lit arm.arm_pos in
                         IRConstantPattern const_val
                     | IdentifierPattern name ->
                         (* Look up enum constant value *)
                         let enum_val = match Symbol_table.lookup_symbol ctx.symbol_table name with
                           | Some symbol ->
                               (match symbol.kind with
                                | Symbol_table.EnumConstant (enum_name, Some value) ->
                                    make_ir_value (IREnumConstant (enum_name, name, value)) IRU32 arm.arm_pos
                                | _ -> failwith ("Unknown identifier in match pattern: " ^ name))
                           | None -> failwith ("Undefined identifier in match pattern: " ^ name)
                         in
                         IRConstantPattern enum_val
                     | DefaultPattern -> IRDefaultPattern
                   in
                   
                   let return_action = match arm.arm_body with
                     | SingleExpr expr ->
                         (match expr.expr_desc with
                          | Ast.Call (callee_expr, args) ->
                              (* Check if this is a simple function call that could be a tail call *)
                              (match callee_expr.expr_desc with
                               | Ast.Identifier name ->
                                   (* Check if this is a helper function - if so, treat as regular call *)
                                   if Hashtbl.mem ctx.helper_functions name then
                                     let ret_val = lower_expression ctx expr in
                                     IRReturnValue ret_val
                                   else
                                     (* This will be converted to tail call by tail call analyzer *)
                                     let arg_vals = List.map (lower_expression ctx) args in
                                     IRReturnCall (name, arg_vals)
                               | _ ->
                                   (* Function pointer call - treat as regular return *)
                                   let ret_val = lower_expression ctx expr in
                                   IRReturnValue ret_val)
                          | Ast.TailCall (name, args) ->
                              (* Explicit tail call *)
                              let arg_vals = List.map (lower_expression ctx) args in
                              IRReturnTailCall (name, arg_vals, 0) (* Index will be set by tail call analyzer *)
                          | _ ->
                              (* Regular return value (including literals) *)
                              let ret_val = lower_expression ctx expr in
                              IRReturnValue ret_val)
                     | Block stmts ->
                         (* For block arms, extract return action from the last statement *)
                         let rec extract_return_action_from_stmt stmt =
                           match stmt.stmt_desc with
                           | Ast.Return (Some return_expr) ->
                               (match return_expr.expr_desc with
                                | Ast.Call (callee_expr, args) ->
                                    (* Check if this is a simple function call that could be a tail call *)
                                    (match callee_expr.expr_desc with
                                     | Ast.Identifier name ->
                                         (* Check if this is a helper function - if so, treat as regular call *)
                                         if Hashtbl.mem ctx.helper_functions name then
                                           let ret_val = lower_expression ctx return_expr in
                                           IRReturnValue ret_val
                                         else
                                           let arg_vals = List.map (lower_expression ctx) args in
                                           IRReturnCall (name, arg_vals)
                                     | _ ->
                                         (* Function pointer call - treat as regular return *)
                                         let ret_val = lower_expression ctx return_expr in
                                         IRReturnValue ret_val)
                                | Ast.TailCall (name, args) ->
                                    let arg_vals = List.map (lower_expression ctx) args in
                                    IRReturnTailCall (name, arg_vals, 0)
                                | _ ->
                                    let ret_val = lower_expression ctx return_expr in
                                    IRReturnValue ret_val)
                           | Ast.ExprStmt expr ->
                               (* Handle implicit return from expression statement *)
                               (match expr.expr_desc with
                                | Ast.Call (callee_expr, args) ->
                                    (match callee_expr.expr_desc with
                                     | Ast.Identifier name ->
                                         (* Check if this is a helper function - if so, treat as regular call *)
                                         if Hashtbl.mem ctx.helper_functions name then
                                           let ret_val = lower_expression ctx expr in
                                           IRReturnValue ret_val
                                         else
                                           let arg_vals = List.map (lower_expression ctx) args in
                                           IRReturnCall (name, arg_vals)
                                     | _ ->
                                         let ret_val = lower_expression ctx expr in
                                         IRReturnValue ret_val)
                                | Ast.TailCall (name, args) ->
                                    let arg_vals = List.map (lower_expression ctx) args in
                                    IRReturnTailCall (name, arg_vals, 0)
                                | _ ->
                                    let ret_val = lower_expression ctx expr in
                                    IRReturnValue ret_val)
                           | Ast.If (_, then_stmts, Some _) ->
                               (* For if-else statements, we'll use the then branch action (both should be compatible) *)
                               extract_return_action_from_block then_stmts
                           | _ ->
                               failwith "Block arm must end with a return statement, expression, or if-else statement"
                         and extract_return_action_from_block stmts =
                           match List.rev stmts with
                           | last_stmt :: _ -> extract_return_action_from_stmt last_stmt
                           | [] -> failwith "Empty block in match arm"
                         in
                         extract_return_action_from_block stmts
                   in
                   
                   { match_pattern = ir_pattern; return_action = return_action; arm_pos = arm.arm_pos }
                 ) arms in
                 
                 let instr = make_ir_instruction (IRMatchReturn (matched_val, ir_arms)) stmt.stmt_pos in
                 emit_instruction ctx instr;
                 None  (* IRMatchReturn handles the return logic *)
             | Ast.TailCall (name, args) ->
                 (* This is a tail call - generate tail call instruction *)
                 let arg_vals = List.map (lower_expression ctx) args in
                 let tail_call_index = 0 in  (* This will be set by tail call analyzer *)
                 let instr = make_ir_instruction
                   (IRTailCall (name, arg_vals, tail_call_index))
                   stmt.stmt_pos
                 in
                 emit_instruction ctx instr;
                 None  (* Tail calls don't return to caller *)
             | Ast.Call (callee_expr, args) ->
                 (* Check if this is a simple function call that could be a tail call *)
                 (match callee_expr.expr_desc with
                  | Ast.Identifier name ->
                      (* Check if this should be a tail call *)
                      let should_be_tail_call = 
                        (* First check if the identifier is a function parameter or variable (function pointer) *)
                        let is_function_pointer = 
                          Hashtbl.mem ctx.function_parameters name || 
                          Hashtbl.mem ctx.variable_types name
                        in
                        
                        if is_function_pointer then
                          (* Function pointer calls should never be tail calls *)
                          false
                        else
                          (* Check if we're in an attributed function context *)
                          match ctx.current_function with
                          | Some current_func_name ->
                              (* Check if caller is attributed (has eBPF attributes) *)
                              let caller_is_attributed = 
                                try
                                  let caller_symbol = Symbol_table.lookup_function ctx.symbol_table current_func_name in
                                  (* TODO: Check if caller has eBPF attributes like @xdp, @tc, etc. *)
                                  (* For now, assume attributed functions are defined in symbol table *)
                                  caller_symbol <> None
                                with _ -> false
                              in
                              
                              (* Check if target function is an attributed function *)
                              let target_is_attributed = 
                                try
                                  let target_symbol = Symbol_table.lookup_function ctx.symbol_table name in
                                  (* TODO: Check if target has eBPF attributes like @xdp, @tc, etc. *)
                                  (* For now, assume attributed functions are defined in symbol table *)
                                  target_symbol <> None
                                with _ -> false
                              in
                              
                              (* Only allow tail calls between attributed functions *)
                              caller_is_attributed && target_is_attributed
                          | None -> false
                      in
                      
                      if should_be_tail_call then
                        (* Generate tail call instruction *)
                        let arg_vals = List.map (lower_expression ctx) args in
                        let tail_call_index = 0 in  (* This will be set by tail call analyzer *)
                        let instr = make_ir_instruction
                          (IRTailCall (name, arg_vals, tail_call_index))
                          stmt.stmt_pos
                        in
                        emit_instruction ctx instr;
                        None  (* Tail calls don't return to caller *)
                      else
                        (* Regular function call in return position *)
                        Some (lower_expression ctx expr)
                  | _ ->
                      (* Function pointer call or other complex expression - treat as regular call *)
                      Some (lower_expression ctx expr))
             | _ -> 
                 (* Regular return expression *)
                 Some (lower_expression ctx expr))
        | None -> None
      in
      (* Only generate IRReturn if we have a return value (IRMatchReturn handles its own logic) *)
      (match return_val with
       | Some _ -> 
           let instr = make_ir_instruction (IRReturn return_val) stmt.stmt_pos in
           emit_instruction ctx instr
       | None -> ())
      
  | Ast.If (cond_expr, then_stmts, else_opt) ->
      let cond_val = lower_expression ctx cond_expr in
      
      if ctx.in_bpf_loop_callback then
        (* Special handling for bpf_loop callbacks - use conditional returns *)
        let check_for_break_continue stmts =
          List.fold_left (fun acc stmt ->
            match stmt.Ast.stmt_desc with
            | Ast.Break -> Some (make_ir_value (IRLiteral (IntLit (Ast.Signed64 1L, None))) IRU32 stmt.stmt_pos)
            | Ast.Continue -> Some (make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 stmt.stmt_pos)
            | _ -> acc
          ) None stmts
        in
        
        let then_return = check_for_break_continue then_stmts in
        let else_return = match else_opt with
          | Some else_stmts -> check_for_break_continue else_stmts
          | None -> None
        in
        
        if then_return <> None || else_return <> None then
          (* Generate conditional return instruction *)
          let cond_return_instr = make_ir_instruction 
            (IRCondReturn (cond_val, then_return, else_return))
            stmt.stmt_pos in
          emit_instruction ctx cond_return_instr
        else
          (* Regular if statement without break/continue - process normally *)
          List.iter (lower_statement ctx) then_stmts;
          (match else_opt with
           | Some else_stmts -> List.iter (lower_statement ctx) else_stmts
           | None -> ())
      else if ctx.is_userspace then
        (* For userspace, detect and generate if-else-if chains *)
        let rec collect_if_chain acc_conditions acc_then_bodies current_cond current_then current_else =
          let new_conditions = acc_conditions @ [current_cond] in
          let new_then_bodies = acc_then_bodies @ [current_then] in
          match current_else with
          | None -> (new_conditions, new_then_bodies, None)
          | Some else_stmts ->
              (* Check if this is an else-if pattern: single If statement *)
              (match else_stmts with
               | [single_stmt] when (match single_stmt.Ast.stmt_desc with Ast.If (_, _, _) -> true | _ -> false) ->
                   (* This is an else-if: extract the nested if statement *)
                   (match single_stmt.Ast.stmt_desc with
                    | Ast.If (next_cond_expr, next_then_stmts, next_else_opt) ->
                        let next_cond_val = lower_expression ctx next_cond_expr in
                        (* Capture instructions for next then block *)
                        let old_block = ctx.current_block in
                        ctx.current_block <- [];
                        List.iter (lower_statement ctx) next_then_stmts;
                        let next_then_instructions = List.rev ctx.current_block in
                        ctx.current_block <- old_block;
                        (* Recursively collect more if-else-if chains *)
                        collect_if_chain new_conditions new_then_bodies next_cond_val next_then_instructions next_else_opt
                    | _ -> (new_conditions, new_then_bodies, Some else_stmts))
               | _ ->
                   (* This is a regular else block *)
                   (new_conditions, new_then_bodies, Some else_stmts))
        in
        
        (* Capture instructions for initial then block *)
        let old_block = ctx.current_block in
        ctx.current_block <- [];
        List.iter (lower_statement ctx) then_stmts;
        let initial_then_instructions = List.rev ctx.current_block in
        ctx.current_block <- old_block;
        
        (* Capture instructions for else block if needed *)
        let else_instrs_opt = match else_opt with
          | Some else_stmts ->
              ctx.current_block <- [];
              List.iter (lower_statement ctx) else_stmts;
              let else_instrs = List.rev ctx.current_block in
              ctx.current_block <- old_block;
              Some else_instrs
          | None -> None
        in
        
        (* Collect the if-else-if chain *)
        let (conditions, then_bodies, final_else) = collect_if_chain [] [] cond_val initial_then_instructions else_opt in
        
        (* Generate appropriate instruction based on the result *)
        let if_instr = if List.length conditions > 1 then
          (* Multiple conditions: generate if-else-if chain *)
          let conditions_and_bodies = List.combine conditions then_bodies in
          let final_else_instrs = match final_else with
            | Some else_stmts ->
                ctx.current_block <- [];
                List.iter (lower_statement ctx) else_stmts;
                let else_instrs = List.rev ctx.current_block in
                ctx.current_block <- old_block;
                Some else_instrs
            | None -> None
          in
          make_ir_instruction 
            (IRIfElseChain (conditions_and_bodies, final_else_instrs))
            stmt.stmt_pos
        else
          (* Single condition: generate regular IRIf *)
          make_ir_instruction 
            (IRIf (cond_val, initial_then_instructions, else_instrs_opt))
            stmt.stmt_pos
        in
        emit_instruction ctx if_instr
      else if ctx.in_try_block then
        (* For try blocks, use structured IRIf to avoid disrupting statement ordering *)
        let then_instructions = ref [] in
        
        (* Temporarily capture instructions for then block *)
        let old_block = ctx.current_block in
        ctx.current_block <- [];
        List.iter (lower_statement ctx) then_stmts;
        then_instructions := List.rev ctx.current_block;
        ctx.current_block <- old_block;
        
        (* Temporarily capture instructions for else block *)
        let else_instrs_opt = match else_opt with
          | Some else_stmts ->
              ctx.current_block <- [];
              List.iter (lower_statement ctx) else_stmts;
              let else_instrs = List.rev ctx.current_block in
              ctx.current_block <- old_block;
              Some else_instrs
          | None -> None
        in
        
        (* Generate IRIf instruction *)
        let if_instr = make_ir_instruction 
          (IRIf (cond_val, !then_instructions, else_instrs_opt))
          stmt.stmt_pos in
        emit_instruction ctx if_instr
      else
        (* For eBPF contexts, use structured IRIf to avoid goto complexity *)
        let then_instructions = ref [] in
        
        (* Temporarily capture instructions for then block *)
        let old_block = ctx.current_block in
        ctx.current_block <- [];
        List.iter (lower_statement ctx) then_stmts;
        then_instructions := List.rev ctx.current_block;
        ctx.current_block <- old_block;
        
        (* Temporarily capture instructions for else block *)
        let else_instrs_opt = match else_opt with
          | Some else_stmts ->
              ctx.current_block <- [];
              List.iter (lower_statement ctx) else_stmts;
              let else_instrs = List.rev ctx.current_block in
              ctx.current_block <- old_block;
              Some else_instrs
          | None -> None
        in
        
        (* Generate IRIf instruction *)
        let if_instr = make_ir_instruction 
          (IRIf (cond_val, !then_instructions, else_instrs_opt))
          stmt.stmt_pos in
        emit_instruction ctx if_instr
      
  | Ast.For (var, start_expr, end_expr, body_stmts) ->
      (* Analyze the loop to determine if it's bounded or unbounded *)
      let loop_analysis = 
        match ctx.const_env with
        | Some const_env -> Loop_analysis.analyze_for_loop_with_context const_env start_expr end_expr
        | None -> Loop_analysis.analyze_for_loop start_expr end_expr
      in
      
      (* Use different loop strategy for userspace vs eBPF *)
      let loop_strategy = 
        if ctx.is_userspace then
          (* For userspace, always use BpfLoopHelper to generate C for loops *)
          Loop_analysis.BpfLoopHelper
        else
          (* For eBPF, use the original eBPF-specific strategy *)
          Loop_analysis.get_ebpf_loop_strategy loop_analysis
      in
      
      (* Loop analysis performed for optimization *)
      
      let start_val = lower_expression ctx start_expr in
      let end_val = lower_expression ctx end_expr in
      
      (* Create loop counter variable *)
      let counter_val = make_ir_value (IRVariable var) IRU32 stmt.stmt_pos in
      
      (* Different IR generation based on loop strategy *)
      (match loop_strategy with
       | Loop_analysis.UnrolledLoop ->
           (* Unroll small constant loops *)
           (match loop_analysis.bound_info with
            | Loop_analysis.Bounded (start_int, end_int) ->
                for i = start_int to end_int - 1 do
                  let iter_val = make_ir_value (IRLiteral (IntLit (Ast.Signed64 (Int64.of_int i), None))) IRU32 stmt.stmt_pos in
                  let assign_instr = make_ir_instruction (IRAssign (counter_val, make_ir_expr (IRValue iter_val) IRU32 stmt.stmt_pos)) stmt.stmt_pos in
                  emit_instruction ctx assign_instr;
                  List.iter (lower_statement ctx) body_stmts;
                done
            | _ -> failwith "Unrolled loop should have bounded info")
            
       | Loop_analysis.BpfLoopHelper ->
           (* Use bpf_loop() for unbounded or complex loops *)
           let bpf_loop_comment = make_ir_instruction 
             (IRComment "(* Using bpf_loop() for unbounded loop *)")
             stmt.stmt_pos in
           emit_instruction ctx bpf_loop_comment;
           
           (* Create a separate context for the loop body *)
           let body_ctx = {
             ctx with
             current_block = [];
             blocks = [];
             (* For userspace, don't set in_bpf_loop_callback to allow normal break/continue *)
             in_bpf_loop_callback = not ctx.is_userspace;
           } in
           
           (* Lower the loop body statements to IR instructions *)
           List.iter (lower_statement body_ctx) body_stmts;
           let body_instructions = List.rev body_ctx.current_block in
           
           (* Create loop context register *)
           let loop_ctx_val = allocate_temp_variable ctx "loop_ctx" 
             (IRPointer (IRStruct ("loop_ctx", []), make_bounds_info ())) stmt.stmt_pos in
           
           (* Create the bpf_loop instruction with IR body *)
           let bpf_loop_instr = make_ir_instruction 
             (IRBpfLoop (start_val, end_val, counter_val, loop_ctx_val, body_instructions))
             stmt.stmt_pos in
           emit_instruction ctx bpf_loop_instr
           
       | Loop_analysis.SimpleLoop ->
           (* Use UnrolledLoop for all SimpleLoop cases to maintain variable scoping *)
           (* This avoids both basic block ordering issues and callback scoping issues *)
           (match loop_analysis.bound_info with
            | Loop_analysis.Bounded (start_int, end_int) ->
                let simple_loop_comment = make_ir_instruction 
                  (IRComment "(* Using unrolled loop for simple bounded case *)")
                  stmt.stmt_pos in
                emit_instruction ctx simple_loop_comment;
                
                (* Unroll the loop iterations *)
                for i = start_int to end_int - 1 do
                  let iter_val = make_ir_value (IRLiteral (IntLit (Ast.Signed64 (Int64.of_int i), None))) IRU32 stmt.stmt_pos in
                  let assign_instr = make_ir_instruction (IRAssign (counter_val, make_ir_expr (IRValue iter_val) IRU32 stmt.stmt_pos)) stmt.stmt_pos in
                  emit_instruction ctx assign_instr;
                  List.iter (lower_statement ctx) body_stmts;
                done
            | _ -> 
                (* Fallback to BpfLoopHelper for unbounded simple loops *)
                let bpf_loop_comment = make_ir_instruction 
                  (IRComment "(* Using bpf_loop() for unbounded simple loop *)")
                  stmt.stmt_pos in
                emit_instruction ctx bpf_loop_comment;
                
                (* Process loop body in isolated context to collect instructions *)
                let body_instructions = ref [] in
                let old_current_block = ctx.current_block in
                ctx.current_block <- [];
                List.iter (lower_statement ctx) body_stmts;
                body_instructions := List.rev ctx.current_block;
                ctx.current_block <- old_current_block;
                
                (* Create a dummy context value for the loop *)
                let loop_ctx_val = make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 stmt.stmt_pos in
                
                (* Emit IRBpfLoop instruction with collected body *)
                let bpf_loop_instr = make_ir_instruction 
                  (IRBpfLoop (start_val, end_val, counter_val, loop_ctx_val, !body_instructions))
                  stmt.stmt_pos in
                emit_instruction ctx bpf_loop_instr))
      
  | Ast.ForIter (index_var, value_var, iterable_expr, body_stmts) ->
      (* For-iter loops are always considered unbounded *)
      let loop_analysis = Loop_analysis.analyze_for_iter_loop iterable_expr in
      let _ = lower_expression ctx iterable_expr in
      
      (* Create iterator variables *)
      let index_val = make_ir_value (IRVariable index_var) IRU32 stmt.stmt_pos in
      let _value_val = make_ir_value (IRVariable value_var) IRU32 stmt.stmt_pos in
      
      (* ForIter always uses bpf_loop() for now *)
      let iter_comment = make_ir_instruction 
        (IRComment (Printf.sprintf "(* ForIter loop: %s *)\n(* Using bpf_loop() for iterator protocol *)" 
                   (Loop_analysis.string_of_loop_analysis loop_analysis)))
        stmt.stmt_pos in
      emit_instruction ctx iter_comment;
      
      (* Placeholder for bpf_loop implementation *)
      let loop_ctx_val = allocate_temp_variable ctx "iter_ctx" 
        (IRPointer (IRStruct ("iter_ctx", []), make_bounds_info ())) stmt.stmt_pos in
      
      (* Create a separate context for the loop body *)
      let body_ctx = {
        ctx with
        current_block = [];
        blocks = [];
        (* For userspace, don't set in_bpf_loop_callback to allow normal break/continue *)
        in_bpf_loop_callback = not ctx.is_userspace;
      } in
      
      (* Lower the loop body statements to IR instructions *)
      List.iter (lower_statement body_ctx) body_stmts;
      let body_instructions = List.rev body_ctx.current_block in
      
      (* Mark as iterator bpf_loop *)
      let start_val = make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) IRU32 stmt.stmt_pos in
      let end_val = make_ir_value (IRLiteral (IntLit (Ast.Signed64 100L, None))) IRU32 stmt.stmt_pos in (* Placeholder *)
      let bpf_iter_instr = make_ir_instruction 
        (IRBpfLoop (start_val, end_val, index_val, loop_ctx_val, body_instructions))
        stmt.stmt_pos in
      emit_instruction ctx bpf_iter_instr
      
  | Ast.While (cond_expr, body_stmts) ->
      (* Similar to for loop but without counter management *)
      let loop_header = Printf.sprintf "while_header_%d" ctx.next_block_id in
      let loop_body = Printf.sprintf "while_body_%d" (ctx.next_block_id + 1) in
      let loop_exit = Printf.sprintf "while_exit_%d" (ctx.next_block_id + 2) in
      
      (* Jump to header *)
      let jump_to_header = make_ir_instruction (IRJump loop_header) stmt.stmt_pos in
      emit_instruction ctx jump_to_header;
      let _pre_while_block = create_basic_block ctx "pre_while" in
      
      (* Condition check *)
      let cond_val = lower_expression ctx cond_expr in
      let while_cond_jump = make_ir_instruction 
        (IRCondJump (cond_val, loop_body, loop_exit)) 
        stmt.stmt_pos in
      emit_instruction ctx while_cond_jump;
      let _header_block = create_basic_block ctx loop_header in
      
      (* Body *)
      List.iter (lower_statement ctx) body_stmts;
      let back_jump = make_ir_instruction (IRJump loop_header) stmt.stmt_pos in
      emit_instruction ctx back_jump;
      let _body_block = create_basic_block ctx loop_body in
      
      (* Exit *)
      let _exit_block = create_basic_block ctx loop_exit in
      
      (* Note: Control flow connections and loop depth will be established during CFG construction *)
      ()
  
  | Ast.Break ->
      (* Generate break instruction for IR *)
      let instr = make_ir_instruction IRBreak stmt.stmt_pos in
      emit_instruction ctx instr
  
  | Ast.FieldAssignment (object_expr, field_name, value_expr) ->
      (* Check if we're trying to assign to a config field *)
      let is_config = match object_expr.expr_desc with
        | Ast.Identifier var_name ->
            (match Symbol_table.lookup_symbol ctx.symbol_table var_name with
             | Some { kind = Config _; _ } -> true
             | _ -> false)
        | _ -> false
      in
      
      if is_config then (
        (* This is a config field assignment *)
        let map_name = match object_expr.expr_desc with
          | Ast.Identifier var_name -> var_name
          | _ -> failwith "Config field assignment must reference a config variable"
        in
        
        if not ctx.is_userspace then
          (* We're in eBPF kernel space - config fields are read-only *)
          failwith (Printf.sprintf 
            "Config field assignment not allowed in eBPF programs at %s. Config fields are read-only in kernel space and can only be modified from userspace."
            (string_of_position stmt.stmt_pos))
        else (
          (* We're in userspace - config field assignment is allowed *)
          let key_val = make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) (IRU32) stmt.stmt_pos in
          let map_val = make_ir_value (IRMapRef map_name) (IRPointer (IRU8, make_bounds_info ())) stmt.stmt_pos in
          let value_val = lower_expression ctx value_expr in
          let instr = make_ir_instruction 
            (IRConfigFieldUpdate (map_val, key_val, field_name, value_val)) 
            stmt.stmt_pos 
          in
          emit_instruction ctx instr
        )
      ) else (
        (* This is regular struct field assignment *)
        let obj_val = lower_expression ctx object_expr in
        let value_val = lower_expression ctx value_expr in
        let instr = make_ir_instruction 
          (IRStructFieldAssignment (obj_val, field_name, value_val)) 
          stmt.stmt_pos 
        in
        emit_instruction ctx instr
      )
      
  | Ast.ArrowAssignment (object_expr, field_name, value_expr) ->
      (* Arrow assignment (pointer->field = value) - similar to field assignment but for pointers *)
      let obj_val = lower_expression ctx object_expr in
      let value_val = lower_expression ctx value_expr in
      (* For arrow assignment, we treat it similar to struct field assignment *)
      let instr = make_ir_instruction 
        (IRStructFieldAssignment (obj_val, field_name, value_val)) 
        stmt.stmt_pos 
      in
      emit_instruction ctx instr
      
  | Ast.Continue ->
      (* Generate continue instruction for IR *)
      let instr = make_ir_instruction IRContinue stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Try (try_stmts, catch_clauses) ->
      (* For try/catch blocks, we need to ensure proper statement ordering *)
      (* The key insight is that we need to process try/catch as a single unit *)
      (* while maintaining the sequential ordering of statements *)
      
      (* Convert AST catch clauses to IR catch clauses with proper bodies *)
      let ir_catch_clauses = List.map (fun clause ->
        let ir_pattern = match clause.Ast.catch_pattern with
          | Ast.IntPattern code -> Ir.IntCatchPattern code
          | Ast.WildcardPattern -> Ir.WildcardCatchPattern
        in
        
        (* Process catch clause body statements to IR instructions *)
        (* We need to maintain the same context for proper variable resolution *)
        let catch_instructions = ref [] in
        let old_current_block = ctx.current_block in
        ctx.current_block <- [];
        
        List.iter (lower_statement ctx) clause.Ast.catch_body;
        catch_instructions := List.rev ctx.current_block;
        
        ctx.current_block <- old_current_block;
        
        { Ir.catch_pattern = ir_pattern; Ir.catch_body = !catch_instructions }
      ) catch_clauses in
      
      (* Process try block statements while maintaining proper ordering *)
      (* The key is to process the try block in the current context but *)
      (* capture the instructions separately *)
      let try_instructions = ref [] in
      let old_current_block = ctx.current_block in
      let old_in_try_block = ctx.in_try_block in
      ctx.current_block <- [];
      ctx.in_try_block <- true;
      
      (* Process try statements in the current context to maintain variable scope *)
      (* and proper control flow block creation *)
      List.iter (lower_statement ctx) try_stmts;
      try_instructions := List.rev ctx.current_block;
      
      (* Restore the original current_block and in_try_block flag *)
      ctx.current_block <- old_current_block;
      ctx.in_try_block <- old_in_try_block;
      
      let instr = make_ir_instruction (IRTry (!try_instructions, ir_catch_clauses)) stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Throw expr ->
      (* Evaluate the expression to get the error code *)
      let _error_value = lower_expression ctx expr in
      (* For now, assume it's an integer literal - in a full implementation, 
         we'd need to evaluate the expression at compile time *)
      let error_code = match expr.expr_desc with
        | Ast.Literal (Ast.IntLit (code, _)) -> Ir.IntErrorCode (Int64.to_int (Ast.IntegerValue.to_int64 code))
        | Ast.Identifier _ -> 
            (* For identifiers (like enum values), we'd need to resolve them *)
            (* For now, use a default error code *)
            Ir.IntErrorCode 1
        | _ -> 
            (* For complex expressions, we'd need constant folding *)
            Ir.IntErrorCode 1
      in
      let instr = make_ir_instruction (IRThrow error_code) stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Defer expr ->
      (* Convert defer expression to instruction list *)
      let defer_instructions = ref [] in
      let old_blocks = ctx.current_block in
      ctx.current_block <- [];
      let _ = lower_expression ctx expr in
      defer_instructions := List.rev ctx.current_block;
      ctx.current_block <- old_blocks;
      
      let instr = make_ir_instruction (IRDefer !defer_instructions) stmt.stmt_pos in
      emit_instruction ctx instr

(** Helper function to take first n elements from a list *)
let rec list_take n lst =
  if n <= 0 then []
  else match lst with
    | [] -> []
    | x :: xs -> x :: list_take (n - 1) xs

(** Convert IRReturnCall actions to IRReturnTailCall with proper indices in IRMatchReturn instructions *)
let convert_match_return_calls_to_tail_calls ir_function =
  let rec update_instruction instr =
    match instr.instr_desc with
    | IRMatchReturn (matched_val, arms) ->
        let updated_arms = List.map (fun arm ->
          match arm.return_action with
          | IRReturnCall (func_name, args) ->
              (* Convert to tail call with index 0 - will be updated by tail call analyzer *)
              { arm with return_action = IRReturnTailCall (func_name, args, 0) }
          | _ -> arm
        ) arms in
        { instr with instr_desc = IRMatchReturn (matched_val, updated_arms) }
    | IRIf (cond, then_body, else_body) ->
        let updated_then = List.map update_instruction then_body in
        let updated_else = Option.map (List.map update_instruction) else_body in
        { instr with instr_desc = IRIf (cond, updated_then, updated_else) }
    | IRIfElseChain (conditions_and_bodies, final_else) ->
        let updated_conditions_and_bodies = List.map (fun (cond, then_body) ->
          (cond, List.map update_instruction then_body)
        ) conditions_and_bodies in
        let updated_final_else = Option.map (List.map update_instruction) final_else in
        { instr with instr_desc = IRIfElseChain (updated_conditions_and_bodies, updated_final_else) }
    | _ -> instr
  in
  
  let updated_blocks = List.map (fun block ->
    { block with instructions = List.map update_instruction block.instructions }
  ) ir_function.basic_blocks in
  
  { ir_function with basic_blocks = updated_blocks }

(** Lower AST function to IR function *)
let lower_function ctx prog_name ?(program_type : program_type option = None) ?(func_target = None) (func_def : Ast.function_def) =
  ctx.current_function <- Some func_def.func_name;
  
  (* Reset for new function *)
  Hashtbl.clear ctx.variable_types;
  Hashtbl.clear ctx.function_parameters;
  (* next_register field removed in new architecture *)
  ctx.current_block <- [];
  ctx.blocks <- [];
  ctx.stack_usage <- 0;
  
  (* Register kprobe parameter mappings ONLY for kprobe programs *)
  (match program_type with
  | Some (Ast.Probe Ast.Kprobe) ->
      let parameters = List.map (fun (param_name, param_type) ->
        let param_type_str = match param_type with
          | Ast.U8 -> "u8" | Ast.U16 -> "u16" | Ast.U32 -> "u32" | Ast.U64 -> "u64"
          | Ast.I8 -> "i8" | Ast.I16 -> "i16" | Ast.I32 -> "i32" | Ast.I64 -> "i64"
          | Ast.Bool -> "bool" | Ast.Char -> "char" | Ast.Void -> "void"
          | Ast.Pointer Ast.U8 -> "*u8"
          | Ast.Pointer _ -> "*u8"  (* Simplified pointer handling *)
          | Ast.UserType name -> name
          | _ -> "unknown"
        in
        (param_name, param_type_str)
      ) func_def.func_params in
      Kernelscript_context.Kprobe_codegen.register_kprobe_parameter_mappings func_def.func_name parameters
  | _ -> ());

  (* Store function parameters (don't allocate registers for them) *)
  let ir_params = List.map (fun (name, ast_type) ->
    let ir_type = ast_type_to_ir_type_with_context ctx.symbol_table ast_type in
    Hashtbl.add ctx.function_parameters name ir_type;
    (name, ir_type)
  ) func_def.func_params in
  
  (* Declare named return variable if present *)
  (match Ast.get_return_variable_name func_def.func_return_type with
   | Some var_name ->
       let return_type = match Ast.get_return_type func_def.func_return_type with
         | Some ast_type -> ast_type_to_ir_type_with_context ctx.symbol_table ast_type
         | None -> IRU32
       in
       (* Emit variable declaration for named return variable *)
       emit_variable_decl ctx var_name return_type None func_def.func_pos
   | None -> ());
  
  (* Helper function to lower statement with access to preceding statements *)
  let lower_statement_with_context all_statements current_index stmt =
    (* Get all statements before the current one *)
    let preceding_statements = list_take current_index all_statements in
    
    (* Collect constants from preceding statements *)
    let const_env = Loop_analysis.collect_constants_from_statements preceding_statements in
    
    (* Store const_env in context temporarily for loop analysis *)
    let old_const_env = ctx.const_env in
    ctx.const_env <- Some const_env;
    
    (* Lower the statement *)
    lower_statement ctx stmt;
    
    (* Restore const_env *)
    ctx.const_env <- old_const_env
  in
  
  (* Lower function body with context *)
  List.iteri (lower_statement_with_context func_def.func_body) func_def.func_body;
  
  (* Handle any remaining instructions by adding them to the last block or creating a sequential block *)
  (if ctx.current_block <> [] then
    (* If there are remaining instructions, add them to the last block if it exists *)
    match ctx.blocks with
    | last_block :: rest_blocks ->
        (* Add remaining instructions to the last block *)
        let updated_last_block = { last_block with instructions = last_block.instructions @ (List.rev ctx.current_block) } in
        ctx.blocks <- updated_last_block :: rest_blocks;
        ctx.current_block <- []
    | [] ->
        (* If no blocks exist, create an entry block with these instructions *)
        let _ = create_basic_block ctx "entry" in
        ()
  );
  
  (* Convert return type *)
  let ir_return_type = match Ast.get_return_type func_def.func_return_type with
    | Some ast_type -> Some (ast_type_to_ir_type_with_context ctx.symbol_table ast_type)
    | None -> None
  in
  
  (* Create IR function *)
  let ir_blocks = List.rev ctx.blocks in
  let is_main = func_def.func_name = "main" in
  
  (* Use program name for main function, regular function names for others *)
  let ir_func_name = if is_main then prog_name else func_def.func_name in
  
  (* Clear function parameters for next function *)
  Hashtbl.clear ctx.function_parameters;
  
  let ir_function = make_ir_function 
    ir_func_name 
    ir_params 
    ir_return_type 
    ir_blocks
    ~total_stack_usage:ctx.stack_usage
    ~is_main:is_main
    func_def.func_pos in
  
  (* Set the program type for the function *)
  ir_function.func_program_type <- program_type;
  
  (* Set the target for the function (for kprobe/tracepoint) *)
  ir_function.func_target <- func_target;
  
  (* Convert IRReturnCall actions to IRReturnTailCall in IRMatchReturn instructions *)
  convert_match_return_calls_to_tail_calls ir_function

(** Lower AST map declaration to IR map definition *)
let lower_map_declaration symbol_table (map_decl : Ast.map_declaration) =
  let ir_key_type = ast_type_to_ir_type_with_context symbol_table map_decl.Ast.key_type in
  let ir_value_type = ast_type_to_ir_type_with_context symbol_table map_decl.Ast.value_type in
  let ir_map_type = ast_map_type_to_ir_map_type map_decl.Ast.map_type in

  (* Generate standardized pin path if map is pinned *)
  let pin_path = 
    if map_decl.Ast.is_pinned then
      Some (Printf.sprintf "/sys/fs/bpf/%s/maps/%s" symbol_table.project_name map_decl.Ast.name)
    else
      None
  in
  
  (* Convert AST flags to integer representation *)
  let flags = Maps.ast_flags_to_int map_decl.Ast.config.flags in
  
  make_ir_map_def
    map_decl.Ast.name
    ir_key_type
    ir_value_type
    ir_map_type
    map_decl.Ast.config.max_entries
    ~ast_key_type:map_decl.Ast.key_type
    ~ast_value_type:map_decl.Ast.value_type
    ~ast_map_type:map_decl.Ast.map_type
    ~flags:flags
    ~is_global:map_decl.Ast.is_global
    ?pin_path:pin_path
    map_decl.Ast.map_pos

(** Convert config field type to IR type with unified logic **)
let rec config_field_type_to_ir_type field_type =
  match field_type with
  | Ast.U8 | Ast.I8 -> IRU8   (* Map signed to unsigned for IR *)
  | Ast.U16 | Ast.I16 -> IRU16 (* Map signed to unsigned for IR *)
  | Ast.U32 | Ast.I32 -> IRU32 (* Map signed to unsigned for IR *)
  | Ast.U64 | Ast.I64 -> IRU64 (* Map signed to unsigned for IR *)
  | Ast.Bool -> IRBool
  | Ast.Char -> IRChar
  | Ast.Array (elem_type, size) ->
      let ir_elem_type = config_field_type_to_ir_type elem_type in
      let bounds_info = { min_size = Some size; max_size = Some size; alignment = 1; nullable = false } in
      IRArray (ir_elem_type, size, bounds_info)
  | _ -> failwith ("Unsupported config field type: " ^ (Ast.string_of_bpf_type field_type))

(** Lower AST config declaration to IR global config *)
let lower_config_declaration _symbol_table (config_decl : Ast.config_declaration) =
  let ir_fields = List.map (fun field ->
    let ir_type = config_field_type_to_ir_type field.Ast.field_type in
    let default_value = match field.Ast.field_default with
      | Some literal -> Some (lower_literal literal field.Ast.field_pos)
      | None -> None
    in
    make_ir_config_field 
      field.Ast.field_name 
      ir_type 
      default_value 
      false  (* is_mutable: configs are read-only by default *)
      field.Ast.field_pos
  ) config_decl.Ast.config_fields in
  
  make_ir_global_config 
    config_decl.Ast.config_name 
    ir_fields 
    config_decl.Ast.config_pos

(** Lower AST global variable declaration to IR global variable *)
let lower_global_variable_declaration symbol_table (global_var_decl : Ast.global_variable_declaration) =
  let ir_type = match global_var_decl.global_var_type with
    | Some ast_type -> ast_type_to_ir_type_with_context symbol_table ast_type
    | None -> 
        (* If no type specified, infer from initial value *)
        (match global_var_decl.global_var_init with
         | Some init_expr ->
             (* Convert the expression to get its type information *)
             (match init_expr.expr_desc with
              | Literal (IntLit (_, _)) -> IRU32  (* Default integer type *)
              | Literal (StringLit s) -> IRStr (max 1 (String.length s))  (* String type *)
              | Literal (BoolLit _) -> IRBool
              | Literal (CharLit _) -> IRChar
              | Literal (NullLit) -> IRPointer (IRU8, make_bounds_info ~nullable:true ())  (* Default pointer type *)
              | Literal (ArrayLit _) -> IRArray (IRU32, 1, make_bounds_info ())  (* Default array type *)
              | UnaryOp (Neg, _) -> IRI32  (* Negative expressions default to signed *)
              | _ -> IRU32)  (* Default to U32 for other expressions *)
         | None -> IRU32)  (* Default type when no type or value specified *)
  in
  let ir_init = match global_var_decl.global_var_init with
    | Some init_expr ->
        (* For simple literals, extract the literal directly *)
        (match init_expr.expr_desc with
         | Literal lit -> Some (make_ir_value (IRLiteral lit) ir_type global_var_decl.global_var_pos)
         | UnaryOp (Neg, {expr_desc = Literal (IntLit (n, orig)); _}) ->
             (* Handle negative integer literals by creating a negated literal *)
             Some (make_ir_value (IRLiteral (IntLit (Ast.Signed64 (Int64.neg (Ast.IntegerValue.to_int64 n)), orig))) ir_type global_var_decl.global_var_pos)
         | _ -> 
             (* For more complex expressions, we need to evaluate them at compile time *)
             (* For now, default to zero/null initialization *)
             (match ir_type with
              | IRU32 | IRI32 -> Some (make_ir_value (IRLiteral (IntLit (Ast.Signed64 0L, None))) ir_type global_var_decl.global_var_pos)
              | IRBool -> Some (make_ir_value (IRLiteral (BoolLit false)) ir_type global_var_decl.global_var_pos)
              | IRStr _ -> Some (make_ir_value (IRLiteral (StringLit "")) ir_type global_var_decl.global_var_pos)
              | _ -> None))
    | None -> None
  in
  make_ir_global_variable
    global_var_decl.global_var_name
    ir_type
    ir_init
    global_var_decl.global_var_pos
    ~is_local:global_var_decl.is_local
    ~is_pinned:global_var_decl.is_pinned
    ()


(** Convert AST function to IR function for userspace context *)
let lower_userspace_function ctx func_def =
  (* Validate main function signature if it's the main function *)
  if func_def.Ast.func_name = "main" then (
    (* Validate main function signature: fn main() -> i32 or fn main(args: CustomStruct) -> i32 *)
    let expected_return = Some Ast.I32 in
    
    (* Check parameter count and types *)
    let params_valid = 
      (* Allow no parameters: fn main() -> i32 *)
      List.length func_def.Ast.func_params = 0 ||
      (* Allow single struct parameter: fn main(args: CustomStruct) -> i32 *)
      (List.length func_def.Ast.func_params = 1 &&
       match func_def.Ast.func_params with
       | [(_, Ast.Struct _)] -> true  (* Accept struct types *)
       | [(_, Ast.UserType _)] -> true  (* Accept user-defined types (structs) *)
       | [(_, _)] -> false (* Reject non-struct single parameters *)
       | _ -> false)
    in
    
    (* Check return type *)
    let return_valid = (Ast.get_return_type func_def.Ast.func_return_type) = expected_return in
    
    if not params_valid then
      failwith (Printf.sprintf 
        "main() function must have no parameters or one struct parameter, got: %s"
        (String.concat ", " (List.map (fun (name, typ) -> 
          Printf.sprintf "%s: %s" name (Ast.string_of_bpf_type typ)
        ) func_def.Ast.func_params)));
    
    if not return_valid then
      failwith (Printf.sprintf
        "main() function must return i32, got: %s"
        (match Ast.get_return_type func_def.Ast.func_return_type with 
         | Some t -> Ast.string_of_bpf_type t 
         | None -> "void"));
  );
  
  ctx.is_userspace <- true;
  let ir_function = lower_function ctx func_def.Ast.func_name ~program_type:None ~func_target:None func_def in
  ctx.is_userspace <- false;
  ir_function

(** Generate coordinator logic *)
and generate_coordinator_logic _ctx _ir_functions =
  let dummy_pos = { line = 1; column = 1; filename = "generated" } in
  
  (* Generate simplified setup logic *)
  let setup_logic = [
    make_ir_instruction (IRComment "Setup global maps and BPF programs") dummy_pos;
    make_ir_instruction (IRComment "Load BPF object and extract file descriptors") dummy_pos;
    make_ir_instruction (IRComment "Attach programs to appropriate hooks") dummy_pos;
  ] in
  
  (* Generate simplified event processing *)
  let event_processing = [
    make_ir_instruction (IRComment "Main event processing loop") dummy_pos;
    make_ir_instruction (IRComment "Poll for events from BPF programs") dummy_pos;
    make_ir_instruction (IRComment "Process ring buffer and perf events") dummy_pos;
  ] in
  
  (* Generate simplified cleanup logic *)
  let cleanup_logic = [
    make_ir_instruction (IRComment "Detach BPF programs") dummy_pos;
    make_ir_instruction (IRComment "Close map file descriptors") dummy_pos;
    make_ir_instruction (IRComment "Cleanup BPF object") dummy_pos;
  ] in
  
  (* Generate config management *)
  let config_management = make_ir_config_management [] [] [] in
  
  make_ir_coordinator_logic setup_logic event_processing cleanup_logic config_management
  

let convert_config_declarations_to_ir config_declarations =
  List.map (fun config_decl ->
    let ir_fields = List.map (fun field ->
      let ir_type = config_field_type_to_ir_type field.Ast.field_type in
      (field.Ast.field_name, ir_type)
    ) config_decl.Ast.config_fields in
    {
      config_struct_name = config_decl.Ast.config_name;
      fields = ir_fields;
      serialization = Json;
    }
  ) config_declarations

let generate_userspace_bindings_from_functions _prog_def userspace_functions maps config_declarations =
  (* Generate bindings based on userspace functions *)
  if List.length userspace_functions = 0 then (
    (* Default bindings when no userspace functions are specified *)
    let map_wrappers = List.map (fun map_def ->
      let operations = [OpLookup; OpUpdate; OpDelete; OpIterate] in
      {
        wrapper_map_name = map_def.map_name;
        operations;
        safety_checks = true;
      }
    ) maps in
    
    let config_structs = convert_config_declarations_to_ir config_declarations in
    
    [{
      language = C;
      map_wrappers;
      event_handlers = [];
      config_structs;
    }]
  ) else (
    (* Generate bindings based on userspace functions *)
    let map_wrappers = List.map (fun map_def ->
      let operations = [OpLookup; OpUpdate; OpDelete; OpIterate] in
      {
        wrapper_map_name = map_def.map_name;
        operations;
        safety_checks = true;
      }
    ) maps in
    
    let config_structs = convert_config_declarations_to_ir config_declarations in
    
    let target_languages = [C] in
    
    List.map (fun language ->
      {
        language;
        map_wrappers;
        event_handlers = [];
        config_structs;
      }
    ) target_languages
  )

(** Generate userspace bindings for multiple programs *)
let generate_userspace_bindings_from_multi_programs _prog_defs _userspace_functions maps config_declarations =
  (* Generate bindings for all programs with userspace functions *)
  let map_wrappers = List.map (fun map_def ->
    let operations = [OpLookup; OpUpdate; OpDelete; OpIterate] in
    {
      wrapper_map_name = map_def.map_name;
      operations;
      safety_checks = true;
    }
  ) maps in
  
  let config_structs = convert_config_declarations_to_ir config_declarations in
  
  [{
    language = C;
    map_wrappers;
    event_handlers = [];
    config_structs;
  }]

(** Lower a single program from AST to IR *)
let lower_single_program ctx prog_def _global_ir_maps _kernel_shared_functions =
  (* Include program-scoped maps *)
  let program_scoped_maps = prog_def.prog_maps in
  
  (* Lower program-scoped maps *)
  let ir_program_maps = List.map (fun map_decl -> lower_map_declaration ctx.symbol_table map_decl) program_scoped_maps in
  
  (* Add all maps to context for this program *)
  List.iter (fun (map_def : ir_map_def) -> 
    Hashtbl.add ctx.maps map_def.map_name map_def
  ) (ir_program_maps : ir_map_def list);
  (* Also add global maps to context *)
  List.iter (fun (map_def : ir_map_def) -> 
    Hashtbl.add ctx.maps map_def.map_name map_def
  ) (_global_ir_maps : ir_map_def list);
  
  (* Lower program-local functions only - kernel functions are handled separately *)
  let ir_program_functions = List.mapi (fun index func -> 
    (* For attributed functions (single function programs), the function IS the entry function *)
    (* But struct_ops functions should NOT be marked as main functions *)
    let is_attributed_entry = (List.length prog_def.prog_functions = 1 && index = 0 && prog_def.prog_type <> Ast.StructOps) in
    (* Extract target from program definition *)
    let func_target = prog_def.prog_target in
    let temp_func = lower_function ctx prog_def.prog_name ~program_type:(Some prog_def.prog_type) ~func_target func in
    if is_attributed_entry then
      (* Mark the attributed function as entry by updating the is_main field *)
      { temp_func with is_main = true }
    else
      temp_func
  ) prog_def.prog_functions in
  
  (* Find entry function - for attributed functions, it's the single function we just marked *)
  (* For struct_ops functions, we'll use the first function as entry but it won't be marked as main *)
  let entry_function = 
    try
      List.find (fun f -> f.is_main) ir_program_functions
    with Not_found ->
      (* For struct_ops functions, use the first function as entry *)
      if List.length ir_program_functions = 0 then
        failwith ("No functions found in program " ^ prog_def.prog_name ^ ". This might be due to IR generation failures.")
      else
        List.hd ir_program_functions
  in
  
  (* Create IR program with the entry function *)
  make_ir_program 
    prog_def.prog_name 
    prog_def.prog_type 
    entry_function 
    prog_def.prog_pos

(** Validate multiple programs for consistency *)
let validate_multiple_programs prog_defs =
  (* Check for duplicate program names *)
  let names = List.map (fun p -> p.prog_name) prog_defs in
  let unique_names = List.sort_uniq String.compare names in
  if List.length names <> List.length unique_names then
    failwith "Multiple programs cannot have the same name";
  
  (* Allow multiple programs of the same type - needed for tail calls *)
  (* Note: Multiple programs of the same type are valid and needed for tail call chains *)
  
  (* Each attributed function serves as the entry function for its program type *)
  List.iter (fun prog_def ->
    (* For attributed functions, the single function IS the entry function *)
    if List.length prog_def.prog_functions = 0 then
      failwith (Printf.sprintf "Program '%s' has no functions" prog_def.prog_name);
    (* Attributed functions convert to exactly one function which serves as entry *)
    if List.length prog_def.prog_functions > 1 then
      failwith (Printf.sprintf "Program '%s' was converted incorrectly - should have exactly one function" prog_def.prog_name)
  ) prog_defs

(** Check if a struct is used only in userspace contexts *)
let is_struct_userspace_only ast struct_name =
  let is_used_in_ebpf = ref false in
  let is_used_in_userspace = ref false in
  
  let rec check_type_usage = function
    | Ast.UserType name when name = struct_name -> true
    | Ast.Struct name when name = struct_name -> true
    | Ast.Pointer inner_type -> check_type_usage inner_type
    | Ast.Array (inner_type, _) -> check_type_usage inner_type
    | Ast.Function (param_types, return_type) ->
        List.exists check_type_usage param_types || check_type_usage return_type
    | _ -> false
  in
  
  let check_function_usage func_def is_ebpf_context =
    (* Check if function uses the struct *)
    let uses_struct = 
      List.exists (fun (_, param_type) -> check_type_usage param_type) func_def.func_params ||
      (match func_def.func_return_type with 
       | Some (Ast.Unnamed rt) -> check_type_usage rt 
       | Some (Ast.Named (_, rt)) -> check_type_usage rt
       | None -> false)
    in
    
    if uses_struct then (
      if is_ebpf_context then
        is_used_in_ebpf := true
      else if func_def.func_name = "main" then
        is_used_in_userspace := true
    )
  in
  
  (* Check all function declarations *)
  List.iter (function
    | Ast.AttributedFunction attr_func -> 
        (* eBPF functions are wrapped in AttributedFunction *)
        check_function_usage attr_func.attr_function true
    | Ast.GlobalFunction func_def -> 
        (* Regular userspace functions *)
        check_function_usage func_def false

    | _ -> ()
  ) ast;
  
  (* A struct is userspace-only if it's used in userspace but not in eBPF *)
  !is_used_in_userspace && not !is_used_in_ebpf

(** Check if a struct should be excluded from eBPF (not used by eBPF programs) *)
let should_exclude_struct_from_ebpf ast struct_name =
  let is_used_in_ebpf = ref false in
  
  let rec check_type_usage = function
    | Ast.UserType name when name = struct_name -> true
    | Ast.Struct name when name = struct_name -> true
    | Ast.Pointer inner_type -> check_type_usage inner_type
    | Ast.Array (inner_type, _) -> check_type_usage inner_type
    | Ast.Function (param_types, return_type) ->
        List.exists check_type_usage param_types || check_type_usage return_type
    | _ -> false
  in
  
  let check_function_usage func_def is_ebpf_context =
    (* Check if function uses the struct *)
    let uses_struct = 
      List.exists (fun (_, param_type) -> check_type_usage param_type) func_def.func_params ||
      (match func_def.func_return_type with 
       | Some (Ast.Unnamed rt) -> check_type_usage rt 
       | Some (Ast.Named (_, rt)) -> check_type_usage rt
       | None -> false)
    in
    
    if uses_struct && is_ebpf_context then
      is_used_in_ebpf := true
  in
  
  (* Check all function declarations *)
  List.iter (function
    | Ast.AttributedFunction attr_func -> 
        (* eBPF functions are wrapped in AttributedFunction *)
        check_function_usage attr_func.attr_function true
    | Ast.GlobalFunction func_def -> 
        (* Regular userspace functions *)
        check_function_usage func_def false

    | _ -> ()
  ) ast;
  
  (* Exclude struct if it's not used in eBPF *)
  not !is_used_in_ebpf

(** Convert a global variable declaration with map type to IR map definition *)
let convert_global_var_to_map symbol_table global_var_decl =
  match global_var_decl.Ast.global_var_type with
  | Some (Ast.Map (key_type, value_type, map_type, size)) ->
      let ir_key_type = ast_type_to_ir_type_with_context symbol_table key_type in
      let ir_value_type = ast_type_to_ir_type_with_context symbol_table value_type in
      let ir_map_type = ast_map_type_to_ir_map_type map_type in
      let pin_path = 
        if global_var_decl.Ast.is_pinned then
          Some (Printf.sprintf "/sys/fs/bpf/%s/maps/%s" symbol_table.project_name global_var_decl.Ast.global_var_name)
        else
          None
      in
      Some (make_ir_map_def
        global_var_decl.Ast.global_var_name
        ir_key_type
        ir_value_type
        ir_map_type
        size
        ~ast_key_type:key_type
        ~ast_value_type:value_type
        ~ast_map_type:map_type
        ~flags:0
        ~is_global:true
        ?pin_path:pin_path
        global_var_decl.Ast.global_var_pos)
  | _ -> None

(** Check if a global variable declaration has a map type *)
let is_global_var_map global_var_decl =
  match global_var_decl.Ast.global_var_type with
  | Some (Ast.Map _) -> true
  | _ -> false

let lower_multi_program ast symbol_table source_name =
  (* Phase 1: Collect and categorize declarations in source order *)
  let (ordered_declarations, all_maps, all_global_vars) = 
    List.fold_left (fun (decls, maps, vars) decl ->
      match decl with
      | Ast.MapDecl map_decl -> 
          let ir_map = lower_map_declaration symbol_table map_decl in
          ((decl, `Map ir_map) :: decls, ir_map :: maps, vars)
      | Ast.GlobalVarDecl var_decl when is_global_var_map var_decl ->
          let ir_map = match convert_global_var_to_map symbol_table var_decl with
            | Some map -> map
            | None -> failwith "Expected map conversion to succeed"
          in
          let ir_var = lower_global_variable_declaration symbol_table var_decl in
          ((decl, `MapFromGlobalVar (ir_map, ir_var)) :: decls, ir_map :: maps, ir_var :: vars)
      | Ast.GlobalVarDecl var_decl ->
          let ir_var = lower_global_variable_declaration symbol_table var_decl in
          ((decl, `GlobalVar ir_var) :: decls, maps, ir_var :: vars)
      | other ->
          ((decl, `Other other) :: decls, maps, vars)
    ) ([], [], []) ast
  in
  
  (* Phase 2: Create context with ALL maps available *)
  let ctx = create_context ~global_variables:all_global_vars symbol_table in
  add_maps_to_context ctx all_maps;
  
  (* Analyze assignment patterns for optimization early *)
  let _optimization_info = analyze_assignment_patterns ctx ast in
  
  (* Phase 3: Process declarations in original order *)
  let source_declarations = ref [] in
  let declaration_order = ref 0 in
  
  (* Helper function to add a declaration to source order *)
  let add_source_declaration decl_desc pos =
    let decl = make_ir_source_declaration decl_desc !declaration_order pos in
    source_declarations := decl :: !source_declarations;
    incr declaration_order
  in
  
  (* Helper function to get position from AST declaration *)
  let get_decl_pos = function
    | Ast.TypeDef (Ast.TypeAlias (_, _, pos)) -> pos
    | Ast.TypeDef (Ast.StructDef (_, _, pos)) -> pos
    | Ast.TypeDef (Ast.EnumDef (_, _, pos)) -> pos
    | Ast.MapDecl map_decl -> map_decl.map_pos
    | Ast.ConfigDecl config_decl -> config_decl.config_pos
    | Ast.GlobalVarDecl global_var_decl -> global_var_decl.global_var_pos
    | Ast.GlobalFunction func_def -> func_def.func_pos
    | Ast.StructDecl struct_def -> struct_def.struct_pos
    | Ast.AttributedFunction attr_func -> attr_func.attr_function.func_pos
    | Ast.ImplBlock impl_block -> impl_block.impl_pos
    | _ -> { line = 1; column = 1; filename = source_name }
  in
  
  (* Process declarations in original order using our categorized list *)
  List.rev ordered_declarations |> List.iter (fun (original_decl, processed) ->
    let pos = get_decl_pos original_decl in
    match processed with
    | `Map ir_map -> 
        add_source_declaration (IRDeclMapDef ir_map) pos
    | `MapFromGlobalVar (ir_map, ir_var) ->
        (* For global variables with map types, add both the map and the variable *)
        add_source_declaration (IRDeclMapDef ir_map) pos;
        add_source_declaration (IRDeclGlobalVarDef ir_var) pos
    | `GlobalVar ir_var ->
        add_source_declaration (IRDeclGlobalVarDef ir_var) pos
    | `Other decl ->
        (* Handle other declaration types *)
        (match decl with
         | Ast.TypeDef (Ast.TypeAlias (name, underlying_type, pos)) ->
             let ir_type = ast_type_to_ir_type_with_context symbol_table underlying_type in
             add_source_declaration (IRDeclTypeAlias (name, ir_type, pos)) pos
         | Ast.TypeDef (Ast.StructDef (name, fields, pos)) ->
             (* Only filter user-defined structs, not kernel structs from .kh files *)
             let is_kernel_struct = Filename.check_suffix pos.filename ".kh" in
             let should_include = is_kernel_struct || not (should_exclude_struct_from_ebpf ast name) in
             if should_include then (
               let ir_fields = List.map (fun (field_name, field_type) ->
                 (field_name, ast_type_to_ir_type_with_context symbol_table field_type)
               ) fields in
               add_source_declaration (IRDeclStructDef (name, ir_fields, pos)) pos
             )
         | Ast.TypeDef (Ast.EnumDef (name, values, pos)) ->
             let ir_values = List.map (fun (enum_name, opt_value) ->
               (enum_name, Option.value ~default:(Ast.Signed64 0L) opt_value)
             ) values in
             add_source_declaration (IRDeclEnumDef (name, ir_values, pos)) pos
         | Ast.ConfigDecl config_decl ->
             let ir_config_def = lower_config_declaration symbol_table config_decl in
             add_source_declaration (IRDeclConfigDef ir_config_def) config_decl.config_pos
         | Ast.GlobalFunction func_def ->
             let ir_func = 
               if func_def.func_scope = Ast.Kernel then
                 lower_function ctx "global" ~program_type:None ~func_target:None func_def
               else
                 lower_userspace_function ctx func_def
             in
             add_source_declaration (IRDeclFunctionDef ir_func) func_def.func_pos
         | Ast.StructDecl struct_def ->
             (* Only filter user-defined structs, not kernel structs from .kh files *)
             let is_kernel_struct = Filename.check_suffix struct_def.struct_pos.filename ".kh" in
             let should_include = is_kernel_struct || not (should_exclude_struct_from_ebpf ast struct_def.struct_name) in
             if should_include then (
               let ir_fields = List.map (fun (field_name, field_type) ->
                 (field_name, ast_type_to_ir_type_with_context symbol_table field_type)
               ) struct_def.struct_fields in
               add_source_declaration (IRDeclStructDef (struct_def.struct_name, ir_fields, struct_def.struct_pos)) struct_def.struct_pos
             )
         | Ast.AttributedFunction _ | Ast.ImplBlock _ -> 
             (* These are handled elsewhere *)
             ()
         | _ -> () )
  );
  
  (* Extract impl blocks as struct_ops declarations *)
  let impl_block_declarations = List.filter_map (function
    | Ast.ImplBlock impl_block ->
        (* Check if this impl block has @struct_ops attribute *)
        let has_struct_ops_attr = List.exists (function
          | Ast.AttributeWithArg ("struct_ops", _) -> true
          | _ -> false
        ) impl_block.impl_attributes in
        if has_struct_ops_attr then Some impl_block else None
    | _ -> None
  ) ast in
  
  (* Find all program declarations by converting from attributed functions *)
  let prog_defs = List.filter_map (function
    | Ast.AttributedFunction attr_func ->
        (* Convert attributed function to program_def for compatibility *)
        (match attr_func.attr_list with
         | SimpleAttribute prog_type_str :: _ ->
             (match prog_type_str with
              | "kfunc" -> None  (* Skip kfunc functions - they're not eBPF programs *)
              | "private" -> None  (* Skip private functions - they're not eBPF programs *)
              | "helper" -> None  (* Skip helper functions - they're shared eBPF functions, not individual programs *)
              | "test" -> None  (* Skip test functions - they're userspace test functions, not eBPF programs *)
              | _ ->
                  let prog_type = match prog_type_str with
                    | "xdp" -> Ast.Xdp
                    | "tc" -> Ast.Tc  

                    | "tracepoint" -> Ast.Tracepoint
                    | _ -> failwith ("Unknown program type: " ^ prog_type_str)
                  in
                  Some {
                    Ast.prog_name = attr_func.attr_function.func_name;
                    prog_type = prog_type;
                    prog_functions = [attr_func.attr_function];
                    prog_maps = [];
                    prog_structs = [];
                    prog_target = None;
                    prog_pos = attr_func.attr_pos;
                  })
                  | AttributeWithArg (attr_name, target_func) :: _ ->
             (* Handle attributes with arguments like @tc("ingress"), @probe("sys_read") *)
             (match attr_name with
              | "tc" ->
                  Some {
                    Ast.prog_name = attr_func.attr_function.func_name;
                    prog_type = Ast.Tc;
                    prog_functions = [attr_func.attr_function];
                    prog_maps = [];
                    prog_structs = [];
                    prog_target = Some target_func;
                    prog_pos = attr_func.attr_pos;
                  }
              | "probe" ->
                  (* Determine probe type based on whether target contains offset *)
                  let probe_kind = if String.contains target_func '+' then Ast.Kprobe else Ast.Fprobe in
                  Some {
                    Ast.prog_name = attr_func.attr_function.func_name;
                    prog_type = Ast.Probe probe_kind;
                    prog_functions = [attr_func.attr_function];
                    prog_maps = [];
                    prog_structs = [];
                    prog_target = Some target_func;
                    prog_pos = attr_func.attr_pos;
                  }
              | "tracepoint" ->
                  Some {
                    Ast.prog_name = attr_func.attr_function.func_name;
                    prog_type = Ast.Tracepoint;
                    prog_functions = [attr_func.attr_function];
                    prog_maps = [];
                    prog_structs = [];
                    prog_target = Some target_func;
                    prog_pos = attr_func.attr_pos;
                  }
              | _ -> None)
         | _ -> None)
    | _ -> None
  ) ast in
  
  (* Add impl block functions as program definitions *)
  let impl_block_prog_defs = List.map (fun impl_block ->
    List.filter_map (fun item ->
      match item with
      | Ast.ImplFunction func ->
          (* Create a program definition for each impl block function *)
          (* These will be eBPF programs with SEC("struct_ops/function_name") *)
          Some {
            Ast.prog_name = func.func_name;
            prog_type = Ast.StructOps;  (* Use the struct_ops program type *)
            prog_functions = [func];
            prog_maps = [];
            prog_structs = [];
            prog_target = None; (* struct_ops don't have targets *)
            prog_pos = func.func_pos;
          }
      | Ast.ImplStaticField (_, _) -> None  (* Static fields are not programs *)
    ) impl_block.impl_items
  ) impl_block_declarations |> List.concat in
  
  (* Combine regular program definitions with impl block program definitions *)
  let all_prog_defs = prog_defs @ impl_block_prog_defs in
  
  (* Allow compilation if we have either traditional eBPF programs OR struct_ops declarations *)
  (* Extract struct_ops declarations early to check for valid compilation targets *)
  let struct_ops_declarations = List.filter_map (function
    | Ast.StructDecl struct_def ->
        (* Check if this struct has @struct_ops attribute *)
        let has_struct_ops_attr = List.exists (function
          | Ast.AttributeWithArg ("struct_ops", _) -> true
          | _ -> false
        ) struct_def.struct_attributes in
        if has_struct_ops_attr then Some struct_def else None
    | _ -> None
  ) ast in
  
  if all_prog_defs = [] && struct_ops_declarations = [] && impl_block_declarations = [] then
    failwith "No program declarations or struct_ops found";
  
  (* Only validate multiple programs if we have any traditional eBPF programs *)
  if all_prog_defs <> [] then
    validate_multiple_programs all_prog_defs;
  
  (* Also add all program-scoped maps to main context for userspace processing *)
  List.iter (fun prog_def ->
    let program_scoped_maps = prog_def.prog_maps in
    let ir_program_maps = List.map (fun map_decl -> lower_map_declaration ctx.symbol_table map_decl) program_scoped_maps in
    add_maps_to_context ctx ir_program_maps
  ) all_prog_defs;
  
  (* Use maps from Phase 1 - no need to reprocess global maps *)
  let all_global_maps = all_maps in
  
  (* Convert ir_map_def list to map_flag_info list for userspace bindings *)
  let ir_map_def_to_map_flag_info (ir_map : ir_map_def) : Maps.map_flag_info =
    (* Find assignments to this specific map *)
    let all_map_assignments = Map_assignment.extract_map_assignments_from_ast ast in
    let map_assignments = List.filter (fun assignment -> 
      assignment.Map_assignment.map_name = ir_map.map_name
    ) all_map_assignments in
    
    (* Extract initial values from assignments with literal keys and values *)
    let initial_values = List.filter_map (fun assignment ->
      match assignment.Map_assignment.key_expr.expr_desc, assignment.Map_assignment.value_expr.expr_desc with
      | Literal key_lit, Literal value_lit ->
          let key_str = match key_lit with
            | IntLit (i, _) -> Ast.IntegerValue.to_string i
            | StringLit s -> "\"" ^ s ^ "\""
            | _ -> "0"
          in
          let value_str = match value_lit with
            | IntLit (i, _) -> Ast.IntegerValue.to_string i
            | StringLit s -> "\"" ^ s ^ "\""
            | BoolLit b -> if b then "1" else "0"
            | _ -> "0"
          in
          Some (key_str ^ ":" ^ value_str)
      | _ -> None
    ) map_assignments in
    
    {
      Maps.map_name = ir_map.map_name;
      has_initial_values = List.length initial_values > 0;
      initial_values;
      key_type = string_of_ir_type ir_map.map_key_type;
      value_type = string_of_ir_type ir_map.map_value_type;
    }
  in
  
  let map_flag_infos = List.map ir_map_def_to_map_flag_info all_global_maps in
  
  (* Separate global functions by scope and extract @helper attributed functions as kernel shared functions *)
  let all_global_functions = List.filter_map (function
    | Ast.GlobalFunction func -> Some func
    | _ -> None
  ) ast in
  
  (* Extract @helper attributed functions and treat them as kernel shared functions *)
  let helper_functions = List.filter_map (function
    | Ast.AttributedFunction attr_func ->
        let is_helper = List.exists (function
          | Ast.SimpleAttribute "helper" -> true
          | _ -> false
        ) attr_func.attr_list in
        if is_helper then
          Some attr_func.attr_function
        else
          None
    | _ -> None
  ) ast in
  
  let (kernel_shared_functions, userspace_functions) = List.partition (fun func ->
    func.Ast.func_scope = Ast.Kernel
  ) all_global_functions in
  
  (* Combine regular kernel functions with helper functions *)
  let all_kernel_shared_functions = kernel_shared_functions @ helper_functions in
  
  (* Extract helper function names for context *)
  let helper_function_names = List.map (fun func -> func.Ast.func_name) helper_functions in
  
  (* Lower kernel functions once - they are shared across all programs *)
  let kernel_ctx = create_context ~global_variables:all_global_vars ~helper_functions:helper_function_names symbol_table in
  (* Copy maps from main context to kernel context *)
  copy_maps_to_context ctx kernel_ctx;
  let ir_kernel_functions = List.map (lower_function kernel_ctx "kernel" ~program_type:None ~func_target:None) all_kernel_shared_functions in
  
  (* Lower each program *)
  let ir_programs = List.map (fun prog_def ->
    (* Create a fresh context for each program *)
    let prog_ctx = create_context ~global_variables:all_global_vars ~helper_functions:helper_function_names symbol_table in
    (* Copy maps from main context to program context *)
    copy_maps_to_context ctx prog_ctx;
    lower_single_program prog_ctx prog_def all_global_maps all_kernel_shared_functions
  ) all_prog_defs in
  
  (* Convert AST userspace functions to IR userspace program *)
  let userspace_program = 
    if List.length userspace_functions = 0 then
      None
    else
      (* Main function is now mandatory for all userspace code *)
      let main_functions = List.filter (fun f -> f.Ast.func_name = "main") userspace_functions in
      if List.length main_functions = 0 then
        failwith "Userspace code must contain a main() function (no longer optional)";
      if List.length main_functions > 1 then
        failwith "Only one main() function is allowed";
      
      (* Extract struct definitions from AST (single source of truth) *)
      (* Filter out kernel structs from .kh header files *)
      let struct_definitions = List.filter_map (function
        | Ast.StructDecl struct_def -> 
            (* Filter out structs from .kh header files - they should not appear in userspace code *)
            let is_header_struct = Filename.check_suffix struct_def.Ast.struct_pos.filename ".kh" in
            if is_header_struct then
              None
            else
              Some struct_def
        | _ -> None
      ) ast in
      
      (* Convert struct definitions to IR (no duplication) *)
      let ir_userspace_structs = List.map (fun struct_def ->
        let ir_fields = List.map (fun (field_name, field_type) ->
          let ir_field_type = match field_type with
            | Ast.Function (param_types, return_type) ->
                (* Convert function types to function pointers *)
                let ir_param_types = List.map ast_type_to_ir_type param_types in
                let ir_return_type = ast_type_to_ir_type return_type in
                IRFunctionPointer (ir_param_types, ir_return_type)
            | _ -> ast_type_to_ir_type_with_context symbol_table field_type
          in
          (field_name, ir_field_type)
        ) struct_def.Ast.struct_fields in
        make_ir_struct_def 
          struct_def.Ast.struct_name 
          ir_fields 
          8 (* default alignment *)
          (List.length ir_fields * 8) (* estimated size *)
          struct_def.Ast.struct_pos
      ) struct_definitions in
      
      let userspace_ctx = create_context ~global_variables:all_global_vars symbol_table in
      (* Copy maps from main context to userspace context *)
      copy_maps_to_context ctx userspace_ctx;
      let ir_functions = List.map (fun func -> lower_userspace_function userspace_ctx func) userspace_functions in
      Some (make_ir_userspace_program ir_functions ir_userspace_structs [] (generate_coordinator_logic userspace_ctx ir_functions) (match userspace_functions with [] -> { line = 1; column = 1; filename = source_name } | h::_ -> h.func_pos))
  in
  
  (* Extract config declarations from AST *)
  let config_declarations = List.filter_map (function
    | Ast.ConfigDecl config -> Some config
    | _ -> None
  ) ast in
  
  (* Note: struct_ops instances are now just regular variable declarations with struct literals *)
  
  (* Lower struct_ops declarations to IR *)
  let ir_struct_ops_declarations = List.map (fun struct_def ->
    (* Extract kernel struct name from @struct_ops attribute *)
    let kernel_struct_name = extract_struct_ops_kernel_name struct_def.struct_attributes in
    
    let ir_methods = List.map (fun (field_name, field_type) ->
      let ir_field_type = match field_type with
        | Ast.Function (param_types, return_type) ->
            (* Convert function types to function pointers *)
            let ir_param_types = List.map ast_type_to_ir_type param_types in
            let ir_return_type = ast_type_to_ir_type return_type in
            IRFunctionPointer (ir_param_types, ir_return_type)
        | _ -> ast_type_to_ir_type_with_context symbol_table field_type
      in
      make_ir_struct_ops_method 
        field_name
        ir_field_type
        struct_def.Ast.struct_pos
    ) struct_def.Ast.struct_fields in
    make_ir_struct_ops_declaration
      struct_def.Ast.struct_name
      kernel_struct_name
      ir_methods
      struct_def.Ast.struct_pos
  ) struct_ops_declarations in
  
  (* Lower impl blocks to struct_ops declarations *)
  let ir_impl_block_declarations = List.map (fun impl_block ->
    (* Extract kernel struct name from @struct_ops attribute *)
    let kernel_struct_name = extract_struct_ops_kernel_name impl_block.impl_attributes in
    
    (* Convert impl block functions to struct_ops methods *)
    let ir_methods = List.filter_map (fun item ->
      match item with
      | Ast.ImplFunction func ->
          (* Create method from function signature *)
          let ir_param_types = List.map (fun (_, param_type) -> ast_type_to_ir_type param_type) func.func_params in
          let ir_return_type = match Ast.get_return_type func.func_return_type with
            | Some ret_type -> ast_type_to_ir_type ret_type
            | None -> IRVoid
          in
          let method_type = IRFunctionPointer (ir_param_types, ir_return_type) in
          Some (make_ir_struct_ops_method 
            func.func_name
            method_type
            func.func_pos)
      | Ast.ImplStaticField (_, _) -> None  (* Static fields are not methods *)
    ) impl_block.impl_items in
    
    make_ir_struct_ops_declaration
      impl_block.impl_name
      kernel_struct_name
      ir_methods
      impl_block.impl_pos
  ) impl_block_declarations in
  
  (* Lower struct_ops instances to IR - create from impl blocks *)
  let ir_struct_ops_instances = List.map (fun impl_block ->
    (* Extract kernel struct name from @struct_ops attribute *)
    let kernel_struct_name = extract_struct_ops_kernel_name impl_block.impl_attributes in
    
    (* Convert impl block items to struct_ops instance fields *)
    let ir_instance_fields = List.filter_map (fun item ->
      match item with
      | Ast.ImplFunction func ->
          (* Function reference - create IRFunctionRef *)
          let func_val = make_ir_value (IRFunctionRef func.func_name) IRVoid func.func_pos in
          Some (func.func_name, func_val)
      | Ast.ImplStaticField (field_name, field_expr) ->
          (* Static field - convert expression to IR value *)
          let field_val = match field_expr.expr_desc with
            | Ast.Literal literal ->
                (match literal with
                | Ast.StringLit s -> make_ir_value (IRLiteral (StringLit s)) (IRStr (String.length s + 1)) field_expr.expr_pos
                | Ast.NullLit -> make_ir_value (IRLiteral NullLit) (IRPointer (IRU8, make_bounds_info ~nullable:true ())) field_expr.expr_pos
                | Ast.IntLit (value, _) -> 
                    let ir_type = if Ast.IntegerValue.compare_with_zero value < 0 then IRI32 else IRU32 in
                    make_ir_value (IRLiteral (IntLit (value, None))) ir_type field_expr.expr_pos
                | Ast.BoolLit b -> make_ir_value (IRLiteral (BoolLit b)) IRBool field_expr.expr_pos
                | Ast.CharLit c -> make_ir_value (IRLiteral (CharLit c)) IRChar field_expr.expr_pos
                | _ -> failwith ("Unsupported literal type in static field: " ^ (Ast.string_of_literal literal)))
            | _ -> failwith "Static fields must be literals"
          in
          Some (field_name, field_val)
    ) impl_block.impl_items in
    
    make_ir_struct_ops_instance
      impl_block.impl_name
      kernel_struct_name
      ir_instance_fields
      impl_block.impl_pos
  ) impl_block_declarations in
  
  (* Use the unified literal conversion function *)
  let ast_literal_to_ir_value = lower_literal in
  
  (* Convert config declarations to IR *)
  let ir_global_configs = List.map (fun config_decl ->
    let ir_fields = List.map (fun field ->
      let ir_type = match field.Ast.field_type with
        | Ast.U8 -> IRU8
        | Ast.U16 -> IRU16
        | Ast.U32 -> IRU32
        | Ast.U64 -> IRU64
        | Ast.I8 -> IRI8
        | Ast.I16 -> IRI16
        | Ast.I32 -> IRI32
        | Ast.I64 -> IRI64
        | Ast.Bool -> IRBool
        | Ast.Char -> IRChar
        | Ast.Array (elem_type, size) ->
            let ir_elem_type = ast_basic_type_to_ir_type elem_type in
            let bounds_info = { min_size = Some size; max_size = Some size; alignment = 1; nullable = false } in
            IRArray (ir_elem_type, size, bounds_info)
        | _ -> failwith ("Unsupported config field type: " ^ (Ast.string_of_bpf_type field.Ast.field_type))
      in
      let default_value = match field.Ast.field_default with
        | Some literal -> Some (ast_literal_to_ir_value literal field.Ast.field_pos)
        | None -> None
      in
      make_ir_config_field 
        field.Ast.field_name 
        ir_type 
        default_value 
        false  (* is_mutable: configs are read-only by default *)
        field.Ast.field_pos
    ) config_decl.Ast.config_fields in
    make_ir_global_config 
      config_decl.Ast.config_name 
      ir_fields 
      config_decl.Ast.config_pos
  ) config_declarations in
  
  (* Generate userspace bindings *)
  let userspace_bindings = generate_userspace_bindings_from_multi_programs all_prog_defs userspace_functions map_flag_infos config_declarations in

  (* Create multi-program IR *)
  let multi_pos = match all_prog_defs with
    | [] -> { line = 1; column = 1; filename = source_name }
    | first :: _ -> first.prog_pos
  in
  
  (* Combine both traditional struct_ops declarations and impl block declarations *)
  let combined_struct_ops_declarations = ir_struct_ops_declarations @ ir_impl_block_declarations in
  
  make_ir_multi_program source_name ir_programs ir_kernel_functions all_global_maps 
    ~global_configs:ir_global_configs ~global_variables:all_global_vars
    ~struct_ops_declarations:combined_struct_ops_declarations
    ~struct_ops_instances:ir_struct_ops_instances ?userspace_program:userspace_program 
    ~userspace_bindings:userspace_bindings ~source_declarations:(List.rev !source_declarations) multi_pos

(** Main entry point for IR generation *)
let generate_ir ?(use_type_annotations=false) ast symbol_table source_name =
  try
    if use_type_annotations then
      (* For type-checked AST, expressions already have proper type annotations *)
      lower_multi_program ast symbol_table source_name
    else
      (* For raw AST, we need to do type checking first or use fallback types *)
      lower_multi_program ast symbol_table source_name
  with
  | exn ->
      Printf.eprintf "IR generation failed: %s\n" (Printexc.to_string exn);
      raise exn