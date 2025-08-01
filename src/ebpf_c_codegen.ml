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

(** eBPF C Code Generation from IR
    This module generates idiomatic eBPF C code from the IR representation.
    The generated code is compatible with clang -target bpf compilation.
    
    Key features:
    - Map definitions using SEC("maps") sections
    - Standard BPF helper function calls
    - Context field access
    - Bounds checking as C conditionals
    - Structured control flow
*)

open Ir
open Printf

(** Memory region types for dynptr API selection *)
type memory_region_type =
  | PacketData        (* XDP/TC packet data - use bpf_dynptr_from_xdp/skb *)
  | MapValue          (* Map lookup result - use bpf_dynptr_from_mem *)
  | RingBuffer        (* Ring buffer data - use bpf_dynptr_from_ringbuf *)
  | LocalStack        (* Local stack variables - use regular access *)
  | RegularMemory     (* Other memory - use enhanced safety *)

(** Enhanced memory region detection using provided region information *)
type enhanced_memory_info = {
  region_type: memory_region_type;
  bounds_verified: bool;
  size_hint: int option;
}

(** Variable name to enhanced memory info mapping *)
type memory_info_map = (string, enhanced_memory_info) Hashtbl.t

type bounds_hint = { verified: bool; size_hint: int }

(** Detect memory region type from IR value semantics *)
let detect_memory_region_type ir_val =
  match ir_val.value_desc with
  | IRContextField (XdpCtx, ("data" | "data_end" | "data_meta")) -> PacketData
  | IRContextField (TcCtx, ("data" | "data_end")) -> PacketData
  | IRVariable _ -> LocalStack  (* Variables are typically stack-allocated *)
  | IRMapRef _ -> RegularMemory  (* Map references *)
  | IRLiteral _ -> RegularMemory  (* Literals *)
  | IRRegister _ -> RegularMemory  (* Registers *)
  | _ -> RegularMemory

(** Check if IR value represents packet data *)
let is_packet_data_value ir_val =
  match detect_memory_region_type ir_val with
  | PacketData -> true
  | _ -> false

(** Check if IR value represents map-derived data - heuristic approach *)
let is_map_value_parameter ir_val =
  match ir_val.val_type with
  | IRPointer (IRStruct _, _) -> 
      (* Struct pointers that are variables could be from map lookups *)
      (match ir_val.value_desc with
       | IRVariable name -> 
           (* Heuristic: variables with certain names are likely map-derived *)
           String.contains name '_' && (String.length name > 3)
       | _ -> false)
  | _ -> false

(** Check if IR value is local stack memory *)
let is_local_stack_value ir_val =
  match detect_memory_region_type ir_val with
  | LocalStack -> true
  | _ -> false

(** Enhanced memory region detection using provided memory info *)
let detect_memory_region_enhanced ?(memory_info_map=None) ir_val =
  match memory_info_map with
  | Some info_map ->
      (* Use provided memory region information *)
      (match ir_val.value_desc with
       | IRVariable var_name ->
           (try
             let info = Hashtbl.find info_map var_name in
             info.region_type
           with
           | Not_found -> LocalStack)  (* Default for unknown variables *)
       | IRContextField (XdpCtx, ("data" | "data_end" | "data_meta")) -> PacketData
       | IRContextField (TcCtx, ("data" | "data_end")) -> PacketData
       | IRMapRef _ -> RegularMemory
       | IRLiteral _ -> RegularMemory
       | IRRegister _ -> RegularMemory
       | _ -> RegularMemory)
  | None ->
      (* Fallback to heuristic detection *)
      detect_memory_region_type ir_val

(** Get enhanced bounds information *)
let get_enhanced_bounds_info ?(memory_info_map=None) ir_val =
  match memory_info_map with
  | Some info_map ->
      (match ir_val.value_desc with
       | IRVariable var_name ->
           (try
             let info = Hashtbl.find info_map var_name in
             Some { verified = info.bounds_verified; size_hint = 
               match info.size_hint with Some s -> s | None -> 0 }
           with
           | Not_found -> None)
       | _ -> None)
  | None -> None

(** C code generation context *)
type c_context = {
  (* Generated C code lines *)
  mutable output_lines: string list;
  (* Current indentation level *)
  mutable indent_level: int;
  (* Variable counter for generating unique names *)
  mutable var_counter: int;
  (* Label counter for control flow *)
  mutable label_counter: int;
  (* Include statements needed *)
  mutable includes: string list;
  (* Map definitions that need to be emitted *)
  mutable map_definitions: ir_map_def list;
  (* Next label ID for generating unique callback function names *)
  mutable next_label_id: int;
  (* Pending callbacks to be emitted *)
  mutable pending_callbacks: string list;
  (* Current error variable for try/catch blocks *)
  mutable current_error_var: string option;
  (* Variable name to original type alias mapping *)
  mutable variable_type_aliases: (string * string) list;
  (* Pinned global variables for transparent access *)
  mutable pinned_globals: string list;
  (* Flag to indicate if we're generating code for a return context *)
  mutable in_return_context: bool;
  (* Optimization flags *)
  mutable enable_temp_var_optimization: bool;
  (* Register to meaningful name mapping for optimization *)
  mutable register_name_hints: (int, string) Hashtbl.t;
  (* Track which registers can be inlined *)
  mutable inlinable_registers: (int, string) Hashtbl.t;
  (* Track which registers have been declared to avoid redeclaration *)
  mutable declared_registers: (int, unit) Hashtbl.t;
  (* Current function's context type for proper field access generation *)
  mutable current_function_context_type: string option;
  (* Track dynptr-backed pointers for proper field assignment *)
  mutable dynptr_backed_pointers: (string, string) Hashtbl.t; (* pointer_var -> dynptr_var *)
}

let create_c_context () = {
  output_lines = [];
  indent_level = 0;
  var_counter = 0;
  label_counter = 0;
  includes = [];
  map_definitions = [];
  next_label_id = 0;
  pending_callbacks = [];
  current_error_var = None;
  variable_type_aliases = [];
  pinned_globals = [];
  in_return_context = false;
  enable_temp_var_optimization = true;
  register_name_hints = Hashtbl.create 32;
  inlinable_registers = Hashtbl.create 32;
  declared_registers = Hashtbl.create 32;
  current_function_context_type = None;
  dynptr_backed_pointers = Hashtbl.create 32;
}

(** Helper functions for code generation *)

(** Calculate the size of a type for dynptr field assignment operations.
    This function should only be called with basic value types that are valid
    for struct field assignments. The type checker ensures only compatible
    types reach this point. *)
let rec calculate_type_size ir_type =
  match ir_type with
  (* Basic integer types *)
  | IRU8 | IRI8 | IRChar -> 1
  | IRU16 | IRI16 -> 2
  | IRU32 | IRI32 | IRF32 -> 4
  | IRU64 | IRI64 | IRF64 -> 8
  | IRBool -> 1
  
  (* String and pointer types (valid in some field contexts) *)
  | IRStr _ -> 1  (* Size of individual char *)
  | IRPointer (_, _) -> 8  (* Pointer size *)
  
  (* Array elements - recurse to get element size *)
  | IRArray (elem_type, _, _) -> calculate_type_size elem_type
  
  (* These types should never appear in field assignments due to type checking *)
  | IRVoid -> 
      failwith "calculate_type_size: IRVoid should not appear in field assignments"
  | IRStruct (struct_name, _) -> 
      failwith ("calculate_type_size: IRStruct should not appear in field assignments, got: " ^ struct_name)
  | IREnum (enum_name, _) -> 
      failwith ("calculate_type_size: IREnum should not appear in field assignments, got: " ^ enum_name) 
  | IRResult (_, _) ->
      failwith "calculate_type_size: IRResult should not appear in field assignments"
  | IRAction _ ->
      failwith "calculate_type_size: IRAction should not appear in field assignments"
  | IRTypeAlias (alias_name, _) ->
      failwith ("calculate_type_size: IRTypeAlias should be resolved by type checker, got: " ^ alias_name)
  | IRStructOps (ops_name, _) ->
      failwith ("calculate_type_size: IRStructOps should not appear in field assignments, got: " ^ ops_name)
  | IRFunctionPointer (_, _) ->
      failwith "calculate_type_size: IRFunctionPointer should not appear in field assignments"
  | IRRingbuf (_, _) ->
      failwith "calculate_type_size: IRRingbuf should not appear in field assignments"
  | IRContext _ ->
      failwith "calculate_type_size: IRContext should not appear in field assignments"

let indent ctx = String.make (ctx.indent_level * 4) ' '

let emit_line ctx line =
  ctx.output_lines <- ctx.output_lines @ [(indent ctx ^ line)]

let emit_blank_line ctx =
  ctx.output_lines <- ctx.output_lines @ [""]

let increase_indent ctx = ctx.indent_level <- ctx.indent_level + 1

let decrease_indent ctx = ctx.indent_level <- ctx.indent_level - 1

let add_include ctx include_name =
  if not (List.mem include_name ctx.includes) then
    ctx.includes <- include_name :: ctx.includes

let fresh_var ctx prefix =
  ctx.var_counter <- ctx.var_counter + 1;
  sprintf "%s_%d" prefix ctx.var_counter

let fresh_label ctx prefix =
  ctx.label_counter <- ctx.label_counter + 1;
  sprintf "%s_%d" prefix ctx.label_counter

(** Optimization: Check if a register can be inlined *)
let can_inline_register ctx reg =
  ctx.enable_temp_var_optimization && Hashtbl.mem ctx.inlinable_registers reg

(** Optimization: Get inlined expression for a register *)
let get_inlined_expression ctx reg =
  try
    Some (Hashtbl.find ctx.inlinable_registers reg)
  with Not_found -> None

(** Optimization: Mark register as inlinable with expression *)
let mark_register_inlinable ctx reg expr =
  if ctx.enable_temp_var_optimization then
    Hashtbl.replace ctx.inlinable_registers reg expr

(** Optimization: Generate meaningful variable names *)
let get_meaningful_var_name ctx reg ir_type =
  if ctx.enable_temp_var_optimization then
    (* First check if there are explicit register hints - these take precedence *)
    match Hashtbl.find_opt ctx.register_name_hints reg with
    | Some hint -> sprintf "%s_%d" hint reg
    | None ->
        (* For return-like types, use consistent naming when no explicit hints exist *)
        let should_use_val_prefix = match ir_type with
          | IRU32 | IRI32 | IRU64 | IRI64 -> true
          | _ -> false
        in
        if should_use_val_prefix then
          sprintf "val_%d" reg
        else
          let type_hint = match ir_type with
            | IRBool -> "cond"
            | IRStr _ -> "str"
            | IRPointer _ -> "ptr"
            | IRAction _ -> "action"
            | _ -> "var"
          in
          sprintf "%s_%d" type_hint reg
  else
    sprintf "tmp_%d" reg

(** Add register name hint for better variable names *)
let add_register_hint ctx reg hint =
  if ctx.enable_temp_var_optimization then
    Hashtbl.replace ctx.register_name_hints reg hint

(** Type conversion from IR types to C types *)

let rec ebpf_type_from_ir_type = function
  | IRU8 -> "__u8"
  | IRU16 -> "__u16" 
  | IRU32 -> "__u32"
  | IRU64 -> "__u64"
  | IRI8 -> "__s8"
  | IRI16 -> "__s16"
  | IRI32 -> "__s32"
  | IRI64 -> "__s64"
  | IRF32 -> "__u32" (* Fixed point representation in kernel *)
  | IRF64 -> "__u64" (* Fixed point representation in kernel *)
  | IRVoid -> "void"
  | IRBool -> "__u8"
  | IRChar -> "char"
  | IRStr size -> sprintf "str_%d_t" size
  | IRPointer (inner_type, _) -> sprintf "%s*" (ebpf_type_from_ir_type inner_type)
  | IRArray (inner_type, size, _) -> sprintf "%s[%d]" (ebpf_type_from_ir_type inner_type) size
  | IRStruct (name, _) -> sprintf "struct %s" name
              | IREnum (name, _) -> sprintf "enum %s" name

  | IRResult (ok_type, _err_type) -> ebpf_type_from_ir_type ok_type (* simplified to ok type *)
  | IRTypeAlias (name, _) -> name (* Use the alias name directly *)
  | IRStructOps (name, _) -> sprintf "struct %s_ops" name (* struct_ops as function pointer structs *)
  | IRContext XdpCtx -> "struct xdp_md"
  | IRContext TcCtx -> "struct __sk_buff"
  | IRContext KprobeCtx -> "struct pt_regs"
  | IRContext TracepointCtx -> "void"
  | IRAction Xdp_actionType -> "int"
  | IRAction TcActionType -> "int"
  | IRAction GenericActionType -> "int"
    | IRFunctionPointer (param_types, return_type) ->
      let return_type_str = ebpf_type_from_ir_type return_type in
      let param_types_str = List.map ebpf_type_from_ir_type param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "%s (*)" return_type_str ^ sprintf "(%s)" params_str
  | IRRingbuf (_value_type, _size) ->
      (* Ring buffer objects are represented as void pointers in eBPF C *)
      "void*"  (* Function pointer type *)

(** Generate proper C declaration for eBPF, handling function pointers correctly *)
let generate_ebpf_c_declaration ir_type var_name =
  match ir_type with
  | IRFunctionPointer (param_types, return_type) ->
      let return_type_str = ebpf_type_from_ir_type return_type in
      let param_types_str = List.map ebpf_type_from_ir_type param_types in
      let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
      sprintf "%s (*%s)(%s)" return_type_str var_name params_str
  | IRStr size -> sprintf "str_%d_t %s" size var_name
  | IRArray (element_type, size, _) ->
      let element_type_str = ebpf_type_from_ir_type element_type in
      sprintf "%s %s[%d]" element_type_str var_name size
  | _ -> sprintf "%s %s" (ebpf_type_from_ir_type ir_type) var_name

(** Map type conversion *)

let ir_map_type_to_c_type = function
  | IRHash -> "BPF_MAP_TYPE_HASH"
  | IRMapArray -> "BPF_MAP_TYPE_ARRAY"
  | IRPercpu_hash -> "BPF_MAP_TYPE_PERCPU_HASH"
  | IRPercpu_array -> "BPF_MAP_TYPE_PERCPU_ARRAY"
  | IRLru_hash -> "BPF_MAP_TYPE_LRU_HASH"


(** Collect all string sizes used in the program *)

let rec collect_string_sizes_from_type = function
  | IRStr size -> [size]
  | IRPointer (inner_type, _) -> collect_string_sizes_from_type inner_type
  | IRArray (inner_type, _, _) -> collect_string_sizes_from_type inner_type

  | IRResult (ok_type, err_type) -> 
      (collect_string_sizes_from_type ok_type) @ (collect_string_sizes_from_type err_type)
  | _ -> []

let collect_string_sizes_from_value ir_val =
  collect_string_sizes_from_type ir_val.val_type

let collect_string_sizes_from_expr ir_expr =
  match ir_expr.expr_desc with
  | IRValue ir_val -> collect_string_sizes_from_value ir_val
  | IRBinOp (left, _, right) -> 
      (collect_string_sizes_from_value left) @ (collect_string_sizes_from_value right)
  | IRUnOp (_, ir_val) -> collect_string_sizes_from_value ir_val
  | IRCast (ir_val, target_type) -> 
      (collect_string_sizes_from_value ir_val) @ (collect_string_sizes_from_type target_type)
  | IRFieldAccess (obj_val, _) -> collect_string_sizes_from_value obj_val
  | IRStructLiteral (_, field_assignments) ->
      List.fold_left (fun acc (_, field_val) ->
        acc @ (collect_string_sizes_from_value field_val)
      ) [] field_assignments
  | IRMatch (matched_val, arms) ->
      (* Collect string sizes from matched expression and all arms *)
      (collect_string_sizes_from_value matched_val) @
      (List.fold_left (fun acc arm ->
        acc @ (collect_string_sizes_from_value arm.ir_arm_value)
      ) [] arms)

let rec collect_string_sizes_from_instr ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest_val, expr) -> 
      (collect_string_sizes_from_value dest_val) @ (collect_string_sizes_from_expr expr)
  | IRConstAssign (dest_val, expr) -> 
      (collect_string_sizes_from_value dest_val) @ (collect_string_sizes_from_expr expr)
  | IRDeclareVariable (dest_val, _typ, init_expr_opt) ->
      let dest_sizes = collect_string_sizes_from_value dest_val in
      let init_sizes = match init_expr_opt with
        | Some init_expr -> collect_string_sizes_from_expr init_expr
        | None -> []
      in
      dest_sizes @ init_sizes
  | IRCall (_, args, ret_opt) ->
      let args_sizes = List.fold_left (fun acc arg -> 
        acc @ (collect_string_sizes_from_value arg)) [] args in
      let ret_sizes = match ret_opt with
        | Some ret_val -> collect_string_sizes_from_value ret_val
        | None -> []
      in
      args_sizes @ ret_sizes
  | IRMapLoad (map_val, key_val, dest_val, _) ->
      (collect_string_sizes_from_value map_val) @ 
      (collect_string_sizes_from_value key_val) @ 
      (collect_string_sizes_from_value dest_val)
  | IRMapStore (map_val, key_val, value_val, _) ->
      (collect_string_sizes_from_value map_val) @ 
      (collect_string_sizes_from_value key_val) @ 
      (collect_string_sizes_from_value value_val)
  | IRMapDelete (map_val, key_val) ->
      (collect_string_sizes_from_value map_val) @ 
      (collect_string_sizes_from_value key_val)
  | IRConfigFieldUpdate (map_val, key_val, _field, value_val) ->
      (collect_string_sizes_from_value map_val) @ 
      (collect_string_sizes_from_value key_val) @ 
      (collect_string_sizes_from_value value_val)
  | IRStructFieldAssignment (obj_val, _field, value_val) ->
      (collect_string_sizes_from_value obj_val) @ 
      (collect_string_sizes_from_value value_val)
  | IRConfigAccess (_config_name, _field_name, result_val) ->
      collect_string_sizes_from_value result_val
  | IRContextAccess (dest_val, _context_type, _field_name) -> 
      collect_string_sizes_from_value dest_val
  | IRBoundsCheck (ir_val, _, _) -> 
      collect_string_sizes_from_value ir_val
  | IRJump _ -> []
  | IRCondJump (cond_val, _, _) -> 
      collect_string_sizes_from_value cond_val
  | IRIf (cond_val, then_instrs, else_instrs_opt) ->
      let cond_sizes = collect_string_sizes_from_value cond_val in
      let then_sizes = List.fold_left (fun acc instr -> 
        acc @ (collect_string_sizes_from_instr instr)) [] then_instrs in
      let else_sizes = match else_instrs_opt with
        | Some else_instrs -> List.fold_left (fun acc instr -> 
            acc @ (collect_string_sizes_from_instr instr)) [] else_instrs
        | None -> []
      in
      cond_sizes @ then_sizes @ else_sizes
  | IRIfElseChain (conditions_and_bodies, final_else) ->
      let cond_sizes = List.fold_left (fun acc (cond_val, then_instrs) ->
        let cond_sizes = collect_string_sizes_from_value cond_val in
        let then_sizes = List.fold_left (fun acc instr -> 
          acc @ (collect_string_sizes_from_instr instr)) [] then_instrs in
        acc @ cond_sizes @ then_sizes
      ) [] conditions_and_bodies in
      let else_sizes = match final_else with
        | Some else_instrs -> List.fold_left (fun acc instr -> 
            acc @ (collect_string_sizes_from_instr instr)) [] else_instrs
        | None -> []
      in
      cond_sizes @ else_sizes
  | IRMatchReturn (matched_val, arms) ->
      let matched_sizes = collect_string_sizes_from_value matched_val in
      let arms_sizes = List.fold_left (fun acc arm ->
        let pattern_sizes = match arm.match_pattern with
          | IRConstantPattern const_val -> collect_string_sizes_from_value const_val
          | IRDefaultPattern -> []
        in
        let action_sizes = match arm.return_action with
          | IRReturnValue ret_val -> collect_string_sizes_from_value ret_val
          | IRReturnCall (_, args) -> List.fold_left (fun acc arg -> 
              acc @ (collect_string_sizes_from_value arg)) [] args
          | IRReturnTailCall (_, args, _) -> List.fold_left (fun acc arg -> 
              acc @ (collect_string_sizes_from_value arg)) [] args
        in
        acc @ pattern_sizes @ action_sizes
      ) [] arms in
      matched_sizes @ arms_sizes
  | IRReturn ret_opt ->
      (match ret_opt with
       | Some ret_val -> collect_string_sizes_from_value ret_val
       | None -> [])
  | IRComment _ -> [] (* Comments don't contain values *)
  | IRBpfLoop (start_val, end_val, counter_val, ctx_val, body_instructions) ->
      (collect_string_sizes_from_value start_val) @ 
      (collect_string_sizes_from_value end_val) @ 
      (collect_string_sizes_from_value counter_val) @ 
      (collect_string_sizes_from_value ctx_val) @
      (List.fold_left (fun acc instr -> 
        acc @ (collect_string_sizes_from_instr instr)) [] body_instructions)
  | IRBreak -> []
  | IRContinue -> []
  | IRCondReturn (cond_val, ret_if_true, ret_if_false) ->
      let cond_sizes = collect_string_sizes_from_value cond_val in
      let true_sizes = match ret_if_true with
        | Some ret_val -> collect_string_sizes_from_value ret_val
        | None -> []
      in
      let false_sizes = match ret_if_false with
        | Some ret_val -> collect_string_sizes_from_value ret_val
        | None -> []
      in
      cond_sizes @ true_sizes @ false_sizes
  | IRTry (try_instructions, _catch_clauses) ->
      List.fold_left (fun acc instr -> 
        acc @ (collect_string_sizes_from_instr instr)) [] try_instructions
  | IRThrow _error_code ->
      [] (* Throw statements don't contain values to collect *)
  | IRDefer defer_instructions ->
      List.fold_left (fun acc instr -> 
        acc @ (collect_string_sizes_from_instr instr)) [] defer_instructions
  | IRTailCall (_, args, _) ->
      List.fold_left (fun acc arg ->
        acc @ (collect_string_sizes_from_value arg)) [] args
  | IRStructOpsRegister (instance_val, struct_ops_val) ->
      (collect_string_sizes_from_value instance_val) @ (collect_string_sizes_from_value struct_ops_val)
  | IRObjectNew (dest_val, _) ->
      collect_string_sizes_from_value dest_val
  | IRObjectNewWithFlag (dest_val, _, flag_val) ->
      (collect_string_sizes_from_value dest_val) @ (collect_string_sizes_from_value flag_val)
  | IRObjectDelete ptr_val ->
      collect_string_sizes_from_value ptr_val
  | IRRingbufOp (ringbuf_val, _) ->
      collect_string_sizes_from_value ringbuf_val

let collect_string_sizes_from_function ir_func =
  List.fold_left (fun acc block ->
    List.fold_left (fun acc instr ->
      acc @ (collect_string_sizes_from_instr instr)
    ) acc block.instructions
  ) [] ir_func.basic_blocks

let collect_string_sizes_from_multi_program ir_multi_prog =
  let program_sizes = List.fold_left (fun acc ir_prog ->
    let entry_sizes = collect_string_sizes_from_function ir_prog.entry_function in
    acc @ entry_sizes
  ) [] ir_multi_prog.programs in
  
  (* Also collect from kernel functions *)
  let kernel_func_sizes = List.fold_left (fun acc ir_func ->
    let func_sizes = collect_string_sizes_from_function ir_func in
    acc @ func_sizes
  ) [] ir_multi_prog.kernel_functions in
  
  (* NOTE: We used to collect string sizes from all userspace structs here, but this was incorrect.
     Only structs that are actually used by eBPF programs should be considered.
     The existing logic already collects string sizes from:
     1. eBPF programs and their functions  
     2. Kernel functions
     This is sufficient to capture all string sizes needed by eBPF programs.
     Userspace-only structs (like command-line argument structs) should not be included. *)
  
  program_sizes @ kernel_func_sizes

(** Collect enum definitions from IR types *)
let collect_enum_definitions ?symbol_table ir_multi_prog =
  let enum_map = Hashtbl.create 16 in
  
  let rec collect_from_type = function
    | IREnum (name, values) -> Hashtbl.replace enum_map name values
    | IRPointer (inner_type, _) -> collect_from_type inner_type
    | IRArray (inner_type, _, _) -> collect_from_type inner_type
  
    | IRResult (ok_type, err_type) -> 
        collect_from_type ok_type; collect_from_type err_type
    | _ -> ()
  in
  
  let collect_from_map_def map_def =
    collect_from_type map_def.map_key_type;
    collect_from_type map_def.map_value_type
  in
  
  let collect_from_value ir_val =
    collect_from_type ir_val.val_type;
    (* Also collect from enum constants *)
    (match ir_val.value_desc with
     | IREnumConstant (enum_name, constant_name, value) ->
         let current_values = try Hashtbl.find enum_map enum_name with Not_found -> [] in
         let updated_values = (constant_name, value) :: (List.filter (fun (name, _) -> name <> constant_name) current_values) in
         Hashtbl.replace enum_map enum_name updated_values
     | _ -> ())
  in
  
  let collect_from_expr ir_expr =
    match ir_expr.expr_desc with
    | IRValue ir_val -> collect_from_value ir_val
    | IRBinOp (left, _, right) -> 
        collect_from_value left; collect_from_value right
    | IRUnOp (_, ir_val) -> collect_from_value ir_val
    | IRCast (ir_val, target_type) -> 
        collect_from_value ir_val; collect_from_type target_type
    | IRFieldAccess (obj_val, _) -> collect_from_value obj_val
    | IRStructLiteral (_, field_assignments) ->
        List.iter (fun (_, field_val) -> collect_from_value field_val) field_assignments
    | IRMatch (matched_val, arms) ->
        (* Collect from matched expression and all arms *)
        collect_from_value matched_val;
        List.iter (fun arm -> collect_from_value arm.ir_arm_value) arms
  in
  
  let rec collect_from_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> 
        collect_from_value dest_val; collect_from_expr expr
    | IRDeclareVariable (dest_val, _typ, init_expr_opt) ->
        collect_from_value dest_val;
        (match init_expr_opt with
         | Some init_expr -> collect_from_expr init_expr
         | None -> ())
    | IRCall (_, args, ret_opt) ->
        List.iter collect_from_value args;
        (match ret_opt with Some ret_val -> collect_from_value ret_val | None -> ())
    | IRMapLoad (map_val, key_val, dest_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value dest_val
    | IRMapStore (map_val, key_val, value_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value value_val
    | IRMapDelete (map_val, key_val) ->
        collect_from_value map_val; collect_from_value key_val
    | IRReturn (Some ret_val) -> collect_from_value ret_val
    | IRIf (cond_val, then_instrs, else_instrs_opt) ->
        collect_from_value cond_val;
        List.iter collect_from_instr then_instrs;
        (match else_instrs_opt with Some instrs -> List.iter collect_from_instr instrs | None -> ())
    | _ -> ()
  in
  
  let collect_from_function ir_func =
    List.iter (fun block ->
      List.iter collect_from_instr block.instructions
    ) ir_func.basic_blocks
  in
  
  (* Collect from global maps *)
  List.iter collect_from_map_def ir_multi_prog.global_maps;
  
  (* Collect from all programs *)
  List.iter (fun ir_prog ->
    collect_from_function ir_prog.entry_function;
  ) ir_multi_prog.programs;
  
  (* Also collect enum definitions from symbol table *)
  (match symbol_table with
  | Some st ->
      let global_symbols = Symbol_table.get_global_symbols st in
      List.iter (fun symbol ->
        match symbol.Symbol_table.kind with
        | Symbol_table.TypeDef (Ast.EnumDef (enum_name, enum_values)) ->
            let processed_values = List.map (fun (const_name, opt_value) ->
              (const_name, Option.value ~default:0 opt_value)
            ) enum_values in
            Hashtbl.replace enum_map enum_name processed_values
        | _ -> ()
      ) global_symbols
  | None -> ()); (* No symbol table provided *)
  
  enum_map

(** Generate enum definition *)
let generate_enum_definition ctx enum_name enum_values =
  emit_line ctx (sprintf "enum %s {" enum_name);
  increase_indent ctx;
  let value_count = List.length enum_values in
  List.iteri (fun i (const_name, value) ->
    let line = sprintf "%s = %d%s" const_name value (if i = value_count - 1 then "" else ",") in
    emit_line ctx line
  ) enum_values;
  decrease_indent ctx;
  emit_line ctx "};";
  emit_blank_line ctx

(** Generate enum definitions *)
let generate_enum_definitions ?symbol_table ctx ir_multi_prog =
  let enum_map = collect_enum_definitions ?symbol_table ir_multi_prog in
  if Hashtbl.length enum_map > 0 then (
    (* Filter out kernel-defined enums that are provided by kernel headers *)
    let user_defined_enums = Hashtbl.fold (fun enum_name enum_values acc ->
      if not (Kernel_types.is_well_known_ebpf_type enum_name) then
        (enum_name, enum_values) :: acc
      else
        acc
    ) enum_map [] in
    
    if user_defined_enums <> [] then (
      emit_line ctx "/* User-defined enum definitions */";
      List.iter (fun (enum_name, enum_values) ->
        generate_enum_definition ctx enum_name enum_values
      ) user_defined_enums;
      emit_blank_line ctx
    );
    
    (* Log filtered types for debugging *)
    let filtered_count = (Hashtbl.length enum_map) - (List.length user_defined_enums) in
    if filtered_count > 0 then
      printf "Filtered out %d kernel-defined enum types from C generation\n" filtered_count
  )

(** Generate string type definitions *)

let generate_string_typedefs ctx ir_multi_prog =
  let all_sizes = collect_string_sizes_from_multi_program ir_multi_prog in
  let unique_sizes = List.sort_uniq compare all_sizes in
  if unique_sizes <> [] then (
    emit_line ctx "/* String type definitions */";
    List.iter (fun size ->
      emit_line ctx (sprintf "typedef struct { char data[%d]; __u16 len; } str_%d_t;" (size + 1) size)
    ) unique_sizes;
    emit_blank_line ctx
  )

(** Collect struct definitions from IR multi-program *)
let collect_struct_definitions_from_multi_program ir_multi_prog =
  let struct_defs = ref [] in
  
  (* No more hardcoded cheating - structs should have their fields properly resolved in IR *)
  
  let rec collect_from_type ir_type =
    match ir_type with
          | IRStruct (name, struct_fields) ->
        if not (List.mem_assoc name !struct_defs) then (
          (* Only collect structs that actually have fields - ignore empty structs that are likely type aliases *)
          if struct_fields <> [] then
            struct_defs := (name, struct_fields) :: !struct_defs
          (* Remove warning - empty structs are expected for type aliases *)
        )
    | IRPointer (inner_type, _) -> 
        (* Recursively collect from the pointed-to type *)
        collect_from_type inner_type
    | _ -> ()
  in
  
  let rec collect_from_value ir_val =
    collect_from_type ir_val.val_type
  and collect_from_expr ir_expr =
    collect_from_type ir_expr.expr_type;
    match ir_expr.expr_desc with
    | IRStructLiteral (_struct_name, field_assignments) ->
        (* Also collect struct type from the literal itself *)
        List.iter (fun (_, field_val) -> collect_from_value field_val) field_assignments
    | IRValue ir_val -> collect_from_value ir_val
    | IRBinOp (left, _, right) -> collect_from_value left; collect_from_value right
    | IRUnOp (_, ir_val) -> collect_from_value ir_val
    | IRCast (ir_val, _) -> collect_from_value ir_val
    | IRFieldAccess (obj_val, _) -> collect_from_value obj_val
    | IRMatch (matched_val, arms) ->
        (* Collect from matched expression and all arms *)
        collect_from_value matched_val;
        List.iter (fun arm -> collect_from_value arm.ir_arm_value) arms
  and collect_from_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> 
        collect_from_value dest_val; collect_from_expr expr
    | IRDeclareVariable (dest_val, _typ, init_expr_opt) ->
        collect_from_value dest_val;
        (match init_expr_opt with
         | Some init_expr -> collect_from_expr init_expr
         | None -> ())
    | IRCall (_, args, ret_opt) ->
        List.iter collect_from_value args;
        (match ret_opt with Some ret_val -> collect_from_value ret_val | None -> ())
    | IRMapLoad (map_val, key_val, dest_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value dest_val
    | IRMapStore (map_val, key_val, value_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value value_val
    | IRMapDelete (map_val, key_val) ->
        collect_from_value map_val; collect_from_value key_val
    | IRReturn (Some ret_val) -> collect_from_value ret_val
    | IRIf (cond_val, then_instrs, else_instrs_opt) ->
        collect_from_value cond_val;
                 List.iter collect_from_instr then_instrs;
        (match else_instrs_opt with Some instrs -> List.iter collect_from_instr instrs | None -> ())
    | IRIfElseChain (conditions_and_bodies, final_else) ->
        List.iter (fun (cond_val, then_instrs) ->
          collect_from_value cond_val;
          List.iter collect_from_instr then_instrs
        ) conditions_and_bodies;
        (match final_else with Some instrs -> List.iter collect_from_instr instrs | None -> ())
    | _ -> ()
  in
  
  let collect_from_map_def map_def =
    collect_from_type map_def.map_key_type;
    collect_from_type map_def.map_value_type
  in
  
  let collect_from_function ir_func =
    List.iter (fun block ->
      List.iter collect_from_instr block.instructions
    ) ir_func.basic_blocks;
    (* Also collect from function parameters and return type *)
    List.iter (fun (_, param_type) -> collect_from_type param_type) ir_func.parameters;
    (match ir_func.return_type with Some ret_type -> collect_from_type ret_type | None -> ())
  in
  
  (* Collect from global maps *)
  List.iter collect_from_map_def ir_multi_prog.global_maps;
  
  (* Collect from all programs *)
  List.iter (fun ir_prog ->
    collect_from_function ir_prog.entry_function;
  ) ir_multi_prog.programs;
  
  (* Also collect from kernel functions *)
  List.iter collect_from_function ir_multi_prog.kernel_functions;
  
  (* Collect struct names referenced by struct_ops attributes *)
  let collect_struct_ops_referenced_structs () =
    let struct_ops_structs = ref [] in
    
    (* Check struct_ops declarations for referenced kernel structs *)
    List.iter (fun struct_ops_decl ->
      if not (List.mem_assoc struct_ops_decl.ir_kernel_struct_name !struct_defs) then
        struct_ops_structs := struct_ops_decl.ir_kernel_struct_name :: !struct_ops_structs
    ) ir_multi_prog.struct_ops_declarations;
    
    (* Check struct_ops instances for referenced kernel structs *)
    List.iter (fun struct_ops_inst ->
      if not (List.mem_assoc struct_ops_inst.ir_instance_type !struct_defs) then
        struct_ops_structs := struct_ops_inst.ir_instance_type :: !struct_ops_structs
    ) ir_multi_prog.struct_ops_instances;
    
    !struct_ops_structs
  in
  
  (* Collect userspace structs that are referenced by struct_ops *)
  let struct_ops_referenced_structs = collect_struct_ops_referenced_structs () in
  (match ir_multi_prog.userspace_program with
   | Some userspace_prog ->
       List.iter (fun struct_def ->
         let struct_name = struct_def.struct_name in
         (* Include struct if it's referenced by struct_ops declarations/instances *)
         let is_struct_ops_referenced = List.mem struct_name struct_ops_referenced_structs in
         if is_struct_ops_referenced then (
           let struct_fields = struct_def.struct_fields in
           if not (List.mem_assoc struct_name !struct_defs) then
             struct_defs := (struct_name, struct_fields) :: !struct_defs
         )
       ) userspace_prog.userspace_structs
   | None -> ());
  
  List.rev !struct_defs

(** Generate struct definitions *)
let generate_struct_definitions ctx struct_defs =
  (* Filter out kernel-defined structs using centralized kernel type knowledge *)
  let user_defined_structs = List.filter (fun (struct_name, fields) ->
    (* Check if this struct name is a well-known kernel type *)
    let is_kernel_type = Kernel_types.is_well_known_ebpf_type struct_name in
    
    (* Check if this struct has kernel-defined field types *)
    let has_kernel_field = List.exists (fun (_field_name, field_type) ->
      match field_type with
      | IRStruct (name, _) -> Kernel_types.is_well_known_ebpf_type name
      | IREnum (name, _) -> Kernel_types.is_well_known_ebpf_type name
      | _ -> false
    ) fields in
    
    (* Filter out kernel types and structs with kernel-defined fields *)
    not is_kernel_type && not has_kernel_field
  ) struct_defs in
  
  if user_defined_structs <> [] then (
    emit_line ctx "/* User-defined struct definitions */";
    List.iter (fun (struct_name, fields) ->
      emit_line ctx (sprintf "struct %s {" struct_name);
      increase_indent ctx;
      List.iter (fun (field_name, field_type) ->
        (* Handle array fields with correct C syntax, preserving type aliases *)
        let field_declaration = match field_type with
        | IRArray (inner_type, size, _) ->
            let inner_c_type = ebpf_type_from_ir_type inner_type in
            sprintf "%s %s[%d];" inner_c_type field_name size
        | IRTypeAlias (alias_name, _) ->
            (* Preserve type alias names in struct fields to match original source code *)
            sprintf "%s %s;" alias_name field_name
        | IRFunctionPointer (param_types, return_type) ->
            (* Generate correct function pointer syntax *)
            let return_type_str = ebpf_type_from_ir_type return_type in
            let param_types_str = List.map ebpf_type_from_ir_type param_types in
            let params_str = if param_types_str = [] then "void" else String.concat ", " param_types_str in
            sprintf "%s (*%s)(%s);" return_type_str field_name params_str
        | _ ->
            let c_type = ebpf_type_from_ir_type field_type in
            sprintf "%s %s;" c_type field_name
        in
        emit_line ctx field_declaration
      ) fields;
      decrease_indent ctx;
      emit_line ctx "};"
    ) user_defined_structs;
    emit_blank_line ctx
  );
  
  (* Log filtered types for debugging *)
  let filtered_count = (List.length struct_defs) - (List.length user_defined_structs) in
  if filtered_count > 0 then
    printf "Filtered out %d kernel-defined struct types from C generation\n" filtered_count

(** Collect type aliases from IR multi-program *)
let collect_type_aliases_from_multi_program ir_multi_prog =
  let type_aliases = ref [] in
  
  let collect_from_type ir_type =
    match ir_type with
    | IRTypeAlias (name, underlying_type) ->
        if not (List.mem_assoc name !type_aliases) then
          type_aliases := (name, underlying_type) :: !type_aliases
    | _ -> ()
  in
  
  let rec collect_from_value ir_val =
    collect_from_type ir_val.val_type
  and collect_from_expr ir_expr =
    collect_from_type ir_expr.expr_type
  and collect_from_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> 
        collect_from_value dest_val; collect_from_expr expr
    | IRCall (_, args, ret_opt) ->
        List.iter collect_from_value args;
        (match ret_opt with Some ret_val -> collect_from_value ret_val | None -> ())
    | IRMapLoad (map_val, key_val, dest_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value dest_val
    | IRMapStore (map_val, key_val, value_val, _) ->
        collect_from_value map_val; collect_from_value key_val; collect_from_value value_val
    | IRMapDelete (map_val, key_val) ->
        collect_from_value map_val; collect_from_value key_val
    | IRReturn (Some ret_val) -> collect_from_value ret_val
    | IRIf (cond_val, then_instrs, else_instrs_opt) ->
        collect_from_value cond_val;
        List.iter collect_from_instr then_instrs;
        (match else_instrs_opt with Some instrs -> List.iter collect_from_instr instrs | None -> ())
    | _ -> ()
  in
  
  let collect_from_map_def map_def =
    collect_from_type map_def.map_key_type;
    collect_from_type map_def.map_value_type
  in
  
  let collect_from_function ir_func =
    List.iter (fun block ->
      List.iter collect_from_instr block.instructions
    ) ir_func.basic_blocks;
    (* Also collect from function parameters and return type *)
    List.iter (fun (_, param_type) -> collect_from_type param_type) ir_func.parameters;
    (match ir_func.return_type with Some ret_type -> collect_from_type ret_type | None -> ())
  in
  
  (* Collect from global maps *)
  List.iter collect_from_map_def ir_multi_prog.global_maps;
  
  (* Collect from all programs *)
  List.iter (fun ir_prog ->
    collect_from_function ir_prog.entry_function;
  ) ir_multi_prog.programs;
  
  List.rev !type_aliases

(** Generate type alias definitions *)
let generate_type_alias_definitions ctx type_aliases =
  if type_aliases <> [] then (
    emit_line ctx "/* Type alias definitions */";
    List.iter (fun (alias_name, underlying_type) ->
      let c_type = ebpf_type_from_ir_type underlying_type in
      emit_line ctx (sprintf "typedef %s %s;" c_type alias_name)
    ) type_aliases;
    emit_blank_line ctx
  )

(** Generate type alias definitions from AST types *)
let generate_ast_type_alias_definitions ctx type_aliases =
  if type_aliases <> [] then (
    emit_line ctx "/* Type alias definitions */";
    List.iter (fun (alias_name, underlying_type) ->
      match underlying_type with
        | Ast.Array (element_type, size) ->
            let element_c_type = match element_type with
              | Ast.U8 -> "__u8"
              | Ast.U16 -> "__u16"
              | Ast.U32 -> "__u32"
              | Ast.U64 -> "__u64"
              | Ast.I8 -> "__s8"
              | Ast.I16 -> "__s16"
              | Ast.I32 -> "__s32"
              | Ast.I64 -> "__s64"
              | _ -> "__u8"
            in
            (* Array typedef syntax: typedef element_type alias_name[size]; *)
            emit_line ctx (sprintf "typedef %s %s[%d];" element_c_type alias_name size)
        | _ ->
            let c_type = match underlying_type with
              | Ast.U8 -> "__u8"
              | Ast.U16 -> "__u16"
              | Ast.U32 -> "__u32"
              | Ast.U64 -> "__u64"
              | Ast.I8 -> "__s8"
              | Ast.I16 -> "__s16"
              | Ast.I32 -> "__s32"
              | Ast.I64 -> "__s64"
              | Ast.Bool -> "__u8"  (* eBPF uses __u8 for bool *)
              | Ast.Char -> "char"
              | _ -> "__u32" (* fallback *)
            in
            emit_line ctx (sprintf "typedef %s %s;" c_type alias_name)
    ) type_aliases;
    emit_blank_line ctx
  )

(** Generate config struct definition and map *)
let generate_config_map_definition ctx config_decl =
  let config_name = config_decl.config_name in
  let struct_name = sprintf "%s_config" config_name in
  
  (* Generate C struct for config *)
  emit_line ctx (sprintf "struct %s {" struct_name);
  increase_indent ctx;
  
  List.iter (fun field ->
    let field_declaration = match field.field_type with
      | IRU8 -> sprintf "__u8 %s;" field.field_name
      | IRU16 -> sprintf "__u16 %s;" field.field_name
      | IRU32 -> sprintf "__u32 %s;" field.field_name
      | IRU64 -> sprintf "__u64 %s;" field.field_name
      | IRI8 -> sprintf "__s8 %s;" field.field_name
      | IRBool -> sprintf "__u8 %s;" field.field_name  (* bool -> u8 for BPF compatibility *)
      | IRChar -> sprintf "char %s;" field.field_name
      | IRArray (IRU16, size, _) -> sprintf "__u16 %s[%d];" field.field_name size
      | IRArray (IRU32, size, _) -> sprintf "__u32 %s[%d];" field.field_name size
      | IRArray (IRU64, size, _) -> sprintf "__u64 %s[%d];" field.field_name size
      | _ -> sprintf "__u32 %s;" field.field_name  (* fallback *)
    in
    emit_line ctx field_declaration
  ) config_decl.config_fields;
  
  decrease_indent ctx;
  emit_line ctx "};";
  emit_blank_line ctx;
  
  (* Generate array map for config (single entry at index 0) *)
  let map_name = sprintf "%s_config_map" config_name in
  emit_line ctx "struct {";
  increase_indent ctx;
  emit_line ctx "__uint(type, BPF_MAP_TYPE_ARRAY);";
  emit_line ctx "__uint(max_entries, 1);";
  emit_line ctx "__uint(key_size, sizeof(__u32));";
  emit_line ctx (sprintf "__uint(value_size, sizeof(struct %s));" struct_name);
  decrease_indent ctx;
  emit_line ctx (sprintf "} %s SEC(\".maps\");" map_name);
  emit_blank_line ctx;
  
  (* Generate helper function to access config *)
  emit_line ctx (sprintf "static inline struct %s* get_%s_config(void) {" struct_name config_name);
  increase_indent ctx;
  emit_line ctx "__u32 key = 0;";
  emit_line ctx (sprintf "struct %s *config = bpf_map_lookup_elem(&%s, &key);" struct_name map_name);
  emit_line ctx "if (!config) {";
  increase_indent ctx;
  emit_line ctx "/* Config not initialized - this should not happen in normal operation */";
  emit_line ctx "return NULL;";
  decrease_indent ctx;
  emit_line ctx "}";
  emit_line ctx "return config;";
  decrease_indent ctx;
  emit_line ctx "}";
  emit_blank_line ctx

(** Generate declarations in original AST order to preserve source order *)
let generate_declarations_in_source_order ctx _ir_multi_program type_aliases =
  (* We need to generate declarations in the order they appeared in the original source.
     Since we don't have direct access to the AST here, we need to reconstruct the order.
     For now, we'll use a simple heuristic: type aliases first, then structs. *)
  
  (* Generate type alias definitions from AST first *)
  generate_ast_type_alias_definitions ctx type_aliases;
  
  (* Config maps are now generated from the main multi-program generation function to avoid duplication *)
  (* Remove this generation here as it's handled in generate_c_multi_program *)

  (* With attributed functions, all maps are global - no program-scoped maps *)
  
  (* Generate entry function - this will collect callbacks *)
  (* generate_c_function ctx ir_multi_program.entry_function; *)
  
  (* Now emit any pending callbacks before other functions *)
  if ctx.pending_callbacks <> [] then (
    (* Insert callbacks at the beginning of the output, after includes and maps *)
    let current_output = ctx.output_lines in
    ctx.output_lines <- [];
    List.iter (emit_line ctx) ctx.pending_callbacks;
    ctx.pending_callbacks <- [];
    emit_blank_line ctx;
    (* Prepend current output *)
    ctx.output_lines <- current_output @ ctx.output_lines;
  );
  
  (* With attributed functions, each program has only the entry function - no nested functions *)
  
  (* Function has side effects on ctx, no return value needed *)
  ()

(** Generate standard eBPF includes *)

let generate_includes ctx ?(program_types=[]) () =
  (* Use vmlinux.h which contains all kernel types from BTF *)
  let vmlinux_includes = [
    "#include \"vmlinux.h\"";
  ] in
  
  (* Only include essential eBPF helpers, vmlinux.h provides all kernel types *)
  let standard_includes = [
    "#include <bpf/bpf_helpers.h>";
  ] in
  
  (* Get context-specific includes for macros not in vmlinux.h *)
  let context_includes = List.fold_left (fun acc prog_type ->
    let context_type = match prog_type with
      | Ast.Tc -> Some "tc"
      | _ -> None
    in
    match context_type with
    | Some ctx_type -> 
        let includes = Kernelscript_context.Context_codegen.get_context_includes ctx_type in
        acc @ includes
    | None -> acc
  ) [] program_types in
  
  (* Remove duplicates between all include sets *)
  let all_base_includes = vmlinux_includes @ standard_includes in
  let unique_context_includes = List.filter (fun inc -> 
    not (List.mem inc all_base_includes)) context_includes in
  
  (* For kprobe programs, still use vmlinux.h but include context-specific macro headers *)
  let has_kprobe = List.exists (function Ast.Kprobe -> true | _ -> false) program_types in
  if has_kprobe then (
    (* Use vmlinux.h and context-specific headers for macros *)
    let vmlinux_and_helpers = [
      "#include \"vmlinux.h\"";
      "#include <bpf/bpf_helpers.h>";
    ] in
    
    List.iter (emit_line ctx) vmlinux_and_helpers;
    List.iter (emit_line ctx) unique_context_includes;
    emit_blank_line ctx
  ) else (
    (* For non-kprobe programs, use vmlinux.h and standard processing *)
    let all_includes = vmlinux_includes @ standard_includes @ unique_context_includes in
    List.iter (emit_line ctx) all_includes;
    emit_blank_line ctx;

    (* Use proper kernel implementation: extern declarations and macros *)
    emit_line ctx "extern void *bpf_obj_new_impl(__u64 local_type_id__k, void *meta__ign) __ksym;";
    emit_line ctx "extern void bpf_obj_drop_impl(void *p__alloc, void *meta__ign) __ksym;";
    emit_blank_line ctx;
    
    (* Use exact kernel implementation for proper typeof handling *)
    emit_line ctx "#define ___concat(a, b) a ## b";
    emit_line ctx "#ifdef __clang__";
    emit_line ctx "#define ___bpf_typeof(type) ((typeof(type) *) 0)";
    emit_line ctx "#else";
    emit_line ctx "#define ___bpf_typeof1(type, NR) ({                                         \\";
    emit_line ctx "        extern typeof(type) *___concat(bpf_type_tmp_, NR);                  \\";
    emit_line ctx "        ___concat(bpf_type_tmp_, NR);                                       \\";
    emit_line ctx "})";
    emit_line ctx "#define ___bpf_typeof(type) ___bpf_typeof1(type, __COUNTER__)";
    emit_line ctx "#endif";
    emit_blank_line ctx;
    
    (* Add BPF_TYPE_ID_LOCAL constant *)
    emit_line ctx "#ifndef BPF_TYPE_ID_LOCAL";
    emit_line ctx "#define BPF_TYPE_ID_LOCAL 1";
    emit_line ctx "#endif";
    emit_blank_line ctx;
    
    emit_line ctx "#define bpf_core_type_id_kernel(type) __builtin_btf_type_id(*(type*)0, 0)";
    emit_line ctx "#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_kernel(type), NULL))";
    emit_line ctx "#define bpf_obj_drop(ptr) bpf_obj_drop_impl(ptr, NULL)";
    emit_blank_line ctx
  )

(** Generate map definitions *)

let generate_map_definition ctx map_def =
  let map_type_str = ir_map_type_to_c_type map_def.map_type in
  let key_type_str = ebpf_type_from_ir_type map_def.map_key_type in
  let value_type_str = ebpf_type_from_ir_type map_def.map_value_type in
  
  emit_line ctx "struct {";
  increase_indent ctx;
  emit_line ctx (sprintf "__uint(type, %s);" map_type_str);
  emit_line ctx (sprintf "__uint(max_entries, %d);" map_def.max_entries);
  emit_line ctx (sprintf "__type(key, %s);" key_type_str);
  emit_line ctx (sprintf "__type(value, %s);" value_type_str);
  
  (* Add map flags if specified *)
  if map_def.flags <> 0 then
    emit_line ctx (sprintf "__uint(map_flags, 0x%x);" map_def.flags);
  
  (* Note: We do NOT emit __uint(pinning, LIBBPF_PIN_BY_NAME) here when pin_path is specified.
     Userspace code will handle pinning to the exact path specified in pin_path. *)
  
  decrease_indent ctx;
  emit_line ctx (sprintf "} %s SEC(\".maps\");" map_def.map_name);
  emit_blank_line ctx

(** Generate global variable definitions for eBPF *)
let generate_global_variables ctx global_variables =
  if global_variables <> [] then (
    emit_line ctx "/* Global variables */";
    
    (* Generate __hidden attribute definition for local variables *)
    let has_local_vars = List.exists (fun gv -> gv.is_local) global_variables in
    if has_local_vars then (
      emit_line ctx "#define __hidden __attribute__((visibility(\"hidden\")))";
      emit_blank_line ctx
    );
    
    (* Separate pinned and non-pinned variables *)
    let pinned_vars = List.filter (fun gv -> gv.is_pinned) global_variables in
    let regular_vars = List.filter (fun gv -> not gv.is_pinned) global_variables in
    
    (* Generate pinned globals struct if there are any pinned variables *)
    if pinned_vars <> [] then (
      (* Track pinned globals in the context *)
      ctx.pinned_globals <- List.map (fun gv -> gv.global_var_name) pinned_vars;
      
      emit_line ctx "/* Pinned global variables struct */";
      emit_line ctx "struct __pinned_globals {";
      List.iter (fun global_var ->
        let c_type = ebpf_type_from_ir_type global_var.global_var_type in
        emit_line ctx (sprintf "    %s %s;" c_type global_var.global_var_name)
      ) pinned_vars;
      emit_line ctx "};";
      emit_blank_line ctx;
      
      (* Generate the pinned globals map *)
      emit_line ctx "/* Pinned globals map - single entry array */";
      emit_line ctx "struct {";
      emit_line ctx "    __uint(type, BPF_MAP_TYPE_ARRAY);";
      emit_line ctx "    __type(key, __u32);";
      emit_line ctx "    __type(value, struct __pinned_globals);";
      emit_line ctx "    __uint(max_entries, 1);";
      emit_line ctx "    __uint(map_flags, BPF_F_NO_PREALLOC);";
      emit_line ctx "} __pinned_globals SEC(\".maps\");";
      emit_blank_line ctx;
      
      (* Generate access helpers for pinned variables *)
      emit_line ctx "/* Pinned globals access helpers */";
      emit_line ctx "static __always_inline struct __pinned_globals *get_pinned_globals(void) {";
      emit_line ctx "    __u32 key = 0;";
      emit_line ctx "    return bpf_map_lookup_elem(&__pinned_globals, &key);";
      emit_line ctx "}";
      emit_blank_line ctx;
      
      emit_line ctx "static __always_inline void update_pinned_globals(struct __pinned_globals *globals) {";
      emit_line ctx "    __u32 key = 0;";
      emit_line ctx "    bpf_map_update_elem(&__pinned_globals, &key, globals, BPF_ANY);";
      emit_line ctx "}";
      emit_blank_line ctx
    );
    
    (* Separate ring buffer variables from regular variables *)
    let (ringbuf_vars, non_ringbuf_vars) = List.partition (fun global_var ->
      match global_var.global_var_type with
      | IRRingbuf (_, _) -> true
      | _ -> false
    ) regular_vars in
    
    (* Generate ring buffer maps *)
    List.iter (fun global_var ->
      match global_var.global_var_type with
      | IRRingbuf (_, size) ->
          emit_line ctx (sprintf "/* Ring buffer for %s */" global_var.global_var_name);
          emit_line ctx "struct {";
          emit_line ctx "    __uint(type, BPF_MAP_TYPE_RINGBUF);";
          emit_line ctx (sprintf "    __uint(max_entries, %d);" size);
          emit_line ctx (sprintf "} %s SEC(\".maps\");" global_var.global_var_name);
          emit_blank_line ctx
      | _ -> () (* Should not happen due to filtering above *)
    ) ringbuf_vars;
    
    (* Generate regular (non-pinned, non-ringbuf) global variables *)
    List.iter (fun global_var ->
      let c_type = ebpf_type_from_ir_type global_var.global_var_type in
      let var_name = global_var.global_var_name in
      let local_attr = if global_var.is_local then "__hidden __attribute__((aligned(8))) " else "" in
      
      (* Generate variable declaration with initialization if present *)
      (match global_var.global_var_init with
       | Some init_val ->
           let init_str = match init_val.value_desc with
             | IRLiteral (Ast.IntLit (i, original_opt)) -> 
                 (* Use original format if available, otherwise use decimal *)
                 (match original_opt with
                  | Some orig when String.contains orig 'x' || String.contains orig 'X' -> orig
                  | Some orig when String.contains orig 'b' || String.contains orig 'B' -> orig
                  | _ -> string_of_int i)
             | IRLiteral (Ast.BoolLit b) -> if b then "1" else "0"
             | IRLiteral (Ast.StringLit s) -> sprintf "\"%s\"" s
             | IRLiteral (Ast.CharLit c) -> sprintf "'%c'" c
             | IRLiteral (Ast.NullLit) -> "NULL"
             | _ -> "0" (* fallback *)
           in
           if global_var.is_local then
             emit_line ctx (sprintf "%s%s %s = %s;" local_attr c_type var_name init_str)
           else
             emit_line ctx (sprintf "%s %s = %s;" c_type var_name init_str)
       | None ->
           if global_var.is_local then
             emit_line ctx (sprintf "%s%s %s;" local_attr c_type var_name)
           else
             emit_line ctx (sprintf "%s %s;" c_type var_name))
    ) non_ringbuf_vars;
    emit_blank_line ctx
  )

(** Generate struct_ops definitions and instances for eBPF *)
let generate_struct_ops ctx ir_multi_program =
  (* Generate struct_ops declarations *)
  List.iter (fun struct_ops_decl ->
    emit_line ctx (sprintf "/* eBPF struct_ops declaration for %s */" struct_ops_decl.ir_kernel_struct_name);
    (* In eBPF, struct_ops are typically implemented as BPF_MAP_TYPE_STRUCT_OPS maps *)
    emit_line ctx (sprintf "/* struct %s_ops implementation would be auto-generated by libbpf */" struct_ops_decl.ir_struct_ops_name);
    emit_blank_line ctx
  ) ir_multi_program.struct_ops_declarations;

    (* Generate struct_ops instances *)
  List.iter (fun struct_ops_inst ->
    emit_line ctx (sprintf "/* eBPF struct_ops instance %s */" struct_ops_inst.ir_instance_name);
    
    (* Generate simple struct_ops instance with SEC(".struct_ops") *)
    let struct_ops_type = struct_ops_inst.ir_instance_type in
    emit_line ctx (sprintf "SEC(\".struct_ops\")");
    emit_line ctx (sprintf "struct %s %s = {" struct_ops_type struct_ops_inst.ir_instance_name);
    increase_indent ctx;
    
    (* Generate field assignments from the impl block *)
    List.iter (fun (field_name, field_value) ->
      match field_value.value_desc with
      | IRFunctionRef func_name ->
          (* Function reference - use void pointer cast *)
          emit_line ctx (sprintf ".%s = (void *)%s," field_name func_name)
      | IRLiteral (StringLit s) ->
          (* String literal - use direct assignment *)
          emit_line ctx (sprintf ".%s = \"%s\"," field_name s)
      | IRLiteral (NullLit) ->
          (* Null literal *)
          emit_line ctx (sprintf ".%s = NULL," field_name)
      | IRVariable name ->
          (* Variable reference *)
          emit_line ctx (sprintf ".%s = %s," field_name name)
      | _ ->
          (* Other values - use simple fallback *)
          emit_line ctx (sprintf ".%s = 0," field_name)
    ) struct_ops_inst.ir_instance_fields;
    
    decrease_indent ctx;
    emit_line ctx "};";
    emit_blank_line ctx
  ) ir_multi_program.struct_ops_instances

(** Generate C expression from IR value *)

let rec generate_c_value ?(auto_deref_map_access=false) ctx ir_val =
  let base_result = match ir_val.value_desc with
  | IRLiteral (IntLit (i, original_opt)) -> 
      (* Use original format if available, otherwise use decimal *)
      (match original_opt with
       | Some orig when String.contains orig 'x' || String.contains orig 'X' -> orig
       | Some orig when String.contains orig 'b' || String.contains orig 'B' -> orig
       | _ -> string_of_int i)
  | IRLiteral (BoolLit b) -> if b then "1" else "0"
  | IRLiteral (CharLit c) -> sprintf "'%c'" c
  | IRLiteral (NullLit) -> "NULL"
  | IRLiteral (NoneLit) -> "0"
  | IRLiteral (StringLit s) -> 
      (* Generate string literal as struct initialization *)
      (match ir_val.val_type with
       | IRStr size ->
           let temp_var = fresh_var ctx "str_lit" in
                    let len = String.length s in
         let max_content_len = size in (* Full size available for content *)
         let actual_len = min len max_content_len in
         let truncated_s = if actual_len < len then String.sub s 0 actual_len else s in
           
           (* Generate cleaner initialization with string literal + padding *)
           emit_line ctx (sprintf "str_%d_t %s = {" size temp_var);
           emit_line ctx (sprintf "    .data = \"%s\"," (String.escaped truncated_s));
           emit_line ctx (sprintf "    .len = %d" actual_len);
           emit_line ctx "};";
           temp_var
       | _ -> sprintf "\"%s\"" s) (* Fallback for non-string types *)
  | IRLiteral (ArrayLit init_style) ->
      (* Generate C array initialization syntax *)
      (match init_style with
       | ZeroArray -> "{0}"  (* Empty array initialization *)
       | FillArray fill_lit ->
           let fill_str = match fill_lit with
             | Ast.IntLit (i, _) -> string_of_int i
             | Ast.BoolLit b -> if b then "1" else "0"
             | Ast.CharLit c -> sprintf "'%c'" c
             | Ast.StringLit s -> sprintf "\"%s\"" s
             | Ast.NullLit -> "NULL"
             | Ast.NoneLit -> "0"
             | Ast.ArrayLit _ -> "{0}"  (* Nested arrays simplified *)
           in
           "{" ^ fill_str ^ "}"
       | ExplicitArray elements ->
           let element_strings = List.map (fun elem ->
             match elem with
             | Ast.IntLit (i, _) -> string_of_int i
             | Ast.BoolLit b -> if b then "1" else "0"
             | Ast.CharLit c -> sprintf "'%c'" c
             | Ast.StringLit s -> sprintf "\"%s\"" s
             | Ast.NullLit -> "NULL"
             | Ast.NoneLit -> "0"
             | Ast.ArrayLit _ -> "{0}"  (* Nested arrays simplified *)
           ) elements in
           if List.length elements = 0 then
             "{0}"  (* Empty array initialization *)
           else
             "{" ^ String.concat ", " element_strings ^ "}")
  | IRVariable name -> 
      (* Check if this is a pinned global variable *)
      if List.mem name ctx.pinned_globals then
        (* Generate transparent access to pinned global through map *)
        sprintf "({ struct __pinned_globals *__pg = get_pinned_globals(); __pg ? __pg->%s : (typeof(__pg->%s)){0}; })" name name
      (* Check if this is a config access *)
      else if String.contains name '.' then
        let parts = String.split_on_char '.' name in
        match parts with
        | [config_name; field_name] -> 
            (* Generate safe config access with NULL check *)
            sprintf "({ struct %s_config *cfg = get_%s_config(); cfg ? cfg->%s : 0; })" 
              config_name config_name field_name
        | _ -> name
      (* Check if this is a kprobe function parameter *)
      else if ctx.current_function_context_type = Some "kprobe" then
        (try
          (* Try to use kprobe parameter mapping to generate PT_REGS_PARM* access *)
          Kernelscript_context.Context_codegen.generate_context_field_access "kprobe" "ctx" name
        with Failure _ ->
          (* If parameter mapping fails, use name directly (for non-parameter variables) *)
          name)
      else
        name  (* Function parameters and regular variables use their names directly *)
  | IRRegister reg -> 
      (* Check if this register can be inlined *)
      (match get_inlined_expression ctx reg with
       | Some expr -> expr
       | None -> get_meaningful_var_name ctx reg ir_val.val_type)
  | IRMapRef map_name -> sprintf "&%s" map_name
  | IRContextField (ctx_type, field) ->
      let ctx_var = "ctx" in (* Standard context parameter name *)
      (* Use modular context code generation *)
      let ctx_type_str = match ctx_type with
        | XdpCtx -> "xdp"
        | TcCtx -> "tc" 
        | KprobeCtx -> "kprobe"
        | _ -> failwith ("Unsupported context type in IRContextField")
      in
      Kernelscript_context.Context_codegen.generate_context_field_access ctx_type_str ctx_var field
  | IREnumConstant (_enum_name, constant_name, _value) ->
      (* Generate enum constant name instead of numeric value *)
      constant_name
  | IRFunctionRef function_name ->
      (* Generate function reference (just the function name) *)
      function_name
  | IRMapAccess (_, _, (underlying_desc, underlying_type)) ->
      (* Map access semantics: 
         - Default: return the dereferenced value (kernelscript semantics)
         - Special contexts (address-of, none comparisons): return the pointer
      *)
      let underlying_val = { value_desc = underlying_desc; val_type = underlying_type; stack_offset = None; bounds_checked = false; val_pos = ir_val.val_pos } in
      let ptr_str = generate_c_value ~auto_deref_map_access:false ctx underlying_val in
      
      if auto_deref_map_access then
        (* Return the dereferenced value (default kernelscript semantics) *)
        (* For map access, the underlying_type is the pointer type, so we need to dereference it *)
        let deref_type = match underlying_type with
          | IRPointer (inner_type, _) -> inner_type
          | other_type -> other_type
        in
        sprintf "({ %s __val = {0}; if (%s) { __val = *(%s); } __val; })" 
          (ebpf_type_from_ir_type deref_type) ptr_str ptr_str
      else
        (* Return the pointer (for address-of operations and none comparisons) *)
        ptr_str
  in
  
  (* The auto_deref_map_access flag is now used to control whether to return 
     the value (true - default) or the pointer (false - for special contexts) *)
  base_result

(** Generate string operations for eBPF *)

let generate_string_concat ctx left_val right_val =
  (* For eBPF, we need to manually implement string concatenation *)
  let temp_var = fresh_var ctx "str_concat" in
  let left_str = generate_c_value ctx left_val in
  let right_str = generate_c_value ctx right_val in
  
  (* Extract sizes from string types *)
  let (left_size, right_size) = match left_val.val_type, right_val.val_type with
    | IRStr ls, IRStr rs -> (ls, rs)
    | _ -> failwith "String concat called on non-string types"
  in
  let result_size = left_size + right_size in
  
  (* Generate the concatenation code using typedef'd struct *)
  emit_line ctx (sprintf "str_%d_t %s;" result_size temp_var);
  emit_line ctx (sprintf "%s.len = 0;" temp_var);
  let max_content_len = result_size in (* Full content capacity available *)
  
  (* Copy first string with bounds checking and null terminator detection *)
  emit_line ctx "#pragma unroll";
  emit_line ctx (sprintf "for (int i = 0; i < %d; i++) {" left_size);
  emit_line ctx (sprintf "    if (%s.len >= %d) break;" temp_var max_content_len);
  emit_line ctx (sprintf "    if (%s.data[i] == 0) break;" left_str);
  emit_line ctx (sprintf "    %s.data[%s.len++] = %s.data[i];" temp_var temp_var left_str);
  emit_line ctx "}";
  
  (* Copy second string with bounds checking and null terminator detection *)
  emit_line ctx "#pragma unroll";
  emit_line ctx (sprintf "for (int i = 0; i < %d; i++) {" right_size);
  emit_line ctx (sprintf "    if (%s.len >= %d) break;" temp_var max_content_len);
  emit_line ctx (sprintf "    if (%s.data[i] == 0) break;" right_str);
  emit_line ctx (sprintf "    %s.data[%s.len++] = %s.data[i];" temp_var temp_var right_str);
  emit_line ctx "}";
  
  (* Add null terminator - always safe since we have max_content_len + 1 total bytes *)
  emit_line ctx (sprintf "%s.data[%s.len] = 0;" temp_var temp_var);
  
  temp_var

let generate_string_compare ctx left_val right_val is_equal =
  (* Use bpf_strncmp() helper for efficient string comparison *)
  let left_str = generate_c_value ctx left_val in
  let right_str = generate_c_value ctx right_val in
  
  (* Extract size from left string type for bpf_strncmp bounds *)
  let left_size = match left_val.val_type with
    | IRStr size -> size
    | _ -> failwith "String compare called on non-string type"
  in
  
  (* Generate bpf_strncmp() call - returns 0 if strings are equal *)
  let cmp_result = sprintf "bpf_strncmp(%s.data, %d, %s.data)" left_str left_size right_str in
  
  if is_equal then
    sprintf "(%s == 0)" cmp_result  (* Equal if bpf_strncmp returns 0 *)
  else
    sprintf "(%s != 0)" cmp_result  (* Not equal if bpf_strncmp returns non-zero *)

(** Generate C expression from IR expression *)

let generate_c_expression ctx ir_expr =
  match ir_expr.expr_desc with
  | IRValue ir_val -> 
      (* For IRMapAccess values, auto-dereference by default to return the value *)
      (match ir_val.value_desc with
       | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx ir_val
       | _ -> generate_c_value ctx ir_val)
  | IRBinOp (left, op, right) ->
      (* Check if this is a string operation *)
      (match left.val_type, op, right.val_type with
       | IRStr _, IRAdd, IRStr _ ->
           (* String concatenation *)
           generate_string_concat ctx left right
       | IRStr _, IREq, IRStr _ ->
           (* String equality *)
           generate_string_compare ctx left right true
       | IRStr _, IRNe, IRStr _ ->
           (* String inequality *)
           generate_string_compare ctx left right false
       | IRStr _, IRAdd, _ ->
           (* String indexing: str.data[index] *)
           let array_str = generate_c_value ctx left in
           let index_str = generate_c_value ctx right in
           sprintf "%s.data[%s]" array_str index_str
       | _ ->
           (* Check for none comparisons first *)
           (match left.value_desc, op, right.value_desc with
            | _, IREq, IRLiteral (Ast.NoneLit) 
            | IRLiteral (Ast.NoneLit), IREq, _ ->
                (* Comparison with none: check if pointer is NULL *)
                let non_none_val = if left.value_desc = IRLiteral (Ast.NoneLit) then right else left in
                (* For IRMapAccess, use the underlying pointer directly for NULL check *)
                let val_str = (match non_none_val.value_desc with
                  | IRMapAccess (_, _, (underlying_desc, underlying_type)) ->
                      let underlying_val = { value_desc = underlying_desc; val_type = underlying_type; stack_offset = None; bounds_checked = false; val_pos = non_none_val.val_pos } in
                      generate_c_value ~auto_deref_map_access:false ctx underlying_val
                  | _ -> generate_c_value ctx non_none_val) in
                sprintf "(%s == NULL)" val_str
            | _, IRNe, IRLiteral (Ast.NoneLit)
            | IRLiteral (Ast.NoneLit), IRNe, _ ->
                (* Not-equal comparison with none: check if pointer is not NULL *)
                let non_none_val = if left.value_desc = IRLiteral (Ast.NoneLit) then right else left in
                (* For IRMapAccess, use the underlying pointer directly for NULL check *)
                let val_str = (match non_none_val.value_desc with
                  | IRMapAccess (_, _, (underlying_desc, underlying_type)) ->
                      let underlying_val = { value_desc = underlying_desc; val_type = underlying_type; stack_offset = None; bounds_checked = false; val_pos = non_none_val.val_pos } in
                      generate_c_value ~auto_deref_map_access:false ctx underlying_val
                  | _ -> generate_c_value ctx non_none_val) in
                sprintf "(%s != NULL)" val_str
            | _ ->
                (* Regular binary operation - auto-dereference map access for operands *)
                let left_str = (match left.value_desc with
                  | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx left
                  | _ -> generate_c_value ctx left) in
                let right_str = (match right.value_desc with  
                  | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx right
                  | _ -> generate_c_value ctx right) in
                
                (* Add casting for pointer arithmetic *)
                let (left_str, right_str) = match left.val_type, op, right.val_type with
                  (* Pointer - Pointer = size (cast both to uintptr_t) *)
                  | IRPointer _, IRSub, IRPointer _ -> 
                      (sprintf "((__u64)%s)" left_str, sprintf "((__u64)%s)" right_str)
                  (* Pointer + Integer = Pointer (no casting needed) *)
                  | IRPointer _, (IRAdd | IRSub), _ -> (left_str, right_str)
                  (* Integer + Pointer = Pointer (no casting needed) *)
                  | _, IRAdd, IRPointer _ -> (left_str, right_str)
                  (* Default case - no casting *)
                  | _ -> (left_str, right_str)
                in
                
                let op_str = match op with
                  | IRAdd -> "+" | IRSub -> "-" | IRMul -> "*" | IRDiv -> "/" | IRMod -> "%"
                  | IREq -> "==" | IRNe -> "!=" | IRLt -> "<" | IRLe -> "<=" | IRGt -> ">" | IRGe -> ">="
                  | IRAnd -> "&&" | IROr -> "||"
                  | IRBitAnd -> "&" | IRBitOr -> "|" | IRBitXor -> "^"
                  | IRShiftL -> "<<" | IRShiftR -> ">>"
                in
                sprintf "(%s %s %s)" left_str op_str right_str))
  | IRUnOp (op, ir_val) ->
      (match op with
       | IRAddressOf ->
           (* Address-of operation: for map access, return the pointer directly *)
           (match ir_val.value_desc with
            | IRMapAccess (_, _, _) -> 
                (* For map access address-of, return the underlying pointer *)
                generate_c_value ~auto_deref_map_access:false ctx ir_val
            | _ ->
                (* For other values, take address normally *)
                let val_str = generate_c_value ctx ir_val in
                sprintf "(&%s)" val_str)
       | IRDeref ->
           (* Use enhanced semantic analysis to determine appropriate access method *)
           let val_str = (match ir_val.value_desc with
             | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx ir_val
             | _ -> generate_c_value ctx ir_val) in
           (match detect_memory_region_enhanced ir_val with
            | PacketData ->
                (* Packet data - use bpf_dynptr_from_xdp *)
                (match ir_val.val_type with
                 | IRPointer (inner_type, _) ->
                     let c_type = ebpf_type_from_ir_type inner_type in
                     let size = match inner_type with
                       | IRI8 | IRU8 -> 1 | IRI16 | IRU16 -> 2 | IRI32 | IRU32 -> 4 | IRI64 | IRU64 -> 8 | _ -> 4
                     in
                     sprintf "({ %s __pkt_val = 0; struct bpf_dynptr __pkt_dynptr; if (bpf_dynptr_from_xdp(&__pkt_dynptr, ctx) == 0) { void* __pkt_data = bpf_dynptr_data(&__pkt_dynptr, (%s - (void*)(long)ctx->data), %d); if (__pkt_data) __pkt_val = *(%s*)__pkt_data; } __pkt_val; })" 
                       c_type val_str size c_type
                 | _ -> sprintf "SAFE_DEREF(%s)" val_str)
            
            | LocalStack ->
                (* Local stack variables - use direct access *)
                sprintf "*%s" val_str
            
            | _ when is_map_value_parameter ir_val ->
                (* Map value parameters - use bpf_dynptr_from_mem *)
                (match ir_val.val_type with
                 | IRPointer (inner_type, _) ->
                     let c_type = ebpf_type_from_ir_type inner_type in
                     let size = match inner_type with
                       | IRI8 | IRU8 -> 1 | IRI16 | IRU16 -> 2 | IRI32 | IRU32 -> 4 | IRI64 | IRU64 -> 8 | _ -> 4
                     in
                     sprintf "({ %s __mem_val = 0; struct bpf_dynptr __mem_dynptr; if (bpf_dynptr_from_mem(%s, %d, 0, &__mem_dynptr) == 0) { void* __mem_data = bpf_dynptr_data(&__mem_dynptr, 0, %d); if (__mem_data) __mem_val = *(%s*)__mem_data; } __mem_val; })" 
                       c_type val_str size size c_type
                 | _ -> sprintf "SAFE_DEREF(%s)" val_str)
            
            | _ ->
                (* Regular memory - use enhanced safety *)
                (match ir_val.val_type with
                 | IRPointer (inner_type, bounds_info) ->
                     let c_type = ebpf_type_from_ir_type inner_type in
                     if bounds_info.nullable then
                       sprintf "({ %s __val = {0}; if (%s && (void*)%s >= (void*)0x1000) { __builtin_memcpy(&__val, %s, sizeof(%s)); } __val; })" c_type val_str val_str val_str c_type
                     else
                       sprintf "SAFE_DEREF(%s)" val_str
                 | _ -> sprintf "SAFE_DEREF(%s)" val_str))
       | IRNot | IRNeg | IRBitNot ->
           (* Standard unary operations - auto-dereference map access *)
           let val_str = (match ir_val.value_desc with
             | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx ir_val
             | _ -> generate_c_value ctx ir_val) in
           let op_str = match op with
             | IRNot -> "!" | IRNeg -> "-" | IRBitNot -> "~" 
             | _ -> failwith "Unexpected unary op"
           in
           sprintf "(%s%s)" op_str val_str)
  | IRCast (ir_val, target_type) ->
      let val_str = generate_c_value ctx ir_val in
      let type_str = ebpf_type_from_ir_type target_type in
      sprintf "((%s)%s)" type_str val_str
  | IRFieldAccess (obj_val, field) ->
      let obj_str = generate_c_value ctx obj_val in
      (* Use enhanced semantic analysis for field access *)
      (match detect_memory_region_enhanced obj_val with
       | PacketData ->
           (* Packet data field access - use bpf_dynptr_from_xdp *)
           (match obj_val.val_type with
            | IRPointer (IRStruct (struct_name, _), _) ->
                (* Note: For field ACCESS (not assignment), we use sizeof(__typeof(field)) 
                   which is calculated by the C compiler, so we don't need calculate_type_size here *)
                let field_size = sprintf "sizeof(__typeof(((%s*)0)->%s))" 
                                        (sprintf "struct %s" struct_name) field in
                let full_struct_name = sprintf "struct %s" struct_name in
                sprintf "({ __typeof(((%s*)0)->%s) __field_val = 0; struct bpf_dynptr __pkt_dynptr; if (bpf_dynptr_from_xdp(&__pkt_dynptr, ctx) == 0) { void* __field_data = bpf_dynptr_data(&__pkt_dynptr, (%s - (void*)(long)ctx->data) + __builtin_offsetof(%s, %s), %s); if (__field_data) __field_val = *(__typeof(((%s*)0)->%s)*)__field_data; } __field_val; })" 
                  full_struct_name field obj_str full_struct_name field field_size full_struct_name field
            | _ -> sprintf "SAFE_PTR_ACCESS(%s, %s)" obj_str field)
       
               | _ when is_map_value_parameter obj_val ->
            (* Map value field access - use bpf_dynptr_from_mem *)
            (match obj_val.val_type with
             | IRPointer (IRStruct (struct_name, _), _) ->
                 (* Note: For field ACCESS (not assignment), we use sizeof(__typeof(field)) 
                    which is calculated by the C compiler, so we don't need calculate_type_size here *)
                 let field_size = sprintf "sizeof(__typeof(((%s*)0)->%s))" 
                                         (sprintf "struct %s" struct_name) field in
                 let full_struct_name = sprintf "struct %s" struct_name in
                 sprintf "({ __typeof(((%s*)0)->%s) __field_val = 0; struct bpf_dynptr __mem_dynptr; if (bpf_dynptr_from_mem(%s, sizeof(%s), 0, &__mem_dynptr) == 0) { void* __field_data = bpf_dynptr_data(&__mem_dynptr, __builtin_offsetof(%s, %s), %s); if (__field_data) __field_val = *(__typeof(((%s*)0)->%s)*)__field_data; } __field_val; })" 
                   full_struct_name field obj_str full_struct_name full_struct_name field field_size full_struct_name field
             | _ -> sprintf "SAFE_PTR_ACCESS(%s, %s)" obj_str field)
       
                | _ ->
            (* Regular field access with enhanced safety checks for pointers *)
            (match obj_val.val_type with
             | IRPointer (_, bounds_info) ->
                 (* Use enhanced pointer field access with null and bounds checking *)
                 if bounds_info.nullable then
                   sprintf "({ typeof((%s)->%s) __field_val = {0}; if (%s && (void*)%s >= (void*)0x1000) { __field_val = (%s)->%s; } __field_val; })" obj_str field obj_str obj_str obj_str field
                 else
                   sprintf "SAFE_PTR_ACCESS(%s, %s)" obj_str field
             | _ -> 
                 (* Check if this is actually a pointer type that wasn't detected *)
                 (match obj_val.value_desc with
                  | IRMapAccess (_, _, _) -> 
                      (* Map lookups return pointers, always use arrow notation *)
                      sprintf "SAFE_PTR_ACCESS(%s, %s)" obj_str field
                  | _ -> 
                      (* Direct struct field access *)
                      sprintf "%s.%s" obj_str field)))
      
  | IRStructLiteral (_struct_name, field_assignments) ->
      (* Generate C struct literal: {.field1 = value1, .field2 = value2} *)
      let field_strs = List.map (fun (field_name, field_val) ->
        let field_value_str = generate_c_value ctx field_val in
        sprintf ".%s = %s" field_name field_value_str
      ) field_assignments in
      sprintf "{%s}" (String.concat ", " field_strs)

  | IRMatch (matched_val, arms) ->
      (* For match expressions, always generate control flow when in return context *)
      (* This handles the case where match arms contain tail calls *)
      let should_generate_control_flow = ctx.in_return_context in
      
      if should_generate_control_flow then
        (* Generate if-else chain with returns for tail call scenarios *)
        let matched_str = generate_c_value ctx matched_val in
        
        let generate_match_arm is_first arm =
          let arm_val_str = generate_c_value ctx arm.ir_arm_value in
          match arm.ir_arm_pattern with
          | IRConstantPattern const_val ->
              let const_str = generate_c_value ctx const_val in
              let keyword = if is_first then "if" else "else if" in
              emit_line ctx (sprintf "%s (%s == %s) {" keyword matched_str const_str);
              increase_indent ctx;
              emit_line ctx (sprintf "return %s;" arm_val_str);
              decrease_indent ctx;
              emit_line ctx "}"
          | IRDefaultPattern ->
              emit_line ctx "else {";
              increase_indent ctx;
              emit_line ctx (sprintf "return %s;" arm_val_str);
              decrease_indent ctx;
              emit_line ctx "}"
        in
        
        (* Generate all arms *)
        (match arms with
         | [] -> () (* No arms - should not happen *)
         | first_arm :: rest_arms ->
             generate_match_arm true first_arm;
             List.iter (generate_match_arm false) rest_arms);
        
        (* Return empty string since control flow handles the return *)
        ""
      else
        (* Optimization: Try to inline simple match expressions *)
        let matched_str = generate_c_value ctx matched_val in
        
        (* Check if we can inline this match expression - be more conservative *)
        let can_inline = ctx.enable_temp_var_optimization && 
                        List.length arms <= 2 && 
                        List.for_all (fun arm ->
                          match arm.ir_arm_value.value_desc with
                          | IRLiteral _ | IREnumConstant _ -> true
                          | _ -> false) arms &&
                        List.for_all (fun arm ->
                          match arm.ir_arm_pattern with
                          | IRConstantPattern _ | IRDefaultPattern -> true) arms in
        
        if can_inline then
          (* Generate inline ternary expression for simple cases *)
          let generate_inline_condition () =
            let rec build_ternary = function
              | [] -> "0" (* Should not happen *)
              | [arm] ->
                  (match arm.ir_arm_pattern with
                   | IRDefaultPattern -> generate_c_value ctx arm.ir_arm_value
                   | IRConstantPattern const_val ->
                       let const_str = generate_c_value ctx const_val in
                       let arm_val_str = generate_c_value ctx arm.ir_arm_value in
                       sprintf "(%s == %s) ? %s : 0" matched_str const_str arm_val_str)
              | arm :: rest_arms ->
                  (match arm.ir_arm_pattern with
                   | IRConstantPattern const_val ->
                       let const_str = generate_c_value ctx const_val in
                       let arm_val_str = generate_c_value ctx arm.ir_arm_value in
                       let rest_expr = build_ternary rest_arms in
                       sprintf "(%s == %s) ? %s : (%s)" matched_str const_str arm_val_str rest_expr
                   | IRDefaultPattern ->
                       generate_c_value ctx arm.ir_arm_value)
            in
            build_ternary arms
          in
          sprintf "(%s)" (generate_inline_condition ())
        else
          (* Generate regular if-else chain with temporary variable for complex cases *)
          let temp_var = fresh_var ctx "match_result" in
          let result_type = ebpf_type_from_ir_type ir_expr.expr_type in
          
          (* Generate temporary variable for the result *)
          emit_line ctx (sprintf "%s %s;" result_type temp_var);
          
          (* Generate if-else chain *)
          let generate_match_arm is_first arm =
            let arm_val_str = generate_c_value ctx arm.ir_arm_value in
            match arm.ir_arm_pattern with
            | IRConstantPattern const_val ->
                let const_str = generate_c_value ctx const_val in
                let keyword = if is_first then "if" else "else if" in
                emit_line ctx (sprintf "%s (%s == %s) {" keyword matched_str const_str);
                increase_indent ctx;
                emit_line ctx (sprintf "%s = %s;" temp_var arm_val_str);
                decrease_indent ctx;
                emit_line ctx "}"
            | IRDefaultPattern ->
                emit_line ctx "else {";
                increase_indent ctx;
                emit_line ctx (sprintf "%s = %s;" temp_var arm_val_str);
                decrease_indent ctx;
                emit_line ctx "}"
          in
          
          (* Generate all arms *)
          (match arms with
           | [] -> () (* No arms - should not happen *)
           | first_arm :: rest_arms ->
               generate_match_arm true first_arm;
               List.iter (generate_match_arm false) rest_arms);
          
          (* Return the temporary variable *)
          temp_var



(** Generate bounds checking *)

let generate_bounds_check ctx ir_val min_bound max_bound =
  let val_str = generate_c_value ctx ir_val in
  emit_line ctx (sprintf "if (%s < %d || %s > %d) {" val_str min_bound val_str max_bound);
  increase_indent ctx;
  emit_line ctx "return XDP_DROP; /* Bounds check failed */";
  decrease_indent ctx;
  emit_line ctx "}"

(** Generate map operations *)

let generate_map_load ctx map_val key_val dest_val load_type =
  let map_str = generate_c_value ctx map_val in
  let dest_str = generate_c_value ctx dest_val in
  
  match load_type with
  | DirectLoad ->
      emit_line ctx (sprintf "%s = *%s;" dest_str map_str)
  | MapLookup ->
      (* Handle key - create temp variable for any value that would require address taking *)
      let key_str = generate_c_value ctx key_val in
      let needs_temp_var = match key_val.value_desc with
        | IRLiteral _ -> true
        | _ -> 
            (* Check if the generated C value looks like a literal that can't have its address taken *)
            let is_numeric_literal = try ignore (int_of_string key_str); true with _ -> false in
            let is_hex_literal = String.contains key_str 'x' || String.contains key_str 'X' in
            is_numeric_literal || is_hex_literal
      in
      
      let key_var = if needs_temp_var then
        let temp_key = fresh_var ctx "key" in
        let key_type = ebpf_type_from_ir_type key_val.val_type in
        emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
        temp_key
      else
        key_str
      in
      
      (* Map lookup returns pointer directly - don't dereference it *)
      emit_line ctx (sprintf "%s = bpf_map_lookup_elem(%s, &%s);" dest_str map_str key_var)
  | MapPeek ->
      emit_line ctx (sprintf "%s = bpf_ringbuf_reserve(%s, sizeof(*%s), 0);" dest_str map_str dest_str)

let generate_map_store ctx map_val key_val value_val store_type =
  let map_str = generate_c_value ctx map_val in
  
  match store_type with
  | DirectStore ->
      let value_str = generate_c_value ctx value_val in
      emit_line ctx (sprintf "*%s = %s;" map_str value_str)
  | MapUpdate ->
      (* Handle key - create temp variable for any value that would require address taking *)
      let key_str = generate_c_value ctx key_val in
      let needs_temp_var = match key_val.value_desc with
        | IRLiteral _ -> true
        | _ -> 
            (* Check if the generated C value looks like a literal that can't have its address taken *)
            let is_numeric_literal = try ignore (int_of_string key_str); true with _ -> false in
            let is_hex_literal = String.contains key_str 'x' || String.contains key_str 'X' in
            is_numeric_literal || is_hex_literal
      in
      
      let key_var = if needs_temp_var then
        let temp_key = fresh_var ctx "key" in
        let key_type = ebpf_type_from_ir_type key_val.val_type in
        emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
        temp_key
      else
        key_str
      in
      
      (* Handle value - create temp variable for any value that would require address taking *)
      let value_str = generate_c_value ctx value_val in
      let needs_temp_var_value = match value_val.value_desc with
        | IRLiteral _ -> true
        | _ -> 
            (* Check if the generated C value looks like a literal that can't have its address taken *)
            let is_numeric_literal = try ignore (int_of_string value_str); true with _ -> false in
            let is_hex_literal = String.contains value_str 'x' || String.contains value_str 'X' in
            is_numeric_literal || is_hex_literal
      in
      
      let value_var = if needs_temp_var_value then
        let temp_value = fresh_var ctx "value" in
        let value_type = ebpf_type_from_ir_type value_val.val_type in
        emit_line ctx (sprintf "%s %s = %s;" value_type temp_value value_str);
        temp_value
      else
        value_str
      in
      
      emit_line ctx (sprintf "bpf_map_update_elem(%s, &%s, &%s, BPF_ANY);" map_str key_var value_var)
  | MapPush ->
      let value_str = generate_c_value ctx value_val in
      emit_line ctx (sprintf "bpf_ringbuf_submit(%s, 0);" value_str)


let generate_map_delete ctx map_val key_val =
  let map_str = generate_c_value ctx map_val in
  
  (* Handle key - create temp variable for any value that would require address taking *)
  let key_str = generate_c_value ctx key_val in
  let needs_temp_var = match key_val.value_desc with
    | IRLiteral _ -> true
    | _ -> 
        (* Check if the generated C value looks like a literal that can't have its address taken *)
        let is_numeric_literal = try ignore (int_of_string key_str); true with _ -> false in
        let is_hex_literal = String.contains key_str 'x' || String.contains key_str 'X' in
        is_numeric_literal || is_hex_literal
  in
  
  let key_var = if needs_temp_var then
    let temp_key = fresh_var ctx "key" in
    let key_type = ebpf_type_from_ir_type key_val.val_type in
    emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
    temp_key
  else
    key_str
  in
  
  emit_line ctx (sprintf "bpf_map_delete_elem(%s, &%s);" map_str key_var)

(* Ring buffer code generation *)
let generate_ringbuf_operation ctx ringbuf_val op =
  match op with
  | RingbufReserve result_val ->
      (* Generate bpf_ringbuf_reserve_dynptr call - modern dynptr API *)
      (* Handle pinned ring buffers specially to avoid address-of-rvalue issues *)
      let ringbuf_str = match ringbuf_val.value_desc with
        | IRVariable name when List.mem name ctx.pinned_globals ->
            (* For pinned ring buffers, create a temporary pointer variable *)
            let temp_var = fresh_var ctx "pinned_ringbuf" in
            emit_line ctx (sprintf "void *%s;" temp_var);
            emit_line ctx (sprintf "{ struct __pinned_globals *__pg = get_pinned_globals();" );
            emit_line ctx (sprintf "  %s = __pg ? __pg->%s : NULL; }" temp_var name);
            temp_var
        | _ ->
            (* Regular ring buffer - use address-of *)
            "&" ^ (generate_c_value ctx ringbuf_val)
      in
      let result_str = generate_c_value ctx result_val in
      
      (* Calculate proper size based on the result type *)
      let size = match result_val.val_type with
        | IRPointer (IRStruct (struct_name, _), _) ->
            (* Use sizeof for struct types *)
            sprintf "sizeof(struct %s)" struct_name
        | IRPointer (elem_type, _) ->
            (* Use sizeof for the pointed-to type *)
            sprintf "sizeof(%s)" (ebpf_type_from_ir_type elem_type)
        | other_type ->
            (* This should never happen if type checker is working correctly *)
            failwith (sprintf "generate_ringbuf_operation: Invalid result type for ringbuf reservation: %s. Expected pointer to struct." 
                     (match other_type with
                      | IRU32 -> "IRU32"
                      | IRU64 -> "IRU64" 
                      | IRStruct (name, _) -> "IRStruct " ^ name
                      | IRVoid -> "IRVoid"
                      | _ -> "unknown type"))
      in
      
      (* Get consistent variable name for the result register *)
      let result_var_name = match result_val.value_desc with
        | IRRegister reg -> get_meaningful_var_name ctx reg result_val.val_type
        | IRVariable name -> name
        | _ -> "dynptr_data"
      in
      
      (* Declare dynptr for the reservation - track it for later submit/discard *)
      let dynptr_var = result_var_name ^ "_dynptr" in
      emit_line ctx (sprintf "struct bpf_dynptr %s;" dynptr_var);
      
      (* The data pointer variable will be declared by the function's register collection phase *)
      
      emit_line ctx (sprintf "if (bpf_ringbuf_reserve_dynptr(%s, %s, 0, &%s) == 0) {" 
                     ringbuf_str size dynptr_var);
      
      (* Get data pointer from dynptr *)
      emit_line ctx (sprintf "    %s = bpf_dynptr_data(&%s, 0, %s);" 
                     result_str dynptr_var size);
      (* Track this pointer as dynptr-backed for field assignments *)
      Hashtbl.replace ctx.dynptr_backed_pointers result_str dynptr_var;
      emit_line ctx "} else {";
      emit_line ctx (sprintf "    %s = NULL;" result_str);
      emit_line ctx "}"
  
  | RingbufSubmit data_val ->
      (* Generate bpf_ringbuf_submit_dynptr call *)
      let data_str = generate_c_value ctx data_val in
      (* Use the tracked dynptr variable for this data pointer *)
      let dynptr_var = match Hashtbl.find_opt ctx.dynptr_backed_pointers data_str with
        | Some tracked_dynptr -> tracked_dynptr
        | None -> 
            (* Fallback: construct dynptr name from data pointer name *)
            let base_name = match data_val.value_desc with
              | IRRegister reg -> sprintf "ptr_%d" reg
              | IRVariable name -> name
              | _ -> "dynptr_data"
            in
            base_name ^ "_dynptr"
      in
      emit_line ctx (Printf.sprintf "bpf_ringbuf_submit_dynptr(&%s, 0);" dynptr_var)
  
  | RingbufDiscard data_val ->
      (* Generate bpf_ringbuf_discard_dynptr call *)
      let data_str = generate_c_value ctx data_val in
      (* Use the tracked dynptr variable for this data pointer *)
      let dynptr_var = match Hashtbl.find_opt ctx.dynptr_backed_pointers data_str with
        | Some tracked_dynptr -> tracked_dynptr
        | None -> 
            (* Fallback: construct dynptr name from data pointer name *)
            let base_name = match data_val.value_desc with
              | IRRegister reg -> sprintf "ptr_%d" reg
              | IRVariable name -> name
              | _ -> "dynptr_data"
            in
            base_name ^ "_dynptr"
      in
      emit_line ctx (Printf.sprintf "bpf_ringbuf_discard_dynptr(&%s, 0);" dynptr_var)
  
  | RingbufOnEvent _handler_name ->
      (* on_event is userspace-only operation *)
      failwith "Ring buffer on_event() operation is not supported in eBPF programs - it's userspace-only"

(** Generate C code for IR instruction *)

(** Helper function to convert AST expressions to C code for bpf_loop callbacks *)
let rec generate_ast_expr_to_c (expr : Ast.expr) counter_var =
  match expr.Ast.expr_desc with
  | Ast.Literal (Ast.IntLit (i, _)) -> string_of_int i
  | Ast.Literal (Ast.BoolLit b) -> if b then "true" else "false"
  | Ast.Identifier name when name = "i" -> counter_var (* Map loop variable to counter *)
  | Ast.Identifier name -> name
  | Ast.BinaryOp (left, op, right) ->
      let left_c = generate_ast_expr_to_c left counter_var in
      let right_c = generate_ast_expr_to_c right counter_var in
      let op_c = match op with
        | Ast.Add -> "+"
        | Ast.Sub -> "-"
        | Ast.Mul -> "*"
        | Ast.Div -> "/"
        | Ast.Mod -> "%"
        | Ast.Eq -> "=="
        | Ast.Ne -> "!="
        | Ast.Lt -> "<"
        | Ast.Le -> "<="
        | Ast.Gt -> ">"
        | Ast.Ge -> ">="
        | Ast.And -> "&&"
        | Ast.Or -> "||"
      in
      sprintf "(%s %s %s)" left_c op_c right_c
  | _ -> "/* complex expr */"

(** Generate assignment instruction with optional const keyword *)
and generate_assignment ctx dest_val expr is_const =
  let assignment_prefix = if is_const then "const " else "" in
  
  (* Optimization: Check if we can inline simple expressions *)
  let can_inline_expr = ctx.enable_temp_var_optimization && 
                       (match dest_val.value_desc with
                        | IRRegister _ -> true
                        | _ -> false) &&
                       (match expr.expr_desc with
                        | IRValue src_val -> 
                            (match src_val.value_desc with
                             | IRLiteral _ | IREnumConstant _ | IRVariable _ -> true
                             | _ -> false)
                        | IRBinOp (_, _, _) -> true
                        | IRUnOp (_, _) -> true
                        | IRCast (_, _) -> true
                        | _ -> false) in
  
  (* Check if this is a pinned global variable assignment *)
  (match dest_val.value_desc with
   | IRVariable name when List.mem name ctx.pinned_globals ->
       (* Special handling for pinned global variable assignment *)
       let expr_str = generate_c_expression ctx expr in
       emit_line ctx (sprintf "{ struct __pinned_globals *__pg = get_pinned_globals();");
       emit_line ctx (sprintf "  if (__pg) {");
       emit_line ctx (sprintf "    __pg->%s = %s;" name expr_str);
       emit_line ctx (sprintf "    update_pinned_globals(__pg);");
       emit_line ctx (sprintf "  }");
       emit_line ctx (sprintf "}")
   | IRRegister reg when can_inline_expr ->
       (* Optimization: Only inline very simple expressions to avoid correctness issues *)
       let should_inline = match expr.expr_desc with
         | IRValue src_val -> 
             (match src_val.value_desc with
              | IRLiteral _ | IREnumConstant _ -> true
              | _ -> false)
         | _ -> false
       in
        (* Prevent inlining for registers that might be named return variables *)
        let might_be_return_var = 
          (* Low-numbered registers are often used for important variables like return values *)
          reg <= 15 && 
          (* Common return value types *)
          (match dest_val.val_type with
          | IRU32 | IRI32 | IRU64 | IRI64 | IRBool | IRAction _ | IRStr _ | IRPointer _ -> true
          | _ -> false) in
       if should_inline && not might_be_return_var then (
         let expr_str = generate_c_expression ctx expr in
         mark_register_inlinable ctx reg expr_str;
         (* Don't emit assignment - expression will be inlined *)
         ()
       ) else (
         (* Generate normal assignment for complex expressions *)
         let dest_str = generate_c_value ctx dest_val in
         let expr_str = generate_c_expression ctx expr in
         
         (* Check if we're assigning a dynptr-backed pointer to another variable *)
         (match expr.expr_desc with
          | IRValue src_val ->
              let src_str = generate_c_value ctx src_val in
              (match Hashtbl.find_opt ctx.dynptr_backed_pointers src_str with
               | Some dynptr_var ->
                   (* Source is dynptr-backed, mark destination as dynptr-backed too *)
                   Hashtbl.replace ctx.dynptr_backed_pointers dest_str dynptr_var
               | None -> ())
          | _ -> ());
         
         emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str expr_str)
       )
   | _ ->
       (* Check for dynptr pointer assignment tracking before string assignment *)
       (match expr.expr_desc with
        | IRValue src_val ->
            let dest_str = generate_c_value ctx dest_val in
            let src_str = generate_c_value ctx src_val in
            (match Hashtbl.find_opt ctx.dynptr_backed_pointers src_str with
             | Some dynptr_var ->
                 (* Source is dynptr-backed, mark destination as dynptr-backed too *)
                 Hashtbl.replace ctx.dynptr_backed_pointers dest_str dynptr_var
             | None -> ())
        | _ -> ());
       
       (* Check if this is a string assignment *)
       (match dest_val.val_type, expr.expr_desc with
        | IRStr dest_size, IRValue src_val when (match src_val.val_type with IRStr src_size -> src_size <= dest_size | _ -> false) ->
            (* String to string assignment with compatible sizes - regenerate src with dest size *)
            let dest_str = generate_c_value ctx dest_val in
            let src_str = match src_val.value_desc with
              | IRLiteral (StringLit s) ->
                  (* Regenerate string literal with destination size *)
                  let temp_var = fresh_var ctx "str_lit" in
                  let len = String.length s in
                  let max_content_len = dest_size in
                  let actual_len = min len max_content_len in
                  let truncated_s = if actual_len < len then String.sub s 0 actual_len else s in
                  emit_line ctx (sprintf "str_%d_t %s = {" dest_size temp_var);
                  emit_line ctx (sprintf "    .data = \"%s\"," (String.escaped truncated_s));
                  emit_line ctx (sprintf "    .len = %d" actual_len);
                  emit_line ctx "};";
                  temp_var
              | _ -> generate_c_value ctx src_val
            in
            emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str src_str)
        | IRStr _, IRValue src_val when (match src_val.val_type with IRStr _ -> true | _ -> false) ->
            (* String to string assignment - need to copy struct *)
            let dest_str = generate_c_value ctx dest_val in
            let src_str = generate_c_value ctx src_val in
            emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str src_str)
        | IRStr _size, IRValue src_val when (match src_val.value_desc with IRLiteral (StringLit _) -> true | _ -> false) ->
            (* String literal to string assignment - already handled above *)
            let dest_str = generate_c_value ctx dest_val in
            let src_str = generate_c_value ctx src_val in
            emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str src_str)
        | IRStr _, _ ->
            (* Other string expressions (concatenation, etc.) *)
            let dest_str = generate_c_value ctx dest_val in
            let expr_str = generate_c_expression ctx expr in
            emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str expr_str)
        | _ ->
            (* Regular assignment - handle struct literals specially *)
            let dest_str = generate_c_value ctx dest_val in
            (match expr.expr_desc with
             | IRStructLiteral (struct_name, field_assignments) ->
                 (* For struct literal assignments, use compound literal syntax *)
                 let field_strs = List.map (fun (field_name, field_val) ->
                   let field_value_str = generate_c_value ctx field_val in
                   sprintf ".%s = %s" field_name field_value_str
                 ) field_assignments in
                 let struct_type = sprintf "struct %s" struct_name in
                 emit_line ctx (sprintf "%s%s = (%s){%s};" assignment_prefix dest_str struct_type (String.concat ", " field_strs))
             | _ ->
                 (* Other expressions *)
                 let expr_str = generate_c_expression ctx expr in
                 emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str expr_str))))

(** Generate C code for truthy/falsy conversion *)
let generate_truthy_conversion ctx ir_value =
  match ir_value.val_type with
  | IRBool -> 
      (* Already boolean, use as-is *)
      generate_c_value ctx ir_value
  | IRU8 | IRU16 | IRU32 | IRU64 | IRI8 | IRI16 | IRI32 | IRI64 ->
      (* Numbers: 0 is falsy, non-zero is truthy *)
      sprintf "(%s != 0)" (generate_c_value ctx ir_value)
  | IRChar ->
      (* Characters: '\0' is falsy, others truthy *)
      sprintf "(%s != '\\0')" (generate_c_value ctx ir_value)
  | IRStr _ ->
      (* Strings: empty is falsy, non-empty is truthy *)
      sprintf "(%s.len > 0)" (generate_c_value ctx ir_value)
  | IRPointer (_, _) ->
      (* Pointers: null is falsy, non-null is truthy *)
      sprintf "(%s != NULL)" (generate_c_value ctx ir_value)
  | IREnum (_, _) ->
      (* Enums: based on numeric value *)
      sprintf "(%s != 0)" (generate_c_value ctx ir_value)
  | _ ->
      (* This should never be reached due to type checking *)
      failwith ("Internal error: Type " ^ (string_of_ir_type ir_value.val_type) ^ " cannot be used in boolean context")

let rec generate_c_instruction ctx ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest_val, expr) ->
      (* Regular assignment without const keyword *)
      generate_assignment ctx dest_val expr false
      
  | IRConstAssign (dest_val, expr) ->
      (* Const assignment with const keyword *)
      generate_assignment ctx dest_val expr true
      
  | IRDeclareVariable (dest_val, typ, init_expr_opt) ->
      (* Variable declaration with optional initialization *)
      let var_name = match dest_val.value_desc with 
        | IRRegister reg -> 
            let name = get_meaningful_var_name ctx reg typ in
            (* Store the declared name for this register to ensure consistency *)
            Hashtbl.replace ctx.register_name_hints reg (String.split_on_char '_' name |> List.hd);
            (* Mark this register as declared *)
            Hashtbl.add ctx.declared_registers reg ();
            name
        | _ -> failwith "IRDeclareVariable target must be a register"
      in
      
      (* Special handling for different types in variable declarations *)
      (match typ with
       | IRArray (element_type, size, _) ->
           (* Array declaration with proper C syntax *)
           let element_type_str = ebpf_type_from_ir_type element_type in
           let array_decl = sprintf "%s %s[%d]" element_type_str var_name size in
           (match init_expr_opt with
            | Some init_expr ->
                let init_str = generate_c_expression ctx init_expr in
                emit_line ctx (sprintf "%s = %s;" array_decl init_str)
            | None ->
                emit_line ctx (sprintf "%s;" array_decl))
       | IRStr dest_size ->
           (* String variable declaration with special handling for string literals *)
           let type_str = ebpf_type_from_ir_type typ in
           (match init_expr_opt with
            | Some init_expr ->
                (match init_expr.expr_desc with
                 | IRValue src_val when (match src_val.value_desc with IRLiteral (StringLit _) -> true | _ -> false) ->
                     (* String literal initialization - generate compatible literal *)
                     (match src_val.value_desc with
                      | IRLiteral (StringLit s) ->
                          let len = String.length s in
                          let max_content_len = dest_size in
                          let actual_len = min len max_content_len in
                          let truncated_s = if actual_len < len then String.sub s 0 actual_len else s in
                          emit_line ctx (sprintf "%s %s = {" type_str var_name);
                          emit_line ctx (sprintf "    .data = \"%s\"," (String.escaped truncated_s));
                          emit_line ctx (sprintf "    .len = %d" actual_len);
                          emit_line ctx "};"
                      | _ ->
                          let init_str = generate_c_expression ctx init_expr in
                          emit_line ctx (sprintf "%s %s = %s;" type_str var_name init_str))
                 | _ ->
                     (* Other initialization expressions *)
                     let init_str = generate_c_expression ctx init_expr in
                     emit_line ctx (sprintf "%s %s = %s;" type_str var_name init_str))
            | None ->
                emit_line ctx (sprintf "%s %s;" type_str var_name))
       | _ ->
           (* Regular variable declaration - use proper C declaration generator *)
           let decl_str = generate_ebpf_c_declaration typ var_name in
           (match init_expr_opt with
            | Some init_expr ->
                let init_str = generate_c_expression ctx init_expr in
                emit_line ctx (sprintf "%s = %s;" decl_str init_str)
            | None ->
                emit_line ctx (sprintf "%s;" decl_str)))
      
  | IRCall (target, args, ret_opt) ->
      (* Handle different call targets *)
      let (actual_name, translated_args) = match target with
        | DirectCall name ->
            (* Check if this is a built-in function that needs context-specific translation *)
            (match Stdlib.get_ebpf_implementation name with
        | Some ebpf_impl ->
            (* This is a built-in function - translate for eBPF context *)
            (match name with
             | "print" -> 
                 (* Special handling for print: convert to bpf_printk format *)
                 (match args with
                  | [] -> (ebpf_impl, ["\"\""])
                  | [first_ir] -> 
                      (* Single argument case - use as format string *)
                      (match first_ir.value_desc with
                       | IRLiteral (StringLit s) -> 
                           (* String literal - use directly for bpf_printk *)
                           (ebpf_impl, [sprintf "\"%s\"" s])
                       | _ ->
                           (* Other types - auto-dereference map access values *)
                           let first_arg = (match first_ir.value_desc with
                             | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx first_ir
                             | _ -> generate_c_value ctx first_ir) in
                           (match first_ir.val_type with
                            | IRStr _ -> (ebpf_impl, [first_arg ^ ".data"])
                            | _ -> (ebpf_impl, [first_arg])))
                  | first_ir :: rest_ir ->
                     (* Multiple arguments: first is format string, rest are arguments *)
                     (* bpf_printk limits: format string + up to 3 args *)
                     let limited_rest = 
                       let rec take n lst =
                         if n <= 0 then []
                         else match lst with
                         | [] -> []
                         | h :: t -> h :: take (n - 1) t
                       in
                       take (min 3 (List.length rest_ir)) rest_ir
                     in
                     
                     (* Use the first argument directly as the format string *)
                     let format_arg = match first_ir.value_desc with
                       | IRLiteral (StringLit s) -> 
                           (* String literal - use directly for bpf_printk *)
                           sprintf "\"%s\"" s
                       | _ ->
                           (* Other types - generate as usual *)
                           let format_str = generate_c_value ctx first_ir in
                           (match first_ir.val_type with
                            | IRStr _ -> format_str ^ ".data"
                            | _ -> format_str)
                     in
                     
                     (* Generate remaining arguments - auto-dereference map access values *)
                     let rest_args = List.map (fun arg_ir ->
                       match arg_ir.value_desc with
                       | IRMapAccess (_, _, _) -> generate_c_value ~auto_deref_map_access:true ctx arg_ir
                       | _ -> generate_c_value ctx arg_ir) limited_rest in
                     (ebpf_impl, format_arg :: rest_args))
             | _ -> 
                 (* For other built-in functions, use standard conversion *)
                 let c_args = List.map (generate_c_value ctx) args in
                 (ebpf_impl, c_args))
        | None ->
            (* Regular function call *)
            let c_args = List.map (generate_c_value ctx) args in
            (name, c_args))
        | FunctionPointerCall func_ptr ->
            (* Function pointer call - generate the function pointer directly *)
            let func_ptr_str = generate_c_value ctx func_ptr in
            let c_args = List.map (generate_c_value ctx) args in
            (func_ptr_str, c_args)
      in
      let args_str = String.concat ", " translated_args in
      (match ret_opt with
       | Some ret_val ->
           let ret_str = generate_c_value ctx ret_val in
           emit_line ctx (sprintf "%s = %s(%s);" ret_str actual_name args_str)
       | None ->
           emit_line ctx (sprintf "%s(%s);" actual_name args_str))
           
  | IRTailCall (name, _args, index) ->
      (* Generate bpf_tail_call instruction *)
      emit_line ctx (sprintf "/* Tail call to %s (index %d) */" name index);
      emit_line ctx (sprintf "bpf_tail_call(ctx, &prog_array, %d);" index);
      emit_line ctx "/* If tail call fails, continue execution */"

  | IRMapLoad (map_val, key_val, dest_val, load_type) ->
      generate_map_load ctx map_val key_val dest_val load_type

  | IRMapStore (map_val, key_val, value_val, store_type) ->
      generate_map_store ctx map_val key_val value_val store_type

  | IRMapDelete (map_val, key_val) ->
      generate_map_delete ctx map_val key_val

  | IRRingbufOp (ringbuf_val, op) ->
      generate_ringbuf_operation ctx ringbuf_val op

  | IRConfigFieldUpdate (_map_val, _key_val, _field, _value_val) ->
      (* Config field updates should never occur in eBPF programs - they are read-only *)
      failwith "Internal error: Config field updates in eBPF programs should have been caught during type checking - configs are read-only in kernel space"

  | IRStructFieldAssignment (obj_val, field_name, value_val) ->
      (* Enhanced struct field assignment with safety checks *)
      let obj_str = generate_c_value ctx obj_val in
      let value_str = generate_c_value ctx value_val in
      
      (* Check if this is a dynptr-backed pointer first *)
      (match Hashtbl.find_opt ctx.dynptr_backed_pointers obj_str with
       | Some dynptr_var ->
        (* This is a dynptr-backed pointer - use bpf_dynptr_write *)
          let field_size = calculate_type_size value_val.val_type in
          (match obj_val.val_type with
           | IRPointer (IRStruct (struct_name, _), _) ->
                let full_struct_name = sprintf "struct %s" struct_name in
                emit_line ctx (sprintf "{ %s __tmp_val = %s;" (ebpf_type_from_ir_type value_val.val_type) value_str);
                emit_line ctx (sprintf "  bpf_dynptr_write(&%s, __builtin_offsetof(%s, %s), &__tmp_val, %d, 0); }" 
                         dynptr_var full_struct_name field_name field_size)
            | _ ->
                (* Fallback to direct assignment for non-struct types *)
                emit_line ctx (sprintf "if (%s) { %s->%s = %s; }" obj_str obj_str field_name value_str))
       | None ->
           (* Not a dynptr-backed pointer - use enhanced semantic analysis for field assignment *)
           (match detect_memory_region_enhanced obj_val with
               | PacketData ->
            (* Packet data field assignment - use dynptr API for safe write *)
           (match obj_val.val_type with
            | IRPointer (IRStruct (struct_name, _), _) ->
                 let field_size = calculate_type_size value_val.val_type in
                 let full_struct_name = sprintf "struct %s" struct_name in
                 emit_line ctx (sprintf "{ struct bpf_dynptr __pkt_dynptr; bpf_dynptr_from_xdp(&__pkt_dynptr, ctx);");
                 emit_line ctx (sprintf "  __u32 __field_offset = (%s - ctx->data) + __builtin_offsetof(%s, %s);" obj_str full_struct_name field_name);
                 emit_line ctx (sprintf "  bpf_dynptr_write(&__pkt_dynptr, __field_offset, &%s, %d, 0); }" value_str field_size)
             | _ ->
                 emit_line ctx (sprintf "if (%s) { %s->%s = %s; }" obj_str obj_str field_name value_str))
        
        | _ when is_map_value_parameter obj_val ->
            (* Map value field assignment - use dynptr API *)
            (match obj_val.val_type with
             | IRPointer (IRStruct (struct_name, _), _) ->
                 let field_size = calculate_type_size value_val.val_type in
                 let full_struct_name = sprintf "struct %s" struct_name in
                 emit_line ctx (sprintf "{ struct bpf_dynptr __mem_dynptr; bpf_dynptr_from_mem(%s, sizeof(%s), 0, &__mem_dynptr);" obj_str full_struct_name);
                 emit_line ctx (sprintf "  bpf_dynptr_write(&__mem_dynptr, __builtin_offsetof(%s, %s), &%s, %d, 0); }" full_struct_name field_name value_str field_size)
             | _ ->
                 emit_line ctx (sprintf "if (%s) { %s->%s = %s; }" obj_str obj_str field_name value_str))
        
        | _ ->
            (* Regular field assignment with enhanced pointer safety checks *)
            (match obj_val.val_type with
             | IRPointer (_, bounds_info) ->
                 if bounds_info.nullable then (
                   emit_line ctx (sprintf "if (%s && (void*)%s >= (void*)0x1000) {" obj_str obj_str);
                   increase_indent ctx;
                   emit_line ctx (sprintf "%s->%s = %s;" obj_str field_name value_str);
                   decrease_indent ctx;
                   emit_line ctx "}"
                 ) else (
                   emit_line ctx (sprintf "if (%s) { %s->%s = %s; }" obj_str obj_str field_name value_str)
                 )
             | _ ->
                 (* Check if this is actually a pointer type that wasn't detected *)
                 (match obj_val.value_desc with
                  | IRMapAccess (_, _, _) -> 
                      (* Map lookups return pointers, always use arrow notation *)
                      emit_line ctx (sprintf "if (%s) { %s->%s = %s; }" obj_str obj_str field_name value_str)
                  | _ -> 
                      (* Direct struct field assignment *)
                      emit_line ctx (sprintf "%s.%s = %s;" obj_str field_name value_str)))))
      
  | IRConfigAccess (config_name, field_name, result_val) ->
      (* For eBPF, config access goes through global maps *)
      let result_str = generate_c_value ctx result_val in
      let config_map_name = sprintf "%s_config_map" config_name in
      emit_line ctx (sprintf "{ __u32 config_key = 0; /* global config key */");
      emit_line ctx (sprintf "  void* config_ptr = bpf_map_lookup_elem(&%s, &config_key);" config_map_name);
      emit_line ctx (sprintf "  if (config_ptr) {");
      emit_line ctx (sprintf "    %s = ((struct %s_config*)config_ptr)->%s;" result_str config_name field_name);
      emit_line ctx (sprintf "  } else { %s = 0; }" result_str);
      emit_line ctx (sprintf "}")
      
  | IRContextAccess (dest_val, context_type, field_name) ->
      let dest_str = generate_c_value ctx dest_val in
      (* Use BTF-integrated context code generation directly *)
      let access_str = Kernelscript_context.Context_codegen.generate_context_field_access context_type "ctx" field_name in
      emit_line ctx (sprintf "%s = %s;" dest_str access_str)

  | IRBoundsCheck (value_val, min_bound, max_bound) ->
      let value_str = generate_c_value ctx value_val in
      emit_line ctx (sprintf "if (%s < %d || %s > %d) return XDP_ABORTED;" 
                     value_str min_bound value_str max_bound)

  | IRJump label ->
      emit_line ctx (sprintf "goto %s;" label)

  | IRCondJump (cond_val, true_label, false_label) ->
      let cond_str = generate_c_value ctx cond_val in
      emit_line ctx (sprintf "if (%s) goto %s; else goto %s;" cond_str true_label false_label)

  | IRIf (cond_val, then_body, else_body) ->
      (* For eBPF, use structured if statements instead of goto-based control flow *)
      (* This avoids the complex label management and makes the code more readable *)
      let cond_str = generate_truthy_conversion ctx cond_val in
      
      emit_line ctx (sprintf "if (%s) {" cond_str);
      increase_indent ctx;
      List.iter (generate_c_instruction ctx) then_body;
      decrease_indent ctx;
      
      (match else_body with
       | Some else_instrs ->
           emit_line ctx "} else {";
           increase_indent ctx;
           List.iter (generate_c_instruction ctx) else_instrs;
           decrease_indent ctx;
           emit_line ctx "}"
       | None ->
           emit_line ctx "}")

  | IRIfElseChain (conditions_and_bodies, final_else) ->
      (* Generate if-else-if chains with proper C formatting for eBPF *)
      List.iteri (fun i (cond_val, then_body) ->
        let cond_str = generate_truthy_conversion ctx cond_val in
        let keyword = if i = 0 then "if" else "} else if" in
        emit_line ctx (sprintf "%s (%s) {" keyword cond_str);
        increase_indent ctx;
        List.iter (generate_c_instruction ctx) then_body;
        decrease_indent ctx
      ) conditions_and_bodies;
      
      (match final_else with
       | Some else_instrs ->
           emit_line ctx "} else {";
           increase_indent ctx;
           List.iter (generate_c_instruction ctx) else_instrs;
           decrease_indent ctx;
           emit_line ctx "}"
       | None ->
           emit_line ctx "}")

  | IRMatchReturn (matched_val, arms) ->
      (* Generate if-else chain for match expression in return position *)
      let matched_str = generate_c_value ctx matched_val in
      
      let generate_match_arm is_first arm =
        match arm.match_pattern with
        | IRConstantPattern const_val ->
            let const_str = generate_c_value ctx const_val in
            let keyword = if is_first then "if" else "} else if" in
            emit_line ctx (sprintf "%s (%s == %s) {" keyword matched_str const_str);
            increase_indent ctx;
            
            (* Generate appropriate return/tail call based on the return action *)
            (match arm.return_action with
             | IRReturnValue ret_val ->
                 let ret_str = generate_c_value ctx ret_val in
                 emit_line ctx (sprintf "return %s;" ret_str)
             | IRReturnCall (func_name, args) ->
                 (* Generate tail call for function call in return position *)
                 let args_str = String.concat ", " (List.map (generate_c_value ctx) args) in
                 emit_line ctx (sprintf "/* Tail call to %s */" func_name);
                 emit_line ctx (sprintf "bpf_tail_call(ctx, &prog_array, 0); /* %s(%s) */" func_name args_str);
                 emit_line ctx "/* If tail call fails, continue execution */"
             | IRReturnTailCall (func_name, args, index) ->
                 (* Generate explicit tail call *)
                 let args_str = String.concat ", " (List.map (generate_c_value ctx) args) in
                 emit_line ctx (sprintf "/* Tail call to %s (index %d) */" func_name index);
                 emit_line ctx (sprintf "bpf_tail_call(ctx, &prog_array, %d); /* %s(%s) */" index func_name args_str);
                 emit_line ctx "/* If tail call fails, continue execution */");
            
            decrease_indent ctx
        | IRDefaultPattern ->
            emit_line ctx "} else {";
            increase_indent ctx;
            
            (* Generate appropriate return/tail call for default case *)
            (match arm.return_action with
             | IRReturnValue ret_val ->
                 let ret_str = generate_c_value ctx ret_val in
                 emit_line ctx (sprintf "return %s;" ret_str)
             | IRReturnCall (func_name, args) ->
                 (* Generate tail call for function call in return position *)
                 let args_str = String.concat ", " (List.map (generate_c_value ctx) args) in
                 emit_line ctx (sprintf "/* Tail call to %s */" func_name);
                 emit_line ctx (sprintf "bpf_tail_call(ctx, &prog_array, 0); /* %s(%s) */" func_name args_str);
                 emit_line ctx "/* If tail call fails, continue execution */"
             | IRReturnTailCall (func_name, args, index) ->
                 (* Generate explicit tail call *)
                 let args_str = String.concat ", " (List.map (generate_c_value ctx) args) in
                 emit_line ctx (sprintf "/* Tail call to %s (index %d) */" func_name index);
                 emit_line ctx (sprintf "bpf_tail_call(ctx, &prog_array, %d); /* %s(%s) */" index func_name args_str);
                 emit_line ctx "/* If tail call fails, continue execution */");
            
            decrease_indent ctx;
            emit_line ctx "}"
      in
      
      (* Generate all arms *)
      (match arms with
       | [] -> () (* No arms - should not happen *)
       | first_arm :: rest_arms ->
           generate_match_arm true first_arm;
           List.iter (generate_match_arm false) rest_arms;
           (* Close the if-else chain if no default was provided *)
           if not (List.exists (fun arm -> match arm.match_pattern with IRDefaultPattern -> true | _ -> false) arms) then
             emit_line ctx "}")

  | IRReturn ret_opt ->
      begin match ret_opt with
      | Some ret_val ->
          (* Set return context flag before generating the return value *)
          let old_return_context = ctx.in_return_context in
          ctx.in_return_context <- true;
          
          let ret_str = match ret_val.value_desc with
            (* Use context-specific action constant mapping *)
            | IRLiteral (IntLit (i, _)) when ret_val.val_type = IRAction Xdp_actionType ->
                (match Kernelscript_context.Context_codegen.map_context_action_constant "xdp" i with
                 | Some action -> action
                 | None -> string_of_int i)
            | IRLiteral (IntLit (i, _)) when ret_val.val_type = IRAction TcActionType ->
                (match Kernelscript_context.Context_codegen.map_context_action_constant "tc" i with
                 | Some action -> action
                 | None -> string_of_int i)
            | IRMapAccess (_, _, _) ->
                (* For map access in return position, auto-dereference to return the value *)
                generate_c_value ~auto_deref_map_access:true ctx ret_val
            | _ -> generate_c_value ctx ret_val
          in
          
          (* Restore return context flag *)
          ctx.in_return_context <- old_return_context;
          
          emit_line ctx (sprintf "return %s;" ret_str)
      | None ->
          emit_line ctx "return XDP_PASS;"  (* Default XDP action *)
      end

  | IRComment comment ->
      emit_line ctx (sprintf "/* %s */" comment)

  | IRBpfLoop (start_val, end_val, counter_val, _ctx_val, body_instructions) ->
      let start_str = generate_c_value ctx start_val in
      let end_str = generate_c_value ctx end_val in
      
      (* Generate unique callback function name *)
      let callback_name = sprintf "loop_callback_%d" ctx.next_label_id in
      ctx.next_label_id <- ctx.next_label_id + 1;
      
      (* Create a separate context for the callback function *)
      let callback_ctx = create_c_context () in
      callback_ctx.indent_level <- 1; (* Start with one level of indentation *)
      
      (* Use consistent variable naming between callback declaration and usage *)
      let setup_callback_variable_names callback_ctx registers =
        (* For each register, determine its variable name and store in callback context *)
        List.iter (fun (reg, _reg_type) ->
          (* Store the variable name in the callback context's register hints *)
          Hashtbl.replace callback_ctx.register_name_hints reg "tmp"
        ) registers
      in
      
      (* Generate callback function signature *)
      emit_line callback_ctx (sprintf "static long %s(__u32 index, void *ctx_ptr) {" callback_name);
      increase_indent callback_ctx;
      
      (* Extract the variable name from counter_val for proper declaration in callback *)
      let counter_var_name = match counter_val.value_desc with
        | IRRegister reg -> sprintf "tmp_%d" reg
        | IRVariable name -> name
        | _ -> "loop_counter"
      in
      
      (* Collect all registers used in the callback body *)
      let callback_registers = ref [] in
      let collect_callback_registers ir_instr =
        let collect_in_value ir_val =
          match ir_val.value_desc with
          | IRRegister reg -> 
              if not (List.mem_assoc reg !callback_registers) then
                callback_registers := (reg, ir_val.val_type) :: !callback_registers
          | _ -> ()
        in
        let collect_in_expr ir_expr =
          match ir_expr.expr_desc with
          | IRValue ir_val -> collect_in_value ir_val
          | IRBinOp (left, _, right) -> collect_in_value left; collect_in_value right
          | IRUnOp (_, ir_val) -> collect_in_value ir_val
          | IRCast (ir_val, _) -> collect_in_value ir_val
          | IRFieldAccess (obj_val, _) -> collect_in_value obj_val
          | IRStructLiteral (_, field_assignments) ->
              List.iter (fun (_, field_val) -> collect_in_value field_val) field_assignments
          | IRMatch (matched_val, arms) ->
              (* Collect from matched expression and all arms *)
              collect_in_value matched_val;
              List.iter (fun arm -> collect_in_value arm.ir_arm_value) arms
        in
        let rec collect_in_instr ir_instr =
          match ir_instr.instr_desc with
          | IRAssign (dest_val, expr) -> collect_in_value dest_val; collect_in_expr expr
          | IRMapLoad (dest_val, map_val, key_val, _) ->
              collect_in_value dest_val; collect_in_value map_val; collect_in_value key_val
          | IRMapStore (map_val, key_val, value_val, _) ->
              collect_in_value map_val; collect_in_value key_val; collect_in_value value_val
          | IRMapDelete (map_val, key_val) ->
              collect_in_value map_val; collect_in_value key_val
          | IRConfigFieldUpdate (map_val, key_val, _, value_val) ->
              collect_in_value map_val; collect_in_value key_val; collect_in_value value_val
          | IRStructFieldAssignment (obj_val, _, value_val) ->
              collect_in_value obj_val; collect_in_value value_val
          | IRConfigAccess (_, _, result_val) ->
              collect_in_value result_val
          | IRContextAccess (result_val, _, _) ->
              collect_in_value result_val
          | IRBoundsCheck (value_val, _, _) ->
              collect_in_value value_val
          | IRCondJump (cond_val, _, _) ->
              collect_in_value cond_val
          | IRIf (cond_val, then_body, else_body) ->
              collect_in_value cond_val;
              List.iter collect_in_instr then_body;
              (match else_body with
               | Some else_instrs -> List.iter collect_in_instr else_instrs
               | None -> ())
          | IRIfElseChain (conditions_and_bodies, final_else) ->
              List.iter (fun (cond_val, then_body) ->
                collect_in_value cond_val;
                List.iter collect_in_instr then_body
              ) conditions_and_bodies;
              (match final_else with
               | Some else_instrs -> List.iter collect_in_instr else_instrs
               | None -> ())
          | IRMatchReturn (matched_val, arms) ->
              collect_in_value matched_val;
              List.iter (fun arm ->
                (match arm.match_pattern with
                 | IRConstantPattern const_val -> collect_in_value const_val
                 | IRDefaultPattern -> ());
                (match arm.return_action with
                 | IRReturnValue ret_val -> collect_in_value ret_val
                 | IRReturnCall (_, args) -> List.iter collect_in_value args
                 | IRReturnTailCall (_, args, _) -> List.iter collect_in_value args)
              ) arms
          | IRReturn ret_opt -> Option.iter collect_in_value ret_opt
          | IRCondReturn (cond_val, ret_if_true, ret_if_false) ->
              collect_in_value cond_val;
              Option.iter collect_in_value ret_if_true;
              Option.iter collect_in_value ret_if_false
          | IRTry (try_instructions, _catch_clauses) ->
              List.iter collect_in_instr try_instructions
          | IRBpfLoop (start_val, end_val, counter_val, ctx_val, body_instructions) ->
              collect_in_value start_val; collect_in_value end_val; 
              collect_in_value counter_val; collect_in_value ctx_val;
              List.iter collect_in_instr body_instructions
          | IRStructOpsRegister (instance_val, struct_ops_val) ->
              collect_in_value instance_val; collect_in_value struct_ops_val
          | IRDefer defer_instructions ->
              List.iter collect_in_instr defer_instructions
          | IRConstAssign (dest_val, const_expr) ->
              collect_in_value dest_val; collect_in_expr const_expr
          | IRDeclareVariable (dest_val, _, init_expr_opt) ->
              collect_in_value dest_val;
              Option.iter collect_in_expr init_expr_opt
          | IRCall (_, args, result_val_opt) ->
              List.iter collect_in_value args;
              Option.iter collect_in_value result_val_opt
          | IRTailCall (_, args, _) ->
              List.iter collect_in_value args
          | IRObjectNew (dest_val, _) ->
              collect_in_value dest_val
          | IRObjectNewWithFlag (dest_val, _, flag_val) ->
              collect_in_value dest_val; collect_in_value flag_val
          | IRObjectDelete ptr_val ->
              collect_in_value ptr_val
          | IRRingbufOp (ringbuf_val, _) ->
              collect_in_value ringbuf_val
          | IRJump _ | IRComment _ | IRBreak | IRContinue | IRThrow _ -> ()
        in
        collect_in_instr ir_instr
      in
      
      (* Collect registers from all body instructions *)
      List.iter collect_callback_registers body_instructions;
      
      (* Setup consistent variable naming for the callback context *)
      setup_callback_variable_names callback_ctx !callback_registers;
      
      (* Get the counter register for exclusion *)
      let counter_reg = match counter_val.value_desc with
        | IRRegister reg -> Some reg
        | _ -> None
      in
      
      (* Declare the loop counter variable in callback scope *)
      let counter_type = ebpf_type_from_ir_type counter_val.val_type in
      emit_line callback_ctx (sprintf "%s %s = index;" counter_type counter_var_name);
      
      (* Add counter variable to callback context's register hints *)
      (match counter_val.value_desc with
       | IRRegister reg -> 
           (* Map the counter register to its actual variable name in callback *)
           let counter_hint = if counter_var_name = sprintf "tmp_%d" reg then "tmp" else "val" in
           Hashtbl.replace callback_ctx.register_name_hints reg counter_hint
       | _ -> ());
      
      (* Collect registers that will be declared by IRDeclareVariable instructions *)
      let ir_declared_registers = ref [] in
      List.iter (fun ir_instr ->
        match ir_instr.instr_desc with
        | IRDeclareVariable (dest_val, _, _) ->
            (match dest_val.value_desc with
             | IRRegister reg -> ir_declared_registers := reg :: !ir_declared_registers
             | _ -> ())
        | _ -> ()
      ) body_instructions;
      
      (* Declare all variables used in the callback, excluding counter register and IR-declared ones *)
      let declared_vars = ref [counter_var_name] in (* Include counter to avoid redefinition *)
      List.iter (fun (reg, reg_type) ->
        let c_type = ebpf_type_from_ir_type reg_type in
        let reg_name = sprintf "tmp_%d" reg in
        (* Skip counter register, IR-declared registers, and already declared variables *)
        if (match counter_reg with Some cr -> reg <> cr | None -> true) &&
           not (List.mem reg !ir_declared_registers) &&
           not (List.mem reg_name !declared_vars) then (
          emit_line callback_ctx (sprintf "%s %s;" c_type reg_name);
          declared_vars := reg_name :: !declared_vars
        )
      ) (List.sort (fun (r1, _) (r2, _) -> compare r1 r2) !callback_registers);
      
      emit_blank_line callback_ctx;
      
      (* Generate C code for each IR instruction in the loop body *)
      let has_early_return = ref false in
      List.iter (fun ir_instr ->
        if not !has_early_return then
          match ir_instr.instr_desc with
          | IRBreak -> 
              emit_line callback_ctx "return 1; /* Break loop */";
              has_early_return := true
          | IRContinue -> 
              emit_line callback_ctx "return 0; /* Continue loop */";
              has_early_return := true
          | _ ->
              (* Generate C code for regular IR instructions *)
              generate_c_instruction callback_ctx ir_instr
      ) body_instructions;
      
      (* Add default return if no early return was encountered *)
      if not !has_early_return then
        emit_line callback_ctx "return 0; /* Continue loop */";
      
      decrease_indent callback_ctx;
      emit_line callback_ctx "}";
      emit_blank_line callback_ctx;
      
      (* Store forward declaration and callback for top-level emission *)
      let forward_decl = sprintf "static long %s(__u32 index, void *ctx_ptr);" callback_name in
      let callback_lines = callback_ctx.output_lines in
      ctx.pending_callbacks <- forward_decl :: "" :: callback_lines @ [""] @ ctx.pending_callbacks;
      
      (* Generate the actual bpf_loop() call *)
      emit_line ctx (sprintf "/* bpf_loop() call for unbounded loop */");
      emit_line ctx (sprintf "{");
      increase_indent ctx;
      emit_line ctx (sprintf "__u32 start_val = %s;" start_str);
      emit_line ctx (sprintf "__u32 end_val = %s;" end_str);
      emit_line ctx (sprintf "__u32 nr_loops = (end_val > start_val) ? (end_val - start_val) : 0;");
      emit_line ctx (sprintf "void *callback_ctx = NULL; /* TODO: pass loop context */");
      emit_line ctx (sprintf "long result = bpf_loop(nr_loops, %s, callback_ctx, 0);" callback_name);
      emit_line ctx (sprintf "if (result < 0) {");
      increase_indent ctx;
      emit_line ctx (sprintf "/* bpf_loop failed */");
      emit_line ctx (sprintf "return XDP_ABORTED;");
      decrease_indent ctx;
      emit_line ctx (sprintf "}");
      decrease_indent ctx;
      emit_line ctx "}"

  | IRBreak ->
      (* In bpf_loop() callbacks, return 1 to break the loop *)
      (* In regular C loops, emit break statement *)
      emit_line ctx "break;"

  | IRContinue ->
      (* In bpf_loop() callbacks, return 0 to continue the loop *)
      (* In regular C loops, emit continue statement *)
      emit_line ctx "continue;"

  | IRCondReturn (cond_val, ret_if_true, ret_if_false) ->
      (* Generate conditional return for bpf_loop() callbacks *)
      let cond_c = generate_c_value ctx cond_val in
      emit_line ctx (sprintf "if (%s) {" cond_c);
      increase_indent ctx;
      (match ret_if_true with
       | Some ret_val -> 
           let ret_c = generate_c_value ctx ret_val in
           emit_line ctx (sprintf "return %s; /* Break/Continue loop */" ret_c)
       | None -> 
           emit_line ctx "/* No action for true branch */");
      decrease_indent ctx;
      (match ret_if_false with
       | Some ret_val ->
           emit_line ctx "} else {";
           increase_indent ctx;
           let ret_c = generate_c_value ctx ret_val in
           emit_line ctx (sprintf "return %s; /* Break/Continue loop */" ret_c);
           decrease_indent ctx;
           emit_line ctx "}"
       | None ->
           emit_line ctx "}")

  | IRTry (try_instructions, _catch_clauses) ->
      (* For eBPF, generate structured try/catch with error status variable and if() checks *)
      let error_var = sprintf "__error_status_%d" ctx.next_label_id in
      ctx.next_label_id <- ctx.next_label_id + 1;
      
      emit_line ctx "/* try block start */";
      emit_line ctx (sprintf "int %s = 0; /* error status */" error_var);
      emit_line ctx "{";
      increase_indent ctx;
      
      (* Generate try block instructions *)
      (* We need to track the error variable in context for throw statements *)
      let old_error_var = ctx.current_error_var in
      ctx.current_error_var <- Some error_var;
      List.iter (generate_c_instruction ctx) try_instructions;
      ctx.current_error_var <- old_error_var;
      
      decrease_indent ctx;
      emit_line ctx "}";
      
      (* Generate catch blocks as if-else chain *)
      List.iteri (fun i catch_clause ->
        let pattern_comment = match catch_clause.catch_pattern with
          | IntCatchPattern code -> sprintf "catch %d" code
          | WildcardCatchPattern -> "catch _"
        in
        let condition = match catch_clause.catch_pattern with
          | IntCatchPattern code -> sprintf "%s == %d" error_var code
          | WildcardCatchPattern -> sprintf "%s != 0" error_var
        in
        
        let if_keyword = if i = 0 then "if" else "else if" in
        emit_line ctx (sprintf "%s (%s) { /* %s */" if_keyword condition pattern_comment);
        increase_indent ctx;
        
        (* Generate catch block instructions from IR *)
        List.iter (generate_c_instruction ctx) catch_clause.catch_body;
        
        decrease_indent ctx;
        emit_line ctx "}";
      ) _catch_clauses;
      
      emit_line ctx "/* try block end */"

  | IRThrow error_code ->
      (* Generate assignment to error status variable *)
      let code_val = match error_code with
        | IntErrorCode code -> code
      in
      (match ctx.current_error_var with
       | Some error_var ->
           emit_line ctx (sprintf "%s = %d; /* throw %d */" error_var code_val code_val)
       | None ->
           (* If not in a try block, this is an uncaught throw - could return error code *)
           emit_line ctx (sprintf "return %d; /* uncaught throw %d */" code_val code_val))

  | IRDefer defer_instructions ->
      (* For eBPF, defer is not directly supported, so we'll generate comments *)
      emit_line ctx "/* defer block - should be executed on function exit */";
      List.iter (fun instr ->
        emit_line ctx (sprintf "/* deferred: %s */" (string_of_ir_instruction instr))
      ) defer_instructions
  | IRStructOpsRegister (_instance_val, _struct_ops_val) ->
      (* For eBPF, struct_ops registration is handled by userspace loader *)
      emit_line ctx (sprintf "/* struct_ops_register - handled by userspace */")

    | IRObjectNew (dest_val, obj_type) ->
      let dest_str = generate_c_value ctx dest_val in
      let type_str = ebpf_type_from_ir_type obj_type in
      (* Use proper kernel pattern: ptr = bpf_obj_new(type) *)
      emit_line ctx (sprintf "%s = bpf_obj_new(%s);" dest_str type_str)
      
  | IRObjectNewWithFlag _ ->
      (* GFP flags should never reach eBPF code generation - this is an internal error *)
      failwith ("Internal error: GFP allocation flags are not supported in eBPF context. " ^
                "This should have been caught by the type checker.")
      
  | IRObjectDelete ptr_val ->
      let ptr_str = generate_c_value ctx ptr_val in
      (* Use the proper kernel bpf_obj_drop(ptr) macro *)
      emit_line ctx (sprintf "bpf_obj_drop(%s);" ptr_str)

(** Generate C code for basic block *)

let generate_c_basic_block ctx ir_block =
  (* Skip labels for "entry" since eBPF code generation uses structured control flow *)
  let should_emit_label = ir_block.label <> "entry" in
  
  if should_emit_label then (
    decrease_indent ctx;
    emit_line ctx (sprintf "%s:" ir_block.label);
    increase_indent ctx
  );
  
  (* Optimize function call + variable declaration patterns *)
  let rec optimize_instructions instrs =
    match instrs with
    | call_instr :: decl_instr :: rest ->
        (match call_instr.instr_desc, decl_instr.instr_desc with
         | IRCall (target, args, Some ret_val), IRDeclareVariable (dest_val, typ, None) 
           when ret_val.value_desc = dest_val.value_desc ->
             (* Combine function call with variable declaration *)
             let var_name = get_meaningful_var_name ctx 
               (match dest_val.value_desc with 
                | IRRegister reg -> reg 
                | _ -> failwith "IRDeclareVariable target must be a register") 
               typ in
             let type_str = ebpf_type_from_ir_type typ in
             let call_str = match target with
               | DirectCall name ->
                   let args_str = String.concat ", " (List.map (generate_c_value ctx) args) in
                   sprintf "%s(%s)" name args_str
               | _ -> "/* complex call */" in
             emit_line ctx (sprintf "%s %s = %s;" type_str var_name call_str);
             optimize_instructions rest
         | _ ->
             generate_c_instruction ctx call_instr;
             optimize_instructions (decl_instr :: rest))
    | instr :: rest ->
        generate_c_instruction ctx instr;
        optimize_instructions rest
    | [] -> ()
  in
  
  optimize_instructions ir_block.instructions

(** Collect mapping from registers to variable names *)
let collect_register_variable_mapping ir_func =
  let register_var_map = ref [] in
  let last_declared_var = ref None in
  let collect_from_instr ir_instr =
    match ir_instr.instr_desc with
    | IRComment comment ->
        (* Parse comments like "Declaration ip" to extract variable names *)
        (try
           let prefix = "Declaration " in
           if String.length comment > String.length prefix && 
              String.sub comment 0 (String.length prefix) = prefix then (
             let var_name = String.sub comment (String.length prefix) 
                                     (String.length comment - String.length prefix) in
             let clean_var_name = String.trim var_name in
             last_declared_var := Some clean_var_name
           )
         with _ -> ())
    | IRAssign (dest_val, _) ->
        (match dest_val.value_desc, !last_declared_var with
         | IRRegister reg, Some var_name ->
             register_var_map := (reg, var_name) :: !register_var_map;
             last_declared_var := None
         | _ -> ())
    | _ -> ()
  in
  List.iter (fun block ->
    List.iter collect_from_instr block.instructions
  ) ir_func.basic_blocks;
  !register_var_map

(** Collect all registers used in a function with their types *)
let collect_registers_in_function ir_func =
  let registers = ref [] in
  let collect_in_value ir_val =
    match ir_val.value_desc with
    | IRRegister reg -> 
        if not (List.mem_assoc reg !registers) then
          registers := (reg, ir_val.val_type) :: !registers
    | _ -> ()
  in
  let collect_in_expr ir_expr =
    match ir_expr.expr_desc with
    | IRValue ir_val -> collect_in_value ir_val
    | IRBinOp (left, _, right) -> collect_in_value left; collect_in_value right
    | IRUnOp (_, ir_val) -> collect_in_value ir_val
    | IRCast (ir_val, _) -> collect_in_value ir_val
    | IRFieldAccess (obj_val, _) -> collect_in_value obj_val
    | IRStructLiteral (_, field_assignments) ->
        List.iter (fun (_, field_val) -> collect_in_value field_val) field_assignments
    | IRMatch (matched_val, arms) ->
        (* Collect from matched expression and all arms *)
        collect_in_value matched_val;
        List.iter (fun arm -> collect_in_value arm.ir_arm_value) arms
  in
  let rec collect_in_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> collect_in_value dest_val; collect_in_expr expr
    | IRConstAssign (dest_val, expr) -> collect_in_value dest_val; collect_in_expr expr
    | IRDeclareVariable (dest_val, typ, init_expr_opt) ->
        (* Use the explicit type from the declaration, not the inferred type *)
        (match dest_val.value_desc with
         | IRRegister reg -> 
             if not (List.mem_assoc reg !registers) then
               registers := (reg, typ) :: !registers
         | _ -> ());
        (match init_expr_opt with
         | Some init_expr -> collect_in_expr init_expr
         | None -> ())
    | IRCall (_, args, ret_opt) -> 
        List.iter collect_in_value args;
        Option.iter collect_in_value ret_opt
    | IRMapLoad (map_val, key_val, dest_val, _) ->
        collect_in_value map_val; collect_in_value key_val; collect_in_value dest_val
    | IRMapStore (map_val, key_val, value_val, _) ->
        collect_in_value map_val; collect_in_value key_val; collect_in_value value_val
    | IRMapDelete (map_val, key_val) ->
        collect_in_value map_val; collect_in_value key_val
    | IRConfigFieldUpdate (map_val, key_val, _field, value_val) ->
        collect_in_value map_val; collect_in_value key_val; collect_in_value value_val
    | IRStructFieldAssignment (obj_val, _field, value_val) ->
        collect_in_value obj_val; collect_in_value value_val
    | IRConfigAccess (_config_name, _field_name, result_val) ->
        collect_in_value result_val
    | IRContextAccess (dest_val, context_type, field_name) -> 
        (* Use BTF to determine the correct type based on the field *)
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
        in
        let correct_type = 
          match Kernelscript_context.Context_codegen.get_context_field_c_type context_type field_name with
          | Some c_type -> c_type_to_ir_type c_type
          | None -> IRU32  (* Default fallback *)
        in
        (match dest_val.value_desc with
         | IRRegister reg -> 
             if not (List.mem_assoc reg !registers) then
               registers := (reg, correct_type) :: !registers
         | _ -> ())
    | IRBoundsCheck (ir_val, _, _) -> collect_in_value ir_val
    | IRCondJump (cond_val, _, _) -> collect_in_value cond_val
    | IRIf (cond_val, then_body, else_body) ->
        collect_in_value cond_val;
        List.iter collect_in_instr then_body;
        (match else_body with
         | Some else_instrs -> List.iter collect_in_instr else_instrs
         | None -> ())
    | IRIfElseChain (conditions_and_bodies, final_else) ->
        List.iter (fun (cond_val, then_body) ->
          collect_in_value cond_val;
          List.iter collect_in_instr then_body
        ) conditions_and_bodies;
        (match final_else with
         | Some else_instrs -> List.iter collect_in_instr else_instrs
         | None -> ())
    | IRMatchReturn (matched_val, arms) ->
        collect_in_value matched_val;
        List.iter (fun arm ->
          (match arm.match_pattern with
           | IRConstantPattern const_val -> collect_in_value const_val
           | IRDefaultPattern -> ());
          (match arm.return_action with
           | IRReturnValue ret_val -> collect_in_value ret_val
           | IRReturnCall (_, args) -> List.iter collect_in_value args
           | IRReturnTailCall (_, args, _) -> List.iter collect_in_value args)
        ) arms
    | IRReturn ret_opt -> Option.iter collect_in_value ret_opt
    | IRJump _ -> ()
    | IRComment _ -> () (* Comments don't use registers *)
    | IRBpfLoop (start_val, end_val, counter_val, ctx_val, body_instructions) ->
        collect_in_value start_val; collect_in_value end_val; 
        collect_in_value counter_val; collect_in_value ctx_val;
        (* Also collect registers from body instructions *)
        List.iter collect_in_instr body_instructions
    | IRBreak -> ()
    | IRContinue -> ()
    | IRCondReturn (cond_val, ret_if_true, ret_if_false) ->
        collect_in_value cond_val;
        Option.iter collect_in_value ret_if_true;
        Option.iter collect_in_value ret_if_false
    | IRTry (try_instructions, _catch_clauses) ->
        List.iter collect_in_instr try_instructions
    | IRThrow _error_code ->
        ()  (* Throw statements don't contain values to collect *)
    | IRDefer defer_instructions ->
        List.iter collect_in_instr defer_instructions
    | IRTailCall (_, args, _) ->
        List.iter collect_in_value args
    | IRStructOpsRegister (instance_val, struct_ops_val) ->
        collect_in_value instance_val; collect_in_value struct_ops_val
    | IRObjectNew (dest_val, _) ->
        collect_in_value dest_val
    | IRObjectNewWithFlag (dest_val, _, flag_val) ->
        collect_in_value dest_val; collect_in_value flag_val
    | IRObjectDelete ptr_val ->
        collect_in_value ptr_val
    | IRRingbufOp (ringbuf_val, op) ->
        collect_in_value ringbuf_val;
        (* Also collect registers from ring buffer operation arguments *)
        (match op with
         | RingbufReserve result_val -> collect_in_value result_val
         | RingbufSubmit data_val -> collect_in_value data_val  
         | RingbufDiscard data_val -> collect_in_value data_val
         | RingbufOnEvent _ -> ())
  in
  List.iter (fun block ->
    List.iter collect_in_instr block.instructions
  ) ir_func.basic_blocks;
  List.sort (fun (r1, _) (r2, _) -> compare r1 r2) !registers

(** Generate C function from IR function with type alias support *)

let generate_c_function ctx ir_func =
  (* Clear per-function state to avoid conflicts between functions *)
  Hashtbl.clear ctx.register_name_hints;
  Hashtbl.clear ctx.inlinable_registers;
  Hashtbl.clear ctx.declared_registers;
  
  (* Determine current function's context type from first parameter or program type *)
  ctx.current_function_context_type <- 
    (match ir_func.func_program_type with
     | Some Ast.Kprobe -> Some "kprobe"  (* Always kprobe for kprobe functions *)
     | _ ->
         (* Fall back to parameter-based detection *)
         (match ir_func.parameters with
          | (_, IRContext XdpCtx) :: _ -> Some "xdp"
          | (_, IRContext TcCtx) :: _ -> Some "tc"
          | (_, IRContext KprobeCtx) :: _ -> Some "kprobe"
          | (_, IRPointer (IRContext XdpCtx, _)) :: _ -> Some "xdp"
          | (_, IRPointer (IRContext TcCtx, _)) :: _ -> Some "tc"
          | (_, IRPointer (IRContext KprobeCtx, _)) :: _ -> Some "kprobe"
          | (_, IRPointer (IRStruct ("__sk_buff", _), _)) :: _ -> Some "tc"  (* Handle __sk_buff as TC context *)
          | (_, IRPointer (IRStruct ("xdp_md", _), _)) :: _ -> Some "xdp"    (* Handle xdp_md as XDP context *)
          | _ -> None));
  
  let return_type_str = 
    (* Special handling for kprobe functions: always use int return type for eBPF compatibility *)
    match ir_func.func_program_type with
    | Some Ast.Kprobe -> "__s32"  (* eBPF kprobe programs must return int *)
    | _ ->
        match ir_func.return_type with
        | Some ret_type -> ebpf_type_from_ir_type ret_type
        | None -> "void"
  in
  
  let params_str = 
    (* Special handling for kprobe functions *)
    match ir_func.func_program_type with
    | Some Ast.Kprobe ->
        (* Kprobe functions always use struct pt_regs *ctx parameter *)
        "struct pt_regs *ctx"
    | _ ->
        (* Other program types: use parameters as-is *)
        String.concat ", " 
          (List.map (fun (name, param_type) ->
             sprintf "%s %s" (ebpf_type_from_ir_type param_type) name
           ) ir_func.parameters)
  in
  
  let section_attr = 
    (* Check if this is a struct_ops function first *)
    match ir_func.func_program_type with
    | Some Ast.StructOps -> sprintf "SEC(\"struct_ops/%s\")" ir_func.func_name  (* struct_ops functions use their name in the section *)
    | Some Ast.Kprobe when ir_func.is_main -> "SEC(\"kprobe\")"  (* Always use kprobe section for kprobe functions *)
    | Some Ast.Tracepoint when ir_func.is_main -> "SEC(\"tracepoint\")"  (* Always use tracepoint section for tracepoint functions *)
    | _ ->
        (* For non-struct_ops, non-kprobe, and non-tracepoint functions, only generate SEC if it's a main function *)
        if ir_func.is_main then
          match ir_func.parameters with
          | [] -> "SEC(\"prog\")"  (* Default section for parameterless functions *)
          | (_, IRContext XdpCtx) :: _ -> "SEC(\"xdp\")"
          | (_, IRContext TcCtx) :: _ -> "SEC(\"tc\")"
          | (_, IRContext KprobeCtx) :: _ -> "SEC(\"kprobe\")"
          | (_, IRContext TracepointCtx) :: _ -> "SEC(\"tracepoint\")"
          | (_, IRPointer (IRContext XdpCtx, _)) :: _ -> "SEC(\"xdp\")"
          | (_, IRPointer (IRContext TcCtx, _)) :: _ -> "SEC(\"tc\")"
          | (_, IRPointer (IRContext KprobeCtx, _)) :: _ -> "SEC(\"kprobe\")"
          | (_, IRPointer (IRContext TracepointCtx, _)) :: _ -> "SEC(\"tracepoint\")"
          | (_, IRPointer (IRStruct ("__sk_buff", _), _)) :: _ -> "SEC(\"tc\")"  (* Handle __sk_buff as TC context *)
          | _ -> "SEC(\"prog\")"
        else ""
  in
  
  emit_line ctx section_attr;
  emit_line ctx (sprintf "%s %s(%s) {" return_type_str ir_func.func_name params_str);
  increase_indent ctx;
  
  (* Function parameters are handled directly via IRVariable - no register mapping needed *)
  
  (* Collect all registers used (parameters use IRVariable, not registers) *)
  let all_registers = collect_registers_in_function ir_func in
  
  (* Collect registers that are handled by IRDeclareVariable instructions *)
  let declared_registers = ref [] in
  List.iter (fun block ->
    List.iter (fun instr ->
      match instr.instr_desc with
      | IRDeclareVariable (dest_val, _, _) ->
          (match dest_val.value_desc with
           | IRRegister reg -> declared_registers := reg :: !declared_registers
           | _ -> ())
      (* IRRingbufOp registers are now handled by the regular collection process *)
      | _ -> ()
    ) block.instructions
  ) ir_func.basic_blocks;
  
  (* Declare temporary variables for all registers *)
  let register_variable_map = collect_register_variable_mapping ir_func in
  
  (* Add all pre-declared registers to the context's declared_registers hashtable *)
  List.iter (fun reg -> Hashtbl.add ctx.declared_registers reg ()) !declared_registers;
  
  (* Generate proper variable declarations for all registers *)
  let register_declarations = ref [] in
  List.iter (fun (reg, reg_type) ->
    (* Skip declaration if register can be inlined, is handled by IRDeclareVariable, or already declared by operations *)
    if not (can_inline_register ctx reg) && not (List.mem reg !declared_registers) && not (Hashtbl.mem ctx.declared_registers reg) then (
      let effective_type = match reg_type with
        | IRTypeAlias (alias_name, _) -> alias_name  (* Use the alias name directly *)
        | _ ->
            (* Check if this register corresponds to a variable with a type alias *)
            (match List.assoc_opt reg register_variable_map with
             | Some var_name ->
                 (* Add register hint for better variable names *)
                 add_register_hint ctx reg var_name;
                 (match List.assoc_opt var_name ctx.variable_type_aliases with
                  | Some alias_name -> alias_name
                  | None -> 
                      (* Use the proper declaration function for complex types *)
                      let var_name = get_meaningful_var_name ctx reg reg_type in
                      let decl = generate_ebpf_c_declaration reg_type var_name in
                      register_declarations := (decl ^ ";") :: !register_declarations;
                      "" (* Skip the simple type processing below *)
                  )
             | None -> 
                 (* Use the proper declaration function for complex types *)
                 let var_name = get_meaningful_var_name ctx reg reg_type in
                 let decl = generate_ebpf_c_declaration reg_type var_name in
                 register_declarations := (decl ^ ";") :: !register_declarations;
                 Hashtbl.add ctx.declared_registers reg ();
                 "" (* Skip the simple type processing below *)
            )
      in
      (* Handle simple types that use alias names *)
      if effective_type <> "" then (
        let var_name = get_meaningful_var_name ctx reg reg_type in
        let simple_decl = sprintf "%s %s;" effective_type var_name in
        register_declarations := simple_decl :: !register_declarations;
        Hashtbl.add ctx.declared_registers reg ()
      )
    )
  ) all_registers;
  
  (* Emit all variable declarations *)
  let sorted_declarations = List.sort String.compare (List.rev !register_declarations) in
  List.iter (emit_line ctx) sorted_declarations;
  if all_registers <> [] then emit_blank_line ctx;
  
  (* Generate basic blocks *)
  List.iter (generate_c_basic_block ctx) ir_func.basic_blocks;
  
  decrease_indent ctx;
  emit_line ctx "}";
  emit_blank_line ctx

(** Generate complete C program from IR *)

let generate_c_program ?_config_declarations ir_prog =
  let ctx = create_c_context () in
  
  (* Initialize modular context code generators *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  (* Add standard includes *)
  let program_types = [ir_prog.program_type] in
  generate_includes ctx ~program_types ();
  
  (* Generate string type definitions *)
  let temp_multi_prog = {
    source_name = ir_prog.name;
    programs = [ir_prog];
    kernel_functions = [];
    global_maps = [];
    global_configs = [];
    global_variables = [];
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = None;
    userspace_bindings = [];
    ring_buffer_registry = Ir.create_empty_ring_buffer_registry ();
    multi_pos = ir_prog.ir_pos;
  } in
  generate_string_typedefs ctx temp_multi_prog;
  
  (* Generate enum definitions *)
  generate_enum_definitions ctx temp_multi_prog;
  
  (* Struct definitions are generated in the main entry point to avoid duplication *)
  
  (* Generate type alias definitions *)
  let type_aliases = collect_type_aliases_from_multi_program temp_multi_prog in
  generate_type_alias_definitions ctx type_aliases;
  
  (* Generate config maps from temporary multi-program structure *)
  if temp_multi_prog.global_configs <> [] then
    List.iter (generate_config_map_definition ctx) temp_multi_prog.global_configs;

  (* With attributed functions, all maps are global - no program-scoped maps *)
  
  (* Generate entry function - this will collect callbacks *)
  generate_c_function ctx ir_prog.entry_function;
  
  (* Now emit any pending callbacks before other functions *)
  if ctx.pending_callbacks <> [] then (
    (* Insert callbacks at the beginning of the output, after includes and maps *)
    let current_output = ctx.output_lines in
    ctx.output_lines <- [];
    List.iter (emit_line ctx) ctx.pending_callbacks;
    ctx.pending_callbacks <- [];
    emit_blank_line ctx;
    (* Prepend current output *)
    ctx.output_lines <- current_output @ ctx.output_lines;
  );
  
  (* With attributed functions, each program has only the entry function - no nested functions *)
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" ctx.output_lines

(** Generate complete C program from multiple IR programs *)

let generate_c_multi_program ?_config_declarations ?(type_aliases=[]) ?(variable_type_aliases=[]) ir_multi_prog =
  let ctx = create_c_context () in
  
  (* Initialize modular context code generators *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  Kernelscript_context.Kprobe_codegen.register ();
  Kernelscript_context.Tracepoint_codegen.register ();
  
  (* Store variable type aliases for later lookup *)
  ctx.variable_type_aliases <- variable_type_aliases;
  
  (* Add standard includes *)
  let program_types = List.map (fun prog -> prog.program_type) ir_multi_prog.programs in
  generate_includes ctx ~program_types ();
  
  (* Generate string type definitions *)
      generate_string_typedefs ctx ir_multi_prog;
  
  (* Generate enum definitions *)
      generate_enum_definitions ctx ir_multi_prog;
  
  (* Generate declarations in original AST order to preserve source order *)
      generate_declarations_in_source_order ctx ir_multi_prog type_aliases;
  
  (* Generate struct definitions *)
      let struct_defs = collect_struct_definitions_from_multi_program ir_multi_prog in
  generate_struct_definitions ctx struct_defs;
  
  (* Generate config maps from IR multi-program *)
      if ir_multi_prog.global_configs <> [] then
    List.iter (generate_config_map_definition ctx) ir_multi_prog.global_configs;
  
  (* Generate global map definitions *)
      List.iter (generate_map_definition ctx) ir_multi_prog.global_maps;
  
  (* Generate global variables BEFORE functions that use them *)
      generate_global_variables ctx ir_multi_prog.global_variables;
  
  (* Generate struct_ops definitions and instances *)
      generate_struct_ops ctx ir_multi_prog;
  
  (* With attributed functions, all maps are global - no program-scoped maps *)
  
  (* First pass: collect all callbacks *)
  let temp_ctx = create_c_context () in
  List.iter (fun ir_prog ->
    (* With attributed functions, each program has only its entry function *)
    generate_c_function temp_ctx ir_prog.entry_function
  ) ir_multi_prog.programs;
  
  (* Emit collected callbacks *)
  if temp_ctx.pending_callbacks <> [] then (
    List.iter (emit_line ctx) temp_ctx.pending_callbacks;
    emit_blank_line ctx;
  );
  
  (* Generate kernel functions once - they are shared across all programs *)
      List.iter (generate_c_function ctx) ir_multi_prog.kernel_functions;

  (* Generate attributed functions (each program has only the entry function) *)
  List.iter (fun ir_prog ->
    (* With attributed functions, each program contains only its entry function - no nested functions *)
    generate_c_function ctx ir_prog.entry_function
  ) ir_multi_prog.programs;
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" ctx.output_lines



(** Main compilation entry point *)

let compile_to_c ?_config_declarations ir_program =
  let c_code = generate_c_program ?_config_declarations ir_program in
  c_code

(** Helper function to write C code to file *)

let write_c_to_file ir_program filename =
  let c_code = compile_to_c ir_program in
  let oc = open_out filename in
  output_string oc c_code;
  close_out oc;
  c_code

(** Helper function to compile C code to eBPF object *)

let compile_c_to_ebpf c_filename obj_filename =
  let cmd = sprintf "clang -target bpf -O2 -g -c %s -o %s" c_filename obj_filename in
  let exit_code = Sys.command cmd in
  if exit_code = 0 then
    Ok obj_filename
  else
    Error (sprintf "Compilation failed with exit code %d" exit_code)

(** Generate config access expression *)
let generate_config_access _ctx config_name field_name =
  sprintf "get_%s_config()->%s" config_name field_name

(** Generate ProgArray map for tail calls *)
let generate_prog_array_map ctx prog_array_size =
  if prog_array_size > 0 then (
    emit_line ctx "/* eBPF program array for tail calls */";
    emit_line ctx "struct {";
    increase_indent ctx;
    emit_line ctx "__uint(type, BPF_MAP_TYPE_PROG_ARRAY);";
    emit_line ctx (sprintf "__uint(max_entries, %d);" prog_array_size);
    emit_line ctx "__uint(key_size, sizeof(__u32));";
    emit_line ctx "__uint(value_size, sizeof(__u32));";
    decrease_indent ctx;
    emit_line ctx "} prog_array SEC(\".maps\");";
    emit_blank_line ctx
  )

(** Compile multi-program IR to eBPF C code with automatic tail call detection *)
let compile_multi_to_c_with_tail_calls 
    ?(_config_declarations=[]) ?(type_aliases=[]) ?(variable_type_aliases=[]) ?(kfunc_declarations=[]) ?symbol_table ?(tail_call_analysis=None)
    (ir_multi_prog : Ir.ir_multi_program) =
  
  let ctx = create_c_context () in
  
  (* Initialize modular context code generators *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  Kernelscript_context.Kprobe_codegen.register ();
  Kernelscript_context.Tracepoint_codegen.register ();
  
  (* Generate headers and includes *)
  let program_types = List.map (fun ir_prog -> ir_prog.program_type) ir_multi_prog.programs in
  generate_includes ctx ~program_types ();
  
  (* Generate dynptr safety macros and helper functions *)
  emit_line ctx "/* eBPF Dynptr API integration for enhanced pointer safety */";
  emit_line ctx "/* Using system-provided bpf_dynptr_* helper functions from bpf_helpers.h */";
  emit_blank_line ctx;
  
  (* Generate enhanced dynptr safety macros *)
  emit_line ctx "/* Enhanced dynptr safety macros */";
  emit_line ctx "#define DYNPTR_SAFE_ACCESS(dynptr, offset, size, type) \\";
  emit_line ctx "    ({ \\";
  emit_line ctx "        type *__ptr = (type*)bpf_dynptr_data(dynptr, offset, sizeof(type)); \\";
  emit_line ctx "        __ptr ? *__ptr : (type){0}; \\";
  emit_line ctx "    })";
  emit_blank_line ctx;
  
  emit_line ctx "#define DYNPTR_SAFE_WRITE(dynptr, offset, value, type) \\";
  emit_line ctx "    ({ \\";
  emit_line ctx "        type __tmp = (value); \\";
  emit_line ctx "        bpf_dynptr_write(dynptr, offset, &__tmp, sizeof(type), 0); \\";
  emit_line ctx "    })";
  emit_blank_line ctx;
  
  emit_line ctx "#define DYNPTR_SAFE_READ(dst, dynptr, offset, type) \\";
  emit_line ctx "    bpf_dynptr_read(dst, sizeof(type), dynptr, offset, 0)";
  emit_blank_line ctx;
  
  (* Fallback macros for regular pointers *)
  emit_line ctx "/* Fallback macros for regular pointer operations */";
  emit_line ctx "#define SAFE_DEREF(ptr) \\";
  emit_line ctx "    ({ \\";
  emit_line ctx "        typeof(*ptr) __val = {0}; \\";
  emit_line ctx "        if (ptr) { \\";
  emit_line ctx "            __builtin_memcpy(&__val, ptr, sizeof(__val)); \\";
  emit_line ctx "        } \\";
  emit_line ctx "        __val; \\";
  emit_line ctx "    })";
  emit_blank_line ctx;
  
  emit_line ctx "#define SAFE_PTR_ACCESS(ptr, field) \\";
  emit_line ctx "    ({ \\";
  emit_line ctx "        typeof((ptr)->field) __val = {0}; \\";
  emit_line ctx "        if (ptr) { \\";
  emit_line ctx "            __val = (ptr)->field; \\";
  emit_line ctx "        } \\";
  emit_line ctx "        __val; \\";
  emit_line ctx "    })";
  emit_blank_line ctx;
  
  (* Store variable type aliases for later lookup *)
  ctx.variable_type_aliases <- variable_type_aliases;
  
  (* Generate kfunc declarations *)
  let rec ast_type_to_c_type ast_type =
    match ast_type with
    | Ast.U8 -> "__u8" | Ast.U16 -> "__u16" | Ast.U32 -> "__u32" | Ast.U64 -> "__u64"
    | Ast.I8 -> "__s8" | Ast.I16 -> "__s16" | Ast.I32 -> "__s32" | Ast.I64 -> "__s64"
    | Ast.Bool -> "bool" | Ast.Char -> "char" | Ast.Void -> "void"
    | Ast.Pointer inner_type -> sprintf "%s*" (ast_type_to_c_type inner_type)
    | _ -> "void"
  in
  List.iter (fun kfunc ->
    let params_str = String.concat ", " (List.map (fun (name, param_type) ->
      let c_type = ast_type_to_c_type param_type in
      sprintf "%s %s" c_type name
    ) kfunc.Ast.func_params) in
    let return_type_str = match Ast.get_return_type kfunc.Ast.func_return_type with
      | Some ret_type -> ast_type_to_c_type ret_type
      | None -> "void"
    in
    emit_line ctx (sprintf "/* kfunc declaration */");
    emit_line ctx (sprintf "%s %s(%s);" return_type_str kfunc.Ast.func_name params_str);
  ) kfunc_declarations;
  
  if kfunc_declarations <> [] then emit_blank_line ctx;
  
  (* Generate string type definitions *)
  generate_string_typedefs ctx ir_multi_prog;
  
  (* Generate enum definitions *)
  generate_enum_definitions ?symbol_table ctx ir_multi_prog;
  
  (* Generate declarations in original AST order to preserve source order *)
  generate_declarations_in_source_order ctx ir_multi_prog type_aliases;
  
  (* Generate struct definitions *)
  let struct_defs = collect_struct_definitions_from_multi_program ir_multi_prog in
  generate_struct_definitions ctx struct_defs;
  
  (* Generate global map definitions BEFORE functions that use them *)
  List.iter (generate_map_definition ctx) ir_multi_prog.global_maps;
  
  (* Generate config maps from IR multi-program BEFORE functions that use them *)
  if ir_multi_prog.global_configs <> [] then
    List.iter (generate_config_map_definition ctx) ir_multi_prog.global_configs;
  
  (* Generate ProgArray map BEFORE functions that use it *)
  let prog_array_size = match tail_call_analysis with
    | Some analysis -> analysis.Tail_call_analyzer.prog_array_size
    | None -> 0
  in
  
  if prog_array_size > 0 then
    generate_prog_array_map ctx prog_array_size;
  
  (* Generate global variables BEFORE functions that use them *)
  generate_global_variables ctx ir_multi_prog.global_variables;
  
  (* Generate kernel functions once - they are shared across all programs *)
  List.iter (generate_c_function ctx) ir_multi_prog.kernel_functions;

  (* First pass: collect all callbacks *)
  let temp_ctx = create_c_context () in
      List.iter (fun ir_prog ->
      generate_c_function temp_ctx ir_prog.entry_function
   ) ir_multi_prog.programs;
  
  (* Emit collected callbacks BEFORE the actual functions *)
  if temp_ctx.pending_callbacks <> [] then (
    List.iter (emit_line ctx) temp_ctx.pending_callbacks;
    emit_blank_line ctx;
  );
  
  (* Generate C functions for each eBPF program after maps and configs are defined *)
  List.iter (fun ir_prog ->
    generate_c_function ctx ir_prog.entry_function
  ) ir_multi_prog.programs;

  (* Generate struct_ops definitions and instances after functions are defined *)
  generate_struct_ops ctx ir_multi_prog;
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Create or use provided tail call analysis result *)
  let final_tail_call_analysis = match tail_call_analysis with
    | Some analysis -> analysis
    | None -> {
        Tail_call_analyzer.dependencies = [];
        prog_array_size = 0;
        index_mapping = Hashtbl.create 0;
        errors = [];
      }
  in
  
  (* Assemble final output *)
  let final_output = String.concat "\n" ctx.output_lines in
  
  (final_output, final_tail_call_analysis)

(** Multi-program compilation entry point with automatic tail call handling *)

let compile_multi_to_c ?(_config_declarations=[]) ?(type_aliases=[]) ?(variable_type_aliases=[]) ?(tail_call_analysis=None) ir_multi_program =
  (* Always use the intelligent tail call compilation that auto-detects and handles tail calls *)
  let (c_code, _final_tail_call_analysis) = compile_multi_to_c_with_tail_calls 
    ~type_aliases ~variable_type_aliases ~tail_call_analysis ir_multi_program in
  
  (* Tail call analysis results calculated and stored *)
  c_code

(** Multi-program compilation entry point that returns both code and tail call analysis *)

let compile_multi_to_c_with_analysis ?(_config_declarations=[]) ?(type_aliases=[]) ?(variable_type_aliases=[]) ?(kfunc_declarations=[]) ?symbol_table ?(tail_call_analysis=None) ir_multi_program =
  (* Always use the intelligent tail call compilation that auto-detects and handles tail calls *)
      let (c_code, final_tail_call_analysis) = compile_multi_to_c_with_tail_calls 
        ~type_aliases ~variable_type_aliases ~kfunc_declarations ?symbol_table ~tail_call_analysis ir_multi_program in
  
  (* Tail call analysis results calculated and stored *)
  (c_code, final_tail_call_analysis)


