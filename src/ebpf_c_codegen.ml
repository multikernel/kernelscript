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
}

(** Helper functions for code generation *)

let indent ctx = String.make (ctx.indent_level * 4) ' '

let emit_line ctx line =
  ctx.output_lines <- (indent ctx ^ line) :: ctx.output_lines

let emit_blank_line ctx =
  ctx.output_lines <- "" :: ctx.output_lines

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

(** Type conversion from IR types to C types *)

let rec ebpf_type_from_ir_type = function
  | IRU8 -> "__u8"
  | IRU16 -> "__u16" 
  | IRU32 -> "__u32"
  | IRU64 -> "__u64"
  | IRI8 -> "__s8"
  | IRF32 -> "__u32" (* Fixed point representation in kernel *)
  | IRF64 -> "__u64" (* Fixed point representation in kernel *)
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
  | IRContext XdpCtx -> "struct xdp_md*"
  | IRContext TcCtx -> "struct __sk_buff*"
  | IRContext KprobeCtx -> "struct pt_regs*"
  | IRContext UprobeCtx -> "struct pt_regs*"
  | IRContext TracepointCtx -> "void*"
  | IRContext LsmCtx -> "void*"
  | IRContext CgroupSkbCtx -> "struct __sk_buff*"
  | IRAction XdpActionType -> "int"
  | IRAction TcActionType -> "int"
  | IRAction GenericActionType -> "int"

(** Map type conversion *)

let ir_map_type_to_c_type = function
  | IRHashMap -> "BPF_MAP_TYPE_HASH"
  | IRMapArray -> "BPF_MAP_TYPE_ARRAY"
  | IRPercpuHash -> "BPF_MAP_TYPE_PERCPU_HASH"
  | IRPercpuArray -> "BPF_MAP_TYPE_PERCPU_ARRAY"
  | IRLruHash -> "BPF_MAP_TYPE_LRU_HASH"
  | IRRingBuffer -> "BPF_MAP_TYPE_RINGBUF"
  | IRPerfEvent -> "BPF_MAP_TYPE_PERF_EVENT_ARRAY"
  | IRDevMap -> "BPF_MAP_TYPE_DEVMAP"

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

let rec collect_string_sizes_from_instr ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest_val, expr) -> 
      (collect_string_sizes_from_value dest_val) @ (collect_string_sizes_from_expr expr)
  | IRConstAssign (dest_val, expr) -> 
      (collect_string_sizes_from_value dest_val) @ (collect_string_sizes_from_expr expr)
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
  | IRContextAccess (dest_val, _access_type) -> 
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

let collect_string_sizes_from_function ir_func =
  List.fold_left (fun acc block ->
    List.fold_left (fun acc instr ->
      acc @ (collect_string_sizes_from_instr instr)
    ) acc block.instructions
  ) [] ir_func.basic_blocks

let collect_string_sizes_from_multi_program ir_multi_prog =
  List.fold_left (fun acc ir_prog ->
    let entry_sizes = collect_string_sizes_from_function ir_prog.entry_function in
    acc @ entry_sizes
  ) [] ir_multi_prog.programs

(** Collect enum definitions from IR types *)
let collect_enum_definitions ir_multi_prog =
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
    collect_from_type ir_val.val_type
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
  in
  
  let rec collect_from_instr ir_instr =
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
let generate_enum_definitions ctx ir_multi_prog =
  let enum_map = collect_enum_definitions ir_multi_prog in
  if Hashtbl.length enum_map > 0 then (
    emit_line ctx "/* Enum definitions */";
    Hashtbl.iter (fun enum_name enum_values ->
      generate_enum_definition ctx enum_name enum_values
    ) enum_map;
    emit_blank_line ctx
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
    | IRStruct (name, fields) ->
        if not (List.mem_assoc name !struct_defs) then (
          (* Only collect structs that actually have fields - ignore empty structs that are likely type aliases *)
          if fields <> [] then
            struct_defs := (name, fields) :: !struct_defs
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
  
  (* Also collect from kernel functions *)
  List.iter collect_from_function ir_multi_prog.kernel_functions;
  
  List.rev !struct_defs

(** Generate struct definitions *)
let generate_struct_definitions ctx struct_defs =
  if struct_defs <> [] then (
    emit_line ctx "/* Struct definitions */";
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
        | _ ->
            let c_type = ebpf_type_from_ir_type field_type in
            sprintf "%s %s;" c_type field_name
        in
        emit_line ctx field_declaration
      ) fields;
      decrease_indent ctx;
      emit_line ctx "};"
    ) struct_defs;
    emit_blank_line ctx
  )

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
              | Ast.U8 -> "uint8_t"
              | Ast.U16 -> "uint16_t"
              | Ast.U32 -> "uint32_t"
              | Ast.U64 -> "uint64_t"
              | _ -> "uint8_t"
            in
            (* Array typedef syntax: typedef element_type alias_name[size]; *)
            emit_line ctx (sprintf "typedef %s %s[%d];" element_c_type alias_name size)
        | _ ->
            let c_type = match underlying_type with
              | Ast.U8 -> "uint8_t"
              | Ast.U16 -> "uint16_t"
              | Ast.U32 -> "uint32_t"
              | Ast.U64 -> "uint64_t"
              | Ast.I8 -> "int8_t"
              | Ast.I16 -> "int16_t"
              | Ast.I32 -> "int32_t"
              | Ast.I64 -> "int64_t"
              | Ast.Bool -> "bool"
              | Ast.Char -> "char"
              | _ -> "uint32_t" (* fallback *)
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
let generate_declarations_in_source_order ctx ir_multi_program type_aliases =
  (* We need to generate declarations in the order they appeared in the original source.
     Since we don't have direct access to the AST here, we need to reconstruct the order.
     For now, we'll use a simple heuristic: type aliases first, then structs. *)
  
  (* Generate type alias definitions from AST first *)
  generate_ast_type_alias_definitions ctx type_aliases;
  
  (* Generate config maps if provided *)
  if ir_multi_program.global_configs <> [] then
    List.iter (generate_config_map_definition ctx) ir_multi_program.global_configs;

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
    (* Reverse and prepend current output *)
    ctx.output_lines <- (List.rev current_output) @ ctx.output_lines;
  );
  
  (* With attributed functions, each program has only the entry function - no nested functions *)
  
  (* Function has side effects on ctx, no return value needed *)
  ()

(** Generate standard eBPF includes *)

let generate_includes ctx ?(program_types=[]) ?(include_builtin_headers=false) () =
  let standard_includes = [
    "#include <linux/bpf.h>";
    "#include <bpf/bpf_helpers.h>";
    "#include <linux/if_ether.h>";
    "#include <linux/ip.h>";
    "#include <linux/in.h>";
    "#include <linux/if_xdp.h>";
    "#include <linux/types.h>";
  ] in
  
  (* Get context-specific includes *)
  let context_includes = List.fold_left (fun acc prog_type ->
    let context_type = match prog_type with
      | Ast.Xdp -> Some "xdp"
      | Ast.Tc -> Some "tc"
      | Ast.Kprobe -> Some "kprobe"
      | _ -> None
    in
    match context_type with
    | Some ctx_type -> 
        let includes = Kernelscript_context.Context_codegen.get_context_includes ctx_type in
        acc @ includes
    | None -> acc
  ) [] program_types in
  
  (* Remove duplicates between standard and context includes *)
  let unique_context_includes = List.filter (fun inc -> 
    not (List.mem inc standard_includes)) context_includes in
  
  (* Only add builtin headers if explicitly requested (for debugging/testing) *)
  let builtin_includes = if include_builtin_headers then
    List.fold_left (fun acc prog_type ->
      match prog_type with
      | Ast.Xdp -> "#include \"xdp.h\"" :: acc
      | Ast.Tc -> "#include \"tc.h\"" :: acc
      | Ast.Kprobe -> "#include \"kprobe.h\"" :: acc
      | _ -> acc
    ) [] program_types
  else
    [] (* Skip builtin headers - enum constants come from system headers *)
  in
  
  let all_includes = standard_includes @ unique_context_includes @ (List.rev builtin_includes) in
  List.iter (fun inc -> ctx.output_lines <- inc :: ctx.output_lines) (List.rev all_includes);
  emit_blank_line ctx

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
    (* TODO: Generate actual struct_ops map definition *)
    emit_line ctx (sprintf "/* struct_ops map for %s would be defined here */" struct_ops_inst.ir_instance_name);
    emit_blank_line ctx
  ) ir_multi_program.struct_ops_instances

(** Generate C expression from IR value *)

let generate_c_value ctx ir_val =
  match ir_val.value_desc with
  | IRLiteral (IntLit (i, original_opt)) -> 
      (* Use original format if available, otherwise use decimal *)
      (match original_opt with
       | Some orig when String.contains orig 'x' || String.contains orig 'X' -> orig
       | Some orig when String.contains orig 'b' || String.contains orig 'B' -> orig
       | _ -> string_of_int i)
  | IRLiteral (BoolLit b) -> if b then "true" else "false"
  | IRLiteral (CharLit c) -> sprintf "'%c'" c
  | IRLiteral (NullLit) -> "NULL"
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
  | IRLiteral (ArrayLit _) -> "/* Array literal not supported */"
  | IRVariable name -> 
      (* Check if this is a config access *)
      if String.contains name '.' then
        let parts = String.split_on_char '.' name in
        match parts with
        | [config_name; field_name] -> 
            (* Generate safe config access with NULL check *)
            sprintf "({ struct %s_config *cfg = get_%s_config(); cfg ? cfg->%s : 0; })" 
              config_name config_name field_name
        | _ -> name
      else
        name  (* Function parameters and regular variables use their names directly *)
  | IRRegister reg -> sprintf "tmp_%d" reg  (* Registers are always temporary variables *)
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
  | IRValue ir_val -> generate_c_value ctx ir_val
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
           (* Regular binary operation *)
           let left_str = generate_c_value ctx left in
           let right_str = generate_c_value ctx right in
           let op_str = match op with
             | IRAdd -> "+" | IRSub -> "-" | IRMul -> "*" | IRDiv -> "/" | IRMod -> "%"
             | IREq -> "==" | IRNe -> "!=" | IRLt -> "<" | IRLe -> "<=" | IRGt -> ">" | IRGe -> ">="
             | IRAnd -> "&&" | IROr -> "||"
             | IRBitAnd -> "&" | IRBitOr -> "|" | IRBitXor -> "^"
             | IRShiftL -> "<<" | IRShiftR -> ">>"
           in
           sprintf "(%s %s %s)" left_str op_str right_str)
  | IRUnOp (op, ir_val) ->
      let val_str = generate_c_value ctx ir_val in
      (match op with
       | IRDeref ->
           (* Use enhanced semantic analysis to determine appropriate access method *)
           (match detect_memory_region_enhanced ir_val with
            | PacketData ->
                (* Packet data - use bpf_dynptr_from_xdp *)
                (match ir_val.val_type with
                 | IRPointer (inner_type, _) ->
                     let c_type = ebpf_type_from_ir_type inner_type in
                     let size = match inner_type with
                       | IRI8 | IRU8 -> 1 | IRU16 -> 2 | IRU32 -> 4 | IRU64 -> 8 | _ -> 4
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
                       | IRI8 | IRU8 -> 1 | IRU16 -> 2 | IRU32 -> 4 | IRU64 -> 8 | _ -> 4
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
       | IRAddressOf ->
           (* Address-of operation *)
           sprintf "(&%s)" val_str
       | IRNot | IRNeg | IRBitNot ->
           (* Standard unary operations *)
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
                let field_size = 4 in (* Default - should be calculated from struct *)
                let full_struct_name = sprintf "struct %s" struct_name in
                sprintf "({ __typeof(((%s*)0)->%s) __field_val = 0; struct bpf_dynptr __pkt_dynptr; if (bpf_dynptr_from_xdp(&__pkt_dynptr, ctx) == 0) { void* __field_data = bpf_dynptr_data(&__pkt_dynptr, (%s - (void*)(long)ctx->data) + __builtin_offsetof(%s, %s), %d); if (__field_data) __field_val = *(__typeof(((%s*)0)->%s)*)__field_data; } __field_val; })" 
                  full_struct_name field obj_str full_struct_name field field_size full_struct_name field
            | _ -> sprintf "SAFE_PTR_ACCESS(%s, %s)" obj_str field)
       
               | _ when is_map_value_parameter obj_val ->
            (* Map value field access - use bpf_dynptr_from_mem *)
            (match obj_val.val_type with
             | IRPointer (IRStruct (struct_name, _), _) ->
                 let field_size = 4 in (* Default - should be calculated from struct *)
                 let full_struct_name = sprintf "struct %s" struct_name in
                 sprintf "({ __typeof(((%s*)0)->%s) __field_val = 0; struct bpf_dynptr __mem_dynptr; if (bpf_dynptr_from_mem(%s, sizeof(%s), 0, &__mem_dynptr) == 0) { void* __field_data = bpf_dynptr_data(&__mem_dynptr, __builtin_offsetof(%s, %s), %d); if (__field_data) __field_val = *(__typeof(((%s*)0)->%s)*)__field_data; } __field_val; })" 
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
                 (* Direct struct field access *)
                 sprintf "%s.%s" obj_str field))
      
  | IRStructLiteral (_struct_name, field_assignments) ->
      (* Generate C struct literal: {.field1 = value1, .field2 = value2} *)
      let field_strs = List.map (fun (field_name, field_val) ->
        let field_value_str = generate_c_value ctx field_val in
        sprintf ".%s = %s" field_name field_value_str
      ) field_assignments in
      sprintf "{%s}" (String.concat ", " field_strs)



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
      (* Handle key - create temp variable if it's a literal *)
      let key_var = match key_val.value_desc with
        | IRLiteral _ -> 
            let temp_key = fresh_var ctx "key" in
            let key_type = ebpf_type_from_ir_type key_val.val_type in
            let key_str = generate_c_value ctx key_val in
            emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
            temp_key
        | _ -> generate_c_value ctx key_val
      in
      (* bpf_map_lookup_elem returns a pointer, so we need to dereference it *)
      emit_line ctx (sprintf "{ void* __tmp_ptr = bpf_map_lookup_elem(%s, &%s);" map_str key_var);
      emit_line ctx (sprintf "  if (__tmp_ptr) %s = *(%s*)__tmp_ptr;" dest_str (ebpf_type_from_ir_type dest_val.val_type));
      (* Handle fallback value based on type *)
      let fallback_value = match dest_val.val_type with
        | IRStruct (_, _) -> sprintf "(%s){0}" (ebpf_type_from_ir_type dest_val.val_type)
        | _ -> "0"
      in
      emit_line ctx (sprintf "  else %s = %s; }" dest_str fallback_value)
  | MapPeek ->
      emit_line ctx (sprintf "%s = bpf_ringbuf_reserve(%s, sizeof(*%s), 0);" dest_str map_str dest_str)

let generate_map_store ctx map_val key_val value_val store_type =
  let map_str = generate_c_value ctx map_val in
  
  match store_type with
  | DirectStore ->
      let value_str = generate_c_value ctx value_val in
      emit_line ctx (sprintf "*%s = %s;" map_str value_str)
  | MapUpdate ->
      (* Handle key - create temp variable if it's a literal *)
      let key_var = match key_val.value_desc with
        | IRLiteral _ -> 
            let temp_key = fresh_var ctx "key" in
            let key_type = ebpf_type_from_ir_type key_val.val_type in
            let key_str = generate_c_value ctx key_val in
            emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
            temp_key
        | _ -> generate_c_value ctx key_val
      in
      
      (* Handle value - create temp variable if it's a literal *)
      let value_var = match value_val.value_desc with
        | IRLiteral _ ->
            let temp_value = fresh_var ctx "value" in
            let value_type = ebpf_type_from_ir_type value_val.val_type in
            let value_str = generate_c_value ctx value_val in
            emit_line ctx (sprintf "%s %s = %s;" value_type temp_value value_str);
            temp_value
        | _ -> generate_c_value ctx value_val
      in
      
      emit_line ctx (sprintf "bpf_map_update_elem(%s, &%s, &%s, BPF_ANY);" map_str key_var value_var)
  | MapPush ->
      let value_str = generate_c_value ctx value_val in
      emit_line ctx (sprintf "bpf_ringbuf_submit(%s, 0);" value_str)

let generate_map_delete ctx map_val key_val =
  let map_str = generate_c_value ctx map_val in
  
  (* Handle key - create temp variable if it's a literal *)
  let key_var = match key_val.value_desc with
    | IRLiteral _ -> 
        let temp_key = fresh_var ctx "key" in
        let key_type = ebpf_type_from_ir_type key_val.val_type in
        let key_str = generate_c_value ctx key_val in
        emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
        temp_key
    | _ -> generate_c_value ctx key_val
  in
  
  emit_line ctx (sprintf "bpf_map_delete_elem(%s, &%s);" map_str key_var)



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
  
  (* Check if this is a string assignment *)
  (match dest_val.val_type, expr.expr_desc with
   | IRStr _, IRValue src_val when (match src_val.val_type with IRStr _ -> true | _ -> false) ->
       (* String to string assignment - need to copy struct *)
       let dest_str = generate_c_value ctx dest_val in
       let src_str = generate_c_value ctx src_val in
       emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str src_str)
   | IRStr _size, IRValue src_val when (match src_val.value_desc with IRLiteral (StringLit _) -> true | _ -> false) ->
       (* String literal to string assignment - already handled in generate_c_value *)
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
            emit_line ctx (sprintf "%s%s = %s;" assignment_prefix dest_str expr_str)))

let rec generate_c_instruction ctx ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest_val, expr) ->
      (* Regular assignment without const keyword *)
      generate_assignment ctx dest_val expr false
      
  | IRConstAssign (dest_val, expr) ->
      (* Const assignment with const keyword *)
      generate_assignment ctx dest_val expr true
      
  | IRCall (name, args, ret_opt) ->
      (* Check if this is a built-in function that needs context-specific translation *)
      let (actual_name, translated_args) = match Stdlib.get_ebpf_implementation name with
        | Some ebpf_impl ->
            (* This is a built-in function - translate for eBPF context *)
            (match name with
             | "print" -> 
                 (* Helper function to generate proper C arg based on IR type *)
                 let generate_print_arg ir_val =
                   let base_arg = generate_c_value ctx ir_val in
                   match ir_val.val_type with
                   | IRStr _ -> base_arg ^ ".data"  (* String types need .data field *)
                   | _ -> base_arg  (* Other types use as-is *)
                 in
                 (* Special handling for print: convert to bpf_printk format *)
                 (match args with
                  | [] -> (ebpf_impl, ["\"\""])
                  | [first_ir] -> 
                      (* For string struct arguments, use .data field *)
                      let first_arg = generate_print_arg first_ir in
                      (ebpf_impl, [sprintf "\"%s\"" "%s"; first_arg])
                  | first_ir :: rest_ir ->
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
                     let format_specifiers = List.map (fun _ -> "%d") limited_rest in
                     let format_str = sprintf "\"%s%s\"" "%s" (String.concat " " format_specifiers) in
                     (* Generate first argument with proper type handling *)
                     let first_arg = generate_print_arg first_ir in
                     (* Generate remaining arguments *)
                     let rest_args = List.map (generate_c_value ctx) limited_rest in
                     (ebpf_impl, format_str :: first_arg :: rest_args))
             | _ -> 
                 (* For other built-in functions, use standard conversion *)
                 let c_args = List.map (generate_c_value ctx) args in
                 (ebpf_impl, c_args))
        | None ->
            (* Regular function call *)
            let c_args = List.map (generate_c_value ctx) args in
            (name, c_args)
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

  | IRConfigFieldUpdate (_map_val, _key_val, _field, _value_val) ->
      (* Config field updates should never occur in eBPF programs - they are read-only *)
      failwith "Internal error: Config field updates in eBPF programs should have been caught during type checking - configs are read-only in kernel space"

  | IRStructFieldAssignment (obj_val, field_name, value_val) ->
      (* Enhanced struct field assignment with safety checks *)
      let obj_str = generate_c_value ctx obj_val in
      let value_str = generate_c_value ctx value_val in
      
      (* Use enhanced semantic analysis for field assignment *)
      (match detect_memory_region_enhanced obj_val with
               | PacketData ->
            (* Packet data field assignment - use dynptr API for safe write *)
            (match obj_val.val_type with
             | IRPointer (IRStruct (struct_name, _), _) ->
                 let field_size = 4 in (* Default - should be calculated from struct *)
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
                 let field_size = 4 in
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
                 (* Direct struct field assignment *)
                 emit_line ctx (sprintf "%s.%s = %s;" obj_str field_name value_str)))
      
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
      
  | IRContextAccess (dest_val, access_type) ->
      let dest_str = generate_c_value ctx dest_val in
      (* Map access type to context field name and determine context type *)
      let (ctx_type_str, field_name) = match access_type with
        | PacketData -> ("xdp", "data")
        | PacketEnd -> ("xdp", "data_end") 
        | DataMeta -> ("xdp", "data_meta")
        | IngressIfindex -> ("xdp", "ingress_ifindex")
        | DataLen -> ("tc", "len") (* TC-specific *)
        | MarkField -> ("tc", "mark") (* TC-specific *)
        | Priority -> ("tc", "priority") (* TC-specific *)
        | CbField -> ("tc", "cb") (* TC-specific *)
      in
      (* Use modular context code generation *)
      let access_str = Kernelscript_context.Context_codegen.generate_context_field_access ctx_type_str "ctx" field_name in
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
      let cond_str = generate_c_value ctx cond_val in
      
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

  | IRReturn ret_opt ->
      begin match ret_opt with
      | Some ret_val ->
          let ret_str = match ret_val.value_desc with
            (* Use context-specific action constant mapping *)
            | IRLiteral (IntLit (i, _)) when ret_val.val_type = IRAction XdpActionType ->
                (match Kernelscript_context.Context_codegen.map_context_action_constant "xdp" i with
                 | Some action -> action
                 | None -> string_of_int i)
            | IRLiteral (IntLit (i, _)) when ret_val.val_type = IRAction TcActionType ->
                (match Kernelscript_context.Context_codegen.map_context_action_constant "tc" i with
                 | Some action -> action
                 | None -> string_of_int i)
            | _ -> generate_c_value ctx ret_val
          in
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
        in
                 let collect_in_instr ir_instr =
           match ir_instr.instr_desc with
           | IRAssign (dest_val, expr) -> collect_in_value dest_val; collect_in_expr expr
           | IRMapStore (map_val, key_val, value_val, _) ->
               collect_in_value map_val; collect_in_value key_val; collect_in_value value_val
           | _ -> () (* Add other cases as needed *)
        in
        collect_in_instr ir_instr
      in
      
      (* Collect registers from all body instructions *)
      List.iter collect_callback_registers body_instructions;
      
      (* Declare the loop counter variable in callback scope *)
      let counter_type = ebpf_type_from_ir_type counter_val.val_type in
      emit_line callback_ctx (sprintf "%s %s = index;" counter_type counter_var_name);
      
      (* Declare all other registers used in the callback *)
      List.iter (fun (reg, reg_type) ->
        let c_type = ebpf_type_from_ir_type reg_type in
        let reg_name = sprintf "tmp_%d" reg in
        if reg_name <> counter_var_name then
          emit_line callback_ctx (sprintf "%s %s;" c_type reg_name)
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
      
      (* Store callback for later emission - reverse to get correct order *)
      ctx.pending_callbacks <- (List.rev callback_ctx.output_lines) @ ctx.pending_callbacks;
      
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

(** Generate C code for basic block *)

let generate_c_basic_block ctx ir_block =
  (* Emit label *)
  if ir_block.label <> "entry" then (
    decrease_indent ctx;
    emit_line ctx (sprintf "%s:" ir_block.label);
    increase_indent ctx
  );
  
  (* Emit instructions *)
  List.iter (generate_c_instruction ctx) ir_block.instructions

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
  in
  let rec collect_in_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> collect_in_value dest_val; collect_in_expr expr
    | IRConstAssign (dest_val, expr) -> collect_in_value dest_val; collect_in_expr expr
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
    | IRContextAccess (dest_val, _access_type) -> collect_in_value dest_val
    | IRBoundsCheck (ir_val, _, _) -> collect_in_value ir_val
    | IRCondJump (cond_val, _, _) -> collect_in_value cond_val
    | IRIf (cond_val, then_body, else_body) ->
        collect_in_value cond_val;
        List.iter collect_in_instr then_body;
        (match else_body with
         | Some else_instrs -> List.iter collect_in_instr else_instrs
         | None -> ())
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
  in
  List.iter (fun block ->
    List.iter collect_in_instr block.instructions
  ) ir_func.basic_blocks;
  List.sort (fun (r1, _) (r2, _) -> compare r1 r2) !registers

(** Generate C function from IR function with type alias support *)

let generate_c_function ctx ir_func =
  (* Clear parameter register map for this function *)
  (* param_register_map reset removed *)
  
  let return_type_str = match ir_func.return_type with
    | Some ret_type -> ebpf_type_from_ir_type ret_type
    | None -> "void"
  in
  
  let params_str = String.concat ", " 
    (List.map (fun (name, param_type) ->
       sprintf "%s %s" (ebpf_type_from_ir_type param_type) name
     ) ir_func.parameters)
  in
  
  let section_attr = if ir_func.is_main then
    match ir_func.parameters with
    | [] -> "SEC(\"prog\")"  (* Default section for parameterless functions *)
    | (_, IRContext XdpCtx) :: _ -> "SEC(\"xdp\")"
    | (_, IRContext TcCtx) :: _ -> "SEC(\"tc\")"
    | (_, IRContext KprobeCtx) :: _ -> "SEC(\"kprobe\")"
    | _ -> "SEC(\"prog\")"
  else ""
  in
  
  emit_line ctx section_attr;
  emit_line ctx (sprintf "%s %s(%s) {" return_type_str ir_func.func_name params_str);
  increase_indent ctx;
  
  (* Function parameters are handled directly via IRVariable - no register mapping needed *)
  
  (* Collect all registers used (parameters use IRVariable, not registers) *)
  let all_registers = collect_registers_in_function ir_func in
  
  (* Declare temporary variables for all registers *)
  let register_variable_map = collect_register_variable_mapping ir_func in
  List.iter (fun (reg, reg_type) ->
    let c_type = match reg_type with
      | IRTypeAlias (alias_name, _) -> alias_name  (* Use the alias name directly *)
      | _ ->
          (* Check if this register corresponds to a variable with a type alias *)
          (match List.assoc_opt reg register_variable_map with
           | Some var_name ->
               (match List.assoc_opt var_name ctx.variable_type_aliases with
                | Some alias_name -> alias_name
                | None -> ebpf_type_from_ir_type reg_type)
           | None -> ebpf_type_from_ir_type reg_type)
    in
    emit_line ctx (sprintf "%s tmp_%d;" c_type reg)
  ) all_registers;
  if all_registers <> [] then emit_blank_line ctx;
  
  (* Generate basic blocks *)
  List.iter (generate_c_basic_block ctx) ir_func.basic_blocks;
  
  decrease_indent ctx;
  emit_line ctx "}";
  emit_blank_line ctx

(** Generate complete C program from IR *)

let generate_c_program ?config_declarations ir_prog =
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
    struct_ops_declarations = [];
    struct_ops_instances = [];
    userspace_program = None;
    userspace_bindings = [];
    multi_pos = ir_prog.ir_pos;
  } in
  generate_string_typedefs ctx temp_multi_prog;
  
  (* Generate enum definitions *)
  generate_enum_definitions ctx temp_multi_prog;
  
  (* Struct definitions are generated in the main entry point to avoid duplication *)
  
  (* Generate type alias definitions *)
  let type_aliases = collect_type_aliases_from_multi_program temp_multi_prog in
  generate_type_alias_definitions ctx type_aliases;
  
  (* Generate config maps if provided *)
  begin match config_declarations with
  | Some configs -> List.iter (generate_config_map_definition ctx) configs
  | None -> ()
  end;

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
    (* Reverse and prepend current output *)
    ctx.output_lines <- (List.rev current_output) @ ctx.output_lines;
  );
  
  (* With attributed functions, each program has only the entry function - no nested functions *)
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" (List.rev ctx.output_lines)

(** Generate complete C program from multiple IR programs *)

let generate_c_multi_program ?config_declarations ?(type_aliases=[]) ?(variable_type_aliases=[]) ir_multi_program =
  let ctx = create_c_context () in
  
  (* Initialize modular context code generators *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  (* Store variable type aliases for later lookup *)
  ctx.variable_type_aliases <- variable_type_aliases;
  
  (* Add standard includes *)
  let program_types = List.map (fun prog -> prog.program_type) ir_multi_program.programs in
  generate_includes ctx ~program_types ();
  
  (* Generate string type definitions *)
  generate_string_typedefs ctx ir_multi_program;
  
  (* Generate enum definitions *)
  generate_enum_definitions ctx ir_multi_program;
  
  (* Generate declarations in original AST order to preserve source order *)
  generate_declarations_in_source_order ctx ir_multi_program type_aliases;
  
  (* Generate struct definitions *)
  let struct_defs = collect_struct_definitions_from_multi_program ir_multi_program in
  generate_struct_definitions ctx struct_defs;
  
  (* Generate config maps if provided *)
  begin match config_declarations with
  | Some configs -> List.iter (generate_config_map_definition ctx) configs
  | None -> ()
  end;
  
  (* Generate global map definitions *)
  List.iter (generate_map_definition ctx) ir_multi_program.global_maps;
  
  (* Generate struct_ops definitions and instances *)
  generate_struct_ops ctx ir_multi_program;
  
  (* With attributed functions, all maps are global - no program-scoped maps *)
  
  (* First pass: collect all callbacks *)
  let temp_ctx = create_c_context () in
  List.iter (fun ir_prog ->
    (* With attributed functions, each program has only its entry function *)
    generate_c_function temp_ctx ir_prog.entry_function
  ) ir_multi_program.programs;
  
  (* Emit collected callbacks *)
  if temp_ctx.pending_callbacks <> [] then (
    List.iter (emit_line ctx) temp_ctx.pending_callbacks;
    emit_blank_line ctx;
  );
  
  (* Generate kernel functions once - they are shared across all programs *)
  List.iter (generate_c_function ctx) ir_multi_program.kernel_functions;

  (* Generate attributed functions (each program has only the entry function) *)
  List.iter (fun ir_prog ->
    (* With attributed functions, each program contains only its entry function - no nested functions *)
    generate_c_function ctx ir_prog.entry_function
  ) ir_multi_program.programs;
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" (List.rev ctx.output_lines)



(** Main compilation entry point *)

let compile_to_c ?config_declarations ir_program =
  let c_code = generate_c_program ?config_declarations ir_program in
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
    ?(config_declarations=[]) ?(type_aliases=[]) ?(variable_type_aliases=[]) ?(kfunc_declarations=[])
    (ir_multi_prog : Ir.ir_multi_program) =
  
  let ctx = create_c_context () in
  
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
    | Ast.Bool -> "bool" | Ast.Char -> "char"
    | Ast.Pointer inner_type -> sprintf "%s*" (ast_type_to_c_type inner_type)
    | _ -> "void"
  in
  List.iter (fun kfunc ->
    let params_str = String.concat ", " (List.map (fun (name, param_type) ->
      let c_type = ast_type_to_c_type param_type in
      sprintf "%s %s" c_type name
    ) kfunc.Ast.func_params) in
    let return_type_str = match kfunc.Ast.func_return_type with
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
  generate_enum_definitions ctx ir_multi_prog;
  
  (* Generate declarations in original AST order to preserve source order *)
  generate_declarations_in_source_order ctx ir_multi_prog type_aliases;
  
  (* Generate struct definitions *)
  let struct_defs = collect_struct_definitions_from_multi_program ir_multi_prog in
  generate_struct_definitions ctx struct_defs;
  
  (* Generate struct_ops definitions and instances *)
  generate_struct_ops ctx ir_multi_prog;
  
  (* Generate kernel functions once - they are shared across all programs *)
  List.iter (generate_c_function ctx) ir_multi_prog.kernel_functions;

  (* Generate C functions for each eBPF program and check for tail calls *)
  let temp_ctx = create_c_context () in
  List.iter (fun ir_prog ->
    generate_c_function temp_ctx ir_prog.entry_function
  ) ir_multi_prog.programs;
  
  (* Check if the generated code contains bpf_tail_call and extract target information *)
  let generated_code = String.concat "\n" (List.rev temp_ctx.output_lines) in
  let has_tail_calls = try 
    let _ = Str.search_forward (Str.regexp "bpf_tail_call") generated_code 0 in true 
  with Not_found -> false in
  
  (* Extract tail call targets from comments in generated code *)
  let tail_call_targets = if has_tail_calls then
    let lines = String.split_on_char '\n' generated_code in
    List.fold_left (fun acc line ->
      (* Look for comments like "/* Tail call to drop_handler (index 0) */" *)
      if String.contains line '/' && String.contains line '*' then
        let comment_regex = Str.regexp {|/\* Tail call to \([a-zA-Z_][a-zA-Z0-9_]*\) (index \([0-9]+\)) \*/|} in
        try
          let _ = Str.search_forward comment_regex line 0 in
          let target_name = Str.matched_group 1 line in
          let index = int_of_string (Str.matched_group 2 line) in
          (target_name, index) :: acc
        with Not_found -> acc
      else acc
    ) [] lines
  else [] in
  
  (* Generate ProgArray if tail calls detected in the generated code *)
  let max_index = if List.length tail_call_targets > 0 then
    List.fold_left (fun max_idx (_, idx) -> max max_idx idx) 0 tail_call_targets + 1
  else if has_tail_calls then 1 else 0 in
  
  if max_index > 0 then
    generate_prog_array_map ctx max_index;
  
  (* Generate global map definitions *)
  List.iter (generate_map_definition ctx) ir_multi_prog.global_maps;
  
  (* Generate config maps *)
  List.iter (generate_config_map_definition ctx) config_declarations;
  
  (* Now generate the actual functions *)
  List.iter (fun ir_prog ->
    generate_c_function ctx ir_prog.entry_function
  ) ir_multi_prog.programs;
  
  (* Emit pending callbacks *)
  List.rev ctx.pending_callbacks |> List.iter (emit_line ctx);
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Create tail call analysis result with extracted targets *)
  let index_mapping = Hashtbl.create 16 in
  List.iter (fun (target_name, index) ->
    Hashtbl.add index_mapping target_name index
  ) tail_call_targets;
  
  let tail_call_analysis = {
    Tail_call_analyzer.dependencies = [];
    prog_array_size = max_index;
    index_mapping = index_mapping;
    errors = [];
  } in
  
  (String.concat "\n" (List.rev ctx.output_lines), tail_call_analysis)

(** Multi-program compilation entry point with automatic tail call handling *)

let compile_multi_to_c ?(config_declarations=[]) ?(type_aliases=[]) ?(variable_type_aliases=[]) ir_multi_program =
  (* Always use the intelligent tail call compilation that auto-detects and handles tail calls *)
  let (c_code, tail_call_analysis) = compile_multi_to_c_with_tail_calls 
    ~config_declarations ~type_aliases ~variable_type_aliases ir_multi_program in
  
  (* Print tail call analysis results *)
  Printf.printf "Tail call analysis: %d dependencies, ProgArray size: %d\n" 
    (List.length tail_call_analysis.dependencies) tail_call_analysis.prog_array_size;
  
  c_code

(** Multi-program compilation entry point that returns both code and tail call analysis *)

let compile_multi_to_c_with_analysis ?(config_declarations=[]) ?(type_aliases=[]) ?(variable_type_aliases=[]) ?(kfunc_declarations=[]) ir_multi_program =
  (* Always use the intelligent tail call compilation that auto-detects and handles tail calls *)
  let (c_code, tail_call_analysis) = compile_multi_to_c_with_tail_calls 
    ~config_declarations ~type_aliases ~variable_type_aliases ~kfunc_declarations ir_multi_program in
  
  (* Print tail call analysis results *)
  Printf.printf "Tail call analysis: %d dependencies, ProgArray size: %d\n" 
    (List.length tail_call_analysis.dependencies) tail_call_analysis.prog_array_size;
  
  (c_code, tail_call_analysis)
