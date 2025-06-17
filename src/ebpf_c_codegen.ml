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

(** C code generation context *)
type c_codegen_context = {
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
  | IROption inner_type -> sprintf "%s*" (ebpf_type_from_ir_type inner_type) (* nullable pointer *)
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
  | IROption inner_type -> collect_string_sizes_from_type inner_type
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

let rec collect_string_sizes_from_instr ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest_val, expr) -> 
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
  | IRReturn ret_opt ->
      (match ret_opt with
       | Some ret_val -> collect_string_sizes_from_value ret_val
       | None -> [])
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
  | _ -> []

let collect_string_sizes_from_function ir_func =
  List.fold_left (fun acc block ->
    List.fold_left (fun acc instr ->
      acc @ (collect_string_sizes_from_instr instr)
    ) acc block.instructions
  ) [] ir_func.basic_blocks

let collect_string_sizes_from_multi_program ir_multi_prog =
  List.fold_left (fun acc ir_prog ->
    let main_sizes = collect_string_sizes_from_function ir_prog.main_function in
    let other_sizes = List.fold_left (fun acc func ->
      acc @ (collect_string_sizes_from_function func)
    ) [] ir_prog.functions in
    acc @ main_sizes @ other_sizes
  ) [] ir_multi_prog.programs

(** Collect enum definitions from IR types *)
let collect_enum_definitions ir_multi_prog =
  let enum_map = Hashtbl.create 16 in
  
  let rec collect_from_type = function
    | IREnum (name, values) -> Hashtbl.replace enum_map name values
    | IRPointer (inner_type, _) -> collect_from_type inner_type
    | IRArray (inner_type, _, _) -> collect_from_type inner_type
    | IROption inner_type -> collect_from_type inner_type
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
    List.iter collect_from_map_def ir_prog.local_maps;
    collect_from_function ir_prog.main_function;
    List.iter collect_from_function ir_prog.functions
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
    List.iter collect_from_map_def ir_prog.local_maps;
    collect_from_function ir_prog.main_function;
    List.iter collect_from_function ir_prog.functions
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

(** Generate standard eBPF includes *)

let generate_includes ctx ?(program_types=[]) () =
  let standard_includes = [
    "#include <linux/bpf.h>";
    "#include <bpf/bpf_helpers.h>";
    "#include <linux/if_ether.h>";
    "#include <linux/ip.h>";
    "#include <linux/in.h>";
    "#include <linux/if_xdp.h>";
    "#include <stdint.h>";
    "#include <stdbool.h>";
  ] in
  
  (* Add builtin headers based on program types *)
  let builtin_includes = List.fold_left (fun acc prog_type ->
    match prog_type with
    | Ast.Xdp -> "#include \"xdp.h\"" :: acc
    | Ast.Tc -> "#include \"tc.h\"" :: acc
    | Ast.Kprobe -> "#include \"kprobe.h\"" :: acc
    | _ -> acc
  ) [] program_types in
  
  let all_includes = standard_includes @ (List.rev builtin_includes) in
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
  
  (* Add pinning if specified *)
  begin match map_def.pin_path with
  | Some _path -> emit_line ctx (sprintf "__uint(pinning, LIBBPF_PIN_BY_NAME);")
  | None -> ()
  end;
  
  decrease_indent ctx;
  emit_line ctx (sprintf "} %s SEC(\".maps\");" map_def.map_name);
  emit_blank_line ctx

(** Generate config struct definition and map *)
let generate_config_map_definition ctx config_decl =
  let config_name = config_decl.Ast.config_name in
  let struct_name = sprintf "%s_config" config_name in
  
  (* Generate C struct for config *)
  emit_line ctx (sprintf "struct %s {" struct_name);
  increase_indent ctx;
  
  List.iter (fun field ->
    let field_declaration = match field.Ast.field_type with
      | Ast.U8 -> sprintf "__u8 %s;" field.Ast.field_name
      | Ast.U16 -> sprintf "__u16 %s;" field.Ast.field_name
      | Ast.U32 -> sprintf "__u32 %s;" field.Ast.field_name
      | Ast.U64 -> sprintf "__u64 %s;" field.Ast.field_name
      | Ast.I8 -> sprintf "__s8 %s;" field.Ast.field_name
      | Ast.I16 -> sprintf "__s16 %s;" field.Ast.field_name
      | Ast.I32 -> sprintf "__s32 %s;" field.Ast.field_name
      | Ast.I64 -> sprintf "__s64 %s;" field.Ast.field_name
      | Ast.Bool -> sprintf "__u8 %s;" field.Ast.field_name  (* bool -> u8 for BPF compatibility *)
      | Ast.Char -> sprintf "char %s;" field.Ast.field_name
      | Ast.Array (Ast.U16, size) -> sprintf "__u16 %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U32, size) -> sprintf "__u32 %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U64, size) -> sprintf "__u64 %s[%d];" field.Ast.field_name size
      | _ -> sprintf "__u32 %s;" field.Ast.field_name  (* fallback *)
    in
    emit_line ctx field_declaration
  ) config_decl.Ast.config_fields;
  
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

(** Generate C expression from IR value *)

let generate_c_value ctx ir_val =
  match ir_val.value_desc with
  | IRLiteral (IntLit i) -> string_of_int i
  | IRLiteral (BoolLit b) -> if b then "true" else "false"
  | IRLiteral (CharLit c) -> sprintf "'%c'" c
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
        name
  | IRRegister reg -> sprintf "tmp_%d" reg (* Convert registers to C variables *)
  | IRMapRef map_name -> sprintf "&%s" map_name
  | IRContextField (ctx_type, field) ->
      let ctx_var = "ctx" in (* Standard context parameter name *)
      begin match ctx_type, field with
      | XdpCtx, "data" -> sprintf "(void*)(long)%s->data" ctx_var
      | XdpCtx, "data_end" -> sprintf "(void*)(long)%s->data_end" ctx_var
      | XdpCtx, "data_meta" -> sprintf "(void*)(long)%s->data_meta" ctx_var
      | TcCtx, "data" -> sprintf "(void*)(long)%s->data" ctx_var
      | TcCtx, "data_end" -> sprintf "(void*)(long)%s->data_end" ctx_var
      | _, field -> sprintf "%s->%s" ctx_var field
      end

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
      let op_str = match op with
        | IRNot -> "!" | IRNeg -> "-" | IRBitNot -> "~"
      in
      sprintf "(%s%s)" op_str val_str
  | IRCast (ir_val, target_type) ->
      let val_str = generate_c_value ctx ir_val in
      let type_str = ebpf_type_from_ir_type target_type in
      sprintf "((%s)%s)" type_str val_str
  | IRFieldAccess (obj_val, field) ->
      let obj_str = generate_c_value ctx obj_val in
      sprintf "%s.%s" obj_str field

(** Generate helper function calls *)

let generate_helper_call ctx func_name args ret_var_opt =
  let bpf_func_name = match func_name with
    | "trace_printk" -> "bpf_trace_printk"
    | "get_current_pid_tgid" -> "bpf_get_current_pid_tgid"
    | "ktime_get_ns" -> "bpf_ktime_get_ns"
    | "map_lookup_elem" -> "bpf_map_lookup_elem"
    | "map_update_elem" -> "bpf_map_update_elem"
    | "map_delete_elem" -> "bpf_map_delete_elem"
    | name -> name (* Pass through unknown functions *)
  in
  
  let args_str = String.concat ", " (List.map (generate_c_value ctx) args) in
  let call_str = sprintf "%s(%s)" bpf_func_name args_str in
  
  match ret_var_opt with
  | Some ret_var ->
      let ret_str = generate_c_value ctx ret_var in
      emit_line ctx (sprintf "%s = %s;" ret_str call_str)
  | None ->
      emit_line ctx (sprintf "%s;" call_str)

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
      emit_line ctx (sprintf "  else %s = 0; }" dest_str)
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
  | Ast.Literal (Ast.IntLit i) -> string_of_int i
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

let rec generate_c_instruction ctx ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest_val, expr) ->
      (* Check if this is a string assignment *)
      (match dest_val.val_type, expr.expr_desc with
       | IRStr _, IRValue src_val when (match src_val.val_type with IRStr _ -> true | _ -> false) ->
           (* String to string assignment - need to copy struct *)
           let dest_str = generate_c_value ctx dest_val in
           let src_str = generate_c_value ctx src_val in
           emit_line ctx (sprintf "%s = %s;" dest_str src_str)
       | IRStr _size, IRValue src_val when (match src_val.value_desc with IRLiteral (StringLit _) -> true | _ -> false) ->
           (* String literal to string assignment - already handled in generate_c_value *)
           let dest_str = generate_c_value ctx dest_val in
           let src_str = generate_c_value ctx src_val in
           emit_line ctx (sprintf "%s = %s;" dest_str src_str)
       | IRStr _, _ ->
           (* Other string expressions (concatenation, etc.) *)
           let dest_str = generate_c_value ctx dest_val in
           let expr_str = generate_c_expression ctx expr in
           emit_line ctx (sprintf "%s = %s;" dest_str expr_str)
       | _ ->
           (* Regular assignment *)
           let dest_str = generate_c_value ctx dest_val in
           let expr_str = generate_c_expression ctx expr in
           emit_line ctx (sprintf "%s = %s;" dest_str expr_str))

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

  | IRMapLoad (map_val, key_val, dest_val, load_type) ->
      generate_map_load ctx map_val key_val dest_val load_type

  | IRMapStore (map_val, key_val, value_val, store_type) ->
      generate_map_store ctx map_val key_val value_val store_type

  | IRMapDelete (map_val, key_val) ->
      generate_map_delete ctx map_val key_val

  | IRConfigFieldUpdate (_map_val, _key_val, _field, _value_val) ->
      (* Config field updates should never occur in eBPF programs - they are read-only *)
      failwith "Internal error: Config field updates in eBPF programs should have been caught during type checking - configs are read-only in kernel space"
      
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
      let access_str = match access_type with
        | PacketData -> "ctx->data"
        | PacketEnd -> "ctx->data_end"
        | DataMeta -> "ctx->data_meta"
        | IngressIfindex -> "ctx->ingress_ifindex"
        | DataLen -> "ctx->len"
        | MarkField -> "ctx->mark"
        | Priority -> "ctx->priority"
        | CbField -> "ctx->cb[0]"
      in
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
      (* For eBPF, convert structured if to goto-based control flow *)
      let cond_str = generate_c_value ctx cond_val in
      let then_label = sprintf "then_%d" ctx.label_counter in
      let else_label = sprintf "else_%d" (ctx.label_counter + 1) in
      let merge_label = sprintf "merge_%d" (ctx.label_counter + 2) in
      ctx.label_counter <- ctx.label_counter + 3;
      
      emit_line ctx (sprintf "if (%s) goto %s; else goto %s;" cond_str then_label else_label);
      
      (* Then block *)
      emit_line ctx (sprintf "%s:" then_label);
      increase_indent ctx;
      List.iter (generate_c_instruction ctx) then_body;
      emit_line ctx (sprintf "goto %s;" merge_label);
      decrease_indent ctx;
      
      (* Else block *)
      emit_line ctx (sprintf "%s:" else_label);
      increase_indent ctx;
      (match else_body with
       | Some else_instrs -> List.iter (generate_c_instruction ctx) else_instrs
       | None -> emit_line ctx "/* empty else block */");
      emit_line ctx (sprintf "goto %s;" merge_label);
      decrease_indent ctx;
      
      (* Merge point *)
      emit_line ctx (sprintf "%s:" merge_label)

  | IRReturn ret_opt ->
      begin match ret_opt with
      | Some ret_val ->
          let ret_str = match ret_val.value_desc with
            (* Convert integer literals to XDP constants for XDP programs *)
            | IRLiteral (IntLit 0) when ret_val.val_type = IRAction XdpActionType -> "XDP_ABORTED"
            | IRLiteral (IntLit 1) when ret_val.val_type = IRAction XdpActionType -> "XDP_DROP"
            | IRLiteral (IntLit 2) when ret_val.val_type = IRAction XdpActionType -> "XDP_PASS"
            | IRLiteral (IntLit 3) when ret_val.val_type = IRAction XdpActionType -> "XDP_REDIRECT"
            | IRLiteral (IntLit 4) when ret_val.val_type = IRAction XdpActionType -> "XDP_TX"
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

  | IRTry (try_instructions, catch_clauses) ->
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
      ) catch_clauses;
      
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
  in
  let rec collect_in_instr ir_instr =
    match ir_instr.instr_desc with
    | IRAssign (dest_val, expr) -> collect_in_value dest_val; collect_in_expr expr
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
  in
  List.iter (fun block ->
    List.iter collect_in_instr block.instructions
  ) ir_func.basic_blocks;
  List.sort (fun (r1, _) (r2, _) -> compare r1 r2) !registers

(** Generate C function from IR function with type alias support *)

let generate_c_function ctx ir_func =
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
  
  (* Declare temporary variables for all registers used *)
  let registers = collect_registers_in_function ir_func in
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
  ) registers;
  if registers <> [] then emit_blank_line ctx;
  
  (* Generate basic blocks *)
  List.iter (generate_c_basic_block ctx) ir_func.basic_blocks;
  
  decrease_indent ctx;
  emit_line ctx "}";
  emit_blank_line ctx

(** Generate complete C program from IR *)

let generate_c_program ?config_declarations ir_prog =
  let ctx = create_c_context () in
  
  (* Add standard includes *)
  let program_types = [ir_prog.program_type] in
  generate_includes ctx ~program_types ();
  
  (* Generate string type definitions *)
  let temp_multi_prog = {
    source_name = ir_prog.name;
    programs = [ir_prog];
    global_maps = [];
    global_configs = [];
    userspace_program = None;
    userspace_bindings = [];
    multi_pos = ir_prog.ir_pos;
  } in
  generate_string_typedefs ctx temp_multi_prog;
  
  (* Generate enum definitions *)
  generate_enum_definitions ctx temp_multi_prog;
  
  (* Generate type alias definitions *)
  let type_aliases = collect_type_aliases_from_multi_program temp_multi_prog in
  generate_type_alias_definitions ctx type_aliases;
  
  (* Generate config maps if provided *)
  begin match config_declarations with
  | Some configs -> List.iter (generate_config_map_definition ctx) configs
  | None -> ()
  end;
  
  (* Generate map definitions *)
  List.iter (generate_map_definition ctx) (ir_prog.local_maps);
  
  (* Generate main function - this will collect callbacks *)
  generate_c_function ctx ir_prog.main_function;
  
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
  
  (* Generate other functions (excluding main to avoid duplicates) *)
  let other_functions = List.filter (fun f -> not f.is_main) ir_prog.functions in
  List.iter (generate_c_function ctx) other_functions;
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" (List.rev ctx.output_lines)

(** Generate complete C program from multiple IR programs *)

let generate_c_multi_program ?config_declarations ?(type_aliases=[]) ?(variable_type_aliases=[]) ir_multi_program =
  let ctx = create_c_context () in
  
  (* Store variable type aliases for later lookup *)
  ctx.variable_type_aliases <- variable_type_aliases;
  
  (* Add standard includes *)
  let program_types = List.map (fun prog -> prog.program_type) ir_multi_program.programs in
  generate_includes ctx ~program_types ();
  
  (* Generate type alias definitions from AST *)
  generate_ast_type_alias_definitions ctx type_aliases;
  
  (* Generate config maps if provided *)
  begin match config_declarations with
  | Some configs -> List.iter (generate_config_map_definition ctx) configs
  | None -> ()
  end;
  
  (* Generate global map definitions *)
  List.iter (generate_map_definition ctx) ir_multi_program.global_maps;
  
  (* Generate all local map definitions from all programs *)
  List.iter (fun ir_prog ->
    List.iter (generate_map_definition ctx) ir_prog.local_maps
  ) ir_multi_program.programs;
  
  (* First pass: collect all callbacks *)
  let temp_ctx = create_c_context () in
  List.iter (fun ir_prog ->
    generate_c_function temp_ctx ir_prog.main_function;
    let other_functions = List.filter (fun f -> not f.is_main) ir_prog.functions in
    List.iter (generate_c_function temp_ctx) other_functions
  ) ir_multi_program.programs;
  
  (* Emit collected callbacks *)
  if temp_ctx.pending_callbacks <> [] then (
    List.iter (emit_line ctx) temp_ctx.pending_callbacks;
    emit_blank_line ctx;
  );
  
  (* Second pass: generate actual functions *)
  List.iter (fun ir_prog ->
    generate_c_function ctx ir_prog.main_function;
    let other_functions = List.filter (fun f -> not f.is_main) ir_prog.functions in
    List.iter (generate_c_function ctx) other_functions
  ) ir_multi_program.programs;
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" (List.rev ctx.output_lines)

(** Enhanced multi-program compilation entry point with analysis *)

let compile_multi_to_c_with_analysis ?(type_aliases=[]) ?(variable_type_aliases=[]) ir_multi_program 
                                   (multi_prog_analysis: Multi_program_analyzer.multi_program_analysis) 
                                   (resource_plan: Multi_program_ir_optimizer.resource_plan)
                                   (_optimization_results: Multi_program_ir_optimizer.optimization_strategy list) =
  let ctx = create_c_context () in
  
  (* Add enhanced includes for multi-program systems *)
  let program_types = List.map (fun prog -> prog.program_type) ir_multi_program.programs in
  generate_includes ctx ~program_types ();
  
  (* Generate string type definitions *)
  generate_string_typedefs ctx ir_multi_program;
  
  (* Store variable type aliases for later lookup *)
  ctx.variable_type_aliases <- variable_type_aliases;
  
  (* Generate enum definitions *)
  generate_enum_definitions ctx ir_multi_program;
  
  (* Generate type alias definitions from AST *)
  generate_ast_type_alias_definitions ctx type_aliases;
  
  emit_line ctx "/* Enhanced Multi-Program eBPF System */";
  emit_line ctx (sprintf "/* Programs: %d, Global Maps: %d */" 
    (List.length ir_multi_program.programs) 
    (List.length ir_multi_program.global_maps));
  
  (* Add multi-program analysis comments *)
  if List.length multi_prog_analysis.potential_conflicts > 0 then (
    emit_line ctx "/* ⚠️  Multi-Program Conflicts Detected: */";
    List.iter (fun conflict ->
      emit_line ctx (sprintf "/*   - %s */" conflict)
    ) multi_prog_analysis.potential_conflicts;
  );
  
  if List.length multi_prog_analysis.optimization_opportunities > 0 then (
    emit_line ctx "/* 💡 Multi-Program Optimizations Applied: */";
    List.iter (fun opt ->
      emit_line ctx (sprintf "/*   - %s */" opt)
    ) multi_prog_analysis.optimization_opportunities;
  );
  
  emit_line ctx (sprintf "/* Resource Plan: %d instructions, %d bytes stack */"
    resource_plan.estimated_instructions resource_plan.estimated_stack);
  emit_blank_line ctx;
  
  (* Generate global map definitions with analysis info *)
  List.iter (fun map_def ->
    (* Add analysis comments for maps *)
    let accessing_programs = 
      List.fold_left (fun acc (map_name, programs) ->
        if map_name = map_def.map_name then
          programs @ acc
        else acc
      ) [] multi_prog_analysis.map_usage_patterns
    in
    if List.length accessing_programs > 1 then (
      emit_line ctx (sprintf "/* Map '%s' shared by programs: %s */" 
        map_def.map_name 
        (String.concat ", " accessing_programs));
    );
    generate_map_definition ctx map_def
  ) ir_multi_program.global_maps;
  
  (* Generate all local map definitions from all programs *)
  List.iter (fun ir_prog ->
    List.iter (generate_map_definition ctx) ir_prog.local_maps
  ) ir_multi_program.programs;
  
  (* First pass: collect all callbacks *)
  let temp_ctx = create_c_context () in
  List.iter (fun ir_prog ->
    generate_c_function temp_ctx ir_prog.main_function;
    let other_functions = List.filter (fun f -> not f.is_main) ir_prog.functions in
    List.iter (generate_c_function temp_ctx) other_functions
  ) ir_multi_program.programs;
  
  (* Emit collected callbacks *)
  if temp_ctx.pending_callbacks <> [] then (
    List.iter (emit_line ctx) temp_ctx.pending_callbacks;
    emit_blank_line ctx;
  );
  
  (* Second pass: generate actual functions *)
  List.iter (fun ir_prog ->
    generate_c_function ctx ir_prog.main_function;
    let other_functions = List.filter (fun f -> not f.is_main) ir_prog.functions in
    List.iter (generate_c_function ctx) other_functions
  ) ir_multi_program.programs;
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" (List.rev ctx.output_lines)

(** Main compilation entry point *)

let compile_to_c ?config_declarations ir_program =
  let c_code = generate_c_program ?config_declarations ir_program in
  c_code

(** Multi-program compilation entry point *)

let compile_multi_to_c ?config_declarations ?(type_aliases=[]) ?(variable_type_aliases=[]) ir_multi_program =
  let c_code = generate_c_multi_program ?config_declarations ~type_aliases ~variable_type_aliases ir_multi_program in
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

