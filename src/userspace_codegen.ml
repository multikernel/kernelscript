(** IR-based Userspace C Code Generation
    This module generates complete userspace C programs from KernelScript IR programs.
    This is the unified IR-first userspace code generator.
*)

open Ir
open Printf

(** Function usage tracking for optimization *)
type function_usage = {
  mutable uses_load_program: bool;
  mutable uses_attach_program: bool;
  mutable uses_map_operations: bool;
  mutable used_maps: string list;
}

let create_function_usage () = {
  uses_load_program = false;
  uses_attach_program = false;
  uses_map_operations = false;
  used_maps = [];
}

(** Context for C code generation *)
type userspace_context = {
  temp_counter: int ref;
  function_name: string;
  is_main: bool;
  (* Track register to variable name mapping for better C code *)
  register_vars: (int, string) Hashtbl.t;
  (* Track variable declarations needed *)
  var_declarations: (string, string) Hashtbl.t; (* var_name -> c_type *)
  (* Track function usage for optimization *)
  function_usage: function_usage;
}

let create_userspace_context () = {
  temp_counter = ref 0;
  function_name = "user_function";
  is_main = false;
  register_vars = Hashtbl.create 32;
  var_declarations = Hashtbl.create 32;
  function_usage = create_function_usage ();
}

let create_main_context () = {
  temp_counter = ref 0;
  function_name = "main";
  is_main = true;
  register_vars = Hashtbl.create 32;
  var_declarations = Hashtbl.create 32;
  function_usage = create_function_usage ();
}

let fresh_temp_var ctx prefix =
  incr ctx.temp_counter;
  sprintf "%s_%d" prefix !(ctx.temp_counter)

(** Track function usage based on instruction *)
let track_function_usage ctx instr =
  match instr.instr_desc with
  | IRCall (func_name, _, _) ->
      (match func_name with
       | "load_program" -> ctx.function_usage.uses_load_program <- true
       | "attach_program" -> ctx.function_usage.uses_attach_program <- true
       | _ -> ())
  | IRMapLoad (map_val, _, _, _) 
  | IRMapStore (map_val, _, _, _) 
  | IRMapDelete (map_val, _) ->
      ctx.function_usage.uses_map_operations <- true;
      (match map_val.value_desc with
       | IRMapRef map_name ->
           if not (List.mem map_name ctx.function_usage.used_maps) then
             ctx.function_usage.used_maps <- map_name :: ctx.function_usage.used_maps
       | _ -> ())
  | IRConfigFieldUpdate (map_val, _, _, _) ->
      ctx.function_usage.uses_map_operations <- true;
      (match map_val.value_desc with
       | IRMapRef map_name ->
           if not (List.mem map_name ctx.function_usage.used_maps) then
             ctx.function_usage.used_maps <- map_name :: ctx.function_usage.used_maps
       | _ -> ())
  | _ -> ()

(** Recursively track usage in all instructions *)
let rec track_usage_in_instructions ctx instrs =
  List.iter (fun instr ->
    track_function_usage ctx instr;
    match instr.instr_desc with
    | IRIf (_, then_body, else_body) ->
        track_usage_in_instructions ctx then_body;
        (match else_body with
         | Some else_instrs -> track_usage_in_instructions ctx else_instrs
         | None -> ())
    | IRBpfLoop (_, _, _, _, body_instrs) ->
        track_usage_in_instructions ctx body_instrs
    | IRTry (try_instrs, catch_clauses) ->
        track_usage_in_instructions ctx try_instrs;
        List.iter (fun clause ->
          track_usage_in_instructions ctx clause.catch_body
        ) catch_clauses
    | _ -> ()
  ) instrs

(** Collect string sizes from IR *)
let rec collect_string_sizes_from_ir_type = function
  | IRStr size -> [size]
  | IRPointer (inner_type, _) -> collect_string_sizes_from_ir_type inner_type
  | IRArray (inner_type, _, _) -> collect_string_sizes_from_ir_type inner_type
  | IROption inner_type -> collect_string_sizes_from_ir_type inner_type
  | IRResult (ok_type, err_type) -> 
      (collect_string_sizes_from_ir_type ok_type) @ (collect_string_sizes_from_ir_type err_type)
  | _ -> []

let collect_string_sizes_from_ir_value ir_value =
  let type_sizes = collect_string_sizes_from_ir_type ir_value.val_type in
  let literal_sizes = match ir_value.value_desc with
    | IRLiteral (StringLit _) ->
        (match ir_value.val_type with
         | IRStr size -> [size]
         | _ -> [])
    | _ -> []
  in
  type_sizes @ literal_sizes

let collect_string_sizes_from_ir_expr ir_expr =
  match ir_expr.expr_desc with
  | IRValue ir_value -> collect_string_sizes_from_ir_value ir_value
  | IRBinOp (left, _, right) -> 
      (collect_string_sizes_from_ir_value left) @ (collect_string_sizes_from_ir_value right)
  | IRUnOp (_, operand) -> collect_string_sizes_from_ir_value operand
  | IRCast (value, target_type) -> 
      (collect_string_sizes_from_ir_value value) @ (collect_string_sizes_from_ir_type target_type)
  | IRFieldAccess (obj, _) -> collect_string_sizes_from_ir_value obj

let collect_string_sizes_from_ir_instruction ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest, expr) -> 
      (collect_string_sizes_from_ir_value dest) @ (collect_string_sizes_from_ir_expr expr)
  | IRCall (_, args, ret_opt) ->
      let ret_sizes = match ret_opt with
        | Some ret_val -> collect_string_sizes_from_ir_value ret_val
        | None -> []
      in
      let arg_sizes = List.fold_left (fun acc arg -> 
        acc @ (collect_string_sizes_from_ir_value arg)
      ) [] args in
      ret_sizes @ arg_sizes
  | IRReturn value_opt ->
      (match value_opt with
       | Some value -> collect_string_sizes_from_ir_value value
       | None -> [])
  | IRIf (cond, _, _) -> collect_string_sizes_from_ir_value cond
  | IRMapLoad (_, _, dest, _) -> collect_string_sizes_from_ir_value dest
  | IRMapStore (_, _, value, _) -> collect_string_sizes_from_ir_value value
  | IRMapDelete (_, _) -> []
  | IRConfigFieldUpdate (_, _, _, value) -> collect_string_sizes_from_ir_value value
  | IRBoundsCheck (value, _, _) -> collect_string_sizes_from_ir_value value
  | _ -> [] (* Other instruction types don't contain string sizes *)

let collect_string_sizes_from_ir_function ir_func =
  let param_sizes = List.fold_left (fun acc (_, param_type) ->
    acc @ (collect_string_sizes_from_ir_type param_type)
  ) [] ir_func.parameters in
  let return_sizes = match ir_func.return_type with
    | Some ret_type -> collect_string_sizes_from_ir_type ret_type
    | None -> [] in
  let body_sizes = List.fold_left (fun acc block ->
    List.fold_left (fun acc2 instr ->
      acc2 @ (collect_string_sizes_from_ir_instruction instr)
    ) acc block.instructions
  ) [] ir_func.basic_blocks in
  param_sizes @ return_sizes @ body_sizes

let collect_string_sizes_from_userspace_program userspace_prog =
  List.fold_left (fun acc func ->
    acc @ (collect_string_sizes_from_ir_function func)
  ) [] userspace_prog.userspace_functions

(** Collect enum definitions from IR types *)
let collect_enum_definitions_from_userspace userspace_prog =
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
  
  (* Collect from struct fields *)
  List.iter (fun struct_def ->
    List.iter (fun (_field_name, field_type) ->
      collect_from_type field_type
    ) struct_def.struct_fields
  ) userspace_prog.userspace_structs;
  
  (* Collect from all userspace functions *)
  List.iter collect_from_function userspace_prog.userspace_functions;
  
  enum_map

(** Generate enum definition *)
let generate_enum_definition_userspace enum_name enum_values =
  let value_count = List.length enum_values in
  let enum_variants = List.mapi (fun i (const_name, value) ->
    let line = sprintf "    %s = %d%s" const_name value (if i = value_count - 1 then "" else ",") in
    line
  ) enum_values in
  sprintf "enum %s {\n%s\n};" enum_name (String.concat "\n" enum_variants)

(** Generate all enum definitions for userspace *)
let generate_enum_definitions_userspace userspace_prog =
  let enum_map = collect_enum_definitions_from_userspace userspace_prog in
  if Hashtbl.length enum_map > 0 then (
    let enum_defs = Hashtbl.fold (fun enum_name enum_values acc ->
      (generate_enum_definition_userspace enum_name enum_values) :: acc
    ) enum_map [] in
    "/* Enum definitions */\n" ^ (String.concat "\n\n" enum_defs) ^ "\n\n"
  ) else ""

(** Generate string type definitions *)
let generate_string_typedefs _string_sizes =
  (* For userspace, we don't need complex string typedefs - just use char arrays *)
  ""

(** Collect type aliases from userspace program *)
let collect_type_aliases_from_userspace_program userspace_prog =
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
    | IRReturn (Some ret_val) -> collect_from_value ret_val
    | _ -> ()
  in
  
  let collect_from_function ir_func =
    List.iter (fun block ->
      List.iter collect_from_instr block.instructions
    ) ir_func.basic_blocks;
    (* Also collect from function parameters and return type *)
    List.iter (fun (_, param_type) -> collect_from_type param_type) ir_func.parameters;
    (match ir_func.return_type with Some ret_type -> collect_from_type ret_type | None -> ())
  in
  
  (* Collect from struct fields *)
  List.iter (fun struct_def ->
    List.iter (fun (_field_name, field_type) ->
      collect_from_type field_type
    ) struct_def.struct_fields
  ) userspace_prog.userspace_structs;
  
  (* Collect from all userspace functions *)
  List.iter collect_from_function userspace_prog.userspace_functions;
  
  List.rev !type_aliases

(** Convert IR types to C types *)
let rec c_type_from_ir_type = function
  | IRU8 -> "uint8_t"
  | IRU16 -> "uint16_t"
  | IRU32 -> "uint32_t"
  | IRU64 -> "uint64_t"
  | IRI8 -> "int8_t"
  | IRF32 -> "float"
  | IRF64 -> "double"
  | IRBool -> "bool"
  | IRChar -> "char"
  | IRStr _ -> "char" (* Base type for userspace string - size handled in declaration *)
  | IRPointer (inner_type, _) -> sprintf "%s*" (c_type_from_ir_type inner_type)
  | IRArray (inner_type, size, _) -> sprintf "%s[%d]" (c_type_from_ir_type inner_type) size
  | IRStruct (name, _) -> sprintf "struct %s" name
  | IREnum (name, _) -> sprintf "enum %s" name
  | IROption inner_type -> sprintf "%s*" (c_type_from_ir_type inner_type) (* nullable pointer *)
  | IRResult (ok_type, _err_type) -> c_type_from_ir_type ok_type (* simplified to ok type *)
  | IRTypeAlias (name, _) -> name (* Use the alias name directly *)
  | IRStructOps (name, _) -> sprintf "struct %s_ops" name (* struct_ops as function pointer structs *)
  | IRContext _ -> "void*" (* context pointers *)
  | IRAction _ -> "int" (* action return values *)

(** Generate type alias definitions for userspace *)
let generate_type_alias_definitions_userspace type_aliases =
  if type_aliases <> [] then (
    let type_alias_defs = List.map (fun (alias_name, underlying_type) ->
      let c_type = c_type_from_ir_type underlying_type in
      sprintf "typedef %s %s;" c_type alias_name
    ) type_aliases in
    "/* Type alias definitions */\n" ^ (String.concat "\n" type_alias_defs) ^ "\n\n"
  ) else ""

(** Generate type alias definitions for userspace from AST types *)
let generate_type_alias_definitions_userspace_from_ast type_aliases =
  if type_aliases <> [] then (
    let type_alias_defs = List.map (fun (alias_name, underlying_type) ->
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
            sprintf "typedef %s %s[%d];" element_c_type alias_name size
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
            sprintf "typedef %s %s;" c_type alias_name
    ) type_aliases in
    "/* Type alias definitions */\n" ^ (String.concat "\n" type_alias_defs) ^ "\n\n"
  ) else ""

(** Generate string helper functions *)
let generate_string_helpers _string_sizes =
  (* For userspace, we don't need complex string helper functions - just use standard C *)
  ""

(** Get or create a meaningful variable name for a register *)
let get_register_var_name ctx reg_id ir_type =
  match Hashtbl.find_opt ctx.register_vars reg_id with
  | Some var_name -> var_name
  | None ->
      let var_name = sprintf "var_%d" reg_id in
      (* Handle string types specially for variable declarations *)
      let c_type = match ir_type with
        | IRStr size -> sprintf "char[%d]" size
        | _ -> c_type_from_ir_type ir_type
      in
      Hashtbl.add ctx.register_vars reg_id var_name;
      Hashtbl.add ctx.var_declarations var_name c_type;
      var_name

(** Generate C value from IR value *)
let generate_c_value_from_ir ctx ir_value =
  match ir_value.value_desc with
  | IRLiteral (IntLit (i, original_opt)) -> 
      (* Use original format if available, otherwise use decimal *)
      (match original_opt with
       | Some orig when String.contains orig 'x' || String.contains orig 'X' -> orig
       | Some orig when String.contains orig 'b' || String.contains orig 'B' -> orig
       | _ -> string_of_int i)
  | IRLiteral (CharLit c) -> sprintf "'%c'" c
  | IRLiteral (BoolLit b) -> if b then "true" else "false"
  | IRLiteral (StringLit s) -> 
      (* Generate simple string literal for userspace *)
      sprintf "\"%s\"" s
  | IRLiteral (ArrayLit elems) -> 
      let elem_strs = List.map (function
        | Ast.IntLit (i, _) -> string_of_int i
        | Ast.CharLit c -> sprintf "'%c'" c
        | Ast.BoolLit b -> if b then "true" else "false"
        | Ast.StringLit s -> sprintf "\"%s\"" s
        | Ast.ArrayLit _ -> "{...}" (* nested arrays simplified *)
      ) elems in
      sprintf "{%s}" (String.concat ", " elem_strs)
  | IRVariable name -> name
  | IRRegister reg_id -> get_register_var_name ctx reg_id ir_value.val_type
  | IRContextField (_ctx_type, field) -> sprintf "ctx->%s" field
  | IRMapRef map_name -> sprintf "%s_fd" map_name

(** Generate C expression from IR expression *)
let generate_c_expression_from_ir ctx ir_expr =
  match ir_expr.expr_desc with
  | IRValue ir_value -> generate_c_value_from_ir ctx ir_value
  | IRBinOp (left_val, op, right_val) ->
      (* Check if this is a string operation *)
      (match left_val.val_type, op, right_val.val_type with
       | IRStr _, IRAdd, IRStr _ ->
           (* String concatenation - use safer approach for userspace *)
           let left_str = generate_c_value_from_ir ctx left_val in
           let right_str = generate_c_value_from_ir ctx right_val in
           (* Use a temporary stack array for concatenation *) 
           let result_size = match ir_expr.expr_type with
             | IRStr size -> size
             | _ -> 256 (* fallback size *)
           in
           sprintf "({ char __tmp[%d] = {0}; size_t __left_len = strlen(%s); size_t __right_len = strlen(%s); if (__left_len + __right_len < %d) { strcpy(__tmp, %s); strcat(__tmp, %s); } else { strncpy(__tmp, %s, %d - 1); __tmp[%d - 1] = '\\0'; } __tmp; })" 
             result_size left_str right_str result_size left_str right_str left_str result_size result_size
       | IRStr _, IREq, IRStr _ ->
           (* String equality - use strcmp *)
           let left_str = generate_c_value_from_ir ctx left_val in
           let right_str = generate_c_value_from_ir ctx right_val in
           sprintf "(strcmp(%s, %s) == 0)" left_str right_str
       | IRStr _, IRNe, IRStr _ ->
           (* String inequality - use strcmp *)
           let left_str = generate_c_value_from_ir ctx left_val in
           let right_str = generate_c_value_from_ir ctx right_val in
           sprintf "(strcmp(%s, %s) != 0)" left_str right_str
       | IRStr _, IRAdd, _ when (match right_val.val_type with IRU32 | IRU16 | IRU8 -> true | _ -> false) ->
           (* String indexing: str[index] *)
           let array_str = generate_c_value_from_ir ctx left_val in
           let index_str = generate_c_value_from_ir ctx right_val in
           sprintf "%s[%s]" array_str index_str
       | _ ->
           (* Regular binary operation *)
           let left_str = generate_c_value_from_ir ctx left_val in
           let right_str = generate_c_value_from_ir ctx right_val in
           let op_str = match op with
             | IRAdd -> "+"
             | IRSub -> "-"
             | IRMul -> "*"
             | IRDiv -> "/"
             | IRMod -> "%"
             | IREq -> "=="
             | IRNe -> "!="
             | IRLt -> "<"
             | IRLe -> "<="
             | IRGt -> ">"
             | IRGe -> ">="
             | IRAnd -> "&&"
             | IROr -> "||"
             | IRBitAnd -> "&"
             | IRBitOr -> "|"
             | IRBitXor -> "^"
             | IRShiftL -> "<<"
             | IRShiftR -> ">>"
           in
           sprintf "(%s %s %s)" left_str op_str right_str)
  | IRUnOp (op, operand_val) ->
      let operand_str = generate_c_value_from_ir ctx operand_val in
      let op_str = match op with
        | IRNot -> "!"
        | IRNeg -> "-"
        | IRBitNot -> "~"
      in
      sprintf "%s%s" op_str operand_str
  | IRCast (value, target_type) ->
      (* Handle string type conversions *)
      (match value.val_type, target_type with
       | IRStr src_size, IRStr dest_size when src_size <> dest_size ->
           (* String type conversion: copy data and length from source *)
           let value_str = generate_c_value_from_ir ctx value in
           sprintf "({ str_%d_t __conv; strncpy(__conv.data, (%s).data, (%s).len); __conv.len = (%s).len; if (__conv.len >= %d) __conv.len = %d - 1; __conv.data[__conv.len] = '\\0'; __conv; })" 
             dest_size value_str value_str value_str dest_size dest_size
       | _ ->
           let value_str = generate_c_value_from_ir ctx value in
           let type_str = c_type_from_ir_type target_type in
           sprintf "((%s)%s)" type_str value_str)
  | IRFieldAccess (obj_val, field) ->
      let obj_str = generate_c_value_from_ir ctx obj_val in
      sprintf "%s.%s" obj_str field

(** Generate map operations from IR *)
let generate_map_load_from_ir ctx map_val key_val dest_val load_type =
  let map_str = generate_c_value_from_ir ctx map_val in
  let dest_str = generate_c_value_from_ir ctx dest_val in
  
  match load_type with
  | DirectLoad ->
      sprintf "%s = *%s;" dest_str map_str
  | MapLookup ->
      (match key_val.value_desc with
        | IRLiteral _ -> 
            let temp_key = fresh_temp_var ctx "key" in
            let key_type = c_type_from_ir_type key_val.val_type in
            let key_str = generate_c_value_from_ir ctx key_val in
            sprintf "%s %s = %s;\n    { void* __tmp_ptr = bpf_map_lookup_elem(%s, &%s);\n      if (__tmp_ptr) %s = *(%s*)__tmp_ptr;\n      else %s = 0; }" 
              key_type temp_key key_str map_str temp_key dest_str (c_type_from_ir_type dest_val.val_type) dest_str
        | _ -> 
            let key_str = generate_c_value_from_ir ctx key_val in
            sprintf "{ void* __tmp_ptr = bpf_map_lookup_elem(%s, &(%s));\n      if (__tmp_ptr) %s = *(%s*)__tmp_ptr;\n      else %s = 0; }" 
              map_str key_str dest_str (c_type_from_ir_type dest_val.val_type) dest_str)
  | MapPeek ->
      sprintf "%s = bpf_ringbuf_reserve(%s, sizeof(*%s), 0);" dest_str map_str dest_str

let generate_map_store_from_ir ctx map_val key_val value_val store_type =
  let map_str = generate_c_value_from_ir ctx map_val in
  
  match store_type with
  | DirectStore ->
      let value_str = generate_c_value_from_ir ctx value_val in
      sprintf "*%s = %s;" map_str value_str
  | MapUpdate ->
      let key_var = match key_val.value_desc with
        | IRLiteral _ -> 
            let temp_key = fresh_temp_var ctx "key" in
            let key_type = c_type_from_ir_type key_val.val_type in
            let key_str = generate_c_value_from_ir ctx key_val in
            (temp_key, sprintf "%s %s = %s;" key_type temp_key key_str)
        | _ -> 
            let key_str = generate_c_value_from_ir ctx key_val in
            (key_str, "")
      in
      
      let value_var = match value_val.value_desc with
        | IRLiteral _ ->
            let temp_value = fresh_temp_var ctx "value" in
            let value_type = c_type_from_ir_type value_val.val_type in
            let value_str = generate_c_value_from_ir ctx value_val in
            (temp_value, sprintf "%s %s = %s;" value_type temp_value value_str)
        | _ -> 
            let value_str = generate_c_value_from_ir ctx value_val in
            (value_str, "")
      in
      
      let (key_name, key_decl) = key_var in
      let (value_name, value_decl) = value_var in
      let setup = [key_decl; value_decl] |> List.filter (fun s -> s <> "") |> String.concat "\n    " in
      let setup_str = if setup = "" then "" else setup ^ "\n    " in
      sprintf "%sbpf_map_update_elem(%s, &%s, &%s, BPF_ANY);" setup_str map_str key_name value_name
  | MapPush ->
      let value_str = generate_c_value_from_ir ctx value_val in
      sprintf "bpf_ringbuf_submit(%s, 0);" value_str

let generate_map_delete_from_ir ctx map_val key_val =
  let map_str = generate_c_value_from_ir ctx map_val in
  
  match key_val.value_desc with
    | IRLiteral _ -> 
        let temp_key = fresh_temp_var ctx "key" in
        let key_type = c_type_from_ir_type key_val.val_type in
        let key_str = generate_c_value_from_ir ctx key_val in
        sprintf "%s %s = %s;\n    bpf_map_delete_elem(%s, &%s);" key_type temp_key key_str map_str temp_key
    | _ -> 
        let key_str = generate_c_value_from_ir ctx key_val in
        sprintf "bpf_map_delete_elem(%s, &(%s));" map_str key_str

(** Global config names collector *)
let global_config_names = ref []

(** Generate config field update instruction from IR *)
let generate_config_field_update_from_ir ctx map_val key_val field value_val =
  let map_str = generate_c_value_from_ir ctx map_val in
  let value_str = generate_c_value_from_ir ctx value_val in
  let key_str = generate_c_value_from_ir ctx key_val in
  
  (* Extract config name from map name (e.g., "&network" -> "network") *)
  let clean_map_str = if String.get map_str 0 = '&' then 
    String.sub map_str 1 (String.length map_str - 1)
  else map_str in
  let config_name = if String.contains clean_map_str '_' then
    let parts = String.split_on_char '_' clean_map_str in
    List.hd parts
  else clean_map_str in
  
  let temp_struct = fresh_temp_var ctx "config" in
  let temp_key = fresh_temp_var ctx "key" in
  
  (* Add config name to global collection during processing *)
  if not (List.mem config_name !global_config_names) then (
    global_config_names := config_name :: !global_config_names
  );
  sprintf {|    struct %s_config %s;
    uint32_t %s = %s;
    // Load current config from map
    if (bpf_map_lookup_elem(%s_config_map_fd, &%s, &%s) == 0) {
        // Update the field
        %s.%s = %s;
        // Write back to map
        bpf_map_update_elem(%s_config_map_fd, &%s, &%s, BPF_ANY);
    }|} 
    config_name temp_struct temp_key key_str config_name temp_key temp_struct
    temp_struct field value_str config_name temp_key temp_struct

(** Generate C instruction from IR instruction *)
let rec generate_c_instruction_from_ir ctx instruction =
  match instruction.instr_desc with
  | IRAssign (dest, src) ->
      (* Simple assignment for userspace - strings are just char arrays *)
      let dest_str = generate_c_value_from_ir ctx dest in
      let src_str = generate_c_expression_from_ir ctx src in
      
      (* For string assignments, use safer approach to avoid truncation warnings *)
      (match dest.val_type with
       | IRStr size -> 
           sprintf "{ size_t __src_len = strlen(%s); if (__src_len < %d) { strcpy(%s, %s); } else { strncpy(%s, %s, %d - 1); %s[%d - 1] = '\\0'; } }" 
             src_str size dest_str src_str dest_str src_str size dest_str size
       | _ -> sprintf "%s = %s;" dest_str src_str)
  
  | IRCall (func_name, args, result_opt) ->
      (* Track function usage for optimization *)
      track_function_usage ctx instruction;
      
      (* Check if this is a built-in function that needs context-specific translation *)
      let (actual_name, translated_args) = match Stdlib.get_userspace_implementation func_name with
        | Some userspace_impl ->
            (* This is a built-in function - translate for userspace context *)
            let c_args = List.map (generate_c_value_from_ir ctx) args in
            (match func_name with
             | "print" -> 
                 (* Special handling for print: convert to printf format *)
                 (match c_args with
                  | [] -> (userspace_impl, ["\"\\n\""])
                  | [first] -> (userspace_impl, [sprintf "%s \"\\n\"" first])
                  | args -> (userspace_impl, args @ ["\"\\n\""]))
             | "load_program" ->
                 (* Special handling for load_program: generate libbpf program loading code *)
                 ctx.function_usage.uses_load_program <- true;
                 (match c_args with
                  | [program_name] ->
                      (* Extract program name from identifier - remove quotes if present *)
                      let clean_name = if String.contains program_name '"' then
                        String.sub program_name 1 (String.length program_name - 2)
                      else program_name in
                      ("load_bpf_program", [sprintf "\"%s\"" clean_name])
                  | _ -> failwith "load_program expects exactly one argument")
             | "attach_program" ->
                 (* Special handling for attach_program: now takes program handle (not program name) *)
                 ctx.function_usage.uses_attach_program <- true;
                 (match c_args with
                  | [program_handle; target; flags] ->
                      (* Use the program handle variable directly instead of extracting program name *)
                      ("attach_bpf_program_by_fd", [program_handle; target; flags])
                  | _ -> failwith "attach_program expects exactly three arguments")
             | _ -> (userspace_impl, c_args))
        | None ->
            (* Regular function call *)
            let c_args = List.map (generate_c_value_from_ir ctx) args in
            (func_name, c_args)
      in
      let args_str = String.concat ", " translated_args in
      (match result_opt with
       | Some result -> sprintf "%s = %s(%s);" (generate_c_value_from_ir ctx result) actual_name args_str
       | None -> sprintf "%s(%s);" actual_name args_str)
  
  | IRReturn value_opt ->
      (match value_opt with
       | Some value -> sprintf "return %s;" (generate_c_value_from_ir ctx value)
       | None -> "return;")
  
  | IRMapLoad (map_val, key_val, dest_val, load_type) ->
      track_function_usage ctx instruction;
      generate_map_load_from_ir ctx map_val key_val dest_val load_type
  
  | IRMapStore (map_val, key_val, value_val, store_type) ->
      track_function_usage ctx instruction;
      generate_map_store_from_ir ctx map_val key_val value_val store_type
  
  | IRMapDelete (map_val, key_val) ->
      track_function_usage ctx instruction;
      generate_map_delete_from_ir ctx map_val key_val
  
  | IRConfigFieldUpdate (map_val, key_val, field, value_val) ->
      track_function_usage ctx instruction;
      generate_config_field_update_from_ir ctx map_val key_val field value_val
  
  | IRConfigAccess (config_name, field_name, result_val) ->
      (* Generate config access for userspace - direct struct field access *)
      let result_str = generate_c_value_from_ir ctx result_val in
      sprintf "%s = get_%s_config()->%s;" result_str config_name field_name
  
  | IRContextAccess (dest, access_type) ->
      let access_str = match access_type with
        | PacketData -> "ctx->data"
        | PacketEnd -> "ctx->data_end" 
        | DataMeta -> "ctx->data_meta"
        | IngressIfindex -> "ctx->ingress_ifindex"
        | DataLen -> "ctx->len"
        | MarkField -> "ctx->mark"
        | Priority -> "ctx->priority"
        | CbField -> "ctx->cb"
      in
      sprintf "%s = %s;" (generate_c_value_from_ir ctx dest) access_str
  
  | IRJump label ->
      sprintf "goto %s;" label
  
  | IRCondJump (condition, true_label, false_label) ->
      sprintf "if (%s) goto %s; else goto %s;" 
        (generate_c_value_from_ir ctx condition) true_label false_label
  
  | IRIf (condition, then_body, else_body) ->
      let cond_str = generate_c_value_from_ir ctx condition in
      let then_stmts = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) then_body) in
      (match else_body with
       | None ->
           sprintf "if (%s) {\n        %s\n    }" cond_str then_stmts
       | Some else_stmts ->
           let else_stmts_str = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) else_stmts) in
           sprintf "if (%s) {\n        %s\n    } else {\n        %s\n    }" cond_str then_stmts else_stmts_str)
  
  | IRBoundsCheck (value, min_val, max_val) ->
      sprintf "/* bounds check: %s in [%d, %d] */" 
        (generate_c_value_from_ir ctx value) min_val max_val
  
  | IRComment comment ->
      sprintf "/* %s */" comment
  
  | IRBpfLoop (start, end_val, counter, _ctx_val, body_instrs) ->
      let start_str = generate_c_value_from_ir ctx start in
      let end_str = generate_c_value_from_ir ctx end_val in
      let counter_str = generate_c_value_from_ir ctx counter in
      let body_stmts = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) body_instrs) in
      sprintf "for (%s = %s; %s <= %s; %s++) {\n        %s\n    }" 
        counter_str start_str counter_str end_str counter_str body_stmts
  
  | IRBreak -> "break;"
  | IRContinue -> "continue;"
  
  | IRCondReturn (condition, true_ret, false_ret) ->
      let cond_str = generate_c_value_from_ir ctx condition in
      let true_str = match true_ret with
        | Some v -> generate_c_value_from_ir ctx v
        | None -> ""
      in
      let false_str = match false_ret with
        | Some v -> generate_c_value_from_ir ctx v
        | None -> ""
      in
      if true_ret <> None && false_ret <> None then
        sprintf "return %s ? %s : %s;" cond_str true_str false_str
      else if true_ret <> None then
        sprintf "if (%s) return %s;" cond_str true_str
      else
        sprintf "if (!(%s)) return %s;" cond_str false_str

  | IRTry (try_instructions, catch_clauses) ->
      (* Generate setjmp/longjmp for userspace try/catch *)
      let try_body = String.concat "\n        " (List.map (generate_c_instruction_from_ir ctx) try_instructions) in
      let catch_handlers = List.mapi (fun i catch_clause ->
        let (pattern_str, case_code) = match catch_clause.catch_pattern with
          | IntCatchPattern code -> (sprintf "error_%d" code, code)
          | WildcardCatchPattern -> ("any_error", i + 1) (* Use index for wildcard *)
        in
        sprintf "    case %d: /* catch %s */\n        /* Handle error here */\n        break;" case_code pattern_str
      ) catch_clauses in
      let catch_code = String.concat "\n" catch_handlers in
      sprintf {|{
        jmp_buf exception_buffer;
        int exception_code = setjmp(exception_buffer);
        if (exception_code == 0) {
            /* try block */
            %s
        } else {
            /* catch handlers */
            switch (exception_code) {
%s
            default:
                fprintf(stderr, "Unhandled exception: %%d\\n", exception_code);
                exit(1);
            }
        }
    }|} try_body catch_code

  | IRThrow error_code ->
      (* Generate longjmp for userspace throw *)
      let code_val = match error_code with
        | IntErrorCode code -> code
      in
      sprintf "longjmp(exception_buffer, %d); /* throw error */" code_val

  | IRDefer defer_instructions ->
      (* For userspace, generate defer using function-scope cleanup *)
      let defer_body = String.concat "\n    " (List.map (generate_c_instruction_from_ir ctx) defer_instructions) in
      sprintf "/* defer block - executed at function exit */\n    {\n    %s\n    }" defer_body

(** Generate C struct from IR struct definition *)
let generate_c_struct_from_ir ir_struct =
  let fields_str = String.concat ";\n    " 
    (List.map (fun (field_name, field_type) ->
       (* Handle string types specially for correct C syntax *)
       match field_type with
       | IRStr size -> sprintf "char %s[%d]" field_name size
       | _ -> sprintf "%s %s" (c_type_from_ir_type field_type) field_name
     ) ir_struct.struct_fields)
  in
  sprintf "struct %s {\n    %s;\n};" ir_struct.struct_name fields_str

(** Generate variable declarations for a function *)
let generate_variable_declarations ctx =
  let declarations = Hashtbl.fold (fun var_name c_type acc ->
    (* Handle array declarations properly *)
    if String.contains c_type '[' && String.contains c_type ']' then
      let parts = String.split_on_char '[' c_type in
      let base_type = List.hd parts in
      let array_part = "[" ^ String.concat "[" (List.tl parts) in
      sprintf "%s %s%s;" base_type var_name array_part :: acc
    else
      sprintf "%s %s;" c_type var_name :: acc
  ) ctx.var_declarations [] in
  if declarations = [] then ""
  else "    " ^ String.concat "\n    " (List.rev declarations) ^ "\n"

(** Collect function usage information from IR function *)
let collect_function_usage_from_ir_function ir_func =
  let ctx = create_userspace_context () in
  List.iter (fun block ->
    track_usage_in_instructions ctx block.instructions
  ) ir_func.basic_blocks;
  ctx.function_usage

(** Check if all execution paths in a function have explicit return statements *)
let all_paths_have_return (ir_func : ir_function) : bool =
  (* Use proper control flow analysis on IR instead of string scanning *)
  let return_info = Ir_analysis.ReturnAnalysis.analyze_returns ir_func in
  return_info.all_paths_return

(** Generate C function from IR function *)
let generate_c_function_from_ir (ir_func : ir_function) =
  let params_str = String.concat ", " 
    (List.map (fun (name, ir_type) ->
       (* Handle string types specially for function parameters *)
       match ir_type with
       | IRStr size -> sprintf "char %s[%d]" name size
       | _ -> sprintf "%s %s" (c_type_from_ir_type ir_type) name
     ) ir_func.parameters)
  in
  
  let return_type_str = match ir_func.return_type with
    | Some ret_type -> c_type_from_ir_type ret_type
    | None -> "void"
  in
  
  let ctx = if ir_func.func_name = "main" then create_main_context () else 
    { (create_userspace_context ()) with function_name = ir_func.func_name } in
  
  (* Generate function body from basic blocks *)
  let body_parts = List.map (fun block ->
    let label_part = if block.label <> "entry" then [sprintf "%s:" block.label] else [] in
    let instr_parts = List.map (generate_c_instruction_from_ir ctx) block.instructions in
    label_part @ instr_parts
  ) ir_func.basic_blocks in
  
  let body_c = String.concat "\n    " (List.flatten body_parts) in
  
  (* Generate variable declarations *)
  let var_decls = generate_variable_declarations ctx in
  
  let adjusted_params = if ir_func.func_name = "main" then 
    (* Main function can be either main() or main(args) - generate appropriate C signature *)
    (if List.length ir_func.parameters = 0 then "void" else "int argc, char **argv")
  else
    (if params_str = "" then "void" else params_str) in
  
  let adjusted_return_type = if ir_func.func_name = "main" then "int" else return_type_str in
  
  if ir_func.func_name = "main" then
    let args_parsing_code = 
      if List.length ir_func.parameters > 0 then
        (* Generate argument parsing for struct parameter *)
        let (param_name, param_type) = List.hd ir_func.parameters in
        (match param_type with
         | IRStruct (struct_name, _) ->
           sprintf "    // Parse command line arguments\n    struct %s %s = parse_arguments(argc, argv);" struct_name param_name
         | _ -> "    // No argument parsing needed")
      else
        "    // No arguments to parse"
    in
    
    (* Generate assignment from parsed args to IR variables *)
    let args_assignment_code = 
      if List.length ir_func.parameters > 0 then
        let (param_name, param_type) = List.hd ir_func.parameters in
        (match param_type with
         | IRStruct (_, _) ->
           sprintf "    // Copy parsed arguments to function variable\n    var_0 = %s;" param_name
         | _ -> "")
      else
        ""
    in
    
    (* Check if this main function uses maps and needs auto-initialization *)
    let func_usage = collect_function_usage_from_ir_function ir_func in
    let needs_auto_init = func_usage.uses_map_operations && not func_usage.uses_load_program in
    let auto_init_call = if needs_auto_init then
      "    \n    // Auto-initialize BPF maps\n    atexit(cleanup_bpf_maps);\n    if (init_bpf_maps() < 0) {\n        return 1;\n    }"
    else "" in
    
    (* Generate ONLY what the user explicitly wrote with auto-initialization if needed *)
    let default_return = if all_paths_have_return ir_func then "" else "\n    \n    return 0; /* Default return if no explicit return */" in
    sprintf {|%s %s(%s) {
%s    
%s%s
%s
    
    %s%s
}|} adjusted_return_type ir_func.func_name adjusted_params var_decls args_parsing_code args_assignment_code auto_init_call body_c default_return
  else
    sprintf {|%s %s(%s) {
%s    %s
    %s
}|} adjusted_return_type ir_func.func_name adjusted_params var_decls body_c
      (if return_type_str = "void" then "" else "return 0;")

(** Generate command line argument parsing for struct parameter *)
let generate_getopt_parsing (struct_name : string) (param_name : string) (struct_fields : (string * ir_type) list) =
  (* Generate option struct array for getopt_long *)
  let options = List.mapi (fun i (field_name, _) ->
    sprintf "        {\"%s\", required_argument, 0, %d}," field_name (i + 1)
  ) struct_fields in
  
  let options_array = String.concat "\n" options in
  
  (* Generate case statements for option parsing *)
  let case_statements = List.mapi (fun i (field_name, field_type) ->
         let parse_code = match field_type with
       | IRU8 | IRU16 | IRU32 -> sprintf "%s.%s = (uint32_t)atoi(optarg);" param_name field_name
       | IRU64 -> sprintf "%s.%s = (uint64_t)atoll(optarg);" param_name field_name
       | IRI8 -> sprintf "%s.%s = (int8_t)atoi(optarg);" param_name field_name
       | IRBool -> sprintf "%s.%s = (atoi(optarg) != 0);" param_name field_name
       | IRStr size -> sprintf "strncpy(%s.%s, optarg, %d - 1); %s.%s[%d - 1] = '\\0';" param_name field_name size param_name field_name size
       | _ -> sprintf "%s.%s = (uint32_t)atoi(optarg); // fallback" param_name field_name
    in
    sprintf "        case %d:\n            %s\n            break;" (i + 1) parse_code
  ) struct_fields in
  
  let case_code = String.concat "\n" case_statements in
  
  (* Generate help text *)
     let help_options = List.map (fun (field_name, field_type) ->
     let type_hint = match field_type with
       | IRU8 | IRU16 | IRU32 | IRU64 -> "<number>"
       | IRI8 -> "<number>" 
       | IRBool -> "<0|1>"
       | IRStr _ -> "<string>"
       | _ -> "<value>"
    in
    sprintf "    printf(\"  --%s=%s\\n\");" field_name type_hint
  ) struct_fields in
  
  let help_text = String.concat "\n" help_options in
  
  sprintf {|
/* Parse command line arguments into %s */
struct %s parse_arguments(int argc, char **argv) {
    struct %s %s = {0}; // Initialize all fields to 0
    
    static struct option long_options[] = {
%s
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
        switch (c) {
%s
        case 'h':
            printf("Usage: %%s [options]\\n", argv[0]);
            printf("Options:\\n");
%s
            printf("  --help           Show this help message\\n");
            exit(0);
            break;
        case '?':
            fprintf(stderr, "Unknown option. Use --help for usage information.\\n");
            exit(1);
            break;
        default:
            fprintf(stderr, "Error parsing arguments\\n");
            exit(1);
        }
    }
    
    return %s;
}
|} struct_name struct_name struct_name param_name options_array case_code help_text param_name

(** Generate map file descriptor declarations *)
let generate_map_fd_declarations maps =
  List.map (fun map ->
    sprintf "int %s_fd = -1;" map.map_name
  ) maps |> String.concat "\n"

(** Generate map operation functions *)
let generate_map_operation_functions maps =
  List.map (fun map ->
    let key_type = c_type_from_ir_type map.map_key_type in
    let value_type = c_type_from_ir_type map.map_value_type in
  sprintf {|
// Map operations for %s
int %s_lookup(%s *key, %s *value) {
    return bpf_map_lookup_elem(%s_fd, key, value);
}

int %s_update(%s *key, %s *value) {
    return bpf_map_update_elem(%s_fd, key, value, BPF_ANY);
}

int %s_delete(%s *key) {
    return bpf_map_delete_elem(%s_fd, key);
}

int %s_get_next_key(%s *key, %s *next_key) {
    return bpf_map_get_next_key(%s_fd, key, next_key);
}|} 
      map.map_name
      map.map_name key_type value_type map.map_name
      map.map_name key_type value_type map.map_name
      map.map_name key_type map.map_name
      map.map_name key_type key_type map.map_name
  ) maps |> String.concat "\n"

(** Generate map setup code - handle both regular and pinned maps *)
let generate_map_setup_code maps =
  List.map (fun map ->
    match map.pin_path with
    | Some pin_path ->
        (* For pinned maps, try multiple approaches in order *)
        sprintf {|    /* Load or create pinned %s map */
    %s_fd = bpf_obj_get("%s");
    if (%s_fd < 0) {
        /* Map not pinned yet, load from eBPF object and pin it */
        struct bpf_map *%s_map = bpf_object__find_map_by_name(bpf_obj, "%s");
        if (!%s_map) {
            fprintf(stderr, "Failed to find %s map in eBPF object\n");
            return -1;
        }
        /* Pin the map to the specified path */
        if (bpf_map__pin(%s_map, "%s") < 0) {
            fprintf(stderr, "Failed to pin %s map to %s\n");
            return -1;
        }
        /* Get file descriptor after pinning */
        %s_fd = bpf_map__fd(%s_map);
        if (%s_fd < 0) {
            fprintf(stderr, "Failed to get fd for %s map\n");
            return -1;
        }
    }|}
          map.map_name
          map.map_name pin_path
          map.map_name
          map.map_name map.map_name
          map.map_name
          map.map_name
          map.map_name pin_path
          map.map_name pin_path
          map.map_name map.map_name
          map.map_name
          map.map_name
    | None ->
        (* For non-pinned maps, just load from BPF object *)
        sprintf {|    /* Load %s map from eBPF object */
    %s_fd = bpf_object__find_map_fd_by_name(bpf_obj, "%s");
    if (%s_fd < 0) {
        fprintf(stderr, "Failed to find %s map in eBPF object\n");
        return -1;
    }|}
          map.map_name
          map.map_name map.map_name
          map.map_name map.map_name
  ) maps |> String.concat "\n"

(** Generate config struct definition from config declaration - reusing eBPF logic *)
let generate_config_struct_from_decl (config_decl : Ast.config_declaration) =
  let config_name = config_decl.config_name in
  let struct_name = sprintf "%s_config" config_name in
  
  (* Generate C struct for config - using same logic as eBPF but with standard C types *)
  let field_declarations = List.map (fun field ->
    let field_declaration = match field.Ast.field_type with
      | Ast.U8 -> sprintf "    uint8_t %s;" field.Ast.field_name
      | Ast.U16 -> sprintf "    uint16_t %s;" field.Ast.field_name
      | Ast.U32 -> sprintf "    uint32_t %s;" field.Ast.field_name
      | Ast.U64 -> sprintf "    uint64_t %s;" field.Ast.field_name
      | Ast.I8 -> sprintf "    int8_t %s;" field.Ast.field_name
      | Ast.I16 -> sprintf "    int16_t %s;" field.Ast.field_name
      | Ast.I32 -> sprintf "    int32_t %s;" field.Ast.field_name
      | Ast.I64 -> sprintf "    int64_t %s;" field.Ast.field_name
      | Ast.Bool -> sprintf "    bool %s;" field.Ast.field_name
      | Ast.Char -> sprintf "    char %s;" field.Ast.field_name
      | Ast.Array (Ast.U16, size) -> sprintf "    uint16_t %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U32, size) -> sprintf "    uint32_t %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U64, size) -> sprintf "    uint64_t %s[%d];" field.Ast.field_name size
      | Ast.Array (Ast.U8, size) -> sprintf "    uint8_t %s[%d];" field.Ast.field_name size
      | _ -> sprintf "    uint32_t %s;" field.Ast.field_name  (* fallback *)
    in
    field_declaration
  ) config_decl.Ast.config_fields in
  
  sprintf "struct %s {\n%s\n};" struct_name (String.concat "\n" field_declarations)

(** Generate config initialization from declaration defaults *)
let generate_config_initialization (config_decl : Ast.config_declaration) =
  let config_name = config_decl.config_name in
  let struct_name = sprintf "%s_config" config_name in
  
  (* Generate field initializations with default values *)
  let field_initializations = List.map (fun field ->
    let initialization = match field.Ast.field_default with
      | Some default_value -> 
          (match default_value with
           | Ast.IntLit (i, _) -> sprintf "    init_config.%s = %d;" field.Ast.field_name i
           | Ast.BoolLit b -> sprintf "    init_config.%s = %s;" field.Ast.field_name (if b then "true" else "false")
           | Ast.ArrayLit elements ->
               (* Handle array initialization *)
               let elements_str = List.mapi (fun i element ->
                 match element with
                 | Ast.IntLit (value, _) -> sprintf "    init_config.%s[%d] = %d;" field.Ast.field_name i value
                 | _ -> sprintf "    init_config.%s[%d] = 0;" field.Ast.field_name i (* fallback *)
               ) elements in
               String.concat "\n" elements_str
           | _ -> sprintf "    init_config.%s = 0;" field.Ast.field_name (* fallback *))
      | None -> sprintf "    init_config.%s = 0;" field.Ast.field_name (* default to 0 if no default specified *)
    in
    initialization
  ) config_decl.Ast.config_fields in
  
  sprintf {|    /* Initialize %s config map with default values */
    struct %s init_config = {0};
    uint32_t config_key = 0;
%s
    if (bpf_map_update_elem(%s_config_map_fd, &config_key, &init_config, BPF_ANY) < 0) {
        fprintf(stderr, "Failed to initialize %s config map with default values\n");
        return -1;
    }|} config_name struct_name (String.concat "\n" field_initializations) config_name config_name

(** Generate necessary headers based on maps used *)
let generate_headers_for_maps maps =
  let has_maps = List.length maps > 0 in
  let has_pinned_maps = List.exists (fun map -> map.pin_path <> None) maps in
  let has_perf_events = List.exists (fun map -> map.map_type = IRPerfEvent) maps in
  let has_ring_buffer = List.exists (fun map -> map.map_type = IRRingBuffer) maps in
  
  let base_headers = [
    "#include <stdio.h>";
    "#include <stdlib.h>";
    "#include <string.h>";
    "#include <errno.h>";
    "#include <unistd.h>";
    "#include <signal.h>";
  ] in
  
  let bpf_headers = if has_maps then [
    "#include <bpf/bpf.h>";
    "#include <bpf/libbpf.h>";
  ] else [] in
  
  let pinning_headers = if has_pinned_maps then [
    "#include <sys/stat.h>";
    "#include <sys/types.h>";
  ] else [] in
  
  let event_headers = 
    (if has_perf_events then ["#include <sys/poll.h>"] else []) @
    (if has_ring_buffer then ["#include <linux/ring_buffer.h>"] else []) in
  
  String.concat "\n" (base_headers @ bpf_headers @ pinning_headers @ event_headers)

(** Generate complete userspace program from IR *)
let generate_complete_userspace_program_from_ir ?(config_declarations = []) ?(type_aliases = []) (userspace_prog : ir_userspace_program) (global_maps : ir_map_def list) source_filename =
  let base_includes = generate_headers_for_maps global_maps in
  let additional_includes = {|#include <stdbool.h>
#include <getopt.h>
#include <fcntl.h>
#include <net/if.h>
#include <setjmp.h>
#include <linux/bpf.h>
#include <sys/resource.h>

/* Generated from KernelScript IR */
|} in
  let includes = base_includes ^ "\n" ^ additional_includes in

  (* Reset and use the global config names collector *)
  global_config_names := [];
  
  (* Check if main function has struct parameters and generate getopt parsing *)
  let main_function = List.find_opt (fun f -> f.func_name = "main") userspace_prog.userspace_functions in
  let getopt_parsing_code = match main_function with
    | Some main_func when List.length main_func.parameters > 0 ->
        let (param_name, param_type) = List.hd main_func.parameters in
        (match param_type with
         | IRStruct (struct_name, _) ->
           (* Look up the actual struct definition to get the fields *)
           (match List.find_opt (fun s -> s.struct_name = struct_name) userspace_prog.userspace_structs with
            | Some struct_def -> generate_getopt_parsing struct_name param_name struct_def.struct_fields
            | None -> "")
         | _ -> "")
    | _ -> ""
  in
  
  (* Collect string sizes from the userspace program *)
  let string_sizes = collect_string_sizes_from_userspace_program userspace_prog in
  
  (* Generate string type definitions and helpers *)
  let string_typedefs = generate_string_typedefs string_sizes in
  let string_helpers = generate_string_helpers string_sizes in
  
  (* Generate enum definitions *)
  let enum_definitions = generate_enum_definitions_userspace userspace_prog in
  
  (* Generate type alias definitions from AST *)
  let type_alias_definitions = generate_type_alias_definitions_userspace_from_ast type_aliases in
  
  (* Collect function usage information from all functions *)
  let all_usage = List.fold_left (fun acc_usage func ->
    let func_usage = collect_function_usage_from_ir_function func in
    {
      uses_load_program = acc_usage.uses_load_program || func_usage.uses_load_program;
      uses_attach_program = acc_usage.uses_attach_program || func_usage.uses_attach_program;
      uses_map_operations = acc_usage.uses_map_operations || func_usage.uses_map_operations;
      used_maps = List.fold_left (fun acc map_name ->
        if List.mem map_name acc then acc else map_name :: acc
      ) acc_usage.used_maps func_usage.used_maps;
    }
  ) (create_function_usage ()) userspace_prog.userspace_functions in

  (* Generate functions first so config names get collected *)
  let functions = String.concat "\n\n" 
    (List.map generate_c_function_from_ir userspace_prog.userspace_functions) in
  
  (* Generate config struct definitions using actual config declarations *)
  let config_structs = List.map generate_config_struct_from_decl config_declarations in
  
  (* Filter out config structs from IR structs since we generate them separately from config_declarations *)
  let non_config_ir_structs = List.filter (fun ir_struct ->
    not (String.contains ir_struct.struct_name '_' && 
         String.ends_with ~suffix:"_config" ir_struct.struct_name)
  ) userspace_prog.userspace_structs in
  
  let structs = String.concat "\n\n" 
    ((List.map generate_c_struct_from_ir non_config_ir_structs) @ config_structs) in
  
  (* Generate map-related code only if maps are actually used *)
  let used_global_maps = List.filter (fun map ->
    List.mem map.map_name all_usage.used_maps
  ) global_maps in
  
  let map_fd_declarations = if all_usage.uses_map_operations then
    generate_map_fd_declarations used_global_maps
  else "" in
  
  (* Generate config map file descriptors only if needed *)
  let config_fd_declarations = if all_usage.uses_map_operations then
    List.map (fun config_decl ->
      sprintf "int %s_config_map_fd = -1;" config_decl.Ast.config_name
    ) config_declarations
  else [] in
  
  let all_fd_declarations = if all_usage.uses_map_operations then
    map_fd_declarations :: config_fd_declarations |> String.concat "\n"
  else "" in
  
  let map_operation_functions = if all_usage.uses_map_operations then
    generate_map_operation_functions used_global_maps
  else "" in
  
  let map_setup_code = if all_usage.uses_map_operations then
    generate_map_setup_code used_global_maps
  else "" in
  
  (* Generate config map setup code - load from eBPF object and initialize with defaults *)
  let config_setup_code = if all_usage.uses_map_operations then
    List.map (fun config_decl ->
      let config_name = config_decl.Ast.config_name in
      let load_code = sprintf {|    /* Load %s config map from eBPF object */
    %s_config_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "%s_config_map");
    if (%s_config_map_fd < 0) {
        fprintf(stderr, "Failed to find %s config map in eBPF object\n");
        return -1;
    }|} config_name config_name config_name config_name config_name in
      let init_code = generate_config_initialization config_decl in
      load_code ^ "\n" ^ init_code
    ) config_declarations |> String.concat "\n"
  else "" in
  
  let all_setup_code = map_setup_code ^ 
    (if map_setup_code <> "" && config_setup_code <> "" then "\n" else "") ^ 
    config_setup_code in
  
  (* Extract base name from source filename *)
  let base_name = Filename.remove_extension (Filename.basename source_filename) in
  
  (* Generate automatic BPF object initialization when maps are used but load_program is not called *)
  let needs_auto_bpf_init = all_usage.uses_map_operations && not all_usage.uses_load_program in
  let auto_bpf_init_code = if needs_auto_bpf_init && all_setup_code <> "" then
    sprintf {|
/* Auto-generated BPF object initialization */
static struct bpf_object *bpf_obj = NULL;

int init_bpf_maps(void) {
    if (bpf_obj) return 0; // Already initialized
    
    bpf_obj = bpf_object__open_file("%s.ebpf.o", NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return -1;
    }
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return -1;
    }
    
%s
    return 0;
}

void cleanup_bpf_maps(void) {
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
}
|} base_name all_setup_code
  else "" in
  
  (* Only generate BPF helper functions when they're actually used *)
  let bpf_helper_functions = 
    let load_function = if all_usage.uses_load_program then
      sprintf {|int load_bpf_program(const char *program_name) {
    if (!bpf_obj) {
        bpf_obj = bpf_object__open_file("%s.ebpf.o", NULL);
        if (libbpf_get_error(bpf_obj)) {
            fprintf(stderr, "Failed to open BPF object\\n");
            return -1;
        }
        if (bpf_object__load(bpf_obj)) {
            fprintf(stderr, "Failed to load BPF object\\n");
            return -1;
        }
        %s
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj, program_name);
    if (!prog) {
        fprintf(stderr, "Failed to find program '%%s' in BPF object\\n", program_name);
        return -1;
    }
    
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get file descriptor for program '%%s'\\n", program_name);
        return -1;
    }
    
    return prog_fd;
}|} base_name all_setup_code
    else "" in
    
    let attach_function = if all_usage.uses_attach_program then
      {|int attach_bpf_program_by_fd(int prog_fd, const char *target, int flags) {
    if (prog_fd < 0) {
        fprintf(stderr, "Invalid program file descriptor: %d\n", prog_fd);
        return -1;
    }
    
    // Get program type from file descriptor  
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    int ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (ret) {
        fprintf(stderr, "Failed to get program info: %s\n", strerror(errno));
        return -1;
    }
    
    switch (info.type) {
        case BPF_PROG_TYPE_XDP: {
            int ifindex = if_nametoindex(target);
            if (ifindex == 0) {
                fprintf(stderr, "Failed to get interface index for '%s'\n", target);
                return -1;
            }
            
            // Use modern libbpf API for XDP attachment
            ret = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
            if (ret) {
                fprintf(stderr, "Failed to attach XDP program to interface '%s': %s\n", target, strerror(errno));
                return -1;
            }
            
            return 0;
        }
        default:
            fprintf(stderr, "Unsupported program type for attachment: %d\n", info.type);
            return -1;
    }
}|}
    else "" in
    
    let bpf_obj_decl = if all_usage.uses_load_program || all_usage.uses_attach_program then
      "struct bpf_object *bpf_obj = NULL;"
    else "" in
    
    let functions_list = List.filter (fun s -> s <> "") [load_function; attach_function] in
    if functions_list = [] && bpf_obj_decl = "" then ""
    else
      sprintf "\n/* BPF Helper Functions (generated only when used) */\n%s\n\n%s" 
        bpf_obj_decl (String.concat "\n\n" functions_list) in
  
  sprintf {|%s

%s

%s

%s

%s

%s

%s

%s
%s

%s
%s

%s
|} includes string_typedefs type_alias_definitions string_helpers enum_definitions structs all_fd_declarations map_operation_functions auto_bpf_init_code getopt_parsing_code bpf_helper_functions functions

(** Generate userspace C code from IR multi-program *)
let generate_userspace_code_from_ir ?(config_declarations = []) ?(type_aliases = []) (ir_multi_prog : ir_multi_program) ?(output_dir = ".") source_filename =
  let content = match ir_multi_prog.userspace_program with
    | Some userspace_prog -> 
        generate_complete_userspace_program_from_ir ~config_declarations ~type_aliases userspace_prog ir_multi_prog.global_maps source_filename
    | None -> 
        sprintf {|#include <stdio.h>

int main(void) {
    printf("No userspace program defined in IR\n");
    return 0;
}
|}
  in
  
  (* Create output directory *)
  (try Unix.mkdir output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  
  (* Generate output file *)
  let base_name = Filename.remove_extension (Filename.basename source_filename) in
  let filename = sprintf "%s.c" base_name in
  let filepath = Filename.concat output_dir filename in
  let oc = open_out filepath in
  output_string oc content;
  close_out oc;
  printf "✅ Generated IR-based userspace program: %s\n" filepath

(** Compatibility functions for tests *)
let generate_c_statement _stmt = "/* IR-based statement generation */"

let generate_c_statement_with_context _ctx _stmt = "/* IR-based statement generation */" 
