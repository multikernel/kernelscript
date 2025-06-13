(** IR-based Userspace C Code Generation
    This module generates complete userspace C programs from KernelScript IR programs.
    This is the unified IR-first userspace code generator.
*)

open Ir
open Printf

(** Context for C code generation *)
type userspace_context = {
  temp_counter: int ref;
  function_name: string;
  is_main: bool;
  (* Track register to variable name mapping for better C code *)
  register_vars: (int, string) Hashtbl.t;
  (* Track variable declarations needed *)
  var_declarations: (string, string) Hashtbl.t; (* var_name -> c_type *)
}

let create_userspace_context () = {
  temp_counter = ref 0;
  function_name = "user_function";
  is_main = false;
  register_vars = Hashtbl.create 32;
  var_declarations = Hashtbl.create 32;
}

let create_main_context () = {
  temp_counter = ref 0;
  function_name = "main";
  is_main = true;
  register_vars = Hashtbl.create 32;
  var_declarations = Hashtbl.create 32;
}

let fresh_temp_var ctx prefix =
  incr ctx.temp_counter;
  sprintf "%s_%d" prefix !(ctx.temp_counter)

(** Convert IR types to C types *)
let rec c_type_from_ir_type = function
  | IRU8 -> "uint8_t"
  | IRU16 -> "uint16_t"
  | IRU32 -> "uint32_t"
  | IRU64 -> "uint64_t"
  | IRBool -> "bool"
  | IRChar -> "char"
  | IRPointer (inner_type, _) -> sprintf "%s*" (c_type_from_ir_type inner_type)
  | IRArray (inner_type, size, _) -> sprintf "%s[%d]" (c_type_from_ir_type inner_type) size
  | IRStruct (name, _) -> sprintf "struct %s" name
  | IREnum (name, _) -> sprintf "enum %s" name
  | IROption inner_type -> sprintf "%s*" (c_type_from_ir_type inner_type) (* nullable pointer *)
  | IRResult (ok_type, _err_type) -> c_type_from_ir_type ok_type (* simplified to ok type *)
  | IRContext _ -> "void*" (* context pointers *)
  | IRAction _ -> "int" (* action return values *)

(** Get or create a meaningful variable name for a register *)
let get_register_var_name ctx reg_id ir_type =
  match Hashtbl.find_opt ctx.register_vars reg_id with
  | Some var_name -> var_name
  | None ->
      let var_name = sprintf "var_%d" reg_id in
      let c_type = c_type_from_ir_type ir_type in
      Hashtbl.add ctx.register_vars reg_id var_name;
      Hashtbl.add ctx.var_declarations var_name c_type;
      var_name

(** Generate C value from IR value *)
let generate_c_value_from_ir ctx ir_value =
  match ir_value.value_desc with
  | IRLiteral (IntLit i) -> string_of_int i
  | IRLiteral (CharLit c) -> sprintf "'%c'" c
  | IRLiteral (BoolLit b) -> if b then "true" else "false"
  | IRLiteral (StringLit s) -> sprintf "\"%s\"" s
  | IRLiteral (ArrayLit elems) -> 
      let elem_strs = List.map (function
        | Ast.IntLit i -> string_of_int i
        | Ast.CharLit c -> sprintf "'%c'" c
        | Ast.BoolLit b -> if b then "true" else "false"
        | Ast.StringLit s -> sprintf "\"%s\"" s
        | Ast.ArrayLit _ -> "{...}" (* nested arrays simplified *)
      ) elems in
      sprintf "{%s}" (String.concat ", " elem_strs)
  | IRVariable name -> name
  | IRRegister reg_id -> get_register_var_name ctx reg_id ir_value.val_type
  | IRContextField (_ctx_type, field) -> sprintf "ctx->%s" field
  | IRMapRef map_name -> sprintf "&%s" map_name

(** Generate C expression from IR expression *)
let generate_c_expression_from_ir ctx ir_expr =
  match ir_expr.expr_desc with
  | IRValue ir_value -> generate_c_value_from_ir ctx ir_value
  | IRBinOp (left_val, op, right_val) ->
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
      sprintf "(%s %s %s)" left_str op_str right_str
  | IRUnOp (op, operand_val) ->
      let operand_str = generate_c_value_from_ir ctx operand_val in
      let op_str = match op with
        | IRNot -> "!"
        | IRNeg -> "-"
        | IRBitNot -> "~"
      in
      sprintf "%s%s" op_str operand_str
  | IRCast (value, target_type) ->
      let value_str = generate_c_value_from_ir ctx value in
      let type_str = c_type_from_ir_type target_type in
      sprintf "((%s)%s)" type_str value_str

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
      sprintf "%s = %s;" (generate_c_value_from_ir ctx dest) (generate_c_expression_from_ir ctx src)
  
  | IRCall (func_name, args, result_opt) ->
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
  
  | IRReturn (Some value) ->
      (* In main function, use __return_value instead of immediate return to allow cleanup *)
      if ctx.function_name = "main" then
        sprintf "__return_value = %s; goto cleanup;" (generate_c_value_from_ir ctx value)
      else
        sprintf "return %s;" (generate_c_value_from_ir ctx value)
  
  | IRReturn None ->
      (* In main function, use goto cleanup instead of immediate return *)
      if ctx.function_name = "main" then
        "goto cleanup;"
      else
        "return;"
  
  | IRMapLoad (map_val, key_val, dest_val, load_type) ->
      generate_map_load_from_ir ctx map_val key_val dest_val load_type
  
  | IRMapStore (map_val, key_val, value_val, store_type) ->
      generate_map_store_from_ir ctx map_val key_val value_val store_type
  
  | IRMapDelete (map_val, key_val) ->
      generate_map_delete_from_ir ctx map_val key_val
  
  | IRConfigFieldUpdate (map_val, key_val, field, value_val) ->
      generate_config_field_update_from_ir ctx map_val key_val field value_val
  
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

(** Generate C struct from IR struct definition *)
let generate_c_struct_from_ir ir_struct =
  let fields_str = String.concat ";\n    " 
    (List.map (fun (field_name, field_type) ->
       sprintf "%s %s" (c_type_from_ir_type field_type) field_name
     ) ir_struct.struct_fields)
  in
  sprintf "struct %s {\n    %s;\n};" ir_struct.struct_name fields_str

(** Generate variable declarations for a function *)
let generate_variable_declarations ctx =
  let declarations = Hashtbl.fold (fun var_name c_type acc ->
    sprintf "%s %s;" c_type var_name :: acc
  ) ctx.var_declarations [] in
  if declarations = [] then ""
  else "    " ^ String.concat "\n    " (List.rev declarations) ^ "\n"

(** Generate C function from IR function *)
let generate_c_function_from_ir (ir_func : ir_function) =
  let params_str = String.concat ", " 
    (List.map (fun (name, ir_type) ->
       sprintf "%s %s" (c_type_from_ir_type ir_type) name
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
  
  let adjusted_params = if ir_func.func_name = "main" then "int argc, char **argv" else
    (if params_str = "" then "void" else params_str) in
  
  let adjusted_return_type = if ir_func.func_name = "main" then "int" else return_type_str in
  
  if ir_func.func_name = "main" then
    sprintf {|%s %s(%s) {
    int __return_value = 0;
%s    
    printf("Starting userspace coordinator for eBPF programs\n");
    
    // Initialize BPF programs and maps
    if (setup_bpf_environment() != 0) {
        fprintf(stderr, "Failed to setup BPF environment\n");
        return 1;
    }
    
    // User-defined logic from IR
    %s
    
    cleanup:
    // Cleanup
    cleanup_bpf_environment();
    printf("Userspace coordinator shutting down\n");
    return __return_value;
}|} adjusted_return_type ir_func.func_name adjusted_params var_decls body_c
  else
    sprintf {|%s %s(%s) {
%s    %s
    %s
}|} adjusted_return_type ir_func.func_name adjusted_params var_decls body_c 
      (if return_type_str = "void" then "" else "return 0;")

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

(** Generate map setup code - load from eBPF object *)
let generate_map_setup_code maps =
  List.map (fun map ->
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

(** Generate coordinator logic from IR coordinator *)
let generate_coordinator_logic_c (coordinator : ir_coordinator_logic) map_setup_code base_name =
  let map_mgmt_c = String.concat "\n" (List.map (generate_c_instruction_from_ir (create_userspace_context ())) coordinator.map_management.setup_operations) in
  let prog_lifecycle_c = String.concat "\n" (List.map (generate_c_instruction_from_ir (create_userspace_context ())) coordinator.program_lifecycle.loading_sequence) in
  let event_proc_c = String.concat "\n" (List.map (generate_c_instruction_from_ir (create_userspace_context ())) coordinator.event_processing.event_loop) in
  let signal_handling_c = String.concat "\n" (List.map (generate_c_instruction_from_ir (create_userspace_context ())) coordinator.signal_handling.setup_handlers) in
    
    sprintf {|
/* Generated Coordinator Logic */

struct bpf_object *bpf_obj = NULL;

int setup_bpf_environment() {
    /* Load BPF object file */
    bpf_obj = bpf_object__open("%s.ebpf.o");
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return -1;
    }
    
    /* Load BPF program */
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    /* Extract map file descriptors from loaded eBPF object */
%s
    /* Load all BPF programs from object file */
%s
/* Verify program loading success */
    %s
    return 0;
}

void cleanup_bpf_environment() {
    // Cleanup resources
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
    }
}

void handle_events() {
    /* Main event processing loop */
%s
/* Poll for events from BPF programs */
}

void setup_signal_handlers() {
    /* Setup SIGINT and SIGTERM handlers */
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
%s
}
|} base_name map_setup_code prog_lifecycle_c map_mgmt_c event_proc_c signal_handling_c

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

(** Generate complete userspace program from IR *)
let generate_complete_userspace_program_from_ir ?(config_declarations = []) (userspace_prog : ir_userspace_program) (global_maps : ir_map_def list) source_filename =
  let includes = {|#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/resource.h>

/* Generated from KernelScript IR */
|} in

  (* Reset and use the global config names collector *)
  global_config_names := [];
  
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
  
  (* Generate map-related code using global maps from multi-program *)
  let map_fd_declarations = generate_map_fd_declarations global_maps in
  
  (* Generate config map file descriptors *)
  let config_fd_declarations = List.map (fun config_decl ->
    sprintf "int %s_config_map_fd = -1;" config_decl.Ast.config_name
  ) config_declarations in
  
  let all_fd_declarations = map_fd_declarations :: config_fd_declarations |> String.concat "\n" in
  let map_operation_functions = generate_map_operation_functions global_maps in
  let map_setup_code = generate_map_setup_code global_maps in
  
  (* Generate config map setup code - load from eBPF object *)
  let config_setup_code = List.map (fun config_decl ->
    let config_name = config_decl.Ast.config_name in
    sprintf {|    /* Load %s config map from eBPF object */
    %s_config_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "%s_config_map");
    if (%s_config_map_fd < 0) {
        fprintf(stderr, "Failed to find %s config map in eBPF object\n");
        return -1;
    }|}
      config_name config_name config_name config_name config_name
  ) config_declarations |> String.concat "\n" in
  
  let all_setup_code = map_setup_code ^ "\n" ^ config_setup_code in
  
  (* Extract base name from source filename *)
  let base_name = Filename.remove_extension (Filename.basename source_filename) in
  
  (* Generate coordinator logic with map setup *)
  let coordinator_with_maps = generate_coordinator_logic_c userspace_prog.coordinator_logic all_setup_code base_name in
  
  sprintf {|%s

%s

%s

%s

%s

%s
|} includes structs all_fd_declarations map_operation_functions coordinator_with_maps functions

(** Generate userspace C code from IR multi-program *)
let generate_userspace_code_from_ir ?(config_declarations = []) (ir_multi_prog : ir_multi_program) ?(output_dir = ".") source_filename =
  let content = match ir_multi_prog.userspace_program with
    | Some userspace_prog -> 
        generate_complete_userspace_program_from_ir ~config_declarations userspace_prog ir_multi_prog.global_maps source_filename
    | None -> 
        sprintf {|#include <stdio.h>

int main(int argc, char **argv) {
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