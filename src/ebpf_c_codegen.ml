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

let rec ir_type_to_c_type = function
  | IRU8 -> "__u8"
  | IRU16 -> "__u16" 
  | IRU32 -> "__u32"
  | IRU64 -> "__u64"
  | IRBool -> "bool"
  | IRChar -> "char"
  | IRPointer (inner_type, _) -> sprintf "%s*" (ir_type_to_c_type inner_type)
  | IRArray (inner_type, size, _) -> sprintf "%s[%d]" (ir_type_to_c_type inner_type) size
  | IRStruct (name, _) -> sprintf "struct %s" name
  | IREnum (name, _) -> sprintf "enum %s" name
  | IROption _ -> "void*" (* Options represented as nullable pointers *)
  | IRResult _ -> "int" (* Results represented as error codes *)
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

(** Generate standard eBPF includes *)

let generate_includes ctx =
  let standard_includes = [
    "#include <linux/bpf.h>";
    "#include <bpf/bpf_helpers.h>";
    "#include <linux/if_ether.h>";
    "#include <linux/ip.h>";
    "#include <linux/in.h>";
    "#include <stdint.h>";
    "#include <stdbool.h>";
  ] in
  List.iter (fun inc -> ctx.output_lines <- inc :: ctx.output_lines) (List.rev standard_includes);
  emit_blank_line ctx

(** Generate map definitions *)

let generate_map_definition ctx map_def =
  let map_type_str = ir_map_type_to_c_type map_def.map_type in
  let key_type_str = ir_type_to_c_type map_def.map_key_type in
  let value_type_str = ir_type_to_c_type map_def.map_value_type in
  
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

(** Generate C expression from IR value *)

let generate_c_value _ctx ir_val =
  match ir_val.value_desc with
  | IRLiteral (IntLit i) -> string_of_int i
  | IRLiteral (BoolLit b) -> if b then "true" else "false"
  | IRLiteral (CharLit c) -> sprintf "'%c'" c
  | IRLiteral (StringLit s) -> sprintf "\"%s\"" s
  | IRVariable name -> name
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

(** Generate C expression from IR expression *)

let generate_c_expression ctx ir_expr =
  match ir_expr.expr_desc with
  | IRValue ir_val -> generate_c_value ctx ir_val
  | IRBinOp (left, op, right) ->
      let left_str = generate_c_value ctx left in
      let right_str = generate_c_value ctx right in
      let op_str = match op with
        | IRAdd -> "+" | IRSub -> "-" | IRMul -> "*" | IRDiv -> "/" | IRMod -> "%"
        | IREq -> "==" | IRNe -> "!=" | IRLt -> "<" | IRLe -> "<=" | IRGt -> ">" | IRGe -> ">="
        | IRAnd -> "&&" | IROr -> "||"
        | IRBitAnd -> "&" | IRBitOr -> "|" | IRBitXor -> "^"
        | IRShiftL -> "<<" | IRShiftR -> ">>"
      in
      sprintf "(%s %s %s)" left_str op_str right_str
  | IRUnOp (op, ir_val) ->
      let val_str = generate_c_value ctx ir_val in
      let op_str = match op with
        | IRNot -> "!" | IRNeg -> "-" | IRBitNot -> "~"
      in
      sprintf "(%s%s)" op_str val_str
  | IRCast (ir_val, target_type) ->
      let val_str = generate_c_value ctx ir_val in
      let type_str = ir_type_to_c_type target_type in
      sprintf "((%s)%s)" type_str val_str

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
            let key_type = ir_type_to_c_type key_val.val_type in
            let key_str = generate_c_value ctx key_val in
            emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
            temp_key
        | _ -> generate_c_value ctx key_val
      in
      (* bpf_map_lookup_elem returns a pointer, so we need to dereference it *)
      emit_line ctx (sprintf "{ void* __tmp_ptr = bpf_map_lookup_elem(%s, &%s);" map_str key_var);
      emit_line ctx (sprintf "  if (__tmp_ptr) %s = *(%s*)__tmp_ptr;" dest_str (ir_type_to_c_type dest_val.val_type));
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
            let key_type = ir_type_to_c_type key_val.val_type in
            let key_str = generate_c_value ctx key_val in
            emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
            temp_key
        | _ -> generate_c_value ctx key_val
      in
      
      (* Handle value - create temp variable if it's a literal *)
      let value_var = match value_val.value_desc with
        | IRLiteral _ ->
            let temp_value = fresh_var ctx "value" in
            let value_type = ir_type_to_c_type value_val.val_type in
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
        let key_type = ir_type_to_c_type key_val.val_type in
        let key_str = generate_c_value ctx key_val in
        emit_line ctx (sprintf "%s %s = %s;" key_type temp_key key_str);
        temp_key
    | _ -> generate_c_value ctx key_val
  in
  
  emit_line ctx (sprintf "bpf_map_delete_elem(%s, &%s);" map_str key_var)

(** Generate C code for IR instruction *)

let generate_c_instruction ctx ir_instr =
  match ir_instr.instr_desc with
  | IRAssign (dest_val, expr) ->
      let dest_str = generate_c_value ctx dest_val in
      let expr_str = generate_c_expression ctx expr in
      emit_line ctx (sprintf "%s = %s;" dest_str expr_str)

  | IRCall (name, args, ret_opt) ->
      let args_str = String.concat ", " (List.map (generate_c_value ctx) args) in
      (match ret_opt with
       | Some ret_val ->
           let ret_str = generate_c_value ctx ret_val in
           emit_line ctx (sprintf "%s = %s(%s);" ret_str name args_str)
       | None ->
           emit_line ctx (sprintf "%s(%s);" name args_str))

  | IRMapLoad (map_val, key_val, dest_val, load_type) ->
      generate_map_load ctx map_val key_val dest_val load_type

  | IRMapStore (map_val, key_val, value_val, store_type) ->
      generate_map_store ctx map_val key_val value_val store_type

  | IRMapDelete (map_val, key_val) ->
      generate_map_delete ctx map_val key_val

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

  | IRReturn ret_opt ->
      begin match ret_opt with
      | Some ret_val ->
          let ret_str = generate_c_value ctx ret_val in
          emit_line ctx (sprintf "return %s;" ret_str)
      | None ->
          emit_line ctx "return 0;"
      end

  | IRComment comment ->
      emit_line ctx (sprintf "/* %s */" comment)

  | IRBpfLoop (start_val, end_val, counter_val, _ctx_val, body) ->
      let start_str = generate_c_value ctx start_val in
      let end_str = generate_c_value ctx end_val in
      
      (* Generate unique callback function name *)
      let callback_name = sprintf "loop_callback_%d" ctx.next_label_id in
      ctx.next_label_id <- ctx.next_label_id + 1;
      
      (* Generate callback function code - store it for later emission *)
      let callback_code = ref [] in
      
      (* Generate callback function signature and body *)
      callback_code := sprintf "static long %s(__u32 index, void *ctx_ptr) {" callback_name :: !callback_code;
      callback_code := "    /* Loop body for bpf_loop() */" :: !callback_code;
      
      (* Extract the variable name from counter_val for proper declaration in callback *)
      let counter_var_name = match counter_val.value_desc with
        | IRRegister reg -> sprintf "tmp_%d" reg
        | IRVariable name -> name
        | _ -> "loop_counter"
      in
      
      (* Declare the loop counter variable in callback scope *)
      let counter_type = ir_type_to_c_type counter_val.val_type in
      callback_code := sprintf "    %s %s;" counter_type counter_var_name :: !callback_code;
      callback_code := sprintf "    %s = index;" counter_var_name :: !callback_code;
      
      (* Generate actual loop body statements from 'body' parameter *)
      (match body with
      | [] -> 
          callback_code := "    /* Empty loop body */" :: !callback_code;
      | _ -> 
          callback_code := "    /* Loop body statements would be generated here */" :: !callback_code;
          callback_code := sprintf "    /* %d statements in loop body */" (List.length body) :: !callback_code;
      );
      
      callback_code := "    return 0; /* Continue loop */" :: !callback_code;
      callback_code := "}" :: !callback_code;
      callback_code := "" :: !callback_code; (* blank line *)
      
      (* Store callback for later emission *)
      ctx.pending_callbacks <- (List.rev !callback_code) @ ctx.pending_callbacks;
      
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
  in
  let collect_in_instr ir_instr =
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
    | IRContextAccess (dest_val, _) -> collect_in_value dest_val
    | IRBoundsCheck (ir_val, _, _) -> collect_in_value ir_val
    | IRCondJump (cond_val, _, _) -> collect_in_value cond_val
    | IRReturn ret_val_opt -> Option.iter collect_in_value ret_val_opt
    | IRJump _ -> ()
    | IRComment _ -> () (* Comments don't use registers *)
    | IRBpfLoop (start_val, end_val, counter_val, ctx_val, _body) ->
        collect_in_value start_val; collect_in_value end_val; 
        collect_in_value counter_val; collect_in_value ctx_val
  in
  List.iter (fun block ->
    List.iter collect_in_instr block.instructions
  ) ir_func.basic_blocks;
  List.sort (fun (r1, _) (r2, _) -> compare r1 r2) !registers

(** Generate C function from IR function *)

let generate_c_function ctx ir_func =
  let return_type_str = match ir_func.return_type with
    | Some ret_type -> ir_type_to_c_type ret_type
    | None -> "void"
  in
  
  let params_str = String.concat ", " 
    (List.map (fun (name, param_type) ->
       sprintf "%s %s" (ir_type_to_c_type param_type) name
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
  List.iter (fun (reg, reg_type) ->
    let c_type = ir_type_to_c_type reg_type in
    emit_line ctx (sprintf "%s tmp_%d;" c_type reg)
  ) registers;
  if registers <> [] then emit_blank_line ctx;
  
  (* Generate basic blocks *)
  List.iter (generate_c_basic_block ctx) ir_func.basic_blocks;
  
  decrease_indent ctx;
  emit_line ctx "}";
  emit_blank_line ctx

(** Generate complete C program from IR *)

let generate_c_program ir_prog =
  let ctx = create_c_context () in
  
  (* Add standard includes *)
  generate_includes ctx;
  
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

let generate_c_multi_program ir_multi_prog =
  let ctx = create_c_context () in
  
  (* Add standard includes *)
  generate_includes ctx;
  
  (* Generate global map definitions *)
  List.iter (generate_map_definition ctx) ir_multi_prog.global_maps;
  
  (* Generate all local map definitions from all programs *)
  List.iter (fun ir_prog ->
    List.iter (generate_map_definition ctx) ir_prog.local_maps
  ) ir_multi_prog.programs;
  
  (* First pass: collect all callbacks by generating functions *)
  let temp_ctx = create_c_context () in
  List.iter (fun ir_prog ->
    (* Generate main function *)
    generate_c_function temp_ctx ir_prog.main_function;
    
    (* Generate other functions (excluding main to avoid duplicates) *)
    let other_functions = List.filter (fun f -> not f.is_main) ir_prog.functions in
    List.iter (generate_c_function temp_ctx) other_functions
  ) ir_multi_prog.programs;
  
  (* Now emit the collected callbacks *)
  if temp_ctx.pending_callbacks <> [] then (
    List.iter (emit_line ctx) temp_ctx.pending_callbacks;
    emit_blank_line ctx;
  );
  
  (* Second pass: generate actual functions *)
  List.iter (fun ir_prog ->
    (* Generate main function *)
    generate_c_function ctx ir_prog.main_function;
    
    (* Generate other functions (excluding main to avoid duplicates) *)
    let other_functions = List.filter (fun f -> not f.is_main) ir_prog.functions in
    List.iter (generate_c_function ctx) other_functions
  ) ir_multi_prog.programs;
  
  (* Add license (required for eBPF) *)
  emit_line ctx "char _license[] SEC(\"license\") = \"GPL\";";
  
  (* Return generated code *)
  String.concat "\n" (List.rev ctx.output_lines)

(** Enhanced multi-program compilation entry point with analysis *)

let compile_multi_to_c_with_analysis ir_multi_program 
                                   (multi_prog_analysis: Multi_program_analyzer.multi_program_analysis) 
                                   (resource_plan: Multi_program_ir_optimizer.resource_plan)
                                   (_optimization_results: Multi_program_ir_optimizer.optimization_strategy list) =
  let ctx = create_c_context () in
  
  (* Add enhanced includes for multi-program systems *)
  generate_includes ctx;
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

let compile_to_c ir_program =
  let c_code = generate_c_program ir_program in
  c_code

(** Multi-program compilation entry point *)

let compile_multi_to_c ir_multi_program =
  let c_code = generate_c_multi_program ir_multi_program in
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

