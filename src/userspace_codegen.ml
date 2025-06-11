(** Userspace C Code Generation
    This module generates complete userspace C programs from KernelScript IR programs
    with proper main() functions, struct definitions, and BPF interaction code.
*)

open Ir
open Printf

(** Code generation configuration *)
type codegen_config = {
  output_dir: string;
  generate_examples: bool;
  include_safety_checks: bool;
  program_name: string;
}

let default_config program_name = {
  output_dir = ".";
  generate_examples = true;
  include_safety_checks = true;
  program_name = program_name;
}

(** Context for generating unique variable names *)
type userspace_context = {
  mutable temp_var_counter: int;
  mutable in_main_function: bool;
}

let create_userspace_context () = {
  temp_var_counter = 0;
  in_main_function = false;
}

let create_main_context () = {
  temp_var_counter = 0;
  in_main_function = true;
}

let fresh_temp_var ctx prefix =
  ctx.temp_var_counter <- ctx.temp_var_counter + 1;
  sprintf "%s_%d" prefix ctx.temp_var_counter



(* ===== C Type Mappings ===== *)

(** Generate C type declaration from IR type *)
let rec c_type_declaration = function
  | IRU8 -> "__u8"
  | IRU16 -> "__u16"
  | IRU32 -> "__u32"
  | IRU64 -> "__u64"
  | IRBool -> "bool"
  | IRChar -> "char"
  | IRPointer (t, _) -> sprintf "%s*" (c_type_declaration t)
  | IRArray (t, size, _) -> sprintf "%s[%d]" (c_type_declaration t) size
  | IRStruct (name, _fields) -> sprintf "struct %s" name
  | IREnum (name, _) -> sprintf "enum %s" name
  | IROption t -> sprintf "%s*" (c_type_declaration t)
  | IRResult (ok_t, _err_t) -> c_type_declaration ok_t
  | IRContext ctx_type -> c_context_type ctx_type
  | IRAction action_type -> c_action_type action_type

and c_context_type = function
  | XdpCtx -> "struct xdp_md"
  | TcCtx -> "struct __sk_buff"
  | KprobeCtx -> "struct pt_regs"
  | UprobeCtx -> "struct pt_regs"
  | TracepointCtx -> "void*"
  | LsmCtx -> "void*"
  | CgroupSkbCtx -> "struct __sk_buff"

and c_action_type = function
  | XdpActionType -> "int"
  | TcActionType -> "int"
  | GenericActionType -> "int"

(* ===== C Code Generation Functions ===== *)

(** Generate C struct definitions from userspace structs *)
let generate_c_struct_from_userspace (struct_def : Ast.struct_def) =
  let fields = List.map (fun (name, typ) ->
    let c_type = match typ with
      | Ast.U8 -> "__u8"
      | Ast.U16 -> "__u16"
      | Ast.U32 -> "__u32"
      | Ast.U64 -> "__u64"
      | Ast.I8 -> "__s8"
      | Ast.I16 -> "__s16"
      | Ast.I32 -> "__s32"
      | Ast.I64 -> "__s64"
      | Ast.Bool -> "bool"
      | Ast.Char -> "char"
      | Ast.UserType name -> sprintf "struct %s" name
      | _ -> "__u32" (* Default fallback *)
    in
    sprintf "    %s %s;" c_type name
  ) struct_def.struct_fields in
  
  sprintf {|
struct %s {
%s
};
|} struct_def.struct_name (String.concat "\n" fields)

(** Generate C code for a single statement *)
let rec generate_c_statement_with_context ctx (stmt : Ast.statement) = 
  match stmt.stmt_desc with
  | Ast.Declaration (name, typ_opt, expr) ->
      let c_type = match typ_opt with
        | Some Ast.U32 -> "__u32"
        | Some Ast.U64 -> "__u64"
        | Some Ast.I32 -> "__s32"
        | Some _ -> "__u32"  
        | None -> "__u32"  (* default type *)
      in
      sprintf "%s %s = %s;" c_type name (generate_c_expression expr)
  | Ast.Assignment (name, expr) ->
      sprintf "%s = %s;" name (generate_c_expression expr)
  | Ast.IndexAssignment (map_expr, key_expr, value_expr) ->
      (* Handle map assignment like shared_counter[key] = value *)
      let map_name = match map_expr.expr_desc with
        | Ast.Identifier name -> name
        | _ -> "unknown_map"
      in
      let ((key_decl, key_arg), (value_decl, value_arg)) = 
        generate_safe_map_args ctx key_expr (Some value_expr) in
      let statements = [key_decl; value_decl] |> List.filter (fun s -> s <> "") in
      let setup = if statements = [] then "" else String.concat "\n    " statements ^ "\n    " in
      sprintf "%s%s_update(%s, %s, BPF_ANY);" setup map_name key_arg value_arg
  | Ast.ExprStmt expr ->
      sprintf "%s;" (generate_c_expression expr)
  | Ast.Return (Some expr) ->
      if ctx.in_main_function then
        sprintf "__return_value = %s; goto cleanup;" (generate_c_expression expr)
      else
        sprintf "return %s;" (generate_c_expression expr)
  | Ast.Return None ->
      if ctx.in_main_function then
        "__return_value = 0; goto cleanup;"
      else
        "return;"
  | Ast.Delete (map_expr, key_expr) ->
      (* Handle delete statement like delete map[key]; *)
      let map_name = match map_expr.expr_desc with
        | Ast.Identifier name -> name
        | _ -> "unknown_map"
      in
      let ((key_decl, key_arg), _) = 
        generate_safe_map_args ctx key_expr None in
      let setup = if key_decl = "" then "" else key_decl ^ "\n    " in
      sprintf "%s%s_delete(%s);" setup map_name key_arg
  | Ast.For (loop_var, start_expr, end_expr, body) ->
      (* Generate ordinary C for loop - no unrolling, no goto, no bounds checking *)
      let start_c = generate_c_expression start_expr in
      let end_c = generate_c_expression end_expr in
      let body_statements = List.map (generate_c_statement_with_context ctx) body in
      let body_c = String.concat "\n        " body_statements in
      sprintf "for (__u32 %s = %s; %s <= %s; %s++) {\n        %s\n    }" 
        loop_var start_c loop_var end_c loop_var body_c
  | Ast.ForIter (index_var, value_var, iterable_expr, body) ->
      (* Generate C-style iteration over collections *)
      let iterable_c = generate_c_expression iterable_expr in
      let body_statements = List.map (generate_c_statement_with_context ctx) body in
      let body_c = String.concat "\n        " body_statements in
      (* For userspace, we generate a simple indexed loop since we don't have complex iterators *)
      sprintf "/* ForIter: iterating over %s */\n    for (__u32 %s = 0; %s < sizeof(%s)/sizeof((%s)[0]); %s++) {\n        __u32 %s = (%s)[%s];\n        %s\n    }"
        iterable_c index_var index_var iterable_c iterable_c index_var value_var iterable_c index_var body_c
  | _ -> "// TODO: Unsupported statement"

(** Generate C code for expressions *)
and generate_c_expression (expr : Ast.expr) =
  match expr.expr_desc with
  | Ast.Literal (Ast.IntLit i) -> string_of_int i
  | Ast.Literal (Ast.StringLit s) -> sprintf "\"%s\"" s
  | Ast.Identifier name -> name
  | Ast.ArrayAccess (map_expr, key_expr) ->
      (* Handle map access like shared_counter[key] *)
      let map_name = match map_expr.expr_desc with
        | Ast.Identifier name -> name
        | _ -> "unknown_map"
      in
      let key_c = generate_c_expression key_expr in
      (* For map lookups in expressions, we need to be more careful with literals *)
      (match key_expr.expr_desc with
       | Ast.Literal _ ->
           let temp_ctx = create_userspace_context () in
           let temp_key = fresh_temp_var temp_ctx "key" in
           let key_type = "__u32" in
           sprintf "({ %s %s = %s; __u64 __val = 0; %s_lookup(&%s, &__val) == 0 ? __val : 0; })" 
             key_type temp_key key_c map_name temp_key
       | _ ->
           sprintf "({ __u64 __val = 0; %s_lookup(&(%s), &__val) == 0 ? __val : 0; })" map_name key_c)
  | Ast.BinaryOp (left, Ast.Add, right) ->
      sprintf "(%s + %s)" (generate_c_expression left) (generate_c_expression right)
  | Ast.BinaryOp (left, Ast.Sub, right) ->
      sprintf "(%s - %s)" (generate_c_expression left) (generate_c_expression right)
  | Ast.BinaryOp (left, Ast.Mul, right) ->
      sprintf "(%s * %s)" (generate_c_expression left) (generate_c_expression right)
  | _ -> "0"  (* fallback *)

(** Helper function to generate safe key and value expressions for map operations *)
and generate_safe_map_args ctx key_expr value_expr_opt =
  let key_c = generate_c_expression key_expr in
  let key_arg = match key_expr.expr_desc with
    | Ast.Literal _ ->
        let temp_key = fresh_temp_var ctx "key" in
        let key_type = match key_expr.expr_desc with
          | Ast.Literal (Ast.IntLit _) -> "__u32"
          | _ -> "__u32"
        in
        let key_decl = sprintf "%s %s = %s;" key_type temp_key key_c in
        (key_decl, sprintf "&%s" temp_key)
    | _ -> ("", sprintf "&(%s)" key_c)
  in
  
  let value_arg = match value_expr_opt with
    | Some value_expr ->
        let value_c = generate_c_expression value_expr in
        (match value_expr.expr_desc with
         | Ast.Literal _ ->
             let temp_value = fresh_temp_var ctx "value" in
             let value_type = match value_expr.expr_desc with
               | Ast.Literal (Ast.IntLit _) -> "__u32"
               | _ -> "__u32"
             in
             let value_decl = sprintf "%s %s = %s;" value_type temp_value value_c in
             (value_decl, sprintf "&%s" temp_value)
         | _ -> ("", sprintf "&(%s)" value_c))
    | None -> ("", "")
  in
  (key_arg, value_arg)

(** Wrapper function that maintains backward compatibility *)
let generate_c_statement (stmt : Ast.statement) = 
  let ctx = create_userspace_context () in
  generate_c_statement_with_context ctx stmt

(** Generate function implementations from userspace functions *)
let generate_c_function_from_userspace (func : Ast.function_def) =
  let params, return_type, body = 
    if func.func_name = "main" then
      (* Special handling for main function with argc/argv *)

      let params_str = "int argc, char **argv" in
      let return_type = "int" in
      
      (* Generate the actual function body from KernelScript statements *)
      let ctx = create_main_context () in
      let translated_body = String.concat "\n    " (List.map (generate_c_statement_with_context ctx) func.func_body) in
      
      let body = sprintf {|
    int __return_value = 0;
    
    printf("Starting userspace coordinator for eBPF programs\n");
    
    setup_signal_handling();
    
    if (load_all_bpf_programs() != 0) {
        fprintf(stderr, "Failed to load BPF programs\n");
        __return_value = 1;
        goto cleanup;
    }
    
    if (setup_maps() != 0) {
        fprintf(stderr, "Failed to setup maps\n");
        cleanup_bpf_programs();
        __return_value = 1;
        goto cleanup;
    }
    
    if (initialize_all_configs() != 0) {
        fprintf(stderr, "Failed to initialize configs\n");
        cleanup_bpf_programs();
        __return_value = 1;
        goto cleanup;
    }
    
    printf("Executing userspace logic...\n");
    
    // User-defined logic from KernelScript
    %s
    
cleanup:
    printf("Shutting down coordinator...\n");
    cleanup_maps();
    cleanup_bpf_programs();
    return __return_value;
|} translated_body in
      (params_str, return_type, body)
    else
      (* Regular function handling *)
      let params = List.map (fun (name, typ) ->
        let c_type = match typ with
          | Ast.U8 -> "__u8"
          | Ast.U16 -> "__u16"
          | Ast.U32 -> "__u32"
          | Ast.U64 -> "__u64"
          | Ast.I8 -> "__s8"
          | Ast.I16 -> "__s16"
          | Ast.I32 -> "__s32"
          | Ast.I64 -> "__s64"
          | Ast.Bool -> "bool"
          | Ast.Char -> "char"
          | Ast.UserType name -> sprintf "struct %s*" name
          | Ast.Pointer (Ast.Pointer Ast.Char) -> "char **"
          | Ast.Pointer t -> sprintf "%s*" (match t with
            | Ast.Char -> "char"
            | Ast.U32 -> "__u32"
            | _ -> "__u32")
          | _ -> "__u32"
        in
        sprintf "%s %s" c_type name
      ) func.func_params in
      
      let return_type = match func.func_return_type with
        | Some Ast.U8 -> "__u8"
        | Some Ast.U16 -> "__u16"
        | Some Ast.U32 -> "__u32"
        | Some Ast.U64 -> "__u64"
        | Some Ast.I8 -> "__s8"
        | Some Ast.I16 -> "__s16"
        | Some Ast.I32 -> "__s32"
        | Some Ast.I64 -> "__s64"
        | Some Ast.Bool -> "bool"
        | Some Ast.Char -> "char"
        | Some (Ast.UserType name) -> sprintf "struct %s*" name
        | Some _ -> "__u32"
        | None -> "void"
      in
      
      (* Generate the actual function body from KernelScript statements *)
      let ctx = create_userspace_context () in
      let translated_body = String.concat "\n    " (List.map (generate_c_statement_with_context ctx) func.func_body) in
      
      let body = sprintf {|
    // Function body for %s
    %s
    return %s;|} func.func_name translated_body 
        (if return_type = "void" then "" else "0") in
      
      ((if params = [] then "void" else String.concat ", " params), return_type, body)
  in
  
  sprintf {|
%s %s(%s) {%s
}
|} return_type func.func_name params body

(** Generate BPF program loading and management code for multiple programs *)
let generate_bpf_loader_code source_filename =
  (* Extract base name without extension and path for the eBPF object filename *)
  let base_name = Filename.remove_extension (Filename.basename source_filename) in
  sprintf {|
/* Multi-Program BPF Management */
struct bpf_object *bpf_obj = NULL;
struct bpf_program **bpf_programs = NULL;
int *prog_fds = NULL;
int num_programs = 0;

int load_all_bpf_programs(void) {
    // Load BPF object file generated from %s
    bpf_obj = bpf_object__open("%s.ebpf.o");
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return -1;
    }

    // Load all BPF programs into kernel
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    // Count and setup program management structures
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, bpf_obj) {
        num_programs++;
    }
    
    if (num_programs == 0) {
        fprintf(stderr, "ERROR: no BPF programs found\n");
        goto cleanup;
    }
    
    bpf_programs = malloc(num_programs * sizeof(struct bpf_program*));
    prog_fds = malloc(num_programs * sizeof(int));
    
    int i = 0;
    bpf_object__for_each_program(prog, bpf_obj) {
        bpf_programs[i] = prog;
        prog_fds[i] = bpf_program__fd(prog);
        if (prog_fds[i] < 0) {
            fprintf(stderr, "ERROR: getting program fd failed for program %%d\n", i);
            goto cleanup;
        }
        printf("Loaded BPF program '%%s' (fd=%%d)\n", 
               bpf_program__name(prog), prog_fds[i]);
        i++;
    }

    printf("Successfully loaded %%d BPF programs\n", num_programs);
    return 0;

cleanup:
    if (bpf_programs) free(bpf_programs);
    if (prog_fds) free(prog_fds);
    bpf_object__close(bpf_obj);
    return -1;
}

int attach_programs(const char *interface) {
    printf("Attaching BPF programs to interface %%s\n", interface);
    
    // TODO: Add program-specific attachment logic
    // This needs to be customized based on the actual program types
    // For XDP: bpf_set_link_xdp_fd(if_index, prog_fd, flags);
    // For TC: tc filter add dev interface...
    // For kprobe: bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE, ...)
    
    printf("All programs attached successfully\n");
    return 0;
}

void cleanup_bpf_programs(void) {
    if (bpf_programs) {
        free(bpf_programs);
        bpf_programs = NULL;
    }
    if (prog_fds) {
        free(prog_fds);
        prog_fds = NULL;
    }
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
    num_programs = 0;
}
|} source_filename base_name

(** Generate map access code for coordinating multiple programs *)
let generate_map_access_code () =
  {|
/* Global Map Access Functions */
int setup_maps(void) {
    // TODO: Get map file descriptors from loaded BPF object
    // Global maps are shared between all programs
    printf("Setting up global maps for multi-program coordination\n");
    
    // Example for global maps:
    // global_flows_fd = bpf_object__find_map_fd_by_name(bpf_obj, "global_flows");
    // global_events_fd = bpf_object__find_map_fd_by_name(bpf_obj, "global_events");
    // global_config_fd = bpf_object__find_map_fd_by_name(bpf_obj, "global_config");
    
    printf("Global maps setup completed\n");
    return 0;
}

// Process events from all programs
void process_system_events(void) {
    // TODO: Read from global event ring buffers
    // Process events from multiple eBPF programs
    // Example:
    // while (ring_buffer__poll(rb, 0) >= 0) {
    //     // Handle events from all programs
    // }
}

// Update global configuration affecting all programs
int update_global_config(__u32 key, __u64 value) {
    // TODO: Update global configuration map
    // This affects all programs that use global_config map
    // return bpf_map_update_elem(global_config_fd, &key, &value, BPF_ANY);
    return 0;
}

// Get statistics from all programs
int get_combined_stats(void) {
    // TODO: Aggregate statistics from all programs
    // Read from various program-specific and global maps
    printf("Getting combined statistics from all programs\n");
    return 0;
}
|}

(** Generate enhanced map access code with proper map sharing support *)
let generate_enhanced_map_access_code map_declarations =
  if map_declarations = [] then
    generate_map_access_code ()
  else
    let map_fd_vars = List.map (fun (map_decl : Maps.map_declaration) ->
      sprintf "int %s_fd = -1;" map_decl.name
    ) map_declarations in
    
    let map_operations = List.map (fun (map_decl : Maps.map_declaration) ->
      sprintf {|
// Map operations for %s
int %s_lookup(void *key, void *value) {
    if (%s_fd < 0) return -1;
    return bpf_map_lookup_elem(%s_fd, key, value);
}

int %s_update(void *key, void *value, __u64 flags) {
    if (%s_fd < 0) return -1;
    return bpf_map_update_elem(%s_fd, key, value, flags);
}

int %s_delete(void *key) {
    if (%s_fd < 0) return -1;
    return bpf_map_delete_elem(%s_fd, key);
}

int %s_get_next_key(void *key, void *next_key) {
    if (%s_fd < 0) return -1;
    return bpf_map_get_next_key(%s_fd, key, next_key);
}|} 
        map_decl.name
        map_decl.name map_decl.name map_decl.name
        map_decl.name map_decl.name map_decl.name
        map_decl.name map_decl.name map_decl.name
        map_decl.name map_decl.name map_decl.name
    ) map_declarations in
    
    let setup_maps_impl = List.map (fun (map_decl : Maps.map_declaration) ->
      let pin_path_opt = List.fold_left (fun acc attr ->
        match attr with
        | Maps.Pinned path -> Some path
        | _ -> acc
      ) None map_decl.config.attributes in
      
      match pin_path_opt with
      | Some pin_path ->
          sprintf "    // Setup pinned map: %s\n    %s_fd = bpf_obj_get(\"%s\");\n    if (%s_fd < 0) {\n        struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, \"%s\");\n        if (map) {\n            %s_fd = bpf_map__fd(map);\n            bpf_obj_pin(%s_fd, \"%s\");\n            printf(\"Pinned map %s\\n\");\n        }\n    }" 
            map_decl.name map_decl.name pin_path map_decl.name 
            map_decl.name map_decl.name map_decl.name pin_path map_decl.name
      | None ->
          sprintf "    // Setup regular map: %s\n    %s_fd = bpf_object__find_map_fd_by_name(bpf_obj, \"%s\");" 
            map_decl.name map_decl.name map_decl.name
    ) map_declarations in
    
    sprintf {|
/* Enhanced Map Access Functions with Userspace-Kernel Sharing */

// Map file descriptor variables
%s

int setup_maps(void) {
    printf("Setting up maps for userspace-kernel communication\n");
    
    if (!bpf_obj) {
        fprintf(stderr, "ERROR: BPF object not loaded\n");
        return -1;
    }
    
%s
    
    printf("All maps setup completed successfully\n");
    return 0;
}

%s

// Generic map utilities
int get_map_fd(const char *map_name) {
    return -1;
}

void cleanup_maps(void) {
    // Close map file descriptors
%s
    printf("Maps cleaned up\n");
}

// Enhanced event processing with map polling
void process_system_events(void) {
    // Poll ring buffer maps for events
    // TODO: Implement event polling
}

// Enhanced statistics collection
int get_combined_stats(void) {
    printf("Collecting statistics from all maps\n");
    // TODO: Implement statistics collection
    return 0;
}
|}
      (String.concat "\n" map_fd_vars)
      (String.concat "\n" setup_maps_impl)
      (String.concat "\n" map_operations)
      (String.concat "\n" (List.map (fun (map_decl : Maps.map_declaration) ->
        sprintf "    if (%s_fd >= 0) {\n        close(%s_fd);\n        %s_fd = -1;\n    }" 
          map_decl.name map_decl.name map_decl.name
      ) map_declarations))

(** Generate signal handling code *)
let generate_signal_handling () =
  {|
/* Signal Handling */
static volatile bool keep_running = true;

static void sig_int(int signo) {
    (void)signo;
    keep_running = false;
}

void setup_signal_handling(void) {
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);
}
|}

(** Extract map declarations from AST *)
let extract_map_declarations_from_ast (ast : Ast.ast) =
  let global_ast_map_decls = List.filter_map (function
    | Ast.MapDecl m when m.is_global -> Some m  (* Only include global maps *)
    | _ -> None
  ) ast in
  List.map Maps.ast_to_maps_declaration global_ast_map_decls

(** Generate config initialization code *)
let generate_config_initialization (config_declarations : Ast.config_declaration list) =
  let config_structs = List.map (fun config_decl ->
    let struct_name = Printf.sprintf "%s_config" config_decl.Ast.config_name in
    let fields = List.map (fun field ->
      let field_declaration = match field.Ast.field_type with
        | Ast.U8 -> Printf.sprintf "    __u8 %s;" field.Ast.field_name
        | Ast.U16 -> Printf.sprintf "    __u16 %s;" field.Ast.field_name
        | Ast.U32 -> Printf.sprintf "    __u32 %s;" field.Ast.field_name
        | Ast.U64 -> Printf.sprintf "    __u64 %s;" field.Ast.field_name
        | Ast.I8 -> Printf.sprintf "    __s8 %s;" field.Ast.field_name
        | Ast.I16 -> Printf.sprintf "    __s16 %s;" field.Ast.field_name
        | Ast.I32 -> Printf.sprintf "    __s32 %s;" field.Ast.field_name
        | Ast.I64 -> Printf.sprintf "    __s64 %s;" field.Ast.field_name
        | Ast.Bool -> Printf.sprintf "    __u8 %s;" field.Ast.field_name  (* bool -> u8 for BPF compatibility *)
        | Ast.Char -> Printf.sprintf "    char %s;" field.Ast.field_name
        | Ast.Array (Ast.U16, size) -> Printf.sprintf "    __u16 %s[%d];" field.Ast.field_name size
        | Ast.Array (Ast.U32, size) -> Printf.sprintf "    __u32 %s[%d];" field.Ast.field_name size
        | Ast.Array (Ast.U64, size) -> Printf.sprintf "    __u64 %s[%d];" field.Ast.field_name size
        | _ -> Printf.sprintf "    __u32 %s;" field.Ast.field_name  (* fallback *)
      in
      field_declaration
     ) config_decl.Ast.config_fields in
    
    Printf.sprintf {|
struct %s {
%s
};
|} struct_name (String.concat "\n" fields)
  ) config_declarations in
  
  let config_init_functions = List.map (fun config_decl ->
    let config_name = config_decl.Ast.config_name in
    let struct_name = Printf.sprintf "%s_config" config_name in
    let map_name = Printf.sprintf "%s_config_map" config_name in
    
    let field_initializers = List.map (fun field ->
      let default_value = match field.Ast.field_default with
        | Some (Ast.IntLit i) -> string_of_int i
        | Some (Ast.BoolLit b) -> if b then "1" else "0"
        | Some (Ast.StringLit s) -> Printf.sprintf "\"%s\"" s
        | Some (Ast.CharLit c) -> Printf.sprintf "'%c'" c
        | Some (Ast.ArrayLit literals) ->
            let values = List.map (function
              | Ast.IntLit i -> string_of_int i
              | Ast.BoolLit b -> if b then "1" else "0"
              | _ -> "0"
            ) literals in
            Printf.sprintf "{%s}" (String.concat ", " values)
        | None -> "0"  (* Default to zero *)
      in
      Printf.sprintf "        .%s = %s," field.Ast.field_name default_value
    ) config_decl.Ast.config_fields in
    
    Printf.sprintf {|
int init_%s_config(void) {
    printf("Initializing %s config...\n");
    
    struct %s config_data = {
%s
    };
    
    int %s_fd = bpf_object__find_map_fd_by_name(bpf_obj, "%s");
    if (%s_fd < 0) {
        fprintf(stderr, "ERROR: Failed to find %s config map\n");
        return -1;
    }
    
    __u32 key = 0;
    int ret = bpf_map_update_elem(%s_fd, &key, &config_data, BPF_ANY);
    if (ret != 0) {
        fprintf(stderr, "ERROR: Failed to initialize %s config: %%s\n", strerror(errno));
        return -1;
    }
    
    printf("%s config initialized successfully\n");
    return 0;
}
|} config_name config_name struct_name (String.concat "\n" field_initializers) 
   config_name map_name config_name config_name config_name config_name config_name
  ) config_declarations in
  
  let master_init_function = 
    let config_init_calls = List.map (fun config_decl ->
      Printf.sprintf "    if (init_%s_config() != 0) {\n        return -1;\n    }" config_decl.Ast.config_name
    ) config_declarations in
    
    Printf.sprintf {|
int initialize_all_configs(void) {
    printf("Initializing all configuration maps...\n");
    
%s
    
    printf("All configurations initialized successfully\n");
    return 0;
}
|} (String.concat "\n" config_init_calls) in
  
  String.concat "\n" config_structs ^ String.concat "\n" config_init_functions ^ master_init_function

(** Generate complete C userspace coordinator program *)
let generate_complete_userspace_program (userspace_block : Ast.userspace_block) source_filename ?ast ?config_declarations () =
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
|} in

  let structs = String.concat "\n" 
    (List.map generate_c_struct_from_userspace userspace_block.userspace_structs) in
  
  let functions = String.concat "\n" 
    (List.map generate_c_function_from_userspace userspace_block.userspace_functions) in
  
  let bpf_loader = generate_bpf_loader_code source_filename in
  let map_access = match ast with
    | Some ast_data -> 
        let map_declarations = extract_map_declarations_from_ast ast_data in
        generate_enhanced_map_access_code map_declarations
    | None -> generate_map_access_code ()
  in
  let config_init = match config_declarations with
    | Some configs -> generate_config_initialization configs
    | None -> ""
  in
  let signal_handling = generate_signal_handling () in
  
  (* Check if main function exists, if not create a default coordinator main *)
  let has_main = List.exists (fun (f : Ast.function_def) -> f.func_name = "main") userspace_block.userspace_functions in
  let default_main = if not has_main then {|
int main(int argc, char **argv) {
    printf("Starting multi-program eBPF coordinator\n");
    
    // Parse command line arguments
    const char *interface = argc > 1 ? argv[1] : "eth0";
    bool verbose = argc > 2 && strcmp(argv[2], "--verbose") == 0;
    
    if (verbose) {
        printf("Using interface: %s\n", interface);
    }
    
    setup_signal_handling();
    
    if (load_all_bpf_programs() != 0) {
        fprintf(stderr, "Failed to load BPF programs\n");
        return 1;
    }
    
    if (attach_programs(interface) != 0) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        cleanup_bpf_programs();
        return 1;
    }
    
    if (setup_maps() != 0) {
        fprintf(stderr, "Failed to setup global maps\n");
        cleanup_bpf_programs();
        return 1;
    }
    
    if (initialize_all_configs() != 0) {
        fprintf(stderr, "Failed to initialize configs\n");
        cleanup_bpf_programs();
        return 1;
    }
    
    printf("Multi-program eBPF system running on %s. Press Ctrl+C to exit.\n", interface);
    
    // Main coordination loop
    while (keep_running) {
        process_system_events();
        get_combined_stats();
        usleep(100000); // 100ms
    }
    
    printf("Shutting down coordinator...\n");
    cleanup_maps();
    cleanup_bpf_programs();
    return 0;
}
|} else "" in
  
  sprintf {|%s

%s

%s

%s

%s

%s

%s

%s
|} includes structs bpf_loader config_init map_access signal_handling functions default_main

(** Generate default userspace program when no userspace block is provided *)
let generate_default_userspace_program program_name ?ast () =
  let includes = {|#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
|} in

  let bpf_loader = generate_bpf_loader_code program_name in
  let map_access = match ast with
    | Some ast_data -> 
        let map_declarations = extract_map_declarations_from_ast ast_data in
        generate_enhanced_map_access_code map_declarations
    | None -> generate_map_access_code ()
  in
  let signal_handling = generate_signal_handling () in
  
  let main_function = {|
int main(int argc, char **argv) {
    printf("Starting default userspace program for eBPF\n");
    
    setup_signal_handling();
    
    if (load_all_bpf_programs() != 0) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }
    
    if (setup_maps() != 0) {
        fprintf(stderr, "Failed to setup maps\n");
        cleanup_bpf_programs();
        return 1;
    }
    
    printf("BPF program running. Press Ctrl+C to exit.\n");
    
    // Main event loop
    while (keep_running) {
        // Process events, update maps, etc.
        sleep(1);
    }
    
    printf("Shutting down...\n");
    cleanup_bpf_programs();
    return 0;
}
|} in
  
  sprintf {|%s

%s

%s

%s

%s
|} includes bpf_loader map_access signal_handling main_function

(** Write userspace C file with new naming scheme: FOO.c from FOO.ks *)
let write_userspace_c_file content output_dir source_filename =
  (* Create output directory if it doesn't exist *)
  (try Unix.mkdir output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  
  (* Extract base name from source filename and use it for userspace program *)
  let base_name = Filename.remove_extension (Filename.basename source_filename) in
  let filename = sprintf "%s.c" base_name in
  let filepath = Filename.concat output_dir filename in
  let oc = open_out filepath in
  output_string oc content;
  close_out oc;
  printf "Generated userspace coordinator program: %s\n" filepath;
  filepath

(** Main entry point for userspace code generation *)
let generate_userspace_code_from_ast (ast : Ast.ast) ?(output_dir = ".") ?config_declarations source_filename =
  (* Extract userspace block from AST *)
  let userspace_block = 
    List.fold_left (fun acc decl ->
      match decl with
      | Ast.Userspace ub -> Some ub
      | _ -> acc
    ) None ast
  in
  
  let prog_config = { (default_config source_filename) with output_dir = output_dir } in
  
  let content = match userspace_block with
    | Some ub -> 
        generate_complete_userspace_program ub source_filename ~ast:ast ?config_declarations ()
    | None -> 
        generate_default_userspace_program source_filename ~ast:ast ()
  in
  
  let _filepath = write_userspace_c_file content prog_config.output_dir source_filename in
  printf "Successfully generated userspace coordinator program\n" 