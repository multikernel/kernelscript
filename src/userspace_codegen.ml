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

(** Generate function implementations from userspace functions *)
let generate_c_function_from_userspace (func : Ast.function_def) =
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
    | None -> if func.func_name = "main" then "int" else "void"
  in
  
  let body = if func.func_name = "main" then {|
    printf("Starting userspace program for eBPF\n");
    
    // TODO: Add BPF program loading logic here
    // Example:
    // 1. Load the eBPF object file
    // 2. Attach to network interface or kernel hook
    // 3. Set up map access
    // 4. Process events/data
    
    printf("Userspace program completed\n");
    return 0;|} else {|
    // TODO: Implement function body
    printf("Function %s called\n", __func__);
    return 0;|} in
  
  sprintf {|
%s %s(%s) {%s
}
|} return_type func.func_name 
   (if params = [] then "void" else String.concat ", " params)
   body

(** Generate BPF program loading and management code *)
let generate_bpf_loader_code program_name =
  sprintf {|
/* BPF Program Management */
struct bpf_object *bpf_obj = NULL;
struct bpf_program *bpf_prog = NULL;
int prog_fd = -1;

int load_bpf_program(void) {
    // Load BPF object file
    bpf_obj = bpf_object__open("%s.ebpf.o");
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return -1;
    }

    // Load BPF program into kernel
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    // Find the main BPF program
    bpf_prog = bpf_object__find_program_by_name(bpf_obj, "main");
    if (!bpf_prog) {
        fprintf(stderr, "ERROR: finding BPF program 'main' failed\n");
        goto cleanup;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: getting program fd failed\n");
        goto cleanup;
    }

    printf("BPF program loaded successfully (fd=%%d)\n", prog_fd);
    return 0;

cleanup:
    bpf_object__close(bpf_obj);
    return -1;
}

void cleanup_bpf_program(void) {
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
    }
}

int attach_bpf_program(const char *interface) {
    // Example: attach XDP program to network interface
    // This would need to be customized based on program type
    printf("Attaching BPF program to interface %%s\n", interface);
    
    // TODO: Add actual attachment logic based on program type
    // For XDP: bpf_set_link_xdp_fd(if_index, prog_fd, flags);
    // For TC: tc filter add...
    // etc.
    
    return 0;
}
|} program_name

(** Generate map access code *)
let generate_map_access_code () =
  {|
/* Map Access Functions */
int setup_maps(void) {
    // TODO: Get map file descriptors from loaded BPF object
    // Example:
    // map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "map_name");
    
    printf("Maps setup completed\n");
    return 0;
}

// Example map lookup function
int lookup_map_value(__u32 key, __u64 *value) {
    // TODO: Implement actual map lookup
    // return bpf_map_lookup_elem(map_fd, &key, value);
    *value = 0;
    return 0;
}

// Example map update function  
int update_map_value(__u32 key, __u64 value) {
    // TODO: Implement actual map update
    // return bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    return 0;
}
|}

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

(** Generate complete C userspace program *)
let generate_complete_userspace_program (userspace_block : Ast.userspace_block) program_name =
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

  let structs = String.concat "\n" 
    (List.map generate_c_struct_from_userspace userspace_block.userspace_structs) in
  
  let functions = String.concat "\n" 
    (List.map generate_c_function_from_userspace userspace_block.userspace_functions) in
  
  let bpf_loader = generate_bpf_loader_code program_name in
  let map_access = generate_map_access_code () in
  let signal_handling = generate_signal_handling () in
  
  (* Check if main function exists, if not create a default one *)
  let has_main = List.exists (fun (f : Ast.function_def) -> f.func_name = "main") userspace_block.userspace_functions in
  let default_main = if not has_main then {|
int main(int argc, char **argv) {
    printf("Starting userspace program for eBPF\n");
    
    setup_signal_handling();
    
    if (load_bpf_program() != 0) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }
    
    if (setup_maps() != 0) {
        fprintf(stderr, "Failed to setup maps\n");
        cleanup_bpf_program();
        return 1;
    }
    
    printf("BPF program running. Press Ctrl+C to exit.\n");
    
    // Main event loop
    while (keep_running) {
        // TODO: Process events, update maps, etc.
        sleep(1);
    }
    
    printf("Shutting down...\n");
    cleanup_bpf_program();
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
|} includes structs bpf_loader map_access signal_handling functions default_main

(** Generate default userspace program when no userspace block is provided *)
let generate_default_userspace_program program_name =
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
  let map_access = generate_map_access_code () in
  let signal_handling = generate_signal_handling () in
  
  let main_function = {|
int main(int argc, char **argv) {
    printf("Starting default userspace program for eBPF\n");
    
    setup_signal_handling();
    
    if (load_bpf_program() != 0) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }
    
    if (setup_maps() != 0) {
        fprintf(stderr, "Failed to setup maps\n");
        cleanup_bpf_program();
        return 1;
    }
    
    printf("BPF program running. Press Ctrl+C to exit.\n");
    
    // Main event loop
    while (keep_running) {
        // Process events, update maps, etc.
        sleep(1);
    }
    
    printf("Shutting down...\n");
    cleanup_bpf_program();
    return 0;
}
|} in
  
  sprintf {|%s

%s

%s

%s

%s
|} includes bpf_loader map_access signal_handling main_function

(** Write userspace C file *)
let write_userspace_c_file content output_dir program_name =
  (* Create output directory if it doesn't exist *)
  (try Unix.mkdir output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  
  let filename = sprintf "%s.c" program_name in
  let filepath = Filename.concat output_dir filename in
  let oc = open_out filepath in
  output_string oc content;
  close_out oc;
  printf "Generated userspace C program: %s\n" filepath;
  filepath

(** Main entry point for userspace code generation *)
let generate_userspace_code (ir_prog : ir_program) ?(output_dir = ".") () =
  let prog_config = { (default_config ir_prog.name) with output_dir = output_dir } in
  
  let content = match ir_prog.userspace_block with
    | Some userspace_block -> 
        generate_complete_userspace_program userspace_block ir_prog.name
    | None -> 
        generate_default_userspace_program ir_prog.name
  in
  
  let _filepath = write_userspace_c_file content prog_config.output_dir ir_prog.name in
  printf "Successfully generated userspace C program\n" 