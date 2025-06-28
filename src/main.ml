(** KernelScript Compiler - Advanced Multi-Program Pipeline
    
    Advanced Multi-Program Compilation Pipeline:
    Parser → Multi-Program Analyzer → Enhanced Type Checker → 
    Multi-Program IR Optimizer → Advanced Multi-Target Code Generator
*)

open Kernelscript
open Printf
open Multi_program_analyzer
open Multi_program_ir_optimizer

(** Command line options *)
type options = {
  input_file: string;
  output_dir: string option;
  verbose: bool;
  generate_makefile: bool;
  builtin_path: string option;
  btf_vmlinux_path: string option;
}

let default_opts = {
  input_file = "";
  output_dir = None;
  verbose = false;
  generate_makefile = true;
  builtin_path = None;
  btf_vmlinux_path = None;
}

(** Argument parsing *)
let rec parse_args_aux opts = function
  | [] -> opts
  | "-o" :: output :: rest -> parse_args_aux { opts with output_dir = Some output } rest
  | "--output" :: output :: rest -> parse_args_aux { opts with output_dir = Some output } rest
  | "-v" :: rest -> parse_args_aux { opts with verbose = true } rest
  | "--verbose" :: rest -> parse_args_aux { opts with verbose = true } rest
  | "--no-makefile" :: rest -> parse_args_aux { opts with generate_makefile = false } rest
  | "--builtin-path" :: path :: rest -> parse_args_aux { opts with builtin_path = Some path } rest
  | "--btf-vmlinux-path" :: path :: rest -> parse_args_aux { opts with btf_vmlinux_path = Some path } rest
  | arg :: rest when not (String.starts_with ~prefix:"-" arg) ->
      parse_args_aux { opts with input_file = arg } rest
  | unknown :: _ ->
      printf "Unknown option: %s\n" unknown;
      printf "Usage: kernelscript [options] <input_file>\n";
      printf "Options:\n";
      printf "  -o, --output <dir>            Specify output directory\n";
      printf "  -v, --verbose                 Enable verbose output\n";
      printf "  --no-makefile                 Don't generate Makefile\n";
      printf "  --builtin-path <path>         Specify path to builtin KernelScript files\n";
      printf "  --btf-vmlinux-path <path>     Specify path to BTF vmlinux file for kernel module compilation\n";
      exit 1

let parse_args () =
  let args = List.tl (Array.to_list Sys.argv) in
  let opts = parse_args_aux default_opts args in
  if opts.input_file = "" then (
    printf "Error: No input file specified\n";
    printf "Usage: kernelscript [options] <input_file>\n";
    exit 1
  );
  opts

(** Compilation phase tracking *)
type compilation_phase = 
  | Parsing
  | SymbolAnalysis  
  | MultiProgramAnalysis
  | TypeChecking
  | IROptimization
  | CodeGeneration

let string_of_phase = function
  | Parsing -> "Parsing"
  | SymbolAnalysis -> "Symbol Analysis"
  | MultiProgramAnalysis -> "Multi-Program Analysis"
  | TypeChecking -> "Type Checking & AST Enhancement"
  | IROptimization -> "Multi-Program IR Optimization"
  | CodeGeneration -> "Code Generation"

(** List utility functions *)
let rec take n = function
  | [] -> []
  | x :: xs when n > 0 -> x :: take (n - 1) xs
  | _ -> []

(** Code generation targets *)
type code_target =
  | EbpfC
  | UserspaceCoordinator

(** Unified compilation pipeline with multi-program analysis *)
let compile opts source_file =
  let current_phase = ref Parsing in
  
  try
    Printf.printf "\n🔥 KernelScript Compiler\n";
    Printf.printf "========================\n\n";
    Printf.printf "📁 Source: %s\n\n" source_file;
    
    (* Phase 1: Parse source file *)
    Printf.printf "Phase 1: %s\n" (string_of_phase !current_phase);
    let ic = open_in source_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    let lexbuf = Lexing.from_string content in
    let ast = 
      try
        Parser.program Lexer.token lexbuf
      with
      | exn ->
          let lexbuf_pos = Lexing.lexeme_start_p lexbuf in
          Printf.eprintf "❌ Parse error at line %d, column %d\n" 
            lexbuf_pos.pos_lnum 
            (lexbuf_pos.pos_cnum - lexbuf_pos.pos_bol);
          Printf.eprintf "   Last token read: '%s'\n" (Lexing.lexeme lexbuf);
          Printf.eprintf "   Exception: %s\n" (Printexc.to_string exn);
          Printf.eprintf "   Context: Failed to parse the input around this location\n";
          failwith "Parse error"
    in
    Printf.printf "✅ Successfully parsed %d declarations\n\n" (List.length ast);
    
    (* Phase 2: Symbol table analysis *)
    current_phase := SymbolAnalysis;
    Printf.printf "Phase 2: %s\n" (string_of_phase !current_phase);
    
    (* Load builtin ASTs and build symbol table *)
    let symbol_table = Builtin_loader.build_symbol_table_with_builtins ?builtin_path:opts.builtin_path ast in
    Printf.printf "✅ Symbol table created successfully\n\n";
    
    (* Phase 3: Multi-program analysis *)
    current_phase := MultiProgramAnalysis;
    Printf.printf "Phase 3: %s\n" (string_of_phase !current_phase);
    let multi_prog_analysis = analyze_multi_program_system ast in
    
    (* Extract config declarations *)
    let config_declarations = List.filter_map (function
      | Ast.ConfigDecl config -> Some config
      | _ -> None
    ) ast in
    Printf.printf "📋 Found %d config declarations\n" (List.length config_declarations);
    
    (* Phase 4: Enhanced type checking with multi-program context *)
    current_phase := TypeChecking;
    Printf.printf "Phase 4: %s\n" (string_of_phase !current_phase);
    let (annotated_ast, _typed_programs) = Type_checker.type_check_and_annotate_ast ?builtin_path:opts.builtin_path ast in
    Printf.printf "✅ Type checking completed with multi-program annotations\n\n";
    
    (* Phase 5: Multi-program IR optimization *)
    current_phase := IROptimization;
    Printf.printf "Phase 5: %s\n" (string_of_phase !current_phase);
    (* Generate optimized IR using the original function *)
    let optimized_ir = Multi_program_ir_optimizer.generate_optimized_ir annotated_ast multi_prog_analysis symbol_table source_file in
    
    (* Phase 6: Advanced multi-target code generation *)
    current_phase := CodeGeneration;
    Printf.printf "Phase 6: %s\n" (string_of_phase !current_phase);
    let _resource_plan = plan_system_resources optimized_ir.programs multi_prog_analysis in
    let _optimization_strategies = generate_optimization_strategies multi_prog_analysis in
    
    (* Extract type aliases from original AST *)
    let type_aliases = List.filter_map (function
      | Ast.TypeDef (Ast.TypeAlias (name, underlying_type)) -> Some (name, underlying_type)
      | _ -> None
    ) ast in
    
    (* Extract variable declarations with their original declared types *)
    let extract_variable_declarations ast_nodes =
      List.fold_left (fun acc node ->
        match node with
        | Ast.AttributedFunction attr_func ->
            List.fold_left (fun acc2 stmt ->
              match stmt.Ast.stmt_desc with
              | Ast.Declaration (var_name, Some declared_type, _) ->
                  (match declared_type with
                   | Ast.UserType alias_name -> 
                       (* Only store type alias declarations *)
                       (var_name, alias_name) :: acc2
                   | _ -> acc2)
              | _ -> acc2
            ) acc attr_func.attr_function.Ast.func_body
        | Ast.GlobalFunction func ->
            List.fold_left (fun acc2 stmt ->
              match stmt.Ast.stmt_desc with
              | Ast.Declaration (var_name, Some declared_type, _) ->
                  (match declared_type with
                   | Ast.UserType alias_name -> 
                       (* Only store type alias declarations *)
                       (var_name, alias_name) :: acc2
                   | _ -> acc2)
              | _ -> acc2
            ) acc func.Ast.func_body
        | _ -> acc
      ) [] ast_nodes
    in
    let variable_type_aliases = extract_variable_declarations ast in
    
    (* Extract kfunc declarations from AST for eBPF C generation *)
    let kfunc_declarations = List.filter_map (function
      | Ast.AttributedFunction attr_func ->
          (match attr_func.attr_list with
           | SimpleAttribute "kfunc" :: _ -> Some attr_func.attr_function
           | _ -> None)
      | _ -> None
    ) annotated_ast in
    
    (* Generate eBPF C code (with automatic tail call detection and kfunc declarations) *)
    let (ebpf_c_code, tail_call_analysis) = Ebpf_c_codegen.compile_multi_to_c_with_analysis 
      ~config_declarations:optimized_ir.global_configs ~type_aliases ~variable_type_aliases ~kfunc_declarations optimized_ir in
      
    (* Determine output directory *)
    let base_name = Filename.remove_extension (Filename.basename source_file) in
    let output_dir = match opts.output_dir with
      | Some dir -> dir
      | None -> base_name
    in
    
    (* Analyze kfunc dependencies for automatic kernel module loading *)
    let ir_functions = List.map (fun prog -> prog.Ir.entry_function) optimized_ir.programs in
    let kfunc_dependencies = Userspace_codegen.analyze_kfunc_dependencies base_name annotated_ast ir_functions in
    
    (* Generate kernel module for kfuncs if any exist *)
    let kernel_module_code = Kernel_module_codegen.generate_kernel_module_from_ast base_name annotated_ast in
    
    (* Generate userspace coordinator directly to output directory with tail call analysis *)
    Userspace_codegen.generate_userspace_code_from_ir 
      ~config_declarations ~type_aliases ~tail_call_analysis ~kfunc_dependencies optimized_ir ~output_dir source_file;
    
    (* Read the generated userspace code for preview *)
    let userspace_file = output_dir ^ "/" ^ base_name ^ ".c" in
    let userspace_c_code = 
      try
        let ic = open_in userspace_file in
        let content = really_input_string ic (in_channel_length ic) in
        close_in ic;
        content
      with _ -> "/* Failed to read generated userspace code */"
    in
    
    let generated_codes = [
      (EbpfC, ebpf_c_code);
      (UserspaceCoordinator, userspace_c_code);
    ] in
    
    (* Write kernel module file if kfuncs exist *)
    (match kernel_module_code with
     | Some module_code ->
         let module_filename = output_dir ^ "/" ^ base_name ^ ".mod.c" in
         let oc = open_out module_filename in
         output_string oc module_code;
         close_out oc;
         Printf.printf "✅ Generated kernel module: %s\n" module_filename
     | None -> 
         Printf.printf "ℹ️ No kfuncs detected, kernel module not generated\n");
    
    Printf.printf "🎉 Compilation completed successfully!\n\n";
    
    (* Create output directory if it doesn't exist *)
    (try Unix.mkdir output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    
    (* Compile required builtin headers based on program types *)
    let program_types = List.fold_left (fun acc decl ->
      match decl with
      | Ast.AttributedFunction attr_func ->
          (* Extract program type from attribute *)
          (match attr_func.attr_list with
           | SimpleAttribute prog_type_str :: _ ->
               (match prog_type_str with
                | "xdp" -> Ast.Xdp :: acc
                | "tc" -> Ast.Tc :: acc  
                | "kprobe" -> Ast.Kprobe :: acc
                | "uprobe" -> Ast.Uprobe :: acc
                | "tracepoint" -> Ast.Tracepoint :: acc
                | "lsm" -> Ast.Lsm :: acc
                | "cgroup_skb" -> Ast.CgroupSkb :: acc
                | _ -> acc)
           | _ -> acc)
      | _ -> acc
    ) [] ast in
    
    let unique_program_types = List.sort_uniq compare program_types in
    let generated_builtin_headers = ref [] in  (* Track generated headers for cleanup *)
    List.iter (fun prog_type ->
      let (builtin_file, header_name) = match prog_type with
        | Ast.Xdp -> ("builtin/xdp.ks", "xdp.h")
        | Ast.Tc -> ("builtin/tc.ks", "tc.h")
        | Ast.Kprobe -> ("builtin/kprobe.ks", "kprobe.h")
        | _ -> ("", "")  (* Skip unsupported types *)
      in
      if builtin_file <> "" && Sys.file_exists builtin_file then (
        let output_header = Filename.concat output_dir header_name in
        try
          Printf.printf "🔧 Compiling builtin: %s -> %s\n" builtin_file output_header;
          Builtin_compiler.compile_builtin_file builtin_file output_header;
          generated_builtin_headers := output_header :: !generated_builtin_headers;
          Printf.printf "✅ Builtin header generated: %s\n" header_name
        with
        | exn ->
            Printf.eprintf "⚠️ Warning: Failed to compile builtin %s: %s\n" builtin_file (Printexc.to_string exn)
      )
    ) unique_program_types;
    
    Printf.printf "📤 Generated Code Outputs:\n";
    Printf.printf "=========================\n";
    List.iter (fun (target, code) ->
      let (target_name, filename) = match target with
        | EbpfC -> ("eBPF C Code", output_dir ^ "/" ^ base_name ^ ".ebpf.c")
        | UserspaceCoordinator -> ("Userspace Coordinator", output_dir ^ "/" ^ base_name ^ ".c")
      in
      
      (* Write eBPF file, userspace file is already written by userspace codegen *)
      (match target with
        | EbpfC -> 
          let oc = open_out filename in
          output_string oc code;
          close_out oc
        | UserspaceCoordinator -> 
          (* File already written by userspace codegen, just show preview *)
          ()
      );
      
      Printf.printf "\n--- %s → %s ---\n" target_name filename;
      let lines = String.split_on_char '\n' code in
      let preview_lines = take (min 10 (List.length lines)) lines in
      List.iter (Printf.printf "%s\n") preview_lines;
      if List.length lines > 10 then
        Printf.printf "... (%d more lines)\n" (List.length lines - 10);
    ) generated_codes;
    
    Printf.printf "\n✨ Multi-program compilation completed successfully!\n";
    Printf.printf "📁 Output directory: %s/\n" output_dir;
    
    (* Generate Makefile *)
    let kmod_targets = match kernel_module_code with
      | Some _ -> 
        let btf_vmlinux_make_var = match opts.btf_vmlinux_path with
          | Some path -> Printf.sprintf " BTF_VMLINUX_PATH=%s" path
          | None -> ""
        in
        let btf_vmlinux_cflags = match opts.btf_vmlinux_path with
          | Some path -> Printf.sprintf " -DBTF_VMLINUX_PATH=\\\"%s\\\"" path
          | None -> ""
        in
        let btf_post_process = match opts.btf_vmlinux_path with
          | Some path -> Printf.sprintf {|
	@echo "Adding BTF information using custom vmlinux..."
	@if command -v pahole >/dev/null 2>&1; then \
		pahole -J --btf_base %s $@; \
		echo "BTF information added successfully"; \
	else \
		echo "Warning: pahole not found, BTF information not added"; \
	fi
	@RESOLVE_BTFIDS="/lib/modules/$(shell uname -r)/build/tools/bpf/resolve_btfids/resolve_btfids"; \
	if [ -f "$$RESOLVE_BTFIDS" ]; then \
		$$RESOLVE_BTFIDS -b %s $@; \
		echo "BTF IDs resolved successfully"; \
	else \
		echo "Warning: resolve_btfids not found at $$RESOLVE_BTFIDS, BTF IDs not resolved"; \
	fi|} path path
          | None -> ""
        in
        Printf.sprintf {|
# Kernel module targets
KMOD_SRC = %s.mod.c
KMOD_OBJ = %s.mod.ko

# Build kernel module
$(KMOD_OBJ): $(KMOD_SRC)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules%s%s

# Clean kernel module
clean-kmod:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

# Load kernel module
load-kmod: $(KMOD_OBJ)
	sudo insmod $(KMOD_OBJ)

# Unload kernel module
unload-kmod:
	sudo rmmod %s

# Kernel module Makefile for external build
obj-m := %s.mod.o

# Enable debug info for BTF generation
KBUILD_CFLAGS += -g -O2%s
|} base_name base_name btf_vmlinux_make_var btf_post_process base_name base_name btf_vmlinux_cflags
      | None -> ""
    in
    
    let makefile_content = Printf.sprintf {|# Multi-Program eBPF Makefile
# Generated by KernelScript compiler

# Compilers
BPF_CC = clang
CC = gcc

# BPF compilation flags
BPF_CFLAGS = -target bpf -O2 -Wall -Wextra -g
BPF_INCLUDES = -I/usr/include -I/usr/include/x86_64-linux-gnu

# Userspace compilation flags
CFLAGS = -Wall -Wextra -O2
LIBS = -lbpf -lelf -lz

# Object files
BPF_OBJ = %s.ebpf.o
USERSPACE_BIN = %s

# Source files
BPF_SRC = %s.ebpf.c
USERSPACE_SRC = %s.c%s

# Default target - build both eBPF and userspace programs%s
all: $(BPF_OBJ) $(USERSPACE_BIN)%s

# Compile eBPF C to object file
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CC) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

# Compile userspace program
$(USERSPACE_BIN): $(USERSPACE_SRC) $(BPF_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Clean generated files
clean:
	rm -f $(BPF_OBJ) $(USERSPACE_BIN)%s

# Run the userspace program
run: $(USERSPACE_BIN)%s
	sudo ./$(USERSPACE_BIN)

.PHONY: all clean run%s
|} base_name base_name base_name base_name kmod_targets
   (if kernel_module_code <> None then " and kernel module" else "")
   (if kernel_module_code <> None then " $(KMOD_OBJ)" else "")
   (if kernel_module_code <> None then " clean-kmod" else "")
   (if kernel_module_code <> None then "\n\tsudo ./load-kmod.sh || echo 'Note: Run make load-kmod to load kernel module before running'" else "")
   (if kernel_module_code <> None then " load-kmod unload-kmod clean-kmod" else "") in
    
    let makefile_path = output_dir ^ "/Makefile" in
    let oc = open_out makefile_path in
    output_string oc makefile_content;
    close_out oc;
    
    Printf.printf "📄 Generated Makefile: %s/Makefile\n" output_dir;
    Printf.printf "🔨 To compile: cd %s && make\n" output_dir;
    
    (* Clean up temporary builtin headers since they're not included in generated C code *)
    if !generated_builtin_headers <> [] then (
      Printf.printf "🧹 Cleaning up temporary builtin headers...\n";
      List.iter (fun header_path ->
        try
          Sys.remove header_path;
          let header_name = Filename.basename header_path in
          Printf.printf "   ✅ Removed: %s\n" header_name
        with
        | Sys_error _ -> 
          Printf.printf "   ⚠️ Could not remove: %s\n" (Filename.basename header_path)
      ) !generated_builtin_headers;
      Printf.printf "✨ Temporary headers cleaned up\n"
    );
    
  with
  | Failure msg when msg = "Parse error" ->
      Printf.eprintf "❌ Parse error in phase: %s\n" (string_of_phase !current_phase);
      exit 1
  | Type_checker.Type_error (msg, pos) ->
      Printf.eprintf "❌ Type error in phase %s at %s: %s\n" 
        (string_of_phase !current_phase) (Ast.string_of_position pos) msg;
      exit 1
  | exn ->
      Printf.eprintf "❌ Compilation failed in phase %s: %s\n" 
        (string_of_phase !current_phase) (Printexc.to_string exn);
      exit 1

(** Main entry point *)
let () =
  if Array.length Sys.argv < 2 then (
    Printf.printf "Usage: %s <source_file>\n" Sys.argv.(0);
    exit 1
  );
  
  let opts = parse_args () in
  
  compile opts opts.input_file 