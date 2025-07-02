(** KernelScript Compiler - Main Entry Point with Subcommands *)

open Kernelscript
open Printf

(** Subcommand types *)
type subcommand = 
  | Init of { prog_type: string; project_name: string; btf_path: string option }
  | Compile of { input_file: string; output_dir: string option; verbose: bool; generate_makefile: bool; builtin_path: string option; btf_vmlinux_path: string option }

(** Parse command line arguments *)
let rec parse_args () =
  let args = Array.to_list Sys.argv in
  match args with
  | [_] | [_; "--help"] | [_; "-h"] ->
      printf "KernelScript Compiler\n";
      printf "Usage: %s <subcommand> [options]\n\n" (List.hd args);
      printf "Subcommands:\n";
      printf "  init <prog_type> <project_name> [--btf-vmlinux-path <path>]\n";
      printf "    Initialize a new KernelScript project\n";
      printf "    prog_type: xdp | tc | kprobe | uprobe | tracepoint | lsm | cgroup_skb\n";
      printf "    project_name: Name of the project directory to create\n";
      printf "    --btf-vmlinux-path: Path to BTF vmlinux file for type extraction\n\n";
      printf "  compile <input_file> [options]\n";
      printf "    Compile KernelScript source to C code\n";
      printf "    -o, --output <dir>            Specify output directory\n";
      printf "    -v, --verbose                 Enable verbose output\n";
      printf "    --no-makefile                 Don't generate Makefile\n";
      printf "    --builtin-path <path>         Specify path to builtin KernelScript files\n";
      printf "    --btf-vmlinux-path <path>     Specify path to BTF vmlinux file\n";
      exit 0
  | _ :: "init" :: rest -> parse_init_args rest
  | _ :: "compile" :: rest -> parse_compile_args rest
  | _ :: subcommand :: _ ->
      printf "Error: Unknown subcommand '%s'\n" subcommand;
      printf "Run '%s --help' for usage information\n" (List.hd args);
      exit 1
  | _ ->
      printf "Error: No subcommand specified\n";
      printf "Run '%s --help' for usage information\n" (List.hd args);
      exit 1

and parse_init_args args =
  let rec parse_aux prog_type_opt project_name_opt btf_path_opt = function
    | [] ->
        (match (prog_type_opt, project_name_opt) with
         | (Some prog_type, Some project_name) ->
             Init { prog_type; project_name; btf_path = btf_path_opt }
         | (None, _) ->
             printf "Error: Missing program type for init command\n";
             exit 1
         | (_, None) ->
             printf "Error: Missing project name for init command\n";
             exit 1)
    | "--btf-vmlinux-path" :: path :: rest ->
        parse_aux prog_type_opt project_name_opt (Some path) rest
    | arg :: rest when not (String.starts_with ~prefix:"-" arg) ->
        (match (prog_type_opt, project_name_opt) with
         | (None, None) -> parse_aux (Some arg) project_name_opt btf_path_opt rest
         | (Some _, None) -> parse_aux prog_type_opt (Some arg) btf_path_opt rest
         | (Some _, Some _) ->
             printf "Error: Too many arguments for init command\n";
             exit 1
         | (None, Some _) -> (* This shouldn't happen *) 
             parse_aux (Some arg) project_name_opt btf_path_opt rest)
    | unknown :: _ ->
        printf "Error: Unknown option '%s' for init command\n" unknown;
        exit 1
  in
  parse_aux None None None args

and parse_compile_args args =
  let rec parse_aux input_file_opt output_dir verbose generate_makefile builtin_path btf_path = function
    | [] ->
                 (match input_file_opt with
          | Some input_file ->
              Compile { input_file; output_dir; verbose; generate_makefile; builtin_path; btf_vmlinux_path = btf_path }
         | None ->
             printf "Error: No input file specified for compile command\n";
             exit 1)
    | "-o" :: output :: rest ->
        parse_aux input_file_opt (Some output) verbose generate_makefile builtin_path btf_path rest
    | "--output" :: output :: rest ->
        parse_aux input_file_opt (Some output) verbose generate_makefile builtin_path btf_path rest
    | "-v" :: rest ->
        parse_aux input_file_opt output_dir true generate_makefile builtin_path btf_path rest
    | "--verbose" :: rest ->
        parse_aux input_file_opt output_dir true generate_makefile builtin_path btf_path rest
    | "--no-makefile" :: rest ->
        parse_aux input_file_opt output_dir verbose false builtin_path btf_path rest
    | "--builtin-path" :: path :: rest ->
        parse_aux input_file_opt output_dir verbose generate_makefile (Some path) btf_path rest
    | "--btf-vmlinux-path" :: path :: rest ->
        parse_aux input_file_opt output_dir verbose generate_makefile builtin_path (Some path) rest
    | arg :: rest when not (String.starts_with ~prefix:"-" arg) ->
        (match input_file_opt with
         | None -> parse_aux (Some arg) output_dir verbose generate_makefile builtin_path btf_path rest
         | Some _ ->
             printf "Error: Multiple input files specified\n";
             exit 1)
    | unknown :: _ ->
        printf "Error: Unknown option '%s' for compile command\n" unknown;
        exit 1
  in
  parse_aux None None false true None None args

(** Initialize a new KernelScript project *)
let init_project prog_type project_name btf_path =
  printf "🚀 Initializing KernelScript project: %s\n" project_name;
  printf "📋 Program type: %s\n" prog_type;
  
  (* Validate program type *)
  let valid_types = ["xdp"; "tc"; "kprobe"; "uprobe"; "tracepoint"; "lsm"; "cgroup_skb"] in
  if not (List.mem prog_type valid_types) then (
    printf "❌ Error: Invalid program type '%s'\n" prog_type;
    printf "Valid types: %s\n" (String.concat ", " valid_types);
    exit 1
  );
  
  (* Create project directory *)
  (try
    Unix.mkdir project_name 0o755;
    printf "✅ Created project directory: %s/\n" project_name
  with
  | Unix.Unix_error (Unix.EEXIST, _, _) ->
      printf "❌ Error: Directory '%s' already exists\n" project_name;
      exit 1
  | exn ->
      printf "❌ Error creating directory: %s\n" (Printexc.to_string exn);
      exit 1);
  
  (* Generate program template *)
  printf "🔧 Extracting types for %s program...\n" prog_type;
  let template = Btf_parser.get_program_template prog_type btf_path in
  printf "✅ Found %d type definitions\n" (List.length template.types);
  
  (* Generate KernelScript source *)
  let source_content = Btf_parser.generate_kernelscript_source template project_name in
  let source_filename = project_name ^ "/" ^ prog_type ^ ".ks" in
  
  (* Write source file *)
  let oc = open_out source_filename in
  output_string oc source_content;
  close_out oc;
  printf "✅ Generated source file: %s\n" source_filename;
  
  (* Create a simple README *)
  let readme_content = sprintf {|# %s

A KernelScript %s program.

## Building

```bash
# Compile the KernelScript source
kernelscript compile %s.ks

# Build the generated C code
cd %s && make

# Run the program (requires root privileges)
cd %s && make run
```

## Program Structure

- `%s.ks` - Main KernelScript source file
- Generated files will be placed in `%s/` directory after compilation

## Program Type: %s

%s
|} project_name prog_type prog_type project_name project_name prog_type project_name prog_type (match prog_type with
    | "xdp" -> "XDP programs provide high-performance packet processing at the driver level."
    | "tc" -> "TC programs enable traffic control and packet filtering in the Linux networking stack."
    | "kprobe" -> "Kprobe programs allow dynamic tracing of kernel functions."
    | "uprobe" -> "Uprobe programs enable tracing of userspace functions."
    | "tracepoint" -> "Tracepoint programs provide static tracing points in the kernel."
    | "lsm" -> "LSM programs implement security policies and access control."
    | "cgroup_skb" -> "Cgroup SKB programs filter network packets based on cgroup membership."
    | _ -> "eBPF program for kernel-level processing."
  ) in
  
  let readme_filename = project_name ^ "/README.md" in
  let oc = open_out readme_filename in
  output_string oc readme_content;
  close_out oc;
  printf "✅ Generated README: %s\n" readme_filename;
  
  printf "\n🎉 Project '%s' initialized successfully!\n" project_name;
  printf "📁 Project structure:\n";
  printf "   %s/\n" project_name;
  printf "   ├── %s.ks      # KernelScript source\n" prog_type;
  printf "   └── README.md      # Project documentation\n";
  printf "\n🚀 Next steps:\n";
  printf "   1. Edit %s/%s.ks to implement your program logic\n" project_name prog_type;
  printf "   2. Run 'kernelscript compile %s/%s.ks' to compile\n" project_name prog_type;
  printf "   3. Run 'cd %s && make' to build the generated C code\n" project_name

(** Compile KernelScript source (existing functionality) *)
let compile_source input_file output_dir _verbose generate_makefile builtin_path btf_vmlinux_path =
  let current_phase = ref "Parsing" in
  
  (* Initialize context code generators *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  
  try
    Printf.printf "\n🔥 KernelScript Compiler\n";
    Printf.printf "========================\n\n";
    Printf.printf "📁 Source: %s\n\n" input_file;
    
    (* Phase 1: Parse source file *)
    Printf.printf "Phase 1: %s\n" !current_phase;
    let ic = open_in input_file in
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
    current_phase := "Symbol Analysis";
    Printf.printf "Phase 2: %s\n" !current_phase;
    
    (* Load builtin ASTs and build symbol table *)
    let symbol_table = Builtin_loader.build_symbol_table_with_builtins ?builtin_path ast in
    Printf.printf "✅ Symbol table created successfully\n\n";
    
    (* Phase 3: Multi-program analysis *)
    current_phase := "Multi-Program Analysis";
    Printf.printf "Phase 3: %s\n" !current_phase;
    let multi_prog_analysis = Multi_program_analyzer.analyze_multi_program_system ast in
    
    (* Extract config declarations *)
    let config_declarations = List.filter_map (function
      | Ast.ConfigDecl config -> Some config
      | _ -> None
    ) ast in
    Printf.printf "📋 Found %d config declarations\n" (List.length config_declarations);
    
    (* Phase 4: Enhanced type checking with multi-program context *)
    current_phase := "Type Checking";
    Printf.printf "Phase 4: %s\n" !current_phase;
    let (annotated_ast, _typed_programs) = Type_checker.type_check_and_annotate_ast ?builtin_path ast in
    Printf.printf "✅ Type checking completed with multi-program annotations\n\n";
    
    (* Phase 5: Multi-program IR optimization *)
    current_phase := "IR Optimization";
    Printf.printf "Phase 5: %s\n" !current_phase;
    let optimized_ir = Multi_program_ir_optimizer.generate_optimized_ir annotated_ast multi_prog_analysis symbol_table input_file in
    
    (* Phase 6: Advanced multi-target code generation *)
    current_phase := "Code Generation";
    Printf.printf "Phase 6: %s\n" !current_phase;
    let _resource_plan = Multi_program_ir_optimizer.plan_system_resources optimized_ir.programs multi_prog_analysis in
    let _optimization_strategies = Multi_program_ir_optimizer.generate_optimization_strategies multi_prog_analysis in
    
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
    let base_name = Filename.remove_extension (Filename.basename input_file) in
    let output_dir = match output_dir with
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
      ~config_declarations ~type_aliases ~tail_call_analysis ~kfunc_dependencies optimized_ir ~output_dir input_file;
    
    (* Create output directory if it doesn't exist *)
    (try Unix.mkdir output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    
    (* Write eBPF C code *)
    let ebpf_filename = output_dir ^ "/" ^ base_name ^ ".ebpf.c" in
    let oc = open_out ebpf_filename in
    output_string oc ebpf_c_code;
    close_out oc;
    
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
    
    (* Generate Makefile if requested *)
    if generate_makefile then (
      let kmod_targets = match kernel_module_code with
        | Some _ -> 
          let btf_vmlinux_make_var = match btf_vmlinux_path with
            | Some path -> Printf.sprintf " BTF_VMLINUX_PATH=%s" path
            | None -> ""
          in
          let btf_vmlinux_cflags = match btf_vmlinux_path with
            | Some path -> Printf.sprintf " -DBTF_VMLINUX_PATH=\\\"%s\\\"" path
            | None -> ""
          in
          Printf.sprintf {|
# Kernel module targets
KMOD_SRC = %s.mod.c
KMOD_OBJ = %s.mod.ko

# Build kernel module
$(KMOD_OBJ): $(KMOD_SRC)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules%s

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
|} base_name base_name btf_vmlinux_make_var base_name base_name btf_vmlinux_cflags
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
      
      Printf.printf "📄 Generated Makefile: %s/Makefile\n" output_dir
    );
    
    Printf.printf "\n✨ Compilation completed successfully!\n";
    Printf.printf "📁 Output directory: %s/\n" output_dir;
    Printf.printf "🔨 To build: cd %s && make\n" output_dir;
    
  with
  | Failure msg when msg = "Parse error" ->
      Printf.eprintf "❌ Parse error in phase: %s\n" !current_phase;
      exit 1
  | Type_checker.Type_error (msg, pos) ->
      Printf.eprintf "❌ Type error in phase %s at %s: %s\n" 
        !current_phase (Ast.string_of_position pos) msg;
      exit 1
  | exn ->
      Printf.eprintf "❌ Compilation failed in phase %s: %s\n" 
        !current_phase (Printexc.to_string exn);
      exit 1

(** Main entry point *)
let () =
  match parse_args () with
  | Init { prog_type; project_name; btf_path } ->
      init_project prog_type project_name btf_path
  | Compile { input_file; output_dir; verbose; generate_makefile; builtin_path; btf_vmlinux_path } ->
      compile_source input_file output_dir verbose generate_makefile builtin_path btf_vmlinux_path 