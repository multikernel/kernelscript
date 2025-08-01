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

(** KernelScript Compiler - Main Entry Point with Subcommands *)

open Kernelscript
open Printf

(** Subcommand types *)
type subcommand = 
  | Init of { prog_type: string; project_name: string; btf_path: string option }
  | Compile of { input_file: string; output_dir: string option; verbose: bool; generate_makefile: bool; btf_vmlinux_path: string option; test_mode: bool }

(** Parse command line arguments *)
let rec parse_args () =
  let args = Array.to_list Sys.argv in
  match args with
  | [_] | [_; "--help"] | [_; "-h"] ->
      printf "KernelScript Compiler\n";
      printf "Usage: %s <subcommand> [options]\n\n" (List.hd args);
      printf "Subcommands:\n";
      printf "  init <prog_type_or_struct_ops> <project_name> [--btf-vmlinux-path <path>]\n";
      printf "    Initialize a new KernelScript project\n";
      printf "    prog_type: xdp | tc | kprobe/target_function | tracepoint/category/event\n";
      printf "    Examples: kprobe/sys_read, kprobe/vfs_write, kprobe/tcp_sendmsg\n";
      printf "    tracepoint: tracepoint/syscalls/sys_enter_read, tracepoint/sched/sched_switch\n";
      printf "    struct_ops: tcp_congestion_ops\n";
      printf "    project_name: Name of the project directory to create\n";
      printf "    --btf-vmlinux-path: Path to BTF vmlinux file (default: /sys/kernel/btf/vmlinux)\n\n";
      printf "  compile <input_file> [options]\n";
      printf "    Compile KernelScript source to C code\n";
      printf "    -o, --output <dir>            Specify output directory\n";
      printf "    -v, --verbose                 Enable verbose output\n";
      printf "    --no-makefile                 Don't generate Makefile\n";
      printf "    --test                        Compile in test mode (only @test functions become main)\n";
      printf "    --builtin-path <path>         Specify path to builtin KernelScript files\n";
      printf "    --btf-vmlinux-path <path>     Path to BTF vmlinux file (default: /sys/kernel/btf/vmlinux)\n";
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
             (* Set default BTF path if none provided *)
             let final_btf_path = match btf_path_opt with
               | Some path -> Some path
               | None -> Some "/sys/kernel/btf/vmlinux"
             in
             Init { prog_type; project_name; btf_path = final_btf_path }
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
  let rec parse_aux input_file_opt output_dir verbose generate_makefile btf_path test_mode = function
    | [] ->
                 (match input_file_opt with
          | Some input_file ->
              (* Set default BTF path if none provided *)
              let final_btf_path = match btf_path with
                | Some path -> Some path
                | None -> Some "/sys/kernel/btf/vmlinux"
              in
              Compile { input_file; output_dir; verbose; generate_makefile; btf_vmlinux_path = final_btf_path; test_mode }
         | None ->
             printf "Error: No input file specified for compile command\n";
             exit 1)
    | "-o" :: output :: rest ->
        parse_aux input_file_opt (Some output) verbose generate_makefile btf_path test_mode rest
    | "--output" :: output :: rest ->
        parse_aux input_file_opt (Some output) verbose generate_makefile btf_path test_mode rest
    | "-v" :: rest ->
        parse_aux input_file_opt output_dir true generate_makefile btf_path test_mode rest
    | "--verbose" :: rest ->
        parse_aux input_file_opt output_dir true generate_makefile btf_path test_mode rest
    | "--no-makefile" :: rest ->
        parse_aux input_file_opt output_dir verbose false btf_path test_mode rest
    | "--test" :: rest ->
        parse_aux input_file_opt output_dir verbose generate_makefile btf_path true rest
    | "--btf-vmlinux-path" :: path :: rest ->
        parse_aux input_file_opt output_dir verbose generate_makefile (Some path) test_mode rest
    | arg :: rest when not (String.starts_with ~prefix:"-" arg) ->
        (match input_file_opt with
         | None -> parse_aux (Some arg) output_dir verbose generate_makefile btf_path test_mode rest
         | Some _ ->
             printf "Error: Multiple input files specified\n";
             exit 1)
    | unknown :: _ ->
        printf "Error: Unknown option '%s' for compile command\n" unknown;
        exit 1
  in
  parse_aux None None false true None false args

(** Initialize a new KernelScript project *)
let init_project prog_type_or_struct_ops project_name btf_path =
  printf "🚀 Initializing KernelScript project: %s\n" project_name;
  printf "📋 Type: %s\n" prog_type_or_struct_ops;
  
  (* Parse program type and target function for kprobe/tracepoint *)
  let (prog_type, target_function) = 
    if String.contains prog_type_or_struct_ops '/' then
      let parts = String.split_on_char '/' prog_type_or_struct_ops in
      match parts with
      | [prog; func] when prog = "kprobe" -> (prog, Some func)
      | [prog; category; event] when prog = "tracepoint" -> (prog, Some (category ^ "/" ^ event))
      | _ -> 
          printf "❌ Error: Invalid syntax '%s'. Use kprobe/function_name or tracepoint/category/event\n" prog_type_or_struct_ops;
          exit 1
    else
      (prog_type_or_struct_ops, None)
  in
  
  (* Check if this is a struct_ops or a regular program type *)
  let valid_program_types = ["xdp"; "tc"; "kprobe"; "tracepoint"] in
  let is_struct_ops = Struct_ops_registry.is_known_struct_ops prog_type in
  let is_program_type = List.mem prog_type valid_program_types in
  
  (* Validate kprobe target function *)
  if prog_type = "kprobe" && target_function = None then (
    printf "❌ Error: kprobe requires target function. Use kprobe/function_name\n";
    printf "Examples: kprobe/sys_read, kprobe/vfs_write, kprobe/tcp_sendmsg\n";
    exit 1
  );
  
  (* Validate tracepoint category/event *)
  if prog_type = "tracepoint" && target_function = None then (
    printf "❌ Error: tracepoint requires category/event. Use tracepoint/category/event\n";
    printf "Examples: tracepoint/syscalls/sys_enter_read, tracepoint/sched/sched_switch\n";
    exit 1
  );
  
  if not is_struct_ops && not is_program_type then (
    printf "❌ Error: Invalid type '%s'\n" prog_type;
    printf "Valid program types: %s\n" (String.concat ", " valid_program_types);
    printf "Known struct_ops: %s\n" (String.concat ", " (Struct_ops_registry.get_all_known_struct_ops ()));
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
  
  (* Generate template based on type *)
  let source_content = 
    if is_struct_ops then (
      printf "🔧 Extracting struct_ops definition for %s...\n" prog_type;
      let content = Btf_parser.generate_struct_ops_template btf_path [prog_type] project_name in
      printf "✅ Generated struct_ops template\n";
      content
    ) else (
      match prog_type with
      | "kprobe" ->
          (match target_function with
           | Some func_name ->
               printf "🔧 Extracting types for %s program targeting %s...\n" prog_type func_name;
               let template = Btf_parser.get_kprobe_program_template func_name btf_path in
               printf "✅ Found %d type definitions\n" (List.length template.types);
               Btf_parser.generate_kernelscript_source template project_name
           | None -> failwith "kprobe requires target function")
      | "tracepoint" ->
          (match target_function with
           | Some category_event ->
               printf "🔧 Extracting types for %s program targeting %s...\n" prog_type category_event;
               let template = Btf_parser.get_tracepoint_program_template category_event btf_path in
               printf "✅ Found %d type definitions\n" (List.length template.types);
               Btf_parser.generate_kernelscript_source template project_name
           | None -> failwith "tracepoint requires category/event")
      | _ ->
          printf "🔧 Extracting types for %s program...\n" prog_type;
          let template = Btf_parser.get_program_template prog_type btf_path in
          printf "✅ Found %d type definitions\n" (List.length template.types);
          Btf_parser.generate_kernelscript_source template project_name
    ) in
  
  let source_filename = project_name ^ "/" ^ project_name ^ ".ks" in
  
  (* Write source file *)
  let oc = open_out source_filename in
  output_string oc source_content;
  close_out oc;
  printf "✅ Generated source file: %s\n" source_filename;
  
  (* Create a simple README *)
  let readme_content = 
    if is_struct_ops then (
      let struct_ops_info = Struct_ops_registry.get_struct_ops_info prog_type in
      let description = match struct_ops_info with
        | Some info -> info.description
        | None -> sprintf "Custom struct_ops implementation for %s" prog_type
      in
      sprintf {|# %s

A KernelScript struct_ops project implementing %s.

## Building

```bash
# Compile the KernelScript source
kernelscript compile %s.ks

# Build the generated C code
cd %s && make

# Run the program (requires root privileges)
cd %s && make run
```

## Project Structure

- `%s.ks` - Main KernelScript source file with struct_ops definition
- Generated files will be placed in `%s/` directory after compilation

## Struct_ops Type: %s

%s

## BTF Integration

This project uses BTF (BPF Type Format) to extract the exact kernel definition of `%s`.
If you provided --btf-vmlinux-path during initialization, the struct definition matches the kernel.
During compilation, the definition is verified against BTF to ensure compatibility.
|} project_name description project_name project_name project_name project_name project_name prog_type description prog_type
    ) else (
      sprintf {|# %s

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
|} project_name prog_type project_name project_name project_name project_name project_name prog_type (match prog_type with
        | "xdp" -> "XDP programs provide high-performance packet processing at the driver level."
        | "tc" -> "TC programs enable traffic control and packet filtering in the Linux networking stack."
        | "kprobe" -> "Kprobe programs allow dynamic tracing of kernel functions."
        | "tracepoint" -> "Tracepoint programs provide static tracing points in the kernel."
        | _ -> "eBPF program for kernel-level processing."
      )
    ) in
  
  let readme_filename = project_name ^ "/README.md" in
  let oc = open_out readme_filename in
  output_string oc readme_content;
  close_out oc;
  printf "✅ Generated README: %s\n" readme_filename;
  
  printf "\n🎉 Project '%s' initialized successfully!\n" project_name;
  printf "📁 Project structure:\n";
  printf "   %s/\n" project_name;
  printf "   ├── %s.ks      # KernelScript source\n" project_name;
  printf "   └── README.md      # Project documentation\n";
  printf "\n🚀 Next steps:\n";
  if is_struct_ops then (
    printf "   1. Edit %s/%s.ks to implement your struct_ops fields\n" project_name project_name;
    printf "   2. Refer to kernel documentation for %s implementation details\n" prog_type;
    printf "   3. Run 'kernelscript compile %s/%s.ks' to compile with BTF verification\n" project_name project_name;
    printf "   4. Run 'cd %s && make' to build the generated C code\n" project_name
  ) else (
    printf "   1. Edit %s/%s.ks to implement your program logic\n" project_name project_name;
    printf "   2. Run 'kernelscript compile %s/%s.ks' to compile\n" project_name project_name;
    printf "   3. Run 'cd %s && make' to build the generated C code\n" project_name
  )

(** Convert KernelScript type to C type *)
let kernelscript_type_to_c_type = function
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
  | _ -> "int" (* fallback *)

(** Convert KernelScript expression to C *)
let kernelscript_expr_to_c expr =
  match expr.Ast.expr_desc with
  | Ast.Literal (Ast.IntLit (value, _)) -> string_of_int value
  | Ast.Literal (Ast.BoolLit true) -> "true"
  | Ast.Literal (Ast.BoolLit false) -> "false"
  | Ast.Literal (Ast.StringLit str) -> sprintf "\"%s\"" str
  | Ast.Identifier name -> name
  | _ -> "/* TODO: Complex expression */"

(** Convert KernelScript statement to C *)
let kernelscript_stmt_to_c stmt =
  match stmt.Ast.stmt_desc with
  | Ast.Return (Some expr) ->
      sprintf "return %s;" (kernelscript_expr_to_c expr)
  | Ast.Return None -> "return;"
  | Ast.ExprStmt expr ->
      sprintf "%s;" (kernelscript_expr_to_c expr)
  | Ast.Assignment (var_name, expr) ->
      sprintf "%s = %s;" var_name (kernelscript_expr_to_c expr)
  | _ -> "/* TODO: Complex statement */"

(** Actually compile KernelScript functions to C *)
let compile_imported_modules resolved_imports output_dir =
  let ks_imports = List.filter (fun import ->
    match import.Import_resolver.source_type with
    | Ast.KernelScript -> true
    | _ -> false
  ) resolved_imports in
  
  List.iter (fun import ->
    let source_path = import.Import_resolver.resolved_path in
    let module_name = import.Import_resolver.module_name in
    
    Printf.printf "🔧 Compiling imported module: %s\n" module_name;
    
    try
      (* Read and parse the KernelScript source file *)
      let ic = open_in source_path in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      let lexbuf = Lexing.from_string content in
      let imported_ast = Parser.program Lexer.token lexbuf in
      
      (* Extract userspace functions *)
      let userspace_functions = List.filter_map (function
        | Ast.GlobalFunction func -> Some func
        | _ -> None
      ) imported_ast in
      
      if userspace_functions <> [] then (
        (* Generate actual C functions by compiling the KernelScript code *)
        let c_functions = List.map (fun func ->
          let func_name = func.Ast.func_name in
          let prefixed_name = module_name ^ "_" ^ func_name in
          
          (* Get return type *)
          let return_type = match func.Ast.func_return_type with
            | Some (Ast.Unnamed t) -> kernelscript_type_to_c_type t
            | Some (Ast.Named (_, t)) -> kernelscript_type_to_c_type t
            | None -> "void"
          in
          
          (* Get parameters *)
          let params = List.map (fun (name, param_type) ->
            sprintf "%s %s" (kernelscript_type_to_c_type param_type) name
          ) func.Ast.func_params in
          let params_str = if params = [] then "void" else String.concat ", " params in
          
          (* Compile function body from actual KernelScript statements *)
          let body_statements = List.map kernelscript_stmt_to_c func.Ast.func_body in
          let body_str = String.concat "\n    " body_statements in
          
          sprintf "%s %s(%s) {\n    %s\n}" return_type prefixed_name params_str body_str
        ) userspace_functions in
        
        let module_c_content = sprintf {|#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Generated C code from KernelScript module: %s
// Source: %s

%s
|} module_name source_path (String.concat "\n\n" c_functions) in
        
        (* Write the C file *)
        let target_c_file = sprintf "%s/%s.c" output_dir module_name in
        let oc = open_out target_c_file in
        output_string oc module_c_content;
        close_out oc;
        
        Printf.printf "✅ Generated C code for module %s: %s (%d functions)\n" 
          module_name target_c_file (List.length userspace_functions)
      ) else (
        Printf.printf "ℹ️ Module %s has no userspace functions to compile\n" module_name
      )
    with
    | exn ->
        Printf.eprintf "❌ Failed to compile imported module %s: %s\n" module_name (Printexc.to_string exn)
  ) ks_imports

(** Generate C bridge code for imported modules *)
let generate_bridge_code_for_imports resolved_imports =
  let ks_imports = List.filter (fun import ->
    match import.Import_resolver.source_type with
    | Ast.KernelScript -> true
    | _ -> false
  ) resolved_imports in
  
  if ks_imports = [] then ""
  else
    let declarations = List.map (fun import ->
      let module_name = import.Import_resolver.module_name in
      sprintf "// External functions from %s module" module_name
    ) ks_imports in
    
    let bridge_includes = List.map (fun import ->
      let module_name = import.Import_resolver.module_name in
      (* Generate function declarations for each imported module *)
      let function_decls = List.map (fun symbol ->
        match symbol.Import_resolver.symbol_type with
        | Ast.Function (param_types, return_type) ->
            let c_return_type = kernelscript_type_to_c_type return_type in
            let c_param_types = List.map kernelscript_type_to_c_type param_types in
            let params_str = if c_param_types = [] then "void" else String.concat ", " c_param_types in
            sprintf "extern %s %s_%s(%s);" c_return_type module_name symbol.symbol_name params_str
        | _ ->
            sprintf "// %s (non-function symbol)" symbol.symbol_name
      ) import.ks_symbols in
      String.concat "\n" function_decls
    ) ks_imports in
    
    sprintf "\n// Bridge code for imported KernelScript modules\n%s\n\n%s\n"
      (String.concat "\n" declarations)
      (String.concat "\n\n" bridge_includes)

(** Compile KernelScript source (existing functionality) *)
let compile_source input_file output_dir _verbose generate_makefile btf_vmlinux_path test_mode =
  let current_phase = ref "Parsing" in
  
  (* Initialize context code generators *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  Kernelscript_context.Kprobe_codegen.register ();
  Kernelscript_context.Tracepoint_codegen.register ();
  
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
    
    (* Phase 1.5: Import Resolution *)
    Printf.printf "Phase 1.5: Import Resolution\n";
    let resolved_imports = Import_resolver.resolve_all_imports ast input_file in
    Printf.printf "✅ Resolved %d imports\n" (List.length resolved_imports);
    List.iter (fun import -> 
      match import.Import_resolver.source_type with
      | KernelScript -> 
          Printf.printf "   📦 KernelScript: %s (%d symbols)\n" 
            import.module_name (List.length import.ks_symbols)
      | Python -> 
          Printf.printf "   🐍 Python: %s (generic bridge)\n" import.module_name
    ) resolved_imports;
    Printf.printf "\n";
    
    (* Determine output directory early *)
    let actual_output_dir = match output_dir with
      | Some dir -> dir
      | None -> Filename.remove_extension (Filename.basename input_file)
    in
    
    (* Create output directory if it doesn't exist *)
    (try Unix.mkdir actual_output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
    
    (* Compile imported KernelScript modules to C stubs *)
    compile_imported_modules resolved_imports actual_output_dir;
    
    (* Copy Python files to output directory for runtime access *)
    let copy_python_files resolved_imports output_dir =
      List.iter (fun import ->
        match import.Import_resolver.source_type with
        | Ast.Python ->
            let source_path = import.Import_resolver.resolved_path in
            let filename = Filename.basename source_path in
            let target_path = Filename.concat output_dir filename in
            (try
               let ic = open_in source_path in
               let content = really_input_string ic (in_channel_length ic) in
               close_in ic;
               let oc = open_out target_path in
               output_string oc content;
               close_out oc;
               Printf.printf "📋 Copied Python module: %s -> %s\n" source_path target_path
             with exn ->
               Printf.eprintf "⚠️ Failed to copy Python file %s: %s\n" source_path (Printexc.to_string exn))
        | _ -> ()
      ) resolved_imports
    in
    copy_python_files resolved_imports actual_output_dir;
    
    (* Store original AST before any filtering *)
    let original_ast = ast in
    
    (* Test mode: Filter AST for @test functions *)
      let filtered_ast = if test_mode then
    Test_codegen.filter_ast_for_testing ast input_file
    else original_ast in
    
    (* For regular eBPF compilation, always use original AST *)
    let compilation_ast = original_ast in
    
    (* Extract base name for project name *)
    let base_name = Filename.remove_extension (Filename.basename input_file) in
    
    (* Phase 2: Symbol table analysis with BTF type loading *)
    current_phase := "Symbol Analysis";
    Printf.printf "Phase 2: %s\n" !current_phase;
    
    (* Extract struct_ops from compilation AST for BTF verification *)
    let struct_ops_to_verify = List.filter_map (function
      | Ast.StructDecl struct_def ->
          List.fold_left (fun acc attr ->
            match attr with
            | Ast.AttributeWithArg ("struct_ops", kernel_name) -> Some (kernel_name, struct_def.struct_fields)
            | _ -> acc
          ) None struct_def.struct_attributes
      | _ -> None
    ) compilation_ast in
    
    (* Verify struct_ops definitions against BTF if BTF path is provided *)
    (match btf_vmlinux_path with
     | Some btf_path when struct_ops_to_verify <> [] ->
         Printf.printf "🔍 Verifying %d struct_ops definitions against BTF...\n" (List.length struct_ops_to_verify);
         List.iter (fun (kernel_name, user_fields) ->
           match Struct_ops_registry.verify_struct_ops_against_btf btf_path kernel_name user_fields with
           | Ok () ->
               Printf.printf "✅ struct_ops '%s' verified against BTF\n" kernel_name
           | Error msg ->
               Printf.printf "❌ BTF verification failed for struct_ops '%s': %s\n" kernel_name msg;
               Printf.printf "💡 Hint: Use 'kernelscript init %s <project_name> --btf-vmlinux-path %s' to generate the correct definition\n" kernel_name btf_path;
               exit 1
         ) struct_ops_to_verify
     | Some _ when struct_ops_to_verify <> [] ->
         Printf.printf "⚠️ struct_ops found but no BTF path provided - skipping verification\n"
     | _ -> ());
    
    (* Load BTF types for eBPF context types and action constants *)
    let btf_types = try
      let program_types = Multi_program_analyzer.get_program_types_from_ast compilation_ast in
      List.fold_left (fun acc prog_type ->
        let prog_type_str = match prog_type with
          | Ast.Xdp -> "xdp"
          | Ast.Tc -> "tc"
          | Ast.Kprobe -> "kprobe"
          | Ast.Tracepoint -> "tracepoint"
          | _ -> ""
        in
        if prog_type_str <> "" then
          let template = Btf_parser.get_program_template prog_type_str btf_vmlinux_path in
          
          (* Extract context structures and integrate them with context codegen *)
          List.iter (fun btf_type ->
            (* Convert Btf_parser.btf_type_info to Context_codegen.btf_type_info *)
            let context_btf_type = {
              Kernelscript_context.Context_codegen.name = btf_type.Btf_parser.name;
              kind = btf_type.Btf_parser.kind;
              size = btf_type.Btf_parser.size;
              members = btf_type.Btf_parser.members;
              kernel_defined = btf_type.Btf_parser.kernel_defined;
            } in
            
            match btf_type.Btf_parser.name with
            | "xdp_md" -> 
                Printf.printf "🔧 Integrating BTF xdp_md structure with context codegen\n";
                Kernelscript_context.Context_codegen.update_context_codegen_with_btf "xdp" context_btf_type
            | "__sk_buff" ->
                Printf.printf "🔧 Integrating BTF __sk_buff structure with context codegen\n";
                Kernelscript_context.Context_codegen.update_context_codegen_with_btf "tc" context_btf_type
            | "pt_regs" ->
                Printf.printf "🔧 Integrating BTF pt_regs structure with context codegen\n";
                Kernelscript_context.Context_codegen.update_context_codegen_with_btf "kprobe" context_btf_type
            | name when String.starts_with name ~prefix:"trace_event_raw_" ->
                Printf.printf "🔧 Integrating BTF %s structure with context codegen\n" name;
                Kernelscript_context.Context_codegen.update_context_codegen_with_btf "tracepoint" context_btf_type
            | _ -> ()
          ) template.types;
          
          template.types @ acc
        else
          acc
      ) [] program_types
    with
    | _ -> 
        Printf.printf "⚠️ Warning: Could not load BTF types, using context defaults\n";
        (* Context codegens already initialized at the start - don't register again *)
        
        (* Get context types from AST *)
        let program_types = Multi_program_analyzer.get_program_types_from_ast compilation_ast in
        List.fold_left (fun acc prog_type ->
          match prog_type with
          | Ast.Xdp -> 
              (* Get XDP action constants from context system *)
              let xdp_constants = Kernelscript_context.Context_codegen.get_context_action_constants "xdp" in
              let xdp_action_type = {
                Btf_parser.name = "xdp_action";
                kind = "enum";
                size = Some 4;
                members = Some (List.map (fun (name, value) -> 
                  (name, string_of_int value)) xdp_constants);
                kernel_defined = true;
              } in
              let xdp_md_type = {
                Btf_parser.name = "xdp_md";
                kind = "struct";
                size = Some 32;
                members = Some (Kernelscript_context.Context_codegen.get_context_struct_fields "xdp");
                kernel_defined = true;
              } in
              xdp_action_type :: xdp_md_type :: acc
          | Ast.Tc ->
              (* For TC programs, we only need __sk_buff struct - no action enum since return type is int *)
              let sk_buff_type = {
                Btf_parser.name = "__sk_buff";
                kind = "struct";
                size = Some 256;
                members = Some (Kernelscript_context.Context_codegen.get_context_struct_fields "tc");
                kernel_defined = true;
              } in
              sk_buff_type :: acc
          | _ -> acc
        ) [] program_types
    in
    
    (* Convert BTF types to AST declarations *)
    let btf_declarations = List.map (fun btf_type ->
      match btf_type.Btf_parser.kind with
      | "struct" -> 
          let fields = match btf_type.members with
            | Some members -> List.map (fun (field_name, _field_type) -> (field_name, Ast.U32)) members
            | None -> []
          in
          Ast.StructDecl { 
            struct_name = btf_type.Btf_parser.name; 
            struct_fields = fields; 
            struct_attributes = if btf_type.Btf_parser.kernel_defined then [Ast.SimpleAttribute "kernel_only"] else []; 
            struct_pos = { filename = "btf"; line = 1; column = 1 }
          }
      | "enum" ->
          let enum_values = match btf_type.members with
            | Some members -> 
                List.map (fun (const_name, const_value) -> (const_name, Some (int_of_string const_value))) members
            | None -> []
          in
          Ast.TypeDef (Ast.EnumDef (btf_type.Btf_parser.name, enum_values))
      | _ -> 
          Ast.TypeDef (Ast.TypeAlias (btf_type.Btf_parser.name, Ast.U32))
    ) btf_types in
    
          Printf.printf "🔧 Loaded %d BTF type definitions\n" (List.length btf_declarations);
      
      (* Filter out BTF types that are already defined by the user *)
      let user_defined_types = List.fold_left (fun acc decl ->
        match decl with
        | Ast.StructDecl struct_def -> struct_def.struct_name :: acc
        | Ast.TypeDef (Ast.EnumDef (enum_name, _)) -> enum_name :: acc
        | Ast.TypeDef (Ast.StructDef (struct_name, _)) -> struct_name :: acc
        | Ast.TypeDef (Ast.TypeAlias (alias_name, _)) -> alias_name :: acc
        | _ -> acc
      ) [] compilation_ast in
      
      let filtered_btf_declarations = List.filter (fun btf_decl ->
        match btf_decl with
        | Ast.StructDecl struct_def -> 
            if List.mem struct_def.struct_name user_defined_types then (
              Printf.printf "🔧 Skipping BTF type '%s' - already defined by user\n" struct_def.struct_name;
              false
            ) else true
        | Ast.TypeDef (Ast.EnumDef (enum_name, _)) -> 
            if List.mem enum_name user_defined_types then (
              Printf.printf "🔧 Skipping BTF enum '%s' - already defined by user\n" enum_name;
              false
            ) else true
        | Ast.TypeDef (Ast.StructDef (struct_name, _)) -> 
            if List.mem struct_name user_defined_types then (
              Printf.printf "🔧 Skipping BTF struct '%s' - already defined by user\n" struct_name;
              false
            ) else true
        | Ast.TypeDef (Ast.TypeAlias (alias_name, _)) -> 
            if List.mem alias_name user_defined_types then (
              Printf.printf "🔧 Skipping BTF alias '%s' - already defined by user\n" alias_name;
              false
            ) else true
        | _ -> true
      ) btf_declarations in
      
      Printf.printf "🔧 Using %d BTF types after filtering (skipped %d user-defined)\n" 
        (List.length filtered_btf_declarations) 
        (List.length btf_declarations - List.length filtered_btf_declarations);

    (* Add stdlib builtin types to the symbol table *)
    let stdlib_builtin_declarations = Stdlib.get_builtin_types () in
    let all_builtin_declarations = stdlib_builtin_declarations @ filtered_btf_declarations in
    let symbol_table = Symbol_table.build_symbol_table ~project_name:base_name ~builtin_asts:[all_builtin_declarations] compilation_ast in
      
    Printf.printf "✅ Symbol table created successfully with BTF types\n\n";
    
    (* Phase 3: Multi-program analysis *)
    current_phase := "Multi-Program Analysis";
    Printf.printf "Phase 3: %s\n" !current_phase;
    let multi_prog_analysis = Multi_program_analyzer.analyze_multi_program_system compilation_ast in
    
    (* Extract config declarations *)
    let config_declarations = List.filter_map (function
      | Ast.ConfigDecl config -> Some config
      | _ -> None
    ) compilation_ast in
    Printf.printf "📋 Found %d config declarations\n" (List.length config_declarations);
    
    (* Phase 4: Enhanced type checking with multi-program context *)
    current_phase := "Type Checking";
    Printf.printf "Phase 4: %s\n" !current_phase;
    let (annotated_ast, _typed_programs) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ~imports:resolved_imports compilation_ast in
    Printf.printf "✅ Type checking completed with multi-program annotations\n\n";
    
    (* Phase 4.5: Safety Analysis *)
    current_phase := "Safety Analysis";
    Printf.printf "Phase 4.5: %s\n" !current_phase;
    
    (* Extract all functions from the TYPE-ANNOTATED AST for safety analysis *)
    let all_functions = List.fold_left (fun acc decl ->
      match decl with
      | Ast.AttributedFunction attr_func -> attr_func.attr_function :: acc
      | Ast.GlobalFunction func -> func :: acc
      | _ -> acc
    ) [] annotated_ast in
    
    (* Extract map declarations from the TYPE-ANNOTATED AST for safety analysis *)
    let all_maps = List.fold_left (fun acc decl ->
      match decl with
      | Ast.MapDecl map_decl -> map_decl :: acc
      | _ -> acc
    ) [] annotated_ast in
    
    (* Create a program structure for safety analysis *)
    let safety_program = {
      Ast.prog_name = base_name;
      prog_type = Xdp; (* Default - not used by safety checker *)
      prog_functions = all_functions;
      prog_maps = all_maps;
      prog_structs = [];
      prog_pos = Ast.make_position 1 1 input_file;
    } in
    
    (* Run safety analysis *)
    let safety_analysis = Safety_checker.analyze_safety safety_program in
    
    (* Check for safety violations and report them *)
    if not safety_analysis.overall_safe then (
      Printf.eprintf "⚠️  Safety Analysis Issues:\n";
      
      (* Report stack overflow issues *)
      if safety_analysis.stack_analysis.potential_overflow then (
        Printf.eprintf "❌ Stack overflow detected: %d bytes exceeds eBPF limit of %d bytes\n"
          safety_analysis.stack_analysis.max_stack_usage
          Safety_checker.EbpfConstraints.max_stack_size;
        List.iter (fun warning -> Printf.eprintf "   %s\n" warning) safety_analysis.stack_analysis.warnings;
        Printf.eprintf "   Suggestion: Use BPF per-cpu array maps for large data structures\n";
      );
      
      (* Report bounds errors *)
      if safety_analysis.bounds_errors <> [] then (
        Printf.eprintf "❌ Bounds checking errors:\n";
        List.iter (fun error -> 
          Printf.eprintf "   %s\n" (Safety_checker.string_of_bounds_error error)
        ) safety_analysis.bounds_errors;
      );
      
      (* Report pointer safety issues *)
      if safety_analysis.pointer_safety.invalid_pointers <> [] then (
        Printf.eprintf "❌ Pointer safety issues:\n";
        List.iter (fun (ptr, reason) -> 
          Printf.eprintf "   %s: %s\n" ptr reason
        ) safety_analysis.pointer_safety.invalid_pointers;
      );
      
      Printf.eprintf "\n❌ Compilation halted due to safety violations\n";
      exit 1
    ) else (
      Printf.printf "✅ Safety analysis passed - %s stack usage: %d/%d bytes\n\n" 
        base_name 
        safety_analysis.stack_analysis.max_stack_usage 
        Safety_checker.EbpfConstraints.max_stack_size
    );
    
    (* Phase 5: IR Optimization *)
    current_phase := "IR Optimization";
    Printf.printf "Phase 5: %s\n" !current_phase;
    
    (* Generate test file in test mode *)
    let test_file_generated = if test_mode then (
      let test_output_dir = match output_dir with
        | Some dir -> dir
        | None -> base_name
      in
      
      (try Unix.mkdir test_output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
      
      let filtered_symbol_table = Symbol_table.build_symbol_table ~project_name:base_name ~builtin_asts:[filtered_btf_declarations] filtered_ast in
      let (filtered_annotated_ast, _) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some filtered_symbol_table) filtered_ast in
      let test_c_code = Test_codegen.generate_test_program filtered_annotated_ast base_name in
      
      let test_c_file = test_output_dir ^ "/" ^ base_name ^ ".test.c" in
      let test_out = open_out test_c_file in
      output_string test_out test_c_code;
      close_out test_out;
      
      Some test_c_file
    ) else None in
    
    (* Continue with regular eBPF compilation using the appropriate AST *)
    (
          let optimized_ir = Multi_program_ir_optimizer.generate_optimized_ir annotated_ast multi_prog_analysis symbol_table input_file in
    
    (* Ring Buffer Analysis - populate the centralized registry *)
    let ir_with_ring_buffer_analysis = Ir_analysis.RingBufferAnalysis.analyze_and_populate_registry optimized_ir in
  
  (* Phase 6: Advanced multi-target code generation *)
    current_phase := "Code Generation";
    Printf.printf "Phase 6: %s\n" !current_phase;
    let _resource_plan = Multi_program_ir_optimizer.plan_system_resources ir_with_ring_buffer_analysis.programs multi_prog_analysis in
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
    
    (* Perform tail call analysis on AST *)
    let tail_call_analysis = Tail_call_analyzer.analyze_tail_calls annotated_ast in
    
    (* Update IR functions with correct tail call indices *)
    let updated_optimized_ir = 
      let updated_programs = List.map (fun prog ->
        let updated_entry_function = Tail_call_analyzer.update_ir_function_tail_call_indices prog.Ir.entry_function tail_call_analysis in
        { prog with entry_function = updated_entry_function }
      ) ir_with_ring_buffer_analysis.programs in
      
      let updated_kernel_functions = List.map (fun func ->
        Tail_call_analyzer.update_ir_function_tail_call_indices func tail_call_analysis
      ) ir_with_ring_buffer_analysis.kernel_functions in
      
      { ir_with_ring_buffer_analysis with programs = updated_programs; kernel_functions = updated_kernel_functions }
    in
    
    (* Generate eBPF C code (with updated IR and kfunc declarations) *)
    let (ebpf_c_code, _final_tail_call_analysis) = Ebpf_c_codegen.compile_multi_to_c_with_analysis 
      ~type_aliases ~variable_type_aliases ~kfunc_declarations ~symbol_table ~tail_call_analysis:(Some tail_call_analysis) updated_optimized_ir in
      
    (* Analyze kfunc dependencies for automatic kernel module loading *)
    let ir_functions = List.map (fun prog -> prog.Ir.entry_function) ir_with_ring_buffer_analysis.programs in
    let kfunc_dependencies = Userspace_codegen.analyze_kfunc_dependencies base_name annotated_ast ir_functions in
    
    (* Generate kernel module for kfuncs if any exist *)
    let kernel_module_code = Kernel_module_codegen.generate_kernel_module_from_ast base_name annotated_ast in
    
    (* Generate userspace coordinator directly to output directory with tail call analysis *)
    Userspace_codegen.generate_userspace_code_from_ir 
      ~config_declarations ~type_aliases ~tail_call_analysis ~kfunc_dependencies ~resolved_imports ~symbol_table ?btf_path:btf_vmlinux_path updated_optimized_ir ~output_dir:actual_output_dir input_file;
    
    (* Output directory already created earlier *)
    
    (* Write eBPF C code *)
    let ebpf_filename = actual_output_dir ^ "/" ^ base_name ^ ".ebpf.c" in
    let oc = open_out ebpf_filename in
    output_string oc ebpf_c_code;
    close_out oc;
    
    (* Write kernel module file if kfuncs exist *)
    (match kernel_module_code with
    | Some module_code ->
        let module_filename = actual_output_dir ^ "/" ^ base_name ^ ".mod.c" in
        let oc = open_out module_filename in
        output_string oc module_code;
        close_out oc;
        Printf.printf "✅ Generated kernel module: %s\n" module_filename
    | None -> 
        Printf.printf "ℹ️ No kfuncs detected, kernel module not generated\n");
    
    (* Generate Makefile if requested *)
    if generate_makefile then (
      (* Generate shared library rules for imported modules *)
      let ks_imports = List.filter (fun import ->
        match import.Import_resolver.source_type with
        | Ast.KernelScript -> true
        | _ -> false
      ) resolved_imports in
      
      let shared_lib_rules = if ks_imports = [] then ""
        else
          let rules = List.map (fun import ->
            let module_name = import.Import_resolver.module_name in
            sprintf {|
# Shared library for %s module
%s.so: %s.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

|} module_name module_name module_name
          ) ks_imports in
          String.concat "" rules
      in
      
      let shared_lib_targets = if ks_imports = [] then ""
        else
          let targets = List.map (fun import -> import.Import_resolver.module_name ^ ".so") ks_imports in
          String.concat " " targets
      in
      
      let shared_lib_deps = if shared_lib_targets = "" then "" else " " ^ shared_lib_targets in
      
      (* Check if Python imports exist and add Python linking flags *)
      let has_python_imports = List.exists (fun import ->
        match import.Import_resolver.source_type with
        | Ast.Python -> true
        | _ -> false
      ) resolved_imports in
      
      let python_flags = if has_python_imports then " $(shell python3-config --cflags) $(shell python3-config --libs --embed 2>/dev/null || python3-config --libs)" else "" in
      
      (* Check if kernel module was generated *)
      let has_kernel_module = match kernel_module_code with | Some _ -> true | None -> false in
      
      (* Kernel module variables and targets *)
      let kernel_module_vars = if has_kernel_module then
        sprintf {|
# Kernel module files
KERNEL_MODULE_SRC = %s.mod.c
KERNEL_MODULE_OBJ = %s.mod.ko|} base_name base_name
      else "" in
      
      let kernel_module_target = if has_kernel_module then " $(KERNEL_MODULE_OBJ)" else "" in
      
      let kernel_module_rules = if has_kernel_module then
        sprintf {|
# Build kernel module
$(KERNEL_MODULE_OBJ): $(KERNEL_MODULE_SRC)
	@echo "Building kernel module..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
# Install kernel module (requires root)
install-module: $(KERNEL_MODULE_OBJ)
	sudo insmod $(KERNEL_MODULE_OBJ)
	
# Remove kernel module (requires root) 
uninstall-module:
	sudo rmmod %s || true|} base_name
      else "" in
      
      let kernel_module_clean = if has_kernel_module then " $(KERNEL_MODULE_OBJ) modules.order Module.symvers .*.cmd" else "" in
      
      let makefile_content = Printf.sprintf {|# Multi-Program eBPF Makefile
# Generated by KernelScript compiler

# Compilers
BPF_CC = clang
CC = gcc

# BPF compilation flags
BPF_CFLAGS = -target bpf -O2 -Wall -Wextra -g
BPF_INCLUDES = -I/usr/include -I/usr/include/x86_64-linux-gnu

# Userspace compilation flags
CFLAGS = -Wall -Wextra -O2 -fPIC
LIBS = -lbpf -lelf -lz%s

# Object files
BPF_OBJ = %s.ebpf.o
USERSPACE_BIN = %s
SKELETON_H = %s.skel.h

# Source files
BPF_SRC = %s.ebpf.c
USERSPACE_SRC = %s.c

# Default target
all:%s $(BPF_OBJ) $(SKELETON_H) $(USERSPACE_BIN)%s

# Compile eBPF C to object file
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CC) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

# Generate skeleton header
$(SKELETON_H): $(BPF_OBJ)
	@echo "Generating skeleton header..."
	bpftool gen skeleton $< > $@

# Compile userspace program (link with shared libraries)
$(USERSPACE_BIN): $(USERSPACE_SRC) $(SKELETON_H)%s
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)%s%s
%s
%s
# Clean generated files
clean:
	rm -f $(BPF_OBJ) $(SKELETON_H) $(USERSPACE_BIN)%s%s

# Build just the eBPF object without skeleton (for testing)
ebpf-only: $(BPF_OBJ)

# Run the userspace program
run: $(USERSPACE_BIN)
	sudo ./$(USERSPACE_BIN)

# Help target
help:
	@echo "Available targets:"
	@echo "  all            - Build eBPF program and userspace coordinator%s"
	@echo "  ebpf-only      - Build just the eBPF object file"
%s	@echo "  clean          - Clean all generated files"
	@echo "  run            - Run the userspace program (requires sudo)"

.PHONY: all clean run ebpf-only help%s
|} kernel_module_vars base_name base_name base_name base_name base_name 
       shared_lib_deps kernel_module_target shared_lib_deps
       (if shared_lib_targets = "" then "" else (" " ^ String.concat " " (List.map (fun import -> "./" ^ import.Import_resolver.module_name ^ ".so") ks_imports)))
       python_flags
       kernel_module_rules 
       shared_lib_rules 
       (if shared_lib_targets = "" then "" else (" " ^ shared_lib_targets)) 
       kernel_module_clean
       (if has_kernel_module then " and kernel module" else "")
       (if has_kernel_module then sprintf {|	@echo "  install-module - Install kernel module (requires root)"
	@echo "  uninstall-module - Remove kernel module (requires root)"
|} else "")
       (if has_kernel_module then " install-module uninstall-module" else "") in
      
      let makefile_path = actual_output_dir ^ "/Makefile" in
      let oc = open_out makefile_path in
      output_string oc makefile_content;
      close_out oc;
      
      Printf.printf "📄 Generated Makefile: %s/Makefile\n" actual_output_dir;
      
      (* Generate Kbuild file if kernel module exists *)
      if has_kernel_module then (
        let kbuild_content = sprintf "obj-m += %s.mod.o\n" base_name in
        let kbuild_path = actual_output_dir ^ "/Kbuild" in
        let kbuild_oc = open_out kbuild_path in
        output_string kbuild_oc kbuild_content;
        close_out kbuild_oc;
        Printf.printf "📄 Generated Kbuild: %s/Kbuild\n" actual_output_dir
      )
    );
    
      Printf.printf "\n✨ Compilation completed successfully!\n";
      Printf.printf "📁 Output directory: %s/\n" actual_output_dir;
      Printf.printf "🔨 To build: cd %s && make\n" actual_output_dir;
      (match test_file_generated with 
       | Some _ -> Printf.printf "🧪 To build tests: cd %s && make test\n🧪 To run tests: cd %s && make run-test\n" actual_output_dir actual_output_dir
       | None -> ());
    )  (* Close the compilation block *)
    
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
  | Compile { input_file; output_dir; verbose; generate_makefile; btf_vmlinux_path; test_mode } ->
      compile_source input_file output_dir verbose generate_makefile btf_vmlinux_path test_mode 