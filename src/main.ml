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
      printf "    prog_type: xdp | tc | kprobe | uprobe | tracepoint | lsm | cgroup_skb\n";
      printf "    struct_ops: tcp_congestion_ops | bpf_iter_ops | bpf_struct_ops_test | custom_name\n";
      printf "    project_name: Name of the project directory to create\n";
      printf "    --btf-vmlinux-path: Path to BTF vmlinux file for type/struct_ops extraction\n\n";
      printf "  compile <input_file> [options]\n";
      printf "    Compile KernelScript source to C code\n";
      printf "    -o, --output <dir>            Specify output directory\n";
      printf "    -v, --verbose                 Enable verbose output\n";
      printf "    --no-makefile                 Don't generate Makefile\n";
      printf "    --test                        Compile in test mode (only @test functions become main)\n";
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
  let rec parse_aux input_file_opt output_dir verbose generate_makefile btf_path test_mode = function
    | [] ->
                 (match input_file_opt with
          | Some input_file ->
              Compile { input_file; output_dir; verbose; generate_makefile; btf_vmlinux_path = btf_path; test_mode }
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
  
  (* Check if this is a struct_ops or a regular program type *)
  let valid_program_types = ["xdp"; "tc"; "kprobe"; "uprobe"; "tracepoint"; "lsm"; "cgroup_skb"] in
  let is_struct_ops = Struct_ops_registry.is_known_struct_ops prog_type_or_struct_ops in
  let is_program_type = List.mem prog_type_or_struct_ops valid_program_types in
  
  if not is_struct_ops && not is_program_type then (
    printf "❌ Error: Invalid type '%s'\n" prog_type_or_struct_ops;
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
      printf "🔧 Extracting struct_ops definition for %s...\n" prog_type_or_struct_ops;
      let content = Btf_parser.generate_struct_ops_template btf_path [prog_type_or_struct_ops] project_name in
      printf "✅ Generated struct_ops template\n";
      content
    ) else (
      printf "🔧 Extracting types for %s program...\n" prog_type_or_struct_ops;
      let template = Btf_parser.get_program_template prog_type_or_struct_ops btf_path in
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
      let struct_ops_info = Struct_ops_registry.get_struct_ops_info prog_type_or_struct_ops in
      let description = match struct_ops_info with
        | Some info -> info.description
        | None -> sprintf "Custom struct_ops implementation for %s" prog_type_or_struct_ops
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
|} project_name description project_name project_name project_name project_name project_name prog_type_or_struct_ops description prog_type_or_struct_ops
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
|} project_name prog_type_or_struct_ops project_name project_name project_name project_name project_name prog_type_or_struct_ops (match prog_type_or_struct_ops with
        | "xdp" -> "XDP programs provide high-performance packet processing at the driver level."
        | "tc" -> "TC programs enable traffic control and packet filtering in the Linux networking stack."
        | "kprobe" -> "Kprobe programs allow dynamic tracing of kernel functions."
        | "uprobe" -> "Uprobe programs enable tracing of userspace functions."
        | "tracepoint" -> "Tracepoint programs provide static tracing points in the kernel."
        | "lsm" -> "LSM programs implement security policies and access control."
        | "cgroup_skb" -> "Cgroup SKB programs filter network packets based on cgroup membership."
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
    printf "   2. Refer to kernel documentation for %s implementation details\n" prog_type_or_struct_ops;
    printf "   3. Run 'kernelscript compile %s/%s.ks' to compile with BTF verification\n" project_name project_name;
    printf "   4. Run 'cd %s && make' to build the generated C code\n" project_name
  ) else (
    printf "   1. Edit %s/%s.ks to implement your program logic\n" project_name project_name;
    printf "   2. Run 'kernelscript compile %s/%s.ks' to compile\n" project_name project_name;
    printf "   3. Run 'cd %s && make' to build the generated C code\n" project_name
  )

(** Compile KernelScript source (existing functionality) *)
let compile_source input_file output_dir _verbose generate_makefile btf_vmlinux_path test_mode =
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
            struct_attributes = []; 
            kernel_defined = btf_type.Btf_parser.kernel_defined;
            struct_pos = { filename = "btf"; line = 1; column = 1 }
          }
      | "enum" ->
          let enum_values = match btf_type.members with
            | Some members -> 
                List.map (fun (const_name, const_value) -> (const_name, Some (int_of_string const_value))) members
            | None -> []
          in
          Ast.TypeDef (Ast.EnumDef (btf_type.Btf_parser.name, enum_values, btf_type.Btf_parser.kernel_defined))
      | _ -> 
          Ast.TypeDef (Ast.TypeAlias (btf_type.Btf_parser.name, Ast.U32))
    ) btf_types in
    
          Printf.printf "🔧 Loaded %d BTF type definitions\n" (List.length btf_declarations);
      
      (* Filter out BTF types that are already defined by the user *)
      let user_defined_types = List.fold_left (fun acc decl ->
        match decl with
        | Ast.StructDecl struct_def -> struct_def.struct_name :: acc
        | Ast.TypeDef (Ast.EnumDef (enum_name, _, _)) -> enum_name :: acc
        | Ast.TypeDef (Ast.StructDef (struct_name, _, _)) -> struct_name :: acc
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
        | Ast.TypeDef (Ast.EnumDef (enum_name, _, _)) -> 
            if List.mem enum_name user_defined_types then (
              Printf.printf "🔧 Skipping BTF enum '%s' - already defined by user\n" enum_name;
              false
            ) else true
        | Ast.TypeDef (Ast.StructDef (struct_name, _, _)) -> 
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

      let symbol_table = Symbol_table.build_symbol_table ~project_name:base_name ~builtin_asts:[filtered_btf_declarations] compilation_ast in
      
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
    let (annotated_ast, _typed_programs) = Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) compilation_ast in
    Printf.printf "✅ Type checking completed with multi-program annotations\n\n";
    
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
    
    (* Perform tail call analysis on AST *)
    let tail_call_analysis = Tail_call_analyzer.analyze_tail_calls annotated_ast in
    
    (* Update IR functions with correct tail call indices *)
    let updated_optimized_ir = 
      let updated_programs = List.map (fun prog ->
        let updated_entry_function = Tail_call_analyzer.update_ir_function_tail_call_indices prog.Ir.entry_function tail_call_analysis in
        { prog with entry_function = updated_entry_function }
      ) optimized_ir.programs in
      
      let updated_kernel_functions = List.map (fun func ->
        Tail_call_analyzer.update_ir_function_tail_call_indices func tail_call_analysis
      ) optimized_ir.kernel_functions in
      
      { optimized_ir with programs = updated_programs; kernel_functions = updated_kernel_functions }
    in
    
    (* Generate eBPF C code (with updated IR and kfunc declarations) *)
    let (ebpf_c_code, _final_tail_call_analysis) = Ebpf_c_codegen.compile_multi_to_c_with_analysis 
      ~type_aliases ~variable_type_aliases ~kfunc_declarations ~symbol_table ~tail_call_analysis:(Some tail_call_analysis) updated_optimized_ir in
      
    (* Determine output directory *)
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
      ~config_declarations ~type_aliases ~tail_call_analysis ~kfunc_dependencies ~symbol_table updated_optimized_ir ~output_dir input_file;
    
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

# Check if kernel module is loaded
check-kmod:
	@if lsmod | grep -q "^%s"; then \
		echo "Kernel module %s is loaded"; \
	else \
		echo "Kernel module %s is NOT loaded"; \
		echo "Run 'make load-kmod' to load the module before building eBPF skeleton"; \
		exit 1; \
	fi

# Kernel module Makefile for external build
obj-m := %s.mod.o

# Enable debug info for BTF generation
KBUILD_CFLAGS += -g -O2%s
|} base_name base_name btf_vmlinux_make_var base_name base_name base_name base_name base_name btf_vmlinux_cflags
        | None -> ""
      in
      
      let has_kfuncs = kernel_module_code <> None in
      
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
SKELETON_H = %s.skel.h

# Source files
BPF_SRC = %s.ebpf.c
USERSPACE_SRC = %s.c%s

# Default target - build kernel module first%s, then check if loaded, then build eBPF parts
all: %s$(BPF_OBJ) $(SKELETON_H) $(USERSPACE_BIN)

# Alternative target that loads kernel module automatically (requires sudo)
all-with-load: %s$(BPF_OBJ) $(SKELETON_H) $(USERSPACE_BIN)

# Compile eBPF C to object file
$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CC) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

# Generate skeleton header%s
$(SKELETON_H): $(BPF_OBJ)%s
	@echo "Generating skeleton header..."
%s	bpftool gen skeleton $< > $@

# Compile userspace program
$(USERSPACE_BIN): $(USERSPACE_SRC) $(SKELETON_H)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Clean generated files
clean:
	rm -f $(BPF_OBJ) $(SKELETON_H) $(USERSPACE_BIN)%s

# Build just the eBPF object without skeleton (for testing)
ebpf-only: $(BPF_OBJ)

# Run the userspace program
run: $(USERSPACE_BIN)
	sudo ./$(USERSPACE_BIN)

# Help target
help:
	@echo "Available targets:"
	@echo "  all            - Build kernel module%s, check if loaded, then build eBPF parts"
	@echo "  all-with-load  - Build kernel module, load it, then build eBPF parts (requires sudo)"
%s	@echo "  ebpf-only      - Build just the eBPF object file"
	@echo "  clean          - Clean all generated files"
	@echo "  run            - Run the userspace program (requires sudo)"
%s%s

%s

.PHONY: all all-with-load clean run ebpf-only help%s
|} base_name base_name base_name base_name base_name kmod_targets
       (if has_kfuncs then " (if present)" else "")
       (if has_kfuncs then "$(KMOD_OBJ) check-kmod " else "")
       (if has_kfuncs then "$(KMOD_OBJ) load-kmod " else "")
       (if has_kfuncs then " (requires kernel module to be loaded for kfunc BTF info)" else "")
       (if has_kfuncs then " check-kmod" else "")
       (if has_kfuncs then "\t@echo \"Note: This requires the kernel module to be loaded for kfunc BTF information\"\n" else "")
       (if has_kfuncs then " clean-kmod" else "")
       (if has_kfuncs then "" else "")
       (if has_kfuncs then "\n\t@echo \"  load-kmod      - Load the kernel module (requires sudo)\"\n\t@echo \"  unload-kmod    - Unload the kernel module (requires sudo)\"\n\t@echo \"  check-kmod     - Check if kernel module is loaded\"\n" else "")
              (if has_kfuncs then "\n\t@echo \"\"\n\t@echo \"For kfunc programs, you need to load the kernel module first:\"\n\t@echo \"  make load-kmod && make all\"\n\t@echo \"Or use: make all-with-load\"" else "")
       (* Test target help *)
       (match test_file_generated with Some _ -> "\n\t@echo \"  test           - Build test functions\"\n\t@echo \"  run-test       - Build and run test functions\"" | None -> "")
       (* Test target content *)
       (match test_file_generated with 
        | Some _ -> Printf.sprintf "# Test target (compile tests only)\ntest: %s.test.c\n\t$(CC) $(CFLAGS) -o %s_test %s.test.c $(LIBS)\n\n# Run test target (compile and run tests)\nrun-test: test\n\t./%s_test" base_name base_name base_name base_name
        | None -> "")
       (* Test target in .PHONY and kfunc targets *)
       (match test_file_generated with Some _ -> " test run-test" | None -> "") ^ (if has_kfuncs then " load-kmod unload-kmod clean-kmod check-kmod" else "") in
      
      let makefile_path = output_dir ^ "/Makefile" in
      let oc = open_out makefile_path in
      output_string oc makefile_content;
      close_out oc;
      
      Printf.printf "📄 Generated Makefile: %s/Makefile\n" output_dir
    );
    
      Printf.printf "\n✨ Compilation completed successfully!\n";
      Printf.printf "📁 Output directory: %s/\n" output_dir;
      Printf.printf "🔨 To build: cd %s && make\n" output_dir;
      (match test_file_generated with 
       | Some _ -> Printf.printf "🧪 To build tests: cd %s && make test\n🧪 To run tests: cd %s && make run-test\n" output_dir output_dir
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