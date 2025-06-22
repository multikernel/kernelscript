(** Builtin Compiler for KernelScript
    This module compiles KernelScript builtin files to C headers
    that can be included in generated eBPF programs.
*)

open Ast

(** Generate C enum definition from KernelScript enum *)
let generate_c_enum enum_name enum_values =
  let header = Printf.sprintf "enum %s {" enum_name in
  let constants = List.mapi (fun i (const_name, value_opt) ->
    let value = match value_opt with
      | Some v -> v
      | None -> i  (* Auto-assign if no explicit value *)
    in
    let comma = if i = List.length enum_values - 1 then "" else "," in
    Printf.sprintf "    %s = %d%s" const_name value comma
  ) enum_values in
  let footer = "};" in
  String.concat "\n" (header :: constants @ [footer])

(** Generate C struct definition from KernelScript struct *)
let generate_c_struct struct_name struct_fields =
  let header = Printf.sprintf "struct %s {" struct_name in
  let fields = List.map (fun (field_name, field_type) ->
    let c_type = match field_type with
      | U8 -> "__u8"
      | U16 -> "__u16"
      | U32 -> "__u32"
      | U64 -> "__u64"
      | I8 -> "__s8"
      | I16 -> "__s16"
      | I32 -> "__s32"
      | I64 -> "__s64"
      | Bool -> "__u8"  (* bool as u8 in kernel *)
      | Char -> "char"
      | Array (base_type, size) ->
          let base_c_type = match base_type with
            | U8 -> "__u8"
            | U16 -> "__u16"
            | U32 -> "__u32"
            | U64 -> "__u64"
            | I8 -> "__s8"
            | I16 -> "__s16"
            | I32 -> "__s32"
            | I64 -> "__s64"
            | Bool -> "__u8"
            | Char -> "char"
            | _ -> "void*"  (* fallback for complex types *)
          in
          Printf.sprintf "%s[%d]" base_c_type size
      | _ -> "void*"  (* fallback for complex types *)
    in
    Printf.sprintf "    %s %s;" c_type field_name
  ) struct_fields in
  let footer = "};" in
  String.concat "\n" (header :: fields @ [footer])

(** Generate C header content from KernelScript AST *)
let generate_c_header ast builtin_name =
  let header_guard = String.uppercase_ascii builtin_name ^ "_H" in
  let header_start = [
    Printf.sprintf "#ifndef %s" header_guard;
    Printf.sprintf "#define %s" header_guard;
    "";
    Printf.sprintf "/* Generated from %s.ks - Do not edit manually */" builtin_name;
    "";
    "#include <linux/types.h>";
    "#include <linux/bpf.h>";
    "";
  ] in
  
  let content = List.fold_left (fun acc decl ->
    match decl with
    | TypeDef (EnumDef (enum_name, enum_values)) ->
        let c_enum = generate_c_enum enum_name enum_values in
        acc @ [c_enum; ""]
    | TypeDef (StructDef (struct_name, struct_fields)) ->
        let c_struct = generate_c_struct struct_name struct_fields in
        acc @ [c_struct; ""]
    | StructDecl struct_def ->
        let c_struct = generate_c_struct struct_def.struct_name struct_def.struct_fields in
        acc @ [c_struct; ""]
    | _ -> acc  (* Skip other declarations for now *)
  ) [] ast in
  
  let header_end = [
    "";
    Printf.sprintf "#endif /* %s */" header_guard;
  ] in
  
  String.concat "\n" (header_start @ content @ header_end)

(** Compile a builtin KernelScript file to C header *)
let compile_builtin_file input_file output_file =
  try
    (* Read and parse the builtin file *)
    let content = 
      let ic = open_in input_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      content
    in
    
    let ast = Parse.parse_string content in
    
    (* Extract builtin name from filename *)
    let builtin_name = Filename.remove_extension (Filename.basename input_file) in
    
    (* Generate C header *)
    let c_header = generate_c_header ast builtin_name in
    
    (* Write to output file *)
    let oc = open_out output_file in
    output_string oc c_header;
    close_out oc;
    
    Printf.printf "Compiled %s -> %s\n" input_file output_file
    
  with
  | Sys_error msg ->
      Printf.eprintf "Error: %s\n" msg;
      exit 1
  | Parse.Parse_error (msg, pos) ->
      Printf.eprintf "Parse error in %s: %s at line %d, column %d\n" 
        input_file msg pos.line pos.column;
      exit 1
  | e ->
      Printf.eprintf "Error compiling %s: %s\n" input_file (Printexc.to_string e);
      exit 1

(** Compile all builtin files in a directory *)
let compile_builtins_directory builtin_dir output_dir =
  (* Create output directory if it doesn't exist *)
  (try Unix.mkdir output_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  
  (* Find all .ks files in builtin directory *)
  let files = Sys.readdir builtin_dir in
  let ks_files = Array.to_list files 
    |> List.filter (fun f -> Filename.check_suffix f ".ks") 
    |> List.map (fun f -> Filename.concat builtin_dir f) in
  
  (* Compile each builtin file *)
  List.iter (fun input_file ->
    let basename = Filename.remove_extension (Filename.basename input_file) in
    let output_file = Filename.concat output_dir (basename ^ ".h") in
    compile_builtin_file input_file output_file
  ) ks_files;
  
  Printf.printf "Compiled %d builtin files\n" (List.length ks_files)

(** Get the appropriate builtin header for a program type *)
let get_builtin_header_for_program_type = function
  | Xdp -> Some "xdp.h"
  | Tc -> Some "tc.h"
  | Kprobe -> Some "kprobe.h"
  | Uprobe -> Some "uprobe.h"
  | Tracepoint -> Some "tracepoint.h"
  | Lsm -> Some "lsm.h"
  | CgroupSkb -> Some "cgroup_skb.h"

(** Load builtin definitions for type checking *)
let load_builtin_definitions_for_type_checking builtin_dir program_type =
  let builtin_file = match program_type with
    | Xdp -> Some (Filename.concat builtin_dir "xdp.ks")
    | Tc -> Some (Filename.concat builtin_dir "tc.ks")
    | Kprobe -> Some (Filename.concat builtin_dir "kprobe.ks")
    | _ -> None
  in
  
  match builtin_file with
  | Some file when Sys.file_exists file ->
      (try
         let content = 
           let ic = open_in file in
           let content = really_input_string ic (in_channel_length ic) in
           close_in ic;
           content
         in
         Some (Parse.parse_string content)
       with
       | _ -> None)
  | _ -> None 