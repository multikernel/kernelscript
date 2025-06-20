(** Builtin Loader for KernelScript
    This module provides utilities for loading builtin AST files
    to avoid code duplication across the codebase.
*)

open Ast

(** Find builtin directory from various possible locations *)
let find_builtin_dir ?builtin_path () =
  match builtin_path with
  | Some path when Sys.file_exists path && Sys.is_directory path -> Some path
  | Some _ -> None  (* Invalid custom path *)
  | None ->
      let candidates = [
        "builtin";              (* Current directory *)
        "../builtin";           (* From subdirectory like tests/ *)
        "../../builtin";        (* From _build/default/ *)
        "../../../builtin";     (* From _build/default/tests/ *)
        "../../../../builtin";  (* From deeper nested build dirs *)
      ] in
      List.find_opt (fun dir -> Sys.file_exists dir && Sys.is_directory dir) candidates

(** Load a single builtin AST file *)
let load_builtin_ast ?builtin_path builtin_filename =
  match find_builtin_dir ?builtin_path () with
  | Some builtin_dir ->
      let full_path = Filename.concat builtin_dir builtin_filename in
      if Sys.file_exists full_path then
        try
          let content = 
            let ic = open_in full_path in
            let content = really_input_string ic (in_channel_length ic) in
            close_in ic;
            content
          in
          Some (Parse.parse_string content)
        with _ -> None
      else None
  | None -> None

(** Load all standard builtin ASTs (xdp.ks, tc.ks, kprobe.ks) *)
let load_standard_builtins ?builtin_path () =
  let builtin_files = ["xdp.ks"; "tc.ks"; "kprobe.ks"] in
  List.filter_map (load_builtin_ast ?builtin_path) builtin_files

(** Build symbol table with builtin ASTs loaded *)
let build_symbol_table_with_builtins ?builtin_path ast =
  let builtin_asts = load_standard_builtins ?builtin_path () in
  if builtin_asts = [] then
    Symbol_table.build_symbol_table ast
  else
    Symbol_table.build_symbol_table ~builtin_asts ast

(** Parse string with builtin constants loaded - validation should be done separately *)
let parse_with_builtins ?builtin_path code =
  let ast = Parse.parse_string code in
  let _symbol_table = build_symbol_table_with_builtins ?builtin_path ast in
  ast

(** Load specific builtin ASTs by program types *)
let load_builtins_for_program_types ?builtin_path program_types =
  let builtin_files = List.filter_map (function
    | Xdp -> Some "xdp.ks"
    | Tc -> Some "tc.ks"
    | Kprobe -> Some "kprobe.ks"
    | _ -> None
  ) program_types in
  List.filter_map (load_builtin_ast ?builtin_path) builtin_files 