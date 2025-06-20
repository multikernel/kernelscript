(** Builtin Loader for KernelScript
    This module provides utilities for loading builtin AST files
    to avoid code duplication across the codebase.
*)



(** Find builtin directory from various possible locations *)
val find_builtin_dir : ?builtin_path:string -> unit -> string option

(** Load a single builtin AST file *)
val load_builtin_ast : ?builtin_path:string -> string -> Ast.declaration list option

(** Load all standard builtin ASTs (xdp.ks, tc.ks, kprobe.ks) *)
val load_standard_builtins : ?builtin_path:string -> unit -> Ast.declaration list list

(** Build symbol table with builtin ASTs loaded *)
val build_symbol_table_with_builtins : ?builtin_path:string -> Ast.declaration list -> Symbol_table.symbol_table

(** Parse string with builtin constants loaded - validation should be done separately *)
val parse_with_builtins : ?builtin_path:string -> string -> Ast.declaration list

(** Load specific builtin ASTs by program types *)
val load_builtins_for_program_types : ?builtin_path:string -> Ast.program_type list -> Ast.declaration list list 