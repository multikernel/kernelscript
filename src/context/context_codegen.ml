(** Context Code Generation Interface
    This module defines the interface for context-specific code generators
*)

type context_field_access = {
  field_name: string;
  c_expression: string -> string; (* ctx_var -> C expression *)
  requires_cast: bool;
  field_type: string; (* C type of the field *)
}

type context_codegen = {
  name: string;
  c_type: string;
  section_prefix: string;
  field_mappings: (string * context_field_access) list;
  generate_includes: unit -> string list;
  generate_field_access: string -> string -> string; (* ctx_var -> field_name -> C expression *)
}

(** Registry for context code generators *)
let context_generators = Hashtbl.create 8

(** Register a context code generator *)
let register_context_codegen ctx_type codegen =
  Hashtbl.replace context_generators ctx_type codegen

(** Get a context code generator by type *)
let get_context_codegen ctx_type =
  try
    Some (Hashtbl.find context_generators ctx_type)
  with Not_found -> None

(** Initialize all context code generators *)
let init_context_codegens () =
  (* This will be called by the individual modules *)
  ()

(** Generate field access for a context type *)
let generate_context_field_access ctx_type ctx_var field_name =
  match get_context_codegen ctx_type with
  | Some codegen -> codegen.generate_field_access ctx_var field_name
  | None -> failwith ("Unknown context type: " ^ ctx_type)

(** Get context-specific includes *)
let get_context_includes ctx_type =
  match get_context_codegen ctx_type with
  | Some codegen -> codegen.generate_includes ()
  | None -> [] 