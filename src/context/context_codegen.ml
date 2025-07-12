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
  map_action_constant: int -> string option; (* Map integer to action constant *)
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



(** Map action constant for a context type *)
let map_context_action_constant ctx_type action_value =
  match get_context_codegen ctx_type with
  | Some codegen -> codegen.map_action_constant action_value
  | None -> None

(** Get all action constants for a context type as (name, value) pairs *)
let get_context_action_constants ctx_type =
  match get_context_codegen ctx_type with
  | Some codegen ->
      (* Generate constants by testing integer values *)
      let rec collect_constants acc value =
        if value > 10 then acc  (* Reasonable limit *)
        else
          match codegen.map_action_constant value with
          | Some name -> collect_constants ((name, value) :: acc) (value + 1)
          | None -> collect_constants acc (value + 1)
      in
      List.rev (collect_constants [] 0)
  | None -> []

(** Get struct field definitions for a context type as (name, c_type) pairs *)
let get_context_struct_fields ctx_type =
  match get_context_codegen ctx_type with
  | Some codegen ->
      List.map (fun (field_name, field_access) ->
        (field_name, field_access.field_type)
      ) codegen.field_mappings
  | None -> [] 

(** Get the C type string for a context field *)
let get_context_field_c_type ctx_type field_name =
  match get_context_codegen ctx_type with
  | Some codegen ->
      (try
        let (_, field_access) = List.find (fun (name, _) -> name = field_name) codegen.field_mappings in
        Some field_access.field_type
      with Not_found -> None)
  | None -> None 