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

(** Context Code Generation Interface
    This module defines the interface for context-specific code generators
*)

type context_field_access = {
  field_name: string;
  c_expression: string -> string; (* ctx_var -> C expression *)
  requires_cast: bool;
  field_type: string; (* C type of the field *)
}

(** BTF type information for context codegen *)
type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
  kernel_defined: bool;
}

type context_codegen = {
  name: string;
  c_type: string;
  section_prefix: string;
  field_mappings: (string * context_field_access) list;
  generate_includes: unit -> string list;
  generate_field_access: string -> string -> string; (* ctx_var -> field_name -> C expression *)
  map_action_constant: int -> string option; (* Map integer to action constant *)
  generate_function_signature: (string -> (string * string) list -> string -> string) option; (* func_name -> parameters -> return_type -> signature *)
  generate_section_name: (string option -> string) option; (* Optional function to generate SEC(...) attribute with target *)
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

(** Generate custom function signature for a context type *)
let generate_context_function_signature ctx_type func_name parameters return_type =
  match get_context_codegen ctx_type with
  | Some codegen ->
      (match codegen.generate_function_signature with
      | Some gen_func -> Some (gen_func func_name parameters return_type)
      | None -> None)
  | None -> None

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

(** Create context field access from BTF field information *)
let create_btf_field_access field_name field_type =
  (* Determine if casting is needed based on field type *)
  let requires_cast = 
    String.contains field_type '*' || 
    (String.contains field_type 'u' && String.contains field_type '6') (* __u64 *)
  in
  
  let c_expression = fun ctx_var ->
    if requires_cast then
      Printf.sprintf "(%s)(long)%s->%s" field_type ctx_var field_name
    else
      Printf.sprintf "%s->%s" ctx_var field_name
  in
  
  {
    field_name;
    c_expression;
    requires_cast;
    field_type;
  }

(** Create context codegen from BTF type information *)
let create_context_codegen_from_btf ctx_type_name btf_type_info =
  let field_mappings = match btf_type_info.members with
    | Some members ->
        List.map (fun (field_name, field_type) ->
          (field_name, create_btf_field_access field_name field_type)
        ) members
    | None -> []
  in
  
  let generate_field_access ctx_var field_name =
    try
      let (_, field_access) = List.find (fun (name, _) -> name = field_name) field_mappings in
      field_access.c_expression ctx_var
    with Not_found ->
      failwith ("Unknown BTF context field: " ^ field_name ^ " for type: " ^ ctx_type_name)
  in
  
  let generate_includes () = 
    (* Generate appropriate includes based on context type *)
    match ctx_type_name with
    | "xdp" -> [
        "#include <linux/bpf.h>";
        "#include <bpf/bpf_helpers.h>";
        "#include <linux/if_ether.h>";
        "#include <linux/ip.h>";
        "#include <linux/in.h>";
        "#include <linux/if_xdp.h>";
      ]
    | "tc" -> [
        "#include <linux/bpf.h>";
        "#include <bpf/bpf_helpers.h>";
        "#include <linux/if_ether.h>";
        "#include <linux/ip.h>";
        "#include <linux/in.h>";
        "#include <linux/pkt_cls.h>";
      ]
    | _ -> [
        "#include <linux/bpf.h>";
        "#include <bpf/bpf_helpers.h>";
      ]
  in
  
  let map_action_constant = match ctx_type_name with
    | "xdp" -> (function
        | 0 -> Some "XDP_ABORTED"
        | 1 -> Some "XDP_DROP"
        | 2 -> Some "XDP_PASS"
        | 3 -> Some "XDP_REDIRECT"
        | 4 -> Some "XDP_TX"
        | _ -> None)
    | "tc" -> (function
        | 255 -> Some "TC_ACT_UNSPEC"
        | 0 -> Some "TC_ACT_OK"
        | 1 -> Some "TC_ACT_RECLASSIFY"
        | 2 -> Some "TC_ACT_SHOT"
        | 3 -> Some "TC_ACT_PIPE"
        | 4 -> Some "TC_ACT_STOLEN"
        | 5 -> Some "TC_ACT_QUEUED"
        | 6 -> Some "TC_ACT_REPEAT"
        | 7 -> Some "TC_ACT_REDIRECT"
        | _ -> None)
    | _ -> (fun _ -> None)
  in
  
  let c_type = match ctx_type_name with
    | "xdp" -> "struct xdp_md*"
    | "tc" -> "struct __sk_buff*"
    | _ -> Printf.sprintf "struct %s*" btf_type_info.name
  in
  
  let section_prefix = match ctx_type_name with
    | "xdp" -> "xdp"
    | "tc" -> "classifier"
    | _ -> ctx_type_name
  in
  
  {
    name = Printf.sprintf "%s (BTF)" ctx_type_name;
    c_type;
    section_prefix;
    field_mappings;
    generate_includes;
    generate_field_access;
    map_action_constant;
    generate_function_signature = None;
    generate_section_name = None;
  }

(** Register context codegen from BTF type information *)
let register_btf_context_codegen ctx_type_name btf_type_info =
  let codegen = create_context_codegen_from_btf ctx_type_name btf_type_info in
  register_context_codegen ctx_type_name codegen;
  Printf.printf "🔧 Registered BTF-based context codegen for %s with %d fields\n" 
    ctx_type_name (List.length codegen.field_mappings)

(** Update context codegen with BTF information if available *)
let update_context_codegen_with_btf ctx_type_name btf_type_info =
  match get_context_codegen ctx_type_name with
  | Some existing_codegen ->
      (* Merge BTF fields with existing hardcoded fields *)
      let btf_fields = match btf_type_info.members with
        | Some members ->
            List.map (fun (field_name, field_type) ->
              (field_name, create_btf_field_access field_name field_type)
            ) members
        | None -> []
      in
      
      (* Combine existing and BTF fields, with BTF fields taking precedence *)
      let existing_field_names = List.map fst existing_codegen.field_mappings in
      let btf_only_fields = List.filter (fun (name, _) -> 
        not (List.mem name existing_field_names)
      ) btf_fields in
      let combined_fields = existing_codegen.field_mappings @ btf_only_fields in
      
      let updated_codegen = {
        existing_codegen with
        field_mappings = combined_fields;
        name = Printf.sprintf "%s (BTF-enhanced)" ctx_type_name;
      } in
      
      register_context_codegen ctx_type_name updated_codegen;
      Printf.printf "🔧 Enhanced context codegen for %s with %d additional BTF fields\n" 
        ctx_type_name (List.length btf_only_fields)
  | None ->
      (* No existing codegen, create new one from BTF *)
      register_btf_context_codegen ctx_type_name btf_type_info

(** Generate section name for a context type with optional direction *)
let generate_context_section_name ctx_type direction =
  match get_context_codegen ctx_type with
  | Some codegen -> 
      (match codegen.generate_section_name with
       | Some section_fn -> Some (section_fn direction)
       | None -> None)
  | None -> None 