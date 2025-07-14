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

(** Context Code Generation Interface *)

type context_field_access = {
  field_name: string;
  c_expression: string -> string;
  requires_cast: bool;
  field_type: string;
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
  generate_field_access: string -> string -> string;
  map_action_constant: int -> string option;
}

(** Register a context code generator *)
val register_context_codegen : string -> context_codegen -> unit

(** Get a context code generator by type *)
val get_context_codegen : string -> context_codegen option

(** Initialize all context code generators *)
val init_context_codegens : unit -> unit

(** Generate field access for a context type *)
val generate_context_field_access : string -> string -> string -> string

(** Get context-specific includes *)
val get_context_includes : string -> string list

(** Map action constant for a context type *)
val map_context_action_constant : string -> int -> string option

(** Get all action constants for a context type *)
val get_context_action_constants : string -> (string * int) list

(** Get struct field definitions for a context type *)
val get_context_struct_fields : string -> (string * string) list

(** Get the C type string for a context field *)
val get_context_field_c_type : string -> string -> string option

(** BTF integration functions *)

(** Register context codegen from BTF type information *)
val register_btf_context_codegen : string -> btf_type_info -> unit

(** Update context codegen with BTF information if available *)
val update_context_codegen_with_btf : string -> btf_type_info -> unit 