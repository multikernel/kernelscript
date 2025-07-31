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

(** Tracepoint-specific code generation
    This module handles code generation for tracepoint programs
*)

open Printf
open Context_codegen

(** Dynamic tracepoint parameter mappings - populated during compilation based on tracepoint signature *)
let tracepoint_parameter_mappings = ref []

(** Dynamic tracepoint context type - populated during compilation based on tracepoint event *)
let tracepoint_context_type = ref "void*"

(** Register tracepoint parameter mappings for a specific event *)
let register_tracepoint_parameter_mappings _event_name parameters context_type =
  (* Store the context type for later use *)
  tracepoint_context_type := context_type;
  
  let param_mappings = List.map (fun (param_name, param_type) ->
    (param_name, {
      field_name = param_name;
      c_expression = (fun ctx_var -> sprintf "%s->%s" ctx_var param_name);
      requires_cast = false;
      field_type = param_type;
    })
  ) parameters in
  tracepoint_parameter_mappings := param_mappings

(** Clear tracepoint parameter mappings *)
let clear_tracepoint_parameter_mappings () =
  tracepoint_parameter_mappings := [];
  tracepoint_context_type := "void*"

(** Generate tracepoint-specific includes *)
let generate_tracepoint_includes () = [
  "#include <linux/types.h>";
  "#include <bpf/bpf_helpers.h>";
  "#include <bpf/bpf_tracing.h>";
  "#include <linux/trace_events.h>";
]

(** Generate field access for tracepoint context *)
let generate_tracepoint_field_access ctx_var field_name =
  try
    (* Use dynamic parameter mappings based on tracepoint event signature *)
    let (_, field_access) = List.find (fun (name, _) -> name = field_name) !tracepoint_parameter_mappings in
    field_access.c_expression ctx_var
  with Not_found ->
    failwith ("Unknown tracepoint field: " ^ field_name ^ ". Make sure the tracepoint event structure is properly extracted from BTF.")

(** Map tracepoint return constants *)
let map_tracepoint_action_constant = function
  | 0 -> Some "0"  (* Continue execution *)
  | -1 -> Some "-1"  (* Error *)
  | _ -> None

(** Create tracepoint code generator *)
let create () = {
  name = "Tracepoint";
  c_type = !tracepoint_context_type;
  section_prefix = "tracepoint";
  field_mappings = []; (* No static field mappings - use dynamic parameter mappings *)
  generate_includes = generate_tracepoint_includes;
  generate_field_access = generate_tracepoint_field_access;
  map_action_constant = map_tracepoint_action_constant;
}

(** Register this codegen with the context registry *)
let register () =
  let tracepoint_codegen = create () in
  Context_codegen.register_context_codegen "tracepoint" tracepoint_codegen 