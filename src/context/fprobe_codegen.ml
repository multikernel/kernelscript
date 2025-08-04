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

(** Fprobe-specific code generation
    This module handles code generation for fentry/fexit probe programs
*)

open Printf
open Context_codegen

(** Generate fprobe-specific includes with BPF tracing support *)
let generate_fprobe_includes () = [
  "#include <bpf/bpf_tracing.h>";
]

(** Generate field access for fprobe context - fprobe uses direct parameters, no context struct *)
let generate_fprobe_field_access _ctx_var field_name =
  (* Fprobe functions use direct parameters, so field access is just the parameter name *)
  field_name

(** Generate BPF_PROG() function signature for fentry functions *)
let generate_fprobe_function_signature func_name parameters _return_type =
  let params_str = String.concat ", " (List.map (fun (name, param_type) ->
    (* BPF_PROG() expects standard C types like "void *buf" or "int fd" *)
    sprintf "%s %s" param_type name
  ) parameters) in
  sprintf "int BPF_PROG(%s, %s)" func_name params_str

(** Map fprobe return constants *)
let map_fprobe_action_constant = function
  | 0 -> Some "0"  (* Continue execution *)
  | -1 -> Some "-1"  (* Error *)
  | _ -> None

(** Generate fprobe section name with target function *)
let generate_fprobe_section_name target =
  match target with
  | Some func_name -> sprintf "SEC(\"fentry/%s\")" func_name
  | None -> "SEC(\"fentry\")" (* Fallback for cases without target *)

(** Create fprobe code generator *)
let create () = {
  name = "Fprobe";
  c_type = ""; (* Fprobe doesn't use a context struct - uses direct parameters *)
  section_prefix = "fentry";
  field_mappings = []; (* No context field mappings - use direct parameter access *)
  generate_includes = generate_fprobe_includes;
  generate_field_access = generate_fprobe_field_access;
  map_action_constant = map_fprobe_action_constant;
  generate_function_signature = Some generate_fprobe_function_signature;
  generate_section_name = Some generate_fprobe_section_name;
}

(** Register this codegen with the context registry *)
let register () =
  let fprobe_codegen = create () in
  Context_codegen.register_context_codegen "fprobe" fprobe_codegen