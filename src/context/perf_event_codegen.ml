(*
 * Copyright 2026 Siyuan Sun
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

(** perf_event-specific code generation
    Handles SEC("perf_event") programs with bpf_perf_event_data context.
*)

open Printf
open Context_codegen

(** Generate perf_event-specific includes *)
let generate_perf_event_includes () = [
  "#include <bpf/bpf_helpers.h>";
  "#include <bpf/bpf_tracing.h>";
]

(** Field access for bpf_perf_event_data context.
    Phase 1 supports a minimal set of fields.
    Full field access is added in Phase 3 (perf_event_codegen expansion). *)
let generate_perf_event_field_access ctx_var field_name =
  match field_name with
  | "sample_period" -> sprintf "%s->sample_period" ctx_var
  | "addr"          -> sprintf "%s->addr" ctx_var
  | "cpu"           -> sprintf "bpf_get_smp_processor_id()"
  | _ ->
      failwith (sprintf "Unknown perf_event context field: %s. \
        Supported fields in Phase 1: sample_period, addr, cpu." field_name)

(** perf_event programs always return 0 or 1 – no named action constants *)
let map_perf_event_action_constant = function
  | 0 -> Some "0"
  | _ -> None

(** Generate SEC("perf_event") attribute *)
let generate_perf_event_section_name _target =
  "SEC(\"perf_event\")"

(** Static field mapping table (minimal Phase 1 set) *)
let perf_event_field_mappings = [
  ("sample_period", {
    field_name = "sample_period";
    c_expression = (fun ctx_var -> sprintf "%s->sample_period" ctx_var);
    requires_cast = false;
    field_type = "__u64";
  });
  ("addr", {
    field_name = "addr";
    c_expression = (fun ctx_var -> sprintf "%s->addr" ctx_var);
    requires_cast = false;
    field_type = "__u64";
  });
]

(** Create perf_event code generator *)
let create () = {
  name = "PerfEvent";
  c_type = "struct bpf_perf_event_data";
  section_prefix = "perf_event";
  field_mappings = perf_event_field_mappings;
  generate_includes = generate_perf_event_includes;
  generate_field_access = generate_perf_event_field_access;
  map_action_constant = map_perf_event_action_constant;
  generate_function_signature = None;
  generate_section_name = Some generate_perf_event_section_name;
}

(** Register this codegen with the context registry *)
let register () =
  let codegen = create () in
  Context_codegen.register_context_codegen "perf_event" codegen
