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

(** TC (Traffic Control) specific code generation
    This module handles code generation for TC programs
*)

open Printf
open Context_codegen

(** TC field mappings from KernelScript to kernel struct __sk_buff *)
let tc_field_mappings = [
  ("data", {
    field_name = "data";
    c_expression = (fun ctx_var -> sprintf "(__u64)(long)%s->data" ctx_var);
    requires_cast = true;
    field_type = "__u64";
  });
  
  ("data_end", {
    field_name = "data_end";
    c_expression = (fun ctx_var -> sprintf "(__u64)(long)%s->data_end" ctx_var);
    requires_cast = true;
    field_type = "__u64";
  });
  
  ("len", {
    field_name = "len";
    c_expression = (fun ctx_var -> sprintf "%s->len" ctx_var);
    requires_cast = false;
    field_type = "__u32";
  });
  
  ("ifindex", {
    field_name = "ifindex";
    c_expression = (fun ctx_var -> sprintf "%s->ifindex" ctx_var);
    requires_cast = false;
    field_type = "__u32";
  });
  
  ("protocol", {
    field_name = "protocol";
    c_expression = (fun ctx_var -> sprintf "%s->protocol" ctx_var);
    requires_cast = false;
    field_type = "__u32";
  });
  
  ("mark", {
    field_name = "mark";
    c_expression = (fun ctx_var -> sprintf "%s->mark" ctx_var);
    requires_cast = false;
    field_type = "__u32";
  });
]

(** Generate TC-specific includes *)
let generate_tc_includes () = [
  "#include <linux/bpf.h>";
  "#include <bpf/bpf_helpers.h>";
  "#include <linux/if_ether.h>";
  "#include <linux/ip.h>";
  "#include <linux/in.h>";
  "#include <linux/pkt_cls.h>";
]

(** Generate field access for TC context *)
let generate_tc_field_access ctx_var field_name =
  try
    let (_, field_access) = List.find (fun (name, _) -> name = field_name) tc_field_mappings in
    field_access.c_expression ctx_var
  with Not_found ->
    failwith ("Unknown TC context field: " ^ field_name)

(** Map TC action constants *)
let map_tc_action_constant = function
  | 255 -> Some "TC_ACT_UNSPEC"
  | 0 -> Some "TC_ACT_OK"
  | 1 -> Some "TC_ACT_RECLASSIFY"
  | 2 -> Some "TC_ACT_SHOT"
  | 3 -> Some "TC_ACT_PIPE"
  | 4 -> Some "TC_ACT_STOLEN"
  | 5 -> Some "TC_ACT_QUEUED"
  | 6 -> Some "TC_ACT_REPEAT"
  | 7 -> Some "TC_ACT_REDIRECT"
  | _ -> None

(** Create TC code generator *)
let create () = {
  name = "TC";
  c_type = "struct __sk_buff*";
  section_prefix = "classifier";
  field_mappings = tc_field_mappings;
  generate_includes = generate_tc_includes;
  generate_field_access = generate_tc_field_access;
  map_action_constant = map_tc_action_constant;
}

(** Register this codegen with the context registry *)
let register () =
  let tc_codegen = create () in
  Context_codegen.register_context_codegen "tc" tc_codegen 