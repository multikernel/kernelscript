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

(** XDP-specific code generation
    This module handles code generation for XDP (eXpress Data Path) programs
*)

open Printf
open Context_codegen

(** XDP field mappings from KernelScript to kernel struct xdp_md *)
let xdp_field_mappings = [
  ("data", {
    field_name = "data";
    c_expression = (fun ctx_var -> sprintf "(void*)(long)%s->data" ctx_var);
    requires_cast = true;
    field_type = "__u8*";
  });
  
  ("data_end", {
    field_name = "data_end";
    c_expression = (fun ctx_var -> sprintf "(void*)(long)%s->data_end" ctx_var);
    requires_cast = true;
    field_type = "__u8*";
  });
  
  ("data_meta", {
    field_name = "data_meta";
    c_expression = (fun ctx_var -> sprintf "(void*)(long)%s->data_meta" ctx_var);
    requires_cast = true;
    field_type = "__u8*";
  });
  
  ("ingress_ifindex", {
    field_name = "ingress_ifindex";
    c_expression = (fun ctx_var -> sprintf "%s->ingress_ifindex" ctx_var);
    requires_cast = false;
    field_type = "__u32";
  });
  
  ("rx_queue_index", {
    field_name = "rx_queue_index";
    c_expression = (fun ctx_var -> sprintf "%s->rx_queue_index" ctx_var);
    requires_cast = false;
    field_type = "__u32";
  });
  
  ("egress_ifindex", {
    field_name = "egress_ifindex";
    c_expression = (fun ctx_var -> sprintf "%s->egress_ifindex" ctx_var);
    requires_cast = false;
    field_type = "__u32";
  });
]

(** Generate XDP-specific includes *)
let generate_xdp_includes () = [
  "#include <linux/bpf.h>";
  "#include <bpf/bpf_helpers.h>";
  "#include <linux/if_ether.h>";
  "#include <linux/ip.h>";
  "#include <linux/in.h>";
  "#include <linux/if_xdp.h>";
]

(** Generate field access for XDP context *)
let generate_xdp_field_access ctx_var field_name =
  try
    let (_, field_access) = List.find (fun (name, _) -> name = field_name) xdp_field_mappings in
    field_access.c_expression ctx_var
  with Not_found ->
    failwith ("Unknown XDP context field: " ^ field_name)

(** Map XDP action constants *)
let map_xdp_action_constant = function
  | 0 -> Some "XDP_ABORTED"
  | 1 -> Some "XDP_DROP"
  | 2 -> Some "XDP_PASS"
  | 3 -> Some "XDP_REDIRECT"
  | 4 -> Some "XDP_TX"
  | _ -> None

(** Create XDP code generator *)
let create () = {
  name = "XDP";
  c_type = "struct xdp_md*";
  section_prefix = "xdp";
  field_mappings = xdp_field_mappings;
  generate_includes = generate_xdp_includes;
  generate_field_access = generate_xdp_field_access;
  map_action_constant = map_xdp_action_constant;
}

(** Register this codegen with the context registry *)
let register () =
  let xdp_codegen = create () in
  Context_codegen.register_context_codegen "xdp" xdp_codegen

(** Helper function to get packet data bounds *)
let generate_packet_bounds_check ctx_var =
  sprintf "void *data = (void*)(long)%s->data;\n    void *data_end = (void*)(long)%s->data_end;" ctx_var ctx_var

(** Helper function for packet parsing *)
let generate_eth_header_access _ctx_var =
  sprintf "struct ethhdr *eth = (struct ethhdr *)data;\n    if (eth + 1 > data_end) return XDP_DROP;" 