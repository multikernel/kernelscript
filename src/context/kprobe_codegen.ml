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

(** Kprobe-specific code generation
    This module handles code generation for kprobe programs
*)

open Printf
open Context_codegen

(** Kprobe field mappings from KernelScript to kernel struct pt_regs *)
let kprobe_field_mappings = [
  ("regs", {
    field_name = "regs";
    c_expression = (fun ctx_var -> sprintf "%s" ctx_var);
    requires_cast = false;
    field_type = "struct pt_regs*";
  });
  
  ("ip", {
    field_name = "ip";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_IP(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("sp", {
    field_name = "sp";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_SP(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("ax", {
    field_name = "ax";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_PARM1(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("bx", {
    field_name = "bx";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_PARM2(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("cx", {
    field_name = "cx";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_PARM3(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("dx", {
    field_name = "dx";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_PARM4(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("si", {
    field_name = "si";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_PARM5(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("di", {
    field_name = "di";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_PARM6(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
  
  ("ret", {
    field_name = "ret";
    c_expression = (fun ctx_var -> sprintf "PT_REGS_RC(%s)" ctx_var);
    requires_cast = false;
    field_type = "unsigned long";
  });
]

(** Generate kprobe-specific includes *)
let generate_kprobe_includes () = [
  "#include <linux/bpf.h>";
  "#include <bpf/bpf_helpers.h>";
  "#include <linux/ptrace.h>";
  "#include <bpf/bpf_tracing.h>";
]

(** Generate field access for kprobe context *)
let generate_kprobe_field_access ctx_var field_name =
  try
    let (_, field_access) = List.find (fun (name, _) -> name = field_name) kprobe_field_mappings in
    field_access.c_expression ctx_var
  with Not_found ->
    failwith ("Unknown kprobe context field: " ^ field_name)

(** Map kprobe return constants *)
let map_kprobe_action_constant = function
  | 0 -> Some "0"  (* Continue execution *)
  | -1 -> Some "-1"  (* Error *)
  | _ -> None

(** Create kprobe code generator *)
let create () = {
  name = "Kprobe";
  c_type = "struct pt_regs*";
  section_prefix = "kprobe";
  field_mappings = kprobe_field_mappings;
  generate_includes = generate_kprobe_includes;
  generate_field_access = generate_kprobe_field_access;
  map_action_constant = map_kprobe_action_constant;
}

(** Register this codegen with the context registry *)
let register () =
  let kprobe_codegen = create () in
  Context_codegen.register_context_codegen "kprobe" kprobe_codegen

(** Helper function to get function arguments from pt_regs *)
let generate_function_args_access ctx_var arg_count =
  let arg_macros = [
    "PT_REGS_PARM1";
    "PT_REGS_PARM2"; 
    "PT_REGS_PARM3";
    "PT_REGS_PARM4";
    "PT_REGS_PARM5";
    "PT_REGS_PARM6";
  ] in
  let rec build_args acc i =
    if i >= arg_count || i >= List.length arg_macros then
      List.rev acc
    else
      let arg_macro = List.nth arg_macros i in
      let arg_access = sprintf "%s(%s)" arg_macro ctx_var in
      build_args (arg_access :: acc) (i + 1)
  in
  build_args [] 0

(** Helper function for getting return value *)
let generate_return_value_access ctx_var =
  sprintf "PT_REGS_RC(%s)" ctx_var 