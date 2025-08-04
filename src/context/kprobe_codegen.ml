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

(** Dynamic kprobe parameter mappings - populated during compilation based on function signature *)
let kprobe_parameter_mappings = ref []

(** Register kprobe parameter mappings for a specific function *)
let register_kprobe_parameter_mappings func_name parameters =
  let param_mappings = List.mapi (fun i (param_name, param_type) ->
    let parm_macro = match i with
      | 0 -> "PT_REGS_PARM1"
      | 1 -> "PT_REGS_PARM2" 
      | 2 -> "PT_REGS_PARM3"
      | 3 -> "PT_REGS_PARM4"
      | 4 -> "PT_REGS_PARM5"
      | 5 -> "PT_REGS_PARM6"
      | _ -> failwith (sprintf "Too many parameters for kprobe function %s (max 6)" func_name)
    in
    (param_name, {
      field_name = param_name;
      c_expression = (fun ctx_var -> sprintf "%s(%s)" parm_macro ctx_var);
      requires_cast = false;
      field_type = param_type;
    })
  ) parameters in
  kprobe_parameter_mappings := param_mappings

(** Clear kprobe parameter mappings *)
let clear_kprobe_parameter_mappings () =
  kprobe_parameter_mappings := []

(** Generate kprobe-specific includes with architecture definition at the top *)
let generate_kprobe_includes () = [
  "/* Target architecture definition required for PT_REGS_PARM* macros */";
  "#ifndef __TARGET_ARCH_x86";
  "#define __TARGET_ARCH_x86";
  "#endif";
  "";
  "#include <bpf/bpf_tracing.h>";
]

(** Generate field access for kprobe context *)
let generate_kprobe_field_access ctx_var field_name =
  try
    (* Use dynamic parameter mappings based on kernel function signature *)
    let (_, field_access) = List.find (fun (name, _) -> name = field_name) !kprobe_parameter_mappings in
    field_access.c_expression ctx_var
  with Not_found ->
    failwith ("Unknown kprobe parameter: " ^ field_name ^ ". Make sure the kernel function signature is properly extracted from BTF.")

(** Map kprobe return constants *)
let map_kprobe_action_constant = function
  | 0 -> Some "0"  (* Continue execution *)
  | -1 -> Some "-1"  (* Error *)
  | _ -> None

(** Generate kprobe section name with target function *)
let generate_kprobe_section_name target =
  match target with
  | Some func_name -> sprintf "SEC(\"kprobe/%s\")" func_name
  | None -> "SEC(\"kprobe\")" (* Fallback for cases without target *)

(** Create kprobe code generator *)
let create () = {
  name = "Kprobe";
  c_type = "struct pt_regs*";
  section_prefix = "kprobe";
  field_mappings = []; (* No static field mappings - use dynamic parameter mappings *)
  generate_includes = generate_kprobe_includes;
  generate_field_access = generate_kprobe_field_access;
  map_action_constant = map_kprobe_action_constant;
  generate_function_signature = None;
  generate_section_name = Some generate_kprobe_section_name;
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