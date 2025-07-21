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

(** BTF Parser - Extract type information from BTF files for KernelScript *)

open Printf

type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
  kernel_defined: bool; (* Mark if this type is kernel-defined *)
}

type program_template = {
  program_type: string;
  context_type: string;
  return_type: string;
  includes: string list;
  types: btf_type_info list;
  function_signatures: (string * string) list; (* Function name and signature for kprobe targets *)
}



(** Check if a type name is a well-known kernel type *)
let is_well_known_kernel_type = Kernel_types.is_well_known_ebpf_type

(** Create hardcoded enum definitions for constants that can't be extracted from BTF *)
let create_hardcoded_tc_action_enum () = {
  name = "tc_action";
  kind = "enum";
  size = Some 4;
  members = Some [
    ("TC_ACT_UNSPEC", "-1");
    ("TC_ACT_OK", "0");
    ("TC_ACT_RECLASSIFY", "1");
    ("TC_ACT_SHOT", "2");
    ("TC_ACT_PIPE", "3");
    ("TC_ACT_STOLEN", "4");
    ("TC_ACT_QUEUED", "5");
    ("TC_ACT_REPEAT", "6");
    ("TC_ACT_REDIRECT", "7");
    ("TC_ACT_TRAP", "8");
  ];
  kernel_defined = true;
}

(** Get program template based on eBPF program type *)
let rec get_program_template prog_type btf_path = 
  let (context_type, return_type, common_types) = match prog_type with
    | "xdp" -> ("xdp_md", "xdp_action", [
        "xdp_md"; "xdp_action"
      ])
    | "tc" -> ("__sk_buff", "i32", [
        "__sk_buff"
      ])
    | "kprobe" -> ("pt_regs", "i32", [
        "pt_regs"
      ])
    | "uprobe" -> ("pt_regs", "i32", [
        "pt_regs"
      ])
    | "tracepoint" -> ("trace_entry", "i32", [
        "trace_entry"
      ])
    | "lsm" -> ("task_struct", "i32", [
        "task_struct"; "file"; "inode"
      ])
    | "cgroup_skb" -> ("__sk_buff", "i32", [
        "__sk_buff"
      ])
    | _ -> ("GenericContext", "i32", [])
  in
  
  (* Extract types from BTF - BTF file is required *)
  let extracted_types = match btf_path with
    | Some path when Sys.file_exists path -> extract_types_from_btf path common_types
    | Some path -> failwith (sprintf "BTF file not found: %s" path)
    | None -> failwith "BTF file path is required. Use --btf-vmlinux-path option."
  in
  
  let final_types = extracted_types in
  
  (* No need to filter types since builtin files were removed *)
  let filtered_types = final_types in
  
  (* Add hardcoded enum definitions for macro constants that can't be extracted from BTF *)
  let hardcoded_types = match prog_type with
    | "tc" -> [create_hardcoded_tc_action_enum ()]
    | _ -> []
  in
  
  let all_types = filtered_types @ hardcoded_types in
  
  (* No function signatures for generic program templates - kprobe uses specific template *)
  let function_signatures = [] in
  
  {
    program_type = prog_type;
    context_type = context_type;
    return_type = return_type;
    includes = ["linux/bpf.h"; "linux/pkt_cls.h"; "linux/if_ether.h"; "linux/ip.h"; "linux/tcp.h"; "linux/udp.h"];
    types = all_types;
    function_signatures = function_signatures;
  }

(** Extract specific types from BTF file using binary parser *)
and extract_types_from_btf btf_path type_names =
  try
    printf "Extracting types from BTF file: %s\n" btf_path;
    let binary_types = Btf_binary_parser.parse_btf_file btf_path type_names in
    
    (* Convert binary parser types to btf_type_info *)
    let converted_types = List.map (fun bt ->
      {
        name = bt.Btf_binary_parser.name;
        kind = bt.Btf_binary_parser.kind;
        size = bt.Btf_binary_parser.size;
        members = bt.Btf_binary_parser.members;
        kernel_defined = is_well_known_kernel_type bt.Btf_binary_parser.name;
      }
    ) binary_types in
    
    if List.length converted_types > 0 then (
      printf "Successfully extracted %d types from BTF\n" (List.length converted_types);
      converted_types
    ) else (
      failwith "No types extracted from BTF - requested types not found"
    )
  with
  | exn ->
      failwith (sprintf "BTF extraction failed: %s" (Printexc.to_string exn))

(** Get kprobe program template for a specific target function *)
let get_kprobe_program_template target_function btf_path =
  let context_type = "*pt_regs" in
      let return_type = "i32" in
  
  (* For kprobe, we don't need to extract pt_regs since we're hiding it from users *)
  let extracted_types = [] in
  
  (* Extract specific function signature for the target *)
  let function_signatures = match btf_path with
    | Some path when Sys.file_exists path ->
        printf "🔧 Extracting function signature for %s...\n" target_function;
        let signatures = Btf_binary_parser.extract_kernel_function_signatures path [target_function] in
        if signatures = [] then
          printf "⚠️ Function '%s' not found in BTF - proceeding without signature\n" target_function
        else
          printf "✅ Extracted signature for %s\n" target_function;
        signatures
    | _ -> []
  in
  
  {
    program_type = "kprobe";
    context_type = context_type;
    return_type = return_type;
    includes = ["linux/bpf.h"; "linux/pkt_cls.h"; "linux/if_ether.h"; "linux/ip.h"; "linux/tcp.h"; "linux/udp.h"];
    types = extracted_types;
    function_signatures = function_signatures;
  }

(** Extract struct_ops definitions from BTF and generate KernelScript code *)
let extract_struct_ops_definitions btf_path struct_ops_names =
  match btf_path with
  | Some path when Sys.file_exists path ->
      printf "🔧 Extracting struct_ops definitions: %s\n" (String.concat ", " struct_ops_names);
      Struct_ops_registry.extract_struct_ops_from_btf path struct_ops_names
  | Some path ->
      failwith (sprintf "BTF file not found: %s" path)
  | None ->
      failwith "BTF file path is required for struct_ops extraction. Use --btf-vmlinux-path option."

(** Generate struct_ops template with BTF extraction *)
let generate_struct_ops_template btf_path struct_ops_names project_name =
  let struct_ops_definitions = extract_struct_ops_definitions btf_path struct_ops_names in
  let struct_ops_code = String.concat "\n\n" struct_ops_definitions in
  
  let example_usage = List.map (fun name ->
    Struct_ops_registry.generate_struct_ops_usage_example name
  ) struct_ops_names |> String.concat "\n\n" in
  
  sprintf {|// Generated struct_ops template for %s
// Extracted from BTF: %s

%s

%s

fn main() -> i32 {
    // TODO: Initialize and register your struct_ops
    print("struct_ops template generated for %s")
    return 0
}|} project_name 
    (match btf_path with 
     | Some path -> sprintf "definitions from %s" path 
     | None -> "placeholder definitions")
    struct_ops_code
    example_usage
    project_name

(** Parse BTF function signature to extract parameter information *)
let parse_function_signature signature =
  (* Parse "fn(param1: type1, param2: type2, ...) -> return_type" *)
  try
    if String.length signature < 3 || not (String.sub signature 0 3 = "fn(") then
      failwith "Invalid function signature format"
    else
      let paren_start = 3 in
      let paren_end = String.index signature ')' in
      let params_str = String.sub signature paren_start (paren_end - paren_start) in
      
      (* Parse return type *)
      let arrow_pos = try Some (String.index signature '>') with Not_found -> None in
      let return_type = match arrow_pos with
        | Some pos when pos > paren_end + 2 ->
            String.trim (String.sub signature (pos + 1) (String.length signature - pos - 1))
        | _ -> "i32"  (* Default return type for kprobe *)
      in
      
      (* Parse parameters *)
      let params = if String.trim params_str = "" then
        []
      else
        let param_list = String.split_on_char ',' params_str in
        List.map (fun param_str ->
          let trimmed = String.trim param_str in
          let colon_pos = String.index trimmed ':' in
          let param_name = String.trim (String.sub trimmed 0 colon_pos) in
          let param_type = String.trim (String.sub trimmed (colon_pos + 1) (String.length trimmed - colon_pos - 1)) in
          (param_name, param_type)
        ) param_list
      in
      
      (params, return_type)
  with
  | exn ->
      printf "⚠️ Warning: Failed to parse function signature '%s': %s\n" signature (Printexc.to_string exn);
      ([], "i32")  (* Fallback *)

(** Generate kprobe function definition from BTF signature *)
let generate_kprobe_function_from_signature func_name signature =
  let (params, return_type) = parse_function_signature signature in
  let params_str = if params = [] then
    ""
  else
    String.concat ", " (List.map (fun (name, typ) -> sprintf "%s: %s" name typ) params)
  in
  sprintf "fn %s(%s) -> %s" func_name params_str return_type

(** Generate KernelScript source code from template *)
let generate_kernelscript_source template project_name =
  let context_comment = match template.program_type with
    | "xdp" -> "// XDP (eXpress Data Path) program for high-performance packet processing"
    | "tc" -> "// TC (Traffic Control) program for network traffic shaping and filtering"
    | "kprobe" -> "// Kprobe program for dynamic kernel tracing"
    | "uprobe" -> "// Uprobe program for userspace function tracing"
    | "tracepoint" -> "// Tracepoint program for static kernel tracing"
    | "lsm" -> "// LSM (Linux Security Module) program for security enforcement"
    | "cgroup_skb" -> "// Cgroup SKB program for cgroup-based packet filtering"
    | _ -> "// eBPF program"
  in
  
  let return_values = match template.program_type with
    | "xdp" -> ["XDP_ABORTED"; "XDP_DROP"; "XDP_PASS"; "XDP_TX"; "XDP_REDIRECT"]
    | "tc" -> ["TC_ACT_OK"; "TC_ACT_SHOT"; "TC_ACT_STOLEN"; "TC_ACT_PIPE"; "TC_ACT_REDIRECT"]
    | _ -> ["0"; "-1"]
  in
  
  let type_definitions = String.concat "\n\n" (List.map (fun type_info ->
    match type_info.kind with
    | "struct" ->
        (match type_info.members with
         | Some members ->
             let member_strings = List.map (fun (name, typ) ->
               sprintf "    %s: %s," name typ
             ) members in
             sprintf "struct %s {\n%s\n}" type_info.name (String.concat "\n" member_strings)
         | None ->
             sprintf "// %s type (placeholder)" type_info.name)
    | "enum" ->
        (match type_info.members with
         | Some members ->
             let member_strings = List.map (fun (name, value) ->
               sprintf "    %s = %s," name value
             ) members in
             sprintf "enum %s {\n%s\n}" type_info.name (String.concat "\n" member_strings)
         | None ->
             sprintf "// %s enum (placeholder)" type_info.name)
    | _ ->
        sprintf "// %s %s (placeholder)" type_info.kind type_info.name
  ) template.types) in
  
  let sample_return = match return_values with
    | first :: _ -> first
    | [] -> "0"
  in
  
  (* Generate function signature comments and actual function definition for kprobe programs *)
  let (function_signatures_comment, target_function_name, function_definition) = 
    if template.program_type = "kprobe" && template.function_signatures <> [] then
      let signature_lines = List.map (fun (func_name, signature) ->
        sprintf "// Target function: %s -> %s" func_name signature
      ) template.function_signatures in
      let comment = sprintf "\n// Target kernel function signature:\n%s\n" 
        (String.concat "\n" signature_lines) in
      let first_func, first_sig = match template.function_signatures with
        | (name, sig_str) :: _ -> (name, sig_str)
        | [] -> ("target_function", "fn() -> i32")
      in
      let func_def = generate_kprobe_function_from_signature first_func first_sig in
      (comment, first_func, func_def)
    else 
      ("", "target_function", sprintf "fn %s_handler(ctx: %s) -> %s" project_name template.context_type template.return_type)
  in
  
  (* Customize attach call for kprobe *)
  let attach_target = if template.program_type = "kprobe" then target_function_name else "eth0" in
  let attach_comment = if template.program_type = "kprobe" then 
    "    // Attach kprobe to target kernel function"
  else 
    "    // TODO: Update interface name and attachment parameters"
  in
  
  let function_name = if template.program_type = "kprobe" then target_function_name else sprintf "%s_handler" project_name in
  
  sprintf {|%s
// Generated by KernelScript compiler with direct BTF parsing
%s
%s

@%s
%s {
    // TODO: Implement your %s logic here
    
    return %s
}

fn main() -> i32 {
    var prog = load(%s)
    
%s
    var result = attach(prog, "%s", 0)
    
    if (result == 0) {
        print("%s program loaded successfully")
    } else {
        print("Failed to load %s program")
        return 1
    }
    
    return 0
}
|} context_comment function_signatures_comment type_definitions template.program_type function_definition template.program_type sample_return function_name attach_comment attach_target template.program_type template.program_type