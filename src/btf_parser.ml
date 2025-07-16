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
  
  {
    program_type = prog_type;
    context_type = context_type;
    return_type = return_type;
    includes = ["linux/bpf.h"; "linux/pkt_cls.h"; "linux/if_ether.h"; "linux/ip.h"; "linux/tcp.h"; "linux/udp.h"];
    types = all_types;
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
  
  sprintf {|%s
// Generated by KernelScript compiler with direct BTF parsing

%s

@%s
fn %s_handler(ctx: *%s) -> %s {
    // TODO: Implement your %s logic here
    
    return %s
}

fn main() -> i32 {
    var prog = load(%s_handler)
    
    // TODO: Update interface name and attachment parameters
    var result = attach(prog, "eth0", 0)
    
    if (result == 0) {
        print("%s program loaded successfully")
    } else {
        print("Failed to load %s program")
        return 1
    }
    
    return 0
}
|} context_comment type_definitions template.program_type project_name template.context_type template.return_type template.program_type sample_return project_name template.program_type template.program_type