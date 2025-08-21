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



(** Cache for BTF-extracted kernel types to avoid re-parsing *)
let kernel_types_cache : (string, string list) Hashtbl.t = Hashtbl.create 16

(** Extract kernel types from BTF file with caching *)
let get_kernel_types_from_btf btf_path =
  match Hashtbl.find_opt kernel_types_cache btf_path with
  | Some cached_types -> cached_types
  | None ->
      let kernel_types = Btf_binary_parser.extract_all_kernel_struct_and_enum_names btf_path in
      Hashtbl.add kernel_types_cache btf_path kernel_types;
      kernel_types

(** Check if a type name is a well-known eBPF kernel type using BTF. *)
let is_well_known_ebpf_type ?btf_path type_name =
  match btf_path with
  | Some path when Sys.file_exists path ->
      let kernel_types = get_kernel_types_from_btf path in
      List.mem type_name kernel_types
  | Some path ->
      failwith (sprintf "BTF file not found: %s" path)
  | None ->
      failwith "BTF file path is required for kernel type detection. Use --btf-vmlinux-path option."

(** Clear the kernel types cache (useful for testing or when BTF file changes) *)
let clear_kernel_types_cache () =
  Hashtbl.clear kernel_types_cache

(** Get all known kernel types for the given BTF file (for debugging/inspection) *)
let get_all_kernel_types ?btf_path () =
  match btf_path with
  | Some path when Sys.file_exists path ->
      get_kernel_types_from_btf path
  | Some path ->
      failwith (sprintf "BTF file not found: %s" path)
  | None ->
      failwith "BTF file path is required for kernel type inspection. Use --btf-vmlinux-path option."

(** Check if a type name is a well-known kernel type (alias for compatibility) *)
let is_well_known_kernel_type ?btf_path = is_well_known_ebpf_type ?btf_path

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
let get_program_template prog_type btf_path = 
  let (context_type, return_type, common_types) = match prog_type with
    | "xdp" -> ("*xdp_md", "xdp_action", [
        "xdp_md"; "xdp_action"
      ])
    | "tc" -> ("*__sk_buff", "i32", [
        "__sk_buff"
      ])
    | _ -> failwith (sprintf "Unsupported program type '%s' for generic template. Use specific template functions for kprobe/tracepoint." prog_type)
  in
  
  (* Extract types from BTF - BTF file is required *)
  let extracted_types = match btf_path with
    | Some path when Sys.file_exists path -> 
        let binary_types = Btf_binary_parser.parse_btf_file path common_types in
        (* Convert binary parser types to btf_type_info *)
        List.map (fun bt -> {
          name = bt.Btf_binary_parser.name;
          kind = bt.Btf_binary_parser.kind;
          size = bt.Btf_binary_parser.size;
          members = bt.Btf_binary_parser.members;
          kernel_defined = is_well_known_ebpf_type ?btf_path bt.Btf_binary_parser.name;
        }) binary_types
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

(** Get tracepoint program template for a specific category/event *)
let get_tracepoint_program_template category_event btf_path =
  (* Parse category and event from the category_event string *)
  let (category, event) = 
    if String.contains category_event '/' then
      let parts = String.split_on_char '/' category_event in
      match parts with
      | [cat; evt] -> (cat, evt)
      | _ -> failwith (sprintf "Invalid tracepoint format '%s'. Use 'category/event'" category_event)
    else
      failwith (sprintf "Invalid tracepoint format '%s'. Use 'category/event'" category_event)
  in
  
  (* Determine typedef_name and raw_name based on the user's logic *)
  let (typedef_name, raw_name) = 
    if category = "syscalls" && String.starts_with event ~prefix:"sys_enter_" then
      ("btf_trace_sys_enter", "trace_event_raw_sys_enter")
    else if category = "syscalls" && String.starts_with event ~prefix:"sys_exit_" then
      ("btf_trace_sys_exit", "trace_event_raw_sys_exit")
    else
      (sprintf "btf_trace_%s" event, sprintf "trace_event_raw_%s" event)
  in
  
  (* Extract the tracepoint structure from BTF *)
  let common_types = [raw_name; typedef_name; "trace_entry"] in
  let extracted_types = match btf_path with
    | Some path when Sys.file_exists path -> 
        let binary_types = Btf_binary_parser.parse_btf_file path common_types in
        (* Convert binary parser types to btf_type_info *)
        List.map (fun bt -> {
          name = bt.Btf_binary_parser.name;
          kind = bt.Btf_binary_parser.kind;
          size = bt.Btf_binary_parser.size;
          members = bt.Btf_binary_parser.members;
          kernel_defined = is_well_known_ebpf_type ?btf_path bt.Btf_binary_parser.name;
        }) binary_types
    | Some path -> failwith (sprintf "BTF file not found: %s" path)
    | None -> failwith "BTF file path is required for tracepoint extraction. Use --btf-vmlinux-path option."
  in
  
  (* Create the context type from the extracted struct *)
  let context_type = sprintf "*%s" raw_name in
  
  {
    program_type = "tracepoint";
    context_type = context_type;
    return_type = "i32";
    includes = ["linux/bpf.h"; "bpf/bpf_helpers.h"; "bpf/bpf_tracing.h"; "linux/trace_events.h"];
    types = extracted_types;
    function_signatures = [(sprintf "%s/%s" category event, sprintf "fn(%s) -> i32" context_type)];
  }

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
    program_type = "probe";
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
let generate_struct_ops_template ?include_kfuncs btf_path struct_ops_names project_name =
  (* Only include struct definitions in main file if no header include *)
  let struct_ops_code = match include_kfuncs with
    | Some _ -> 
        (* With include: struct definitions are in header, main file only has usage examples *)
        ""
    | None ->
        (* Without include: struct definitions go in main file *)
        let struct_ops_definitions = extract_struct_ops_definitions btf_path struct_ops_names in
        String.concat "\n\n" struct_ops_definitions
  in
  
  (* Generate impl block or usage examples based on include *)
  let example_usage = match include_kfuncs with
    | Some _ ->
        (* With include: generate impl block with unique name *)
        List.map (fun name ->
          sprintf {|// Implementation for %s (struct definition in header)
@struct_ops("%s")
impl my_%s {
    // TODO: Implement the required function pointers
    // Example function implementations:
    // fn my_select_cpu(task: *u8, prev_cpu: i32, wake_flags: u64) -> i32 {
    //     // Your CPU selection logic here
    //     return prev_cpu
    // }
    
    // Static field assignments:
    // name: "my_%s",
}|} name name name name
        ) struct_ops_names |> String.concat "\n\n"
    | None ->
        (* Without include: generate usage examples *)
        List.map (fun name ->
          Struct_ops_registry.generate_struct_ops_usage_example name
        ) struct_ops_names |> String.concat "\n\n"
  in
  
  let include_line = match include_kfuncs with
    | Some kh_filename -> sprintf "\ninclude \"%s\"\n" kh_filename
    | None -> ""
  in
  
  sprintf {|// Generated struct_ops template for %s
// Extracted from BTF: %s%s

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
    include_line
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
let generate_kernelscript_source ?extra_param ?include_kfuncs template project_name =
  (* Initialize context code generators to ensure they're available *)
  Kernelscript_context.Xdp_codegen.register ();
  Kernelscript_context.Tc_codegen.register ();
  Kernelscript_context.Kprobe_codegen.register ();
  Kernelscript_context.Tracepoint_codegen.register ();
  Kernelscript_context.Fprobe_codegen.register ();
  
  (* Get program description from context codegen system *)
  let context_comment = "// " ^ (Kernelscript_context.Context_codegen.get_context_program_description template.program_type) in
  
  (* Get return values from context codegen system if available *)
  let return_values = 
    let action_constants = Kernelscript_context.Context_codegen.get_context_action_constants template.program_type in
    if action_constants <> [] then
      List.map fst action_constants  (* Extract constant names *)
    else
      (* Fallback for program types without action constants *)
      ["0"; "-1"]
  in
  
  (* Helper function to generate type definition string *)
  let generate_type_definition ?(kernel_marker=false) type_info =
    match type_info.kind with
    | "struct" ->
        (match type_info.members with
         | Some members ->
             let member_strings = List.map (fun (name, typ) ->
               sprintf "    %s: %s," name typ
             ) members in
             let marker = if kernel_marker && type_info.kernel_defined then
               "// @kernel_only - This struct is only for eBPF compilation, not userspace\n"
             else "" in
             sprintf "%sstruct %s {\n%s\n}" marker type_info.name (String.concat "\n" member_strings)
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
  in

  (* Separate kernel types from user types *)
  let type_definitions = match include_kfuncs with
    | Some _ -> 
        (* With include: Only user-defined types in main file *)
        let user_types = List.filter (fun type_info -> not type_info.kernel_defined) template.types in
        String.concat "\n\n" (List.map (generate_type_definition ~kernel_marker:false) user_types)
    | None ->
        (* Standalone: All types in main file, with kernel markers *)
        String.concat "\n\n" (List.map (generate_type_definition ~kernel_marker:true) template.types)
  in
  
  let sample_return = match return_values with
    | first :: _ -> first
    | [] -> "0"
  in
  
  (* Generate function signature comments and actual function definition for specific program types *)
  let (function_signatures_comment, target_function_name, function_definition, custom_attribute) = 
    if template.program_type = "probe" && template.function_signatures <> [] then
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
      (comment, first_func, func_def, Some (sprintf "@probe(\"%s\")" first_func))
    else if template.program_type = "tracepoint" && template.function_signatures <> [] then
      let signature_lines = List.map (fun (event_name, signature) ->
        sprintf "// Tracepoint event: %s -> %s" event_name signature
      ) template.function_signatures in
      let comment = sprintf "\n// Tracepoint event signature:\n%s\n" 
        (String.concat "\n" signature_lines) in
      let first_event, _first_sig = match template.function_signatures with
        | (name, sig_str) :: _ -> (name, sig_str)
        | [] -> ("category/event", "fn(void*) -> i32")
      in
      let func_def = sprintf "fn %s_handler(ctx: %s) -> %s" 
        (String.map (function '/' -> '_' | c -> c) first_event) template.context_type template.return_type in
      (comment, first_event, func_def, Some (sprintf "@tracepoint(\"%s\")" first_event))
    else if template.program_type = "tc" && extra_param <> None then
      let direction = match extra_param with Some d -> d | None -> "ingress" in
      let comment = sprintf "\n// TC %s traffic control program\n" direction in
      let func_name = sprintf "%s_%s_handler" project_name direction in
      let func_def = sprintf "fn %s(ctx: %s) -> %s" func_name template.context_type template.return_type in
      (comment, direction, func_def, Some (sprintf "@tc(\"%s\")" direction))
    else 
      ("", "target_function", sprintf "fn %s_handler(ctx: %s) -> %s" project_name template.context_type template.return_type, None)
  in
  
  (* Use custom attribute if available, otherwise use generic program type attribute *)
  let attribute_line = match custom_attribute with
    | Some attr -> attr
    | None -> "@" ^ template.program_type
  in
  
  (* Customize attach call for probe/tracepoint *)
  let attach_target = 
    if template.program_type = "probe" then target_function_name 
    else if template.program_type = "tracepoint" then target_function_name
    else "eth0" 
  in
  let attach_comment = 
    if template.program_type = "probe" then 
      "    // Attach probe to target kernel function"
    else if template.program_type = "tracepoint" then
      "    // Attach tracepoint to target kernel event"
    else 
      "    // TODO: Update interface name and attachment parameters"
  in
  
  let function_name = 
    if template.program_type = "probe" then target_function_name 
    else if template.program_type = "tracepoint" then 
      String.map (function '/' -> '_' | c -> c) target_function_name ^ "_handler"
    else if template.program_type = "tc" && extra_param <> None then
      let direction = match extra_param with Some d -> d | None -> "ingress" in
      sprintf "%s_%s_handler" project_name direction
    else sprintf "%s_handler" project_name
  in
  
  let program_description = 
    if template.program_type = "tc" && extra_param <> None then
      let direction = match extra_param with Some d -> d | None -> "ingress" in
      sprintf "TC %s" direction
    else template.program_type
  in
  
  let include_line = match include_kfuncs with
    | Some kh_filename -> sprintf "\ninclude \"%s\"\n" kh_filename
    | None -> ""
  in
  
  sprintf {|%s
// Generated by KernelScript compiler with direct BTF parsing%s
%s
%s

%s
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
|} context_comment include_line function_signatures_comment type_definitions attribute_line function_definition template.program_type sample_return function_name attach_comment attach_target program_description program_description

(* Program-type specific kernel type names to extract from BTF *)
let get_program_btf_types prog_type =
  match prog_type with
  | "xdp" -> [
      ("xdp_md", "struct");
      ("xdp_action", "enum");
    ]
  | "tc" -> [
      ("__sk_buff", "struct");
      ("bpf_flow_keys", "struct");
      ("bpf_sock", "struct");
    ]
  | "probe" -> [
      ("pt_regs", "struct");
    ]
  | "tracepoint" -> [
      ("trace_entry", "struct");
    ]
  | _ -> []

(* Program-type specific kfunc names to extract from BTF *)
let get_program_kfunc_names prog_type =
  let common_kfuncs = [
    "bpf_ktime_get_ns";
    "bpf_trace_printk"; 
    "bpf_get_current_pid_tgid";
    "bpf_get_current_comm";
  ] in
  let specific_kfuncs = match prog_type with
    | "xdp" -> [
        "bpf_xdp_adjust_head";
        "bpf_xdp_adjust_tail";
        "bpf_redirect";
        "bpf_xdp_adjust_meta";
        "bpf_fib_lookup";
      ]
    | "tc" -> [
        "bpf_skb_change_head";
        "bpf_skb_change_tail";
        "bpf_clone_redirect";
        "bpf_skb_store_bytes";
        "bpf_skb_load_bytes";
      ]
    | "probe" -> [
        "bpf_probe_read";
        "bpf_probe_read_kernel";
        "bpf_probe_read_user";
        "bpf_probe_read_str";
      ]
    | "tracepoint" -> [
        "bpf_get_stackid";
        "bpf_perf_event_output";
        "bpf_get_stack";
      ]
    | _ -> []
  in
  common_kfuncs @ specific_kfuncs

(* Convert BTF kfunc signature to extern declaration *)
let convert_kfunc_signature_to_extern name signature =
  try
    if String.length signature < 3 || not (String.sub signature 0 3 = "fn(") then
      sprintf "extern %s() -> i32" name
    else
      let paren_start = 3 in
      let paren_end = String.index signature ')' in
      let params_str = String.sub signature paren_start (paren_end - paren_start) in
      
      let arrow_pos = try Some (String.index signature '>') with Not_found -> None in
      let return_type = match arrow_pos with
        | Some pos when pos > paren_end + 2 ->
            String.trim (String.sub signature (pos + 1) (String.length signature - pos - 1))
        | _ -> "i32"
      in
      
      sprintf "extern %s(%s) -> %s" name params_str return_type
  with
  | exn ->
      printf "Warning: Failed to parse kfunc signature '%s': %s\n" signature (Printexc.to_string exn);
      sprintf "extern %s() -> i32" name

(* Convert BTF type to KernelScript type definition *)
let convert_btf_type_to_ks_definition btf_type =
  match btf_type.Btf_binary_parser.kind with
  | "struct" ->
      let fields = match btf_type.Btf_binary_parser.members with
        | Some members -> 
            List.map (fun (name, typ) -> 
              let ks_type = match typ with
                | "unsigned int" | "__u32" | "u32" -> "u32"
                | "unsigned short" | "__u16" | "u16" -> "u16"
                | "unsigned char" | "__u8" | "u8" -> "u8"
                | "unsigned long long" | "__u64" | "u64" -> "u64"
                | "int" | "__s32" | "s32" -> "i32"
                | "short" | "__s16" | "s16" -> "i16"
                | "char" | "__s8" | "s8" -> "i8"
                | "long long" | "__s64" | "s64" -> "i64"
                | _ when String.contains typ '*' -> "*u8"
                | _ -> "u32"
              in
              sprintf "    %s: %s," name ks_type
            ) members
            |> String.concat "\n"
        | None -> ""
      in
      sprintf "struct %s {\n%s\n}" btf_type.Btf_binary_parser.name fields
  | "enum" | "enum64" ->
      let values = match btf_type.Btf_binary_parser.members with
        | Some members ->
            List.map (fun (name, value) -> 
              sprintf "    %s = %s," name value
            ) members
            |> String.concat "\n"
        | None -> ""
      in
      sprintf "enum %s {\n%s\n}" btf_type.Btf_binary_parser.name values
  | _ -> sprintf "// %s (unsupported type)" btf_type.Btf_binary_parser.name

(* Generate hardcoded enum definitions that can't be extracted from BTF *)
let generate_hardcoded_enums prog_type =
  match prog_type with
  | "tc" -> 
      sprintf {|enum tc_action {
    TC_ACT_UNSPEC = -1,
    TC_ACT_OK = 0,
    TC_ACT_RECLASSIFY = 1,
    TC_ACT_SHOT = 2,
    TC_ACT_PIPE = 3,
    TC_ACT_STOLEN = 4,
    TC_ACT_QUEUED = 5,
    TC_ACT_REPEAT = 6,
    TC_ACT_REDIRECT = 7,
    TC_ACT_TRAP = 8,
}|}
  | _ -> ""

(* Generate program-type specific header content using BTF *)
let generate_program_header ~extract_kfuncs prog_type btf_path =
  let type_specs = get_program_btf_types prog_type in
  let kfunc_names = if extract_kfuncs then get_program_kfunc_names prog_type else [] in
  
  let header = sprintf {|// AUTO-GENERATED %s DEFINITIONS - DO NOT EDIT
// Contains all kernel types and functions needed for %s programs
// Generated by KernelScript compiler from BTF

|} (String.uppercase_ascii prog_type) prog_type in
  
  let type_definitions = 
    try
      let type_name_list = List.map (fun (name, _kind) -> name) type_specs in
      let btf_types = Btf_binary_parser.parse_btf_file btf_path type_name_list in
      let filtered_types = List.filter (fun btf_type ->
        List.exists (fun (name, _kind) -> name = btf_type.Btf_binary_parser.name) type_specs
      ) btf_types in
      if filtered_types <> [] then
        List.map convert_btf_type_to_ks_definition filtered_types |> String.concat "\n\n"
      else
        sprintf "// Warning: No BTF types found for %s" prog_type
    with
    | exn ->
        printf "Warning: Failed to extract BTF types: %s\n" (Printexc.to_string exn);
        sprintf "// Warning: BTF extraction failed for %s" prog_type
  in
  
  let kfunc_declarations = 
    try
      let btf_kfuncs = Btf_binary_parser.extract_kfuncs_from_btf btf_path in
      let filtered_kfuncs = List.filter (fun (name, _) ->
        List.mem name kfunc_names
      ) btf_kfuncs in
      if filtered_kfuncs <> [] then
        List.map (fun (name, signature) -> convert_kfunc_signature_to_extern name signature) filtered_kfuncs
        |> String.concat "\n"
      else
        sprintf "// No BTF kfuncs found for %s" prog_type
    with
    | exn ->
        printf "Warning: Failed to extract BTF kfuncs: %s\n" (Printexc.to_string exn);
        sprintf "// Warning: BTF kfunc extraction failed for %s" prog_type
  in
  
  let hardcoded_enums = generate_hardcoded_enums prog_type in
  let enum_section = if hardcoded_enums <> "" then hardcoded_enums ^ "\n\n" else "" in
  sprintf "%s%s\n\n%s%s\n" header type_definitions enum_section kfunc_declarations

(* Get struct_ops-specific enum names to extract from BTF *)
let get_struct_ops_enum_names struct_ops_name =
  match struct_ops_name with
  | "sched_ext_ops" -> [
      "scx_public_consts";
      "scx_dsq_id_flags";
    ]
  | _ -> []

(* Generate struct_ops-specific header content using BTF *)
let generate_struct_ops_header struct_ops_name btf_path =
  let header = sprintf {|// AUTO-GENERATED %s DEFINITIONS - DO NOT EDIT
// Contains kernel struct definition for %s
// Generated by KernelScript compiler from BTF

|} (String.uppercase_ascii struct_ops_name) struct_ops_name in
  
  let struct_definitions = 
    try
      let btf_types = Btf_binary_parser.parse_btf_file btf_path [struct_ops_name] in
      let filtered_types = List.filter (fun btf_type ->
        btf_type.Btf_binary_parser.name = struct_ops_name && btf_type.Btf_binary_parser.kind = "struct"
      ) btf_types in
      if filtered_types <> [] then
        List.map convert_btf_type_to_ks_definition filtered_types |> String.concat "\n\n"
      else
        sprintf "// Warning: No BTF struct found for %s" struct_ops_name
    with
    | exn ->
        printf "Warning: Failed to extract BTF struct for %s: %s\n" struct_ops_name (Printexc.to_string exn);
        sprintf "// Warning: BTF extraction failed for %s" struct_ops_name
  in
  
  (* Extract related enums for specific struct_ops types *)
  let enum_definitions = 
    let enum_names = get_struct_ops_enum_names struct_ops_name in
    if enum_names <> [] then
      try
        let btf_enums = Btf_binary_parser.parse_btf_file btf_path enum_names in
        let filtered_enums = List.filter (fun btf_type ->
          (btf_type.Btf_binary_parser.kind = "enum" || btf_type.Btf_binary_parser.kind = "enum64") && 
          List.mem btf_type.Btf_binary_parser.name enum_names
        ) btf_enums in
        if filtered_enums <> [] then
          "\n// Related kernel enums\n" ^ 
          (List.map convert_btf_type_to_ks_definition filtered_enums |> String.concat "\n\n")
        else
          sprintf "\n// Warning: No BTF enums found for %s" struct_ops_name
      with
      | exn ->
          printf "Warning: Failed to extract BTF enums for %s: %s\n" struct_ops_name (Printexc.to_string exn);
          sprintf "\n// Warning: BTF enum extraction failed for %s" struct_ops_name
    else
      ""
  in
  
  sprintf "%s%s%s\n" header struct_definitions enum_definitions

(* Generate tracepoint-specific header content using BTF *)
let generate_tracepoint_header category_event btf_path =
  (* Parse category and event from the category_event string *)
  let (category, event) = 
    if String.contains category_event '/' then
      let parts = String.split_on_char '/' category_event in
      match parts with
      | [cat; evt] -> (cat, evt)
      | _ -> failwith (sprintf "Invalid tracepoint format '%s'. Use 'category/event'" category_event)
    else
      failwith (sprintf "Invalid tracepoint format '%s'. Use 'category/event'" category_event)
  in
  
  let header = sprintf {|// AUTO-GENERATED %s TRACEPOINT DEFINITIONS - DO NOT EDIT
// Contains kernel types needed for %s/%s tracepoint programs
// Generated by KernelScript compiler from BTF

|} (String.uppercase_ascii event) category event in
  
  (* Determine typedef_name and raw_name based on the user's logic *)
  let (typedef_name, raw_name) = 
    if category = "syscalls" && String.starts_with event ~prefix:"sys_enter_" then
      ("btf_trace_sys_enter", "trace_event_raw_sys_enter")
    else if category = "syscalls" && String.starts_with event ~prefix:"sys_exit_" then
      ("btf_trace_sys_exit", "trace_event_raw_sys_exit")
    else
      (sprintf "btf_trace_%s" event, sprintf "trace_event_raw_%s" event)
  in
  
  (* Extract the tracepoint structures from BTF *)
  let common_types = [raw_name; typedef_name; "trace_entry"] in
  let struct_definitions = 
    try
      let btf_types = Btf_binary_parser.parse_btf_file btf_path common_types in
      let filtered_types = List.filter (fun btf_type ->
        btf_type.Btf_binary_parser.kind = "struct" && 
        (btf_type.Btf_binary_parser.name = raw_name || 
         btf_type.Btf_binary_parser.name = "trace_entry")
      ) btf_types in
      if filtered_types <> [] then
        List.map convert_btf_type_to_ks_definition filtered_types |> String.concat "\n\n"
      else
        sprintf "// Warning: No BTF structs found for %s/%s" category event
    with
    | exn ->
        printf "Warning: Failed to extract BTF structs for %s/%s: %s\n" category event (Printexc.to_string exn);
        sprintf "// Warning: BTF extraction failed for %s/%s" category event
  in
  
  sprintf "%s%s\n" header struct_definitions
