(** BTF Parser - Extract type information from BTF files for KernelScript *)

open Printf

type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
}

type program_template = {
  program_type: string;
  context_type: string;
  return_type: string;
  includes: string list;
  types: btf_type_info list;
}

(** Get program template based on eBPF program type *)
let rec get_program_template prog_type btf_path = 
  let (context_type, return_type, common_types) = match prog_type with
    | "xdp" -> ("XdpContext", "XdpAction", [
        "xdp_md"; "xdp_action"
      ])
    | "tc" -> ("TcContext", "TcAction", [
        "__sk_buff"; "tc_action"
      ])
    | "kprobe" -> ("KprobeContext", "i32", [
        "pt_regs"
      ])
    | "uprobe" -> ("UprobeContext", "i32", [
        "pt_regs"
      ])
    | "tracepoint" -> ("TracepointContext", "i32", [
        "trace_entry"
      ])
    | "lsm" -> ("LsmContext", "i32", [
        "task_struct"; "file"; "inode"
      ])
    | "cgroup_skb" -> ("CgroupSkbContext", "i32", [
        "__sk_buff"
      ])
    | _ -> ("GenericContext", "i32", [])
  in
  
  (* Extract types from BTF if path is provided *)
  let extracted_types = match btf_path with
    | Some path when Sys.file_exists path -> extract_types_from_btf path common_types
    | _ -> []
  in
  
  (* If no types extracted, use builtin types for XDP/TC to avoid conflicts *)
  let final_types = if List.length extracted_types = 0 then
    match prog_type with
    | "xdp" | "tc" -> 
        printf "No BTF types found, using builtin types for %s program\n" prog_type;
        [] (* These have builtin types, don't generate conflicting fallback types *)
    | _ -> 
        printf "No BTF types found, using fallback types\n";
        generate_fallback_types common_types
  else
    extracted_types
  in
  
  (* Filter out builtin types that are already provided by builtin files *)
  let builtin_types = match prog_type with
    | "xdp" -> ["XdpAction"; "XdpContext"] (* Keep xdp_md and xdp_action from BTF *)
    | "tc" -> ["TcAction"; "TcContext"] (* Keep __sk_buff and tc_action from BTF *)
    | _ -> []
  in
  
  let filtered_types = List.filter (fun type_info -> 
    not (List.mem type_info.name builtin_types)
  ) final_types in
  
  {
    program_type = prog_type;
    context_type = context_type;
    return_type = return_type;
    includes = ["linux/bpf.h"; "linux/pkt_cls.h"; "linux/if_ether.h"; "linux/ip.h"; "linux/tcp.h"; "linux/udp.h"];
    types = filtered_types;
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
      }
    ) binary_types in
    
    if List.length converted_types > 0 then (
      printf "Successfully extracted %d types from BTF\n" (List.length converted_types);
      converted_types
    ) else (
      printf "No types extracted from BTF\n";
      [] (* Don't use fallback types anymore - let caller decide *)
    )
  with
  | exn ->
      printf "Warning: BTF extraction failed (%s)\n" (Printexc.to_string exn);
      [] (* Don't use fallback types anymore - let caller decide *)

(** Generate fallback types when BTF extraction fails *)
and generate_fallback_types type_names =
  List.map (fun type_name ->
    match type_name with
    | "xdp_md" -> {
        name = "xdp_md";
        kind = "struct";
        size = Some 32;
        members = Some [
          ("data", "u32");
          ("data_end", "u32");
          ("data_meta", "u32");
          ("ingress_ifindex", "u32");
          ("rx_queue_index", "u32");
          ("egress_ifindex", "u32");
        ];
      }
    | "xdp_action" -> {
        name = "xdp_action";
        kind = "enum";
        size = Some 4;
        members = Some [
          ("XDP_ABORTED", "0");
          ("XDP_DROP", "1");
          ("XDP_PASS", "2");
          ("XDP_TX", "3");
          ("XDP_REDIRECT", "4");
        ];
      }
    | "__sk_buff" -> {
        name = "__sk_buff";
        kind = "struct";
        size = Some 192;
        members = Some [
          ("len", "u32");
          ("pkt_type", "u32");
          ("mark", "u32");
          ("queue_mapping", "u32");
          ("protocol", "u32");
          ("vlan_present", "u32");
          ("vlan_tci", "u32");
          ("vlan_proto", "u32");
          ("priority", "u32");
          ("ingress_ifindex", "u32");
          ("ifindex", "u32");
          ("tc_index", "u32");
          ("cb", "u32[5]");
          ("hash", "u32");
          ("tc_classid", "u32");
          ("data", "u32");
          ("data_end", "u32");
          ("napi_id", "u32");
          ("family", "u32");
          ("remote_ip4", "u32");
          ("local_ip4", "u32");
          ("remote_ip6", "u32[4]");
          ("local_ip6", "u32[4]");
          ("remote_port", "u32");
          ("local_port", "u32");
          ("data_meta", "u32");
          ("flow_keys", "u32");
          ("tstamp", "u64");
          ("wire_len", "u32");
          ("gso_segs", "u32");
          ("sk", "u32");
          ("gso_size", "u32");
        ];
      }
    | "tc_action" -> {
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
        ];
      }
    | "pt_regs" -> {
        name = "pt_regs";
        kind = "struct";
        size = Some 168;
        members = Some [
          ("r15", "u64");
          ("r14", "u64");
          ("r13", "u64");
          ("r12", "u64");
          ("bp", "u64");
          ("bx", "u64");
          ("r11", "u64");
          ("r10", "u64");
          ("r9", "u64");
          ("r8", "u64");
          ("ax", "u64");
          ("cx", "u64");
          ("dx", "u64");
          ("si", "u64");
          ("di", "u64");
          ("orig_ax", "u64");
          ("ip", "u64");
          ("cs", "u64");
          ("flags", "u64");
          ("sp", "u64");
          ("ss", "u64");
        ];
      }
    | other -> {
        name = other;
        kind = "struct";
        size = None;
        members = Some [("placeholder", "u32")];
      }
  ) type_names

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
fn %s_handler(ctx: %s) -> %s {
    // TODO: Implement your %s logic here
    
    return %s
}

fn main() -> i32 {
    let prog = load(%s_handler)
    
    // TODO: Update interface name and attachment parameters
    let result = attach(prog, "eth0", 0)
    
    if (result == 0) {
        print("%s program loaded successfully")
    } else {
        print("Failed to load %s program")
        return 1
    }
    
    return 0
}
|} context_comment type_definitions template.program_type project_name template.context_type template.return_type template.program_type sample_return project_name template.program_type template.program_type 