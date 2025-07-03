(** Struct_ops Registry - Manage struct_ops definitions and BTF extraction *)

open Printf

(** Known struct_ops types that can be extracted from BTF *)
type struct_ops_info = {
  name: string;
  description: string;
  kernel_version: string option;
  common_usage: string list;
}

(** Registry of well-known struct_ops types *)
let known_struct_ops = [
  {
    name = "tcp_congestion_ops";
    description = "TCP congestion control operations";
    kernel_version = Some "5.6+";
    common_usage = ["TCP congestion control"; "Network performance optimization"];
  };
  {
    name = "bpf_iter_ops";
    description = "BPF iterator operations";
    kernel_version = Some "5.8+";
    common_usage = ["Kernel data structure iteration"; "System introspection"];
  };
  {
    name = "bpf_struct_ops_test";
    description = "BPF struct_ops test operations";
    kernel_version = Some "5.6+";
    common_usage = ["Testing and development"];
  };
]

(** Check if a struct_ops type is known *)
let is_known_struct_ops name =
  List.exists (fun info -> info.name = name) known_struct_ops

(** Get information about a struct_ops type *)
let get_struct_ops_info name =
  List.find_opt (fun info -> info.name = name) known_struct_ops

(** Get all known struct_ops names *)
let get_all_known_struct_ops () =
  List.map (fun info -> info.name) known_struct_ops

(** Struct_ops field definition for code generation *)
type struct_ops_field = {
  field_name: string;
  field_type: string;
  is_function_pointer: bool;
  description: string option;
}

(** Convert BTF field info to struct_ops field *)
let btf_field_to_struct_ops_field (field_name, field_type) =
  let is_func_ptr = String.contains field_type '*' || String.contains field_type '(' in
  {
    field_name;
    field_type;
    is_function_pointer = is_func_ptr;
    description = None;
  }

(** Generate KernelScript struct_ops definition from BTF info *)
let generate_struct_ops_definition btf_type =
  match btf_type.Btf_binary_parser.members with
  | Some members ->
      let fields = List.map btf_field_to_struct_ops_field members in
      let field_definitions = List.map (fun field ->
        (* Use the actual BTF-resolved type without hardcoding field names *)
        let type_str = match field.field_type with
          | "void*" -> "*u8"  (* Convert void* to *u8 for KernelScript *)
          | "int" -> "i32"
          | "unsigned int" -> "u32"
          | "long" -> "i64"
          | "unsigned long" -> "u64"
          | other -> other
        in
        let comment = match field.description with
          | Some desc -> sprintf "    %s: %s, // %s" field.field_name type_str desc
          | None -> sprintf "    %s: %s," field.field_name type_str
        in
        comment
      ) fields in
      
      Some (sprintf {|@struct_ops("%s")
struct %s {
%s
}|} btf_type.name btf_type.name (String.concat "\n" field_definitions))
  | None -> None

(** Extract struct_ops definitions from BTF file *)
let extract_struct_ops_from_btf btf_path struct_ops_names =
  printf "🔧 Extracting struct_ops definitions from BTF...\n";
  
  (* For struct_ops, extract from the original kernel struct, not the BPF wrapper *)
  (* The BPF wrapper exists but has a different structure with common and data fields *)
  printf "🔍 Looking for kernel struct_ops: %s\n" (String.concat ", " struct_ops_names);
  let btf_types = Btf_binary_parser.parse_btf_file btf_path struct_ops_names in
  
  let struct_ops_definitions = List.filter_map (fun btf_type ->
    if btf_type.Btf_binary_parser.kind = "struct" then
      generate_struct_ops_definition btf_type
    else
      None
  ) btf_types in
  
  printf "✅ Extracted %d struct_ops definitions\n" (List.length struct_ops_definitions);
  struct_ops_definitions

(** Verify struct_ops definition against BTF *)
let verify_struct_ops_against_btf btf_path struct_name user_fields =
  try
    (* Use the original kernel struct for verification, not the BPF wrapper *)
    printf "🔍 Verifying against BTF struct: %s\n" struct_name;
    
    let btf_types = Btf_binary_parser.parse_btf_file btf_path [struct_name] in
    match btf_types with
    | btf_type :: _ when btf_type.Btf_binary_parser.name = struct_name ->
        (match btf_type.members with
         | Some btf_fields ->
             let btf_field_names = List.map (fun (name, _) -> name) btf_fields in
             let user_field_names = List.map (fun (name, _) -> name) user_fields in
             
             (* Check for missing fields *)
             let missing_fields = List.filter (fun btf_field ->
               not (List.mem btf_field user_field_names)
             ) btf_field_names in
             
             (* Check for extra fields *)
             let extra_fields = List.filter (fun user_field ->
               not (List.mem user_field btf_field_names)
             ) user_field_names in
             
             if missing_fields = [] && extra_fields = [] then
               Ok ()
             else
               let error_msg = String.concat "; " [
                 (if missing_fields <> [] then 
                   sprintf "Missing fields: %s" (String.concat ", " missing_fields)
                 else "");
                 (if extra_fields <> [] then 
                   sprintf "Extra fields: %s" (String.concat ", " extra_fields)
                 else "");
               ] |> String.trim in
               Error (sprintf "struct_ops '%s' definition mismatch: %s" struct_name error_msg)
         | None ->
             Error (sprintf "Could not extract fields for struct_ops '%s' from BTF" struct_name))
    | _ ->
        Error (sprintf "struct_ops '%s' not found in BTF" struct_name)
  with
  | exn ->
      Error (sprintf "BTF verification failed for struct_ops '%s': %s" struct_name (Printexc.to_string exn))

(** Generate usage examples for struct_ops **)
let generate_struct_ops_usage_example struct_ops_name =
  sprintf {|// Example implementation for %s
fn setup_%s() -> i32 {
    // TODO: Create and initialize your %s instance
    // Example:
    // my_%s = %s {
    //     // TODO: Implement the required function pointers
    //     // Refer to kernel documentation for %s
    // }
    
    // Register the struct_ops instance
    // let result = register(my_%s)
    // if (result == 0) {
    //     print("%s registered successfully")
    // } else {
    //     print("Failed to register %s")
    // }
    
    return 0
}|} struct_ops_name struct_ops_name struct_ops_name 
    struct_ops_name struct_ops_name struct_ops_name
    struct_ops_name struct_ops_name struct_ops_name 