(** Direct Binary BTF Parser - Parse BTF files without external dependencies *)

open Printf

(* BTF binary format constants *)
let btf_magic = 0xeB9F
let btf_version = 1

(* Use shared kernel type checking *)
let is_well_known_kernel_type = Kernel_types.is_well_known_ebpf_type

(* Define our own BTF type info to avoid circular dependency *)
type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
  kernel_defined: bool; (* Mark if this type is kernel-defined *)
}

(* BTF Kind values *)
type btf_kind = 
  | BTF_KIND_UNKN
  | BTF_KIND_INT
  | BTF_KIND_PTR  
  | BTF_KIND_ARRAY
  | BTF_KIND_STRUCT
  | BTF_KIND_UNION
  | BTF_KIND_ENUM
  | BTF_KIND_FWD
  | BTF_KIND_TYPEDEF
  | BTF_KIND_VOLATILE
  | BTF_KIND_CONST
  | BTF_KIND_RESTRICT
  | BTF_KIND_FUNC
  | BTF_KIND_FUNC_PROTO
  | BTF_KIND_VAR
  | BTF_KIND_DATASEC
  | BTF_KIND_FLOAT

let btf_kind_of_int = function
  | 0 -> BTF_KIND_UNKN
  | 1 -> BTF_KIND_INT
  | 2 -> BTF_KIND_PTR
  | 3 -> BTF_KIND_ARRAY
  | 4 -> BTF_KIND_STRUCT
  | 5 -> BTF_KIND_UNION
  | 6 -> BTF_KIND_ENUM
  | 7 -> BTF_KIND_FWD
  | 8 -> BTF_KIND_TYPEDEF
  | 9 -> BTF_KIND_VOLATILE
  | 10 -> BTF_KIND_CONST
  | 11 -> BTF_KIND_RESTRICT
  | 12 -> BTF_KIND_FUNC
  | 13 -> BTF_KIND_FUNC_PROTO
  | 14 -> BTF_KIND_VAR
  | 15 -> BTF_KIND_DATASEC
  | 16 -> BTF_KIND_FLOAT
  | _ -> BTF_KIND_UNKN

(* BTF header structure *)
type btf_header = {
  magic: int;
  version: int;
  flags: int;
  hdr_len: int;
  type_off: int;
  type_len: int;
  str_off: int;
  str_len: int;
}

(* BTF type structure *)
type btf_type = {
  name_off: int;
  info: int;
  size_type: int; (* size for ints/structs, type id for pointers/arrays *)
}

(* BTF member structure for structs/unions *)
type btf_member = {
  name_off: int;
  type_id: int;
  offset: int;
}

(* BTF enum value structure *)
type btf_enum = {
  name_off: int;
  value: int;
}

(* Parsed BTF type information *)
type parsed_btf_type = {
  id: int;
  name: string;
  kind: btf_kind;
  size: int option;
  members: (string * int * int) list option; (* name, type_id, offset *)
  enum_values: (string * int) list option; (* name, value for enums *)
}

(* Binary reading utilities *)
let read_uint32_le data offset =
  if offset + 4 > Bytes.length data then
    failwith "Buffer overflow reading uint32"
  else
    let b0 = Bytes.get_uint8 data offset in
    let b1 = Bytes.get_uint8 data (offset + 1) in
    let b2 = Bytes.get_uint8 data (offset + 2) in
    let b3 = Bytes.get_uint8 data (offset + 3) in
    b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24)

let read_uint16_le data offset =
  if offset + 2 > Bytes.length data then
    failwith "Buffer overflow reading uint16"
  else
    let b0 = Bytes.get_uint8 data offset in
    let b1 = Bytes.get_uint8 data (offset + 1) in
    b0 lor (b1 lsl 8)

let read_uint8 data offset =
  if offset >= Bytes.length data then
    failwith "Buffer overflow reading uint8"
  else
    Bytes.get_uint8 data offset

(* String table utilities *)
let read_string data str_section_start str_offset =
  let offset = str_section_start + str_offset in
  if offset >= Bytes.length data then ""
  else
    let buf = Buffer.create 64 in
    let rec loop i =
      if i >= Bytes.length data then
        Buffer.contents buf
      else
        let c = Bytes.get_uint8 data i in
        if c = 0 then
          Buffer.contents buf
        else (
          Buffer.add_char buf (Char.chr c);
          loop (i + 1)
        )
    in
    loop offset

(* Parse BTF header *)
let parse_btf_header data =
  if Bytes.length data < 24 then
    failwith "BTF file too small for header"
  else
    let magic = read_uint16_le data 0 in
    let version = read_uint8 data 2 in
    let flags = read_uint8 data 3 in
    let hdr_len = read_uint32_le data 4 in
    let type_off = read_uint32_le data 8 in
    let type_len = read_uint32_le data 12 in
    let str_off = read_uint32_le data 16 in
    let str_len = read_uint32_le data 20 in
    
    if magic <> btf_magic then
      failwith (sprintf "Invalid BTF magic: 0x%x (expected 0x%x)" magic btf_magic);
    
    if version <> btf_version then
      printf "Warning: BTF version %d (expected %d)\n" version btf_version;
    

    
    {
      magic = magic;
      version = version;
      flags = flags;
      hdr_len = hdr_len;
      type_off = type_off;
      type_len = type_len;
      str_off = str_off;
      str_len = str_len;
    }

(* Parse BTF type *)
let parse_btf_type data offset =
  let name_off = read_uint32_le data offset in
  let info = read_uint32_le data (offset + 4) in
  let size_type = read_uint32_le data (offset + 8) in
  {
    name_off = name_off;
    info = info;
    size_type = size_type;
  }

(* Extract kind and vlen from info field *)
let extract_kind_vlen info =
  let kind = btf_kind_of_int ((info lsr 24) land 0x1f) in
  let vlen = info land 0xffff in
  (kind, vlen)



(* Parse BTF members for struct/union types *)
let parse_btf_members data offset vlen =
  let rec parse_members acc i curr_offset =
    if i >= vlen then acc
    else
      let name_off = read_uint32_le data curr_offset in
      let type_id = read_uint32_le data (curr_offset + 4) in
      let offset_val = read_uint32_le data (curr_offset + 8) in
      let member = {
        name_off = name_off;
        type_id = type_id;
        offset = offset_val;
      } in
      parse_members (member :: acc) (i + 1) (curr_offset + 12)
  in
  List.rev (parse_members [] 0 offset)

(* Parse BTF enum values *)
let parse_btf_enum_values data offset vlen =
  let rec parse_enums acc i curr_offset =
    if i >= vlen then acc
    else
      let name_off = read_uint32_le data curr_offset in
      let value = read_uint32_le data (curr_offset + 4) in
      let enum_val = {
        name_off = name_off;
        value = value;
      } in
      parse_enums (enum_val :: acc) (i + 1) (curr_offset + 8)
  in
  List.rev (parse_enums [] 0 offset)

(* Lightweight type scanning - only extract name and basic info without members *)
let scan_btf_type data str_start offset =
  let btf_type = parse_btf_type data offset in
  let (kind, vlen) = extract_kind_vlen btf_type.info in 
  let name = read_string data str_start btf_type.name_off in
  
  (* Calculate next offset based on BTF kind without allocating member data *)
  let next_offset = match kind with
    | BTF_KIND_STRUCT | BTF_KIND_UNION ->
        offset + 12 + (vlen * 12) (* Each member is 12 bytes *)
    | BTF_KIND_ENUM ->
        offset + 12 + (vlen * 8)  (* Each enum value is 8 bytes *)
    | BTF_KIND_FUNC_PROTO ->
        offset + 12 + (vlen * 8)  (* Each parameter is 8 bytes *)
    | BTF_KIND_ARRAY ->
        offset + 12 + 12               (* Array info is 12 bytes *)
    | _ ->
        offset + 12                    (* Basic types are just 12 bytes *)
  in
  
  (name, kind, vlen, offset, next_offset)

(* Scan all BTF types to find target types by name - no member parsing *)
let find_target_types data header target_names =
  let types_start = header.hdr_len + header.type_off in
  let types_end = types_start + header.type_len in
  let str_start = header.hdr_len + header.str_off in
  
  let target_set = List.fold_left (fun acc name -> 
    let module StringSet = Set.Make(String) in
    StringSet.add name acc
  ) (let module StringSet = Set.Make(String) in StringSet.empty) target_names in
  
  let rec scan_types found_types offset type_id =
    if offset >= types_end then found_types
    else if offset + 12 > Bytes.length data then found_types
    else
      try
        let (name, kind, vlen, curr_offset, next_offset) = scan_btf_type data str_start offset in
        
        (* Validate offset progression *)
        if next_offset <= offset then found_types (* Must advance *)
        else if next_offset > types_end then found_types (* Stay within bounds *)
        else
          let module StringSet = Set.Make(String) in
          if StringSet.mem name target_set then
            (* Found a target type - store its info for detailed parsing *)
            let found_info = (name, kind, vlen, curr_offset, type_id) in
            scan_types (found_info :: found_types) next_offset (type_id + 1)
          else
            (* Not a target type - just advance *)
            scan_types found_types next_offset (type_id + 1)
      with
      | _ -> found_types (* Skip problematic types *)
  in
  
  List.rev (scan_types [] types_start 1)

(* Parse detailed type information only for found target types *)
let parse_target_type_details data str_start (name, kind, vlen, offset, type_id) =
  try
    (* Only parse members/enum values for types we actually care about *)
    let (members, enum_values) = match kind with
      | BTF_KIND_STRUCT | BTF_KIND_UNION when vlen > 0 ->
          if offset + 12 + (vlen * 12) <= Bytes.length data then
            let members_offset = offset + 12 in
            let members = parse_btf_members data members_offset vlen in
            let member_names = List.map (fun (member : btf_member) ->
              let member_name = read_string data str_start member.name_off in
              (member_name, member.type_id, member.offset)
            ) members in
            (Some member_names, None)
          else
            (None, None)
      | BTF_KIND_ENUM when vlen > 0 ->
          if offset + 12 + (vlen * 8) <= Bytes.length data then
            let enums_offset = offset + 12 in
            let enum_vals = parse_btf_enum_values data enums_offset vlen in
            let enum_names = List.map (fun (enum_val : btf_enum) ->
              let enum_name = read_string data str_start enum_val.name_off in
              (enum_name, enum_val.value)
            ) enum_vals in
            (None, Some enum_names)
          else
            (None, None)
      | _ ->
          (None, None)
    in
    
    let btf_type_info = parse_btf_type data offset in
    Some {
      id = type_id;
      name = name;
      kind = kind;
      size = (match kind with
        | BTF_KIND_INT | BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_ENUM ->
            Some btf_type_info.size_type
        | _ -> None);
      members = members;
      enum_values = enum_values;
    }
  with
  | _ -> None (* Skip if parsing fails *)

(* New elegant BTF parsing approach: scan first, then parse only needed types *)
let parse_btf_types data header target_names =
  let str_start = header.hdr_len + header.str_off in
  
  (* Step 1: Scan all types to find our target types by name *)
  let found_target_info = find_target_types data header target_names in
  
  (* Step 2: Parse detailed information only for found target types *)
  List.filter_map (parse_target_type_details data str_start) found_target_info

(* Convert BTF types to KernelScript format *)
let btf_type_to_kernelscript btf_types type_name =
  let find_type name =
    List.find_opt (fun t -> t.name = name) btf_types
  in
  
  let rec resolve_type_name type_id =
    try
      let t = List.find (fun t -> t.id = type_id) btf_types in
      match t.kind with
      | BTF_KIND_INT ->
          (match t.size with
           | Some 1 -> "u8"
           | Some 2 -> "u16" 
           | Some 4 -> "u32"
           | Some 8 -> "u64"
           | _ -> "u32")
      | BTF_KIND_PTR -> "*u8"
      | BTF_KIND_ARRAY -> "u8[1]" (* Simplified - would need array parsing *)
      | BTF_KIND_TYPEDEF -> resolve_type_name t.id (* Follow typedef chain *)
      | _ -> t.name
    with Not_found -> "u32" (* Default fallback *)
  in
  
  match find_type type_name with
  | Some btf_type when btf_type.kind = BTF_KIND_STRUCT ->
      let members = match btf_type.members with
        | Some members ->
            List.map (fun (name, type_id, _offset) ->
              let type_str = resolve_type_name type_id in
              (name, type_str)
            ) members
        | None -> []
      in
      Some {
        name = btf_type.name;
        kind = "struct";
        size = btf_type.size;
        members = Some members;
        kernel_defined = is_well_known_kernel_type btf_type.name;
      }
  | Some btf_type when btf_type.kind = BTF_KIND_ENUM ->
      let enum_values = match btf_type.enum_values with
        | Some values ->
            List.map (fun (name, value) ->
              (name, string_of_int value)
            ) values
        | None -> []
      in
      Some {
        name = btf_type.name;
        kind = "enum";
        size = btf_type.size;
        members = Some enum_values;
        kernel_defined = is_well_known_kernel_type btf_type.name;
      }
  | _ -> None

(* Updated main BTF parsing function *)
let parse_btf_file btf_path target_types =
  try
    let ic = open_in_bin btf_path in
    let data = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    let data_bytes = Bytes.of_string data in
    let header = parse_btf_header data_bytes in
    
    let btf_types = parse_btf_types data_bytes header target_types in
    
    (* Extract requested types *)
    let extracted_types = List.filter_map (fun type_name ->
      btf_type_to_kernelscript btf_types type_name
    ) target_types in
    
    printf "Successfully parsed BTF file: %s\n" btf_path;
    printf "Found %d target types, extracted %d requested types\n" 
      (List.length btf_types) (List.length extracted_types);
    
    extracted_types
    
  with
  | Sys_error msg ->
      printf "Error reading BTF file %s: %s\n" btf_path msg;
      []
  | exn ->
      printf "Error parsing BTF file %s: %s\n" btf_path (Printexc.to_string exn);
      [] 