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

(** BTF Binary Parser using libbpf C bindings *)

open Printf

(** BTF type information *)
type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
  kernel_defined: bool;
}

(** BTF handle type *)
type btf_handle

(** C bindings to libbpf BTF functions *)
external btf_new_from_file : string -> btf_handle option = "btf_new_from_file_stub"
external btf_get_nr_types : btf_handle -> int = "btf_get_nr_types_stub"
external btf_type_by_id : btf_handle -> int -> (int * string * int * int * int) = "btf_type_by_id_stub"

external btf_type_get_members : btf_handle -> int -> (string * int) array = "btf_type_get_members_stub"
external btf_resolve_type : btf_handle -> int -> string = "btf_resolve_type_stub"
external btf_extract_function_signatures : btf_handle -> string list -> (string * string) list = "btf_extract_function_signatures_stub"
external btf_extract_kernel_struct_names : btf_handle -> string list = "btf_extract_kernel_struct_names_stub"
external btf_free : btf_handle -> unit = "btf_free_stub"

(** Parse BTF file and extract requested types using libbpf *)
let parse_btf_file btf_path target_types =
  try
    match btf_new_from_file btf_path with
    | None -> (
      printf "Error: Failed to open BTF file %s\n" btf_path;
      []
    )
    | Some btf_handle -> (
      let nr_types = btf_get_nr_types btf_handle in
      let results = ref [] in
      
      (* Helper function to extract union members *)
      let extract_union_members btf_handle union_type_id =
        try
          let member_array = btf_type_get_members btf_handle union_type_id in
          let member_list = Array.to_list member_array in
          List.fold_left (fun acc (field_name, field_type_id) ->
            if field_name = "" then
              (* Skip anonymous members within the union to avoid infinite recursion *)
              acc
            else
              try
                let field_type = btf_resolve_type btf_handle field_type_id in
                (field_name, field_type) :: acc
              with
              | _ -> acc
          ) [] member_list
        with
        | _ -> []
      in
      
      (* Iterate through all BTF types *)
      for i = 1 to nr_types do
        try
          let (kind_int, name, size, _type_id, _vlen) = btf_type_by_id btf_handle i in
          
          (* Check if this is a target type *)
          if List.mem name target_types then (
            let kind_str = match kind_int with
              | 4 -> "struct"
              | 5 -> "union"
              | 6 -> "enum"
              | _ -> "unknown"
            in
            
            (* Get members for struct/union/enum types *)
            let members = 
              if kind_int = 4 || kind_int = 5 then (
                (* Struct/Union: resolve member types *)
                try
                  let member_array = btf_type_get_members btf_handle i in
                  let member_list = Array.to_list member_array in
                  (* Resolve each member's type and handle anonymous unions *)
                  let resolved_members = List.fold_left (fun acc (field_name, field_type_id) ->
                    try
                      let field_type = btf_resolve_type btf_handle field_type_id in
                      if field_name = "" && field_type = "union" then
                        (* Anonymous union: extract its members and flatten them *)
                        let union_members = extract_union_members btf_handle field_type_id in
                        union_members @ acc
                      else if field_name = "" then
                        (* Other anonymous types: skip them to avoid syntax errors *)
                        acc
                      else
                        (* Regular named field *)
                        (field_name, field_type) :: acc
                    with
                    | _ ->
                        (* If we can't resolve the type, include it as unknown if it has a name *)
                        if field_name <> "" then
                          (field_name, "unknown") :: acc
                        else
                          acc
                  ) [] member_list in
                  Some (List.rev resolved_members)
                with
                | _ -> None
              ) else if kind_int = 6 then (
                (* Enum: extract enum values *)
                try
                  let member_array = btf_type_get_members btf_handle i in
                  let member_list = Array.to_list member_array in
                  (* For enums, second element is the value, not type_id *)
                  let enum_values = List.map (fun (enum_name, enum_value) ->
                    (enum_name, string_of_int enum_value)
                  ) member_list in
                  Some enum_values
                with
                | _ -> None
              ) else None
            in
            
            let type_info = {
              name = name;
              kind = kind_str;
              size = (if size > 0 then Some size else None);
              members = members;
              kernel_defined = true;
            } in
            results := type_info :: !results
          )
        with
        | _ -> (* Skip problematic types *)
            ()
      done;
      
      btf_free btf_handle;
      List.rev !results
    )
  with
  | exn ->
      printf "Error parsing BTF file %s: %s\n" btf_path (Printexc.to_string exn);
      []

(** Extract kernel function signatures for kprobe targets *)
let extract_kernel_function_signatures btf_path function_names =
  try
    printf "Extracting function signatures from BTF file: %s\n" btf_path;
    printf "Target functions: %s\n" (String.concat ", " function_names);
    
    match btf_new_from_file btf_path with
    | None -> (
      printf "Error: Failed to open BTF file %s\n" btf_path;
      []
    )
    | Some btf_handle -> (
      let signatures = btf_extract_function_signatures btf_handle function_names in
      btf_free btf_handle;
      
      printf "Successfully extracted %d function signatures\n" (List.length signatures);
      List.iter (fun (name, sig_str) ->
        printf "  Function: %s -> %s\n" name sig_str
      ) signatures;
      
      signatures
    )
  with
  | exn ->
      printf "Error extracting function signatures from BTF file %s: %s\n" btf_path (Printexc.to_string exn);
      []

(** Extract all kernel-defined struct names from BTF file.
    @param btf_path Path to the binary BTF file
    @return List of kernel struct names *)
let extract_all_kernel_struct_names btf_path =
  try
    match btf_new_from_file btf_path with
    | None -> []
    | Some btf_handle ->
        let struct_names = btf_extract_kernel_struct_names btf_handle in
        btf_free btf_handle;
        struct_names
  with
  | _ -> [] 