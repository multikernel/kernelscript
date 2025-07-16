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
                  (* Resolve each member's type *)
                  let resolved_members = List.map (fun (field_name, field_type_id) ->
                    try
                      let field_type = btf_resolve_type btf_handle field_type_id in
                      (field_name, field_type)
                    with
                    | _ ->
                        (field_name, "unknown")
                  ) member_list in
                  Some resolved_members
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