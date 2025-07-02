(** Direct Binary BTF Parser Interface *)

type btf_type_info = {
  name: string;
  kind: string;
  size: int option;
  members: (string * string) list option; (* field_name * field_type *)
  kernel_defined: bool; (* Mark if this type is kernel-defined *)
}

(** Parse a binary BTF file directly and extract requested types.
    @param btf_path Path to the binary BTF file
    @param target_types List of type names to extract
    @return List of extracted type definitions in KernelScript format *)
val parse_btf_file : string -> string list -> btf_type_info list 