(** BTF Parser - Extract type information from BTF files for KernelScript *)

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

(** Get program template based on eBPF program type with optional BTF extraction *)
val get_program_template : string -> string option -> program_template

(** Check if a type name is a well-known eBPF kernel type *)
val is_well_known_kernel_type : string -> bool

(** Generate KernelScript source code from template *)
val generate_kernelscript_source : program_template -> string -> string 