open Alcotest
open Kernelscript.Btf_parser

let test_xdp_template_generation () =
  let template = get_program_template "xdp" None in
  check string "program type" "xdp" template.program_type;
  check string "context type" "XdpContext" template.context_type;
  check string "return type" "XdpAction" template.return_type;
  check bool "Should have type definitions" true (List.length template.types > 0);
  (* Check that xdp_md is filtered out (it conflicts with builtin) *)
  check bool "Should not include xdp_md type" false
    (List.exists (fun t -> t.name = "xdp_md") template.types);
  (* Check that ethhdr is included *)
  check bool "Should include ethhdr type" true
    (List.exists (fun t -> t.name = "ethhdr") template.types)

let test_tc_template_generation () =
  let template = get_program_template "tc" None in
  check string "program type" "tc" template.program_type;
  check string "context type" "TcContext" template.context_type;
  check string "return type" "TcAction" template.return_type;
  check bool "Should have type definitions" true (List.length template.types > 0);
  (* Check that __sk_buff is filtered out (it conflicts with builtin) *)
  check bool "Should not include __sk_buff type" false
    (List.exists (fun t -> t.name = "__sk_buff") template.types)

let test_kprobe_template_generation () =
  let template = get_program_template "kprobe" None in
  check string "program type" "kprobe" template.program_type;
  check string "context type" "KprobeContext" template.context_type;
  check string "return type" "i32" template.return_type;
  check bool "Should have type definitions" true (List.length template.types > 0);
  (* Check that pt_regs is included *)
  check bool "Should include pt_regs type" true
    (List.exists (fun t -> t.name = "pt_regs") template.types)

let test_source_generation () =
  let template = get_program_template "xdp" None in
  let source = generate_kernelscript_source template "test_project" in
  let contains_substring s substr = 
    try ignore (Str.search_forward (Str.regexp_string substr) s 0); true with Not_found -> false
  in
  check bool "Should contain project handler function" true
    (contains_substring (String.lowercase_ascii source) (String.lowercase_ascii "test_project_handler"));
  check bool "Should contain XDP attribute" true
    (contains_substring source "@xdp");
  check bool "Should contain main function" true
    (contains_substring source "fn main()");
  check bool "Should contain networking structs" true
    (contains_substring source "struct ethhdr");
  (* Should NOT contain builtin types that conflict *)
  check bool "Should not contain XdpAction enum definition" false
    (contains_substring source "enum XdpAction");
  check bool "Should not contain xdp_md struct definition" false
    (contains_substring source "struct xdp_md")

let test_array_syntax () =
  let template = get_program_template "xdp" None in
  let source = generate_kernelscript_source template "test_project" in
  let contains_substring s substr = 
    try ignore (Str.search_forward (Str.regexp_string substr) s 0); true with Not_found -> false
  in
  (* Check that array syntax is correct (u8[6] not [u8; 6]) *)
  check bool "Should use correct array syntax" true
    (contains_substring source "u8[6]");
  check bool "Should not use incorrect array syntax" false
    (contains_substring source "[u8; 6]")

let test_invalid_program_type () =
  let template = get_program_template "invalid_type" None in
  check string "program type" "invalid_type" template.program_type;
  check string "context type" "GenericContext" template.context_type;
  check string "return type" "i32" template.return_type;
  check (list (module struct type t = btf_type_info let pp _ _ = () let equal a b = a.name = b.name end)) "types" [] template.types

let () = run "BTF Parser Tests" [
  "template_generation", [
    test_case "XDP template generation" `Quick test_xdp_template_generation;
    test_case "TC template generation" `Quick test_tc_template_generation;
    test_case "Kprobe template generation" `Quick test_kprobe_template_generation;
    test_case "Invalid program type" `Quick test_invalid_program_type;
  ];
  "source_generation", [
    test_case "Source generation" `Quick test_source_generation;
    test_case "Array syntax" `Quick test_array_syntax;
  ];
] 