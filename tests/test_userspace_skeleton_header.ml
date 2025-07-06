open Alcotest
open Kernelscript.Ir
open Kernelscript.Userspace_codegen

(** Helper function to check if string contains substring *)
let contains_substr str substr =
  try 
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in 
    true
  with Not_found -> false

let test_skeleton_header_inclusion () =
  (* Test that skeleton header is included when load() is used *)
  let test_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test.ks" } in
  let load_call = make_ir_instruction (IRCall ("load", [make_ir_value (IRLiteral (StringLit "test_prog")) (IRStr 10) test_pos], Some (make_ir_value (IRVariable "prog") IRI32 test_pos))) test_pos in
  let entry_block = make_ir_basic_block "entry" [load_call] 0 in
  let main_func = make_ir_function "main" [] (Some IRI32) [entry_block] test_pos in
  
  let userspace_prog = make_ir_userspace_program
    [main_func] [] [] (make_ir_coordinator_logic [] [] [] (make_ir_config_management [] [] [])) test_pos in
  
  let ir_multi_prog = make_ir_multi_program "test" [] [] [] ~userspace_program:userspace_prog test_pos in
  
  let generated_code = generate_complete_userspace_program_from_ir userspace_prog [] ir_multi_prog "test.ks" in
  
  check bool "Should include skeleton header when load() is used" true (contains_substr generated_code "test.skel.h");
  check bool "Should declare skeleton instance when load() is used" true (contains_substr generated_code "struct test_ebpf *obj")

let test_skeleton_header_inclusion_attach () =
  (* Test that skeleton header is included when attach() is used *)
  let test_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test.ks" } in
  let attach_call = make_ir_instruction (IRCall ("attach", [make_ir_value (IRLiteral (IntLit (1, None))) IRI32 test_pos; make_ir_value (IRLiteral (StringLit "lo")) (IRStr 10) test_pos; make_ir_value (IRLiteral (IntLit (0, None))) IRI32 test_pos], None)) test_pos in
  let entry_block = make_ir_basic_block "entry" [attach_call] 0 in
  let main_func = make_ir_function "main" [] (Some IRI32) [entry_block] test_pos in
  
  let userspace_prog = make_ir_userspace_program
    [main_func] [] [] (make_ir_coordinator_logic [] [] [] (make_ir_config_management [] [] [])) test_pos in
  
  let ir_multi_prog = make_ir_multi_program "test" [] [] [] ~userspace_program:userspace_prog test_pos in
  
  let generated_code = generate_complete_userspace_program_from_ir userspace_prog [] ir_multi_prog "test.ks" in
  
  check bool "Should include skeleton header when attach() is used" true (contains_substr generated_code "test.skel.h");
  check bool "Should declare skeleton instance when attach() is used" true (contains_substr generated_code "struct test_ebpf *obj")

let test_skeleton_header_not_included_without_bpf_functions () =
  (* Test that skeleton header is not included when no BPF functions are used *)
  let test_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test.ks" } in
  let printf_call = make_ir_instruction (IRCall ("printf", [make_ir_value (IRLiteral (StringLit "Hello World")) (IRStr 20) test_pos], None)) test_pos in
  let entry_block = make_ir_basic_block "entry" [printf_call] 0 in
  let main_func = make_ir_function "main" [] (Some IRI32) [entry_block] test_pos in
  
  let userspace_prog = make_ir_userspace_program
    [main_func] [] [] (make_ir_coordinator_logic [] [] [] (make_ir_config_management [] [] [])) test_pos in
  
  let ir_multi_prog = make_ir_multi_program "test" [] [] [] ~userspace_program:userspace_prog test_pos in
  
  let generated_code = generate_complete_userspace_program_from_ir userspace_prog [] ir_multi_prog "test.ks" in
  
  check bool "Should not include skeleton header when no BPF functions are used" false (contains_substr generated_code "test.skel.h");
  check bool "Should not declare skeleton instance when no BPF functions are used" false (contains_substr generated_code "struct test_ebpf *obj")

let test_skeleton_header_included_with_global_variables () =
  (* Test that skeleton header is included when global variables are present *)
  let test_pos = { Kernelscript.Ast.line = 1; column = 1; filename = "test.ks" } in
  let global_var = {
    global_var_name = "test_var";
    global_var_type = IRU32;
    global_var_init = Some (make_ir_value (IRLiteral (IntLit (42, None))) IRU32 test_pos);
    global_var_pos = test_pos;
    is_local = false;
    is_pinned = false;
  } in
  
  let printf_call = make_ir_instruction (IRCall ("printf", [make_ir_value (IRLiteral (StringLit "Hello World")) (IRStr 20) test_pos], None)) test_pos in
  let entry_block = make_ir_basic_block "entry" [printf_call] 0 in
  let main_func = make_ir_function "main" [] (Some IRI32) [entry_block] test_pos in
  
  let userspace_prog = make_ir_userspace_program
    [main_func] [] [] (make_ir_coordinator_logic [] [] [] (make_ir_config_management [] [] [])) test_pos in
  
  let ir_multi_prog = make_ir_multi_program "test" [] [] [] ~global_variables:[global_var] ~userspace_program:userspace_prog test_pos in
  
  let generated_code = generate_complete_userspace_program_from_ir userspace_prog [] ir_multi_prog "test.ks" in
  
  check bool "Should include skeleton header when global variables are present" true (contains_substr generated_code "test.skel.h");
  check bool "Should declare skeleton instance when global variables are present" true (contains_substr generated_code "struct test_ebpf *obj")

let tests = [
  test_case "test_skeleton_header_inclusion" `Quick test_skeleton_header_inclusion;
  test_case "test_skeleton_header_inclusion_attach" `Quick test_skeleton_header_inclusion_attach;
  test_case "test_skeleton_header_not_included_without_bpf_functions" `Quick test_skeleton_header_not_included_without_bpf_functions;
  test_case "test_skeleton_header_included_with_global_variables" `Quick test_skeleton_header_included_with_global_variables;
]

let () = run "Userspace Skeleton Header Tests" [
  ("userspace_skeleton_header", tests);
] 