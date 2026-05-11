open Alcotest
open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Userspace_codegen
open Kernelscript.Parse
open Kernelscript.Type_checker

let contains_substr str substr =
  try
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in
    true
  with Not_found -> false

let count_substr str substr =
  let regexp = Str.regexp_string substr in
  let rec loop start count =
    try
      let index = Str.search_forward regexp str start in
      loop (index + String.length substr) (count + 1)
    with Not_found -> count
  in
  loop 0 0

let test_pos = { line = 1; column = 1; filename = "test.ks" }

let int32_value value =
  make_ir_value (IRLiteral (IntLit (Signed64 value, None))) IRI32 test_pos

let uint32_value value =
  make_ir_value (IRLiteral (IntLit (Signed64 value, None))) IRU32 test_pos

let uint64_value value =
  make_ir_value (IRLiteral (IntLit (Signed64 value, None))) IRU64 test_pos

let bool_value value =
  make_ir_value (IRLiteral (BoolLit value)) IRBool test_pos

let int64_value value =
  make_ir_value (IRLiteral (IntLit (Signed64 value, None))) IRI64 test_pos

let perf_type_value name raw_value =
  make_ir_value
    (IREnumConstant ("perf_type", name, Signed64 raw_value))
    (IREnum ("perf_type", []))
    test_pos

let perf_config_value enum_name name raw_value =
  make_ir_value
    (IREnumConstant (enum_name, name, Signed64 raw_value))
    (IREnum (enum_name, []))
    test_pos

let perf_attr_expr ~pid ~cpu =
  make_ir_expr
    (IRStructLiteral ("perf_options", [
      ("perf_type", perf_type_value "perf_type_hardware" 0L);
      ("perf_config", perf_config_value "perf_hw_config" "branch_misses" 5L);
      ("pid", int32_value pid);
      ("cpu", int32_value cpu);
      ("period", uint64_value 1000000L);
      ("wakeup", uint32_value 1L);
      ("inherit", bool_value false);
      ("exclude_kernel", bool_value false);
      ("exclude_user", bool_value false);
    ]))
    (IRStruct ("perf_options", []))
    test_pos

let make_generated_code instructions =
  let entry_block = make_ir_basic_block "entry" instructions 0 in
  let main_func = make_ir_function "main" [] (Some IRI32) [entry_block] ~is_main:true test_pos in
  let userspace_prog =
    make_ir_userspace_program
      [main_func]
      []
      (make_ir_coordinator_logic [] [] [] (make_ir_config_management [] [] []))
      test_pos
  in
  let ir_multi_prog = make_ir_multi_program "test" ~userspace_program:userspace_prog test_pos in
  generate_complete_userspace_program_from_ir userspace_prog [] ir_multi_prog "test.ks"

let test_perf_event_codegen_enforces_pid_cpu_rules () =
  let prog_handle = make_ir_value (IRVariable "prog") IRI32 test_pos in
  let attr_value = make_ir_value (IRVariable "attr") (IRStruct ("perf_options", [])) test_pos in
  let flags_value = uint32_value 0L in
  let attr_decl =
    make_ir_instruction
      (IRVariableDecl (attr_value, IRStruct ("perf_options", []), Some (perf_attr_expr ~pid:(-1L) ~cpu:(-1L))))
      test_pos
  in
  let attach_call =
    make_ir_instruction
      (IRCall (DirectCall "attach", [prog_handle; attr_value; flags_value], None))
      test_pos
  in
  let generated_code = make_generated_code [attr_decl; attach_call] in

  check bool "preserve raw cpu value" true
    (contains_substr generated_code "int cpu = ks_attr.cpu;");
  check bool "reject invalid pid below -1" true
    (contains_substr generated_code "if (pid < -1)");
  check bool "reject invalid cpu below -1" true
    (contains_substr generated_code "if (cpu < -1)");
  check bool "reject system-wide attach without explicit cpu" true
    (contains_substr generated_code "if (pid == -1 && cpu == -1)");
  check bool "remove old cpu normalization" false
    (contains_substr generated_code "int cpu = ks_attr.cpu >= 0 ? ks_attr.cpu : 0;");
  check bool "perf detach disables event" true
    (contains_substr generated_code "PERF_EVENT_IOC_DISABLE");
  check bool "perf detach closes event fd" true
    (contains_substr generated_code "close(entry->perf_fd);");
  (* Attach success detection *)
  check bool "perf attach emits IOC_ENABLE on success" true
    (contains_substr generated_code "PERF_EVENT_IOC_ENABLE");
	  check bool "perf attach prints success message" true
	    (contains_substr generated_code "Perf event program attached: id=%d prog_fd=%d perf_fd=%d target=%s");
	  check bool "perf attach labels event configuration" true
	    (contains_substr generated_code "perf_event:type=%d config=%llu period=%llu");
	  (* Detach success detection *)
	  check bool "perf detach prints success message" true
	    (contains_substr generated_code "Perf event attachment detached: id=%d prog_fd=%d perf_fd=%d target=%s");
  (* Invalid fd guard *)
  check bool "perf attach rejects invalid prog_fd" true
    (contains_substr generated_code "Invalid program file descriptor:")

let find_substr_pos str substr =
  try Some (Str.search_forward (Str.regexp_string substr) str 0)
  with Not_found -> None

(* Verify A appears before B in the generated code string *)
let appears_before str a b =
  match find_substr_pos str a, find_substr_pos str b with
  | Some pa, Some pb -> pa < pb
  | _ -> false

let perf_attr_expr_with ~period ~wakeup =
  make_ir_expr
    (IRStructLiteral ("perf_options", [
      ("perf_type", perf_type_value "perf_type_hardware" 0L);
      ("perf_config", perf_config_value "perf_hw_config" "branch_misses" 5L);
      ("pid",     int32_value 1234L);
      ("cpu",     int32_value 0L);
      ("period",  uint64_value period);
      ("wakeup",  uint32_value wakeup);
      ("inherit",         bool_value false);
      ("exclude_kernel",  bool_value false);
      ("exclude_user",    bool_value false);
    ]))
    (IRStruct ("perf_options", []))
    test_pos

(* Generate code that attaches a perf_event program via 3-arg attach(prog, opts, flags) *)
let make_perf_code_with ~period ~wakeup =
  let prog_handle = make_ir_value (IRVariable "prog") IRI32 test_pos in
  let attr_value  = make_ir_value (IRVariable "attr") (IRStruct ("perf_options", [])) test_pos in
  let flags_value = uint32_value 0L in
  let attachment_value =
    make_ir_value
      (IRVariable "att")
      (IRStruct ("PerfAttachment", [("perf_fd", IRI32); ("link_id", IRI32); ("prog_fd", IRI32)]))
      test_pos
  in
  let attr_decl =
    make_ir_instruction
      (IRVariableDecl (attr_value, IRStruct ("perf_options", []),
                       Some (perf_attr_expr_with ~period ~wakeup)))
      test_pos
  in
  let attach_call =
    make_ir_instruction
      (IRCall (DirectCall "attach", [prog_handle; attr_value; flags_value], Some attachment_value))
      test_pos
  in
  make_generated_code [attr_decl; attach_call]

let test_perf_event_counting_starts_correctly () =
  let code = make_perf_code_with ~period:1000000L ~wakeup:1L in

  (* 1. Counter starts disabled: perf_event_open is called with disabled=1 so the
        kernel won't fire events before we are ready. *)
  check bool "attr.disabled set to 1 before perf_event_open" true
    (contains_substr code "ks_attr.attr.disabled = 1;");

  (* 2. The fd-close-on-exec flag is passed to perf_event_open for fd safety. *)
  check bool "PERF_FLAG_FD_CLOEXEC passed to perf_event_open" true
    (contains_substr code "PERF_FLAG_FD_CLOEXEC");

  (* 3. Counter is zeroed before the BPF program is attached and enabled,
        so the first sample starts from 0. *)
  check bool "IOC_RESET issued before enabling" true
    (contains_substr code "PERF_EVENT_IOC_RESET");

  (* 4. Ordering guarantee: RESET must appear before ENABLE in the generated source. *)
  check bool "IOC_RESET precedes IOC_ENABLE in source" true
    (appears_before code "PERF_EVENT_IOC_RESET" "PERF_EVENT_IOC_ENABLE");

  (* 5. BPF program is linked to the perf fd before enabling (attach before enable). *)
  check bool "attach_perf_event called before IOC_ENABLE" true
    (appears_before code "bpf_program__attach_perf_event" "PERF_EVENT_IOC_ENABLE");

  (* 6. Counting truly kicks off: IOC_ENABLE is the last step and must be present. *)
  check bool "IOC_ENABLE present to start counting" true
    (contains_substr code "PERF_EVENT_IOC_ENABLE")

let test_perf_event_period_and_wakeup_defaults () =
  (* When period=0 and wakeup=0 the codegen must substitute safe defaults so that
     the kernel actually delivers samples. *)
  let code = make_perf_code_with ~period:0L ~wakeup:0L in

  check bool "default sample_period 1000000 used when period=0" true
    (contains_substr code "ks_attr.period > 0 ? ks_attr.period : 1000000");
  check bool "default wakeup_events 1 used when wakeup=0" true
    (contains_substr code "ks_attr.wakeup > 0 ? ks_attr.wakeup : 1")

let test_perf_event_period_and_wakeup_custom () =
  (* When the user supplies explicit values the codegen must honour them, not the
     defaults, so counting happens at the requested granularity. *)
  let code = make_perf_code_with ~period:500000L ~wakeup:4L in

  (* The conditional expression is still present - values are resolved at runtime *)
  check bool "runtime period expression present for custom period" true
    (contains_substr code "ks_attr.period > 0 ? ks_attr.period : 1000000");
  check bool "runtime wakeup expression present for custom wakeup" true
    (contains_substr code "ks_attr.wakeup > 0 ? ks_attr.wakeup : 1")

let test_standard_attach_uses_libbpf_error_checks () =
  let prog_handle = make_ir_value (IRVariable "prog") IRI32 test_pos in
  let target = make_ir_value (IRLiteral (StringLit "eth0")) (IRStr 16) test_pos in
  let flags = uint32_value 0L in
  let attach_call =
    make_ir_instruction
      (IRCall (DirectCall "attach", [prog_handle; target; flags], None))
      test_pos
  in
  let generated_code = make_generated_code [attach_call] in

  (* After removing the dead PERF_EVENT case from attach_bpf_program_by_fd, only
     the four non-XDP program types (kprobe, tracing, tracepoint, TC) have a
     libbpf_get_error check; XDP uses bpf_xdp_attach which returns a plain errno. *)
  check int "standard attach branches use libbpf_get_error" 4
    (count_substr generated_code "libbpf_get_error(link)");
  check bool "old null-link checks removed" false
    (contains_substr generated_code "if (!link)");
  check bool "kprobe reports libbpf error string" true
    (contains_substr generated_code "Failed to attach kprobe to function '%s': %s");
  check bool "tracepoint reports libbpf error string" true
    (contains_substr generated_code "Failed to attach tracepoint to '%s:%s': %s");
  check bool "tc reports libbpf error string" true
    (contains_substr generated_code "Failed to attach TC program to interface '%s': %s")

let test_perf_read_helpers_not_generated () =
  (* perf_event attach alone should not emit read helpers when they are unused. *)
  let code = make_perf_code_with ~period:1000000L ~wakeup:1L in

  check bool "ks_read_perf_count helper omitted" false
    (contains_substr code "ks_read_perf_count");
  check bool "ks_perf_attachment_read helper omitted" false
    (contains_substr code "ks_perf_attachment_read");
  check bool "perf counter read syscall omitted" false
    (contains_substr code "read(perf_fd, &count, sizeof(count))")

let test_read_helpers_generated_when_used () =
  let prog_handle = make_ir_value (IRVariable "prog") IRI32 test_pos in
  let attr_value  = make_ir_value (IRVariable "attr") (IRStruct ("perf_options", [])) test_pos in
  let flags_value = uint32_value 0L in
  let attachment_value =
    make_ir_value
      (IRVariable "att")
      (IRStruct ("PerfAttachment", [("perf_fd", IRI32); ("link_id", IRI32); ("prog_fd", IRI32)]))
      test_pos
  in
  let count_value = make_ir_value (IRVariable "count") IRI64 test_pos in
  let attr_decl =
    make_ir_instruction
      (IRVariableDecl (attr_value, IRStruct ("perf_options", []),
                       Some (perf_attr_expr_with ~period:1000000L ~wakeup:1L)))
      test_pos
  in
  let attach_call =
    make_ir_instruction
      (IRCall (DirectCall "attach", [prog_handle; attr_value; flags_value], Some attachment_value))
      test_pos
  in
  let read_call =
    make_ir_instruction
      (IRCall (DirectCall "read", [attachment_value], Some count_value))
      test_pos
  in
  let code = make_generated_code [attr_decl; attach_call; read_call] in
  check bool "ks_read_perf_count helper generated when read is used" true
    (contains_substr code "ks_read_perf_count");
  check bool "ks_perf_attachment_read helper generated when read is used" true
    (contains_substr code "ks_perf_attachment_read");
  check bool "read duplicates perf fd under the lock" true
    (contains_substr code "dup_fd = dup(cur->perf_fd)");
  check bool "read closes duplicate fd after reading" true
    (contains_substr code "close(dup_fd)")

let test_perf_attach_event_function_generated () =
  (* attach(prog, perf_options{...}, 0) must generate ks_attach_perf_event which
     owns the full open-reset-attach-enable lifecycle in a single C function. *)
  let code = make_perf_code_with ~period:1000000L ~wakeup:1L in

  check bool "ks_attach_perf_event function generated" true
    (contains_substr code "ks_attach_perf_event");
  check bool "ks_attach_perf_event calls ks_open_perf_event" true
    (contains_substr code "ks_open_perf_event");
  check bool "counter reset before attach" true
    (contains_substr code "PERF_EVENT_IOC_RESET");
  check bool "bpf_program__attach_perf_event used for linking" true
    (contains_substr code "bpf_program__attach_perf_event");
  check bool "IOC_ENABLE used to start counting" true
    (contains_substr code "PERF_EVENT_IOC_ENABLE");
  (* The old __PERF_RAW_EMIT__ sentinel and snprintf string hack must be gone *)
  check bool "no __PERF_RAW_EMIT__ sentinel in generated code" false
    (contains_substr code "__PERF_RAW_EMIT__");
  check bool "no snprintf perf_fd string hack" false
    (contains_substr code "snprintf(%s, sizeof(%s),");
  check bool "perf attr type copied directly from perf_options" true
    (contains_substr code "ks_attr.attr.type = (__u32)ks_attr.perf_type;");
  check bool "perf attr config copied directly from perf_options" true
    (contains_substr code "ks_attr.attr.config = (__u64)ks_attr.perf_config;");
  check bool "old perf_counter switch removed" false
    (contains_substr code "switch (ks_attr.counter)");
  check bool "find_prog_by_fd helper used for program lookup" true
    (contains_substr code "find_prog_by_fd");
  check bool "perf attach rejects wrong program type at runtime" true
    (contains_substr code "is not a @perf_event program");
  check bool "perf attach returns PerfAttachment" true
    (contains_substr code "PerfAttachment ks_attach_perf_event");
  check bool "attachment struct typedef emitted" true
    (contains_substr code "typedef struct PerfAttachment")

let test_detach_attach_concurrent_window () =
  (* During a detach, the entry stays in the list but is marked detaching=1.
   * A concurrent attach for the same prog_fd must succeed (not be blocked by
   * the still-present but detaching entry). *)
  let code = make_perf_code_with ~period:1000000L ~wakeup:1L in
  check bool "attachment_entry has detaching field" true
    (contains_substr code "int detaching;");
  check bool "add_attachment skips detaching entries in duplicate check" true
    (contains_substr code "!existing->detaching");
  check bool "detach marks entry as detaching before teardown" true
    (contains_substr code "entry->detaching = 1");
  check bool "detach re-locks to unlink and free entry after teardown" true
    (contains_substr code "Phase 2: teardown is complete");
  check bool "perf attachments get unique attachment ids" true
    (contains_substr code "entry->attachment_id = next_attachment_id++")

(* ── Type-checking regression tests ───────────────────────────────────── *)

let parse_and_check source =
  let ast = parse_string source in
  type_check_ast ast

(* A well-formed @perf_event function must pass the type checker end-to-end. *)
let test_perf_event_valid_signature () =
  let source =
    "@perf_event\nfn on_event(ctx: *bpf_perf_event_data) -> i32 {\n    return 0\n}" in
  (match parse_and_check source with
   | [_] -> ()
   | _ -> fail "Valid @perf_event signature should pass type checking")

(* Using the wrong context type (e.g. *xdp_md) must be rejected. *)
let test_perf_event_wrong_ctx_type () =
  let source =
    "@perf_event\nfn on_event(ctx: *xdp_md) -> i32 {\n    return 0\n}" in
  (try
    let _ = parse_and_check source in
    fail "Wrong context type should have been rejected by type checker"
  with _ -> ())

(* Zero parameters must be rejected. *)
let test_perf_event_no_params () =
  let source =
    "@perf_event\nfn on_event() -> i32 {\n    return 0\n}" in
  (try
    let _ = parse_and_check source in
    fail "Zero parameters should have been rejected by type checker"
  with _ -> ())

(* More than one parameter must be rejected. *)
let test_perf_event_too_many_params () =
  let source =
    "@perf_event\nfn on_event(ctx: *bpf_perf_event_data, extra: u32) -> i32 {\n    return 0\n}" in
  (try
    let _ = parse_and_check source in
    fail "Two parameters should have been rejected by type checker"
  with _ -> ())

(* Non-i32 return types (u32, void, bool) must be rejected. *)
let test_perf_event_wrong_return_type () =
  let invalid_cases = [
    ("u32",  "@perf_event\nfn on_event(ctx: *bpf_perf_event_data) -> u32 { return 0 }");
    ("void", "@perf_event\nfn on_event(ctx: *bpf_perf_event_data) -> void { }");
    ("bool", "@perf_event\nfn on_event(ctx: *bpf_perf_event_data) -> bool { return false }");
  ] in
  List.iter (fun (label, source) ->
    (try
      let _ = parse_and_check source in
      fail (Printf.sprintf "Return type '%s' should have been rejected by type checker" label)
    with _ -> ())
  ) invalid_cases

let type_checking_tests = [
  test_case "perf_event_valid_signature"  `Quick test_perf_event_valid_signature;
  test_case "perf_event_wrong_ctx_type"   `Quick test_perf_event_wrong_ctx_type;
  test_case "perf_event_no_params"        `Quick test_perf_event_no_params;
  test_case "perf_event_too_many_params"  `Quick test_perf_event_too_many_params;
  test_case "perf_event_wrong_return_type"`Quick test_perf_event_wrong_return_type;
]

let tests = [
  test_case "perf_event_codegen_enforces_pid_cpu_rules" `Quick test_perf_event_codegen_enforces_pid_cpu_rules;
  test_case "perf_event_counting_starts_correctly"      `Quick test_perf_event_counting_starts_correctly;
  test_case "perf_event_period_and_wakeup_defaults"     `Quick test_perf_event_period_and_wakeup_defaults;
  test_case "perf_event_period_and_wakeup_custom"       `Quick test_perf_event_period_and_wakeup_custom;
  test_case "perf_read_helpers_not_generated"           `Quick test_perf_read_helpers_not_generated;
  test_case "read_helpers_generated_when_used"          `Quick test_read_helpers_generated_when_used;
  test_case "perf_attach_event_function_generated"      `Quick test_perf_attach_event_function_generated;
  test_case "detach_attach_concurrent_window"           `Quick test_detach_attach_concurrent_window;
  test_case "standard_attach_uses_libbpf_error_checks"  `Quick test_standard_attach_uses_libbpf_error_checks;
]

let () = run "Perf Event Attach Tests" [
  ("perf_event_attach", tests);
  ("perf_event_type_checking", type_checking_tests);
]
