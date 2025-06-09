open Kernelscript.Ast

(** Test position tracking *)
let test_position () =
  let pos = make_position 10 25 "test.ks" in
  let pos_str = string_of_position pos in
  let expected = "test.ks:10:25" in
  if pos_str = expected then
    Printf.printf "✓ Position tracking test passed\n"
  else
    Printf.printf "✗ Position tracking test failed: expected '%s', got '%s'\n" expected pos_str

(** Test literal creation and pretty-printing *)
let test_literals () =
  let tests = [
    (IntLit 42, "42");
    (StringLit "hello", "\"hello\"");
    (CharLit 'a', "'a'");
    (BoolLit true, "true");
    (BoolLit false, "false");
  ] in
  let all_passed = List.for_all (fun (lit, expected) ->
    let result = string_of_literal lit in
    result = expected
  ) tests in
  if all_passed then
    Printf.printf "✓ Literals test passed\n"
  else
    Printf.printf "✗ Literals test failed\n"

(** Test BPF type system *)
let test_bpf_types () =
  let tests = [
    (U8, "u8");
    (U32, "u32");
    (Bool, "bool");
    (Array (U8, 10), "[u8; 10]");
    (Pointer U32, "*u32");
    (UserType "CustomType", "CustomType");
  ] in
  let all_passed = List.for_all (fun (typ, expected) ->
    let result = string_of_bpf_type typ in
    result = expected
  ) tests in
  if all_passed then
    Printf.printf "✓ BPF types test passed\n"
  else
    Printf.printf "✗ BPF types test failed\n"

(** Test expression creation and pretty-printing *)
let test_expressions () =
  let pos = make_position 1 1 "test.ks" in
  
  (* Simple literal expression *)
  let literal_expr = make_expr (Literal (IntLit 42)) pos in
  let literal_str = string_of_expr literal_expr in
  
  (* Identifier expression *)
  let id_expr = make_expr (Identifier "x") pos in
  let id_str = string_of_expr id_expr in
  
  (* Binary operation: x + 42 *)
  let binary_expr = make_expr (BinaryOp (id_expr, Add, literal_expr)) pos in
  let binary_str = string_of_expr binary_expr in
  
  (* Function call: func(x, 42) *)
  let call_expr = make_expr (FunctionCall ("func", [id_expr; literal_expr])) pos in
  let call_str = string_of_expr call_expr in
  
  let tests_passed = 
    literal_str = "42" &&
    id_str = "x" &&
    binary_str = "(x + 42)" &&
    call_str = "func(x, 42)" in
    
  if tests_passed then
    Printf.printf "✓ Expressions test passed\n"
  else (
    Printf.printf "✗ Expressions test failed\n";
    Printf.printf "  literal: %s\n" literal_str;
    Printf.printf "  id: %s\n" id_str;
    Printf.printf "  binary: %s\n" binary_str;
    Printf.printf "  call: %s\n" call_str
  )

(** Test statement creation *)
let test_statements () =
  let pos = make_position 1 1 "test.ks" in
  
  (* Declaration: let x = 42; *)
  let decl_stmt = make_stmt (Declaration ("x", None, make_expr (Literal (IntLit 42)) pos)) pos in
  let decl_str = string_of_stmt decl_stmt in
  
  (* Assignment: x = 10; *)
  let assign_stmt = make_stmt (Assignment ("x", make_expr (Literal (IntLit 10)) pos)) pos in
  let assign_str = string_of_stmt assign_stmt in
  
  (* Return: return x; *)
  let return_stmt = make_stmt (Return (Some (make_expr (Identifier "x") pos))) pos in
  let return_str = string_of_stmt return_stmt in
  
  let tests_passed = 
    decl_str = "let x = 42;" &&
    assign_str = "x = 10;" &&
    return_str = "return x;" in
    
  if tests_passed then
    Printf.printf "✓ Statements test passed\n"
  else (
    Printf.printf "✗ Statements test failed\n";
    Printf.printf "  decl: %s\n" decl_str;
    Printf.printf "  assign: %s\n" assign_str;
    Printf.printf "  return: %s\n" return_str
  )

(** Test function definition *)
let test_function_def () =
  let pos = make_position 1 1 "test.ks" in
  
  (* fn main(ctx: UserType) -> U32 { return 0; } *)
  let params = [("ctx", UserType "XdpContext")] in
  let return_type = Some U32 in
  let body = [
    make_stmt (Return (Some (make_expr (Literal (IntLit 0)) pos))) pos
  ] in
  let func = make_function "main" params return_type body pos in
  let func_str = string_of_function func in
  
  let expected_contains = ["fn main"; "ctx: XdpContext"; "-> u32"; "return 0;"] in
  let all_found = List.for_all (fun substr -> 
    try
      let _ = Str.search_forward (Str.regexp_string substr) func_str 0 in
      true
    with Not_found -> false
  ) expected_contains in
  
  if all_found then
    Printf.printf "✓ Function definition test passed\n"
  else (
    Printf.printf "✗ Function definition test failed\n";
    Printf.printf "  function: %s\n" func_str
  )

(** Test program definition *)
let test_program_def () =
  let pos = make_position 1 1 "test.ks" in
  
  (* Simple main function *)
  let main_func = make_function "main" [("ctx", UserType "XdpContext")] 
    (Some (UserType "XdpAction"))
    [make_stmt (Return (Some (make_expr (Identifier "XdpAction::Pass") pos))) pos]
    pos in
    
  (* Program definition *)
  let program = make_program "test_program" Xdp [main_func] pos in
  let prog_str = string_of_program program in
  
  let expected_parts = ["program test_program"; "xdp"; "fn main"; "XdpContext"; "XdpAction"] in
  let contains_all = List.for_all (fun part ->
    try
      let _ = Str.search_forward (Str.regexp_string part) prog_str 0 in
      true
    with Not_found -> false
  ) expected_parts in
  
  if contains_all then
    Printf.printf "✓ Program definition test passed\n"
  else (
    Printf.printf "✗ Program definition test failed\n";
    Printf.printf "  program: %s\n" prog_str
  )

(** Test complete AST creation *)
let test_complete_ast () =
  let pos = make_position 1 1 "test.ks" in
  
  (* Create a simple program *)
  let main_func = make_function "main" [("ctx", UserType "XdpContext")] 
    (Some (UserType "XdpAction"))
    [
      make_stmt (Declaration ("x", Some U32, make_expr (Literal (IntLit 42)) pos)) pos;
      make_stmt (Return (Some (make_expr (Identifier "XdpAction::Pass") pos))) pos;
    ]
    pos in
    
  let program = make_program "complete_test" Xdp [main_func] pos in
  let ast = [Program program] in
  let ast_str = string_of_ast ast in
  
  (* Check that the AST string contains key elements *)
  let key_elements = ["program complete_test"; "xdp"; "fn main"; "let x: u32 = 42"] in
  let all_present = List.for_all (fun elem ->
    try
      let _ = Str.search_forward (Str.regexp_string elem) ast_str 0 in
      true
    with Not_found -> false
  ) key_elements in
  
  if all_present then
    Printf.printf "✓ Complete AST test passed\n"
  else (
    Printf.printf "✗ Complete AST test failed\n";
    Printf.printf "  AST: %s\n" ast_str
  )

(** Test operator precedence representation *)
let test_operators () =
  let tests = [
    (Add, "+");
    (Sub, "-");
    (Mul, "*");
    (Eq, "==");
    (Ne, "!=");
    (And, "&&");
    (Or, "||");
  ] in
  
  let all_passed = List.for_all (fun (op, expected) ->
    let result = string_of_binary_op op in
    result = expected
  ) tests in
  
  if all_passed then
    Printf.printf "✓ Operators test passed\n"
  else
    Printf.printf "✗ Operators test failed\n"

(** Test extended type system with advanced type definitions *)
let test_extended_types () =
  let tests = [
    (* Built-in context types *)
    (XdpContext, "xdp_context");
    (TcContext, "tc_context");
    (KprobeContext, "kprobe_context");  
    (UprobeContext, "uprobe_context");
    (TracepointContext, "tracepoint_context");
    (LsmContext, "lsm_context");
    (CgroupSkbContext, "cgroup_skb_context");
    (XdpAction, "xdp_action");
    (TcAction, "tc_action");
    (* Extended types *)
    (Struct "PacketData", "struct PacketData");
    (Enum "Action", "enum Action");
    (Option U32, "option u32");
    (Result (U32, Struct "Error"), "result (u32, struct Error)");
    (Function ([U32; Bool], U64), "function (u32, bool) -> u64");
    (Map (U32, U64, HashMap), "map (u32, u64, hash_map)");
    (Map (Struct "Key", Option (Struct "Value"), Array), "map (struct Key, option struct Value, array)");
  ] in
  
  let all_passed = List.for_all (fun (typ, expected) ->
    let result = string_of_bpf_type typ in
    result = expected
  ) tests in
  
  if all_passed then
    Printf.printf "✓ Extended types test passed\n"
  else (
    Printf.printf "✗ Extended types test failed\n";
    List.iter (fun (typ, expected) ->
      let result = string_of_bpf_type typ in
      if result <> expected then
        Printf.printf "  %s: expected '%s', got '%s'\n" 
          (match typ with 
           | Struct name -> "Struct " ^ name 
           | _ -> "type") expected result
    ) tests
  )

(** Test type definitions *)
let test_type_definitions () =
  (* Test struct definition *)
  let struct_def = StructDef ("PacketInfo", [
    ("src_ip", U32);
    ("dst_ip", U32);
    ("protocol", U8);
    ("payload_len", U16);
  ]) in
  let struct_str = string_of_declaration (TypeDef struct_def) in
  
  (* Test enum definition *)
  let enum_def = make_enum_def "Action" [
    ("Pass", None);
    ("Drop", None);
    ("Redirect", Some 10);
  ] in
  let enum_str = string_of_declaration (TypeDef enum_def) in
  
  (* Test type alias *)
  let alias_def = make_type_alias "IpAddr" U32 in
  let alias_str = string_of_declaration (TypeDef alias_def) in
  
  let struct_valid = String.length struct_str > 0 && 
    (try let _ = Str.search_forward (Str.regexp_string "struct PacketInfo") struct_str 0 in true
     with Not_found -> false) in
  let enum_valid = String.length enum_str > 0 &&
    (try let _ = Str.search_forward (Str.regexp_string "enum Action") enum_str 0 in true
     with Not_found -> false) in
  let alias_valid = String.length alias_str > 0 &&
    (try let _ = Str.search_forward (Str.regexp_string "type IpAddr = u32") alias_str 0 in true
     with Not_found -> false) in
  
  if struct_valid && enum_valid && alias_valid then
    Printf.printf "✓ Type definitions test passed\n"
  else (
    Printf.printf "✗ Type definitions test failed\n";
    if not struct_valid then Printf.printf "  struct failed: %s\n" struct_str;
    if not enum_valid then Printf.printf "  enum failed: %s\n" enum_str;
    if not alias_valid then Printf.printf "  alias failed: %s\n" alias_str
  )

(** Test map declarations *)
let test_map_declarations () =
  let pos = make_position 1 1 "test.ks" in
  
  (* Test map configuration *)
  let config = make_map_config 1024 ~key_size:4 ~value_size:8 [
    Pinned "/sys/fs/bpf/my_map";
    ReadOnly;
  ] in
  
  (* Test map declaration *)
  let map_decl = make_map_declaration "packet_count" U32 U64 HashMap config true pos in
  let map_str = string_of_declaration (MapDecl map_decl) in
  
  let expected_parts = [
    "map<u32, u64>";
    "packet_count";
    "hash_map";
    "max_entries = 1024";
    "pinned = \"/sys/fs/bpf/my_map\"";
    "read_only";
  ] in
  
  let all_found = List.for_all (fun part ->
    try let _ = Str.search_forward (Str.regexp_string part) map_str 0 in true
    with Not_found -> false
  ) expected_parts in
  
  if all_found then
    Printf.printf "✓ Map declarations test passed\n"
  else (
    Printf.printf "✗ Map declarations test failed\n";
    Printf.printf "  map string: %s\n" map_str;
    List.iter (fun part ->
      try let _ = Str.search_forward (Str.regexp_string part) map_str 0 in ()
      with Not_found -> Printf.printf "  missing: %s\n" part
    ) expected_parts
  )

(** Test map types *)
let test_map_types () =
  let tests = [
    (HashMap, "hash_map");
    (Array, "array");
    (PercpuHash, "percpu_hash");
    (PercpuArray, "percpu_array");
    (LruHash, "lru_hash");
    (RingBuffer, "ring_buffer");
    (PerfEvent, "perf_event");
  ] in
  
  let all_passed = List.for_all (fun (map_type, expected) ->
    let result = string_of_map_type map_type in
    result = expected
  ) tests in
  
  if all_passed then
    Printf.printf "✓ Map types test passed\n"
  else
    Printf.printf "✗ Map types test failed\n"

(** Test comprehensive advanced type system scenario *)
let test_comprehensive_type_system () =
  let pos = make_position 1 1 "comprehensive_test.ks" in
  
  (* Create a comprehensive AST with all new features *)
  let struct_def = TypeDef (StructDef ("PacketInfo", [
    ("src_ip", U32);
    ("dst_ip", U32);
    ("protocol", U8);
  ])) in
  
  let enum_def = TypeDef (make_enum_def "FilterAction" [
    ("Allow", Some 0);
    ("Block", Some 1);
    ("Log", Some 2);
  ]) in
  
  let alias_def = TypeDef (make_type_alias "Counter" U64) in
  
  let config = make_map_config 1024 [Pinned "/sys/fs/bpf/packet_map"] in
  let map_decl = MapDecl (make_map_declaration "packet_stats" 
    (Struct "PacketInfo") (UserType "Counter") HashMap config true pos) in
  
  (* Function using new types *)
  let main_func = make_function "process_packet" 
    [("ctx", XdpContext); ("info", Struct "PacketInfo")]
    (Some XdpAction)
    [
      make_stmt (Declaration ("action", Some (Enum "FilterAction"), 
        make_expr (Identifier "FilterAction::Allow") pos)) pos;
      make_stmt (Return (Some (make_expr (Identifier "XdpAction::Pass") pos))) pos;
    ]
    pos in
    
  let program = make_program "packet_filter" Xdp [main_func] pos in
  
  let ast = [struct_def; enum_def; alias_def; map_decl; Program program] in
  let ast_str = string_of_ast ast in
  
  let key_features = [
    "struct PacketInfo";
    "enum FilterAction";
    "type Counter = u64";
    "map<struct PacketInfo, Counter>";
    "xdp_context";
    "xdp_action";
    "hash_map";
  ] in
  
  let all_present = List.for_all (fun feature ->
    try let _ = Str.search_forward (Str.regexp_string feature) ast_str 0 in true
    with Not_found -> false
  ) key_features in
  
  if all_present then
    Printf.printf "✓ Comprehensive type system test passed\n"
  else (
    Printf.printf "✗ Comprehensive type system test failed\n";
    Printf.printf "Generated AST:\n%s\n" ast_str;
    List.iter (fun feature ->
      try let _ = Str.search_forward (Str.regexp_string feature) ast_str 0 in ()
      with Not_found -> Printf.printf "  missing feature: %s\n" feature
    ) key_features
  )

let run_tests () =
  Printf.printf "Running KernelScript AST Tests\n";
  Printf.printf "==============================\n\n";
  test_position ();
  test_literals ();
  test_bpf_types ();
  test_expressions ();
  test_statements ();
  test_function_def ();
  test_program_def ();
  test_complete_ast ();
  test_operators ();
  test_extended_types ();
  test_type_definitions ();
  test_map_declarations ();
  test_map_types ();
  test_comprehensive_type_system ();
  Printf.printf "\nAST tests completed.\n"

let () = run_tests () 