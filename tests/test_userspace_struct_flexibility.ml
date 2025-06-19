open Alcotest
open Kernelscript.Parse

(** Helper function to check if generated code contains a pattern *)
let contains_pattern code pattern =
  try
    let regex = Str.regexp pattern in
    ignore (Str.search_forward regex code 0);
    true
  with Not_found -> false

(** Helper function to generate userspace code from a program *)
let generate_userspace_code_from_program program_text filename =
  let ast = parse_string program_text in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table filename in
  
  let temp_dir = Filename.temp_file "test_userspace_struct" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  let _output_file = Kernelscript.Userspace_codegen.generate_userspace_code_from_ir 
    ir ~output_dir:temp_dir filename in
  let generated_file = Filename.concat temp_dir (filename ^ ".c") in
  
  if Sys.file_exists generated_file then (
    let ic = open_in generated_file in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Cleanup *)
    Unix.unlink generated_file;
    Unix.rmdir temp_dir;
    
    content
  ) else (
    failwith "Failed to generate userspace code file"
  )

(** Test 1: Ensure global function main works with custom struct name "ServerConfig" *)
let test_global_function_main_with_different_struct_name () =
  let program_text = {|
map<u32, u64> server_stats : HashMap(32)

program server_monitor : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

struct ServerConfig {
    max_connections: u64,
    enable_logging: u32,
    port_number: u32,
}

fn main(settings: ServerConfig) -> i32 {
    if (settings.enable_logging > 0) {
        return settings.port_number
    }
    return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_server_config" in
    
    (* Check struct definition uses ServerConfig *)
    check bool "struct ServerConfig defined" true 
      (contains_pattern result "struct ServerConfig");
    
    (* Check function signature uses ServerConfig *)
    check bool "parse_arguments returns struct ServerConfig" true 
      (contains_pattern result "struct ServerConfig parse_arguments");
    
    (* Check variable uses settings parameter name *)
    check bool "variable declared as struct ServerConfig settings" true 
      (contains_pattern result "struct ServerConfig settings");
    
    (* Check getopt options include ServerConfig fields *)
    check bool "max_connections option exists" true 
      (contains_pattern result "\"max_connections\"");
    check bool "enable_logging option exists" true 
      (contains_pattern result "\"enable_logging\"");
    check bool "port_number option exists" true 
      (contains_pattern result "\"port_number\"");
    
    (* Check field access uses settings parameter name *)
    check bool "field access uses settings parameter name" true 
      (contains_pattern result "settings\\.enable_logging");
    check bool "field assignment uses settings parameter name" true 
      (contains_pattern result "settings\\.max_connections");
    
    (* Ensure NO hardcoded "Args", "args", "config", or "MyConfiguration" *)
    check bool "no hardcoded Args struct" false 
      (contains_pattern result "struct Args");
    check bool "no hardcoded MyConfiguration struct" false 
      (contains_pattern result "struct MyConfiguration");
    check bool "no hardcoded args variable" false 
      (contains_pattern result "Args args");
    check bool "no hardcoded config variable" false 
      (contains_pattern result "MyConfiguration config");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 2: Ensure global function main works with single-letter struct name *)
let test_global_function_main_with_minimal_struct_name () =
  let program_text = {|
map<u32, u64> minimal_map : HashMap(8)

program minimal_prog : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

struct X {
    a: u32,
    b: u32,
}

fn main(x: X) -> i32 {
    return x.a + x.b
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_minimal_struct" in
    
    (* Check struct definition uses X *)
    check bool "struct X defined" true 
      (contains_pattern result "struct X");
    
    (* Check function signature uses X *)
    check bool "parse_arguments returns struct X" true 
      (contains_pattern result "struct X parse_arguments");
    
    (* Check variable uses x parameter name *)
    check bool "variable declared as struct X x" true 
      (contains_pattern result "struct X x");
    
    (* Check getopt options include X fields *)
    check bool "field a option exists" true 
      (contains_pattern result "\"a\"");
    check bool "field b option exists" true 
      (contains_pattern result "\"b\"");
    
    (* Check field access uses x parameter name *)
    check bool "field access uses x.a" true 
      (contains_pattern result "x\\.a");
    check bool "field access uses x.b" true 
      (contains_pattern result "x\\.b");
    
  with
  | exn -> fail ("Test failed with exception: " ^ Printexc.to_string exn)

(** Test 3: Ensure compilation and validation still works with custom struct names *)
let test_global_function_main_validation_with_custom_struct () =
  let program_text = {|
map<u32, u64> validation_map : HashMap(16)

program validation_prog : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

struct CustomArgs {
    debug_level: u32,
    output_file: u32,
}

fn main(custom_args: CustomArgs) -> i32 {
    if (custom_args.debug_level > 0) {
        return 1
    }
    return 0
}
|} in
  
  try
    (* Test that parsing, type checking, and IR generation all work *)
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test_validation" in
    
    check bool "custom struct validation passes" true true;
    
  with
  | exn -> fail ("Validation failed with custom struct: " ^ Printexc.to_string exn)

(** Test 4: Verify argument parsing and assignment to IR variables works correctly *)
let test_argument_parsing_assignment_bug_fix () =
  let program_text = {|
program packet_filter : xdp {
    fn main(ctx: XdpContext) -> XdpAction {
        return 2
    }
}

struct Args {
    enable_debug: u32,
    interface: str<16>
}

fn main(args: Args) -> i32 {
    if (args.enable_debug > 0) {
        print("Debug mode enabled")
    }
    let prog = load_program(packet_filter)
    attach_program(prog, args.interface, 0)
    return 0
}
|} in
  
  try
    let result = generate_userspace_code_from_program program_text "test_arg_assignment" in
    
    (* 1. Check that arguments are parsed correctly *)
    check bool "parse_arguments generates struct Args" true 
      (contains_pattern result "struct Args parse_arguments");
    check bool "args variable declared correctly" true 
      (contains_pattern result "struct Args args = parse_arguments");
    
    (* 2. Check that parsed arguments are assigned to IR variables *)
    check bool "parsed args assigned to var_0" true 
      (contains_pattern result "var_0 = args;");
    
    (* 3. Check that IR variables use the struct fields correctly *)
    check bool "var_0.interface used for attach_program" true 
      (contains_pattern result "var_0\\.interface");
    check bool "var_0.enable_debug accessible" true 
      (contains_pattern result "var_0\\.enable_debug");
    
    (* 4. Check that string argument parsing uses strncpy (not atoi) *)
    check bool "interface uses strncpy not atoi" true 
      (contains_pattern result "strncpy(args\\.interface, optarg");
    check bool "interface does not use atoi" false 
      (contains_pattern result "args\\.interface.*atoi");
    
    (* 5. Check the assignment bridge exists (critical for the bug fix) *)
    check bool "assignment from args to var_0 exists" true 
      (contains_pattern result "// Copy parsed arguments to function variable");
    
    (* 6. Ensure no orphaned uninitialized var_0 usage *)
    let var_0_usage_count = 
      let rec count_matches pattern text start acc =
        try
          let pos = Str.search_forward (Str.regexp pattern) text start in
          count_matches pattern text (pos + 1) (acc + 1)
        with Not_found -> acc
      in
      count_matches "var_0\\." result 0 0
    in
    check bool "var_0 is used at least twice (enable_debug and interface)" true 
      (var_0_usage_count >= 2);
    
  with
  | exn -> fail ("Argument parsing assignment test failed: " ^ Printexc.to_string exn)

(** All global function struct flexibility tests *)
let global_function_struct_flexibility_tests = [
  "global_function_main_with_different_struct_name", `Quick, test_global_function_main_with_different_struct_name;
  "global_function_main_with_minimal_struct_name", `Quick, test_global_function_main_with_minimal_struct_name;
  "global_function_main_validation_with_custom_struct", `Quick, test_global_function_main_validation_with_custom_struct;
  "argument_parsing_assignment_bug_fix", `Quick, test_argument_parsing_assignment_bug_fix;
]

let () =
  run "KernelScript Global Function Struct Flexibility Tests" [
    "global_function_struct_flexibility", global_function_struct_flexibility_tests;
  ] 