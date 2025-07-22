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
 
(*
 * Import System Tests for KernelScript
 * 
 * This test suite validates the unified import system introduced in commit 1482b7f.
 * The import system supports importing both KernelScript modules (.ks files) and 
 * external language modules (Python .py files) using a unified syntax:
 *
 * ```kernelscript
 * import utils from "./common/utils.ks"           // KernelScript import
 * import ml_analysis from "./ml/threat_analysis.py"  // Python import
 * ```
 *
 * Key Features Tested:
 * 
 * 1. **Unified Import Syntax**: Both KernelScript and Python modules use the same syntax
 * 2. **Automatic Type Detection**: File extension (.ks vs .py) determines import behavior
 * 3. **Symbol Extraction**: For KernelScript modules, extract exportable functions, types, etc.
 * 4. **Python FFI Bridging**: Generate C bridge code for Python function calls
 * 5. **Type Safety**: Module function calls are type-checked appropriately
 * 6. **Error Handling**: Proper error reporting for missing files, parse errors, etc.
 *
 * Architecture Overview:
 * - import_resolver.ml: Handles file resolution and symbol extraction
 * - userspace_codegen.ml: Generates FFI bridge code for Python modules
 * - type_checker.ml: Validates module function calls during compilation
 * - ast.ml: Extended with ImportDecl and ModuleCall expression types
 *
 * Test Structure:
 * - Basic functionality tests (parsing, type detection)
 * - Symbol extraction tests for KernelScript modules  
 * - Python module resolution and bridge generation
 * - Error handling for various failure cases
 * - Integration tests with complete import workflows
 *)

open Alcotest
open Kernelscript.Ast
open Kernelscript.Import_resolver

(** Test helper to create test position *)
let test_pos = { line = 1; column = 1; filename = "test.ks" }

(** Test helper to create a temporary file with content *)
let create_temp_file content extension =
  Random.self_init ();
  let temp_dir = Filename.get_temp_dir_name () in
  let timestamp = Unix.gettimeofday () in
  let random_id = Random.int 1000000 in
  let unique_name = Printf.sprintf "ks_test_%d_%.6f_%d" (Unix.getpid ()) timestamp random_id in
  let test_dir = Filename.concat temp_dir unique_name in
  
  let rec try_create_dir dir_name attempts =
    if attempts <= 0 then failwith "Could not create unique temporary directory";
    try
      Unix.mkdir dir_name 0o755;
      dir_name
    with Unix.Unix_error (Unix.EEXIST, _, _) ->
      let new_random = Random.int 1000000 in
      let new_unique_name = Printf.sprintf "ks_test_%d_%.6f_%d" (Unix.getpid ()) timestamp new_random in
      let new_test_dir = Filename.concat temp_dir new_unique_name in
      try_create_dir new_test_dir (attempts - 1)
  in
  
  let final_test_dir = try_create_dir test_dir 5 in
  let file_path = Filename.concat final_test_dir ("test" ^ extension) in
  let oc = open_out file_path in
  output_string oc content;
  close_out oc;
  file_path

(** Helper to cleanup a temporary file and its directory *)
let cleanup_temp_file file_path =
  try
    if Sys.file_exists file_path then Unix.unlink file_path;
    let dir_path = Filename.dirname file_path in
    if Sys.file_exists dir_path then Unix.rmdir dir_path
  with 
  | Unix.Unix_error _ -> () (* Ignore cleanup errors *)
  | Sys_error _ -> ()

(** Helper to cleanup multiple temporary files *)
let cleanup_temp_files file_paths =
  List.iter cleanup_temp_file file_paths

(** Test helper to parse KernelScript source *)
let parse_kernelscript source =
  let lexbuf = Lexing.from_string source in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Test Import Source Type Detection *)
let test_import_source_type_detection () =
  let test_cases = [
    ("./utils.ks", KernelScript);
    ("../helpers.py", Python);
    ("network_analysis.py", Python);
    ("common.ks", KernelScript);
  ] in
  
  List.iter (fun (path, expected_type) ->
    let actual_type = detect_import_source_type path in
    let type_to_string = function KernelScript -> "KernelScript" | Python -> "Python" in
    check string "source type" (type_to_string expected_type) (type_to_string actual_type)
  ) test_cases

(** Test Import Declaration Parsing *)
let test_import_declaration_parsing () =
  let test_cases = [
    ("import utils from \"./utils.ks\"", "utils", "./utils.ks", KernelScript);
    ("import ml_analysis from \"./analysis.py\"", "ml_analysis", "./analysis.py", Python);
  ] in
  
  List.iter (fun (source, expected_name, expected_path, expected_type) ->
    let full_source = source ^ "\nfn main() -> i32 { return 0 }" in
    let ast = parse_kernelscript full_source in
    match ast with
    | [ImportDecl import_decl; _] ->
        check string "module name" expected_name import_decl.module_name;
        check string "source path" expected_path import_decl.source_path;
        let actual_type = match import_decl.source_type with
          | KernelScript -> "KernelScript" 
          | Python -> "Python" in
        let expected_type_str = match expected_type with
          | KernelScript -> "KernelScript"
          | Python -> "Python" in
        check string "source type" expected_type_str actual_type
    | _ -> failwith "Expected ImportDecl followed by function"
  ) test_cases

(** Test KernelScript Symbol Extraction *)
let test_kernelscript_symbol_extraction () =
  let ks_source = {|
fn validate_config() -> bool {
    return true
}

fn get_status() -> u32 {
    return 42
}

@helper
fn calculate_hash(data: u32) -> u64 {
    return data * 2
}

struct NetworkInfo {
    packet_count: u32,
    byte_count: u64,
}

@private
fn internal_helper() -> i32 {
    return -1
}
|} in
  
  let temp_file = create_temp_file ks_source ".ks" in
  let main_file = Filename.concat (Filename.dirname temp_file) "main.ks" in
  let import_decl = make_import_declaration "test_module" (Filename.basename temp_file) test_pos in
  let resolved = resolve_import import_decl main_file in
  
  (* Check that symbols were extracted correctly *)
  let symbol_names = List.map (fun sym -> sym.symbol_name) resolved.ks_symbols in
  let expected_symbols = [
    "validate_config";  (* Global function *)
    "get_status";       (* Global function *)
    "calculate_hash";   (* Helper function *) 
    "NetworkInfo";      (* Struct *)
  ] in
  
  List.iter (fun expected ->
    if not (List.mem expected symbol_names) then
      failwith (Printf.sprintf "Expected symbol '%s' not found in extracted symbols" expected)
  ) expected_symbols;
  
  (* Check that private function is not exported *)
  if List.mem "internal_helper" symbol_names then
    failwith "Private function should not be exported";
  
  (* Check function signatures *)
  let validate_config_sym = List.find (fun sym -> sym.symbol_name = "validate_config") resolved.ks_symbols in
  (match validate_config_sym.symbol_type with
   | Function ([], Bool) -> () (* Expected signature *)
   | _ -> failwith "validate_config should have signature () -> bool");
   
  (* Cleanup *)
  cleanup_temp_file temp_file

(** Test Python Module Resolution *)
let test_python_module_resolution () =
  let py_source = {|
def get_default_mtu():
    return 1500

def calculate_bandwidth(packets_per_second, packet_size=1500):
    return packets_per_second * packet_size
|} in
  
  let temp_file = create_temp_file py_source ".py" in
  let main_file = Filename.concat (Filename.dirname temp_file) "main.ks" in
  let import_decl = make_import_declaration "network_utils" (Filename.basename temp_file) test_pos in
  let resolved = resolve_import import_decl main_file in
  
  (* Check resolved import properties *)
  check string "module name" "network_utils" resolved.module_name;
  (match resolved.source_type with
   | Python -> ()
   | KernelScript -> failwith "Expected Python source type");
   
  (* Python modules should have empty ks_symbols *)
  check int "ks_symbols count" 0 (List.length resolved.ks_symbols);
  
  (* Should have Python module info *)
  (match resolved.py_module_info with
   | Some py_info ->
       check string "module name" "network_utils" py_info.module_name;
       check string "module path" temp_file py_info.module_path
   | None -> failwith "Expected Python module info");
   
  (* Cleanup *)
  cleanup_temp_file temp_file

(** Test Import Error Handling *)
let test_import_error_handling () =
  (* Test file not found *)
  let import_decl = make_import_declaration "missing" "./nonexistent.ks" test_pos in
  try 
    let _ = resolve_import import_decl "." in
    failwith "Should have failed for missing file"
  with Import_error (msg, _) ->
    let not_found_regex = Str.regexp "not found" in
    if not (try ignore (Str.search_forward not_found_regex msg 0); true with Not_found -> false) then
      failwith ("Expected 'not found' error, got: " ^ msg)

(** Test KernelScript Module Validation *)
let test_kernelscript_module_validation () =
  (* Test 1: Module with main() function should fail *)
  let invalid_main_source = {|
fn helper_function() -> u32 {
    return 123
}

fn main() -> i32 {
    return 0
}
|} in
  
  let temp_main_file = create_temp_file invalid_main_source ".ks" in
  let main_file = Filename.concat (Filename.dirname temp_main_file) "main.ks" in
  let import_decl = make_import_declaration "invalid_main" (Filename.basename temp_main_file) test_pos in
  
  (try
    let _ = resolve_import import_decl main_file in
    failwith "Should have failed for module with main() function"
  with Import_error (msg, _) ->
    let main_regex = Str.regexp "cannot contain main() function" in
    if not (try ignore (Str.search_forward main_regex msg 0); true with Not_found -> false) then
      failwith ("Expected main() function error, got: " ^ msg));
  
  cleanup_temp_file temp_main_file;
  
  (* Test 2: Module with eBPF program should fail *)
  let invalid_ebpf_source = {|
fn helper_function() -> u32 {
    return 456
}

@xdp
fn packet_filter(ctx: *xdp_md) -> xdp_action {
    return XDP_PASS
}
|} in
  
  let temp_ebpf_file = create_temp_file invalid_ebpf_source ".ks" in
  let main_file2 = Filename.concat (Filename.dirname temp_ebpf_file) "main.ks" in
  let import_decl2 = make_import_declaration "invalid_ebpf" (Filename.basename temp_ebpf_file) test_pos in
  
  (try
    let _ = resolve_import import_decl2 main_file2 in
    failwith "Should have failed for module with attributed program"
  with Import_error (msg, _) ->
    let attr_regex = Str.regexp "cannot contain attributed program functions" in
    if not (try ignore (Str.search_forward attr_regex msg 0); true with Not_found -> false) then
      failwith ("Expected attributed program error, got: " ^ msg));
      
  cleanup_temp_file temp_ebpf_file;
  
  (* Test 3: Valid userspace-only module should succeed *)
  let valid_userspace_source = {|
fn calculate_checksum(data: *u8, length: u32) -> u32 {
    return length * 42
}

@helper
fn format_output(value: u32) -> u32 {
    return value + 1
}

struct ProcessingResult {
    status: u32,
    error_code: u32,
}

type PacketSize = u16
|} in
  
  let temp_valid_file = create_temp_file valid_userspace_source ".ks" in
  let main_file3 = Filename.concat (Filename.dirname temp_valid_file) "main.ks" in
  let import_decl3 = make_import_declaration "valid_userspace" (Filename.basename temp_valid_file) test_pos in
  
  let resolved = resolve_import import_decl3 main_file3 in
  check string "module name" "valid_userspace" resolved.module_name;
  check int "symbols count" 4 (List.length resolved.ks_symbols); (* calculate_checksum, format_output, ProcessingResult, PacketSize *)
  
  cleanup_temp_file temp_valid_file

(** Test Various Attributed Functions Validation *)
let test_attributed_functions_validation () =
  (* Test 1: Unsafe attributes should be rejected *)
  let unsafe_test_cases = ["@xdp"; "@kprobe"; "@custom_attr"] in
  
  List.iter (fun attr ->
    let invalid_source = Printf.sprintf {|
fn helper_function() -> u32 {
    return 789
}

%s
fn test_program(ctx: *void) -> i32 {
    return 0
}
|} attr in
    
    let temp_file = create_temp_file invalid_source ".ks" in
    let main_file = Filename.concat (Filename.dirname temp_file) "main.ks" in
    let import_decl = make_import_declaration "invalid_attr" (Filename.basename temp_file) test_pos in
    
    (try
      let _ = resolve_import import_decl main_file in
      failwith (Printf.sprintf "Should have failed for module with %s attribute" attr)
    with Import_error (msg, _) ->
      let attr_regex = Str.regexp "cannot contain attributed program functions" in
      if not (try ignore (Str.search_forward attr_regex msg 0); true with Not_found -> false) then
        failwith (Printf.sprintf "Expected attributed program error, got: %s" msg));
        
    cleanup_temp_file temp_file
  ) unsafe_test_cases;
  
  (* Test 2: Safe exportable attributes should be allowed and exported *)
  let exportable_test_cases = ["@helper"; "@kfunc"; "@test"] in
  
  List.iter (fun attr ->
    let valid_source = Printf.sprintf {|
fn regular_function() -> u32 {
    return 123
}

%s
fn safe_function() -> u32 {
    return 456
}
|} attr in
    
    let temp_file = create_temp_file valid_source ".ks" in
    let main_file = Filename.concat (Filename.dirname temp_file) "main.ks" in
    let import_decl = make_import_declaration "valid_attr" (Filename.basename temp_file) test_pos in
    
    let resolved = resolve_import import_decl main_file in
    check string "module name" "valid_attr" resolved.module_name;
    (* Should have both functions since safe attributes are allowed *)
    check int "symbols count" 2 (List.length resolved.ks_symbols);
        
    cleanup_temp_file temp_file
  ) exportable_test_cases;
  
  (* Test 3: Private functions should be allowed but not exported *)
  let private_source = {|
fn regular_function() -> u32 {
    return 123
}

@private
fn private_function() -> u32 {
    return 456
}
|} in
  
  let temp_file = create_temp_file private_source ".ks" in
  let main_file = Filename.concat (Filename.dirname temp_file) "main.ks" in
  let import_decl = make_import_declaration "private_test" (Filename.basename temp_file) test_pos in
  
  let resolved = resolve_import import_decl main_file in
  check string "module name" "private_test" resolved.module_name;
  (* Should only have 1 function since private functions are not exported *)
  check int "symbols count" 1 (List.length resolved.ks_symbols);
  
  cleanup_temp_file temp_file

(** Test Python Bridge Generation *)
let test_python_bridge_generation () =
  let py_import = {
    module_name = "network";
    source_type = Python;
    resolved_path = "./network.py";
    ks_symbols = [];
    py_module_info = Some { module_path = "./network.py"; module_name = "network" };
  } in
  
  let resolved_imports = [py_import] in
  
  (* Test Python bridge generation with empty IR programs *)
  let py_bridge = Kernelscript.Userspace_codegen.generate_mixed_bridge_code resolved_imports [] in
  
  (* Check that Python bridge contains module initialization *)
  let init_network_regex = Str.regexp "init_network_bridge" in
  if not (try ignore (Str.search_forward init_network_regex py_bridge 0); true with Not_found -> false) then
    failwith "Python bridge should contain initialization function";
    
  let python_h_regex = Str.regexp "#include <Python.h>" in
  if not (try ignore (Str.search_forward python_h_regex py_bridge 0); true with Not_found -> false) then
    failwith "Python bridge should include Python.h"

(** Test All Imports Resolution *)
let test_all_imports_resolution () =
  (* Create a simple KernelScript module *)
  let ks_source = "fn get_value() -> u32 { return 42 }" in
  let temp_ks_file = create_temp_file ks_source ".ks" in
  
  (* Create a Python module in the same directory *)
  let py_source = "def get_mtu():\n    return 1500" in
  let temp_dir = Filename.dirname temp_ks_file in
  let temp_py_file = Filename.concat temp_dir "test.py" in
  let oc_py = open_out temp_py_file in
  output_string oc_py py_source;
  close_out oc_py;
  
  (* Create main KernelScript program that imports both *)
  let main_source = Printf.sprintf {|
import utils from "%s"
import network from "%s"

fn main() -> i32 {
    return 0
}
|} (Filename.basename temp_ks_file) (Filename.basename temp_py_file) in
  
  let main_temp_file = Filename.concat temp_dir "main.ks" in
  let oc = open_out main_temp_file in
  output_string oc main_source;
  close_out oc;
  
  (* Parse and resolve imports *)
  let ast = parse_kernelscript main_source in
  let resolved_imports = resolve_all_imports ast main_temp_file in
  
  (* Verify that imports were resolved correctly *)
  check int "import count" 2 (List.length resolved_imports);
  
  let utils_import = List.find (fun imp -> imp.module_name = "utils") resolved_imports in
  (match utils_import.source_type with
   | KernelScript -> check int "utils symbols" 1 (List.length utils_import.ks_symbols)
   | Python -> failwith "utils should be KernelScript");
   
  let network_import = List.find (fun imp -> imp.module_name = "network") resolved_imports in
  (match network_import.source_type with
   | Python -> ()
   | KernelScript -> failwith "network should be Python");
   
  (* Cleanup *)
  cleanup_temp_files [temp_ks_file; temp_py_file; main_temp_file]

(** Test Suite *)
let import_tests = [
  test_case "Import source type detection" `Quick test_import_source_type_detection;
  test_case "Import declaration parsing" `Quick test_import_declaration_parsing;
  test_case "KernelScript symbol extraction" `Quick test_kernelscript_symbol_extraction;
  test_case "Python module resolution" `Quick test_python_module_resolution;
  test_case "Import error handling" `Quick test_import_error_handling;
  test_case "KernelScript module validation" `Quick test_kernelscript_module_validation;
  test_case "Attributed functions validation" `Quick test_attributed_functions_validation;
  test_case "Python bridge generation" `Quick test_python_bridge_generation;
  test_case "All imports resolution" `Quick test_all_imports_resolution;
]

let () =
  run "Import System Tests" [
    ("Import System", import_tests);
  ] 