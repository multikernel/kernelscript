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

open Kernelscript
open Ast

let contains_substring s sub =
  let len_s = String.length s in
  let len_sub = String.length sub in
  let rec check i =
    if i + len_sub > len_s then false
    else if String.sub s i len_sub = sub then true
    else check (i + 1)
  in
  check 0

let test_parse_pinned_globals () =
  let program_text = {|
pin var session_count: u64 = 0
pin var debug_enabled: bool = false
var temp_buffer: str(256) = "temporary"
local var internal_counter: u32 = 42

@xdp
fn packet_filter(ctx: *xdp_md) -> u32 {
    session_count = session_count + 1
    if (debug_enabled) {
        print("Session count: %d", session_count)
    }
    return 0
}
|} in
  
  let ast = try Parse.parse_string program_text with
    | exn -> failwith ("Parse error: " ^ Printexc.to_string exn)
  in
  
  (* Find pinned global variables *)
  let pinned_vars = List.filter_map (function
    | GlobalVarDecl gv when gv.is_pinned -> Some gv
    | _ -> None
  ) ast in
  
  (* Find regular global variables *)
  let regular_vars = List.filter_map (function
    | GlobalVarDecl gv when not gv.is_pinned && not gv.is_local -> Some gv
    | _ -> None
  ) ast in
  
  (* Find local variables *)
  let local_vars = List.filter_map (function
    | GlobalVarDecl gv when gv.is_local -> Some gv
    | _ -> None
  ) ast in
  
  (* Verify we have the expected variables *)
  assert (List.length pinned_vars = 2);
  assert (List.length regular_vars = 1);
  assert (List.length local_vars = 1);
  
  (* Check specific pinned variables *)
  let session_count = List.find (fun gv -> gv.global_var_name = "session_count") pinned_vars in
  let debug_enabled = List.find (fun gv -> gv.global_var_name = "debug_enabled") pinned_vars in
  
  assert (session_count.is_pinned = true);
  assert (session_count.is_local = false);
  assert (debug_enabled.is_pinned = true);
  assert (debug_enabled.is_local = false);
  
  Printf.printf "✅ Pinned globals parsing test passed\n"

let test_invalid_pin_local () =
  let program_text = {|
pin local var invalid_var: u32 = 123
|} in
  
  (* This should fail at type checking, not parsing *)
  try
    let ast = Parse.parse_string program_text in
    let symbol_table = Symbol_table.create_symbol_table () in
    let _ctx = Type_checker.type_check_ast ~symbol_table:(Some symbol_table) ast in
    failwith "Expected type error for pin local var"
  with
  | Type_checker.Type_error (msg, _) ->
      assert (contains_substring msg "Cannot pin local variables");
      Printf.printf "✅ Pin local validation test passed\n"
  | exn ->
      failwith ("Unexpected error: " ^ Printexc.to_string exn)

let test_ebpf_codegen_pinned_globals () =
  let program_text = {|
pin var global_counter: u64 = 0
pin var enable_logging: bool = true

@xdp  
fn test_program(ctx: *xdp_md) -> u32 {
    global_counter = global_counter + 1
    if (enable_logging) {
        print("Counter: %d", global_counter)
    }
    return 0
}
|} in
  
  let ast = Parse.parse_string program_text in
  let symbol_table = Symbol_table.create_symbol_table () in
  let ctx = Type_checker.type_check_ast ~symbol_table:(Some symbol_table) ast in
  let ir_multi_prog = Ir_generator.generate_ir ctx symbol_table "test_pinned_globals" in
  
  (* Generate eBPF C code *)
  let ebpf_code = Ebpf_c_codegen.generate_c_multi_program ir_multi_prog in
  
  (* Verify the generated code contains pinned globals structures *)
  assert (contains_substring ebpf_code "struct __pinned_globals");
  assert (contains_substring ebpf_code "global_counter");
  assert (contains_substring ebpf_code "enable_logging");
  assert (contains_substring ebpf_code "__pinned_globals SEC(\".maps\")");
  assert (contains_substring ebpf_code "get_pinned_globals");
  assert (contains_substring ebpf_code "update_pinned_globals");
  
  (* Verify transparent access is generated *)
  assert (contains_substring ebpf_code "__pg->global_counter");
  assert (contains_substring ebpf_code "__pg->enable_logging");
  
  Printf.printf "✅ eBPF codegen pinned globals test passed\n"

let test_ir_generation_pinned_globals () =
  let program_text = {|
pin var shared_state: u32 = 42
var regular_var: u32 = 10

@xdp
fn test_func(ctx: *xdp_md) -> u32 {
    shared_state = shared_state + regular_var
    return 0
}
|} in
  
  let ast = Parse.parse_string program_text in
  let symbol_table = Symbol_table.create_symbol_table () in
  let ctx = Type_checker.type_check_ast ~symbol_table:(Some symbol_table) ast in
  let ir_multi_prog = Ir_generator.generate_ir ctx symbol_table "test_ir_generation" in
  
  (* Find the pinned global variable in IR *)
  let pinned_global = List.find (fun gv -> gv.Ir.global_var_name = "shared_state") ir_multi_prog.Ir.global_variables in
  let regular_global = List.find (fun gv -> gv.Ir.global_var_name = "regular_var") ir_multi_prog.Ir.global_variables in
  
  assert (pinned_global.Ir.is_pinned = true);
  assert (pinned_global.Ir.is_local = false);
  assert (regular_global.Ir.is_pinned = false);
  assert (regular_global.Ir.is_local = false);
  
  Printf.printf "✅ IR generation pinned globals test passed\n"

let run_tests () =
  Printf.printf "Running pinned global variables tests...\n";
  test_parse_pinned_globals ();
  test_invalid_pin_local ();
  test_ebpf_codegen_pinned_globals ();
  test_ir_generation_pinned_globals ();
  Printf.printf "✅ All pinned globals tests passed!\n"

let () = run_tests () 