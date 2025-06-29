(** Unit Tests for Dynptr Bridge Integration *)

open Kernelscript.Dynptr_bridge
open Kernelscript.Builtin_loader
open Kernelscript.Evaluator
open Alcotest

(** Test memory bridge integration *)
let test_memory_bridge_integration () =
  let test_name = "memory bridge integration" in
  
  (* Create a test evaluator context with builtin symbol table *)
  let maps = Hashtbl.create 16 in
  let functions = Hashtbl.create 16 in
  let empty_ast = [] in
  let symbol_table = build_symbol_table_with_builtins empty_ast in
  let eval_ctx = create_eval_context symbol_table maps functions in
  
  (* Add some test variables *)
  let packet_addr = allocate_variable_address eval_ctx "packet_ptr" (PointerValue 0x2000) in
  let map_addr = allocate_context_address eval_ctx "map_value" (IntValue 42) "map_value" in
  
  (* Verify addresses were allocated *)
  check bool (test_name ^ " - packet address allocated") true (packet_addr > 0);
  check bool (test_name ^ " - map address allocated") true (map_addr > 0);
  
  (* Extract memory info *)
  let memory_info = extract_memory_info_from_evaluator eval_ctx in
  
  (* Verify memory info was extracted *)
  check bool (test_name ^ " - memory info extracted") true (Hashtbl.length memory_info > 0);
  
  (* Verify specific variables were captured *)
  check bool (test_name ^ " - packet_ptr info exists") true (Hashtbl.mem memory_info "packet_ptr");
  check bool (test_name ^ " - map_value info exists") true (Hashtbl.mem memory_info "map_value");
  
  (* Verify memory region types *)
  (match Hashtbl.find_opt memory_info "packet_ptr" with
   | Some info -> 
       (match info.Kernelscript.Ebpf_c_codegen.region_type with
        | Kernelscript.Ebpf_c_codegen.PacketData -> 
            check bool (test_name ^ " - packet_ptr has PacketData region") true true
        | Kernelscript.Ebpf_c_codegen.LocalStack ->
            check bool (test_name ^ " - packet_ptr has LocalStack region (expected for variable allocation)") true true
        | _ -> 
            let region_str = match info.Kernelscript.Ebpf_c_codegen.region_type with
              | Kernelscript.Ebpf_c_codegen.PacketData -> "PacketData"
              | Kernelscript.Ebpf_c_codegen.MapValue -> "MapValue"  
              | Kernelscript.Ebpf_c_codegen.LocalStack -> "LocalStack"
              | Kernelscript.Ebpf_c_codegen.RegularMemory -> "RegularMemory"
              | Kernelscript.Ebpf_c_codegen.RingBuffer -> "RingBuffer"
            in
            fail (test_name ^ " - packet_ptr has unexpected region type: " ^ region_str))
   | None -> 
       fail (test_name ^ " - packet_ptr info not found"))

(** Test memory bridge with different region types *)
let test_different_memory_regions () =
  let test_name = "different memory regions" in
  
  (* Create evaluator context *)
  let maps = Hashtbl.create 16 in
  let functions = Hashtbl.create 16 in
  let empty_ast = [] in
  let symbol_table = build_symbol_table_with_builtins empty_ast in
  let eval_ctx = create_eval_context symbol_table maps functions in
  
  (* Add variables of different region types *)
  let _ = allocate_context_address eval_ctx "packet_data" (PointerValue 0x2000) "packet_data" in
  let _ = allocate_context_address eval_ctx "map_value" (IntValue 123) "map_value" in
  let _ = allocate_variable_address eval_ctx "local_var" (IntValue 456) in
  
  (* Extract memory info *)
  let memory_info = extract_memory_info_from_evaluator eval_ctx in
  
  (* Verify all variables are captured *)
  check int (test_name ^ " - all variables captured") 3 (Hashtbl.length memory_info);
  
  (* Verify different region types exist *)
  let has_packet_data = ref false in
  let has_map_value = ref false in
  let has_stack = ref false in
  
  Hashtbl.iter (fun _var_name info ->
    match info.Kernelscript.Ebpf_c_codegen.region_type with
    | Kernelscript.Ebpf_c_codegen.PacketData -> has_packet_data := true
    | Kernelscript.Ebpf_c_codegen.MapValue -> has_map_value := true  
    | Kernelscript.Ebpf_c_codegen.LocalStack -> has_stack := true
    | _ -> ()
  ) memory_info;
  
  check bool (test_name ^ " - has PacketData region") true !has_packet_data;
  check bool (test_name ^ " - has MapValue region") true !has_map_value;
  check bool (test_name ^ " - has LocalStack region") true !has_stack

(** Test error handling in bridge *)
let test_bridge_error_handling () =
  let test_name = "bridge error handling" in
  
  (* Create minimal evaluator context *)
  let maps = Hashtbl.create 16 in
  let functions = Hashtbl.create 16 in
  let empty_ast = [] in
  let symbol_table = build_symbol_table_with_builtins empty_ast in
  let eval_ctx = create_eval_context symbol_table maps functions in
  
  (* Extract memory info from empty context *)
  let memory_info = extract_memory_info_from_evaluator eval_ctx in
  
  (* Should handle empty context gracefully *)
  check int (test_name ^ " - empty context handled") 0 (Hashtbl.length memory_info)

let dynptr_bridge_tests = [
  "memory_bridge_integration", `Quick, test_memory_bridge_integration;
  "different_memory_regions", `Quick, test_different_memory_regions;  
  "bridge_error_handling", `Quick, test_bridge_error_handling;
]

let () =
  run "Dynptr Bridge Tests" [
    "dynptr_bridge", dynptr_bridge_tests;
  ] 