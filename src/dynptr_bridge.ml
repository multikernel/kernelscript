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

(** Bridge module connecting evaluator memory model with dynptr code generation *)

open Ir

(** Convert evaluator memory region to codegen memory region *)
let convert_evaluator_region_type = function
  | Evaluator.PacketDataRegion _ -> Ebpf_c_codegen.PacketData
  | Evaluator.MapValueRegion _ -> Ebpf_c_codegen.MapValue
  | Evaluator.StackRegion -> Ebpf_c_codegen.LocalStack
  | Evaluator.ContextRegion _ -> Ebpf_c_codegen.PacketData  (* Context access often packet-related *)
  | Evaluator.RegularMemoryRegion -> Ebpf_c_codegen.RegularMemory

(** Extract memory region information from evaluator context *)
let extract_memory_info_from_evaluator eval_ctx =
  let memory_info_map = Hashtbl.create 64 in
  
  (* Iterate through all variables and their addresses *)
  Hashtbl.iter (fun var_name addr ->
    match Evaluator.find_memory_region_by_address eval_ctx addr with
    | Some region_info ->
        let bounds = Evaluator.analyze_pointer_bounds eval_ctx addr in
        let enhanced_info = {
          Ebpf_c_codegen.region_type = convert_evaluator_region_type region_info.region_type;
          bounds_verified = bounds.verified;
          size_hint = if bounds.max_offset < max_int then Some bounds.max_offset else None;
        } in
        Hashtbl.add memory_info_map var_name enhanced_info
    | None -> ()  (* Skip variables without region info *)
  ) eval_ctx.variable_addresses;
  
  memory_info_map

(** Public API for dynptr integration *)

(** Compile with memory optimization - enhanced compilation pipeline *)
let compile_with_memory_optimization _ast symbol_table =
  let maps = Hashtbl.create 16 in
  let functions = Hashtbl.create 16 in
  let eval_ctx = Evaluator.create_eval_context symbol_table maps functions in
  
  (* Extract memory information from evaluator *)
  let memory_info = extract_memory_info_from_evaluator eval_ctx in
  
  (* Pass memory info to enhanced code generation *)
  Printf.printf "Enhanced compilation with %d memory regions\n" (Hashtbl.length memory_info);
  
  (* Return context for further processing *)
  eval_ctx

(** Analyze memory usage patterns for dynptr optimization *)
let analyze_memory_usage_patterns _eval_ctx ir_multi_program =
  let analysis_results = ref [] in
  
  (* Analyze each program *)
  List.iter (fun ir_prog ->
    Printf.printf "Analyzing memory patterns for program: %s\n" ir_prog.entry_function.func_name;
    
    (* Collect variable access patterns *)
    let var_access_counts = Hashtbl.create 32 in
    
    (* Simple analysis: count variable accesses *)
    let analyze_instructions instrs =
      List.iter (fun instr ->
        match instr.instr_desc with
        | IRAssign (dest_val, _expr) ->
            (match dest_val.value_desc with
             | IRVariable var_name ->
                 let count = try Hashtbl.find var_access_counts var_name with Not_found -> 0 in
                 Hashtbl.replace var_access_counts var_name (count + 1)
             | _ -> ())
        | _ -> ()  (* TODO: Add more instruction types *)
      ) instrs
    in
    
    (* Analyze all basic blocks *)
    List.iter (fun basic_block ->
      analyze_instructions basic_block.instructions
    ) ir_prog.entry_function.basic_blocks;
    
    (* Generate optimization recommendations *)
    Hashtbl.iter (fun var_name count ->
      if count > 3 then
        analysis_results := (var_name, Printf.sprintf "High access count (%d) - consider dynptr optimization" count) :: !analysis_results
    ) var_access_counts;
    
  ) ir_multi_program.programs;
  
  !analysis_results
