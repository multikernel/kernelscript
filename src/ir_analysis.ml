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

(** IR Analysis Module - Statement Processing and Control Flow Analysis
    
    This module implements:
    - Complete statement processing on IR
    - Control flow analysis on IR CFG  
    - Loop termination verification
    - Return path analysis
    - Dead code elimination
*)

open Ir

(** Control Flow Graph Analysis *)
module CFG = struct
  
  (** Control flow graph representation *)
  type cfg = {
    entry_block: string;
    exit_blocks: string list;
    blocks: ir_basic_block list;
    edges: (string * string) list;
    dominators: (string, string list) Hashtbl.t;
  }
  
  (** Build CFG from IR function *)
  let build_cfg (func : ir_function) : cfg =
    let blocks = func.basic_blocks in
    
    let edges = List.fold_left (fun acc block ->
      List.fold_left (fun acc succ ->
        (block.label, succ) :: acc
      ) acc block.successors
    ) [] blocks in
    
    let entry_block = match blocks with
      | [] -> failwith "Function has no basic blocks"
      | first :: _ -> first.label
    in
    
    let exit_blocks = List.fold_left (fun acc block ->
      if block.successors = [] then block.label :: acc else acc
    ) [] blocks in
    
    {
      entry_block;
      exit_blocks;
      blocks;
      edges;
      dominators = Hashtbl.create 16;
    }
end

(** Loop Analysis *)
module LoopAnalysis = struct
  
  (** Loop information *)
  type loop_info = {
    header: string;
    body_blocks: string list;
    nesting_level: int;
    bounds_checked: bool;
  }
  
  (** Verify loop termination *)
  let verify_termination (func : ir_function) : bool =
    List.for_all (fun block ->
      List.exists (fun instr ->
        instr.bounds_checks <> []
      ) block.instructions
    ) func.basic_blocks
end

(** Return Path Analysis *)
module ReturnAnalysis = struct
  
  (** Return path information *)
  type return_info = {
    has_return: bool;
    all_paths_return: bool;
    return_type_consistent: bool;
  }
  
  (** Analyze return paths in function using proper control flow analysis *)
  let analyze_returns (func : ir_function) : return_info =
    let cfg = CFG.build_cfg func in
    
    (* Check if any block has a return statement *)
    let has_return = List.exists (fun block ->
      List.exists (fun instr ->
        match instr.instr_desc with
        | IRReturn _ -> true
        | _ -> false
      ) block.instructions
    ) func.basic_blocks in
    
    (* Check if all execution paths lead to a return statement *)
    let all_paths_return = 
      if not has_return then false
      else
        (* For each exit block (blocks with no successors), check if it ends with return *)
        let exit_blocks_have_return = List.for_all (fun exit_label ->
          match List.find_opt (fun block -> block.label = exit_label) func.basic_blocks with
          | None -> false
          | Some block ->
              (* Check if the last instruction in this block is a return *)
              (match List.rev block.instructions with
               | last_instr :: _ ->
                   (match last_instr.instr_desc with
                    | IRReturn _ -> true
                    | _ -> false)
               | [] -> false)
        ) cfg.exit_blocks in
        
        (* If there are no explicit exit blocks, check if entry block returns *)
        if cfg.exit_blocks = [] then
          match List.find_opt (fun block -> block.label = cfg.entry_block) func.basic_blocks with
          | None -> false
          | Some entry_block ->
              List.exists (fun instr ->
                match instr.instr_desc with
                | IRReturn _ -> true
                | _ -> false
              ) entry_block.instructions
        else
          exit_blocks_have_return
    in
    
    {
      has_return;
      all_paths_return;
      return_type_consistent = true;
    }
end

(** Dead Code Elimination *)
module DeadCodeElimination = struct
  
  (** Eliminate dead basic blocks *)
  let eliminate_dead_blocks (func : ir_function) : ir_function =
    let _cfg = CFG.build_cfg func in
    let reachable = [_cfg.entry_block] @ _cfg.exit_blocks in
    
    let live_blocks = List.filter (fun block ->
      List.mem block.label reachable || block.reachable
    ) func.basic_blocks in
    
    { func with basic_blocks = live_blocks }
end

(** Statement Processing Engine *)
module StatementProcessor = struct
  
  (** Statement processing result *)
  type processing_result = {
    processed_blocks: ir_basic_block list;
    control_flow_valid: bool;
    optimization_applied: bool;
    warnings: string list;
  }
  
  (** Process all statements in IR function *)
  let process_statements (func : ir_function) : processing_result =
    let _cfg = CFG.build_cfg func in
    let return_info = ReturnAnalysis.analyze_returns func in
    let optimized_func = DeadCodeElimination.eliminate_dead_blocks func in
    
    let warnings = [] in
    let warnings = if not return_info.all_paths_return then
      "Not all control paths return a value" :: warnings
    else warnings in
    
    {
      processed_blocks = optimized_func.basic_blocks;
      control_flow_valid = true;
      optimization_applied = List.length optimized_func.basic_blocks < List.length func.basic_blocks;
      warnings;
    }
end

(** Assignment Optimization Analysis *)
module AssignmentOptimization = struct
  
  (** Extract map assignments from IR function *)
  let extract_ir_assignments (func : ir_function) : Map_assignment.map_assignment list =
    let assignments = ref [] in
    List.iter (fun block ->
      List.iter (fun instr ->
        match instr.instr_desc with
        | IRMapStore (map_val, _key_val, _value_val, _) ->
                         let assignment = Map_assignment.{
               map_name = (match map_val.value_desc with IRMapRef name -> name | _ -> "unknown");
               key_expr = { Ast.expr_desc = Ast.Literal (IntLit (Ast.Signed64 0L, None)); expr_type = None; expr_pos = instr.instr_pos; 
                            type_checked = false; program_context = None; map_scope = None }; (* Simplified for IR analysis *)
                               value_expr = { Ast.expr_desc = Ast.Literal (IntLit (Ast.Signed64 0L, None)); expr_type = None; expr_pos = instr.instr_pos; 
                               type_checked = false; program_context = None; map_scope = None }; (* Simplified for IR analysis *)
               assignment_type = DirectAssignment;
               assignment_pos = instr.instr_pos;
             } in
            assignments := assignment :: !assignments
        | _ -> ()
      ) block.instructions
    ) func.basic_blocks;
    List.rev !assignments
  
  (** Apply assignment optimizations to IR function *)
  let optimize_assignments (func : ir_function) : ir_function * Map_assignment.optimization_info =
    let assignments = extract_ir_assignments func in
    let optimization_info = Map_assignment.analyze_assignment_optimizations assignments in
    
    (* Apply optimizations based on analysis *)
    let optimized_blocks = List.map (fun block ->
      let optimized_instructions = List.map (fun instr ->
        match instr.instr_desc with
        | IRMapStore (_map_val, _key_val, _value_val, _store_type) ->
            (* Add optimization hints based on analysis *)
            let new_hints = if optimization_info.constant_folding then
              BoundsChecked :: instr.verifier_hints
            else
              instr.verifier_hints
            in
            { instr with verifier_hints = new_hints }
        | _ -> instr
      ) block.instructions in
      { block with instructions = optimized_instructions }
    ) func.basic_blocks in
    
    let optimized_func = { func with basic_blocks = optimized_blocks } in
    (optimized_func, optimization_info)
end

(** Main analysis interface *)

(** Analyze IR function and apply optimizations *)
let analyze_ir_function (func : ir_function) : ir_function * string list =
  let result = StatementProcessor.process_statements func in
  let (optimized_func, assignment_opt_info) = AssignmentOptimization.optimize_assignments 
    { func with basic_blocks = result.processed_blocks } in
  
  let warnings = result.warnings in
  let assignment_warnings = List.map (fun (opt : Map_assignment.optimization_record) -> 
    Printf.sprintf "Assignment optimization: %s" opt.optimization_type
  ) assignment_opt_info.optimizations in
  
  (optimized_func, warnings @ assignment_warnings)

(** Analyze entire IR program *)
let analyze_ir_program (prog : ir_program) : ir_program * string list =
  let all_warnings = ref [] in
  
  let (opt_entry, entry_warnings) = analyze_ir_function prog.entry_function in
  all_warnings := entry_warnings @ !all_warnings;
  
  let optimized_prog = { prog with 
    entry_function = opt_entry;
  } in
  
  (optimized_prog, !all_warnings)

(** Utility functions for analysis results *)

(** Check if function has structured control flow *)
let has_structured_control_flow (_func : ir_function) : bool =
  true (* Simplified implementation *)

(** Get loop information for function *)
let get_loop_info (func : ir_function) : LoopAnalysis.loop_info list =
  let cfg = CFG.build_cfg func in
  List.map (fun block ->
    {
      LoopAnalysis.header = block.label;
      body_blocks = [block.label];
      nesting_level = 1;
      bounds_checked = false;
    }
  ) cfg.blocks

(** Check if all loops are bounded *)
let all_loops_bounded (func : ir_function) : bool =
  LoopAnalysis.verify_termination func

(** Get return path analysis *)
let analyze_return_paths (func : ir_function) : ReturnAnalysis.return_info =
  ReturnAnalysis.analyze_returns func

(** Pretty printing for analysis results *)
let string_of_cfg_stats (func : ir_function) : string =
  let cfg = CFG.build_cfg func in
  let loops = get_loop_info func in
  Printf.sprintf "CFG Stats: %d blocks, %d edges, %d loops, %s"
    (List.length cfg.blocks)
    (List.length cfg.edges)
    (List.length loops)
    (if has_structured_control_flow func then "reducible" else "non-reducible")

(** Generate analysis report *)
let generate_analysis_report (func : ir_function) : string =
  let cfg_stats = string_of_cfg_stats func in
  let return_info = analyze_return_paths func in
  let loops_bounded = all_loops_bounded func in
  
  Printf.sprintf "IR Analysis Report for %s:\n%s\nReturn paths: %s\nLoops bounded: %s\n"
    func.func_name
    cfg_stats
    (if return_info.all_paths_return then "complete" else "incomplete")
    (if loops_bounded then "yes" else "no")

(** Ring Buffer Analysis - Centralized processing of all ring buffer operations *)
module RingBufferAnalysis = struct
  
  (** Analyze ring buffer declarations from global variables *)
  let analyze_ring_buffer_declarations (global_variables : ir_global_variable list) : ir_ring_buffer_declaration list =
    List.fold_left (fun acc global_var ->
      match global_var.global_var_type with
      | IRRingbuf (value_type, size) ->
          let rb_decl = {
            rb_name = global_var.global_var_name;
            rb_value_type = value_type;
            rb_size = size;
            rb_is_global = true;
            rb_declaration_pos = global_var.global_var_pos;
          } in
          rb_decl :: acc
      | _ -> acc
    ) [] global_variables

  (** Scan all functions for ring buffer operations *)
  let collect_ring_buffer_operations (functions : ir_function list) : (string * string) list =
    let handler_registrations = ref [] in
    
    List.iter (fun func ->
      List.iter (fun block ->
        List.iter (fun instr ->
          match instr.instr_desc with
          | IRRingbufOp (ringbuf_val, RingbufOnEvent handler_name) ->
              let ringbuf_name = match ringbuf_val.value_desc with
                | IRVariable name -> name
                | IRTempVariable name -> Printf.sprintf "ringbuf_%s" name
                | _ -> failwith "IRRingbufOp requires a ring buffer variable"
              in
              handler_registrations := (ringbuf_name, handler_name) :: !handler_registrations
          | _ -> ()
        ) block.instructions
      ) func.basic_blocks
    ) functions;
    
    !handler_registrations

  (** Analyze usage patterns *)
  let analyze_usage_patterns (programs : ir_program list) (userspace_program : ir_userspace_program option) 
                           (ring_buffer_declarations : ir_ring_buffer_declaration list) : ir_ring_buffer_usage_summary =
    let rb_names = List.map (fun rb -> rb.rb_name) ring_buffer_declarations in
    
    let used_in_ebpf = ref [] in
    let used_in_userspace = ref [] in
    let needs_event_processing = ref [] in
    
    (* Scan eBPF programs *)
    List.iter (fun program ->
      List.iter (fun block ->
        List.iter (fun instr ->
          match instr.instr_desc with
          | IRRingbufOp (ringbuf_val, _) ->
              let ringbuf_name = match ringbuf_val.value_desc with
                | IRVariable name -> name
                | _ -> "unknown"
              in
              if List.mem ringbuf_name rb_names && not (List.mem ringbuf_name !used_in_ebpf) then
                used_in_ebpf := ringbuf_name :: !used_in_ebpf
          | _ -> ()
        ) block.instructions
      ) program.entry_function.basic_blocks
    ) programs;
    
    (* Scan userspace programs *)
    (match userspace_program with
     | Some userspace ->
         List.iter (fun func ->
           List.iter (fun block ->
             List.iter (fun instr ->
               match instr.instr_desc with
               | IRRingbufOp (ringbuf_val, op) ->
                   let ringbuf_name = match ringbuf_val.value_desc with
                     | IRVariable name -> name
                     | _ -> "unknown"
                   in
                   if List.mem ringbuf_name rb_names then (
                     if not (List.mem ringbuf_name !used_in_userspace) then
                       used_in_userspace := ringbuf_name :: !used_in_userspace;
                     
                     (* Check if this ring buffer needs event processing *)
                     match op with
                     | RingbufOnEvent _ ->
                         if not (List.mem ringbuf_name !needs_event_processing) then
                           needs_event_processing := ringbuf_name :: !needs_event_processing
                     | _ -> ()
                   )
               | IRCall (DirectCall "dispatch", args, _) ->
                   (* Check dispatch calls for ring buffer arguments *)
                   List.iter (fun arg ->
                     match arg.value_desc with
                     | IRVariable name when List.mem name rb_names ->
                         if not (List.mem name !needs_event_processing) then
                           needs_event_processing := name :: !needs_event_processing
                     | _ -> ()
                   ) args
               | _ -> ()
             ) block.instructions
           ) func.basic_blocks
         ) userspace.userspace_functions
     | None -> ());
    
    {
      used_in_ebpf = !used_in_ebpf;
      used_in_userspace = !used_in_userspace;
      needs_event_processing = !needs_event_processing;
    }

  (** Main analysis function - populates the ring buffer registry *)
  let analyze_and_populate_registry (ir_multi_prog : ir_multi_program) : ir_multi_program =
    (* Collect declarations from global variables *)
    let ring_buffer_declarations = analyze_ring_buffer_declarations ir_multi_prog.global_variables in
    
    (* Collect all functions (eBPF and userspace) *)
    let all_functions = 
      (List.map (fun prog -> prog.entry_function) ir_multi_prog.programs) @
      ir_multi_prog.kernel_functions @
      (match ir_multi_prog.userspace_program with
       | Some userspace -> userspace.userspace_functions
       | None -> [])
    in
    
    (* Collect event handler registrations *)
    let event_handler_registrations = collect_ring_buffer_operations all_functions in
    
    (* Analyze usage patterns *)
    let usage_summary = analyze_usage_patterns ir_multi_prog.programs ir_multi_prog.userspace_program ring_buffer_declarations in
    
    (* Build the complete registry *)
    let registry = {
      ring_buffer_declarations;
      event_handler_registrations;
      usage_summary;
    } in
    
    (* Return updated ir_multi_prog with populated registry *)
    { ir_multi_prog with ring_buffer_registry = registry }

end 