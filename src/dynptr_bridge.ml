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

(** Enhanced compilation function that uses evaluator memory information *)
let compile_with_memory_optimization ?eval_ctx ir_multi_program =
  match eval_ctx with
  | Some ctx ->
      (* Extract memory information from evaluator *)
      let memory_info_map = extract_memory_info_from_evaluator ctx in
      Printf.printf "Enhanced dynptr compilation: using memory info for %d variables\n" 
        (Hashtbl.length memory_info_map);
      
      (* TODO: Pass memory_info_map to the code generation functions *)
      (* For now, just use the regular compilation *)
      Ebpf_c_codegen.compile_multi_to_c ir_multi_program
      
  | None ->
      Printf.printf "Regular dynptr compilation: no evaluator context provided\n";
      Ebpf_c_codegen.compile_multi_to_c ir_multi_program

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

(** Test function to verify the bridge works *)
let test_memory_bridge () =
  Printf.printf "Testing memory bridge integration...\n";
  
  (* Create a test evaluator context with builtin symbol table *)
  let maps = Hashtbl.create 16 in
  let functions = Hashtbl.create 16 in
  let empty_ast = [] in
  let symbol_table = Builtin_loader.build_symbol_table_with_builtins empty_ast in
  let eval_ctx = Evaluator.create_eval_context symbol_table maps functions in
  
  (* Add some test variables *)
  let _ = Evaluator.allocate_variable_address eval_ctx "packet_ptr" (Evaluator.PointerValue 0x2000) in
  let _ = Evaluator.allocate_context_address eval_ctx "map_value" (Evaluator.IntValue 42) "map_value" in
  
  (* Extract memory info *)
  let memory_info = extract_memory_info_from_evaluator eval_ctx in
  
  Printf.printf "Extracted memory info for %d variables:\n" (Hashtbl.length memory_info);
  Hashtbl.iter (fun var_name info ->
    let region_str = match info.Ebpf_c_codegen.region_type with
      | Ebpf_c_codegen.PacketData -> "PacketData"
      | Ebpf_c_codegen.MapValue -> "MapValue"  
      | Ebpf_c_codegen.LocalStack -> "LocalStack"
      | Ebpf_c_codegen.RegularMemory -> "RegularMemory"
      | Ebpf_c_codegen.RingBuffer -> "RingBuffer"
    in
    Printf.printf "  %s: %s (verified: %b, size: %s)\n" 
      var_name region_str info.Ebpf_c_codegen.bounds_verified 
      (match info.Ebpf_c_codegen.size_hint with Some s -> string_of_int s | None -> "unknown");
  ) memory_info;
  
  Printf.printf "Memory bridge test completed!\n" 