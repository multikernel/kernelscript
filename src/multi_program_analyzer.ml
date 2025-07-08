(** Multi-Program Analyzer for KernelScript
    
    This module analyzes multiple eBPF programs together as a coordinated system,
    detecting cross-program dependencies, shared map usage patterns, and 
    optimization opportunities.
*)

open Ast

(** Linux kernel execution context for eBPF programs *)
type execution_context = {
  program_type: program_type;
  hook_point: string;        (* Kernel hook description *)
  stack_layer: int;          (* Network stack layer (1=earliest, 4=latest, 0=not in packet path) *)
  execution_stage: string;   (* High-level stage *)
  can_drop_packets: bool;    (* Whether program can drop packets *)
}

(** Get execution context for each eBPF program type *)
let get_execution_context = function
  | Xdp -> {
      program_type = Xdp;
      hook_point = "netdev_rx (NIC driver level)";
      stack_layer = 1;  (* EARLIEST - right after NIC hardware *)
      execution_stage = "packet_receive_early";
      can_drop_packets = true;
    }
  | Tc -> {
      program_type = Tc; 
      hook_point = "tc_classify (qdisc layer)";
      stack_layer = 2;  (* LATER - after IP processing *)
      execution_stage = "packet_receive_late";
      can_drop_packets = true;
    }
  | CgroupSkb -> {
      program_type = CgroupSkb;
      hook_point = "cgroup_skb_filter";
      stack_layer = 3;  (* LATEST - after TC *)
      execution_stage = "cgroup_filtering";
      can_drop_packets = true;
    }
  | Lsm -> {
      program_type = Lsm;
      hook_point = "security_hooks (various points)";
      stack_layer = 0;  (* NOT in linear packet path - scattered throughout kernel *)
      execution_stage = "security_enforcement";
      can_drop_packets = true;
    }
  | Kprobe -> {
      program_type = Kprobe;
      hook_point = "kernel_function_entry/exit";
      stack_layer = 0;  (* Can run anywhere - not in packet path *)
      execution_stage = "dynamic_tracing";
      can_drop_packets = false;
    }
  | Uprobe -> {
      program_type = Uprobe;
      hook_point = "user_function_entry/exit";
      stack_layer = 0;  (* Userspace *)
      execution_stage = "user_tracing";
      can_drop_packets = false;
    }
  | Tracepoint -> {
      program_type = Tracepoint;
      hook_point = "static_kernel_tracepoint";
      stack_layer = 0;  (* Can be anywhere *)
      execution_stage = "static_tracing";
      can_drop_packets = false;
    }

(** Check if two programs execute sequentially (not concurrently) *)
let are_sequential prog_type1 prog_type2 =
  let ctx1 = get_execution_context prog_type1 in
  let ctx2 = get_execution_context prog_type2 in
  
  (* Programs in packet processing path with different layers are sequential *)
  if ctx1.stack_layer > 0 && ctx2.stack_layer > 0 && ctx1.stack_layer <> ctx2.stack_layer then
    true
  (* Tracing programs (stack_layer = 0) are concurrent with everything *)
  else if ctx1.stack_layer = 0 || ctx2.stack_layer = 0 then
    false
  else
    false  (* Same layer = potentially concurrent *)

(** Enhanced multi-program analysis result *)
type multi_program_analysis = {
  programs: program_def list;
  global_maps: map_declaration list;
  map_usage_patterns: (string * string list) list; (* map_name -> accessing_programs *)
  potential_conflicts: string list;
  optimization_opportunities: string list;
  execution_flow_info: string list;     (* NEW: Kernel execution flow insights *)
  sequential_dependencies: string list; (* NEW: Sequential access patterns *)
}

(** Extract programs from AST by converting attributed functions to program_def records *)
let extract_programs (ast: declaration list) : program_def list =
  List.filter_map (function
    | AttributedFunction attr_func ->
        (* Convert attributed function to program_def for compatibility *)
        (match attr_func.attr_list with
         | SimpleAttribute prog_type_str :: _ ->
             (match prog_type_str with
              | "kfunc" -> None  (* Skip kfunc functions - they're not eBPF programs *)
              | "private" -> None  (* Skip private functions - they're not eBPF programs *)
              | "helper" -> None  (* Skip helper functions - they're shared eBPF functions, not individual programs *)
              | _ ->
                  let prog_type = match prog_type_str with
                    | "xdp" -> Xdp
                    | "tc" -> Tc  
                    | "kprobe" -> Kprobe
                    | "uprobe" -> Uprobe
                    | "tracepoint" -> Tracepoint
                    | "lsm" -> Lsm
                    | "cgroup_skb" -> CgroupSkb
                    | _ -> failwith ("Unknown program type: " ^ prog_type_str)
                  in
                  Some {
                    prog_name = attr_func.attr_function.func_name;
                    prog_type = prog_type;
                    prog_functions = [attr_func.attr_function];
                    prog_maps = [];
                    prog_structs = [];
                    prog_pos = attr_func.attr_pos;
                  })
         | _ -> None)
    | _ -> None
  ) ast

(** Extract global maps from AST *)
let extract_global_maps (ast: declaration list) : map_declaration list =
  List.filter_map (function
    | MapDecl map_decl when map_decl.is_global -> Some map_decl
    | _ -> None
  ) ast

(** Analyze map usage patterns across programs *)
let analyze_map_usage (programs: program_def list) (global_maps: map_declaration list) 
    : (string * string list) list =
  
  let map_usage_table = Hashtbl.create 32 in
  
  (* Initialize usage tracking for all global maps *)
  List.iter (fun map_decl ->
    Hashtbl.add map_usage_table map_decl.name []
  ) global_maps;
  
  (* Simple map usage analysis - look for map identifiers in expressions *)
  let rec analyze_expr_for_maps prog_name expr =
    match expr.expr_desc with
    | Identifier name ->
        (* Check if this identifier is a global map *)
        if List.exists (fun m -> m.name = name) global_maps then (
          let current_progs = 
            try Hashtbl.find map_usage_table name 
            with Not_found -> [] 
          in
          if not (List.mem prog_name current_progs) then
            Hashtbl.replace map_usage_table name (prog_name :: current_progs)
        )
    | ArrayAccess (map_expr, key_expr) ->
        analyze_expr_for_maps prog_name map_expr;
        analyze_expr_for_maps prog_name key_expr
    | Call (_, args) ->
        List.iter (analyze_expr_for_maps prog_name) args
    | BinaryOp (left, _, right) ->
        analyze_expr_for_maps prog_name left;
        analyze_expr_for_maps prog_name right
    | UnaryOp (_, expr) ->
        analyze_expr_for_maps prog_name expr
    | FieldAccess (obj_expr, _) ->
        analyze_expr_for_maps prog_name obj_expr
    | _ -> ()
  in
  
  let rec analyze_stmt_for_maps prog_name stmt =
    match stmt.stmt_desc with
    | ExprStmt expr ->
        analyze_expr_for_maps prog_name expr
    | Assignment (_, expr) ->
        analyze_expr_for_maps prog_name expr
    | CompoundAssignment (_, _, expr) ->
        analyze_expr_for_maps prog_name expr
    | CompoundIndexAssignment (map_expr, key_expr, _, value_expr) ->
        analyze_expr_for_maps prog_name map_expr;
        analyze_expr_for_maps prog_name key_expr;
        analyze_expr_for_maps prog_name value_expr
    | FieldAssignment (obj_expr, _, value_expr) ->
        analyze_expr_for_maps prog_name obj_expr;
        analyze_expr_for_maps prog_name value_expr
    | ArrowAssignment (obj_expr, _, value_expr) ->
        analyze_expr_for_maps prog_name obj_expr;
        analyze_expr_for_maps prog_name value_expr
    | IndexAssignment (map_expr, key_expr, value_expr) ->
        analyze_expr_for_maps prog_name map_expr;
        analyze_expr_for_maps prog_name key_expr;
        analyze_expr_for_maps prog_name value_expr
    | Declaration (_, _, expr_opt) ->
        (match expr_opt with
         | Some expr -> analyze_expr_for_maps prog_name expr
         | None -> ())
    | ConstDeclaration (_, _, expr) ->
        analyze_expr_for_maps prog_name expr
    | Return (Some expr) ->
        analyze_expr_for_maps prog_name expr
    | If (cond_expr, then_stmts, else_stmts_opt) ->
        analyze_expr_for_maps prog_name cond_expr;
        List.iter (analyze_stmt_for_maps prog_name) then_stmts;
        (match else_stmts_opt with
         | Some else_stmts -> List.iter (analyze_stmt_for_maps prog_name) else_stmts
         | None -> ())
    | For (_, start_expr, end_expr, body_stmts) ->
        analyze_expr_for_maps prog_name start_expr;
        analyze_expr_for_maps prog_name end_expr;
        List.iter (analyze_stmt_for_maps prog_name) body_stmts
    | ForIter (_, _, iter_expr, body_stmts) ->
        analyze_expr_for_maps prog_name iter_expr;
        List.iter (analyze_stmt_for_maps prog_name) body_stmts
    | While (cond_expr, body_stmts) ->
        analyze_expr_for_maps prog_name cond_expr;
        List.iter (analyze_stmt_for_maps prog_name) body_stmts
    | Delete (map_expr, key_expr) ->
        analyze_expr_for_maps prog_name map_expr;
        analyze_expr_for_maps prog_name key_expr
    | Return None -> ()
    | Break -> ()
    | Continue -> ()
    | Try (try_stmts, catch_clauses) ->
        List.iter (analyze_stmt_for_maps prog_name) try_stmts;
        List.iter (fun clause -> 
          List.iter (analyze_stmt_for_maps prog_name) clause.catch_body
        ) catch_clauses
    | Throw _ -> ()  (* Throw statements don't contain map accesses *)
    | Defer expr ->
        analyze_expr_for_maps prog_name expr
  in
  
  (* Analyze all programs *)
  List.iter (fun prog ->
    List.iter (fun func ->
      List.iter (analyze_stmt_for_maps prog.prog_name) func.func_body
    ) prog.prog_functions
  ) programs;
  
  (* Convert hashtable to list *)
  Hashtbl.fold (fun map_name prog_list acc ->
    (map_name, List.rev prog_list) :: acc
  ) map_usage_table []

(** Enhanced conflict detection with kernel execution order awareness *)
let detect_conflicts_with_execution_order (programs: program_def list) 
    (map_usage_patterns: (string * string list) list) : string list * string list =
  
  let real_conflicts = ref [] in
  let sequential_accesses = ref [] in
  
  List.iter (fun (map_name, accessing_programs) ->
    if List.length accessing_programs > 1 then (
      (* Get program types for accessing programs *)
      let prog_types_with_names = List.filter_map (fun prog_name ->
        List.find_map (fun prog ->
          if prog.prog_name = prog_name then 
            Some (prog_name, prog.prog_type) 
          else None
        ) programs
      ) accessing_programs in
      
      (* Analyze each pair of accessing programs *)
      let rec analyze_pairs = function
        | [] | [_] -> ()
        | (name1, type1) :: rest ->
            List.iter (fun (name2, type2) ->
              if are_sequential type1 type2 then (
                (* Sequential access - this is GOOD, not a conflict! *)
                let ctx1 = get_execution_context type1 in
                let ctx2 = get_execution_context type2 in
                let (first_name, first_type, second_name, second_type) = 
                  if ctx1.stack_layer < ctx2.stack_layer then
                    (name1, type1, name2, type2)
                  else
                    (name2, type2, name1, type1)
                in
                let sequential_msg = Printf.sprintf
                  "Sequential map access: %s (%s) → %s (%s) via '%s' (no race condition)"
                  first_name (string_of_program_type first_type)
                  second_name (string_of_program_type second_type)
                  map_name in
                sequential_accesses := sequential_msg :: !sequential_accesses
              ) else (
                (* Concurrent access - TRUE race condition *)
                let conflict_msg = Printf.sprintf 
                  "TRUE RACE CONDITION: Map '%s' accessed concurrently by %s (%s) and %s (%s)" 
                  map_name name1 (string_of_program_type type1)
                  name2 (string_of_program_type type2) in
                real_conflicts := conflict_msg :: !real_conflicts
              )
            ) rest;
            analyze_pairs rest
      in
      analyze_pairs prog_types_with_names
    )
  ) map_usage_patterns;
  
  (!real_conflicts, !sequential_accesses)

(** Generate optimization hints *)
let generate_optimization_hints (map_usage_patterns: (string * string list) list) 
    (global_maps: map_declaration list) : string list =
  
  let hints = ref [] in
  
  (* Suggest per-CPU maps for high-contention scenarios *)
  List.iter (fun (map_name, accessing_programs) ->
    if List.length accessing_programs > 1 then (
      let map_decl = List.find (fun m -> m.name = map_name) global_maps in
      match map_decl.map_type with
      | HashMap ->
          let hint = Printf.sprintf 
            "Consider using PercpuHash for map '%s' to reduce contention between programs: %s" 
            map_name (String.concat ", " accessing_programs) in
          hints := hint :: !hints
      | Array ->
          let hint = Printf.sprintf 
            "Consider using PercpuArray for map '%s' to reduce contention between programs: %s" 
            map_name (String.concat ", " accessing_programs) in
          hints := hint :: !hints
      | _ -> ()
    )
  ) map_usage_patterns;
  
  !hints

(** Main multi-program analysis function *)
let analyze_multi_program_system (ast: declaration list) : multi_program_analysis =
  let programs = extract_programs ast in
  let global_maps = extract_global_maps ast in
  
  let map_usage_patterns = analyze_map_usage programs global_maps in
  let (real_conflicts, sequential_accesses) = 
    detect_conflicts_with_execution_order programs map_usage_patterns in
  let optimization_opportunities = generate_optimization_hints map_usage_patterns global_maps in
  
  (* Generate execution flow description *)
  let execution_flow_info = 
    let network_programs = List.filter (fun prog ->
      let ctx = get_execution_context prog.prog_type in
      ctx.stack_layer > 0
    ) programs in
    
    if List.length network_programs > 1 then (
      let sorted_programs = List.sort (fun prog1 prog2 ->
        let ctx1 = get_execution_context prog1.prog_type in
        let ctx2 = get_execution_context prog2.prog_type in
        compare ctx1.stack_layer ctx2.stack_layer
      ) network_programs in
      
      let flow_desc = List.map (fun prog ->
        let ctx = get_execution_context prog.prog_type in
        Printf.sprintf "%s@%s" prog.prog_name ctx.hook_point
      ) sorted_programs in
      
      ["🔄 Kernel execution flow: " ^ String.concat " → " flow_desc]
    ) else []
  in
  
  {
    programs;
    global_maps;
    map_usage_patterns;
    potential_conflicts = real_conflicts;
    optimization_opportunities;
    execution_flow_info;
    sequential_dependencies = sequential_accesses;
  }

(** Print multi-program analysis results *)
let print_analysis_results (analysis: multi_program_analysis) : unit =
  Printf.printf "\n=== Multi-Program Analysis Results ===\n";
  
  Printf.printf "\nPrograms analyzed: %d\n" (List.length analysis.programs);
  List.iter (fun prog ->
    Printf.printf "  - %s (%s)\n" prog.prog_name (string_of_program_type prog.prog_type)
  ) analysis.programs;
  
  Printf.printf "\nGlobal maps: %d\n" (List.length analysis.global_maps);
  List.iter (fun map_decl ->
    Printf.printf "  - %s (%s)\n" map_decl.name (string_of_map_type map_decl.map_type)
  ) analysis.global_maps;
  
  Printf.printf "\nMap usage patterns:\n";
  List.iter (fun (map_name, accessing_programs) ->
    Printf.printf "  - %s: accessed by %d programs [%s]\n" 
      map_name (List.length accessing_programs) (String.concat ", " accessing_programs)
  ) analysis.map_usage_patterns;
  
  if analysis.execution_flow_info <> [] then (
    Printf.printf "\n";
    List.iter (fun info ->
      Printf.printf "%s\n" info
    ) analysis.execution_flow_info
  );
  
  if analysis.sequential_dependencies <> [] then (
    Printf.printf "\n✅ Sequential access patterns (no race conditions):\n";
    List.iter (fun dep ->
      Printf.printf "  - %s\n" dep
    ) analysis.sequential_dependencies
  );
  
  if analysis.potential_conflicts <> [] then (
    Printf.printf "\n⚠️  True race conditions found:\n";
    List.iter (fun conflict ->
      Printf.printf "  - %s\n" conflict
    ) analysis.potential_conflicts
  );
  
  if analysis.optimization_opportunities <> [] then (
    Printf.printf "\n💡 Optimization opportunities:\n";
    List.iter (fun hint ->
      Printf.printf "  - %s\n" hint
    ) analysis.optimization_opportunities
  );
  
  Printf.printf "\n✅ Multi-program analysis completed.\n\n"

(** Extract program types from AST for BTF loading *)
let get_program_types_from_ast (ast: declaration list) : program_type list =
  List.fold_left (fun acc decl ->
    match decl with
    | AttributedFunction attr_func ->
        (match attr_func.attr_list with
         | SimpleAttribute prog_type_str :: _ ->
             (match prog_type_str with
              | "xdp" -> Xdp :: acc
              | "tc" -> Tc :: acc  
              | "kprobe" -> Kprobe :: acc
              | "uprobe" -> Uprobe :: acc
              | "tracepoint" -> Tracepoint :: acc
              | "lsm" -> Lsm :: acc
              | "cgroup_skb" -> CgroupSkb :: acc
              | _ -> acc)
         | _ -> acc)
    | _ -> acc
  ) [] ast |> List.rev |> fun types -> 
  (* Remove duplicates *)
  List.fold_left (fun acc typ -> 
    if List.mem typ acc then acc else typ :: acc
  ) [] types 