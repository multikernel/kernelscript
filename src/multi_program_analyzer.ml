(** Multi-Program Analyzer for KernelScript
    
    This module analyzes multiple eBPF programs together as a coordinated system,
    detecting cross-program dependencies, shared map usage patterns, and 
    optimization opportunities.
*)

open Ast

(** Multi-program analysis result *)
type multi_program_analysis = {
  programs: program_def list;
  global_maps: map_declaration list;
  map_usage_patterns: (string * string list) list; (* map_name -> accessing_programs *)
  potential_conflicts: string list;
  optimization_opportunities: string list;
}

(** Extract programs from AST *)
let extract_programs (ast: declaration list) : program_def list =
  List.filter_map (function
    | Program prog -> Some prog
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
    | FunctionCall (_, args) ->
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
    | IndexAssignment (map_expr, key_expr, value_expr) ->
        analyze_expr_for_maps prog_name map_expr;
        analyze_expr_for_maps prog_name key_expr;
        analyze_expr_for_maps prog_name value_expr
    | Declaration (_, _, expr) ->
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

(** Detect potential conflicts *)
let detect_conflicts (map_usage_patterns: (string * string list) list) : string list =
  let conflicts = ref [] in
  
  List.iter (fun (map_name, accessing_programs) ->
    if List.length accessing_programs > 1 then (
      let conflict_msg = Printf.sprintf 
        "Map '%s' accessed by multiple programs: %s (potential race condition)" 
        map_name (String.concat ", " accessing_programs) in
      conflicts := conflict_msg :: !conflicts
    )
  ) map_usage_patterns;
  
  !conflicts

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
  let potential_conflicts = detect_conflicts map_usage_patterns in
  let optimization_opportunities = generate_optimization_hints map_usage_patterns global_maps in
  
  {
    programs;
    global_maps;
    map_usage_patterns;
    potential_conflicts;
    optimization_opportunities;
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
  
  if analysis.potential_conflicts <> [] then (
    Printf.printf "\n⚠️  Potential conflicts found:\n";
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