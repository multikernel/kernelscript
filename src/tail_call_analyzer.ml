(** Tail Call Analysis Module for KernelScript
    
    This module implements:
    - Automatic tail call detection based on return position + compatible signatures
    - Dependency tracking for tail call targets
    - ProgArray generation and management
    - Validation of tail call constraints
*)

open Ast

(** Tail call analysis exceptions *)
exception Tail_call_error of string * position

(** Tail call dependency information *)
type tail_call_dependency = {
  caller: string;
  target: string;
  caller_type: program_type;
  target_type: program_type;
  position: position;
}

(** Analysis results *)
type tail_call_analysis = {
  dependencies: tail_call_dependency list;
  prog_array_size: int;
  index_mapping: (string, int) Hashtbl.t;
  errors: string list;
}

(** Helper to create tail call error *)
let tail_call_error msg pos = raise (Tail_call_error (msg, pos))

(** Extract program type from attribute list *)
let extract_program_type attr_list =
  match attr_list with
  | SimpleAttribute prog_type_str :: _ ->
      (match prog_type_str with
       | "xdp" -> Some Xdp
       | "tc" -> Some Tc
       | "kprobe" -> Some Kprobe
       | "uprobe" -> Some Uprobe
       | "tracepoint" -> Some Tracepoint
       | "lsm" -> Some Lsm
       | "cgroup_skb" -> Some CgroupSkb
       | _ -> None)
  | _ -> None

(** Check if two program types are compatible for tail calls *)
let compatible_program_types pt1 pt2 =
  pt1 = pt2

(** Check if a function signature is compatible for tail calling *)
let compatible_signatures caller_params caller_return target_params target_return =
  (* Must have same parameter types and return type *)
  let params_match = 
    List.length caller_params = List.length target_params &&
    List.for_all2 (fun (_, t1) (_, t2) -> t1 = t2) caller_params target_params
  in
  let return_match = caller_return = target_return in
  params_match && return_match

(** Detect tail calls in a return statement *)
let rec detect_tail_calls_in_expr expr attributed_functions =
  match expr.expr_desc with
  | Call (callee_expr, _args) ->
      (* Check if this is a function call to an attributed function *)
      (match callee_expr.expr_desc with
       | Identifier name ->
           if List.exists (fun attr_func -> attr_func.attr_function.func_name = name) attributed_functions then
             [name]
           else
             []
       | _ ->
           (* Function pointer calls are not tail call targets *)
           [])
  | TailCall (name, _args) ->
      (* This is an explicit tail call - already validated by type checker *)
      if List.exists (fun attr_func -> attr_func.attr_function.func_name = name) attributed_functions then
        [name]
      else
        []
  | Match (_matched_expr, match_arms) ->
      (* Handle match expressions - analyze each arm's expression for tail calls *)
              List.fold_left (fun acc arm ->
          match arm.arm_body with
          | SingleExpr expr -> acc @ (detect_tail_calls_in_expr expr attributed_functions)
          | Block stmts -> acc @ (List.fold_left (fun acc stmt -> acc @ (detect_tail_calls_in_stmt stmt attributed_functions)) [] stmts)
        ) [] match_arms
  | _ -> []

and detect_tail_calls_in_stmt stmt attributed_functions =
  match stmt.stmt_desc with
  | Return (Some expr) ->
      detect_tail_calls_in_expr expr attributed_functions
  | If (_, then_stmts, else_stmts_opt) ->
      (* Recursively analyze if/else branches *)
      let then_calls = List.fold_left (fun acc stmt ->
        acc @ (detect_tail_calls_in_stmt stmt attributed_functions)
      ) [] then_stmts in
      let else_calls = match else_stmts_opt with
        | Some else_stmts ->
            List.fold_left (fun acc stmt ->
              acc @ (detect_tail_calls_in_stmt stmt attributed_functions)
            ) [] else_stmts
        | None -> []
      in
      then_calls @ else_calls
  | For (_, _, _, body_stmts) ->
      (* Recursively analyze for loop body *)
      List.fold_left (fun acc stmt ->
        acc @ (detect_tail_calls_in_stmt stmt attributed_functions)
      ) [] body_stmts
  | While (_, body_stmts) ->
      (* Recursively analyze while loop body *)
      List.fold_left (fun acc stmt ->
        acc @ (detect_tail_calls_in_stmt stmt attributed_functions)
      ) [] body_stmts
  | _ -> []

(** Analyze a single attributed function for tail call dependencies *)
let analyze_attributed_function attr_func attributed_functions =
  let caller_type = extract_program_type attr_func.attr_list in
  
  (* Find all tail calls in this function *)
  let tail_calls = List.fold_left (fun acc stmt ->
    acc @ (detect_tail_calls_in_stmt stmt attributed_functions)
  ) [] attr_func.attr_function.func_body in
  
  (* Remove duplicates from tail calls *)
  let unique_tail_calls = List.fold_left (fun acc target ->
    if List.mem target acc then acc else target :: acc
  ) [] tail_calls in
  
  (* Create dependency records *)
  List.fold_left (fun acc target_name ->
    match List.find_opt (fun af -> af.attr_function.func_name = target_name) attributed_functions with
    | Some target_func ->
        let target_type = extract_program_type target_func.attr_list in
        (match caller_type, target_type with
         | Some ct, Some tt when compatible_program_types ct tt ->
             (* Validate signature compatibility *)
             if compatible_signatures 
                attr_func.attr_function.func_params 
                attr_func.attr_function.func_return_type
                target_func.attr_function.func_params
                target_func.attr_function.func_return_type then
               {
                 caller = attr_func.attr_function.func_name;
                 target = target_name;
                 caller_type = ct;
                 target_type = tt;
                 position = attr_func.attr_pos;
               } :: acc
             else
               (* Signature mismatch - this will become a compilation error *)
               acc
         | Some _ct, Some _tt ->
             (* Program type mismatch - this will become a compilation error *)
             acc
         | _ ->
             (* Unknown program type - this will become a compilation error *)
             acc)
    | None ->
        (* Target function not found - this will become a compilation error *)
        acc
  ) [] unique_tail_calls

(** Build complete tail call analysis for all attributed functions *)
let analyze_tail_calls (ast : declaration list) =
  (* Extract all attributed functions *)
  let attributed_functions = List.filter_map (function
    | AttributedFunction attr_func -> Some attr_func
    | _ -> None
  ) ast in
  
  (* Analyze each attributed function *)
  let all_dependencies = List.fold_left (fun acc attr_func ->
    acc @ (analyze_attributed_function attr_func attributed_functions)
  ) [] attributed_functions in
  
  (* Build index mapping for ProgArray *)
  let unique_targets = List.fold_left (fun acc dep ->
    if List.mem dep.target acc then acc else dep.target :: acc
  ) [] all_dependencies in
  
  let index_mapping = Hashtbl.create 16 in
  List.iteri (fun i target ->
    Hashtbl.add index_mapping target i
  ) unique_targets;
  
  {
    dependencies = all_dependencies;
    prog_array_size = List.length unique_targets;
    index_mapping = index_mapping;
    errors = [];
  }

(** Update attributed function with tail call analysis results *)
let update_attributed_function_with_analysis attr_func analysis =
  (* Extract program type *)
  attr_func.program_type <- extract_program_type attr_func.attr_list;
  
  (* Find dependencies for this function *)
  let dependencies = List.filter (fun dep -> 
    dep.caller = attr_func.attr_function.func_name
  ) analysis.dependencies in
  
  attr_func.tail_call_dependencies <- List.map (fun dep -> dep.target) dependencies;
  
  (* Mark function as tail-callable if it's a target *)
  let is_target = List.exists (fun dep -> 
    dep.target = attr_func.attr_function.func_name
  ) analysis.dependencies in
  
  attr_func.attr_function.is_tail_callable <- is_target;
  attr_func.attr_function.tail_call_targets <- List.map (fun dep -> dep.target) dependencies

(** Apply tail call analysis to entire AST *)
let apply_tail_call_analysis ast =
  let analysis = analyze_tail_calls ast in
  
  (* Update all attributed functions with analysis results *)
  List.iter (function
    | AttributedFunction attr_func ->
        update_attributed_function_with_analysis attr_func analysis
    | _ -> ()
  ) ast;
  
  analysis

(** Validate tail call constraints *)
let validate_tail_call_constraints analysis attributed_functions =
  let errors = ref [] in
  
  List.iter (fun dep ->
    match List.find_opt (fun af -> af.attr_function.func_name = dep.caller) attributed_functions,
          List.find_opt (fun af -> af.attr_function.func_name = dep.target) attributed_functions with
    | Some caller_func, Some target_func ->
        (* Validate program type compatibility *)
        if not (compatible_program_types dep.caller_type dep.target_type) then
          errors := (Printf.sprintf "Tail call from %s (@%s) to %s (@%s) - incompatible program types" 
                      dep.caller (string_of_program_type dep.caller_type) 
                      dep.target (string_of_program_type dep.target_type)) :: !errors;
        
        (* Validate signature compatibility *)
        if not (compatible_signatures 
                 caller_func.attr_function.func_params 
                 caller_func.attr_function.func_return_type
                 target_func.attr_function.func_params
                 target_func.attr_function.func_return_type) then
          errors := (Printf.sprintf "Tail call from %s to %s - incompatible function signatures" 
                      dep.caller dep.target) :: !errors
    | _ ->
        errors := (Printf.sprintf "Tail call validation error: missing function definition") :: !errors
  ) analysis.dependencies;
  
  !errors

(** Get all tail call targets that need to be loaded for a given function *)
let get_tail_call_dependencies func_name analysis =
  let rec collect_dependencies visited func_name =
    if List.mem func_name visited then
      [] (* Circular dependency - break cycle *)
    else
      let direct_deps = List.filter_map (fun dep ->
        if dep.caller = func_name then Some dep.target else None
      ) analysis.dependencies in
      
      let indirect_deps = List.fold_left (fun acc target ->
        acc @ (collect_dependencies (func_name :: visited) target)
      ) [] direct_deps in
      
      direct_deps @ indirect_deps
  in
  
  let all_deps = collect_dependencies [] func_name in
  (* Remove duplicates *)
  List.fold_left (fun acc dep ->
    if List.mem dep acc then acc else dep :: acc
  ) [] all_deps 

(** Update IR function with correct tail call indices in IRMatchReturn instructions *)
let update_ir_function_tail_call_indices ir_function analysis =
  let open Ir in
  let rec update_instruction instr =
    match instr.instr_desc with
    | IRMatchReturn (matched_val, arms) ->
        let updated_arms = List.map (fun arm ->
          match arm.return_action with
          | IRReturnTailCall (func_name, args, _old_index) ->
              (* Look up the correct index from analysis *)
              let new_index = try
                Hashtbl.find analysis.index_mapping func_name
              with Not_found -> 0 in
              { arm with return_action = IRReturnTailCall (func_name, args, new_index) }
          | _ -> arm
        ) arms in
        { instr with instr_desc = IRMatchReturn (matched_val, updated_arms) }
    | IRIf (cond, then_body, else_body) ->
        let updated_then = List.map update_instruction then_body in
        let updated_else = Option.map (List.map update_instruction) else_body in
        { instr with instr_desc = IRIf (cond, updated_then, updated_else) }
    | IRIfElseChain (conditions_and_bodies, final_else) ->
        let updated_conditions_and_bodies = List.map (fun (cond, then_body) ->
          (cond, List.map update_instruction then_body)
        ) conditions_and_bodies in
        let updated_final_else = Option.map (List.map update_instruction) final_else in
        { instr with instr_desc = IRIfElseChain (updated_conditions_and_bodies, updated_final_else) }
    | IRTailCall (func_name, args, _old_index) ->
        (* Also update regular tail calls *)
        let new_index = try
          Hashtbl.find analysis.index_mapping func_name
        with Not_found -> 0 in
        { instr with instr_desc = IRTailCall (func_name, args, new_index) }
    | _ -> instr
  in
  
  let updated_blocks = List.map (fun block ->
    { block with instructions = List.map update_instruction block.instructions }
  ) ir_function.basic_blocks in
  
  { ir_function with basic_blocks = updated_blocks } 