(** Map Assignment Analysis Module for KernelScript
    
    This module provides analysis for map assignment operations including
    optimization detection, assignment extraction, and performance analysis.
*)

open Ast

(** Map assignment record for analysis *)
type map_assignment = {
  map_name: string;
  key_expr: expr;
  value_expr: expr;
  assignment_pos: position;
  assignment_type: assignment_type;
}

and assignment_type =
  | DirectAssignment   (* map[key] = value *)
  | ConditionalAssignment  (* if condition then map[key] = value *)
  | ComputedAssignment (* map[key] = map[key] + value *)

(** Optimization record *)
type optimization_record = { 
  optimization_type: string;
  description: string;
  estimated_benefit: int;  (* 0-100 score *)
}

(** Optimization analysis result *)
type optimization_info = { 
  optimizations: optimization_record list; 
  constant_folding: bool;
  optimization_type: string;
  total_optimizations: int;
}

(** Extract map assignments from AST statements *)
let extract_map_assignments (statements: statement list) : map_assignment list =
  let extract_from_stmt stmt =
    match stmt.stmt_desc with
    | IndexAssignment (map_expr, key_expr, value_expr) ->
        let map_name = match map_expr.expr_desc with
          | Identifier name -> name
          | _ -> "unknown_map"
        in
        [{
          map_name = map_name;
          key_expr = key_expr;
          value_expr = value_expr;
          assignment_pos = stmt.stmt_pos;
          assignment_type = DirectAssignment;
        }]
    | _ -> []
  in
  List.flatten (List.map extract_from_stmt statements)

(** Extract map assignments from AST declarations *)
let extract_map_assignments_from_ast (ast: declaration list) : map_assignment list =
  let rec extract_from_decl decl =
    match decl with
    | Program program ->
        List.flatten (List.map extract_from_function program.prog_functions)
    | _ -> []
  and extract_from_function func =
    extract_map_assignments func.func_body
  in
  List.flatten (List.map extract_from_decl ast)

(** Analyze constant expressions for folding opportunities *)
let is_constant_expression expr =
  let rec check_expr e =
    match e.expr_desc with
    | Literal _ -> true
    | BinaryOp (left, _, right) -> check_expr left && check_expr right
    | UnaryOp (_, operand) -> check_expr operand
    | _ -> false
  in
  check_expr expr

(** Detect multiple assignments to same map key *)
let detect_multiple_assignments (assignments: map_assignment list) : (string * int) list =
  let key_counts = Hashtbl.create 16 in
  List.iter (fun assignment ->
    let key = Printf.sprintf "%s[%s]" assignment.map_name 
      (match assignment.key_expr.expr_desc with
       | Literal (IntLit i) -> string_of_int i
       | Identifier name -> name
       | _ -> "expr")
    in
    let current = try Hashtbl.find key_counts key with Not_found -> 0 in
    Hashtbl.replace key_counts key (current + 1)
  ) assignments;
  
  Hashtbl.fold (fun key count acc ->
    if count > 1 then (key, count) :: acc else acc
  ) key_counts []

(** Analyze assignment optimizations *)
let analyze_assignment_optimizations (assignments: map_assignment list) : optimization_info =
  let optimizations = ref [] in
  let has_constant_folding = ref false in
  
  (* Check for multiple assignment elimination *)
  let multiple_assigns = detect_multiple_assignments assignments in
  if List.length multiple_assigns > 0 then (
    optimizations := {
      optimization_type = "multiple_assignment_elimination";
      description = Printf.sprintf "Found %d keys with multiple assignments" (List.length multiple_assigns);
      estimated_benefit = 75;
    } :: !optimizations
  );
  
  (* Check for constant folding opportunities *)
  let constant_exprs = List.filter (fun a -> is_constant_expression a.value_expr) assignments in
  if List.length constant_exprs > 0 then (
    has_constant_folding := true;
    optimizations := {
      optimization_type = "constant_folding";
      description = Printf.sprintf "Found %d constant expressions that can be folded" (List.length constant_exprs);
      estimated_benefit = 60;
    } :: !optimizations
  );
  
  (* Check for sequential key patterns *)
  let sequential_keys = List.filter (fun a ->
    match a.key_expr.expr_desc with
    | BinaryOp (_, Add, {expr_desc = Literal (IntLit _); _}) -> true
    | _ -> false
  ) assignments in
  if List.length sequential_keys > 2 then (
    optimizations := {
      optimization_type = "sequential_access_optimization";
      description = Printf.sprintf "Found %d sequential key accesses" (List.length sequential_keys);
      estimated_benefit = 40;
    } :: !optimizations
  );
  
  {
    optimizations = !optimizations;
    constant_folding = !has_constant_folding;
    optimization_type = if List.length !optimizations > 0 then "multi_optimization" else "none";
    total_optimizations = List.length !optimizations;
  } 