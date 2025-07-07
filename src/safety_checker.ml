(** Memory Safety Analysis Module for KernelScript
    
    This module provides bounds checking analysis, stack usage tracking,
    pointer safety verification, and automatic map access validation.
*)

open Ast
open Maps

(** Stack usage analysis results *)
type stack_analysis = {
  max_stack_usage: int;
  function_usage: (string * int) list;
  potential_overflow: bool;
  warnings: string list;
}

(** Bounds checking error types *)
type bounds_error =
  | ArrayOutOfBounds of string * int * int (* variable, index, size *)
  | InvalidArraySize of string * int
  | PointerOutOfBounds of string
  | NullPointerDereference of string
  | UnknownBounds of string

(** Pointer safety analysis results *)
type pointer_safety = {
  valid_pointers: string list;
  invalid_pointers: (string * string) list; (* pointer, reason *)
  dangling_pointers: string list;
  null_checks_needed: string list;
}

(** Map access safety results *)
type map_access_safety = {
  valid_accesses: (string * map_operation) list;
  invalid_accesses: (string * map_operation * string) list; (* map, operation, reason *)
  missing_bounds_checks: string list;
  concurrent_access_issues: string list;
}

(** Overall safety analysis results *)
type safety_analysis = {
  stack_analysis: stack_analysis;
  bounds_errors: bounds_error list;
  pointer_safety: pointer_safety;
  map_safety: map_access_safety;
  overall_safe: bool;
}

(** eBPF constraints *)
module EbpfConstraints = struct
  let max_stack_size = 512
  let max_loop_iterations = 1000000
  let max_instruction_count = 1000000
  let max_map_value_size = 64 * 1024
  let max_map_key_size = 512
end

(** Stack usage analysis *)

(** Calculate stack usage for a type *)
let rec calculate_type_stack_usage = function
  | U8 | I8 | Bool | Char -> 1
  | U16 | I16 -> 2
  | U32 | I32 -> 4
  | U64 | I64 -> 8
  | Pointer _ -> 8
  | Ast.Array (t, count) -> (calculate_type_stack_usage t) * count
  | Struct _ -> 64 (* Conservative estimate - would need struct size analysis *)
  | UserType _ -> 32 (* Conservative estimate *)
  | _ -> 8 (* Default for other types *)

(** Analyze stack usage in a statement *)
let rec analyze_statement_stack_usage stmt =
  match stmt.stmt_desc with
  | Declaration (name, Some typ, _) ->
      let size = calculate_type_stack_usage typ in
      (size, [Printf.sprintf "Variable %s uses %d bytes" name size])
  | Declaration (_, None, _) ->
      (8, ["Inferred variable uses 8 bytes (default)"]) (* Conservative estimate *)
  | If (_, then_stmts, else_opt) ->
      let then_usage = List.fold_left (fun (acc_size, acc_msgs) stmt ->
        let (size, msgs) = analyze_statement_stack_usage stmt in
        (acc_size + size, acc_msgs @ msgs)
      ) (0, []) then_stmts in
      let else_usage = match else_opt with
        | None -> (0, [])
        | Some else_stmts -> 
            List.fold_left (fun (acc_size, acc_msgs) stmt ->
              let (size, msgs) = analyze_statement_stack_usage stmt in
              (acc_size + size, acc_msgs @ msgs)
            ) (0, []) else_stmts
      in
      let max_usage = max (fst then_usage) (fst else_usage) in
      (max_usage, snd then_usage @ snd else_usage)
  | For (var, _, _, body) ->
      (* Loop variables don't add to stack permanently, but body does *)
      let loop_var_size = 4 in (* Assume u32 loop variable *)
      let body_usage = List.fold_left (fun (acc_size, acc_msgs) stmt ->
        let (size, msgs) = analyze_statement_stack_usage stmt in
        (acc_size + size, acc_msgs @ msgs)
      ) (0, []) body in
      (loop_var_size + fst body_usage, 
       (Printf.sprintf "Loop variable %s uses %d bytes" var loop_var_size) :: snd body_usage)
  | While (_, body) ->
      List.fold_left (fun (acc_size, acc_msgs) stmt ->
        let (size, msgs) = analyze_statement_stack_usage stmt in
        (acc_size + size, acc_msgs @ msgs)
      ) (0, []) body
  | _ -> (0, [])

(** Analyze stack usage in a function *)
let analyze_function_stack_usage func =
  let param_usage = List.fold_left (fun acc (_, typ) ->
    acc + calculate_type_stack_usage typ
  ) 0 func.func_params in
  
  let body_usage = List.fold_left (fun (acc_size, acc_msgs) stmt ->
    let (size, msgs) = analyze_statement_stack_usage stmt in
    (acc_size + size, acc_msgs @ msgs)
  ) (0, []) func.func_body in
  
  let total_usage = param_usage + fst body_usage in
  let messages = (Printf.sprintf "Function %s parameters use %d bytes" func.func_name param_usage) :: snd body_usage in
  
  (total_usage, messages)

(** Bounds checking analysis *)

(** Check array access bounds *)
let check_array_bounds expr =
  let rec check_expr e errors =
    match e.expr_desc with
    | ArrayAccess (arr_expr, idx_expr) ->
        (match arr_expr.expr_desc, idx_expr.expr_desc with
         | Identifier arr_name, Literal (IntLit (idx, _)) ->
             (* Check if we can determine array size from type *)
             (match arr_expr.expr_type with
              | Some (Ast.Array (_, size)) ->
                  if idx >= size || idx < 0 then
                    ArrayOutOfBounds (arr_name, idx, size) :: errors
                  else
                    errors
              | _ -> UnknownBounds arr_name :: errors)
         | Identifier arr_name, _ ->
             (* Runtime bounds check needed *)
             UnknownBounds arr_name :: errors
         | FieldAccess (_, "data"), Literal (IntLit (idx, _)) when idx >= 1500 ->
             (* Unsafe packet access - large index into packet data *)
             PointerOutOfBounds ("packet_data") :: errors
         | _ -> 
             (* Check sub-expressions *)
             let errors' = check_expr arr_expr errors in
             check_expr idx_expr errors')
    | FieldAccess (ptr_expr, field) ->
        (match ptr_expr.expr_desc with
         | Literal (IntLit (0, _)) ->
             (* Null pointer field access *)
             NullPointerDereference field :: errors
         | FieldAccess (_, "data") ->
             (* Direct packet data field access without bounds check *)
             PointerOutOfBounds ("packet_field_" ^ field) :: errors
         | _ -> check_expr ptr_expr errors)
    | FunctionCall (_, args) ->
        List.fold_left (fun acc arg -> check_expr arg acc) errors args
    | BinaryOp (left, _, right) ->
        check_expr right (check_expr left errors)
    | UnaryOp (_, expr) ->
        check_expr expr errors
    | _ -> errors
  in
  check_expr expr []

(** Check array declarations for valid sizes *)
let check_array_declaration name typ =
  match typ with
  | Ast.Array (_, size) when size <= 0 ->
      [InvalidArraySize (name, size)]
  | Ast.Array (_, size) when size > 1000 ->
      [InvalidArraySize (name, size)] (* Too large for eBPF stack *)
  | _ -> []

(** Analyze bounds checking in statements *)
let analyze_statement_bounds stmt =
  let errors = ref [] in
  
  let rec check_stmt s =
    match s.stmt_desc with
    | Declaration (name, Some typ, expr) ->
        errors := check_array_declaration name typ @ !errors;
        errors := check_array_bounds expr @ !errors
    | ExprStmt expr | Assignment (_, expr) ->
        errors := check_array_bounds expr @ !errors
    | CompoundAssignment (_, _, expr) ->
        errors := check_array_bounds expr @ !errors
    | CompoundIndexAssignment (map_expr, key_expr, _, value_expr) ->
        errors := check_array_bounds map_expr @ !errors;
        errors := check_array_bounds key_expr @ !errors;
        errors := check_array_bounds value_expr @ !errors
    | FieldAssignment (obj_expr, _, value_expr) ->
        errors := check_array_bounds obj_expr @ !errors;
        errors := check_array_bounds value_expr @ !errors
    | If (cond, then_stmts, else_opt) ->
        errors := check_array_bounds cond @ !errors;
        List.iter check_stmt then_stmts;
        (match else_opt with
         | None -> ()
         | Some else_stmts -> List.iter check_stmt else_stmts)
    | For (_, start, end_, body) ->
        errors := check_array_bounds start @ !errors;
        errors := check_array_bounds end_ @ !errors;
        List.iter check_stmt body
    | While (cond, body) ->
        errors := check_array_bounds cond @ !errors;
        List.iter check_stmt body
    | Return (Some expr) ->
        errors := check_array_bounds expr @ !errors
    | _ -> ()
  in
  
  check_stmt stmt;
  !errors

(** Pointer safety analysis *)

(** Check for null pointer dereferences *)
let check_pointer_safety expr =
  let rec check_expr e valid_ptrs invalid_ptrs =
    match e.expr_desc with
    | FieldAccess (ptr_expr, _field) ->
        (match ptr_expr.expr_desc with
         | Literal (IntLit (0, _)) ->
             (* Direct null pointer dereference *)
             (valid_ptrs, ("null", "Null pointer dereference") :: invalid_ptrs)
         | Identifier ptr_name ->
             (match ptr_expr.expr_type with
              | Some (Pointer _) ->
                  (* Check if pointer is known to be valid *)
                  if List.mem ptr_name valid_ptrs then
                    (valid_ptrs, invalid_ptrs)
                  else
                    (valid_ptrs, (ptr_name, "Potential null dereference") :: invalid_ptrs)
              | _ -> (valid_ptrs, invalid_ptrs))
         | _ -> check_expr ptr_expr valid_ptrs invalid_ptrs)
    | FunctionCall (_, args) ->
        List.fold_left (fun (v, i) arg ->
          check_expr arg v i
        ) (valid_ptrs, invalid_ptrs) args
    | BinaryOp (left, op, right) ->
        (* Check for division by zero *)
        let invalid_ptrs' = match op, right.expr_desc with
          | Div, Literal (IntLit (0, _)) -> ("division", "Division by zero") :: invalid_ptrs
          | Mod, Literal (IntLit (0, _)) -> ("modulo", "Modulo by zero") :: invalid_ptrs
          | _ -> invalid_ptrs
        in
        (* Check for integer overflow *)
        let invalid_ptrs'' = match op, left.expr_desc, right.expr_desc with
          | Add, Literal (IntLit (a, _)), Literal (IntLit (b, _)) when a > 0 && b > 0 && a > max_int - b ->
              ("overflow", "Integer overflow in addition") :: invalid_ptrs'
          | _ -> invalid_ptrs'
        in
        let (v1, i1) = check_expr left valid_ptrs invalid_ptrs'' in
        check_expr right v1 i1
    | UnaryOp (_, expr) ->
        check_expr expr valid_ptrs invalid_ptrs
    | _ -> (valid_ptrs, invalid_ptrs)
  in
  check_expr expr [] []

(** Map access safety analysis *)

(** Validate map access patterns *)
let analyze_map_access map_name operation _expr_ctx =
  (* This would integrate with the Maps module to validate access patterns *)
  let is_valid_access = true in (* Placeholder - would implement actual logic *)
  let access_warnings = [] in (* Placeholder *)
  
  if is_valid_access then
    ([(map_name, operation)], [], access_warnings)
  else
    ([], [(map_name, operation, "Invalid access pattern")], access_warnings)

(** Check map operations in expressions *)
let rec check_map_operations expr =
  match expr.expr_desc with
  | FunctionCall (name, _args) when String.contains name '.' ->
      (* Map method call *)
      let parts = String.split_on_char '.' name in
      (match parts with
       | [map_name; op_name] ->
           let operation = match op_name with
             | "lookup" -> MapLookup
             | "update" -> MapUpdate
             | "insert" -> MapInsert
             | "delete" -> MapDelete
             | _ -> MapLookup (* Default *)
           in
           analyze_map_access map_name operation expr
       | _ -> ([], [], []))
  | ArrayAccess (arr_expr, _) ->
      (* Array-style map access *)
      (match arr_expr.expr_desc with
       | Identifier map_name ->
           analyze_map_access map_name MapLookup expr
       | _ -> ([], [], []))
  | FunctionCall (_, args) ->
      List.fold_left (fun (v_acc, i_acc, w_acc) arg ->
        let (v, i, w) = check_map_operations arg in
        (v_acc @ v, i_acc @ i, w_acc @ w)
      ) ([], [], []) args
  | BinaryOp (left, _, right) ->
      let (v1, i1, w1) = check_map_operations left in
      let (v2, i2, w2) = check_map_operations right in
      (v1 @ v2, i1 @ i2, w1 @ w2)
  | UnaryOp (_, expr) ->
      check_map_operations expr
  | _ -> ([], [], [])

(** Main safety analysis functions *)

(** Analyze stack usage for a program *)
let analyze_stack_usage program =
  let function_usages = List.map (fun func ->
    let (usage, _messages) = analyze_function_stack_usage func in
    (func.func_name, usage)
  ) program.prog_functions in
  
  let max_usage = List.fold_left (fun acc (_, usage) ->
    max acc usage
  ) 0 function_usages in
  
  let potential_overflow = max_usage > EbpfConstraints.max_stack_size in
  
  let warnings = if potential_overflow then
    [Printf.sprintf "Stack usage %d exceeds eBPF limit %d" max_usage EbpfConstraints.max_stack_size]
  else [] in
  
  {
    max_stack_usage = max_usage;
    function_usage = function_usages;
    potential_overflow = potential_overflow;
    warnings = warnings;
  }

(** Perform bounds checking analysis *)
let analyze_bounds_safety program =
  let all_errors = ref [] in
  
  List.iter (fun func ->
    List.iter (fun stmt ->
      let errors = analyze_statement_bounds stmt in
      all_errors := errors @ !all_errors
    ) func.func_body
  ) program.prog_functions;
  
  !all_errors

(** Perform pointer safety analysis *)
let analyze_pointer_safety program =
  let all_valid = ref [] in
  let all_invalid = ref [] in
  
  List.iter (fun func ->
    List.iter (fun stmt ->
      let rec check_stmt s =
        match s.stmt_desc with
        | ExprStmt expr | Assignment (_, expr) ->
            let (valid, invalid) = check_pointer_safety expr in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid
        | FieldAssignment (obj_expr, _, value_expr) ->
            let (v1, i1) = check_pointer_safety obj_expr in
            let (v2, i2) = check_pointer_safety value_expr in
            all_valid := v1 @ v2 @ !all_valid;
            all_invalid := i1 @ i2 @ !all_invalid
        | If (cond, then_stmts, else_opt) ->
            let (valid, invalid) = check_pointer_safety cond in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid;
            List.iter check_stmt then_stmts;
            (match else_opt with
             | None -> ()
             | Some else_stmts -> List.iter check_stmt else_stmts)
        | For (_, start, end_, body) ->
            let (v1, i1) = check_pointer_safety start in
            let (v2, i2) = check_pointer_safety end_ in
            all_valid := v1 @ v2 @ !all_valid;
            all_invalid := i1 @ i2 @ !all_invalid;
            List.iter check_stmt body
        | While (cond, body) ->
            let (valid, invalid) = check_pointer_safety cond in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid;
            List.iter check_stmt body
        | Return (Some expr) ->
            let (valid, invalid) = check_pointer_safety expr in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid
        | _ -> ()
      in
      check_stmt stmt
    ) func.func_body
  ) program.prog_functions;
  
  {
    valid_pointers = !all_valid;
    invalid_pointers = !all_invalid;
    dangling_pointers = []; (* Would need more sophisticated analysis *)
    null_checks_needed = List.map fst !all_invalid;
  }

(** Perform map access safety analysis *)
let analyze_map_access_safety program =
  let all_valid = ref [] in
  let all_invalid = ref [] in
  let all_warnings = ref [] in
  
  List.iter (fun func ->
    List.iter (fun stmt ->
      let rec check_stmt s =
        match s.stmt_desc with
        | ExprStmt expr | Assignment (_, expr) ->
            let (valid, invalid, warnings) = check_map_operations expr in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid;
            all_warnings := warnings @ !all_warnings
        | If (cond, then_stmts, else_opt) ->
            let (valid, invalid, warnings) = check_map_operations cond in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid;
            all_warnings := warnings @ !all_warnings;
            List.iter check_stmt then_stmts;
            (match else_opt with
             | None -> ()
             | Some else_stmts -> List.iter check_stmt else_stmts)
        | For (_, start, end_, body) ->
            let (v1, i1, w1) = check_map_operations start in
            let (v2, i2, w2) = check_map_operations end_ in
            all_valid := v1 @ v2 @ !all_valid;
            all_invalid := i1 @ i2 @ !all_invalid;
            all_warnings := w1 @ w2 @ !all_warnings;
            List.iter check_stmt body
        | While (cond, body) ->
            let (valid, invalid, warnings) = check_map_operations cond in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid;
            all_warnings := warnings @ !all_warnings;
            List.iter check_stmt body
        | Return (Some expr) ->
            let (valid, invalid, warnings) = check_map_operations expr in
            all_valid := valid @ !all_valid;
            all_invalid := invalid @ !all_invalid;
            all_warnings := warnings @ !all_warnings
        | _ -> ()
      in
      check_stmt stmt
    ) func.func_body
  ) program.prog_functions;
  
  {
    valid_accesses = !all_valid;
    invalid_accesses = !all_invalid;
    missing_bounds_checks = [];
    concurrent_access_issues = [];
  }

(** Check for infinite loops *)
let check_infinite_loops program =
  let has_infinite_loop = ref false in
  
  let rec check_stmt stmt =
    match stmt.stmt_desc with
    | While (cond, _body) ->
        (* Check for obviously infinite loops *)
        (match cond.expr_desc with
         | Literal (BoolLit true) -> has_infinite_loop := true
         | _ -> ())
    | For (_, start, end_, _body) ->
        (* Check for infinite for loops *)
        (match start.expr_desc, end_.expr_desc with
         | Literal (IntLit (s, _)), Literal (IntLit (e, _)) when s >= e -> has_infinite_loop := true
         | _ -> ())
    | If (_, then_stmts, else_opt) ->
        List.iter check_stmt then_stmts;
        (match else_opt with
         | None -> ()
         | Some else_stmts -> List.iter check_stmt else_stmts)
    | _ -> ()
  in
  
  List.iter (fun func ->
    List.iter check_stmt func.func_body
  ) program.prog_functions;
  
  !has_infinite_loop

(** Main safety analysis function *)
let analyze_safety program =
  let stack_analysis = analyze_stack_usage program in
  let bounds_errors = analyze_bounds_safety program in
  let pointer_safety = analyze_pointer_safety program in
  let map_safety = analyze_map_access_safety program in
  let has_infinite_loops = check_infinite_loops program in
  
  let overall_safe = 
    not stack_analysis.potential_overflow &&
    bounds_errors = [] &&
    pointer_safety.invalid_pointers = [] &&
    not has_infinite_loops in
  
  {
    stack_analysis = stack_analysis;
    bounds_errors = bounds_errors;
    pointer_safety = pointer_safety;
    map_safety = map_safety;
    overall_safe = overall_safe;
  }

(** Exception for safety violations *)
exception Bounds_error of bounds_error

(** Safety check function that returns analysis results *)
let safety_check program =
  analyze_safety program

(** Pretty printing functions *)

let string_of_bounds_error = function
  | ArrayOutOfBounds (var, idx, size) ->
      Printf.sprintf "Array bounds error: %s[%d] exceeds size %d" var idx size
  | InvalidArraySize (var, size) ->
      Printf.sprintf "Invalid array size: %s has size %d" var size
  | PointerOutOfBounds ptr ->
      Printf.sprintf "Pointer out of bounds: %s" ptr
  | NullPointerDereference ptr ->
      Printf.sprintf "Null pointer dereference: %s" ptr
  | UnknownBounds var ->
      Printf.sprintf "Unknown bounds for variable: %s" var

let string_of_stack_analysis analysis =
  Printf.sprintf "Stack analysis: max=%d bytes, overflow=%b, functions=[%s]"
    analysis.max_stack_usage
    analysis.potential_overflow
    (String.concat "; " (List.map (fun (name, size) -> 
       Printf.sprintf "%s:%d" name size) analysis.function_usage))

let string_of_safety_analysis analysis =
  Printf.sprintf "Safety analysis: safe=%b, bounds_errors=%d, invalid_pointers=%d, invalid_map_accesses=%d"
    analysis.overall_safe
    (List.length analysis.bounds_errors)
    (List.length analysis.pointer_safety.invalid_pointers)
    (List.length analysis.map_safety.invalid_accesses)

(** Debug functions *)

let print_stack_analysis analysis =
  print_endline (string_of_stack_analysis analysis)

let print_safety_analysis analysis =
  print_endline (string_of_safety_analysis analysis);
  Printf.printf "Stack: %s\n" (string_of_stack_analysis analysis.stack_analysis);
  if analysis.bounds_errors <> [] then begin
    Printf.printf "Bounds errors:\n";
    List.iter (fun error -> 
      Printf.printf "  - %s\n" (string_of_bounds_error error)
    ) analysis.bounds_errors
  end 