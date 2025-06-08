(** IR Generator - AST to IR Lowering
    This module implements the lowering from typed AST to IR, including:
    - Expression and statement lowering
    - Control flow graph construction  
    - Built-in function expansion
    - Safety check insertion
    - Map operation lowering
*)

open Ast
open Ir

(** Context for IR generation *)
type ir_context = {
  (* Variable to register mapping *)
  variables: (string, int) Hashtbl.t;
  (* Next available register *)
  mutable next_register: int;
  (* Current basic block being built *)
  mutable current_block: ir_instruction list;
  (* All basic blocks generated *)
  mutable blocks: ir_basic_block list;
  (* Next block ID *)
  mutable next_block_id: int;
  (* Current stack usage *)
  mutable stack_usage: int;
  (* Map declarations in scope *)
  maps: (string, ir_map_def) Hashtbl.t;
  (* Function being processed *)
  mutable current_function: string option;
  (* Symbol table reference *)
  symbol_table: Symbol_table.symbol_table;
}

(** Create new IR generation context *)
let create_context symbol_table = {
  variables = Hashtbl.create 32;
  next_register = 0;
  current_block = [];
  blocks = [];
  next_block_id = 0;
  stack_usage = 0;
  maps = Hashtbl.create 16;
  current_function = None;
  symbol_table;
}

(** Register allocation *)
let allocate_register ctx =
  let reg = ctx.next_register in
  ctx.next_register <- ctx.next_register + 1;
  reg

(** Get or allocate register for variable *)
let get_variable_register ctx name =
  match Hashtbl.find_opt ctx.variables name with
  | Some reg -> reg
  | None ->
      let reg = allocate_register ctx in
      Hashtbl.add ctx.variables name reg;
      reg

(** Create new basic block *)
let create_basic_block ctx label =
  let block_id = ctx.next_block_id in
  ctx.next_block_id <- ctx.next_block_id + 1;
  let block = make_ir_basic_block label (List.rev ctx.current_block) block_id in
  ctx.blocks <- block :: ctx.blocks;
  ctx.current_block <- [];
  block

(** Add instruction to current block *)
let emit_instruction ctx instr =
  ctx.current_block <- instr :: ctx.current_block;
  ctx.stack_usage <- ctx.stack_usage + instr.instr_stack_usage

(** Generate bounds information for types *)
let generate_bounds_info = function
  | Array (_, size) -> make_bounds_info ~min_size:size ~max_size:size ()
  | Pointer _ -> make_bounds_info ~nullable:true ()
  | _ -> make_bounds_info ()

(** Lower AST literals to IR values *)
let lower_literal lit pos =
  let ir_lit = IRLiteral lit in
  let ir_type = match lit with
    | IntLit _ -> IRU32  (* Default integer type *)
    | StringLit _ -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
    | CharLit _ -> IRChar
    | BoolLit _ -> IRBool
  in
  make_ir_value ir_lit ir_type pos

(** Lower AST binary operators to IR *)
let lower_binary_op = function
  | Add -> IRAdd | Sub -> IRSub | Mul -> IRMul | Div -> IRDiv | Mod -> IRMod
  | Eq -> IREq | Ne -> IRNe | Lt -> IRLt | Le -> IRLe | Gt -> IRGt | Ge -> IRGe
  | And -> IRAnd | Or -> IROr

(** Lower AST unary operators to IR *)
let lower_unary_op = function
  | Not -> IRNot
  | Neg -> IRNeg

(** Generate bounds check for array access *)
let generate_array_bounds_check ctx array_val index_val pos =
  match array_val.val_type with
  | IRArray (_, size, _) ->
      let bounds_check = {
        value = index_val;
        min_bound = 0;
        max_bound = size - 1;
        check_type = ArrayAccess;
      } in
      let instr = make_ir_instruction
        (IRBoundsCheck (index_val, 0, size - 1))
        ~bounds_checks:[bounds_check]
        ~verifier_hints:[BoundsChecked]
        pos
      in
      emit_instruction ctx instr
  | _ -> ()

(** Expand built-in context methods *)
let expand_context_method ctx method_name _args pos =
  let result_reg = allocate_register ctx in
  let result_type = match method_name with
    | "packet" -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
    | "packet_end" -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
    | "data_len" -> IRU32
    | _ -> failwith ("Unknown context method: " ^ method_name)
  in
  let result_val = make_ir_value (IRRegister result_reg) result_type pos in
  
  let access_type = match method_name with
    | "packet" -> PacketData
    | "packet_end" -> PacketEnd
    | "data_len" -> DataLen
    | _ -> failwith ("Unknown context method: " ^ method_name)
  in
  
  let instr = make_ir_instruction
    (IRContextAccess (result_val, access_type))
    ~verifier_hints:[HelperCall method_name]
    pos
  in
  emit_instruction ctx instr;
  result_val

(** Expand map operations *)
let expand_map_operation ctx map_name operation key_val value_val_opt pos =
  let map_def = Hashtbl.find ctx.maps map_name in
  let map_val = make_ir_value (IRMapRef map_name) 
    (IRPointer (IRStruct ("map", []), make_bounds_info ())) pos in
  
  match operation with
  | "lookup" ->
      let result_reg = allocate_register ctx in
      let result_val = make_ir_value (IRRegister result_reg) map_def.map_value_type pos in
      let instr = make_ir_instruction
        (IRMapLoad (map_val, key_val, result_val, MapLookup))
        ~verifier_hints:[HelperCall "map_lookup_elem"]
        pos
      in
      emit_instruction ctx instr;
      result_val
  | "update" ->
      let value_val = match value_val_opt with
        | Some v -> v
        | None -> failwith "Map update requires value"
      in
      let instr = make_ir_instruction
        (IRMapStore (map_val, key_val, value_val, MapUpdate))
        ~verifier_hints:[HelperCall "map_update_elem"]
        pos
      in
      emit_instruction ctx instr;
      (* Return success value *)
      make_ir_value (IRLiteral (IntLit 0)) IRU32 pos
  | "delete" ->
      let instr = make_ir_instruction
        (IRMapDelete (map_val, key_val))
        ~verifier_hints:[HelperCall "map_delete_elem"]
        pos
      in
      emit_instruction ctx instr;
      make_ir_value (IRLiteral (IntLit 0)) IRU32 pos
  | _ -> failwith ("Unknown map operation: " ^ operation)

(** Lower AST expressions to IR values *)
let rec lower_expression ctx (expr : Ast.expr) =
  match expr.expr_desc with
  | Ast.Literal lit ->
      lower_literal lit expr.expr_pos
      
  | Ast.Identifier name ->
      let reg = get_variable_register ctx name in
      let ir_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> failwith ("Untyped identifier: " ^ name)
      in
      make_ir_value (IRRegister reg) ir_type expr.expr_pos
      
  | Ast.FunctionCall (name, args) ->
      let arg_vals = List.map (lower_expression ctx) args in
      
      (* Check for built-in context methods *)
      if String.contains name '.' then
        let parts = String.split_on_char '.' name in
        match parts with
        | ["ctx"; method_name] ->
            expand_context_method ctx method_name arg_vals expr.expr_pos
        | [map_name; operation] when Hashtbl.mem ctx.maps map_name ->
            let key_val = List.hd arg_vals in
            let value_val_opt = if List.length arg_vals > 1 then Some (List.nth arg_vals 1) else None in
            expand_map_operation ctx map_name operation key_val value_val_opt expr.expr_pos
        | _ ->
            (* Regular function call *)
            let result_reg = allocate_register ctx in
            let result_type = match expr.expr_type with
              | Some ast_type -> ast_type_to_ir_type ast_type
              | None -> IRU32 (* Default return type *)
            in
            let result_val = make_ir_value (IRRegister result_reg) result_type expr.expr_pos in
            let instr = make_ir_instruction
              (IRCall (name, arg_vals, Some result_val))
              ~verifier_hints:[HelperCall name]
              expr.expr_pos
            in
            emit_instruction ctx instr;
            result_val
      else
        (* Regular function call *)
        let result_reg = allocate_register ctx in
        let result_type = match expr.expr_type with
          | Some ast_type -> ast_type_to_ir_type ast_type
          | None -> IRU32
        in
        let result_val = make_ir_value (IRRegister result_reg) result_type expr.expr_pos in
        let instr = make_ir_instruction
          (IRCall (name, arg_vals, Some result_val))
          expr.expr_pos
        in
        emit_instruction ctx instr;
        result_val
        
  | Ast.ArrayAccess (array_expr, index_expr) ->
      let array_val = lower_expression ctx array_expr in
      let index_val = lower_expression ctx index_expr in
      
      (* Generate bounds check *)
      generate_array_bounds_check ctx array_val index_val expr.expr_pos;
      
      (* Check if this is map access *)
      (match array_expr.expr_desc with
       | Ast.Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           expand_map_operation ctx map_name "lookup" index_val None expr.expr_pos
       | _ ->
           (* Regular array access *)
           let result_reg = allocate_register ctx in
           let element_type = match array_val.val_type with
             | IRArray (elem_type, _, _) -> elem_type
             | _ -> failwith "Array access on non-array type"
           in
           let result_val = make_ir_value (IRRegister result_reg) element_type expr.expr_pos in
           
           (* Generate pointer arithmetic and load *)
           let ptr_reg = allocate_register ctx in
           let ptr_val = make_ir_value (IRRegister ptr_reg) 
             (IRPointer (element_type, make_bounds_info ())) expr.expr_pos in
           
           (* ptr = &array[index] *)
           let ptr_expr = make_ir_expr (IRBinOp (array_val, IRAdd, index_val)) 
             ptr_val.val_type expr.expr_pos in
           let ptr_assign = make_ir_instruction (IRAssign (ptr_val, ptr_expr)) expr.expr_pos in
           emit_instruction ctx ptr_assign;
           
           (* result = *ptr *)
           let load_expr = make_ir_expr (IRValue ptr_val) element_type expr.expr_pos in
           let load_assign = make_ir_instruction (IRAssign (result_val, load_expr)) expr.expr_pos in
           emit_instruction ctx load_assign;
           
           result_val)
           
  | Ast.FieldAccess (obj_expr, field) ->
      let obj_val = lower_expression ctx obj_expr in
      let result_reg = allocate_register ctx in
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> IRU32
      in
      let result_val = make_ir_value (IRRegister result_reg) result_type expr.expr_pos in
      
      (* Handle context field access *)
      (match obj_val.val_type with
       | IRContext _ctx_type ->
           let access_type = match field with
             | "packet" -> PacketData
             | "packet_end" -> PacketEnd
             | "data_meta" -> DataMeta
             | "ingress_ifindex" -> IngressIfindex
             | "data_len" -> DataLen
             | "mark" -> MarkField
             | "priority" -> Priority
             | "cb" -> CbField
             | _ -> failwith ("Unknown context field: " ^ field)
           in
           let instr = make_ir_instruction
             (IRContextAccess (result_val, access_type))
             expr.expr_pos
           in
           emit_instruction ctx instr;
           result_val
       | _ ->
           failwith "Field access on non-context type not implemented yet")
           
  | Ast.BinaryOp (left_expr, op, right_expr) ->
      let left_val = lower_expression ctx left_expr in
      let right_val = lower_expression ctx right_expr in
      let ir_op = lower_binary_op op in
      
      let result_reg = allocate_register ctx in
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> left_val.val_type (* Use left operand type *)
      in
      let result_val = make_ir_value (IRRegister result_reg) result_type expr.expr_pos in
      
      let bin_expr = make_ir_expr (IRBinOp (left_val, ir_op, right_val)) result_type expr.expr_pos in
      let instr = make_ir_instruction (IRAssign (result_val, bin_expr)) expr.expr_pos in
      emit_instruction ctx instr;
      result_val
      
  | Ast.UnaryOp (op, operand_expr) ->
      let operand_val = lower_expression ctx operand_expr in
      let ir_op = lower_unary_op op in
      
      let result_reg = allocate_register ctx in
      let result_type = operand_val.val_type in
      let result_val = make_ir_value (IRRegister result_reg) result_type expr.expr_pos in
      
      let un_expr = make_ir_expr (IRUnOp (ir_op, operand_val)) result_type expr.expr_pos in
      let instr = make_ir_instruction (IRAssign (result_val, un_expr)) expr.expr_pos in
      emit_instruction ctx instr;
      result_val

(** Lower AST statements to IR instructions *)
let rec lower_statement ctx stmt =
  match stmt.stmt_desc with
  | Ast.ExprStmt expr ->
      let _ = lower_expression ctx expr in
      ()
      
  | Ast.Assignment (name, expr) ->
      let value = lower_expression ctx expr in
      let reg = get_variable_register ctx name in
      let target_type = value.val_type in
      let target_val = make_ir_value (IRRegister reg) target_type stmt.stmt_pos in
      let value_expr = make_ir_expr (IRValue value) target_type stmt.stmt_pos in
      let instr = make_ir_instruction (IRAssign (target_val, value_expr)) stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Declaration (name, typ_opt, expr) ->
      let value = lower_expression ctx expr in
      let reg = get_variable_register ctx name in
      let target_type = match typ_opt with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> value.val_type
      in
      
      (* Add stack usage for local variables *)
      let size = match target_type with
        | IRU8 | IRChar -> 1
        | IRU16 -> 2
        | IRU32 | IRBool -> 4
        | IRU64 -> 8
        | IRArray (_, count, _) -> count * 4 (* Simplified *)
        | _ -> 8 (* Conservative estimate *)
      in
      ctx.stack_usage <- ctx.stack_usage + size;
      
      let target_val = make_ir_value (IRRegister reg) target_type stmt.stmt_pos in
      let value_expr = make_ir_expr (IRValue value) target_type stmt.stmt_pos in
      let instr = make_ir_instruction 
        (IRAssign (target_val, value_expr)) 
        ~stack_usage:size
        stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Return expr_opt ->
      let return_val = match expr_opt with
        | Some expr -> Some (lower_expression ctx expr)
        | None -> None
      in
      let instr = make_ir_instruction (IRReturn return_val) stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.If (cond_expr, then_stmts, else_opt) ->
      let cond_val = lower_expression ctx cond_expr in
      
      (* Create labels for control flow *)
      let then_label = Printf.sprintf "then_%d" ctx.next_block_id in
      let else_label = Printf.sprintf "else_%d" (ctx.next_block_id + 1) in
      let merge_label = Printf.sprintf "merge_%d" (ctx.next_block_id + 2) in
      
      (* Conditional jump *)
      let cond_jump = make_ir_instruction 
        (IRCondJump (cond_val, then_label, else_label)) 
        stmt.stmt_pos in
      emit_instruction ctx cond_jump;
      
      (* End current block *)
      let _ = create_basic_block ctx "cond_block" in
      
      (* Then block *)
      List.iter (lower_statement ctx) then_stmts;
      let jump_to_merge = make_ir_instruction (IRJump merge_label) stmt.stmt_pos in
      emit_instruction ctx jump_to_merge;
      let _then_block = create_basic_block ctx then_label in
      
      (* Else block *)
      (match else_opt with
       | Some else_stmts -> List.iter (lower_statement ctx) else_stmts
       | None -> ());
      let else_jump_to_merge = make_ir_instruction (IRJump merge_label) stmt.stmt_pos in
      emit_instruction ctx else_jump_to_merge;
      let _else_block = create_basic_block ctx else_label in
      
      (* Merge block *)
      let _merge_block = create_basic_block ctx merge_label in
      
      (* Note: Control flow connections will be established during CFG construction *)
      ()
      
  | Ast.For (var, start_expr, end_expr, body_stmts) ->
      let start_val = lower_expression ctx start_expr in
      let end_val = lower_expression ctx end_expr in
      
      (* Create loop counter variable *)
      let counter_reg = get_variable_register ctx var in
      let counter_val = make_ir_value (IRRegister counter_reg) IRU32 stmt.stmt_pos in
      
      (* Initialize counter *)
      let init_expr = make_ir_expr (IRValue start_val) IRU32 stmt.stmt_pos in
      let init_instr = make_ir_instruction (IRAssign (counter_val, init_expr)) stmt.stmt_pos in
      emit_instruction ctx init_instr;
      
      (* Loop labels *)
      let loop_header = Printf.sprintf "loop_header_%d" ctx.next_block_id in
      let loop_body = Printf.sprintf "loop_body_%d" (ctx.next_block_id + 1) in
      let loop_exit = Printf.sprintf "loop_exit_%d" (ctx.next_block_id + 2) in
      
      (* Jump to loop header *)
      let jump_to_header = make_ir_instruction (IRJump loop_header) stmt.stmt_pos in
      emit_instruction ctx jump_to_header;
      let _pre_loop_block = create_basic_block ctx "pre_loop" in
      
      (* Loop condition check *)
      let cond_reg = allocate_register ctx in
      let cond_val = make_ir_value (IRRegister cond_reg) IRBool stmt.stmt_pos in
      let cond_expr = make_ir_expr (IRBinOp (counter_val, IRLt, end_val)) IRBool stmt.stmt_pos in
      let cond_instr = make_ir_instruction (IRAssign (cond_val, cond_expr)) stmt.stmt_pos in
      emit_instruction ctx cond_instr;
      
      let loop_cond_jump = make_ir_instruction 
        (IRCondJump (cond_val, loop_body, loop_exit)) 
        stmt.stmt_pos in
      emit_instruction ctx loop_cond_jump;
      let _header_block = create_basic_block ctx loop_header in
      
      (* Loop body *)
      List.iter (lower_statement ctx) body_stmts;
      
      (* Increment counter *)
      let one_val = make_ir_value (IRLiteral (IntLit 1)) IRU32 stmt.stmt_pos in
      let inc_expr = make_ir_expr (IRBinOp (counter_val, IRAdd, one_val)) IRU32 stmt.stmt_pos in
      let inc_instr = make_ir_instruction (IRAssign (counter_val, inc_expr)) stmt.stmt_pos in
      emit_instruction ctx inc_instr;
      
      (* Jump back to header *)
      let back_jump = make_ir_instruction (IRJump loop_header) stmt.stmt_pos in
      emit_instruction ctx back_jump;
      let _body_block = create_basic_block ctx loop_body in
      
      (* Exit block *)
      let _exit_block = create_basic_block ctx loop_exit in
      
      (* Note: Control flow connections and loop depth will be established during CFG construction *)
      ()
      
  | Ast.While (cond_expr, body_stmts) ->
      (* Similar to for loop but without counter management *)
      let loop_header = Printf.sprintf "while_header_%d" ctx.next_block_id in
      let loop_body = Printf.sprintf "while_body_%d" (ctx.next_block_id + 1) in
      let loop_exit = Printf.sprintf "while_exit_%d" (ctx.next_block_id + 2) in
      
      (* Jump to header *)
      let jump_to_header = make_ir_instruction (IRJump loop_header) stmt.stmt_pos in
      emit_instruction ctx jump_to_header;
      let _pre_while_block = create_basic_block ctx "pre_while" in
      
      (* Condition check *)
      let cond_val = lower_expression ctx cond_expr in
      let while_cond_jump = make_ir_instruction 
        (IRCondJump (cond_val, loop_body, loop_exit)) 
        stmt.stmt_pos in
      emit_instruction ctx while_cond_jump;
      let _header_block = create_basic_block ctx loop_header in
      
      (* Body *)
      List.iter (lower_statement ctx) body_stmts;
      let back_jump = make_ir_instruction (IRJump loop_header) stmt.stmt_pos in
      emit_instruction ctx back_jump;
      let _body_block = create_basic_block ctx loop_body in
      
      (* Exit *)
      let _exit_block = create_basic_block ctx loop_exit in
      
      (* Note: Control flow connections and loop depth will be established during CFG construction *)
      ()

(** Lower AST function to IR function *)
let lower_function ctx (func_def : Ast.function_def) =
  ctx.current_function <- Some func_def.func_name;
  
  (* Reset for new function *)
  Hashtbl.clear ctx.variables;
  ctx.next_register <- 0;
  ctx.current_block <- [];
  ctx.blocks <- [];
  ctx.stack_usage <- 0;
  
  (* Allocate registers for parameters *)
  let ir_params = List.map (fun (name, ast_type) ->
    let _reg = get_variable_register ctx name in
    let ir_type = ast_type_to_ir_type ast_type in
    (name, ir_type)
  ) func_def.func_params in
  
  (* Lower function body *)
  List.iter (lower_statement ctx) func_def.func_body;
  
  (* Create final block if needed *)
  (if ctx.current_block <> [] then
    let _ = create_basic_block ctx "final_block" in
    ()
  );
  
  (* Convert return type *)
  let ir_return_type = match func_def.func_return_type with
    | Some ast_type -> Some (ast_type_to_ir_type ast_type)
    | None -> None
  in
  
  (* Create IR function *)
  let ir_blocks = List.rev ctx.blocks in
  let is_main = func_def.func_name = "main" in
  
  make_ir_function 
    func_def.func_name 
    ir_params 
    ir_return_type 
    ir_blocks
    ~total_stack_usage:ctx.stack_usage
    ~is_main:is_main
    func_def.func_pos

(** Lower AST map declaration to IR map definition *)
let lower_map_declaration map_decl =
  let ir_key_type = ast_type_to_ir_type map_decl.key_type in
  let ir_value_type = ast_type_to_ir_type map_decl.value_type in
  let ir_map_type = ast_map_type_to_ir_map_type map_decl.map_type in
  
  let ir_attributes = List.filter_map (fun attr ->
    match attr with
    | Ast.Pinned _ -> None (* Handled separately *)
    | _ -> Some (ast_map_attr_to_ir_map_attr attr)
  ) map_decl.config.attributes in
  
  let pin_path = List.fold_left (fun acc attr ->
    match attr with
    | Ast.Pinned path -> Some path
    | _ -> acc
  ) None map_decl.config.attributes in
  
  make_ir_map_def
    map_decl.name
    ir_key_type
    ir_value_type
    ir_map_type
    map_decl.config.max_entries
    ~attributes:ir_attributes
    ~is_global:map_decl.is_global
    ?pin_path:pin_path
    map_decl.map_pos

(** Generate userspace bindings for a program *)
let generate_userspace_bindings _prog_def maps =
  let map_wrappers = List.map (fun map_def ->
    {
      wrapper_map_name = map_def.map_name;
      operations = [OpLookup; OpUpdate; OpDelete];
      safety_checks = true;
    }
  ) maps in
  
  let c_bindings = {
    language = C;
    map_wrappers;
    event_handlers = [];
    config_structs = [];
  } in
  
  [c_bindings]

(** Lower complete AST to IR program *)
let lower_program ast symbol_table =
  let ctx = create_context symbol_table in
  
  (* Find the program declaration *)
  let prog_def = List.find_map (function
    | Ast.Program p -> Some p
    | _ -> None
  ) ast in
  
  let prog_def = match prog_def with
    | Some p -> p
    | None -> failwith "No program declaration found"
  in
  
  (* Collect map declarations *)
  let map_decls = List.filter_map (function
    | Ast.MapDecl m -> Some m
    | _ -> None
  ) ast in
  
  let (global_map_decls, local_map_decls) = List.partition (fun (m : Ast.map_declaration) -> m.is_global) map_decls in
  
  (* Lower maps *)
  let ir_global_maps = List.map lower_map_declaration global_map_decls in
  let ir_local_maps = List.map lower_map_declaration local_map_decls in
  
  (* Add maps to context *)
  List.iter (fun ir_map -> 
    Hashtbl.add ctx.maps ir_map.map_name ir_map
  ) (ir_global_maps @ ir_local_maps);
  
  (* Lower functions *)
  let ir_functions = List.map (lower_function ctx) prog_def.prog_functions in
  
  (* Find main function *)
  let main_function = List.find (fun f -> f.is_main) ir_functions in
  
  (* Generate userspace bindings *)
  let userspace_bindings = generate_userspace_bindings prog_def (ir_global_maps @ ir_local_maps) in
  
  (* Create IR program *)
  make_ir_program
    prog_def.prog_name
    prog_def.prog_type
    ir_global_maps
    ir_local_maps
    ir_functions
    main_function
    ~userspace_bindings:userspace_bindings
    prog_def.prog_pos

(** Main entry point for IR generation *)
let generate_ir ast symbol_table =
  try
    lower_program ast symbol_table
  with
  | exn ->
      Printf.eprintf "IR generation failed: %s\n" (Printexc.to_string exn);
      raise exn 