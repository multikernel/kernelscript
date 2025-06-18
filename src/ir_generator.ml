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
open Maps
open Loop_analysis

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
  (* Assignment optimization info *)
  mutable assignment_optimizations: Map_assignment.optimization_info option;
  (* Constant environment for loop analysis *)
  mutable const_env: Loop_analysis.const_env option;
  mutable in_bpf_loop_callback: bool; (* New field to track bpf_loop context *)
  mutable is_userspace: bool; (* New field to track if the program is userspace *)
  mutable in_try_block: bool; (* New field to track if we're inside a try block *)
  (* Track which registers were declared with type aliases *)
  register_aliases: (int, string * ir_type) Hashtbl.t; (* register -> (alias_name, underlying_type) *)
  (* Track variable names to their original declared type names *)
  variable_declared_types: (string, string) Hashtbl.t; (* variable_name -> original_type_name *)
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
  assignment_optimizations = None;
  const_env = None;
  in_bpf_loop_callback = false;
  is_userspace = false;
  in_try_block = false;
  register_aliases = Hashtbl.create 32;
  variable_declared_types = Hashtbl.create 32;
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

(** Analyze assignment patterns for optimization *)
let analyze_assignment_patterns ctx (ast: declaration list) =
  let assignments = Map_assignment.extract_map_assignments_from_ast ast in
  let optimization_info = Map_assignment.analyze_assignment_optimizations assignments in
  ctx.assignment_optimizations <- Some optimization_info;
  optimization_info

(** Add instruction to current block *)
let emit_instruction ctx instr =
  ctx.current_block <- instr :: ctx.current_block;
  ctx.stack_usage <- ctx.stack_usage + instr.instr_stack_usage

(** Generate bounds information for types *)
let generate_bounds_info ast_type = match ast_type with
  | Ast.Array (_, size) -> make_bounds_info ~min_size:size ~max_size:size ()
  | Ast.Pointer _ -> make_bounds_info ~nullable:true ()
  | _ -> make_bounds_info ()

(** Lower AST literals to IR values *)
let lower_literal lit pos =
  let ir_lit = IRLiteral lit in
  let ir_type = match lit with
    | IntLit _ -> IRU32  (* Default integer type *)
    | StringLit s -> IRStr (max 1 (String.length s))  (* String literals get IRStr type *)
    | CharLit _ -> IRChar
    | BoolLit _ -> IRBool
    | ArrayLit literals -> 
        (* Implement proper array literal lowering *)
        let element_count = List.length literals in
        if element_count = 0 then
          (* Empty array defaults to u32 *)
          IRArray (IRU32, 0, make_bounds_info ())
        else
          (* Determine element type from first literal *)
          let first_lit = List.hd literals in
          let element_ir_type = match first_lit with
            | IntLit _ -> IRU32
            | BoolLit _ -> IRBool
            | CharLit _ -> IRChar
            | StringLit _ -> IRPointer (IRU8, make_bounds_info ~nullable:false ())
            | ArrayLit _ -> IRU32  (* Nested arrays default to u32 for now *)
          in
          let bounds_info = make_bounds_info ~min_size:element_count ~max_size:element_count () in
          IRArray (element_ir_type, element_count, bounds_info)
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
      (* Check if this is a map identifier *)
      if Hashtbl.mem ctx.maps name then
        (* For map identifiers, create a map reference *)
        let map_type = IRPointer (IRU8, make_bounds_info ()) in (* Maps are represented as pointers *)
        make_ir_value (IRMapRef name) map_type expr.expr_pos
      else
        (* Check if this is a program reference *)
        (match expr.expr_type with
         | Some (ProgramRef _) ->
             (* Program references should be converted to string literals containing the program name *)
             make_ir_value (IRLiteral (StringLit name)) IRU32 expr.expr_pos
         | _ ->
             (* Check if this is a constant from the symbol table *)
             (match Symbol_table.lookup_symbol ctx.symbol_table name with
              | Some symbol -> 
                  (match symbol.kind with
                   | Symbol_table.EnumConstant (_, Some value) ->
                       (* Enum constants are treated as constants *)
                       let ir_type = match expr.expr_type with
                         | Some ast_type -> ast_type_to_ir_type ast_type
                         | None -> IRU32
                       in
                       make_ir_value (IRLiteral (IntLit value)) ir_type expr.expr_pos
                   | Symbol_table.EnumConstant (_, None) ->
                       (* Enum constant without value - treat as variable *)
                       let reg = get_variable_register ctx name in
                       let ir_type = match expr.expr_type with
                         | Some ast_type -> ast_type_to_ir_type ast_type
                         | None -> failwith ("Untyped identifier: " ^ name)
                       in
                       make_ir_value (IRRegister reg) ir_type expr.expr_pos
                   | _ ->
                       (* Regular variable *)
                       let reg = get_variable_register ctx name in
                       let ir_type = match expr.expr_type with
                         | Some ast_type -> ast_type_to_ir_type ast_type
                         | None -> failwith ("Untyped identifier: " ^ name)
                       in
                       make_ir_value (IRRegister reg) ir_type expr.expr_pos)
              | None ->
                  (* Regular variable *)
                  let reg = get_variable_register ctx name in
                  let ir_type = match expr.expr_type with
                    | Some ast_type -> ast_type_to_ir_type ast_type
                    | None -> failwith ("Untyped identifier: " ^ name)
                  in
                  make_ir_value (IRRegister reg) ir_type expr.expr_pos))
      
  | Ast.ConfigAccess (config_name, field_name) ->
      (* Handle config access like config.field_name *)
      let result_reg = allocate_register ctx in
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> IRU32 (* Default type for config fields *)
      in
      let result_val = make_ir_value (IRRegister result_reg) result_type expr.expr_pos in
      
      (* Generate new IRConfigAccess instruction *)
      let config_access_instr = make_ir_instruction
        (IRConfigAccess (config_name, field_name, result_val))
        expr.expr_pos
      in
      emit_instruction ctx config_access_instr;
      result_val
      
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
      (* Check if this is map access first, before calling lower_expression on array *)
      (match array_expr.expr_desc with
       | Ast.Identifier map_name when Hashtbl.mem ctx.maps map_name ->
           (* This is map access - handle it specially *)
           let index_val = lower_expression ctx index_expr in
           expand_map_operation ctx map_name "lookup" index_val None expr.expr_pos
       | _ ->
           (* Regular array access *)
           let array_val = lower_expression ctx array_expr in
           let index_val = lower_expression ctx index_expr in
           
           (* Generate bounds check *)
           generate_array_bounds_check ctx array_val index_val expr.expr_pos;
           
           let result_reg = allocate_register ctx in
           let element_type = match array_val.val_type with
             | IRArray (elem_type, _, _) -> elem_type
             | IRStr _ -> IRChar  (* String indexing returns char *)
             | _ -> failwith "Array access on non-array type"
           in
           let result_val = make_ir_value (IRRegister result_reg) element_type expr.expr_pos in
           
           (match array_val.val_type with
            | IRStr _ ->
                (* For strings, generate direct indexing: str.data[index] *)
                let index_expr = make_ir_expr (IRBinOp (array_val, IRAdd, index_val)) element_type expr.expr_pos in
                let index_assign = make_ir_instruction (IRAssign (result_val, index_expr)) expr.expr_pos in
                emit_instruction ctx index_assign
            | _ ->
                (* For arrays, generate pointer arithmetic and load *)
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
                emit_instruction ctx load_assign);
           
           result_val)
           
  | Ast.FieldAccess (obj_expr, field) ->
      let obj_val = lower_expression ctx obj_expr in
      let result_reg = allocate_register ctx in
      let result_type = match expr.expr_type with
        | Some ast_type -> ast_type_to_ir_type ast_type
        | None -> IRU32
      in
      let result_val = make_ir_value (IRRegister result_reg) result_type expr.expr_pos in
      
      (* Handle field access for different types *)
      (match obj_val.val_type with
       | IRContext _ctx_type ->
           (* Handle context field access *)
           let access_type = match field with
             | "packet" | "data" -> PacketData
             | "packet_end" | "data_end" -> PacketEnd
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
       | IRStruct (_, _) ->
           (* Handle struct field access *)
           let field_expr = make_ir_expr (IRFieldAccess (obj_val, field)) result_type expr.expr_pos in
           let instr = make_ir_instruction (IRAssign (result_val, field_expr)) expr.expr_pos in
           emit_instruction ctx instr;
           result_val
       | _ ->
           (* For userspace code, allow field access on other types (assuming it will be handled by C compilation) *)
           if ctx.is_userspace then
             let field_expr = make_ir_expr (IRFieldAccess (obj_val, field)) result_type expr.expr_pos in
             let instr = make_ir_instruction (IRAssign (result_val, field_expr)) expr.expr_pos in
             emit_instruction ctx instr;
             result_val
           else
             failwith ("Field access on type " ^ (string_of_ir_type obj_val.val_type) ^ " not supported in eBPF context"))
           
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
      (* Get the target variable's actual type from the symbol table *)
      let target_type = match Symbol_table.lookup_symbol ctx.symbol_table name with
        | Some symbol -> 
            (match symbol.kind with
             | Symbol_table.Variable var_type -> ast_type_to_ir_type_with_context ctx.symbol_table var_type
             | _ -> value.val_type)
        | None -> value.val_type (* Fallback to value type if not found *)
      in
      let target_val = make_ir_value (IRRegister reg) target_type stmt.stmt_pos in
      
      (* If the target type is different from the value type, create a cast expression *)
      let value_expr = 
        if target_type <> value.val_type then
          make_ir_expr (IRCast (value, target_type)) target_type stmt.stmt_pos
        else
          make_ir_expr (IRValue value) target_type stmt.stmt_pos
      in
      let instr = make_ir_instruction (IRAssign (target_val, value_expr)) stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.IndexAssignment (map_expr, key_expr, value_expr) ->
      let map_val = lower_expression ctx map_expr in
      let key_val = lower_expression ctx key_expr in
      let value_val = lower_expression ctx value_expr in
      
      (* Check for optimization opportunities *)
      let hints = match ctx.assignment_optimizations with
        | Some opt_info when opt_info.constant_folding && Map_assignment.is_constant_expression value_expr ->
            [HelperCall "map_update_elem"; BoundsChecked]  (* Mark as optimizable *)
        | Some _opt_info ->
            [HelperCall "map_update_elem"]
        | _ -> [HelperCall "map_update_elem"]
      in
      
      (* Generate map store instruction with optimization hints *)
      let instr = make_ir_instruction
        (IRMapStore (map_val, key_val, value_val, MapUpdate))
        ~verifier_hints:hints
        stmt.stmt_pos
      in
      emit_instruction ctx instr
      
  | Ast.Delete (map_expr, key_expr) ->
      let map_val = lower_expression ctx map_expr in
      let key_val = lower_expression ctx key_expr in
      
      (* Generate map delete instruction *)
      let instr = make_ir_instruction
        (IRMapDelete (map_val, key_val))
        ~verifier_hints:[HelperCall "map_delete_elem"]
        stmt.stmt_pos
      in
      emit_instruction ctx instr
      
  | Ast.Declaration (name, typ_opt, expr) ->
      let value = lower_expression ctx expr in
      let reg = get_variable_register ctx name in
      let target_type = match typ_opt with
        | Some ast_type -> 
                         (* Generate comment for variable name tracking *)
             let debug_comment = make_ir_instruction 
               (IRComment (Printf.sprintf "Declaration %s" name))
               stmt.stmt_pos in
             emit_instruction ctx debug_comment;
            (* Check if this is a type alias and track it *)
            (match ast_type with
             | UserType alias_name ->
                 (match Symbol_table.lookup_symbol ctx.symbol_table alias_name with
                  | Some symbol ->
                      (match symbol.kind with
                       | Symbol_table.TypeDef (Ast.TypeAlias (_, underlying_type)) -> 
                           let underlying_ir_type = ast_type_to_ir_type underlying_type in
                           (* Store the alias information for this register *)
                           Hashtbl.replace ctx.register_aliases reg (alias_name, underlying_ir_type);
                           (* Create IRTypeAlias to preserve the alias name *)
                           IRTypeAlias (alias_name, underlying_ir_type)
                       | _ -> ast_type_to_ir_type ast_type)
                  | None -> ast_type_to_ir_type ast_type)
             | _ -> ast_type_to_ir_type ast_type)
        | None -> value.val_type
      in
      
      (* Add stack usage for local variables *)
      let size = match target_type with
        | IRU8 | IRChar -> 1
        | IRU16 -> 2
        | IRU32 | IRBool -> 4
        | IRU64 -> 8
        | IRArray (_, count, _) -> count * 4 (* Simplified *)
        | IRStr size -> size + 2 (* String data + length field *)
        | _ -> 8 (* Conservative estimate *)
      in
      ctx.stack_usage <- ctx.stack_usage + size;
      
      let target_val = make_ir_value (IRRegister reg) target_type stmt.stmt_pos in
      
      (* If the target type is different from the value type, create a new value with the target type *)
      let coerced_value = 
        if target_type <> value.val_type then
          make_ir_value value.value_desc target_type value.val_pos
        else
          value
      in
      
      let value_expr = make_ir_expr (IRValue coerced_value) target_type stmt.stmt_pos in
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
      
      if ctx.in_bpf_loop_callback then
        (* Special handling for bpf_loop callbacks - use conditional returns *)
        let check_for_break_continue stmts =
          List.fold_left (fun acc stmt ->
            match stmt.Ast.stmt_desc with
            | Ast.Break -> Some (make_ir_value (IRLiteral (IntLit 1)) IRU32 stmt.stmt_pos)
            | Ast.Continue -> Some (make_ir_value (IRLiteral (IntLit 0)) IRU32 stmt.stmt_pos)
            | _ -> acc
          ) None stmts
        in
        
        let then_return = check_for_break_continue then_stmts in
        let else_return = match else_opt with
          | Some else_stmts -> check_for_break_continue else_stmts
          | None -> None
        in
        
        if then_return <> None || else_return <> None then
          (* Generate conditional return instruction *)
          let cond_return_instr = make_ir_instruction 
            (IRCondReturn (cond_val, then_return, else_return))
            stmt.stmt_pos in
          emit_instruction ctx cond_return_instr
        else
          (* Regular if statement without break/continue - process normally *)
          List.iter (lower_statement ctx) then_stmts;
          (match else_opt with
           | Some else_stmts -> List.iter (lower_statement ctx) else_stmts
           | None -> ())
      else if ctx.is_userspace then
        (* For userspace, generate structured IRIf instruction *)
        let then_instructions = ref [] in
        
        (* Temporarily capture instructions for then block *)
        let old_block = ctx.current_block in
        ctx.current_block <- [];
        List.iter (lower_statement ctx) then_stmts;
        then_instructions := List.rev ctx.current_block;
        ctx.current_block <- old_block;
        
        (* Temporarily capture instructions for else block *)
        let else_instrs_opt = match else_opt with
          | Some else_stmts ->
              ctx.current_block <- [];
              List.iter (lower_statement ctx) else_stmts;
              let else_instrs = List.rev ctx.current_block in
              ctx.current_block <- old_block;
              Some else_instrs
          | None -> None
        in
        
        (* Generate IRIf instruction *)
        let if_instr = make_ir_instruction 
          (IRIf (cond_val, !then_instructions, else_instrs_opt))
          stmt.stmt_pos in
        emit_instruction ctx if_instr
      else if ctx.in_try_block then
        (* For try blocks, use structured IRIf to avoid disrupting statement ordering *)
        let then_instructions = ref [] in
        
        (* Temporarily capture instructions for then block *)
        let old_block = ctx.current_block in
        ctx.current_block <- [];
        List.iter (lower_statement ctx) then_stmts;
        then_instructions := List.rev ctx.current_block;
        ctx.current_block <- old_block;
        
        (* Temporarily capture instructions for else block *)
        let else_instrs_opt = match else_opt with
          | Some else_stmts ->
              ctx.current_block <- [];
              List.iter (lower_statement ctx) else_stmts;
              let else_instrs = List.rev ctx.current_block in
              ctx.current_block <- old_block;
              Some else_instrs
          | None -> None
        in
        
        (* Generate IRIf instruction *)
        let if_instr = make_ir_instruction 
          (IRIf (cond_val, !then_instructions, else_instrs_opt))
          stmt.stmt_pos in
        emit_instruction ctx if_instr
      else
        (* Regular control flow for eBPF contexts *)
        (* Create labels for control flow *)
        let cond_label = Printf.sprintf "cond_%d" ctx.next_block_id in
        let then_label = Printf.sprintf "then_%d" (ctx.next_block_id + 1) in
        let else_label = Printf.sprintf "else_%d" (ctx.next_block_id + 2) in
        let merge_label = Printf.sprintf "merge_%d" (ctx.next_block_id + 3) in
        
        (* Conditional jump *)
        let cond_jump = make_ir_instruction 
          (IRCondJump (cond_val, then_label, else_label)) 
          stmt.stmt_pos in
        emit_instruction ctx cond_jump;
        
        (* End current block *)
        let _ = create_basic_block ctx cond_label in
        
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
      (* Analyze the loop to determine if it's bounded or unbounded *)
      let loop_analysis = 
        match ctx.const_env with
        | Some const_env -> Loop_analysis.analyze_for_loop_with_context const_env start_expr end_expr
        | None -> Loop_analysis.analyze_for_loop start_expr end_expr
      in
      
      (* Use different loop strategy for userspace vs eBPF *)
      let loop_strategy = 
        if ctx.is_userspace then
          (* For userspace, always use BpfLoopHelper to generate C for loops *)
          Loop_analysis.BpfLoopHelper
        else
          (* For eBPF, use the eBPF-specific strategy *)
          Loop_analysis.get_ebpf_loop_strategy loop_analysis
      in
      
      (* Debug: print loop analysis *)
      let analysis_debug = Printf.sprintf "(* Loop analysis: %s, strategy: %s *)" 
        (Loop_analysis.string_of_loop_analysis loop_analysis)
        (Loop_analysis.string_of_loop_strategy loop_strategy) in
      
      let start_val = lower_expression ctx start_expr in
      let end_val = lower_expression ctx end_expr in
      
      (* Create loop counter variable *)
      let counter_reg = get_variable_register ctx var in
      let counter_val = make_ir_value (IRRegister counter_reg) IRU32 stmt.stmt_pos in
      
      (* Different IR generation based on loop strategy *)
      (match loop_strategy with
       | Loop_analysis.UnrolledLoop ->
           (* Unroll small constant loops *)
           (match loop_analysis.bound_info with
            | Loop_analysis.Bounded (start_int, end_int) ->
                for i = start_int to end_int - 1 do
                  let iter_val = make_ir_value (IRLiteral (IntLit i)) IRU32 stmt.stmt_pos in
                  let assign_iter = make_ir_instruction (IRAssign (counter_val, make_ir_expr (IRValue iter_val) IRU32 stmt.stmt_pos)) stmt.stmt_pos in
                  emit_instruction ctx assign_iter;
                  List.iter (lower_statement ctx) body_stmts;
                done
            | _ -> failwith "Unrolled loop should have bounded info")
            
       | Loop_analysis.BpfLoopHelper ->
           (* Use bpf_loop() for unbounded or complex loops *)
           let bpf_loop_comment = make_ir_instruction 
             (IRComment (Printf.sprintf "%s\n(* Using bpf_loop() for unbounded loop *)" analysis_debug))
             stmt.stmt_pos in
           emit_instruction ctx bpf_loop_comment;
           
           (* Create a separate context for the loop body *)
           let body_ctx = {
             ctx with
             current_block = [];
             blocks = [];
             (* For userspace, don't set in_bpf_loop_callback to allow normal break/continue *)
             in_bpf_loop_callback = not ctx.is_userspace;
           } in
           
           (* Lower the loop body statements to IR instructions *)
           List.iter (lower_statement body_ctx) body_stmts;
           let body_instructions = List.rev body_ctx.current_block in
           
           (* Create loop context register *)
           let loop_ctx_reg = allocate_register ctx in
           let loop_ctx_val = make_ir_value (IRRegister loop_ctx_reg) 
             (IRPointer (IRStruct ("loop_ctx", []), make_bounds_info ())) stmt.stmt_pos in
           
           (* Create the bpf_loop instruction with IR body *)
           let bpf_loop_instr = make_ir_instruction 
             (IRBpfLoop (start_val, end_val, counter_val, loop_ctx_val, body_instructions))
             stmt.stmt_pos in
           emit_instruction ctx bpf_loop_instr
           
       | Loop_analysis.SimpleLoop ->
           (* Use traditional goto-based loop for simple bounded cases *)
           let simple_loop_comment = make_ir_instruction 
             (IRComment (Printf.sprintf "%s\n(* Using simple loop for bounded case *)" analysis_debug))
             stmt.stmt_pos in
           emit_instruction ctx simple_loop_comment;
           
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
           ())
      
  | Ast.ForIter (index_var, value_var, iterable_expr, body_stmts) ->
      (* For-iter loops are always considered unbounded *)
      let loop_analysis = Loop_analysis.analyze_for_iter_loop iterable_expr in
      let _ = lower_expression ctx iterable_expr in
      
      (* Create iterator variables *)
      let index_reg = get_variable_register ctx index_var in
      let value_reg = get_variable_register ctx value_var in
      let index_val = make_ir_value (IRRegister index_reg) IRU32 stmt.stmt_pos in
      let _value_val = make_ir_value (IRRegister value_reg) IRU32 stmt.stmt_pos in
      
      (* ForIter always uses bpf_loop() for now *)
      let iter_comment = make_ir_instruction 
        (IRComment (Printf.sprintf "(* ForIter loop: %s *)\n(* Using bpf_loop() for iterator protocol *)" 
                   (Loop_analysis.string_of_loop_analysis loop_analysis)))
        stmt.stmt_pos in
      emit_instruction ctx iter_comment;
      
      (* Placeholder for bpf_loop implementation *)
      let loop_ctx_reg = allocate_register ctx in
      let loop_ctx_val = make_ir_value (IRRegister loop_ctx_reg) 
        (IRPointer (IRStruct ("iter_ctx", []), make_bounds_info ())) stmt.stmt_pos in
      
      (* Create a separate context for the loop body *)
      let body_ctx = {
        ctx with
        current_block = [];
        blocks = [];
        (* For userspace, don't set in_bpf_loop_callback to allow normal break/continue *)
        in_bpf_loop_callback = not ctx.is_userspace;
      } in
      
      (* Lower the loop body statements to IR instructions *)
      List.iter (lower_statement body_ctx) body_stmts;
      let body_instructions = List.rev body_ctx.current_block in
      
      (* Mark as iterator bpf_loop *)
      let start_val = make_ir_value (IRLiteral (IntLit 0)) IRU32 stmt.stmt_pos in
      let end_val = make_ir_value (IRLiteral (IntLit 100)) IRU32 stmt.stmt_pos in (* Placeholder *)
      let bpf_iter_instr = make_ir_instruction 
        (IRBpfLoop (start_val, end_val, index_val, loop_ctx_val, body_instructions))
        stmt.stmt_pos in
      emit_instruction ctx bpf_iter_instr
      
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
  
  | Ast.Break ->
      (* Generate break instruction for IR *)
      let instr = make_ir_instruction IRBreak stmt.stmt_pos in
      emit_instruction ctx instr
  
  | Ast.FieldAssignment (object_expr, field_name, value_expr) ->
      (* Check if we're trying to assign to a config field *)
      let map_name = match object_expr.expr_desc with
        | Ast.Identifier var_name -> var_name
        | _ -> failwith "Config field assignment must reference a config variable"
      in
      
      (* Check if this is a config assignment by looking up in symbol table *)
      let is_config = match Symbol_table.lookup_symbol ctx.symbol_table map_name with
        | Some { kind = Config _; _ } -> true
        | _ -> false
      in
      if is_config then (
        (* This is a config field assignment *)
        if not ctx.is_userspace then
          (* We're in eBPF kernel space - config fields are read-only *)
          failwith (Printf.sprintf 
            "Config field assignment not allowed in eBPF programs at %s. Config fields are read-only in kernel space and can only be modified from userspace."
            (string_of_position stmt.stmt_pos))
        else (
          (* We're in userspace - config field assignment is allowed *)
          let key_val = make_ir_value (IRLiteral (IntLit 0)) (IRU32) stmt.stmt_pos in
          let map_val = make_ir_value (IRMapRef map_name) (IRPointer (IRU8, make_bounds_info ())) stmt.stmt_pos in
          let value_val = lower_expression ctx value_expr in
          let instr = make_ir_instruction 
            (IRConfigFieldUpdate (map_val, key_val, field_name, value_val)) 
            stmt.stmt_pos 
          in
          emit_instruction ctx instr
        )
      ) else (
        (* This is regular field assignment (not config) - not implemented yet *)
        failwith "Regular field assignment not implemented yet"
      )
      
  | Ast.Continue ->
      (* Generate continue instruction for IR *)
      let instr = make_ir_instruction IRContinue stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Try (try_stmts, catch_clauses) ->
      (* For try/catch blocks, we need to ensure proper statement ordering *)
      (* The key insight is that we need to process try/catch as a single unit *)
      (* while maintaining the sequential ordering of statements *)
      
      (* Convert AST catch clauses to IR catch clauses with proper bodies *)
      let ir_catch_clauses = List.map (fun clause ->
        let ir_pattern = match clause.Ast.catch_pattern with
          | Ast.IntPattern code -> Ir.IntCatchPattern code
          | Ast.WildcardPattern -> Ir.WildcardCatchPattern
        in
        
        (* Process catch clause body statements to IR instructions *)
        (* We need to maintain the same context for proper variable resolution *)
        let catch_instructions = ref [] in
        let old_current_block = ctx.current_block in
        ctx.current_block <- [];
        
        List.iter (lower_statement ctx) clause.Ast.catch_body;
        catch_instructions := List.rev ctx.current_block;
        
        ctx.current_block <- old_current_block;
        
        { Ir.catch_pattern = ir_pattern; Ir.catch_body = !catch_instructions }
      ) catch_clauses in
      
      (* Process try block statements while maintaining proper ordering *)
      (* The key is to process the try block in the current context but *)
      (* capture the instructions separately *)
      let try_instructions = ref [] in
      let old_current_block = ctx.current_block in
      let old_in_try_block = ctx.in_try_block in
      ctx.current_block <- [];
      ctx.in_try_block <- true;
      
      (* Process try statements in the current context to maintain variable scope *)
      (* and proper control flow block creation *)
      List.iter (lower_statement ctx) try_stmts;
      try_instructions := List.rev ctx.current_block;
      
      (* Restore the original current_block and in_try_block flag *)
      ctx.current_block <- old_current_block;
      ctx.in_try_block <- old_in_try_block;
      
      let instr = make_ir_instruction (IRTry (!try_instructions, ir_catch_clauses)) stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Throw expr ->
      (* Evaluate the expression to get the error code *)
      let _error_value = lower_expression ctx expr in
      (* For now, assume it's an integer literal - in a full implementation, 
         we'd need to evaluate the expression at compile time *)
      let error_code = match expr.expr_desc with
        | Ast.Literal (Ast.IntLit code) -> Ir.IntErrorCode code
        | Ast.Identifier _ -> 
            (* For identifiers (like enum values), we'd need to resolve them *)
            (* For now, use a default error code *)
            Ir.IntErrorCode 1
        | _ -> 
            (* For complex expressions, we'd need constant folding *)
            Ir.IntErrorCode 1
      in
      let instr = make_ir_instruction (IRThrow error_code) stmt.stmt_pos in
      emit_instruction ctx instr
      
  | Ast.Defer expr ->
      (* Convert defer expression to instruction list *)
      let defer_instructions = ref [] in
      let old_blocks = ctx.current_block in
      ctx.current_block <- [];
      let _ = lower_expression ctx expr in
      defer_instructions := List.rev ctx.current_block;
      ctx.current_block <- old_blocks;
      
      let instr = make_ir_instruction (IRDefer !defer_instructions) stmt.stmt_pos in
      emit_instruction ctx instr

(** Helper function to take first n elements from a list *)
let rec list_take n lst =
  if n <= 0 then []
  else match lst with
    | [] -> []
    | x :: xs -> x :: list_take (n - 1) xs

(** Lower AST function to IR function *)
let lower_function ctx prog_name (func_def : Ast.function_def) =
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
    let ir_type = ast_type_to_ir_type_with_context ctx.symbol_table ast_type in
    (name, ir_type)
  ) func_def.func_params in
  
  (* Helper function to lower statement with access to preceding statements *)
  let lower_statement_with_context all_statements current_index stmt =
    (* Get all statements before the current one *)
    let preceding_statements = list_take current_index all_statements in
    
    (* Collect constants from preceding statements *)
    let const_env = Loop_analysis.collect_constants_from_statements preceding_statements in
    
    (* Store const_env in context temporarily for loop analysis *)
    let old_const_env = ctx.const_env in
    ctx.const_env <- Some const_env;
    
    (* Lower the statement *)
    lower_statement ctx stmt;
    
    (* Restore const_env *)
    ctx.const_env <- old_const_env
  in
  
  (* Lower function body with context *)
  List.iteri (lower_statement_with_context func_def.func_body) func_def.func_body;
  
  (* Create final block if needed *)
  (if ctx.current_block <> [] then
    let _ = create_basic_block ctx "final_block" in
    ()
  );
  
  (* Convert return type *)
  let ir_return_type = match func_def.func_return_type with
    | Some ast_type -> Some (ast_type_to_ir_type_with_context ctx.symbol_table ast_type)
    | None -> None
  in
  
  (* Create IR function *)
  let ir_blocks = List.rev ctx.blocks in
  let is_main = func_def.func_name = "main" in
  
  (* Use program name for main function, regular function names for others *)
  let ir_func_name = if is_main then prog_name else func_def.func_name in
  
  make_ir_function 
    ir_func_name 
    ir_params 
    ir_return_type 
    ir_blocks
    ~total_stack_usage:ctx.stack_usage
    ~is_main:is_main
    func_def.func_pos

(** Lower AST map declaration to IR map definition *)
let lower_map_declaration (map_decl : Ast.map_declaration) =
  let ir_key_type = ast_type_to_ir_type map_decl.Ast.key_type in
  let ir_value_type = ast_type_to_ir_type map_decl.Ast.value_type in
  let ir_map_type = ast_map_type_to_ir_map_type map_decl.Ast.map_type in
  
  let ir_attributes = List.filter_map (fun attr ->
    match attr with
    | Ast.Pinned _ -> None (* Handled separately *)
    | Ast.FlagsAttr _ -> None (* Handled separately *)
  ) map_decl.Ast.config.attributes in
  
  let pin_path = List.fold_left (fun _acc attr ->
    match attr with
    | Ast.Pinned path -> Some path
    | _ -> None
  ) None map_decl.Ast.config.attributes in
  
  (* Convert AST flags to integer representation *)
  let flags = Maps.ast_flags_to_int map_decl.Ast.config.flags in
  
  make_ir_map_def
    map_decl.Ast.name
    ir_key_type
    ir_value_type
    ir_map_type
    map_decl.Ast.config.max_entries
    ~attributes:ir_attributes
    ~flags:flags
    ~is_global:map_decl.Ast.is_global
    ?pin_path:pin_path
    map_decl.Ast.map_pos

(** Convert AST function to IR function for userspace context *)
let lower_userspace_function ctx func_def =
  (* Validate main function signature if it's the main function *)
  if func_def.Ast.func_name = "main" then (
    (* Validate main function signature: fn main() -> i32 or fn main(args: CustomStruct) -> i32 *)
    let expected_return = Some Ast.I32 in
    
    (* Check parameter count and types *)
    let params_valid = 
      (* Allow no parameters: fn main() -> i32 *)
      List.length func_def.Ast.func_params = 0 ||
      (* Allow single struct parameter: fn main(args: CustomStruct) -> i32 *)
      (List.length func_def.Ast.func_params = 1 &&
       match func_def.Ast.func_params with
       | [(_, Ast.Struct _)] -> true  (* Accept struct types *)
       | [(_, Ast.UserType _)] -> true  (* Accept user-defined types (structs) *)
       | [(_, _)] -> false (* Reject non-struct single parameters *)
       | _ -> false)
    in
    
    (* Check return type *)
    let return_valid = func_def.Ast.func_return_type = expected_return in
    
    if not params_valid then
      failwith (Printf.sprintf 
        "main() function must have no parameters or one struct parameter, got: %s"
        (String.concat ", " (List.map (fun (name, typ) -> 
          Printf.sprintf "%s: %s" name (Ast.string_of_bpf_type typ)
        ) func_def.Ast.func_params)));
    
    if not return_valid then
      failwith (Printf.sprintf
        "main() function must return i32, got: %s"
        (match func_def.Ast.func_return_type with 
         | Some t -> Ast.string_of_bpf_type t 
         | None -> "void"));
  );
  
  ctx.is_userspace <- true;
  let ir_function = lower_function ctx func_def.Ast.func_name func_def in
  ctx.is_userspace <- false;
  ir_function

(** Generate coordinator logic *)
and generate_coordinator_logic _ctx _ir_functions =
  let dummy_pos = { line = 1; column = 1; filename = "generated" } in
  
  (* Generate simplified setup logic *)
  let setup_logic = [
    make_ir_instruction (IRComment "Setup global maps and BPF programs") dummy_pos;
    make_ir_instruction (IRComment "Load BPF object and extract file descriptors") dummy_pos;
    make_ir_instruction (IRComment "Attach programs to appropriate hooks") dummy_pos;
  ] in
  
  (* Generate simplified event processing *)
  let event_processing = [
    make_ir_instruction (IRComment "Main event processing loop") dummy_pos;
    make_ir_instruction (IRComment "Poll for events from BPF programs") dummy_pos;
    make_ir_instruction (IRComment "Process ring buffer and perf events") dummy_pos;
  ] in
  
  (* Generate simplified cleanup logic *)
  let cleanup_logic = [
    make_ir_instruction (IRComment "Detach BPF programs") dummy_pos;
    make_ir_instruction (IRComment "Close map file descriptors") dummy_pos;
    make_ir_instruction (IRComment "Cleanup BPF object") dummy_pos;
  ] in
  
  (* Generate config management *)
  let config_management = make_ir_config_management [] [] [] in
  
  make_ir_coordinator_logic setup_logic event_processing cleanup_logic config_management
  

let convert_config_declarations_to_ir config_declarations =
  List.map (fun config_decl ->
    let ir_fields = List.map (fun field ->
      let ir_type = match field.Ast.field_type with
        | Ast.U8 -> IRU8
        | Ast.U16 -> IRU16
        | Ast.U32 -> IRU32
        | Ast.U64 -> IRU64
        | Ast.I8 -> IRU8   (* Map signed to unsigned for IR *)
        | Ast.I16 -> IRU16 (* Map signed to unsigned for IR *)
        | Ast.I32 -> IRU32 (* Map signed to unsigned for IR *)
        | Ast.I64 -> IRU64 (* Map signed to unsigned for IR *)
        | Ast.Bool -> IRBool
        | Ast.Char -> IRChar
        | Ast.Array (elem_type, size) ->
            let ir_elem_type = match elem_type with
              | Ast.U8 -> IRU8
              | Ast.U16 -> IRU16
              | Ast.U32 -> IRU32
              | Ast.U64 -> IRU64
              | Ast.I8 -> IRU8   (* Map signed to unsigned for IR *)
              | Ast.I16 -> IRU16 (* Map signed to unsigned for IR *)
              | Ast.I32 -> IRU32 (* Map signed to unsigned for IR *)
              | Ast.I64 -> IRU64 (* Map signed to unsigned for IR *)
              | Ast.Bool -> IRBool
              | Ast.Char -> IRChar
              | _ -> failwith ("Unsupported array element type: " ^ (Ast.string_of_bpf_type elem_type))
            in
            let bounds_info = { min_size = Some size; max_size = Some size; alignment = 1; nullable = false } in
            IRArray (ir_elem_type, size, bounds_info)
        | _ -> failwith ("Unsupported config field type: " ^ (Ast.string_of_bpf_type field.Ast.field_type))
      in
      (field.Ast.field_name, ir_type)
    ) config_decl.Ast.config_fields in
    {
      config_struct_name = config_decl.Ast.config_name;
      fields = ir_fields;
      serialization = Json;
    }
  ) config_declarations

let generate_userspace_bindings_from_functions _prog_def userspace_functions maps config_declarations =
  (* Generate bindings based on userspace functions *)
  if List.length userspace_functions = 0 then (
    (* Default bindings when no userspace functions are specified *)
    let map_wrappers = List.map (fun map_def ->
      let operations = [OpLookup; OpUpdate; OpDelete; OpIterate] in
      {
        wrapper_map_name = map_def.map_name;
        operations;
        safety_checks = true;
      }
    ) maps in
    
    let config_structs = convert_config_declarations_to_ir config_declarations in
    
    [{
      language = C;
      map_wrappers;
      event_handlers = [];
      config_structs;
    }]
  ) else (
    (* Generate bindings based on userspace functions *)
    let map_wrappers = List.map (fun map_def ->
      let operations = [OpLookup; OpUpdate; OpDelete; OpIterate] in
      {
        wrapper_map_name = map_def.map_name;
        operations;
        safety_checks = true;
      }
    ) maps in
    
    let config_structs = convert_config_declarations_to_ir config_declarations in
    
    let target_languages = [C] in
    
    List.map (fun language ->
      {
        language;
        map_wrappers;
        event_handlers = [];
        config_structs;
      }
    ) target_languages
  )

(** Generate userspace bindings for multiple programs *)
let generate_userspace_bindings_from_multi_programs _prog_defs _userspace_functions maps config_declarations =
  (* Generate bindings for all programs with userspace functions *)
  let map_wrappers = List.map (fun map_def ->
    let operations = [OpLookup; OpUpdate; OpDelete; OpIterate] in
    {
      wrapper_map_name = map_def.map_name;
      operations;
      safety_checks = true;
    }
  ) maps in
  
  let config_structs = convert_config_declarations_to_ir config_declarations in
  
  [{
    language = C;
    map_wrappers;
    event_handlers = [];
    config_structs;
  }]

(** Lower a single program from AST to IR *)
let lower_single_program ctx prog_def _global_ir_maps =
  (* Include program-scoped maps *)
  let program_scoped_maps = prog_def.prog_maps in
  
  (* Lower program-scoped maps *)
  let ir_program_maps = List.map (fun map_decl -> lower_map_declaration map_decl) program_scoped_maps in
  
  (* Add all maps to context for this program *)
  List.iter (fun (map_def : ir_map_def) -> 
    Hashtbl.add ctx.maps map_def.map_name map_def
  ) (ir_program_maps : ir_map_def list);
  (* Also add global maps to context *)
  List.iter (fun (map_def : ir_map_def) -> 
    Hashtbl.add ctx.maps map_def.map_name map_def
  ) (_global_ir_maps : ir_map_def list);
  
  (* Lower functions *)
  let ir_functions = List.map (lower_function ctx prog_def.prog_name) prog_def.prog_functions in
  
  (* Find main function *)
  let main_function = List.find (fun f -> f.is_main) ir_functions in
  
  (* Create IR program *)
  make_ir_program 
    prog_def.prog_name 
    prog_def.prog_type 
    ir_program_maps 
    ir_functions 
    main_function 
    prog_def.prog_pos

(** Validate multiple programs for consistency *)
let validate_multiple_programs prog_defs =
  (* Check for duplicate program names *)
  let names = List.map (fun p -> p.prog_name) prog_defs in
  let unique_names = List.sort_uniq String.compare names in
  if List.length names <> List.length unique_names then
    failwith "Multiple programs cannot have the same name";
  
  (* Check for duplicate program types *)
  let types = List.map (fun p -> p.prog_type) prog_defs in
  let unique_types = List.sort_uniq compare types in
  if List.length types <> List.length unique_types then
    failwith "Multiple programs cannot have the same type";
  
  (* Each program must have exactly one main function *)
  List.iter (fun prog_def ->
    let main_functions = List.filter (fun f -> f.Ast.func_name = "main") prog_def.prog_functions in
    if List.length main_functions = 0 then
      failwith (Printf.sprintf "Program '%s' must have a main function" prog_def.prog_name);
    if List.length main_functions > 1 then
      failwith (Printf.sprintf "Program '%s' cannot have multiple main functions" prog_def.prog_name)
  ) prog_defs

(** Lower complete AST to multi-program IR *)
let lower_multi_program ast symbol_table source_name =
  let ctx = create_context symbol_table in
  
  (* Analyze assignment patterns for optimization early *)
  let _optimization_info = analyze_assignment_patterns ctx ast in
  
  (* Find all program declarations *)
  let prog_defs = List.filter_map (function
    | Ast.Program p -> Some p
    | _ -> None
  ) ast in
  
  if prog_defs = [] then
    failwith "No program declarations found";
  
  (* Validate multiple programs *)
  validate_multiple_programs prog_defs;
  
  (* Collect global map declarations *)
  let global_map_decls = List.filter_map (function
    | Ast.MapDecl m when m.is_global -> Some m
    | _ -> None
  ) ast in
  
  (* Lower global maps *)
  let ir_global_maps = List.map (fun map_decl -> lower_map_declaration map_decl) global_map_decls in
  
  (* Add global maps to main context for userspace processing *)
  List.iter (fun (map_def : ir_map_def) -> 
    Hashtbl.add ctx.maps map_def.map_name map_def
  ) ir_global_maps;
  
  (* Also add all program-scoped maps to main context for userspace processing *)
  List.iter (fun prog_def ->
    let program_scoped_maps = prog_def.prog_maps in
    let ir_program_maps = List.map (fun map_decl -> lower_map_declaration map_decl) program_scoped_maps in
    List.iter (fun (map_def : ir_map_def) -> 
      Hashtbl.add ctx.maps map_def.map_name map_def
    ) ir_program_maps
  ) prog_defs;
  
  (* Lower each program *)
  let ir_programs = List.map (fun prog_def ->
    (* Create a fresh context for each program *)
    let prog_ctx = create_context symbol_table in
    lower_single_program prog_ctx prog_def ir_global_maps
  ) prog_defs in
  
  (* Find top-level userspace functions *)
  let userspace_functions = List.filter_map (function
    | Ast.GlobalFunction func -> Some func
    | _ -> None
  ) ast in
  
  (* Convert AST userspace functions to IR userspace program *)
  let userspace_program = 
    if List.length userspace_functions = 0 then
      None
    else
      (* Main function is now mandatory for all userspace code *)
      let main_functions = List.filter (fun f -> f.Ast.func_name = "main") userspace_functions in
      if List.length main_functions = 0 then
        failwith "Userspace code must contain a main() function (no longer optional)";
      if List.length main_functions > 1 then
        failwith "Only one main() function is allowed";
      
      (* Collect struct declarations from AST *)
      let userspace_struct_decls = List.filter_map (function
        | Ast.StructDecl struct_def -> Some struct_def
        | _ -> None
      ) ast in
      
      (* Convert AST struct declarations to IR struct definitions *)
      let ir_userspace_structs = List.map (fun struct_decl ->
        let ir_fields = List.map (fun (field_name, field_type) ->
          (field_name, ast_type_to_ir_type field_type)
        ) struct_decl.Ast.struct_fields in
        make_ir_struct_def 
          struct_decl.Ast.struct_name 
          ir_fields 
          8 (* default alignment *)
          (List.length ir_fields * 8) (* estimated size *)
          struct_decl.Ast.struct_pos
      ) userspace_struct_decls in
      
      let ir_functions = List.map (fun func -> lower_userspace_function ctx func) userspace_functions in
      Some (make_ir_userspace_program ir_functions ir_userspace_structs [] (generate_coordinator_logic ctx ir_functions) (match userspace_functions with [] -> { line = 1; column = 1; filename = source_name } | h::_ -> h.func_pos))
  in
  
  (* Extract all map assignments from the AST to analyze initial values *)
  let all_map_assignments = Map_assignment.extract_map_assignments_from_ast ast in
  
  (* Convert ir_map_def list to map_flag_info list for userspace bindings *)
  let ir_map_def_to_map_flag_info (ir_map : ir_map_def) : Maps.map_flag_info =
    (* Find assignments to this specific map *)
    let map_assignments = List.filter (fun assignment -> 
      assignment.Map_assignment.map_name = ir_map.map_name
    ) all_map_assignments in
    
    (* Extract initial values from assignments with literal keys and values *)
    let initial_values = List.filter_map (fun assignment ->
      match assignment.Map_assignment.key_expr.expr_desc, assignment.Map_assignment.value_expr.expr_desc with
      | Literal key_lit, Literal value_lit ->
          let key_str =           match key_lit with
            | IntLit i -> string_of_int i
            | StringLit s -> "\"" ^ s ^ "\""
            | CharLit c -> "'" ^ String.make 1 c ^ "'"
            | BoolLit b -> string_of_bool b
            | ArrayLit literals -> 
                "[" ^ (String.concat ", " (List.map (function
                  | IntLit i -> string_of_int i
                  | StringLit s -> "\"" ^ s ^ "\""
                  | CharLit c -> "'" ^ String.make 1 c ^ "'"
                  | BoolLit b -> string_of_bool b
                  | ArrayLit _ -> "[]"  (* Nested arrays simplified *)
                ) literals)) ^ "]"
          in
                      let value_str = match value_lit with
            | IntLit i -> string_of_int i
            | StringLit s -> "\"" ^ s ^ "\""
            | CharLit c -> "'" ^ String.make 1 c ^ "'"
            | BoolLit b -> string_of_bool b
            | ArrayLit literals -> 
                "[" ^ (String.concat ", " (List.map (function
                  | IntLit i -> string_of_int i
                  | StringLit s -> "\"" ^ s ^ "\""
                  | CharLit c -> "'" ^ String.make 1 c ^ "'"
                  | BoolLit b -> string_of_bool b
                  | ArrayLit _ -> "[]"  (* Nested arrays simplified *)
                ) literals)) ^ "]"
          in
          Some (key_str ^ ":" ^ value_str)
      | _ -> None
    ) map_assignments in
    
    {
      map_name = ir_map.map_name;
      has_initial_values = List.length map_assignments > 0;
      initial_values = initial_values;
      key_type = string_of_ir_type ir_map.map_key_type;
      value_type = string_of_ir_type ir_map.map_value_type;
    }
  in
  
  let map_flag_infos = List.map ir_map_def_to_map_flag_info ir_global_maps in
  
  (* Extract config declarations from AST *)
  let config_declarations = List.filter_map (function
    | Ast.ConfigDecl config -> Some config
    | _ -> None
  ) ast in
  
  (* Generate userspace bindings *)
  let userspace_bindings = 
    generate_userspace_bindings_from_multi_programs prog_defs userspace_functions map_flag_infos config_declarations
  in
  
  (* Create multi-program IR *)
  let multi_pos = match prog_defs with
    | [] -> { line = 1; column = 1; filename = source_name }
    | first :: _ -> first.prog_pos
  in
  
  make_ir_multi_program 
    source_name 
    ir_programs 
    ir_global_maps 
    ?userspace_program:userspace_program 
    ~userspace_bindings:userspace_bindings 
    multi_pos

(** Main entry point for IR generation *)
let generate_ir ast symbol_table source_name =
  try
    lower_multi_program ast symbol_table source_name
  with
  | exn ->
      Printf.eprintf "IR generation failed: %s\n" (Printexc.to_string exn);
      raise exn 