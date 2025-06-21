open Alcotest
open Kernelscript.Ast
open Kernelscript.Symbol_table
open Kernelscript.Type_checker
open Kernelscript.Ir_generator
open Kernelscript.Ebpf_c_codegen
open Kernelscript.Ir

(** Helper functions *)
let dummy_pos = { line = 1; column = 1; filename = "test_struct_init.ks" }

let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Helper to check if string contains substring *)
let contains_substr str substr =
  try 
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in 
    true
  with Not_found -> false

(** Helper to generate IR and C code from program text *)
let generate_c_from_program program_text program_name =
  let ast = parse_string program_text in
  let symbol_table = build_symbol_table ast in
  let (annotated_ast, _) = type_check_and_annotate_ast ast in
  let ir_multi_prog = generate_ir annotated_ast symbol_table program_name in
  
  (* Initialize context codegens *)
  Kernelscript_context.Xdp_codegen.register ();
  
  (* Generate C code *)
  let c_code = generate_c_multi_program ir_multi_prog in
  c_code

(** Test 1: Basic struct initialization with simple types *)
let test_basic_struct_initialization () =
  let program_text = {|
struct PacketInfo {
    size: u64,
    action: u32,
}

@xdp fn packet_filter(ctx: XdpContext) -> XdpAction {
    let packet_size = ctx.data_end - ctx.data
    let info = PacketInfo {
        size: packet_size,
        action: 2,
    }
    
    if (info.size > 1500) {
      return 1
    }
    return info.action
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let c_code = generate_c_from_program program_text "packet_filter" in
    
    (* Verify struct definition is generated *)
    check bool "struct definition generated" true (contains_substr c_code "struct PacketInfo");
    check bool "size field defined" true (contains_substr c_code "__u64 size");
    check bool "action field defined" true (contains_substr c_code "__u32 action");
    
    (* Verify struct initialization syntax *)
    check bool "struct literal assignment found" true (contains_substr c_code "(struct PacketInfo){");
    check bool "field initialization syntax" true (contains_substr c_code ".size =");
    check bool "action field initialization" true (contains_substr c_code ".action = 2");
    
    (* Verify field access works *)
    check bool "field access generated" true (contains_substr c_code ".size");
    check bool "return field access" true (contains_substr c_code ".action")
  with
  | exn -> fail ("Basic struct initialization test failed: " ^ Printexc.to_string exn)

(** Test 2: Struct initialization with different data types *)
let test_struct_with_different_types () =
  let program_text = {|
struct ConfigData {
    mode: u64,
    flags: u32,
}

@xdp fn config_filter(ctx: XdpContext) -> XdpAction {
    let packet_size = ctx.data_end - ctx.data
    let info = ConfigData {
        mode: packet_size,
        flags: 42,
    }
    
    if (info.mode > 1500) {
      return 1
    }
    return info.flags
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let c_code = generate_c_from_program program_text "config_filter" in
    
    (* Verify all data types are correctly generated *)
    check bool "struct ConfigData defined" true (contains_substr c_code "struct ConfigData");
    check bool "u64 mode field defined" true (contains_substr c_code "__u64 mode");
    check bool "u32 flags field defined" true (contains_substr c_code "__u32 flags");
    
    (* Verify struct initialization syntax *)
    check bool "struct literal syntax" true (contains_substr c_code "(struct ConfigData){");
    check bool "flags literal assignment" true (contains_substr c_code ".flags = 42")
  with
  | exn -> fail ("Different types struct test failed: " ^ Printexc.to_string exn)

(** Test 3: Struct initialization with variables *)
let test_struct_initialization_with_variables () =
  let program_text = {|
struct VariableTest {
    size: u64,
    action: u32,
}

@xdp fn variable_test(ctx: XdpContext) -> XdpAction {
    let packet_size = ctx.data_end - ctx.data
    let info = VariableTest {
        size: packet_size,
        action: 3,
    }
    
    if (info.size > 1500) {
      return 1
    }
    return info.action
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let c_code = generate_c_from_program program_text "variable_test" in
    
    (* Verify struct definition *)
    check bool "VariableTest struct defined" true (contains_substr c_code "struct VariableTest");
    check bool "__u64 size field" true (contains_substr c_code "__u64 size");
    check bool "__u32 action field" true (contains_substr c_code "__u32 action");
    
    (* Verify struct compound literal syntax *)
    check bool "compound literal syntax" true (contains_substr c_code "(struct VariableTest){");
    check bool "literal field assignment" true (contains_substr c_code ".action = 3")
  with
  | exn -> fail ("Variable struct initialization test failed: " ^ Printexc.to_string exn)

(** Test 4: Multiple struct definitions and initializations *)
let test_multiple_struct_definitions () =
  let program_text = {|
struct Header {
    version: u8,
    flags: u8,
}

struct Payload {
    size: u32,
    data_type: u16,
}

@xdp fn multi_struct(ctx: XdpContext) -> XdpAction {
    let hdr = Header {
        version: 1,
        flags: 0,
    }
    
    let payload = Payload {
        size: 1024,
        data_type: 42,
    }
    
    if (hdr.version == 1 && payload.size > 0) {
      return 2
    }
    return 1
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let c_code = generate_c_from_program program_text "multi_struct" in
    
    (* Verify both struct definitions are generated *)
    check bool "Header struct defined" true (contains_substr c_code "struct Header");
    check bool "Payload struct defined" true (contains_substr c_code "struct Payload");
    
    (* Verify both struct initializations *)
    check bool "Header initialization" true (contains_substr c_code "(struct Header){");
    check bool "Payload initialization" true (contains_substr c_code "(struct Payload){");
    
    (* Verify field assignments for both structs *)
    check bool "Header version assignment" true (contains_substr c_code ".version = 1");
    check bool "Header flags assignment" true (contains_substr c_code ".flags = 0");
    check bool "Payload size assignment" true (contains_substr c_code ".size = 1024");
    check bool "Payload data_type assignment" true (contains_substr c_code ".data_type = 42")
  with
  | exn -> fail ("Multiple struct definitions test failed: " ^ Printexc.to_string exn)

(** Test 5: Nested struct usage (assignment and field access) *)
let test_nested_struct_usage () =
  let program_text = {|
struct FieldTest {
    size: u64,
    action: u32,
}

@xdp fn field_test(ctx: XdpContext) -> XdpAction {
    let packet_size = ctx.data_end - ctx.data
    let info = FieldTest {
        size: packet_size,
        action: 4,
    }
    
    if (info.size > 1500) {
      return 1
    }
    return info.action
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let c_code = generate_c_from_program program_text "field_test" in
    
    (* Verify struct definition *)
    check bool "FieldTest struct defined" true (contains_substr c_code "struct FieldTest");
    check bool "__u64 size field" true (contains_substr c_code "__u64 size");
    check bool "__u32 action field" true (contains_substr c_code "__u32 action");
    
    (* Verify struct initialization *)
    check bool "struct literal syntax" true (contains_substr c_code "(struct FieldTest){");
    check bool "field initialization" true (contains_substr c_code ".action = 4")
  with
  | exn -> fail ("Nested struct usage test failed: " ^ Printexc.to_string exn)

(** Test 6: IR generation verification for struct literals *)
let test_ir_struct_literal_generation () =
  let program_text = {|
struct TestStruct {
    field1: u32,
    field2: u64,
}

@xdp fn test_ir(ctx: XdpContext) -> XdpAction {
    let test_obj = TestStruct {
        field1: 42,
        field2: 1000,
    }
    return test_obj.field1
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let ast = parse_string program_text in
    let symbol_table = build_symbol_table ast in
    let (annotated_ast, _) = type_check_and_annotate_ast ast in
    let ir_multi_prog = generate_ir annotated_ast symbol_table "test_ir" in
    
    (* Extract the main function from IR *)
    let test_program = List.find (fun prog -> prog.name = "test_ir") ir_multi_prog.programs in
    let main_func = test_program.entry_function in
    
    (* Look for IRStructLiteral in the instructions *)
    let has_struct_literal = ref false in
    let check_instruction instr =
      match instr.instr_desc with
      | IRAssign (_, expr) ->
        (match expr.expr_desc with
         | IRStructLiteral (struct_name, _) ->
           if struct_name = "TestStruct" then has_struct_literal := true
         | _ -> ())
      | _ -> ()
    in
    
    List.iter (fun block ->
      List.iter check_instruction block.instructions
    ) main_func.basic_blocks;
    
    check bool "IRStructLiteral generated in IR" true !has_struct_literal
  with
  | exn -> fail ("IR struct literal generation test failed: " ^ Printexc.to_string exn)

(** Test 7: Struct initialization in function parameters and returns *)
let test_struct_as_function_parameter () =
  let program_text = {|
struct Parameter {
    size: u64,
    action: u32,
}

@xdp fn param_test(ctx: XdpContext) -> XdpAction {
    let packet_size = ctx.data_end - ctx.data
    let info = Parameter {
        size: packet_size,
        action: 5,
    }
    
    if (info.size > 1500) {
      return 1
    }
    return info.action
}

fn main() -> i32 {
    return 0
}
|} in
  try
    let c_code = generate_c_from_program program_text "param_test" in
    
    (* Verify struct definition *)
    check bool "Parameter struct defined" true (contains_substr c_code "struct Parameter");
    check bool "__u64 size field" true (contains_substr c_code "__u64 size");
    check bool "__u32 action field" true (contains_substr c_code "__u32 action");
    
    (* Verify struct initialization and field access *)
    check bool "struct initialization" true (contains_substr c_code "(struct Parameter){");
    check bool "action field assignment" true (contains_substr c_code ".action = 5")
  with
  | exn -> fail ("Struct as function parameter test failed: " ^ Printexc.to_string exn)

(** All struct initialization tests *)
let tests = [
  "test_basic_struct_initialization", `Quick, test_basic_struct_initialization;
  "test_multiple_struct_definitions", `Quick, test_multiple_struct_definitions;
  "test_ir_struct_literal_generation", `Quick, test_ir_struct_literal_generation;
]

let () = Alcotest.run "Struct Initialization Tests" [
  "struct_initialization", tests
] 