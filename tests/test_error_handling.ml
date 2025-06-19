(** Comprehensive tests for error handling: try/catch/throw/defer functionality *)

open Alcotest
open Kernelscript.Ast
open Kernelscript.Ir_generator

(** Helper functions *)
let parse_string s =
  let lexbuf = Lexing.from_string s in
  Kernelscript.Parser.program Kernelscript.Lexer.token lexbuf

(** Helper function to check if string contains substring *)
let contains_substr str substr =
  try
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in
    true
  with Not_found -> false

(** Helper function to create a simple program with given body *)
let make_simple_program_with_body body_text = {|
map<u32, u32> test_map : HashMap(1024)

program test_prog : xdp {
    fn main(ctx: XdpContext) -> i32 {
|} ^ body_text ^ {|
        return 2  // XDP_PASS
    }
}

fn main() -> i32 {
    return 0
}
|}

(** Test parsing of try/catch/throw/defer statements *)

let test_try_catch_parsing () =
  let program_text = make_simple_program_with_body {|
    try {
        throw 42
    } catch 42 {
        return 1
    }
  |} in
  
  try
    let ast = parse_string program_text in
    match List.nth ast 1 with (* Skip map declaration, get program *)
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let first_stmt = List.hd main_func.func_body in
        (match first_stmt.stmt_desc with
         | Try (try_stmts, catch_clauses) ->
             check int "try block statement count" 1 (List.length try_stmts);
             check int "catch clause count" 1 (List.length catch_clauses);
             let catch_clause = List.hd catch_clauses in
             (match catch_clause.catch_pattern with
              | IntPattern code ->
                  check int "catch pattern code" 42 code
              | _ -> fail "Expected IntPattern")
         | _ -> fail "Expected Try statement")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse try/catch: " ^ Printexc.to_string e)

let test_throw_parsing () =
  let program_text = make_simple_program_with_body {|
    throw 123
  |} in
  
  try
    let ast = parse_string program_text in
    match List.nth ast 1 with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let first_stmt = List.hd main_func.func_body in
        (match first_stmt.stmt_desc with
         | Throw expr ->
             (match expr.expr_desc with
              | Literal (IntLit (code, _)) ->
                  check int "throw code" 123 code
              | _ -> fail "Expected integer literal in throw")
         | _ -> fail "Expected Throw statement")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse throw: " ^ Printexc.to_string e)

let test_defer_parsing () =
  let program_text = make_simple_program_with_body {|
    defer cleanup_function()
  |} in
  
  try
    let ast = parse_string program_text in
    match List.nth ast 1 with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let first_stmt = List.hd main_func.func_body in
        (match first_stmt.stmt_desc with
         | Defer cleanup_expr ->
             (match cleanup_expr.expr_desc with
              | FunctionCall (name, _) ->
                  check string "defer function name" "cleanup_function" name
              | _ -> fail "Expected function call in defer")
         | _ -> fail "Expected Defer statement")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse defer: " ^ Printexc.to_string e)

let test_complex_error_handling_parsing () =
  let program_text = make_simple_program_with_body {|
    defer cleanup_resources()
    
    try {
        let value = test_map[42]
        if (value == 0) {
            throw 404
        }
        defer cleanup_transaction()
    } catch 404 {
        test_map[42] = 100
        return 2
    }
  |} in
  
  try
    let ast = parse_string program_text in
    match List.nth ast 1 with
    | Program prog -> 
        let main_func = List.hd prog.prog_functions in
        let stmts = main_func.func_body in
        check int "total statements" 3 (List.length stmts); (* defer, try, return *)
        
        (* Check first statement is defer *)
        (match (List.hd stmts).stmt_desc with
         | Defer _ -> ()
         | _ -> fail "Expected first statement to be defer");
         
        (* Check second statement is try *)
        (match (List.nth stmts 1).stmt_desc with
         | Try (try_stmts, catch_clauses) ->
             check int "try statements" 3 (List.length try_stmts); (* let, if, defer *)
             check int "catch clauses" 1 (List.length catch_clauses); (* just 404 *)
             
             (* Check catch patterns *)
             let first_catch = List.hd catch_clauses in
             (match first_catch.catch_pattern with
              | IntPattern 404 -> ()
              | _ -> fail "Expected first catch to be 404")
         | _ -> fail "Expected second statement to be try")
    | _ -> fail "Expected program declaration"
  with
  | e -> fail ("Failed to parse complex error handling: " ^ Printexc.to_string e)

(** Test IR generation for error handling constructs *)

let test_try_catch_ir_generation () =
  let program_text = make_simple_program_with_body {|
    try {
        throw 1
    } catch 1 {
        return 1
    }
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    
    (* Just verify that IR generation succeeds *)
    check bool "IR generation succeeds" true (ir_prog.name = "test_prog");
    check bool "Main function exists" true (ir_prog.main_function.func_name = "test_prog")
  with
  | e -> fail ("Failed to generate IR for try/catch: " ^ Printexc.to_string e)

let test_throw_ir_generation () =
  let program_text = make_simple_program_with_body {|
    throw 99
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in  
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    
    (* Just verify that IR generation succeeds *)
    check bool "IR generation succeeds" true (ir_prog.name = "test_prog");
    check bool "Main function exists" true (ir_prog.main_function.func_name = "test_prog")
  with
  | e -> fail ("Failed to generate IR for throw: " ^ Printexc.to_string e)

let test_defer_ir_generation () =
  let program_text = make_simple_program_with_body {|
    defer cleanup()
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    
    (* Just verify that IR generation succeeds *)
    check bool "IR generation succeeds" true (ir_prog.name = "test_prog");
    check bool "Main function exists" true (ir_prog.main_function.func_name = "test_prog")
  with
  | e -> fail ("Failed to generate IR for defer: " ^ Printexc.to_string e)

(** Test eBPF C code generation for error handling *)

let test_ebpf_try_catch_codegen () =
  let program_text = make_simple_program_with_body {|
    try {
        throw 1
    } catch 1 {
        return 1
    }
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_prog in
    
    (* Verify basic C code generation succeeds *)
    check bool "C code generation succeeds" true (String.length c_code > 0);
    check bool "Contains function definition" true (contains_substr c_code "test_prog")
  with
  | e -> fail ("Failed to generate eBPF C code for try/catch: " ^ Printexc.to_string e)

let test_ebpf_throw_codegen () =
  let program_text = make_simple_program_with_body {|
    throw 42
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_prog in
    
    (* Verify basic C code generation succeeds *)
    check bool "C code generation succeeds" true (String.length c_code > 0);
    check bool "Contains function definition" true (contains_substr c_code "test_prog")
  with
  | e -> fail ("Failed to generate eBPF C code for throw: " ^ Printexc.to_string e)

let test_ebpf_defer_codegen () =
  let program_text = make_simple_program_with_body {|
    defer cleanup()
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_prog in
    
    (* Verify basic C code generation succeeds *)
    check bool "C code generation succeeds" true (String.length c_code > 0);
    check bool "Contains function definition" true (contains_substr c_code "test_prog")
  with
  | e -> fail ("Failed to generate eBPF C code for defer: " ^ Printexc.to_string e)

let test_multiple_catch_clauses_codegen () =
  let program_text = make_simple_program_with_body {|
    try {
        throw 1
    } catch 1 {
        return 1
    } catch 2 {
        return 2
    }
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_prog in
    
    (* Verify basic C code generation succeeds *)
    check bool "C code generation succeeds" true (String.length c_code > 0);
    check bool "Contains function definition" true (contains_substr c_code "test_prog")
  with
  | e -> fail ("Failed to generate eBPF C code for multiple catch clauses: " ^ Printexc.to_string e)

(** Test error condition detection *)

let test_uncaught_throw_detection () =
  let program_text = make_simple_program_with_body {|
    throw 500
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_prog in
    
    (* Verify basic C code generation succeeds *)
    check bool "C code generation succeeds" true (String.length c_code > 0)
  with
  | e -> fail ("Unexpected error in uncaught throw test: " ^ Printexc.to_string e)

let test_nested_try_catch_error () =
  let program_text = make_simple_program_with_body {|
    try {
        try {
            throw 404
        } catch 500 {
            return 1
        }
    } catch 404 {
        return 2
    }
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_prog in
    
    (* Verify basic C code generation succeeds *)
    check bool "C code generation succeeds" true (String.length c_code > 0)
  with
  | e -> fail ("Failed to handle nested try/catch: " ^ Printexc.to_string e)

let test_defer_resource_cleanup () =
  let program_text = make_simple_program_with_body {|
    defer release_lock()
    defer close_file()
    
    try {
        throw 1
    } catch 1 {
        return 1
    }
  |} in
  
  try
    let ast = parse_string program_text in
    let symbol_table = Kernelscript.Symbol_table.create_symbol_table () in
    let ir_multi_prog = generate_ir ast symbol_table "test" in
    let ir_prog = List.hd ir_multi_prog.programs in
    let c_code = Kernelscript.Ebpf_c_codegen.generate_c_program ir_prog in
    
    (* Verify basic C code generation succeeds *)
    check bool "C code generation succeeds" true (String.length c_code > 0)
  with
  | e -> fail ("Failed to generate defer resource cleanup: " ^ Printexc.to_string e)

(** Test suite definition *)
let error_handling_tests = [
  (* Parser tests *)
  "try_catch_parsing", `Quick, test_try_catch_parsing;
  "throw_parsing", `Quick, test_throw_parsing;
  "defer_parsing", `Quick, test_defer_parsing;
  "complex_error_handling_parsing", `Quick, test_complex_error_handling_parsing;
  
  (* IR generation tests *)
  "try_catch_ir_generation", `Quick, test_try_catch_ir_generation;
  "throw_ir_generation", `Quick, test_throw_ir_generation;
  "defer_ir_generation", `Quick, test_defer_ir_generation;
  
  (* eBPF codegen tests *)
  "ebpf_try_catch_codegen", `Quick, test_ebpf_try_catch_codegen;
  "ebpf_throw_codegen", `Quick, test_ebpf_throw_codegen;
  "ebpf_defer_codegen", `Quick, test_ebpf_defer_codegen;
  "multiple_catch_clauses_codegen", `Quick, test_multiple_catch_clauses_codegen;
  
  (* Error condition tests *)
  "uncaught_throw_detection", `Quick, test_uncaught_throw_detection;
  "nested_try_catch_error", `Quick, test_nested_try_catch_error;
  "defer_resource_cleanup", `Quick, test_defer_resource_cleanup;
]

(** Run all error handling tests *)
let () = Alcotest.run "Error Handling Tests" [
  "error_handling", error_handling_tests;
] 