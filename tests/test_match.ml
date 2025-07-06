open Alcotest
open Kernelscript.Ast
open Kernelscript.Parse

(** Test position for all tests *)
let test_pos = { line = 1; column = 1; filename = "test" }

(** Test basic match construct parsing *)
let test_basic_match_parsing () =
  let input = {|
    fn test_match() -> u32 {
      var protocol = 6
      return match (protocol) {
        6: 1,
        17: 2,
        default: 0
      }
    }
  |} in
  
  let ast = parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.nth func.func_body 1 in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (matched_expr, arms) ->
      (* Check matched expression *)
      check bool "matched expression is identifier" true 
        (match matched_expr.expr_desc with
         | Identifier "protocol" -> true
         | _ -> false);
      
      (* Check number of arms *)
      check int "number of arms" 3 (List.length arms)
  | _ -> failwith "Expected match expression"

(** Test match with enum constants *)
let test_match_with_enums () =
  let input = {|
    enum Protocol {
      TCP = 6,
      UDP = 17,
      ICMP = 1
    }
    
    fn test_protocol_match(proto: u32) -> u32 {
      return match (proto) {
        TCP: 100,
        UDP: 200,
        ICMP: 300,
        default: 0
      }
    }
  |} in
  
  let ast = parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.nth ast 1 with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check that we have identifier patterns *)
      let first_arm = List.hd arms in
      check bool "first arm is TCP identifier pattern" true
        (match first_arm.arm_pattern with
         | IdentifierPattern "TCP" -> true
         | _ -> false)
  | _ -> failwith "Expected match expression"

(** Test packet matching scenario *)
let test_packet_matching () =
  let input = {|
    @helper
    fn get_protocol(ctx: xdp_md) -> u32 {
      return 6
    }
    
    @xdp
    fn packet_classifier(ctx: xdp_md) -> xdp_action {
      var protocol = get_protocol(ctx)
      
      return match (protocol) {
        6: XDP_PASS,
        17: XDP_PASS, 
        default: XDP_ABORTED
      }
    }
  |} in
  
  let ast = parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let attr_func = match List.nth ast 1 with
    | AttributedFunction af -> af
    | _ -> failwith "Expected attributed function"
  in
  
  let func = attr_func.attr_function in
  let return_stmt = List.nth func.func_body 1 in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (matched_expr, arms) ->
      (* Check that matched expression is the protocol variable *)
      check bool "matched expression is protocol identifier" true
        (match matched_expr.expr_desc with
         | Identifier "protocol" -> true
         | _ -> false);
      
      (* Check that we have 3 arms *)
      check int "number of arms" 3 (List.length arms)
  | _ -> failwith "Expected match expression"

(** Test nested match expressions *)
let test_nested_match () =
  let input = {|
    fn test_nested(x: u32, y: u32) -> u32 {
      return match (x) {
        1: match (y) {
          10: 100,
          20: 200,
          default: 0
        },
        2: 50,
        default: 0
      }
    }
  |} in
  
  let ast = parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check first arm has nested match *)
      let first_arm = List.hd arms in
              check bool "first arm has nested match" true
         (match first_arm.arm_body with
          | SingleExpr expr -> 
              (match expr.expr_desc with
               | Match (_, nested_arms) -> List.length nested_arms = 3
               | _ -> false)
          | Block _ -> false)
  | _ -> failwith "Expected match expression"

(** Test match with string patterns *)
let test_match_string_patterns () =
  let input = {|
    fn test_strings(name: str<10>) -> u32 {
      return match (name) {
        "tcp": 1,
        "udp": 2,
        "icmp": 3,
        default: 0
      }
    }
  |} in
  
  let ast = parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check first arm has string pattern *)
      let first_arm = List.hd arms in
      check bool "first arm has string pattern tcp" true
        (match first_arm.arm_pattern with
         | ConstantPattern (StringLit "tcp") -> true
         | _ -> false)
  | _ -> failwith "Expected match expression"

(** Test match with boolean patterns *)
let test_match_boolean_patterns () =
  let input = {|
    fn test_bool(flag: bool) -> u32 {
      return match (flag) {
        true: 1,
        false: 0
      }
    }
  |} in
  
  let ast = parse_string input in
  let _symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let func = match List.hd ast with
    | GlobalFunction f -> f
    | _ -> failwith "Expected function"
  in
  
  let return_stmt = List.hd func.func_body in
  let match_expr = match return_stmt.stmt_desc with
    | Return (Some expr) -> expr
    | _ -> failwith "Expected return with match expression"
  in
  
  match match_expr.expr_desc with
  | Match (_, arms) ->
      (* Check boolean patterns *)
      let first_arm = List.hd arms in
      check bool "first arm has boolean pattern true" true
        (match first_arm.arm_pattern with
         | ConstantPattern (BoolLit true) -> true
         | _ -> false);
      
      let second_arm = List.nth arms 1 in
      check bool "second arm has boolean pattern false" true
        (match second_arm.arm_pattern with
         | ConstantPattern (BoolLit false) -> true
         | _ -> false)
  | _ -> failwith "Expected match expression"

let suite = [
  "test_basic_match_parsing", `Quick, test_basic_match_parsing;
  "test_match_with_enums", `Quick, test_match_with_enums;
  "test_packet_matching", `Quick, test_packet_matching;
  "test_nested_match", `Quick, test_nested_match;
  "test_match_string_patterns", `Quick, test_match_string_patterns;
  "test_match_boolean_patterns", `Quick, test_match_boolean_patterns;
]

let () = run "Match Construct Tests" [
  "match_tests", suite;
] 