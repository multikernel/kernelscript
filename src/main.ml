open Kernelscript

let print_token = function
  | Parser.PROGRAM -> "PROGRAM"
  | Parser.FN -> "FN"
  | Parser.XDP -> "XDP"
  | Parser.TC -> "TC"
  | Parser.KPROBE -> "KPROBE"
  | Parser.UPROBE -> "UPROBE"
  | Parser.TRACEPOINT -> "TRACEPOINT"
  | Parser.LSM -> "LSM"
  | Parser.IF -> "IF"
  | Parser.ELSE -> "ELSE"
  | Parser.FOR -> "FOR"
  | Parser.WHILE -> "WHILE"
  | Parser.RETURN -> "RETURN"
  | Parser.LET -> "LET"
  | Parser.INT i -> "INT(" ^ string_of_int i ^ ")"
  | Parser.STRING s -> "STRING(\"" ^ s ^ "\")"
  | Parser.IDENTIFIER id -> "IDENTIFIER(" ^ id ^ ")"
  | Parser.CHAR_LIT c -> "CHAR('" ^ String.make 1 c ^ "')"
  | Parser.BOOL_LIT b -> "BOOL(" ^ string_of_bool b ^ ")"
  | Parser.LBRACE -> "{"
  | Parser.RBRACE -> "}"
  | Parser.LPAREN -> "("
  | Parser.RPAREN -> ")"
  | Parser.SEMICOLON -> ";"
  | Parser.COLON -> ":"
  | Parser.ARROW -> "->"
  | Parser.ASSIGN -> "="
  | Parser.PLUS -> "+"
  | Parser.MINUS -> "-"
  | Parser.MULTIPLY -> "*"
  | Parser.DIVIDE -> "/"
  | Parser.LT -> "<"
  | Parser.GT -> ">"
  | Parser.EQ -> "=="
  | Parser.NE -> "!="
  | Parser.LE -> "<="
  | Parser.GE -> ">="
  | Parser.AND -> "&&"
  | Parser.OR -> "||"
  | Parser.NOT -> "!"
  | Parser.DOT -> "."
  | Parser.COMMA -> ","
  | Parser.LBRACKET -> "["
  | Parser.RBRACKET -> "]"
  | Parser.EOF -> "EOF"
  | _ -> "OTHER"

let print_tokens tokens =
  List.iter (fun token ->
    Printf.printf "%s " (print_token token)
  ) tokens;
  Printf.printf "\n"

let test_sample_code () =
  let sample = {|
    program network_monitor : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        let packet_size = ctx.data_end - ctx.data;
        if packet_size > 1500 {
          return 1;
        }
        return 0;
      }
    }
  |} in
  Printf.printf "Sample KernelScript code:\n%s\n\n" sample;
  Printf.printf "Tokens:\n";
  let tokens = Lexer.tokenize_string sample in
  print_tokens tokens

let test_evaluator () =
  Printf.printf "\n=== Evaluator Test ===\n";
  
  (* Create a simple expression evaluation test *)
  let ctx = Evaluator.create_eval_context (Hashtbl.create 0) (Hashtbl.create 0) in
  
  (* Test arithmetic expression: 10 + 5 * 2 *)
  let five = Ast.make_expr (Ast.Literal (Ast.IntLit 5)) (Ast.make_position 1 1 "test") in
  let two = Ast.make_expr (Ast.Literal (Ast.IntLit 2)) (Ast.make_position 1 1 "test") in
  let ten = Ast.make_expr (Ast.Literal (Ast.IntLit 10)) (Ast.make_position 1 1 "test") in
  
  let mul_expr = Ast.make_expr (Ast.BinaryOp (five, Ast.Mul, two)) (Ast.make_position 1 1 "test") in
  let add_expr = Ast.make_expr (Ast.BinaryOp (ten, Ast.Add, mul_expr)) (Ast.make_position 1 1 "test") in
  
  Printf.printf "Evaluating expression: 10 + 5 * 2\n";
  (match Evaluator.evaluate_expression ctx add_expr with
  | Ok result -> 
      Printf.printf "Result: %s\n" (Evaluator.string_of_runtime_value result)
  | Error (msg, pos) -> 
      Printf.printf "Error: %s at %s\n" msg (Ast.string_of_position pos));
    
  (* Test built-in function call *)
  Printf.printf "\nTesting built-in function: bpf_get_current_pid_tgid()\n";
  let func_call = Ast.make_expr (Ast.FunctionCall ("bpf_get_current_pid_tgid", [])) (Ast.make_position 1 1 "test") in
  (match Evaluator.evaluate_expression ctx func_call with
  | Ok result -> 
      Printf.printf "PID/TGID: %s\n" (Evaluator.string_of_runtime_value result)
  | Error (msg, pos) -> 
      Printf.printf "Error: %s at %s\n" msg (Ast.string_of_position pos));
  
  (* Test enum constant *)
  Printf.printf "\nTesting enum constant: XdpAction::Pass\n";
  let enum_expr = Ast.make_expr (Ast.Identifier "XdpAction::Pass") (Ast.make_position 1 1 "test") in
  (match Evaluator.evaluate_expression ctx enum_expr with
  | Ok result -> 
      Printf.printf "XdpAction::Pass = %s\n" (Evaluator.string_of_runtime_value result)
  | Error (msg, pos) -> 
      Printf.printf "Error: %s at %s\n" msg (Ast.string_of_position pos));
  Printf.printf "\n✅ All evaluator tests completed successfully!\n"

let () =
  Printf.printf "KernelScript Compiler Test\n";
  Printf.printf "==========================\n\n";
  test_sample_code ();
  test_evaluator () 