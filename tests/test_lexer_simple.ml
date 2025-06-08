open Kernelscript

let test_keywords () =
  let tokens = Lexer.tokenize_string "program fn map" in
  let expected = [Parser.PROGRAM; Parser.FN; Parser.MAP] in
  if tokens = expected then
    Printf.printf "✓ Keywords test passed\n"
  else
    Printf.printf "✗ Keywords test failed\n"

let test_literals () =
  let tokens = Lexer.tokenize_string "42 \"hello\" true" in
  let expected = [Parser.INT 42; Parser.STRING "hello"; Parser.BOOL_LIT true] in
  if tokens = expected then
    Printf.printf "✓ Literals test passed\n"
  else
    Printf.printf "✗ Literals test failed\n"

let test_hex_literals () =
  let tokens = Lexer.tokenize_string "0xFF" in
  let expected = [Parser.INT 255] in
  if tokens = expected then
    Printf.printf "✓ Hex literals test passed\n"
  else
    Printf.printf "✗ Hex literals test failed\n"

let test_operators () =
  let tokens = Lexer.tokenize_string "+ - * /" in
  let expected = [Parser.PLUS; Parser.MINUS; Parser.MULTIPLY; Parser.DIVIDE] in
  if tokens = expected then
    Printf.printf "✓ Operators test passed\n"
  else
    Printf.printf "✗ Operators test failed\n"

let run_tests () =
  Printf.printf "Running KernelScript Lexer Tests\n";
  Printf.printf "=================================\n\n";
  test_keywords ();
  test_literals ();
  test_hex_literals ();
  test_operators ();
  Printf.printf "\nTests completed.\n"

let () = run_tests () 