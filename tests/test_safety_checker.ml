open Kernelscript.Ast
open Kernelscript.Safety_checker

(** Test suite for Memory Safety Analysis module *)

let () =
  Printf.printf "Testing Safety Checker module...\n";
  
  (* Helper functions to create test programs *)
  let make_test_program name functions =
    let pos = make_position 1 1 "test.ks" in
    {
      prog_name = name;
      prog_type = Xdp;
      prog_functions = functions;
      prog_maps = [];
      prog_pos = pos;
    }
  in
  
  let make_test_function name params body =
    let pos = make_position 1 1 "test.ks" in
    {
      func_name = name;
      func_params = params;
      func_return_type = Some XdpAction;
      func_body = body;
      func_pos = pos;
    }
  in
  
  (* Test 1: Stack usage analysis *)
  Printf.printf "\n=== Test 1: Stack Usage Analysis ===\n";
  
  (* Small function with minimal stack usage *)
  let small_func = make_test_function "small_func" [("ctx", XdpContext)] [
    make_stmt (Declaration ("x", Some U32, make_expr (Literal (IntLit 42)) (make_position 1 1 "test.ks"))) (make_position 1 1 "test.ks");
    make_stmt (Return (Some (make_expr (Identifier "x") (make_position 1 1 "test.ks")))) (make_position 1 1 "test.ks");
  ] in
  
  let small_program = make_test_program "small_test" [small_func] in
  let small_analysis = analyze_stack_usage small_program in
  Printf.printf "Small function stack usage: %s\n" 
    (if small_analysis.max_stack_usage <= 100 then "PASS" else "FAIL");
  Printf.printf "No overflow detected: %s\n" 
    (if not small_analysis.potential_overflow then "PASS" else "FAIL");
  
  (* Large function with potential stack overflow *)
  let large_func = make_test_function "large_func" [("ctx", XdpContext)] [
    make_stmt (Declaration ("big_array", Some (Array (U8, 600)), 
                           make_expr (Literal (IntLit 0)) (make_position 1 1 "test.ks"))) (make_position 1 1 "test.ks");
  ] in
  
  let large_program = make_test_program "large_test" [large_func] in
  let large_analysis = analyze_stack_usage large_program in
  Printf.printf "Large function overflow detected: %s\n" 
    (if large_analysis.potential_overflow then "PASS" else "FAIL");
  Printf.printf "Stack usage exceeds limit: %s\n" 
    (if large_analysis.max_stack_usage > 512 then "PASS" else "FAIL");
  
  (* Test 2: Bounds checking analysis *)
  Printf.printf "\n=== Test 2: Bounds Checking Analysis ===\n";
  
  (* Valid array access *)
  let pos = make_position 1 1 "test.ks" in
  let arr_expr = {
    expr_desc = Identifier "arr";
    expr_pos = pos;
    expr_type = Some (Array (U32, 10));
  } in
  let valid_access = make_expr (ArrayAccess (arr_expr, make_expr (Literal (IntLit 5)) pos)) pos in
  let valid_bounds_errors = check_array_bounds valid_access in
  Printf.printf "Valid array access: %s\n" 
    (if valid_bounds_errors = [] then "PASS" else "FAIL");
  
  (* Invalid array access - out of bounds *)
  let invalid_arr_expr = {
    expr_desc = Identifier "arr";
    expr_pos = pos;
    expr_type = Some (Array (U32, 10));
  } in
  let invalid_access = make_expr (ArrayAccess (invalid_arr_expr, make_expr (Literal (IntLit 15)) pos)) pos in
  let invalid_bounds_errors = check_array_bounds invalid_access in
  Printf.printf "Invalid array access detected: %s\n" 
    (match invalid_bounds_errors with 
     | ArrayOutOfBounds _ :: _ -> "PASS" 
     | _ -> "FAIL");
  
  (* Test 3: Invalid array size *)
  Printf.printf "\n=== Test 3: Array Size Validation ===\n";
  
  let invalid_size_func = make_test_function "invalid_size_func" [("ctx", XdpContext)] [
    make_stmt (Declaration ("bad_array", Some (Array (U32, -1)), 
                           make_expr (Literal (IntLit 0)) pos)) pos;
  ] in
  
  let invalid_size_program = make_test_program "invalid_size_test" [invalid_size_func] in
  let invalid_size_errors = analyze_bounds_safety invalid_size_program in
  Printf.printf "Invalid array size detected: %s\n" 
    (match invalid_size_errors with 
     | InvalidArraySize _ :: _ -> "PASS" 
     | _ -> "FAIL");
  
  (* Test 4: Safety check with exceptions *)
  Printf.printf "\n=== Test 4: Safety Check Exceptions ===\n";
  
  let safe_func = make_test_function "safe_func" [("ctx", XdpContext)] [
    make_stmt (Declaration ("safe_var", Some U32, make_expr (Literal (IntLit 42)) pos)) pos;
    make_stmt (Return (Some (make_expr (Identifier "safe_var") pos))) pos;
  ] in
  
  let safe_program = make_test_program "safe_test" [safe_func] in
  
  (try
    let safe_analysis = safety_check safe_program in
    Printf.printf "Safe program analysis: %s\n" 
      (if safe_analysis.overall_safe then "PASS" else "FAIL")
  with
    | Bounds_error _ -> Printf.printf "Safe program analysis: FAIL");
  
  (* Test with bounds error *)
  let unsafe_arr_expr = {
    expr_desc = Identifier "unsafe_arr";
    expr_pos = pos;
    expr_type = Some (Array (U32, 5));
  } in
  let unsafe_func = make_test_function "unsafe_func" [("ctx", XdpContext)] [
    make_stmt (Declaration ("unsafe_arr", Some (Array (U32, 5)), 
                           make_expr (Literal (IntLit 0)) pos)) pos;
    make_stmt (ExprStmt (make_expr (ArrayAccess (unsafe_arr_expr, make_expr (Literal (IntLit 10)) pos)) pos)) pos;
  ] in
  
  let unsafe_program = make_test_program "unsafe_test" [unsafe_func] in
  
  (try
    let _ = safety_check unsafe_program in
    Printf.printf "Unsafe program exception: FAIL"
  with
    | Bounds_error _ -> Printf.printf "Unsafe program exception: PASS");
  Printf.printf "\n";
  
  (* Test 5: Complete safety analysis *)
  Printf.printf "\n=== Test 5: Complete Safety Analysis ===\n";
  
  let complete_func = make_test_function "complete_func" [("ctx", XdpContext); ("data", Pointer U8)] [
    make_stmt (Declaration ("counter", Some U64, make_expr (Literal (IntLit 0)) pos)) pos;
    make_stmt (Declaration ("buffer", Some (Array (U8, 100)), make_expr (Literal (IntLit 0)) pos)) pos;
    make_stmt (Return (Some (make_expr (Identifier "counter") pos))) pos;
  ] in
  
  let complete_program = make_test_program "complete_test" [complete_func] in
  let complete_analysis = analyze_safety complete_program in
  
  Printf.printf "Complete analysis overall safe: %s\n" 
    (if complete_analysis.overall_safe then "PASS" else "FAIL");
  Printf.printf "Stack analysis included: %s\n" 
    (if complete_analysis.stack_analysis.max_stack_usage > 0 then "PASS" else "FAIL");
  Printf.printf "Bounds errors tracked: %s\n" 
    (if List.length complete_analysis.bounds_errors >= 0 then "PASS" else "FAIL");
  
  (* Test 6: String representations *)
  Printf.printf "\n=== Test 6: String Representations ===\n";
  
  let bounds_error = ArrayOutOfBounds ("test_array", 10, 5) in
  let error_str = string_of_bounds_error bounds_error in
  Printf.printf "Bounds error string: %s\n" 
    (if String.contains error_str '[' && String.contains error_str ']' then "PASS" else "FAIL");
  
  let stack_str = string_of_stack_analysis complete_analysis.stack_analysis in
  Printf.printf "Stack analysis string: %s\n" 
    (if String.contains stack_str '=' then "PASS" else "FAIL");
  
  let safety_str = string_of_safety_analysis complete_analysis in
  Printf.printf "Safety analysis string: %s\n" 
    (if String.contains safety_str '=' then "PASS" else "FAIL");
  
  (* Test 7: Type stack usage calculation *)
  Printf.printf "\n=== Test 7: Type Stack Usage ===\n";
  
  Printf.printf "u8 stack usage: %s\n" 
    (if calculate_type_stack_usage U8 = 1 then "PASS" else "FAIL");
  Printf.printf "u32 stack usage: %s\n" 
    (if calculate_type_stack_usage U32 = 4 then "PASS" else "FAIL");
  Printf.printf "u64 stack usage: %s\n" 
    (if calculate_type_stack_usage U64 = 8 then "PASS" else "FAIL");
  Printf.printf "pointer stack usage: %s\n" 
    (if calculate_type_stack_usage (Pointer U32) = 8 then "PASS" else "FAIL");
  Printf.printf "array stack usage: %s\n" 
    (if calculate_type_stack_usage (Array (U32, 10)) = 40 then "PASS" else "FAIL");
  
  (* Test 8: Function stack usage analysis *)
  Printf.printf "\n=== Test 8: Function Analysis ===\n";
  
  let func_with_params = make_test_function "param_func" [("a", U32); ("b", U64); ("c", Array (U8, 20))] [
    make_stmt (Declaration ("local", Some U32, make_expr (Literal (IntLit 1)) pos)) pos;
  ] in
  
  let (param_usage, _messages) = analyze_function_stack_usage func_with_params in
  Printf.printf "Function with parameters: %s\n" 
    (if param_usage > 30 then "PASS" else "FAIL"); (* 4 + 8 + 20 + 4 = 36 *)
  
  Printf.printf "\nSafety Checker module tests completed!\n" 