open Kernelscript.Ast
open Kernelscript.Maps
open Kernelscript.Map_operations

(** Test suite for Map Operations module *)

let () =
  Printf.printf "Testing Map Operations module...\n";
  
  (* Test 1: Access Pattern Analysis *)
  Printf.printf "\n=== Test 1: Access Pattern Analysis ===\n";
  
  let pos = make_position 1 1 "test.ks" in
  
  (* Test sequential access pattern *)
  let seq_expressions = [
    make_expr (ArrayAccess (make_expr (Identifier "test_map") pos, make_expr (Literal (IntLit 0)) pos)) pos;
    make_expr (ArrayAccess (make_expr (Identifier "test_map") pos, make_expr (Literal (IntLit 1)) pos)) pos;
    make_expr (ArrayAccess (make_expr (Identifier "test_map") pos, make_expr (Literal (IntLit 2)) pos)) pos;
  ] in
  
  let seq_pattern = analyze_access_pattern "test_map" seq_expressions in
  Printf.printf "Sequential access pattern: %s\n" 
    (match seq_pattern with Sequential _ -> "PASS" | _ -> "FAIL");
  
  (* Test random access pattern *)
  let rand_expressions = [
    make_expr (ArrayAccess (make_expr (Identifier "test_map") pos, make_expr (Identifier "key") pos)) pos;
  ] in
  
  let rand_pattern = analyze_access_pattern "test_map" rand_expressions in
  Printf.printf "Random access pattern: %s\n" 
    (match rand_pattern with Random -> "PASS" | _ -> "FAIL");
  
  (* Test batch access pattern *)
  let batch_expressions = List.init 15 (fun i ->
    make_expr (ArrayAccess (make_expr (Identifier "test_map") pos, make_expr (Literal (IntLit i)) pos)) pos
  ) in
  
  let batch_pattern = analyze_access_pattern "test_map" batch_expressions in
  Printf.printf "Batch access pattern: %s\n" 
    (match batch_pattern with Batch _ -> "PASS" | _ -> "FAIL");
  
  (* Test 2: Concurrent Access Safety *)
  Printf.printf "\n=== Test 2: Concurrent Access Safety ===\n";
  
  (* Safe concurrent reads *)
  let safe_read = analyze_concurrent_safety HashMap MapLookup 3 0 in
  Printf.printf "Safe concurrent reads: %s\n" 
    (match safe_read with Safe -> "PASS" | _ -> "FAIL");
  
  (* Read-safe with single writer *)
  let read_safe = analyze_concurrent_safety HashMap MapLookup 2 1 in
  Printf.printf "Read-safe with single writer: %s\n" 
    (match read_safe with ReadSafe -> "PASS" | _ -> "FAIL");
  
  (* Write-locked with multiple writers *)
  let write_locked = analyze_concurrent_safety HashMap MapUpdate 1 2 in
  Printf.printf "Write-locked with multiple writers: %s\n" 
    (match write_locked with WriteLocked -> "PASS" | _ -> "FAIL");
  
  (* Unsafe array operations *)
  let unsafe_array = analyze_concurrent_safety Array MapInsert 0 1 in
  Printf.printf "Unsafe array insert: %s\n" 
    (match unsafe_array with Unsafe _ -> "PASS" | _ -> "FAIL");
  
  (* Test 3: Global Map Sharing Validation *)
  Printf.printf "\n=== Test 3: Global Map Sharing Validation ===\n";
  
  (* Valid sharing - multiple readers *)
  let readers_only = [
    ("prog1", [MapLookup]);
    ("prog2", [MapLookup]);
    ("prog3", [MapLookup]);
  ] in
  
  let valid_sharing = validate_global_sharing "shared_map" HashMap readers_only in
  Printf.printf "Valid sharing (readers only): %s\n" 
    (if valid_sharing.is_valid then "PASS" else "FAIL");
  
  (* Valid sharing - single writer *)
  let single_writer = [
    ("prog1", [MapLookup]);
    ("prog2", [MapUpdate]);
  ] in
  
  let valid_single_writer = validate_global_sharing "shared_map" HashMap single_writer in
  Printf.printf "Valid sharing (single writer): %s\n" 
    (if valid_single_writer.is_valid then "PASS" else "FAIL");
  
  (* Invalid sharing - multiple writers *)
  let multiple_writers = [
    ("prog1", [MapUpdate]);
    ("prog2", [MapUpdate]);
    ("prog3", [MapLookup]);
  ] in
  
  let invalid_sharing = validate_global_sharing "shared_map" HashMap multiple_writers in
  Printf.printf "Invalid sharing (multiple writers): %s\n" 
    (if not invalid_sharing.is_valid then "PASS" else "FAIL");
  Printf.printf "Conflicts detected: %s\n" 
    (if List.length invalid_sharing.conflicts > 0 then "PASS" else "FAIL");
  
  (* Test 4: Operation Validation *)
  Printf.printf "\n=== Test 4: Operation Validation ===\n";
  
  (* Valid low-frequency operation *)
  let low_freq_context = {
    program_name = "test_prog";
    function_name = "test_func";
    map_name = "test_map";
    operation = MapLookup;
    access_pattern = Random;
    concurrent_readers = 1;
    concurrent_writers = 0;
    expected_frequency = 1000;
  } in
  
  let low_freq_validation = validate_operation low_freq_context in
  Printf.printf "Valid low-frequency operation: %s\n" 
    (if low_freq_validation.is_valid then "PASS" else "FAIL");
  Printf.printf "Safe concurrent access: %s\n" 
    (match low_freq_validation.safety_level with Safe -> "PASS" | _ -> "FAIL");
  
  (* High-frequency operation with warnings *)
  let high_freq_context = {
    program_name = "test_prog";
    function_name = "test_func";
    map_name = "test_map";
    operation = MapLookup;
    access_pattern = Random;
    concurrent_readers = 1;
    concurrent_writers = 0;
    expected_frequency = 200000;
  } in
  
  let high_freq_validation = validate_operation high_freq_context in
  Printf.printf "High-frequency operation validation: %s\n" 
    (if high_freq_validation.is_valid then "PASS" else "FAIL");
  Printf.printf "Performance warnings generated: %s\n" 
    (if List.length high_freq_validation.warnings > 0 then "PASS" else "FAIL");
  
  (* Unsafe concurrent operation *)
  let unsafe_context = {
    program_name = "test_prog";
    function_name = "test_func";
    map_name = "test_array";
    operation = MapInsert;
    access_pattern = Random;
    concurrent_readers = 0;
    concurrent_writers = 1;
    expected_frequency = 1000;
  } in
  
  let unsafe_validation = validate_operation unsafe_context in
  Printf.printf "Unsafe operation detected: %s\n" 
    (if List.length unsafe_validation.warnings > 0 then "PASS" else "FAIL");
  
  (* Test 5: Performance Profiles *)
  Printf.printf "\n=== Test 5: Performance Profiles ===\n";
  
  let hash_profile = PerformanceProfiles.get_profile HashMap in
  Printf.printf "HashMap lookup complexity defined: %s\n" 
    (if String.length hash_profile.lookup_complexity > 0 then "PASS" else "FAIL");
  Printf.printf "HashMap memory overhead reasonable: %s\n" 
    (if hash_profile.memory_overhead > 0 && hash_profile.memory_overhead < 100 then "PASS" else "FAIL");
  
  let array_profile = PerformanceProfiles.get_profile Array in
  Printf.printf "Array has O(1) complexity: %s\n" 
    (if String.contains array_profile.lookup_complexity '1' then "PASS" else "FAIL");
  Printf.printf "Array has better cache efficiency: %s\n" 
    (if array_profile.cache_efficiency > hash_profile.cache_efficiency then "PASS" else "FAIL");
  
  (* Test 6: String Representations *)
  Printf.printf "\n=== Test 6: String Representations ===\n";
  
  let seq_str = string_of_access_pattern (Sequential 2) in
  Printf.printf "Sequential pattern string: %s\n" 
    (if String.contains seq_str '2' then "PASS" else "FAIL");
  
  let safety_str = string_of_concurrency_safety WriteLocked in
  Printf.printf "Safety level string: %s\n" 
    (if String.contains safety_str 'L' then "PASS" else "FAIL");
  
  let context_str = string_of_operation_context low_freq_context in
  Printf.printf "Operation context string: %s\n" 
    (if String.contains context_str '{' && String.contains context_str '}' then "PASS" else "FAIL");
  
  let sharing_str = string_of_sharing_validation valid_sharing in
  Printf.printf "Sharing validation string: %s\n" 
    (if String.contains sharing_str '=' then "PASS" else "FAIL");
  
  let validation_str = string_of_operation_validation low_freq_validation in
  Printf.printf "Operation validation string: %s\n" 
    (if String.contains validation_str '=' then "PASS" else "FAIL");
  
  (* Test 7: Complex Access Pattern Analysis *)
  Printf.printf "\n=== Test 7: Complex Access Pattern Analysis ===\n";
  
  (* Mixed access pattern *)
  let mixed_expressions = [
    make_expr (ArrayAccess (make_expr (Identifier "test_map") pos, make_expr (Literal (IntLit 0)) pos)) pos;
    make_expr (ArrayAccess (make_expr (Identifier "test_map") pos, make_expr (Identifier "key") pos)) pos;
    make_expr (FunctionCall ("test_map.lookup", [make_expr (Identifier "key") pos])) pos;
  ] in
  
  let mixed_pattern = analyze_access_pattern "test_map" mixed_expressions in
  Printf.printf "Mixed access pattern handled: %s\n" 
    (match mixed_pattern with Random | Sequential _ | Batch _ -> "PASS" | _ -> "FAIL");
  
  (* No access pattern *)
  let no_access_pattern = analyze_access_pattern "nonexistent_map" mixed_expressions in
  Printf.printf "No access pattern: %s\n" 
    (match no_access_pattern with Random -> "PASS" | _ -> "FAIL");
  
  (* Function call access pattern *)
  let func_expressions = [
    make_expr (FunctionCall ("test_map.lookup", [make_expr (Literal (IntLit 1)) pos])) pos;
    make_expr (FunctionCall ("test_map.update", [make_expr (Literal (IntLit 2)) pos; make_expr (Literal (IntLit 42)) pos])) pos;
  ] in
  
  let func_pattern = analyze_access_pattern "test_map" func_expressions in
  Printf.printf "Function call access pattern: %s\n" 
    (match func_pattern with Random | Batch _ -> "PASS" | _ -> "FAIL");
  
  (* Test 8: Edge Cases *)
  Printf.printf "\n=== Test 8: Edge Cases ===\n";
  
  (* Empty sharing validation *)
  let empty_sharing = validate_global_sharing "empty_map" HashMap [] in
  Printf.printf "Empty sharing validation: %s\n" 
    (if empty_sharing.is_valid then "PASS" else "FAIL");
  
  (* Zero frequency operation *)
  let zero_freq_context = { low_freq_context with expected_frequency = 0 } in
  let zero_freq_validation = validate_operation zero_freq_context in
  Printf.printf "Zero frequency operation: %s\n" 
    (if zero_freq_validation.is_valid then "PASS" else "FAIL");
  
  (* Maximum values *)
  let max_context = {
    program_name = "max_prog";
    function_name = "max_func"; 
    map_name = "max_map";
    operation = MapLookup;
    access_pattern = Random;
    concurrent_readers = 1000;
    concurrent_writers = 0;
    expected_frequency = 1000000;
  } in
  
  let max_validation = validate_operation max_context in
  Printf.printf "Maximum values handled: %s\n" 
    (if max_validation.is_valid then "PASS" else "FAIL");
  
  Printf.printf "\nMap Operations module tests completed!\n" 