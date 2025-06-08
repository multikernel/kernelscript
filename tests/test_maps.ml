open Kernelscript.Ast

(** Test suite for eBPF Maps module *)

let () =
  Printf.printf "Testing Maps module...\n";
  
  (* Test 1: Basic map type validation *)
  Printf.printf "\n=== Test 1: Map Type Validation ===\n";
  let result1 = Kernelscript.Maps.validate_key_type Kernelscript.Maps.Array U32 in
  Printf.printf "Array map with u32 key: %s\n" 
    (match result1 with Kernelscript.Maps.Valid -> "PASS" | _ -> "FAIL");
  
  let result2 = Kernelscript.Maps.validate_key_type Kernelscript.Maps.Array U64 in
  Printf.printf "Array map with u64 key: %s\n" 
    (match result2 with Kernelscript.Maps.InvalidKeyType _ -> "PASS" | _ -> "FAIL");
  
  (* Test 2: Type size calculation *)
  Printf.printf "\n=== Test 2: Type Sizes ===\n";
  Printf.printf "u8 size: %s\n" 
    (match Kernelscript.Maps.get_type_size U8 with Some 1 -> "PASS" | _ -> "FAIL");
  Printf.printf "u32 size: %s\n" 
    (match Kernelscript.Maps.get_type_size U32 with Some 4 -> "PASS" | _ -> "FAIL");
  Printf.printf "u64 size: %s\n" 
    (match Kernelscript.Maps.get_type_size U64 with Some 8 -> "PASS" | _ -> "FAIL");
  
  (* Test 3: Map configuration *)
  Printf.printf "\n=== Test 3: Map Configuration ===\n";
  let config1 = Kernelscript.Maps.make_map_config 1024 () in
  let result3 = Kernelscript.Maps.validate_map_config Kernelscript.Maps.HashMap config1 in
  Printf.printf "Valid config: %s\n" 
    (match result3 with Kernelscript.Maps.Valid -> "PASS" | _ -> "FAIL");
  
  let config2 = Kernelscript.Maps.make_map_config (-1) () in
  let result4 = Kernelscript.Maps.validate_map_config Kernelscript.Maps.HashMap config2 in
  Printf.printf "Invalid max_entries: %s\n" 
    (match result4 with Kernelscript.Maps.InvalidConfiguration _ -> "PASS" | _ -> "FAIL");
  
  (* Test 4: AST conversions *)
  Printf.printf "\n=== Test 4: AST Conversions ===\n";
  let ast_map_type = Kernelscript.Ast.HashMap in
  let ebpf_map_type = Kernelscript.Maps.ast_to_ebpf_map_type ast_map_type in
  Printf.printf "HashMap conversion: %s\n" 
    (match ebpf_map_type with Kernelscript.Maps.HashMap -> "PASS" | _ -> "FAIL");
  
  let back_conversion = Kernelscript.Maps.ebpf_to_ast_map_type ebpf_map_type in
  Printf.printf "Reverse conversion: %s\n" 
    (match back_conversion with Kernelscript.Ast.HashMap -> "PASS" | _ -> "FAIL");
  
  (* Test 5: String representations *)
  Printf.printf "\n=== Test 5: String Representations ===\n";
  Printf.printf "HashMap string: %s\n" 
    (if Kernelscript.Maps.string_of_ebpf_map_type Kernelscript.Maps.HashMap = "hash_map" then "PASS" else "FAIL");
  Printf.printf "Array string: %s\n" 
    (if Kernelscript.Maps.string_of_ebpf_map_type Kernelscript.Maps.Array = "array" then "PASS" else "FAIL");
  
  (* Test 6: Map compatibility *)
  Printf.printf "\n=== Test 6: Program Compatibility ===\n";
  Printf.printf "HashMap with XDP: %s\n" 
    (if Kernelscript.Maps.is_map_compatible_with_program Kernelscript.Maps.HashMap Xdp then "PASS" else "FAIL");
  Printf.printf "Array with TC: %s\n" 
    (if Kernelscript.Maps.is_map_compatible_with_program Kernelscript.Maps.Array Tc then "PASS" else "FAIL");
  
  Printf.printf "\nMaps module tests completed!\n" 