open Kernelscript.Ast
open Kernelscript.Stdlib

let test_builtin_functions () =
  Printf.printf "=== Testing KernelScript Built-in Functions ===\n";
  
  (* Test that print is recognized as a built-in function *)
  Printf.printf "Is 'print' a built-in function? %b\n" (is_builtin_function "print");
  
  (* Test getting function signature *)
  (match get_builtin_function_signature "print" with
   | Some (params, return_type) ->
       Printf.printf "print() signature: %d parameters, returns %s\n"
         (List.length params)
         (match return_type with
          | U32 -> "U32"
          | _ -> "other")
   | None -> Printf.printf "ERROR: Could not get signature for print()\n");
  
  (* Test context-specific implementations *)
  (match get_ebpf_implementation "print" with
   | Some impl -> Printf.printf "eBPF implementation: %s\n" impl
   | None -> Printf.printf "ERROR: No eBPF implementation found\n");
  
  (match get_userspace_implementation "print" with
   | Some impl -> Printf.printf "Userspace implementation: %s\n" impl  
   | None -> Printf.printf "ERROR: No userspace implementation found\n");
  
  Printf.printf "\n=== Code Generation Test ===\n";
  
  (* Test argument formatting for different contexts *)
  let args1 = ["\"Hello\""; "42"] in
  let ebpf_formatted = format_function_args `eBPF args1 in
  let userspace_formatted = format_function_args `Userspace args1 in
  
  Printf.printf "Original args: [%s]\n" (String.concat "; " args1);
  Printf.printf "eBPF formatted: [%s]\n" (String.concat "; " ebpf_formatted);
  Printf.printf "Userspace formatted: [%s]\n" (String.concat "; " userspace_formatted);
  
  Printf.printf "\n=== Test Complete ===\n"

let () = test_builtin_functions () 