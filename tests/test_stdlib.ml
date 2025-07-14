(*
 * Copyright 2025 Multikernel Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

open Kernelscript.Ast
open Kernelscript.Stdlib
open Alcotest

(** Test built-in function recognition *)
let test_builtin_function_recognition () =
  check bool "print is builtin" true (is_builtin_function "print");
  check bool "non_existent is not builtin" false (is_builtin_function "non_existent_function")

(** Test function signature retrieval *)
let test_function_signatures () =
  match get_builtin_function_signature "print" with
  | Some (params, return_type) ->
      check int "print parameter count" 0 (List.length params);
      check bool "print return type is U32" true (return_type = U32)
  | None -> fail "print function signature should exist"

(** Test context-specific implementations *)
let test_context_implementations () =
  (* Test eBPF implementation *)
  (match get_ebpf_implementation "print" with
   | Some impl -> check string "eBPF implementation" "bpf_printk" impl
   | None -> fail "eBPF implementation should exist");
  
  (* Test userspace implementation *)
  (match get_userspace_implementation "print" with
   | Some impl -> check string "userspace implementation" "printf" impl
   | None -> fail "userspace implementation should exist");
  
  (* Test kernel implementation *)
  (match get_kernel_implementation "print" with
   | Some impl -> check string "kernel implementation" "printk" impl
   | None -> fail "kernel implementation should exist")

(** Test argument formatting for different contexts *)
let test_argument_formatting () =
  let args = ["\"Hello\""; "42"] in
  let ebpf_formatted = format_function_args `eBPF args in
  let userspace_formatted = format_function_args `Userspace args in
  
  (* eBPF should format with format string first, limited to 3 additional args *)
  check int "eBPF formatted arg count" 2 (List.length ebpf_formatted);
  check string "eBPF format string" "\"%s%d\"" (List.hd ebpf_formatted);
  
  (* Userspace should keep original args *)
  check int "userspace formatted arg count" 2 (List.length userspace_formatted);
  check (list string) "userspace args preserved" args userspace_formatted;
  
  (* Test empty args *)
  let empty_ebpf = format_function_args `eBPF [] in
  let empty_userspace = format_function_args `Userspace [] in
  check int "empty eBPF args" 1 (List.length empty_ebpf);
  check string "empty eBPF format" "\"\"" (List.hd empty_ebpf);
  check int "empty userspace args" 1 (List.length empty_userspace);
  check string "empty userspace format" "\"\\n\"" (List.hd empty_userspace)

(** Test variadic function properties *)
let test_variadic_properties () =
  match get_builtin_function "print" with
  | Some builtin_func ->
      check bool "print is variadic" true builtin_func.is_variadic;
      check string "print name" "print" builtin_func.name;
      check bool "print return type is U32" true (builtin_func.return_type = U32)
  | None -> fail "print builtin function should exist"

(** Test error cases *)
let test_error_cases () =
  (* Non-existent function should return None *)
  check bool "non-existent function signature is None" true 
    (get_builtin_function_signature "does_not_exist" = None);
  
  check bool "non-existent eBPF impl is None" true 
    (get_ebpf_implementation "does_not_exist" = None);
  
  check bool "non-existent userspace impl is None" true 
    (get_userspace_implementation "does_not_exist" = None)

let stdlib_tests = [
  "builtin_function_recognition", `Quick, test_builtin_function_recognition;
  "function_signatures", `Quick, test_function_signatures;
  "context_implementations", `Quick, test_context_implementations;
  "argument_formatting", `Quick, test_argument_formatting;
  "variadic_properties", `Quick, test_variadic_properties;
  "error_cases", `Quick, test_error_cases;
]

let () =
  run "KernelScript Stdlib Tests" [
    "stdlib", stdlib_tests;
  ] 