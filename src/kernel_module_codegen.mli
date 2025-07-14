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

(** Kernel Module Code Generation for @kfunc Functions
    
    This module generates kernel module C code for functions annotated with @kfunc.
*)

(** Generate kernel module from AST containing @kfunc functions
    
    @param module_name The name of the kernel module to generate
    @param ast The AST containing function declarations
    @return Some module_code if kfuncs are found, None otherwise
*)
val generate_kernel_module_from_ast : string -> Ast.declaration list -> string option 