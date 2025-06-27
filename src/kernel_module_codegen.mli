(** Kernel Module Code Generation for @kfunc Functions
    
    This module generates kernel module C code for functions annotated with @kfunc.
*)

(** Generate kernel module from AST containing @kfunc functions
    
    @param module_name The name of the kernel module to generate
    @param ast The AST containing function declarations
    @return Some module_code if kfuncs are found, None otherwise
*)
val generate_kernel_module_from_ast : string -> Ast.declaration list -> string option 