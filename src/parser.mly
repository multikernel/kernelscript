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

%{
  open Ast

  let make_pos () = 
    let pos = Parsing.symbol_start_pos () in
    { line = pos.pos_lnum; column = pos.pos_cnum - pos.pos_bol; filename = pos.pos_fname }
  
  (* Elegant helper to convert identifier string to map_type *)
  let string_to_map_type = function
    | "hash" -> Hash
    | "array" -> Array
    | "percpu_hash" -> Percpu_hash
    | "percpu_array" -> Percpu_array
    | "lru_hash" -> Lru_hash
    | unknown -> failwith ("Unknown map type: " ^ unknown)
%}

/* Token declarations */
%token <int * string option> INT
%token <string> STRING IDENTIFIER
%token <char> CHAR_LIT
%token <bool> BOOL_LIT
%token NULL NONE

/* Keywords */
%token FN EXTERN INCLUDE PIN TYPE STRUCT ENUM IMPL
%token U8 U16 U32 U64 I8 I16 I32 I64 BOOL CHAR VOID STR
%token IF ELSE FOR WHILE RETURN BREAK CONTINUE
%token VAR CONST CONFIG LOCAL
%token IN NEW DELETE TRY CATCH THROW DEFER MATCH DEFAULT
%token IMPORT FROM


/* Operators */
%token PLUS MINUS MULTIPLY DIVIDE MODULO
%token EQ NE LT LE GT GE AND OR NOT AMPERSAND
%token UMINUS  /* Virtual token for unary minus precedence */
%token PLUS_ASSIGN MINUS_ASSIGN MULTIPLY_ASSIGN DIVIDE_ASSIGN MODULO_ASSIGN


/* Punctuation */
%token LBRACE RBRACE LPAREN RPAREN LBRACKET RBRACKET
%token COMMA DOT COLON ARROW ASSIGN PIPE AT

/* Special */
%token EOF

/* Operator precedence (lowest to highest) */
%left OR
%left AND  
%left EQ NE
%left LT LE GT GE
%left PLUS MINUS
%left MULTIPLY DIVIDE MODULO
%right UMINUS /* Precedence for unary minus - higher than binary ops */
%left LBRACKET

/* Type declarations for non-terminals */
%type <Ast.ast> program
%type <Ast.declaration list> declarations
%type <Ast.declaration> declaration
%type <Ast.config_declaration> config_declaration
%type <Ast.config_field list> config_fields
%type <Ast.config_field> config_field
%type <Ast.attribute list> attribute_list
%type <Ast.attribute> attribute
%type <Ast.attributed_function> attributed_function_declaration
%type <Ast.map_declaration> map_declaration
%type <Ast.struct_def> struct_declaration
%type <(string * Ast.bpf_type) list> struct_fields
%type <string * Ast.bpf_type> struct_field
%type <Ast.type_def> enum_declaration
%type <Ast.type_def> type_alias_declaration
%type <(string * int option) list> enum_variants
%type <(string * int option) list> enum_variant_list
%type <string * int option> enum_variant
%type <int> enum_value
%type <Ast.map_type> map_type

%type <Ast.map_flag list> flag_expression
%type <Ast.map_flag> flag_item

%type <Ast.function_def> function_declaration
%type <Ast.extern_kfunc_declaration> extern_kfunc_declaration
%type <Ast.include_declaration> include_declaration
%type <Ast.return_type_spec option> function_return_type
%type <(string * Ast.bpf_type) list> parameter_list
%type <string * Ast.bpf_type> parameter
%type <Ast.bpf_type> bpf_type
%type <Ast.bpf_type> array_type
%type <Ast.bpf_type> function_type
%type <Ast.bpf_type> generic_type_with_size
%type <Ast.bpf_type> ringbuf_type
%type <Ast.bpf_type list> function_parameter_list
%type <Ast.bpf_type> function_parameter
%type <Ast.statement list> statement_list
%type <Ast.statement> statement
%type <Ast.statement> variable_declaration
%type <Ast.statement> const_declaration
%type <Ast.statement> assignment_or_expression_statement
%type <Ast.statement> compound_assignment_statement
%type <Ast.statement> compound_index_assignment_statement
%type <Ast.statement> field_assignment_statement
%type <Ast.statement> arrow_assignment_statement
%type <Ast.statement> index_assignment_statement
%type <Ast.statement> return_statement
%type <Ast.statement> if_statement
%type <Ast.statement> while_statement
%type <Ast.statement> for_statement
%type <Ast.statement> delete_statement
%type <Ast.statement> break_statement
%type <Ast.statement> continue_statement
%type <Ast.statement> try_statement
%type <Ast.statement> throw_statement
%type <Ast.statement> defer_statement
%type <Ast.catch_clause list> catch_clauses
%type <Ast.catch_clause> catch_clause
%type <Ast.catch_pattern> catch_pattern
%type <Ast.expr> expression
%type <Ast.expr> primary_expression
%type <Ast.expr> function_call
%type <Ast.expr> array_access
%type <Ast.expr> struct_literal
%type <Ast.expr> match_expression
%type <Ast.match_arm list> match_arms
%type <Ast.match_arm> match_arm
%type <Ast.match_pattern> match_pattern
%type <Ast.literal> literal
%type <Ast.array_init_style> array_init_expr
%type <Ast.expr * Ast.expr> range_expression
%type <Ast.expr list> argument_list
%type <Ast.literal list> literal_list
%type <(string * Ast.expr) list> struct_literal_fields
%type <string * Ast.expr> struct_literal_field
%type <Ast.global_variable_declaration> global_variable_declaration
%type <Ast.impl_block> impl_block_declaration
%type <Ast.impl_block_item list> impl_block_items
%type <Ast.impl_block_item> impl_block_item
%type <Ast.import_declaration> import_declaration
%type <string> field_name

/* Start symbol */
%start program

%%

/* Top-level program */
program:
  | declarations EOF { $1 }

declarations:
  | /* empty */ { [] }
  | declaration declarations { $1 :: $2 }

declaration:
  | config_declaration { ConfigDecl $1 }
  | attributed_function_declaration { AttributedFunction $1 }
  | function_declaration { GlobalFunction $1 }
  | extern_kfunc_declaration { ExternKfuncDecl $1 }
  | include_declaration { IncludeDecl $1 }
  | map_declaration { MapDecl $1 }
  | struct_declaration { StructDecl $1 }
  | enum_declaration { TypeDef $1 }
  | type_alias_declaration { TypeDef $1 }
  | global_variable_declaration { GlobalVarDecl $1 }
  | impl_block_declaration { ImplBlock $1 }
  | import_declaration { ImportDecl $1 }

/* Config declaration: config name { config_fields } */
config_declaration:
  | CONFIG IDENTIFIER LBRACE config_fields RBRACE
    { make_config_declaration $2 $4 (make_pos ()) }

config_fields:
  | /* empty */ { [] }
  | config_field COMMA config_fields { $1 :: $3 }
  | config_field { [$1] }

config_field:
  | IDENTIFIER COLON bpf_type ASSIGN literal
    { make_config_field $1 $3 (Some $5) (make_pos ()) }
  | IDENTIFIER COLON bpf_type
    { make_config_field $1 $3 None (make_pos ()) }

/* Attributed function declaration: @attribute [attribute...] fn name(params) -> return_type { body } */
attributed_function_declaration:
  | attribute_list function_declaration { make_attributed_function $1 $2 (make_pos ()) }

attribute_list:
  | attribute { [$1] }
  | attribute attribute_list { $1 :: $2 }

attribute:
  | AT IDENTIFIER { SimpleAttribute $2 }
  | AT IDENTIFIER LPAREN STRING RPAREN { AttributeWithArg ($2, $4) }

/* Function declaration: fn name(params) -> return_type { body } */
function_declaration:
  | FN IDENTIFIER LPAREN parameter_list RPAREN function_return_type LBRACE statement_list RBRACE
    { make_function $2 $4 $6 $8 (make_pos ()) }

/* Extern kfunc declaration: extern name(params) -> return_type; */
extern_kfunc_declaration:
  | EXTERN IDENTIFIER LPAREN parameter_list RPAREN ARROW bpf_type
    { make_extern_kfunc_declaration $2 $4 (Some $7) (make_pos ()) }
  | EXTERN IDENTIFIER LPAREN parameter_list RPAREN
    { make_extern_kfunc_declaration $2 $4 None (make_pos ()) }

/* Include declaration: include "file.ksh" */
include_declaration:
  | INCLUDE STRING
    { make_include_declaration $2 (make_pos ()) }

function_return_type:
  | /* empty */ { None }
  | ARROW bpf_type { Some (make_unnamed_return $2) }
  | ARROW IDENTIFIER COLON bpf_type { Some (make_named_return $2 $4) }

parameter_list:
  | /* empty */ { [] }
  | parameter { [$1] }
  | parameter COMMA parameter_list { $1 :: $3 }

parameter:
  | IDENTIFIER COLON bpf_type { ($1, $3) }

/* BPF Types */
bpf_type:
  | U8 { U8 }
  | U16 { U16 }
  | U32 { U32 }
  | U64 { U64 }
  | I8 { I8 }
  | I16 { I16 }
  | I32 { I32 }
  | I64 { I64 }
  | BOOL { Bool }
  | CHAR { Char }
  | VOID { Void }
  | STR LPAREN INT RPAREN { Str (fst $3) }
  | IDENTIFIER { UserType $1 }
  | array_type { $1 }
  | function_type { $1 }
  | MULTIPLY bpf_type { Pointer $2 }
  | map_type LT bpf_type COMMA bpf_type GT { Map ($3, $5, $1, 1024) }  (* Default size for non-sized maps *)
  | generic_type_with_size { $1 }
  | ringbuf_type { $1 }

/* Array types: type[size] */
array_type:
  | U8 LBRACKET INT RBRACKET { Array (U8, fst $3) }
| U16 LBRACKET INT RBRACKET { Array (U16, fst $3) }
| U32 LBRACKET INT RBRACKET { Array (U32, fst $3) }
| U64 LBRACKET INT RBRACKET { Array (U64, fst $3) }
| I8 LBRACKET INT RBRACKET { Array (I8, fst $3) }
| I16 LBRACKET INT RBRACKET { Array (I16, fst $3) }
| I32 LBRACKET INT RBRACKET { Array (I32, fst $3) }
| I64 LBRACKET INT RBRACKET { Array (I64, fst $3) }
| BOOL LBRACKET INT RBRACKET { Array (Bool, fst $3) }
| CHAR LBRACKET INT RBRACKET { Array (Char, fst $3) }
| IDENTIFIER LBRACKET INT RBRACKET { Array (UserType $1, fst $3) }

/* Function types: fn(param: type, ...) -> return_type */
function_type:
  | FN LPAREN function_parameter_list RPAREN ARROW bpf_type
    { Function ($3, $6) }

function_parameter_list:
  | /* empty */ { [] }
  | function_parameter { [$1] }
  | function_parameter COMMA function_parameter_list { $1 :: $3 }

function_parameter:
  | IDENTIFIER COLON bpf_type { $3 }  /* Named parameter: name: type */
  | bpf_type { $1 }                   /* Anonymous parameter: type */

/* Statements */
statement_list:
  | /* empty */ { [] }
  | statement statement_list { $1 :: $2 }

statement:
  | variable_declaration { $1 }
  | const_declaration { $1 }
  | field_assignment_statement { $1 }
  | arrow_assignment_statement { $1 }
  | index_assignment_statement { $1 }
  | compound_assignment_statement { $1 }
  | compound_index_assignment_statement { $1 }
  | assignment_or_expression_statement { $1 }
  | return_statement { $1 }
  | if_statement { $1 }
  | while_statement { $1 }
  | for_statement { $1 }
  | delete_statement { $1 }
  | break_statement { $1 }
  | continue_statement { $1 }
  | try_statement { $1 }
  | throw_statement { $1 }
  | defer_statement { $1 }

variable_declaration:
  | VAR IDENTIFIER ASSIGN expression
    { make_stmt (Declaration ($2, None, Some $4)) (make_pos ()) }
  | VAR IDENTIFIER COLON bpf_type ASSIGN expression
    { make_stmt (Declaration ($2, Some $4, Some $6)) (make_pos ()) }
  | VAR IDENTIFIER COLON bpf_type
    { make_stmt (Declaration ($2, Some $4, None)) (make_pos ()) }

const_declaration:
  | CONST IDENTIFIER ASSIGN expression
    { make_stmt (ConstDeclaration ($2, None, $4)) (make_pos ()) }
  | CONST IDENTIFIER COLON bpf_type ASSIGN expression
    { make_stmt (ConstDeclaration ($2, Some $4, $6)) (make_pos ()) }

assignment_or_expression_statement:
  | IDENTIFIER ASSIGN expression
    { make_stmt (Assignment ($1, $3)) (make_pos ()) }
  | expression { make_stmt (ExprStmt $1) (make_pos ()) }

compound_assignment_statement:
  | IDENTIFIER PLUS_ASSIGN expression
    { make_stmt (CompoundAssignment ($1, Add, $3)) (make_pos ()) }
  | IDENTIFIER MINUS_ASSIGN expression
    { make_stmt (CompoundAssignment ($1, Sub, $3)) (make_pos ()) }
  | IDENTIFIER MULTIPLY_ASSIGN expression
    { make_stmt (CompoundAssignment ($1, Mul, $3)) (make_pos ()) }
  | IDENTIFIER DIVIDE_ASSIGN expression
    { make_stmt (CompoundAssignment ($1, Div, $3)) (make_pos ()) }
  | IDENTIFIER MODULO_ASSIGN expression
    { make_stmt (CompoundAssignment ($1, Mod, $3)) (make_pos ()) }

field_assignment_statement:
  | primary_expression DOT IDENTIFIER ASSIGN expression
    { make_stmt (FieldAssignment ($1, $3, $5)) (make_pos ()) }

arrow_assignment_statement:
  | primary_expression ARROW IDENTIFIER ASSIGN expression
    { make_stmt (ArrowAssignment ($1, $3, $5)) (make_pos ()) }

index_assignment_statement:
  | expression LBRACKET expression RBRACKET ASSIGN expression
    { make_stmt (IndexAssignment ($1, $3, $6)) (make_pos ()) }

compound_index_assignment_statement:
  | expression LBRACKET expression RBRACKET PLUS_ASSIGN expression
    { make_stmt (CompoundIndexAssignment ($1, $3, Add, $6)) (make_pos ()) }
  | expression LBRACKET expression RBRACKET MINUS_ASSIGN expression
    { make_stmt (CompoundIndexAssignment ($1, $3, Sub, $6)) (make_pos ()) }
  | expression LBRACKET expression RBRACKET MULTIPLY_ASSIGN expression
    { make_stmt (CompoundIndexAssignment ($1, $3, Mul, $6)) (make_pos ()) }
  | expression LBRACKET expression RBRACKET DIVIDE_ASSIGN expression
    { make_stmt (CompoundIndexAssignment ($1, $3, Div, $6)) (make_pos ()) }
  | expression LBRACKET expression RBRACKET MODULO_ASSIGN expression
    { make_stmt (CompoundIndexAssignment ($1, $3, Mod, $6)) (make_pos ()) }

return_statement:
  | RETURN { make_stmt (Return None) (make_pos ()) }
  | RETURN expression { make_stmt (Return (Some $2)) (make_pos ()) }

if_statement:
  | IF LPAREN expression RPAREN LBRACE statement_list RBRACE
    { make_stmt (If ($3, $6, None)) (make_pos ()) }
  | IF LPAREN expression RPAREN LBRACE statement_list RBRACE ELSE LBRACE statement_list RBRACE
    { make_stmt (If ($3, $6, Some $10)) (make_pos ()) }
  | IF LPAREN expression RPAREN LBRACE statement_list RBRACE ELSE if_statement
    { make_stmt (If ($3, $6, Some [$9])) (make_pos ()) }

while_statement:
  | WHILE LPAREN expression RPAREN LBRACE statement_list RBRACE
    { make_stmt (While ($3, $6)) (make_pos ()) }

for_statement:
  | FOR LPAREN IDENTIFIER IN range_expression RPAREN LBRACE statement_list RBRACE
    { let (start_expr, end_expr) = $5 in
      make_stmt (For ($3, start_expr, end_expr, $8)) (make_pos ()) }

delete_statement:
  | DELETE expression LBRACKET expression RBRACKET
    { make_stmt (Delete (DeleteMapEntry ($2, $4))) (make_pos ()) }
  | DELETE expression
    { make_stmt (Delete (DeletePointer $2)) (make_pos ()) }

break_statement:
  | BREAK { make_stmt (Break) (make_pos ()) }

continue_statement:
  | CONTINUE { make_stmt (Continue) (make_pos ()) }

try_statement:
  | TRY LBRACE statement_list RBRACE catch_clauses
    { make_stmt (Try ($3, $5)) (make_pos ()) }

catch_clauses:
  | /* empty */ { [] }
  | catch_clause catch_clauses { $1 :: $2 }

catch_clause:
  | CATCH catch_pattern LBRACE statement_list RBRACE
    { { catch_pattern = $2; catch_body = $4; catch_pos = make_pos () } }

catch_pattern:
  | INT
    { IntPattern (fst $1) }
  | IDENTIFIER
    { if $1 = "_" then WildcardPattern else failwith ("Invalid catch pattern: " ^ $1) }

throw_statement:
  | THROW expression
    { make_stmt (Throw $2) (make_pos ()) }

defer_statement:
  | DEFER expression
    { make_stmt (Defer $2) (make_pos ()) }

/* Expressions - Conservative approach with precedence declarations */
expression:
  | primary_expression { $1 }
  | function_call { $1 }
  | array_access { $1 }
  | struct_literal { $1 }
  | match_expression { $1 }
  /* Binary operations - precedence handled by %left/%right declarations */
  | expression PLUS expression { make_expr (BinaryOp ($1, Add, $3)) (make_pos ()) }
  | expression MINUS expression { make_expr (BinaryOp ($1, Sub, $3)) (make_pos ()) }
  | expression MULTIPLY expression { make_expr (BinaryOp ($1, Mul, $3)) (make_pos ()) }
  | expression DIVIDE expression { make_expr (BinaryOp ($1, Div, $3)) (make_pos ()) }
  | expression MODULO expression { make_expr (BinaryOp ($1, Mod, $3)) (make_pos ()) }
  | expression EQ expression { make_expr (BinaryOp ($1, Eq, $3)) (make_pos ()) }
  | expression NE expression { make_expr (BinaryOp ($1, Ne, $3)) (make_pos ()) }
  | expression LT expression { make_expr (BinaryOp ($1, Lt, $3)) (make_pos ()) }
  | expression LE expression { make_expr (BinaryOp ($1, Le, $3)) (make_pos ()) }
  | expression GT expression { make_expr (BinaryOp ($1, Gt, $3)) (make_pos ()) }
  | expression GE expression { make_expr (BinaryOp ($1, Ge, $3)) (make_pos ()) }
  | expression AND expression { make_expr (BinaryOp ($1, And, $3)) (make_pos ()) }
  | expression OR expression { make_expr (BinaryOp ($1, Or, $3)) (make_pos ()) }
  /* Unary operations */
  | NOT expression %prec UMINUS { make_expr (UnaryOp (Not, $2)) (make_pos ()) }
  | MINUS expression %prec UMINUS { make_expr (UnaryOp (Neg, $2)) (make_pos ()) }
  | MULTIPLY expression %prec UMINUS { make_expr (UnaryOp (Deref, $2)) (make_pos ()) }
  | AMPERSAND expression %prec UMINUS { make_expr (UnaryOp (AddressOf, $2)) (make_pos ()) }

primary_expression:
  | literal { make_expr (Literal $1) (make_pos ()) }
  | IDENTIFIER { make_expr (Identifier $1) (make_pos ()) }
  | LPAREN expression RPAREN { $2 }
  | primary_expression DOT field_name { make_expr (FieldAccess ($1, $3)) (make_pos ()) }
  | primary_expression ARROW field_name { make_expr (ArrowAccess ($1, $3)) (make_pos ()) }
  | NEW bpf_type LPAREN RPAREN { make_expr (New $2) (make_pos ()) }
  | NEW bpf_type LPAREN expression RPAREN { make_expr (NewWithFlag ($2, $4)) (make_pos ()) }

function_call:
  | IDENTIFIER LPAREN argument_list RPAREN
    { make_expr (Call (make_expr (Identifier $1) (make_pos ()), $3)) (make_pos ()) }
  | primary_expression LPAREN argument_list RPAREN
    { make_expr (Call ($1, $3)) (make_pos ()) }



array_access:
  | expression LBRACKET expression RBRACKET { make_expr (ArrayAccess ($1, $3)) (make_pos ()) }

struct_literal:
  | IDENTIFIER LBRACE struct_literal_fields RBRACE
    { make_expr (StructLiteral ($1, $3)) (make_pos ()) }

literal:
  | INT { let (value, original) = $1 in IntLit (value, original) }
  | STRING { StringLit $1 }
  | CHAR_LIT { CharLit $1 }
  | BOOL_LIT { BoolLit $1 }
  | NULL { NullLit }
  | NONE { NoneLit }
  | LBRACKET array_init_expr RBRACKET { ArrayLit $2 }

array_init_expr:
  | /* empty */ { ZeroArray }                           (* [] - zero initialize *)
  | literal { FillArray $1 }                           (* [0] - fill with value *)
  | literal COMMA literal_list { ExplicitArray ($1 :: $3) }  (* [a,b,c] - explicit values *)

literal_list:
  | literal { [$1] }
  | literal COMMA literal_list { $1 :: $3 }

range_expression:
  | primary_expression DOT DOT primary_expression { ($1, $4) }

argument_list:
  | /* empty */ { [] }
  | expression { [$1] }
  | expression COMMA argument_list { $1 :: $3 }

struct_literal_fields:
  | struct_literal_field { [$1] }
  | struct_literal_field COMMA struct_literal_fields { $1 :: $3 }
  | struct_literal_field COMMA { [$1] }  /* Allow trailing comma */

struct_literal_field:
  | field_name COLON expression { ($1, $3) }

/* Map Declarations */
map_declaration:
  | VAR IDENTIFIER COLON map_type LT bpf_type COMMA bpf_type GT LPAREN INT RPAREN
    { let config = make_map_config (fst $11) ~flags:[] () in
      make_map_declaration $2 $6 $8 $4 config true ~is_pinned:false (make_pos ()) }
  | PIN VAR IDENTIFIER COLON map_type LT bpf_type COMMA bpf_type GT LPAREN INT RPAREN
    { let config = make_map_config (fst $12) ~flags:[] () in
      make_map_declaration $3 $7 $9 $5 config true ~is_pinned:true (make_pos ()) }
  | AT IDENTIFIER LPAREN flag_expression RPAREN VAR IDENTIFIER COLON map_type LT bpf_type COMMA bpf_type GT LPAREN INT RPAREN
    { if $2 <> "flags" then failwith ("Unknown map attribute: " ^ $2);
      let config = make_map_config (fst $16) ~flags:$4 () in
      make_map_declaration $7 $11 $13 $9 config true ~is_pinned:false (make_pos ()) }
  | AT IDENTIFIER LPAREN flag_expression RPAREN PIN VAR IDENTIFIER COLON map_type LT bpf_type COMMA bpf_type GT LPAREN INT RPAREN
    { if $2 <> "flags" then failwith ("Unknown map attribute: " ^ $2);
      let config = make_map_config (fst $17) ~flags:$4 () in
      make_map_declaration $8 $12 $14 $10 config true ~is_pinned:true (make_pos ()) }

map_type:
  | IDENTIFIER { string_to_map_type $1 }

/* Generic types with size parameters */
generic_type_with_size:
  | IDENTIFIER LT bpf_type COMMA bpf_type GT LPAREN INT RPAREN { 
        (* Map types with explicit size *)
        Map ($3, $5, string_to_map_type $1, fst $8)
    }

/* Ring buffer types: ringbuf<Event_Type>(size) */
ringbuf_type:
  | IDENTIFIER LT bpf_type GT LPAREN INT RPAREN {
      if $1 = "ringbuf" then
        Ringbuf ($3, fst $6)
      else
        failwith ("Expected 'ringbuf', got: " ^ $1)
    }

flag_expression:
  | flag_item { [$1] }
  | flag_item PIPE flag_expression { $1 :: $3 }

flag_item:
  | IDENTIFIER {
      match $1 with
      | "no_prealloc" -> NoPrealloc
      | "no_common_lru" -> NoCommonLru
      | "rdonly" -> Rdonly
      | "wronly" -> Wronly
      | "clone" -> Clone
      | unknown -> failwith ("Unknown map flag: " ^ unknown)
    }
  | IDENTIFIER LPAREN INT RPAREN {
      match $1 with
      | "numa_node" -> NumaNode (fst $3)
      | unknown -> failwith ("Unknown parameterized map flag: " ^ unknown)
    }

struct_declaration:
  | STRUCT IDENTIFIER LBRACE struct_fields RBRACE
    { make_struct_def $2 $4 (make_pos ()) }
  | attribute_list STRUCT IDENTIFIER LBRACE struct_fields RBRACE
    { make_struct_def ~attributes:$1 $3 $5 (make_pos ()) }

struct_fields:
  | /* empty */ { [] }
  | struct_field COMMA struct_fields { $1 :: $3 }
  | struct_field { [$1] }

struct_field:
  | field_name COLON bpf_type { ($1, $3) }


/* Enum declaration: enum name { variants } - Fixed to eliminate unused production */
enum_declaration:
  | ENUM IDENTIFIER LBRACE enum_variants RBRACE
    { make_enum_def $2 $4 }

enum_variants:
  | /* empty */ { [] }
  | enum_variant_list { List.rev $1 }

enum_variant_list:
  | enum_variant { [$1] }
  | enum_variant_list COMMA enum_variant { $3 :: $1 }
  | enum_variant_list COMMA { $1 }  /* Allow trailing comma */

enum_variant:
  | IDENTIFIER { ($1, None) }  /* Auto-assigned value */
  | IDENTIFIER ASSIGN enum_value { ($1, Some $3) }  /* Explicit value */

/* Enum values can be positive or negative integers */
enum_value:
  | INT { fst $1 }  /* Positive integer */
  | MINUS INT { -(fst $2) }  /* Negative integer */

/* Type alias declaration: type name = type */
type_alias_declaration:
  | TYPE IDENTIFIER ASSIGN bpf_type
    { make_type_alias $2 $4 }

/* Global variable declaration: [pin] [local] var name: type = value */
global_variable_declaration:
  | VAR IDENTIFIER COLON bpf_type ASSIGN expression
    { make_global_var_decl $2 (Some $4) (Some $6) (make_pos ()) () }
  | VAR IDENTIFIER COLON bpf_type
    { make_global_var_decl $2 (Some $4) None (make_pos ()) () }
  | VAR IDENTIFIER ASSIGN expression
    { make_global_var_decl $2 None (Some $4) (make_pos ()) () }
  | LOCAL VAR IDENTIFIER COLON bpf_type ASSIGN expression
    { make_global_var_decl $3 (Some $5) (Some $7) (make_pos ()) ~is_local:true () }
  | LOCAL VAR IDENTIFIER COLON bpf_type
    { make_global_var_decl $3 (Some $5) None (make_pos ()) ~is_local:true () }
  | LOCAL VAR IDENTIFIER ASSIGN expression
    { make_global_var_decl $3 None (Some $5) (make_pos ()) ~is_local:true () }
  | PIN VAR IDENTIFIER COLON bpf_type ASSIGN expression
    { make_global_var_decl $3 (Some $5) (Some $7) (make_pos ()) ~is_pinned:true () }
  | PIN VAR IDENTIFIER COLON bpf_type
    { make_global_var_decl $3 (Some $5) None (make_pos ()) ~is_pinned:true () }
  | PIN VAR IDENTIFIER ASSIGN expression
    { make_global_var_decl $3 None (Some $5) (make_pos ()) ~is_pinned:true () }
  | PIN LOCAL VAR IDENTIFIER COLON bpf_type ASSIGN expression
    { make_global_var_decl $4 (Some $6) (Some $8) (make_pos ()) ~is_local:true ~is_pinned:true () }
  | PIN LOCAL VAR IDENTIFIER COLON bpf_type
    { make_global_var_decl $4 (Some $6) None (make_pos ()) ~is_local:true ~is_pinned:true () }
  | PIN LOCAL VAR IDENTIFIER ASSIGN expression
    { make_global_var_decl $4 None (Some $6) (make_pos ()) ~is_local:true ~is_pinned:true () }

/* Match expressions: match (expr) { pattern: expr, ... } */
match_expression:
  | MATCH LPAREN expression RPAREN LBRACE match_arms RBRACE
    { make_expr (Match ($3, $6)) (make_pos ()) }

match_arms:
  | match_arm { [$1] }
  | match_arm COMMA match_arms { $1 :: $3 }
  | match_arm COMMA { [$1] }  /* Allow trailing comma */

match_arm:
  | match_pattern COLON expression
    { make_match_arm_expr $1 $3 (make_pos ()) }
  | match_pattern COLON LBRACE statement_list RBRACE
    { make_match_arm_block $1 $4 (make_pos ()) }

match_pattern:
  | INT { make_constant_pattern (IntLit (fst $1, snd $1)) }
  | STRING { make_constant_pattern (StringLit $1) }
  | CHAR_LIT { make_constant_pattern (CharLit $1) }
  | BOOL_LIT { make_constant_pattern (BoolLit $1) }
  | IDENTIFIER { make_identifier_pattern $1 }
  | DEFAULT { make_default_pattern () }

/* Impl block declaration: @struct_ops("name") impl name { items } */
impl_block_declaration:
  | attribute_list IMPL IDENTIFIER LBRACE impl_block_items RBRACE
    { make_impl_block $3 $1 $5 (make_pos ()) }

impl_block_items:
  | /* empty */ { [] }
  | impl_block_item impl_block_items { $1 :: $2 }

impl_block_item:
  | function_declaration { ImplFunction $1 }
  | IDENTIFIER COLON expression COMMA { ImplStaticField ($1, $3) }

/* Import declaration: import module_name from "file_path" */
import_declaration:
  | IMPORT IDENTIFIER FROM STRING
    { make_import_declaration $2 $4 (make_pos ()) }

/* Field name: allows both identifiers and specific keywords as field names */
field_name:
  | IDENTIFIER { $1 }
  | TYPE { "type" }

%% 