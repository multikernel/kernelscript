%{
  open Ast

  let make_pos () = 
    let pos = Parsing.symbol_start_pos () in
    { line = pos.pos_lnum; column = pos.pos_cnum - pos.pos_bol; filename = pos.pos_fname }
%}

/* Token declarations */
%token <int> INT
%token <string> STRING IDENTIFIER
%token <char> CHAR_LIT
%token <bool> BOOL_LIT

/* Keywords */
%token PROGRAM FN MAP TYPE STRUCT ENUM
%token U8 U16 U32 U64 I8 I16 I32 I64 BOOL CHAR
%token IF ELSE FOR WHILE RETURN BREAK CONTINUE
%token LET MUT PUB PRIV CONFIG USERSPACE
%token IN

/* Operators */
%token PLUS MINUS MULTIPLY DIVIDE MODULO
%token EQ NE LT LE GT GE AND OR NOT

/* Punctuation */
%token LBRACE RBRACE LPAREN RPAREN LBRACKET RBRACKET
%token SEMICOLON COMMA DOT COLON ARROW ASSIGN PIPE

/* Special */
%token EOF

/* Operator precedence (lowest to highest) */
%left PIPE      /* Flag combination */
%left OR
%left AND
%left EQ NE
%left LT LE GT GE
%left PLUS MINUS
%left MULTIPLY DIVIDE MODULO
%right NOT NEG  /* Unary operators */
%left DOT       /* Field access */
%left LBRACKET  /* Array access */

/* Type declarations for non-terminals */
%type <Ast.ast> program
%type <Ast.declaration list> declarations
%type <Ast.declaration> declaration
%type <Ast.program_def> program_declaration
%type <Ast.program_type> program_type
%type <Ast.map_declaration> map_declaration
%type <Ast.map_declaration> local_map_declaration
%type <Ast.function_def list * Ast.map_declaration list> program_items
%type <[`Function of Ast.function_def | `Map of Ast.map_declaration]> program_item
%type <Ast.userspace_block> userspace_declaration
%type <Ast.function_def list * Ast.struct_def list * Ast.userspace_config list> userspace_body
%type <Ast.function_def list * Ast.struct_def list * Ast.userspace_config list> userspace_item
%type <Ast.struct_def> struct_declaration
%type <(string * Ast.bpf_type) list> struct_fields
%type <string * Ast.bpf_type> struct_field
%type <Ast.userspace_config> userspace_config

%type <Ast.userspace_config_item list> userspace_config_items
%type <Ast.userspace_config_item> userspace_config_item
%type <Ast.map_type> map_type

%type <Ast.map_attribute list> map_attributes
%type <Ast.map_attribute> map_attribute
%type <Ast.map_flag list> flag_expression
%type <Ast.map_flag> flag_item

%type <Ast.function_def> function_declaration
%type <Ast.bpf_type option> function_return_type
%type <(string * Ast.bpf_type) list> parameter_list
%type <string * Ast.bpf_type> parameter
%type <Ast.bpf_type> bpf_type
%type <Ast.statement list> statement_list
%type <Ast.statement> statement
%type <Ast.statement> expression_statement
%type <Ast.statement> variable_declaration
%type <Ast.statement> assignment_statement
%type <Ast.statement> index_assignment_statement
%type <Ast.statement> return_statement
%type <Ast.statement> if_statement
%type <Ast.statement> while_statement
%type <Ast.statement> for_statement
%type <Ast.expr> expression
%type <Ast.expr> primary_expression
%type <Ast.literal> literal
%type <Ast.expr> binary_expression
%type <Ast.expr> unary_expression
%type <Ast.expr> function_call
%type <Ast.expr list> argument_list
%type <Ast.expr> field_access
%type <Ast.expr> array_access

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
  | program_declaration { Program $1 }
  | function_declaration { GlobalFunction $1 }
  | map_declaration { MapDecl $1 }
  | userspace_declaration { Userspace $1 }

/* Program declaration: program name : type { program_items } */
program_declaration:
  | PROGRAM IDENTIFIER COLON program_type LBRACE program_items RBRACE
    { let functions, maps = $6 in
      make_program_with_maps $2 $4 functions maps (make_pos ()) }

program_type:
  | IDENTIFIER { 
      match $1 with
      | "xdp" -> Xdp
      | "tc" -> Tc  
      | "kprobe" -> Kprobe
      | "uprobe" -> Uprobe
      | "tracepoint" -> Tracepoint
      | "lsm" -> Lsm
      | unknown -> failwith ("Unknown program type: " ^ unknown)
    }

program_items:
  | /* empty */ { ([], []) }
  | program_item program_items { 
      let functions, maps = $2 in
      match $1 with
      | `Function func -> (func :: functions, maps)
      | `Map map -> (functions, map :: maps)
    }

program_item:
  | function_declaration { `Function $1 }
  | local_map_declaration { `Map $1 }

/* Top-level userspace declaration: userspace { userspace_body } */
userspace_declaration:
  | USERSPACE LBRACE userspace_body RBRACE
    { let functions, structs, configs = $3 in
      make_userspace_block functions structs configs (make_pos ()) }

/* Function declaration: fn name(params) -> return_type { body } */
function_declaration:
  | FN IDENTIFIER LPAREN parameter_list RPAREN function_return_type LBRACE statement_list RBRACE
    { make_function $2 $4 $6 $8 (make_pos ()) }

function_return_type:
  | /* empty */ { None }
  | ARROW bpf_type { Some $2 }

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
  | IDENTIFIER { UserType $1 }
  | LBRACKET bpf_type SEMICOLON INT RBRACKET { Array ($2, $4) }
  | MULTIPLY bpf_type { Pointer $2 }
  | map_type LT bpf_type COMMA bpf_type GT { Map ($3, $5, $1) }

/* Statements */
statement_list:
  | /* empty */ { [] }
  | statement statement_list { $1 :: $2 }

statement:
  | expression_statement { $1 }
  | variable_declaration { $1 }
  | assignment_statement { $1 }
  | index_assignment_statement { $1 }
  | return_statement { $1 }
  | if_statement { $1 }
  | while_statement { $1 }
  | for_statement { $1 }

expression_statement:
  | expression SEMICOLON { make_stmt (ExprStmt $1) (make_pos ()) }

variable_declaration:
  | LET IDENTIFIER ASSIGN expression SEMICOLON
    { make_stmt (Declaration ($2, None, $4)) (make_pos ()) }
  | LET IDENTIFIER COLON bpf_type ASSIGN expression SEMICOLON
    { make_stmt (Declaration ($2, Some $4, $6)) (make_pos ()) }

assignment_statement:
  | IDENTIFIER ASSIGN expression SEMICOLON
    { make_stmt (Assignment ($1, $3)) (make_pos ()) }

index_assignment_statement:
  | expression LBRACKET expression RBRACKET ASSIGN expression SEMICOLON
    { make_stmt (IndexAssignment ($1, $3, $6)) (make_pos ()) }

return_statement:
  | RETURN SEMICOLON { make_stmt (Return None) (make_pos ()) }
  | RETURN expression SEMICOLON { make_stmt (Return (Some $2)) (make_pos ()) }

if_statement:
  | IF expression LBRACE statement_list RBRACE
    { make_stmt (If ($2, $4, None)) (make_pos ()) }
  | IF expression LBRACE statement_list RBRACE ELSE LBRACE statement_list RBRACE
    { make_stmt (If ($2, $4, Some $8)) (make_pos ()) }
  | IF expression LBRACE statement_list RBRACE ELSE if_statement
    { make_stmt (If ($2, $4, Some [$7])) (make_pos ()) }

while_statement:
  | WHILE expression LBRACE statement_list RBRACE
    { make_stmt (While ($2, $4)) (make_pos ()) }

for_statement:
  | FOR IDENTIFIER IN expression DOT DOT expression LBRACE statement_list RBRACE
    { make_stmt (For ($2, $4, $7, $9)) (make_pos ()) }

/* Expressions */
expression:
  | primary_expression { $1 }
  | binary_expression { $1 }
  | unary_expression { $1 }
  | function_call { $1 }
  | field_access { $1 }
  | array_access { $1 }

primary_expression:
  | literal { make_expr (Literal $1) (make_pos ()) }
  | IDENTIFIER { make_expr (Identifier $1) (make_pos ()) }
  | LPAREN expression RPAREN { $2 }

literal:
  | INT { IntLit $1 }
  | STRING { StringLit $1 }
  | CHAR_LIT { CharLit $1 }
  | BOOL_LIT { BoolLit $1 }

binary_expression:
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

unary_expression:
  | NOT expression %prec NOT { make_expr (UnaryOp (Not, $2)) (make_pos ()) }
  | MINUS expression %prec NEG { make_expr (UnaryOp (Neg, $2)) (make_pos ()) }

function_call:
  | IDENTIFIER LPAREN argument_list RPAREN
    { make_expr (FunctionCall ($1, $3)) (make_pos ()) }

argument_list:
  | /* empty */ { [] }
  | expression { [$1] }
  | expression COMMA argument_list { $1 :: $3 }

field_access:
  | expression DOT IDENTIFIER { make_expr (FieldAccess ($1, $3)) (make_pos ()) }

array_access:
  | expression LBRACKET expression RBRACKET { make_expr (ArrayAccess ($1, $3)) (make_pos ()) }

/* Map Declarations */
map_declaration:
  | MAP LT bpf_type COMMA bpf_type GT IDENTIFIER COLON map_type LPAREN INT RPAREN SEMICOLON
    { let config = make_map_config $11 [] in
      make_map_declaration $7 $3 $5 $9 config true (make_pos ()) }
  | MAP LT bpf_type COMMA bpf_type GT IDENTIFIER COLON map_type LPAREN INT RPAREN LBRACE map_attributes RBRACE SEMICOLON
    { let config = make_map_config $11 $14 in
      make_map_declaration $7 $3 $5 $9 config true (make_pos ()) }

/* Local Map Declarations (inside program blocks) */
local_map_declaration:
  | MAP LT bpf_type COMMA bpf_type GT IDENTIFIER COLON map_type LPAREN INT RPAREN SEMICOLON
    { let config = make_map_config $11 [] in
      make_map_declaration $7 $3 $5 $9 config false (make_pos ()) }
  | MAP LT bpf_type COMMA bpf_type GT IDENTIFIER COLON map_type LPAREN INT RPAREN LBRACE map_attributes RBRACE SEMICOLON
    { let config = make_map_config $11 $14 in
      make_map_declaration $7 $3 $5 $9 config false (make_pos ()) }

map_type:
  | IDENTIFIER { 
      match $1 with
      | "HashMap" -> HashMap
      | "Array" -> Array
      | "PercpuHash" -> PercpuHash
      | "PercpuArray" -> PercpuArray
      | "LruHash" -> LruHash
      | "RingBuffer" -> RingBuffer
      | "PerfEvent" -> PerfEvent
      | unknown -> failwith ("Unknown map type: " ^ unknown)
    }

map_attributes:
  | /* empty */ { [] }
  | map_attribute { [$1] }
  | map_attribute COMMA map_attributes { $1 :: $3 }

map_attribute:
  | IDENTIFIER COLON STRING { 
      match $1 with
      | "pinned" -> Pinned $3
      | "max_entries" -> failwith "max_entries should be specified in map type declaration (e.g., HashMap(1024)), not in attributes block"
      | unknown -> failwith ("Unknown map attribute: " ^ unknown)
    }
  | IDENTIFIER COLON INT { 
      match $1 with
      | "max_entries" -> failwith "max_entries should be specified in map type declaration (e.g., HashMap(1024)), not in attributes block"
      | unknown -> failwith ("Unknown map attribute: " ^ unknown)
    }
  | IDENTIFIER COLON flag_expression {
      match $1 with
      | "flags" -> FlagsAttr $3
      | unknown -> failwith ("Unknown map attribute: " ^ unknown)
    }
  | IDENTIFIER { 
      match $1 with
      | unknown -> failwith ("Unknown map attribute: " ^ unknown)
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
      | "numa_node" -> NumaNode $3
      | unknown -> failwith ("Unknown parameterized map flag: " ^ unknown)
    }

/* Userspace blocks */

userspace_body:
  | /* empty */ { ([], [], []) }
  | userspace_item userspace_body
    { let funcs1, structs1, configs1 = $1 in
      let funcs2, structs2, configs2 = $2 in
      (funcs1 @ funcs2, structs1 @ structs2, configs1 @ configs2) }

userspace_item:
  | function_declaration { ([$1], [], []) }
  | struct_declaration { ([], [$1], []) }
  | userspace_config { ([], [], [$1]) }

struct_declaration:
  | STRUCT IDENTIFIER LBRACE struct_fields RBRACE
    { make_struct_def $2 $4 (make_pos ()) }

struct_fields:
  | /* empty */ { [] }
  | struct_field COMMA struct_fields { $1 :: $3 }
  | struct_field { [$1] }

struct_field:
  | IDENTIFIER COLON bpf_type { ($1, $3) }

userspace_config:
  | IDENTIFIER LBRACE userspace_config_items RBRACE
    { CustomConfig ($1, $3) }



userspace_config_items:
  | /* empty */ { [] }
  | userspace_config_item userspace_config_items { $1 :: $2 }

userspace_config_item:
  | IDENTIFIER COLON literal COMMA { make_userspace_config_item $1 $3 }

%% 