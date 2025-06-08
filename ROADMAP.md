# KernelScript OCaml Implementation Roadmap

## Project Overview

This roadmap outlines the development plan for implementing KernelScript, an eBPF programming language with integrated userspace support, in OCaml. The implementation follows a 6-phase approach over approximately 20 weeks.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Lexer/Parser  │───▶│  Type Checker   │───▶│  Code Generator │
│   (Menhir)      │    │   (Inference)   │    │   (eBPF/User)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AST Types     │    │  Symbol Tables  │    │  Standard Lib   │
│   (Core Lang)   │    │   (Scoping)     │    │   (Built-ins)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## Phase 1: Core Foundation (Weeks 1-3)

### Goals
Establish lexical analysis, basic AST, and simple parsing infrastructure.

### Milestone 1.1: Lexical Analysis (Week 1)
**Deliverables:**
- `src/tokens.ml` - Complete token type definitions
- `src/lexer.mll` - Menhir lexer implementation
- Support for all KernelScript tokens (keywords, operators, literals)
- Comment and whitespace handling

**Key Components:**
```ocaml
type token =
  | PROGRAM | FN | MAP | TYPE | STRUCT | ENUM
  | XDP | TC | KPROBE | UPROBE | TRACEPOINT | LSM
  | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 | BOOL
  | INT of int | STRING of string | CHAR of char | BOOL_LIT of bool
  | IDENTIFIER of string
  | LBRACE | RBRACE | LPAREN | RPAREN | LBRACKET | RBRACKET
  | SEMICOLON | COMMA | DOT | COLON | ARROW | ASSIGN
  | PLUS | MINUS | MULTIPLY | DIVIDE | MODULO
  | EQ | NE | LT | LE | GT | GE | AND | OR | NOT
  | IF | ELSE | FOR | WHILE | RETURN | BREAK | CONTINUE
  | LET | MUT | PUB | PRIV | CONFIG | USERSPACE
  | EOF
```

**Unit Tests:**
```ocaml
let test_keywords () =
  assert_equal [PROGRAM; FN; MAP] (tokenize "program fn map")

let test_literals () =
  assert_equal [INT 42; STRING "hello"; BOOL_LIT true] 
    (tokenize "42 \"hello\" true")

let test_hex_literals () =
  assert_equal [INT 255] (tokenize "0xFF")
```

### Milestone 1.2: Basic AST Structure (Week 2)
**Deliverables:**
- `src/ast.ml` - Core AST type definitions
- Position tracking for error reporting
- Pretty-printing support for debugging

**Key Types:**
```ocaml
type position = { line: int; column: int; filename: string }

type program_type = 
  | Xdp | Tc | Kprobe | Uprobe | Tracepoint | Lsm | CgroupSkb

type bpf_type =
  | U8 | U16 | U32 | U64 | I8 | I16 | I32 | I64 | Bool | Char
  | Array of bpf_type * int
  | Pointer of bpf_type
  | UserType of string

type literal =
  | IntLit of int | StringLit of string | CharLit of char | BoolLit of bool

type expr = {
  expr_desc: expr_desc;
  expr_pos: position;
  expr_type: bpf_type option; (* filled by type checker *)
}

and expr_desc =
  | Literal of literal
  | Identifier of string
  | FunctionCall of string * expr list
  | ArrayAccess of expr * expr
  | FieldAccess of expr * string
  | BinaryOp of expr * binary_op * expr
  | UnaryOp of unary_op * expr

type statement = {
  stmt_desc: stmt_desc;
  stmt_pos: position;
}

and stmt_desc =
  | ExprStmt of expr
  | Assignment of string * expr
  | Declaration of string * bpf_type option * expr
  | Return of expr option
  | If of expr * statement list * statement list option
  | For of string * expr * expr * statement list
  | While of expr * statement list
```

### Milestone 1.3: Simple Parser (Week 3)
**Deliverables:**
- `src/parser.mly` - Menhir parser for basic constructs
- Parse simple programs with main functions
- Basic expression and statement parsing
- Error recovery and reporting

**Unit Tests:**
```ocaml
let test_simple_program () =
  let code = {|
    program test : xdp {
      fn main(ctx: XdpContext) -> XdpAction {
        return XdpAction::Pass;
      }
    }
  |} in
  let ast = parse_string code in
  match ast with
  | [Program { name = "test"; prog_type = Xdp; _ }] -> ()
  | _ -> assert_failure "Failed to parse simple program"

let test_expressions () =
  let code = "x + y * 2" in
  let expr = parse_expression code in
  match expr.expr_desc with
  | BinaryOp (_, Plus, _) -> ()
  | _ -> assert_failure "Operator precedence error"
```

---

## Phase 2: Type System (Weeks 4-6)

### Goals
Implement complete type checking, inference, and symbol resolution.

### Milestone 2.1: Extended Type Definitions (Week 4)
**Deliverables:**
- Complete type system in AST
- Struct, enum, and type alias support
- Option and Result type handling
- Built-in context types (XdpContext, KprobeContext, etc.)

**Extended Types:**
```ocaml
type type_def =
  | StructDef of string * (string * bpf_type) list
  | EnumDef of string * (string * int option) list
  | TypeAlias of string * bpf_type

type bpf_type =
  | (* primitive types *)
  | Struct of string
  | Enum of string  
  | Option of bpf_type
  | Result of bpf_type * bpf_type
  | Function of bpf_type list * bpf_type
  | Map of bpf_type * bpf_type * map_type

type map_type =
  | HashMap | Array | PercpuHash | PercpuArray
  | LruHash | RingBuffer | PerfEvent
```

### Milestone 2.2: Type Checker Implementation (Week 5)
**Deliverables:**
- `src/type_checker.ml` - Complete type inference engine
- Type unification algorithm
- Context-sensitive typing
- Built-in function signatures

**Key Functions:**
```ocaml
val type_check_program : program -> typed_program
val type_check_expression : context -> expr -> typed_expr
val unify_types : bpf_type -> bpf_type -> bpf_type option
val check_function_call : string -> bpf_type list -> bpf_type option
```

**Unit Tests:**
```ocaml
let test_type_inference () =
  let code = {|
    let x = 42;
    let y = x + 10;
  |} in
  let typed_ast = type_check_statements code in
  assert_type U32 (get_var_type typed_ast "x");
  assert_type U32 (get_var_type typed_ast "y")

let test_context_types () =
  let code = {|
    fn main(ctx: XdpContext) -> XdpAction {
      let packet = ctx.packet();
      return XdpAction::Pass;
    }
  |} in
  assert_no_type_errors (type_check_function code)
```

### Milestone 2.3: Symbol Tables and Scoping (Week 6)
**Deliverables:**
- `src/symbol_table.ml` - Hierarchical symbol resolution
- Global vs local scope management
- Map visibility rules
- Function and type name resolution

**Unit Tests:**
```ocaml
let test_global_local_scoping () =
  let code = {|
    map<u32, u64> global_counter : array(256);
    
    program test : xdp {
      map<u32, LocalData> local_map : hash_map(100);
      
      fn main(ctx: XdpContext) -> XdpAction {
        global_counter[0] = 1;
        local_map.insert(1, LocalData::new());
        return XdpAction::Pass;
      }
    }
  |} in
  let symbol_table = build_symbol_table code in
  assert (is_global_map symbol_table "global_counter");
  assert (is_local_map symbol_table "test" "local_map")
```

---

## Phase 3: Maps and Memory Management (Weeks 7-9)

### Goals
Implement eBPF map handling, memory safety, and bounds checking.

### Milestone 3.1: Map Type System (Week 7)
**Deliverables:**
- `src/maps.ml` - eBPF map type definitions
- Map configuration parsing
- Pin path and attribute handling
- Global vs local map semantics

**Map Types:**
```ocaml
type map_config = {
  max_entries: int;
  key_size: int option;
  value_size: int option;
  attributes: map_attribute list;
}

type map_attribute =
  | Pinned of string
  | ReadOnly | WriteOnly | UserspaceWritable
  | Permissions of string

type map_declaration = {
  name: string;
  key_type: bpf_type;
  value_type: bpf_type;
  map_type: map_type;
  config: map_config;
  is_global: bool;
}
```

### Milestone 3.2: Memory Safety Analysis (Week 8)
**Deliverables:**
- `src/safety_checker.ml` - Bounds checking analysis
- Stack usage tracking
- Pointer safety verification
- Automatic map access validation

**Unit Tests:**
```ocaml
let test_bounds_checking () =
  let code = {|
    let arr: [u32; 10] = [0; 10];
    arr[5] = 42;  // OK
    arr[15] = 42; // Should error
  |} in
  assert_raises (Bounds_error _) (fun () -> safety_check code)

let test_stack_usage () =
  let code = {|
    fn large_function() {
      let buffer: [u8; 400] = [0; 400];
      process_buffer(buffer);
    }
  |} in
  let analysis = analyze_stack_usage code in
  assert (analysis.max_stack_usage <= 512)
```

### Milestone 3.3: Map Operation Semantics (Week 9)
**Deliverables:**
- Map access pattern analysis
- Concurrent access safety
- Map method implementations
- Global map sharing validation

---

## Phase 4: Control Flow and Functions (Weeks 10-13)

### Goals
Complete statement handling, function calls, control flow analysis, and introduce IR.

### Milestone 4.1: Expression Evaluation (Week 10)
**Deliverables:**
- `src/evaluator.ml` - Expression evaluation logic
- Operator precedence and associativity
- Function call resolution
- Built-in function implementations

### Milestone 4.2: Intermediate Representation (Week 11)
**Deliverables:**
- `src/ir.ml` - IR type definitions and data structures
- `src/ir_generator.ml` - AST to IR lowering
- Simplified expression and statement representation
- Built-in function expansion and normalization
- Control flow graph construction

**Key IR Components:**
```ocaml
(* Program-level IR *)
type ir_program = {
  name: string;
  program_type: program_type;
  global_maps: ir_map_def list;
  local_maps: ir_map_def list;
  functions: ir_function list;
  main_function: ir_function;
  userspace_bindings: ir_userspace_binding list;
}

(* Enhanced type system for IR *)
type ir_type = 
  | IRU8 | IRU16 | IRU32 | IRU64 | IRBool | IRChar
  | IRPointer of ir_type * bounds_info
  | IRArray of ir_type * int * bounds_info
  | IRStruct of string * (string * ir_type) list
  | IREnum of string * (string * int) list
  | IROption of ir_type
  | IRResult of ir_type * ir_type
  | IRContext of context_type
  | IRAction of action_type

and context_type = 
  | XdpCtx | TcCtx | KprobeCtx | UpprobeCtx | TracepointCtx | LsmCtx

and action_type =
  | XdpActionType | TcActionType | GenericActionType

and bounds_info = {
  min_size: int option;
  max_size: int option;
  alignment: int;
  nullable: bool;
}

(* Enhanced map representation *)
type ir_map_def = {
  name: string;
  key_type: ir_type;
  value_type: ir_type;
  map_type: ir_map_type;
  max_entries: int;
  attributes: ir_map_attr list;
  is_global: bool;
  pin_path: string option;
}

and ir_map_type =
  | IRHashMap | IRArray | IRPercpuHash | IRPercpuArray
  | IRLruHash | IRRingBuffer | IRPerfEvent | IRDevMap

and ir_map_attr =
  | ReadOnly | WriteOnly | UserspaceWritable
  | Permissions of string

(* Values with safety information *)
type ir_value = {
  value_desc: ir_value_desc;
  value_type: ir_type;
  stack_offset: int option; (* for stack variables *)
  bounds_checked: bool;
}

and ir_value_desc =
  | IRLiteral of literal
  | IRVariable of string
  | IRRegister of int
  | IRContextField of context_type * string
  | IRMapRef of string

(* Instructions with verification hints *)
type ir_instruction = {
  instr_desc: ir_instr_desc;
  stack_usage: int;
  bounds_checks: bounds_check list;
  verifier_hints: verifier_hint list;
}

and ir_instr_desc =
  | IRAssign of ir_value * ir_expr
  | IRCall of string * ir_value list * ir_value option
  | IRMapLoad of ir_value * ir_value * ir_value * map_load_type
  | IRMapStore of ir_value * ir_value * ir_value * map_store_type
  | IRMapDelete of ir_value * ir_value
  | IRContextAccess of ir_value * context_access_type
  | IRBoundsCheck of ir_value * int * int (* value, min, max *)
  | IRJump of string
  | IRCondJump of ir_value * string * string
  | IRReturn of ir_value option

and map_load_type = Direct | Lookup | Peek
and map_store_type = Direct | Update | Push
and context_access_type = PacketData | PacketEnd | DataMeta | IngressIfindex

and bounds_check = {
  value: ir_value;
  min_bound: int;
  max_bound: int;
  check_type: bounds_check_type;
}

and bounds_check_type = ArrayAccess | PointerDeref | StackAccess

and verifier_hint =
  | LoopBound of int
  | StackUsage of int
  | NoRecursion
  | BoundsChecked

(* Enhanced basic blocks *)
type ir_basic_block = {
  label: string;
  instructions: ir_instruction list;
  successors: string list;
  predecessors: string list;
  stack_usage: int;
  loop_depth: int;
  reachable: bool;
}

(* Enhanced function representation *)
type ir_function = {
  name: string;
  parameters: (string * ir_type) list;
  return_type: ir_type option;
  basic_blocks: ir_basic_block list;
  total_stack_usage: int;
  max_loop_depth: int;
  calls_helper_functions: string list;
  visibility: visibility;
  is_main: bool;
}

and visibility = Public | Private

(* Userspace binding generation *)
type ir_userspace_binding = {
  language: binding_language;
  map_wrappers: ir_map_wrapper list;
  event_handlers: ir_event_handler list;
  config_structs: ir_config_struct list;
}

and binding_language = C | Rust | Go | Python

and ir_map_wrapper = {
  map_name: string;
  operations: map_operation list;
  safety_checks: bool;
}

and map_operation = Lookup | Update | Delete | Iterate

and ir_event_handler = {
  event_type: string;
  callback_signature: string;
  buffer_management: buffer_type;
}

and buffer_type = RingBuffer | PerfEvent

and ir_config_struct = {
  struct_name: string;
  fields: (string * ir_type) list;
  serialization: serialization_type;
}

and serialization_type = Json | Binary | Custom of string
```

**Unit Tests:**
```ocaml
let test_program_lowering () =
  let ast_program = Program {
    name = "test_xdp";
    prog_type = Xdp;
    maps = [global_map; local_map];
    functions = [main_fn];
  } in
  let ir_prog = lower_program ast_program in
  assert (ir_prog.program_type = Xdp);
  assert (List.length ir_prog.global_maps = 1);
  assert (List.length ir_prog.local_maps = 1);
  assert (ir_prog.main_function.is_main = true)

let test_context_access_lowering () =
  let ast_call = FunctionCall ("ctx.packet", []) in
  let ir_instrs = lower_expression ast_call in
  match List.hd ir_instrs with
  | { instr_desc = IRContextAccess (_, PacketData); _ } -> ()
  | _ -> assert_failure "Context access lowering failed"

let test_map_operation_lowering () =
  let ast_map_access = ArrayAccess (Identifier "my_map", Literal (IntLit 0)) in
  let ir_instrs = lower_expression ast_map_access in
  match List.hd ir_instrs with
  | { instr_desc = IRMapLoad (_, _, _, Lookup); bounds_checks = [_]; _ } -> ()
  | _ -> assert_failure "Map access should generate bounds checks"

let test_bounds_check_insertion () =
  let ast_array_access = ArrayAccess (arr, index) in
  let ir_instrs = lower_expression ast_array_access in
  let bounds_checks = List.concat_map (fun i -> i.bounds_checks) ir_instrs in
  assert (List.length bounds_checks > 0);
  assert (List.exists (fun bc -> bc.check_type = ArrayAccess) bounds_checks)

let test_stack_usage_tracking () =
  let ast_fn = Function {
    name = "test";
    body = [Declaration ("buffer", Array (U8, 100), None)];
  } in
  let ir_fn = lower_function ast_fn in
  assert (ir_fn.total_stack_usage >= 100);
  assert (List.for_all (fun bb -> bb.stack_usage >= 0) ir_fn.basic_blocks)

let test_userspace_binding_generation () =
  let ir_prog = lower_program complex_program in
  let c_bindings = List.find (fun b -> b.language = C) ir_prog.userspace_bindings in
  assert (List.length c_bindings.map_wrappers > 0);
  assert (List.exists (fun op -> op = Lookup) 
    (List.hd c_bindings.map_wrappers).operations)
```

### Milestone 4.3: Statement Processing (Week 12) ✅ COMPLETED
**Deliverables:**
- ✅ Complete statement processing on IR
- ✅ Control flow analysis on IR CFG
- ✅ Loop termination verification
- ✅ Return path analysis
- ✅ Dead code elimination

### Milestone 4.4: Function System (Week 13) ✅ COMPLETED
**Deliverables:**
- ✅ Function signature validation on IR
- ✅ Parameter passing semantics
- ✅ Visibility rules (pub/priv)
- ✅ Recursive call detection
- ✅ Cross-function optimization preparation

---

## Phase 5: Code Generation (Weeks 14-17)

### Goals
Generate eBPF bytecode and userspace bindings from IR.

### Milestone 5.1: eBPF Backend (Weeks 14-15)
**Deliverables:**
- `src/ebpf_codegen.ml` - eBPF bytecode generation from IR
- Register allocation from IR registers
- Instruction selection from IR instructions
- Map operation compilation from IR map operations

### Milestone 5.2: Userspace Bindings (Week 16)
**Deliverables:**
- `src/userspace_codegen.ml` - Generate C/Rust/Go bindings from IR
- Map access wrappers from IR map operations
- Event handling code
- Configuration management

### Milestone 5.3: Standard Library (Week 17)
**Deliverables:**
- `src/stdlib.ml` - Built-in functions expanded in IR
- Network utility functions
- Context helper methods
- Error handling primitives

---

## Phase 6: Integration and Tooling (Weeks 18-21)

### Goals
Build system, testing framework, and documentation.

### Milestone 6.1: Build System (Week 18)
**Deliverables:**
- `dune-project` and `dune` files
- `kernelscript` command-line tool
- Compilation pipeline (AST → IR → Code)
- Error reporting system

### Milestone 6.2: Testing Framework (Week 19)
**Deliverables:**
- Comprehensive test suite
- Integration tests
- Performance benchmarks
- Fuzzing support

### Milestone 6.3: Documentation and Examples (Weeks 20-21)
**Deliverables:**
- API documentation
- Language reference
- Tutorial examples
- Migration guide

---

## Project Structure

```
kernelscript/
├── src/
│   ├── ast.ml              # AST definitions
│   ├── tokens.ml           # Token types
│   ├── lexer.mll           # Lexical analysis
│   ├── parser.mly          # Parser grammar
│   ├── type_checker.ml     # Type system
│   ├── symbol_table.ml     # Symbol resolution
│   ├── maps.ml             # Map handling
│   ├── safety_checker.ml   # Memory safety
│   ├── evaluator.ml        # Expression evaluation
│   ├── ir.ml               # IR definitions
│   ├── ir_generator.ml     # AST to IR lowering
│   ├── ebpf_codegen.ml     # eBPF code generation
│   ├── userspace_codegen.ml # Userspace bindings
│   ├── stdlib.ml           # Standard library
│   └── main.ml             # CLI interface
├── tests/
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── examples/           # Example programs
├── docs/
│   ├── language_ref.md     # Language reference
│   └── api_docs/           # Generated API docs
├── dune-project
└── README.md
```

## Dependencies

**Core OCaml Libraries:**
- `menhir` - Parser generator
- `ppx_deriving` - Code generation
- `core` - Standard library extensions  
- `cmdliner` - Command-line interface
- `yojson` - JSON handling
- `lwt` - Async I/O (for userspace integration)

**Testing:**
- `ounit2` - Unit testing framework
- `qcheck` - Property-based testing
- `bisect_ppx` - Code coverage

## Risk Mitigation

### Technical Risks
1. **eBPF Complexity**: Start with simple programs, gradually add complexity
2. **Type System Complexity**: Implement incrementally with extensive testing
3. **Memory Safety**: Use formal verification techniques where possible

### Schedule Risks
1. **Parser Complexity**: Allocate extra time for grammar edge cases
2. **Code Generation**: Plan for multiple iterations on optimization
3. **Integration**: Reserve buffer time for userspace binding challenges

## Success Metrics

### Functional Requirements
- [ ] Parse all KernelScript constructs correctly
- [ ] Type check programs with detailed error messages
- [ ] Generate working eBPF bytecode
- [ ] Create functional userspace bindings
- [ ] Pass all specification examples

### Quality Requirements
- [ ] >90% test coverage
- [ ] <100ms compilation time for medium programs
- [ ] Clear error messages with source locations
- [ ] Comprehensive documentation

### Performance Targets
- [ ] Compile 1000-line programs in <1 second
- [ ] Generate optimized eBPF comparable to hand-written C
- [ ] Memory usage <100MB for typical programs

---

This roadmap provides a structured approach to implementing KernelScript in OCaml, with clear milestones, deliverables, and success criteria for each phase of development. 