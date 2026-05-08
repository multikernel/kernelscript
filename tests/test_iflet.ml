(*
 * Copyright 2026 Multikernel Technologies, Inc.
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

(** Tests for the `if (var x = expr)` declaration-as-condition statement. *)

open Kernelscript.Ast
open Kernelscript.Parse
open Alcotest

let contains_substr str substr =
  try let _ = Str.search_forward (Str.regexp_string substr) str 0 in true
  with Not_found -> false

let typecheck source =
  let ast = parse_string source in
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  let (typed_ast, _) =
    Kernelscript.Type_checker.type_check_and_annotate_ast
      ~symbol_table:(Some symbol_table) ast in
  (ast, symbol_table, typed_ast)

let codegen_ebpf source =
  let (_ast, symbol_table, typed_ast) = typecheck source in
  let ir = Kernelscript.Ir_generator.generate_ir typed_ast symbol_table "test" in
  Kernelscript.Ebpf_c_codegen.generate_c_multi_program ir

let extract_first_stmt source =
  let ast = parse_string source in
  let attr_func =
    List.find (function AttributedFunction _ -> true | _ -> false) ast in
  match attr_func with
  | AttributedFunction af -> List.nth af.attr_function.func_body 0
  | _ -> failwith "no attributed function"

(** 1. Parse: bare `if (var x = ...)` produces an IfLet AST node. *)
let test_parse_iflet_no_else () =
  let source = {|
var counters : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var c = counters[1]) {
    return XDP_DROP
  }
  return XDP_PASS
}
|} in
  let stmt = extract_first_stmt source in
  match stmt.stmt_desc with
  | IfLet (name, _, _, None) ->
      check string "binding name" "c" name
  | _ -> fail "expected IfLet without else"

(** 2. Parse: `if (var x = ...) { } else { }` round-trips with else. *)
let test_parse_iflet_with_else () =
  let source = {|
var counters : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var c = counters[1]) {
    return XDP_DROP
  } else {
    return XDP_PASS
  }
}
|} in
  let stmt = extract_first_stmt source in
  match stmt.stmt_desc with
  | IfLet (_, _, _, Some _) -> ()
  | _ -> fail "expected IfLet with else"

(** 3. Parse: `else if (var ...)` chains via nested IfLet. *)
let test_parse_iflet_else_iflet () =
  let source = {|
var a : hash<u32, u64>(1024)
var b : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var x = a[1]) {
    return XDP_DROP
  } else if (var y = b[2]) {
    return XDP_PASS
  }
  return XDP_PASS
}
|} in
  let stmt = extract_first_stmt source in
  match stmt.stmt_desc with
  | IfLet (_, _, _, Some [{ stmt_desc = IfLet _; _ }]) -> ()
  | _ -> fail "expected outer IfLet whose else is a single IfLet"

(** 4. Type-check: struct-map binding succeeds; field access in body works. *)
let test_typecheck_struct_binding () =
  let source = {|
struct Stats { count: u64, bytes: u64 }
var stats : hash<u32, Stats>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var s = stats[1]) {
    s.count = s.count + 1
    s.bytes = s.bytes + 100
  }
  return XDP_PASS
}
|} in
  let _ = typecheck source in
  ()

(** 5. Type-check: scalar-map binding succeeds; value used as a value in body. *)
let test_typecheck_scalar_binding () =
  let source = {|
var counters : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var c = counters[1]) {
    if (c > 100) {
      return XDP_DROP
    }
  }
  return XDP_PASS
}
|} in
  let _ = typecheck source in
  ()

(** 6. Reject: binding referenced from the else-branch. *)
let test_reject_binding_in_else () =
  let source = {|
var counters : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var c = counters[1]) {
    return XDP_PASS
  } else {
    var leaked : u64 = c
  }
  return XDP_PASS
}
|} in
  try
    let _ = typecheck source in
    fail "expected rejection of binding leak into else-branch"
  with
  | Kernelscript.Symbol_table.Symbol_error _ -> ()
  | Kernelscript.Type_checker.Type_error _ -> ()

(** 7. Reject: binding referenced after the if-statement (no outer shadow). *)
let test_reject_binding_after_if () =
  let source = {|
var counters : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var c = counters[1]) {
    return XDP_PASS
  }
  var leaked : u64 = c
  return XDP_PASS
}
|} in
  try
    let _ = typecheck source in
    fail "expected rejection of binding leak past the if-statement"
  with
  | Kernelscript.Symbol_table.Symbol_error _ -> ()
  | Kernelscript.Type_checker.Type_error _ -> ()

(** 8. Codegen (struct map): single lookup + presence check + in-place mutation
       with no manual write-back. *)
let test_codegen_struct_in_place () =
  let source = {|
struct Stats { count: u64, bytes: u64 }
var stats : hash<u32, Stats>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var s = stats[1]) {
    s.count = s.count + 1
  }
  return XDP_PASS
}
|} in
  let c = codegen_ebpf source in
  check bool "single map lookup" true (contains_substr c "bpf_map_lookup_elem(&stats");
  check bool "presence check"     true (contains_substr c "!= NULL");
  check bool "in-place ptr->field write" true
    (contains_substr c "->count =");
  (* In-place mutation should mean no bpf_map_update_elem in the truthy branch.
     The else branch is omitted in the source, so there should be zero updates. *)
  let has_update =
    try let _ = Str.search_forward
                  (Str.regexp_string "bpf_map_update_elem(&stats") c 0 in true
    with Not_found -> false in
  check bool "no manual write-back update" false has_update

(** 9. Codegen (scalar map): the binding holds the dereffed value, and the
       presence check uses the underlying lookup pointer. *)
let test_codegen_scalar_value_binding () =
  let source = {|
var counters : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var c = counters[1]) {
    if (c > 100) {
      return XDP_DROP
    }
  }
  return XDP_PASS
}
|} in
  let c = codegen_ebpf source in
  (* The IfLet binding is alpha-renamed to a fresh synthetic name during IR
     lowering (see `subst_ident_stmts` in ir_generator.ml) so that an outer
     variable of the same name is not silently clobbered when the backend
     hoists declarations to function scope. The synthetic name has the
     form `__iflet_<orig>_<N>`. *)
  check bool "scalar binding declared as value, not pointer" true
    (contains_substr c "__u64 __iflet_c_");
  check bool "binding init uses the dereffed value statement-expression" true
    (contains_substr c "__val = *(");
  check bool "presence check on the underlying lookup pointer" true
    (contains_substr c "!= NULL")

(** 10. Codegen (struct map, end-to-end shape): the binding is declared with
       the value type (the type-checker auto-derefs `m[k]` to the struct
       value), but the field operations in the body lower to in-place
       mutation through the underlying lookup pointer rather than through
       the local. The local is therefore dead — clang elides it — but its
       declaration is still syntactically a value, not a pointer.

       Concretely the previous codegen shape was, for user-written code:
         struct Stats* __map_lookup_N;
         __map_lookup_N = bpf_map_lookup_elem(&stats, &k);
         struct Stats s = ({ struct Stats __val = {0};
                             if (__map_lookup_N) { __val = *(__map_lookup_N); }
                             __val; });
         if (__map_lookup_N != NULL) {
           ... __map_lookup_N->count = ... ;
         }
       Phase 2 only changed the synthetic-pointer-binding path (used by the
       lowered `m[k].field op= rhs`); user-written IfLet still produces the
       value-typed local above. Pinning that here so any future change to
       the typing rule is intentional. *)
let test_codegen_struct_value_binding_shape () =
  let source = {|
struct Stats { count: u64 }
var stats : hash<u32, Stats>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var s = stats[1]) {
    s.count = s.count + 1
  }
  return XDP_PASS
}
|} in
  let c = codegen_ebpf source in
  (* Binding is alpha-renamed to `__iflet_s_<N>` — see the comment on
     `test_codegen_scalar_value_binding` for why. *)
  check bool "binding declared with value type, not pointer" true
    (contains_substr c "struct Stats __iflet_s_");
  check bool "value-typed binding uses deref-load init" true
    (contains_substr c "struct Stats __val");
  check bool "field write goes through the underlying lookup pointer" true
    (contains_substr c "->count =")

(** 11a. Reject: int-literal RHS — `if (var x = 5)` is not a presence check.
        The construct only makes sense when the RHS is a map access (auto-
        deref'd to a value but underlying-pointer-checked) or a pointer-typed
        expression. An integer RHS would lower to `__u32 x; if (x != NULL)`,
        which warns under -Wpointer-integer-compare and is semantically
        incoherent — also the evaluator's truthiness rules diverge from the
        codegen's `!= NULL` for non-pointer types. *)
let test_reject_int_literal_rhs () =
  let source = {|
@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var x = 5) {
    return XDP_PASS
  }
  return XDP_DROP
}
|} in
  try
    let _ = typecheck source in
    fail "expected rejection of integer-literal RHS"
  with
  | Kernelscript.Type_checker.Type_error _ -> ()

(** 11b. Reject: non-pointer-returning function RHS. *)
let test_reject_non_pointer_call_rhs () =
  let source = {|
@helper fn returns_zero() -> u32 {
  return 0
}

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  if (var x = returns_zero()) {
    return XDP_PASS
  }
  return XDP_DROP
}
|} in
  try
    let _ = typecheck source in
    fail "expected rejection of non-pointer-returning call as RHS"
  with
  | Kernelscript.Type_checker.Type_error _ -> ()

(** 11. Codegen (shadowing): an outer binding of the same name as the IfLet
       binding must survive both branches and remain referenceable after the
       if. The branch-local invariant the frontend enforces (binding visible
       only inside the then-branch) has to be preserved end-to-end through
       IR lowering — i.e., the inner binding cannot collapse onto the outer
       name in the generated C. *)
let test_codegen_shadow_outer_binding () =
  let source = {|
var counters : hash<u32, u64>(1024)

@xdp fn probe(ctx: *xdp_md) -> xdp_action {
  var c : u64 = 100
  if (var c = counters[1]) {
    return XDP_DROP
  }
  if (c == 100) {
    return XDP_PASS
  }
  return XDP_DROP
}
|} in
  let c = codegen_ebpf source in
  (* The outer `c = 100` declaration must remain literally — the inner binding
     must not reuse the name. *)
  check bool "outer c declared with literal value" true
    (contains_substr c "__u64 c = 100");
  (* The outer `c` must NOT be reassigned by the IfLet's lowering. The bug
     symptom was a statement-expression assignment `c = ({ ... });` that
     clobbered the outer binding with the lookup result (or zero on miss).
     A bare `c = ({` (no `__u64` prefix) is the giveaway. *)
  let outer_clobber =
    try let _ = Str.search_forward
                  (Str.regexp "[^_a-zA-Z0-9]c = ({") c 0 in true
    with Not_found -> false in
  check bool "outer c not clobbered by iflet init" false outer_clobber;
  (* The post-if comparison `c == 100` must reference the outer `c`, not be
     rewritten into another fresh map deref. *)
  check bool "post-if uses outer c by name" true
    (contains_substr c "(c == 100)")

let suite = [
  "parse_iflet_no_else",              `Quick, test_parse_iflet_no_else;
  "parse_iflet_with_else",            `Quick, test_parse_iflet_with_else;
  "parse_iflet_else_iflet",           `Quick, test_parse_iflet_else_iflet;
  "typecheck_struct_binding",         `Quick, test_typecheck_struct_binding;
  "typecheck_scalar_binding",         `Quick, test_typecheck_scalar_binding;
  "reject_binding_in_else",           `Quick, test_reject_binding_in_else;
  "reject_binding_after_if",          `Quick, test_reject_binding_after_if;
  "codegen_struct_in_place",          `Quick, test_codegen_struct_in_place;
  "codegen_scalar_value_binding",     `Quick, test_codegen_scalar_value_binding;
  "codegen_struct_value_binding_shape", `Quick, test_codegen_struct_value_binding_shape;
  "codegen_shadow_outer_binding",     `Quick, test_codegen_shadow_outer_binding;
  "reject_int_literal_rhs",           `Quick, test_reject_int_literal_rhs;
  "reject_non_pointer_call_rhs",      `Quick, test_reject_non_pointer_call_rhs;
]

let () =
  run "IfLet (declaration-as-condition)" [ "iflet", suite ]
