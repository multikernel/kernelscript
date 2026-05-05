open Kernelscript.Ast
open Kernelscript.Parse

let test_parse_sysctl_attribute () =
  let src = {|
@sysctl("net.core.somaxconn")
var somaxconn: u32

fn main() -> i32 { return 0 }
|} in
  let ast = parse_string src in
  let found = List.exists (function
    | GlobalVarDecl gv ->
        gv.global_var_name = "somaxconn"
        && List.exists (function
             | AttributeWithArg ("sysctl", "net.core.somaxconn") -> true
             | _ -> false)
           gv.global_var_attributes
    | _ -> false) ast in
  Alcotest.(check bool) "sysctl attribute parsed" true found

let () =
  Alcotest.run "sysctl" [
    "parse", [
      Alcotest.test_case "attribute on global var" `Quick test_parse_sysctl_attribute;
    ];
  ]
