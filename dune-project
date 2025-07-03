(lang dune 2.9)

(name kernelscript)

(use_standard_c_and_cxx_flags true)

(package
 (name kernelscript)
 (synopsis "KernelScript - eBPF programming language with integrated userspace support")
 (description "A domain-specific language for eBPF programming that provides seamless integration between kernel and userspace code")
 (depends
  ocaml
  dune
  menhir
  alcotest))

(using menhir 2.0) 