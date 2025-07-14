(lang dune 2.9)

(name kernelscript)

(use_standard_c_and_cxx_flags true)

(package
 (name kernelscript)
 (authors "Cong Wang")
 (maintainers "Cong Wang <cwang@multikernel.io>")
 (license Apache-2.0)
 (synopsis "A modern programming language for eBPF development")
 (depends
  ocaml
  dune
  menhir
  alcotest))

(using menhir 2.0) 