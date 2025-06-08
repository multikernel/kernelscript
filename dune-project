(lang dune 2.9)

(name kernelscript)

(package
 (name kernelscript)
 (synopsis "KernelScript - eBPF programming language with integrated userspace support")
 (description "A domain-specific language for eBPF programming that provides seamless integration between kernel and userspace code")
 (depends
  ocaml
  dune
  menhir))

(using menhir 2.0) 