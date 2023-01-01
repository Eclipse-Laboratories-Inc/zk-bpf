# zk-bpf

This is a tool allowing for zero-knowledge execution of eBPF programs, by compiling eBPF to RISC-V and using RISC Zero as a backend. Note that this is still in a very preliminary state, and we only have a small portion of the eBPF instruction set implemented. Currently, it needs `cargo` available in order to run, since the translated eBPF is linked with a Rust wrapper to make the final RISC-V binary.

To try it out, pass an assembly file with `--asm` or an ELF file with `--elf`. You can run the example program with:

```sh
cargo run -- --asm example.s --input-data example-input
```

This will perform a 32-bit multiplication on the two 32-bit numbers in the input file (7 and 8 in this case) and put the output in register 0.

## License

This project is distributed under the Apache License (Version 2.0).
