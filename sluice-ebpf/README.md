# sluice-ebpf

Kernel-side eBPF programs for sluice. **Standalone workspace** — not a member
of the top-level Cargo workspace because it compiles for the
`bpfel-unknown-none` target.

## Building

Requires `bpf-linker`:

```sh
cargo install bpf-linker
```

Then from the repo root:

```sh
cargo run -p xtask -- build-ebpf
```

(or, manually, `cd sluice-ebpf && cargo build --release`).

The built bytecode is consumed by `sluiced` at startup.
