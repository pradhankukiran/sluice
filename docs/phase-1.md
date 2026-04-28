# Phase 1: Workspace Skeleton

Phase 1 lays out the three-process architecture as empty crates so the
build system, toolchains, and CI are wired up before any eBPF or GUI work
begins.

## Implemented

- Cargo workspace with shared dependency versions in `[workspace.dependencies]`
- Rust 1.93 toolchain pinned for the userspace workspace via
  `rust-toolchain.toml`
- `sluice-common` library crate (`no_std`-compatible) defining
  `ConnectEvent` and `Verdict` shared between kernel and userspace
- `sluiced` privileged daemon binary skeleton (logging only)
- `sluice` GUI binary skeleton (logging only)
- `sluice-ebpf` standalone-workspace crate (`no_std`, `no_main`) with
  panic handler stub, pinned to a nightly toolchain for `bpfel-unknown-none`
- `xtask` build orchestrator: `build-ebpf`, `build`, `run-daemon`, `run-gui`
- GitHub Actions CI for the userspace workspace (`fmt`, `clippy`, `build`,
  `test` on `ubuntu-latest`)

## Architecture Decisions

- **Three processes, not one.** eBPF requires `CAP_BPF` + `CAP_NET_ADMIN`,
  but the GUI shouldn't run as root. `sluiced` is the privileged loader and
  rule arbiter; `sluice` is unprivileged and talks to it over a Unix
  socket. This is the same shape used by OpenSnitch and PolicyKit.
- **`sluice-ebpf` is excluded from the main workspace.** It compiles for
  `bpfel-unknown-none` (a tier-3 BPF target) and pulls a different
  toolchain. Keeping it standalone avoids cross-target build pollution.
- **`sluice-common` is `no_std`-feature-gated.** The same crate is depended
  on by both eBPF (`no_std`) and userspace (`std`); the `std` feature is
  default and is disabled in the eBPF crate's dependency entry.
- **`xtask` over `Makefile`/`justfile`.** Build orchestration is Rust so
  it inherits the toolchain pinning and runs identically in CI.

## Current Limits

- No eBPF programs attached. `sluice-ebpf` only contains a panic-handler
  stub; real `cgroup/connect4`/`connect6` and `tc-bpf` programs land in
  later phases.
- `sluiced` and `sluice` only emit a startup log line.
- No IPC between daemon and GUI yet.
- CI does not yet build the eBPF crate (requires `bpf-linker` and the
  pinned nightly).

## Next Phase

Phase 2 adds passive connection observation: a `cgroup/connect4` eBPF
program that emits a `ConnectEvent` into a ring buffer for every outbound
IPv4 connection, plus a userspace consumer in `sluiced` that logs each
event.
