# sluice

A Linux per-process network gate. Watches every outbound connection in the
kernel via eBPF, prompts you to allow or deny, and shapes per-process
bandwidth.

Think "Little Snitch for Linux," but built on modern Rust + Aya eBPF.

## Status

Early development. See [`docs/`](docs/) for the phase-by-phase build log.

## Architecture

Three processes:

- **`sluice-ebpf`** — kernel-side eBPF programs (Rust, compiled to BPF
  bytecode). Hooks `cgroup/connect4`/`connect6` to gate outbound connections,
  and `tc-bpf` egress for per-PID bandwidth shaping.
- **`sluiced`** — privileged userspace daemon (Rust). Loads the eBPF programs,
  reads connection events, owns the rules database, decides verdicts.
- **`sluice`** — unprivileged GUI (Rust + `iced`). Talks to `sluiced` over a
  Unix socket. Shows live "allow this connection?" prompts, manages rules,
  per-process bandwidth sliders.

## License

MIT (see [`LICENSE`](LICENSE)).
