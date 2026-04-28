# sluice

[![CI](https://github.com/pradhankukiran/sluice/actions/workflows/ci.yml/badge.svg)](https://github.com/pradhankukiran/sluice/actions/workflows/ci.yml)
[![Release](https://github.com/pradhankukiran/sluice/actions/workflows/release.yml/badge.svg)](https://github.com/pradhankukiran/sluice/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/pradhankukiran/sluice?color=blue)](https://github.com/pradhankukiran/sluice/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![Rust](https://img.shields.io/badge/Rust-1.93+-CE422B?logo=rust&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-only-FCC624?logo=linux&logoColor=black)
![eBPF](https://img.shields.io/badge/eBPF-Aya-006400?logo=ebpf&logoColor=white)
![iced](https://img.shields.io/badge/GUI-iced-9277C7)
![SQLite](https://img.shields.io/badge/storage-SQLite-003B57?logo=sqlite&logoColor=white)
![Tokio](https://img.shields.io/badge/runtime-Tokio-blueviolet)

A per-process Linux network gate. **Little Snitch for Linux**, built
on modern Rust + Aya eBPF.

Sluice watches every outbound connection in the kernel, prompts you
to allow or deny, and shapes per-process bandwidth — all driven by
eBPF programs and a Rust desktop GUI.

## What it does

- **Live connection feed** — every outbound `connect()` system-wide,
  attributed to its process and destination IP/port.
- **Per-process firewall** — write rules like `exe=/usr/bin/curl
  host=any port=443 verdict=deny` and have them enforced in the
  kernel. Rules can match exe path, IP, CIDR, hostname (DNS-resolved),
  port, port range, and protocol.
- **Interactive prompts** — under `policy=ask`, the daemon raises a
  modal in the GUI when an unrecognized process tries to talk; one
  click decides for the future.
- **Per-process bandwidth shaping** — pick a process, type a KB/s
  rate, watch its egress throttled in real time. Driven by a tc-bpf
  token bucket; live throughput meter ticks once per second.

## Architecture

Three processes, two languages, one shared crate:

```
┌──────────────┐    eBPF     ┌─────────────────────┐
│  sluice-ebpf │ ──────────▶ │  Linux kernel       │
│  (Rust,      │   programs  │  (cgroup/connect4,  │
│   no_std)    │             │   sock_create,      │
└──────────────┘             │   tc-bpf egress)    │
       │                     └─────────────────────┘
       │  bytecode                     ▲
       ▼                               │ map ops
┌──────────────┐    Aya      ┌─────────┴──────────┐
│   sluiced    │ ──────────▶ │ kernel: VERDICTS,  │
│  (privileged │   loads &   │  RATE_LIMITS,      │
│   daemon)    │    attaches │  TX_BYTES,         │
└──────────────┘             │  SOCK_PIDS, EVENTS │
       │                     └────────────────────┘
       │  Unix socket
       │  (newline JSON)
       ▼
┌──────────────┐
│   sluice     │  iced GUI: Events / Rules / Policy / Bandwidth tabs
│  (user GUI)  │  with prompt dialogs, rule editor, bandwidth sliders.
└──────────────┘
```

- **`sluice-common`** — shared `#[repr(C)]` types (ConnectEvent,
  Verdict, TokenBucket) and the IPC wire format. `no_std`-compatible
  for the eBPF crate.
- **`sluice-ebpf`** — kernel-side programs in `no_std` Rust,
  compiled to BPF bytecode via `bpf-linker`.
- **`sluiced`** — privileged daemon. Loads/attaches the eBPF
  programs, owns the SQLite rules database, runs the IPC server.
- **`sluice`** — unprivileged GUI built on `iced`. Connects to
  `sluiced` over `/run/sluice/sluice.sock`.
- **`xtask`** — orchestrates the cross-target build (eBPF crate
  separately from the userspace workspace).

## Building

Requires:

- Linux ≥ 6.0 with cgroup v2 mounted at `/sys/fs/cgroup`.
- Rust stable + nightly-2026-01-15 (pinned in
  `sluice-ebpf/rust-toolchain.toml`).
- `bpf-linker` — `cargo install bpf-linker --locked`.
- For the GUI: standard X11 / Wayland dev libraries (`libx11-dev`,
  `libxkbcommon-dev`, `libwayland-dev`, `libfontconfig1-dev` —
  full list in `.github/workflows/ci.yml`).

```sh
cargo run -p xtask -- build-ebpf       # build kernel-side bytecode
cargo build --workspace                # build userspace (sluiced + sluice + xtask)
```

## Running

Two terminals.

**Terminal A — daemon (root, eBPF requires `CAP_BPF`):**

```sh
sudo SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced
```

By default the rules DB lives at `/var/lib/sluice/rules.db` and the
IPC socket at `/run/sluice/sluice.sock`. Both are overridable via
env (`SLUICE_DB_PATH`, `SLUICE_SOCKET_PATH`) for development without
root-writable `/var`/`/run`.

**Terminal B — GUI (regular user):**

```sh
cargo run -p sluice
```

The window shows live connections, the current rule list, the
default policy, and the Bandwidth tab. Switch the default policy to
**Ask** to start getting prompts.

## CLI

The daemon binary doubles as a CLI for managing rules without the
GUI:

```sh
sluiced rules list
sluiced rules add --exe /usr/bin/curl --host any --port 443 \
                  --proto tcp --verdict deny
sluiced rules rm 1
sluiced policy show
sluiced policy set ask
```

## IPC protocol

Newline-delimited JSON over a Unix socket. Inspectable from the
shell:

```sh
echo '{"type":"request","id":1,"body":{"kind":"hello"}}' \
  | sudo nc -U /run/sluice/sluice.sock
```

See `sluice-common/src/ipc.rs` for the full schema (Frame / Request /
Response / Event enums tagged with `#[serde(rename_all =
"snake_case")]`).

## Phase plan

The build was split into 12 phases, each landing as a series of
small commits with its own design doc. See [`docs/phases.md`](docs/phases.md)
for the index and per-phase deep-dives covering decisions, trade-offs,
and current limits.

| Phase | Topic |
|-------|-------|
| 1 | [Workspace skeleton](docs/phase-1.md) |
| 2 | [Passive connection observation](docs/phase-2.md) |
| 3 | [PID → executable resolution](docs/phase-3.md) |
| 4 | [Rules engine + SQLite](docs/phase-4.md) |
| 5 | [Active blocking](docs/phase-5.md) |
| 6 | [GUI skeleton + IPC](docs/phase-6.md) |
| 7 | [Live prompt dialogs](docs/phase-7.md) |
| 8 | [Rules manager UI](docs/phase-8.md) |
| 9 | [DNS-aware rules](docs/phase-9.md) |
| 10 | [Bandwidth shaping (kernel)](docs/phase-10.md) |
| 11 | [Bandwidth shaping (UI)](docs/phase-11.md) |
| 12 | [Polish + packaging](docs/phase-12.md) |

## Install

### From a tagged release (Debian / Ubuntu)

```sh
wget https://github.com/pradhankukiran/sluice/releases/latest/download/sluiced_0.1.0-1_amd64.deb
sudo dpkg -i sluiced_*.deb
sudo systemctl enable --now sluiced
```

The `.deb` ships `sluiced`, `sluice`, the eBPF bytecode under
`/usr/lib/sluice/`, and the systemd unit at `/lib/systemd/system/sluiced.service`.

### Build a `.deb` locally

```sh
cargo install cargo-deb
cargo build --release --workspace
cargo run -p xtask -- build-ebpf
cargo deb -p sluiced --no-build
sudo dpkg -i target/debian/sluiced_*.deb
sudo systemctl enable --now sluiced
```

### From source (anywhere)

```sh
cargo install bpf-linker --locked
cargo run -p xtask -- build-ebpf
cargo build --release --workspace

sudo install -m 755 target/release/sluiced target/release/sluice /usr/bin/
sudo install -d /usr/lib/sluice
sudo install -m 644 sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf /usr/lib/sluice/
sudo install -m 644 packaging/sluiced.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now sluiced
```

## License

MIT — see [`LICENSE`](LICENSE).
