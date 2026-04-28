# Phase 2: Passive Connection Observation

Phase 2 wires up the eBPF data path end-to-end: every outbound `connect()`
in the system surfaces in `sluiced` as a structured log line. No rules, no
blocking — purely "I see you."

## Implemented

- **`EVENTS` ring buffer** (1 MiB, power-of-two, in `sluice-ebpf/src/maps.rs`)
  carrying `ConnectEvent` records from kernel to userspace.
- **`cgroup/connect4` program** that fires on every IPv4 `connect()` syscall
  in any process within the attached cgroup. Captures PID/TGID, UID/GID,
  `comm`, kernel timestamp, and decodes the destination IPv4 address +
  port from the BPF `sock_addr` context.
- **`cgroup/connect6` sibling** for IPv6 (`user_ip6` array unrolled into
  the 16-byte `addr` field).
- **`sluiced::cgroup`** — resolves the cgroup v2 root (`/sys/fs/cgroup`),
  with `SLUICE_CGROUP_ROOT` env override and an explicit error when v1 is
  detected.
- **`sluiced::ebpf_loader`** — finds the compiled bytecode (`SLUICE_EBPF_BYTECODE`
  env override or compile-time path under
  `sluice-ebpf/target/bpfel-unknown-none/release/`), loads via `aya::Ebpf::load_file`.
- **`sluiced::attach`** — narrows generic `Program`s into `CgroupSockAddr`,
  loads them, attaches to the cgroup root in `Single` mode.
- **`sluiced::ring_reader`** — wraps `aya::maps::ring_buf::RingBuf` in
  `tokio::io::unix::AsyncFd<RingBuf<MapData>>`, calls `.next()` on every
  readiness wakeup, decodes `ConnectEvent` via `read_unaligned`, dispatches
  to a sync callback.
- **`sluiced::formatter`** — stable single-line rendering:
  `firefox pid=4040 uid=1000 -> 140.82.121.4:443 (TCP)`.
- **`#[tokio::main]` async runtime** with `select!` over the reader loop
  and Ctrl-C signal.

## Architecture Decisions

- **`cgroup/connect4` over `kprobe:tcp_v4_connect`.** The cgroup BPF
  programs run *before* the connection is established, in a context where
  the user's task struct is current — so `bpf_get_current_pid_tgid()` and
  `bpf_get_current_comm()` return the issuing process. They also let us
  return 0 to deny in later phases without an extra hook.
- **Ring buffer (`BPF_MAP_TYPE_RINGBUF`) over perf event array.** Lower
  overhead, single shared buffer, modern (5.8+) and recommended for new
  observers. We use `RingBuf::output(&event, 0)` for atomic submit; if the
  buffer is full, we drop rather than block.
- **`#[tokio::main]` async** so phase 6's GUI/IPC can plug into the same
  runtime without restructuring.
- **`AsyncFd<RingBuf<MapData>>`** owns the ring buffer and exposes the
  underlying fd to the tokio reactor — the canonical Aya recipe.
- **`read_unaligned` decode** instead of pulling in `bytemuck`/`zerocopy`.
  `ConnectEvent` is `#[repr(C)]` and compile-time-size-pinned to 64 bytes
  in `sluice-common`, so the decode is sound and we avoid an extra dep.

## Current Limits

- **Passive only.** Both programs always return 1 (allow). No rule
  database, no blocking.
- **No DNS reverse-resolution.** Connections are reported by IP literal,
  not hostname. Phase 9 fixes this.
- **No exe path / cmdline.** Only the kernel's 16-byte `comm` (the
  truncated process name). Phase 3 adds `/proc/PID/exe` and cmdline
  resolution.
- **Drops on burst.** When the ring buffer fills, `output` returns an
  error and the event is silently dropped. Acceptable for a passive
  observer; phase 4+ will add backpressure metrics.
- **No retry on attach.** If sluiced doesn't have `CAP_BPF` +
  `CAP_NET_ADMIN`, attach fails with a clear error message.

## Running it

```sh
cargo run -p xtask -- build-ebpf      # build kernel-side bytecode
sudo SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced
```

Then in another terminal:

```sh
curl -s https://example.com/ > /dev/null
```

`sluiced` should log a line like:

```
INFO sluice::connect: curl pid=12345 uid=1000 -> 93.184.216.34:443 (TCP)
```

## Next Phase

Phase 3 enriches each event in userspace by reading `/proc/<tgid>/exe`
(canonical executable path) and `/proc/<tgid>/cmdline` (full argv). Result
is cached so per-event lookups are O(1) for hot processes.
