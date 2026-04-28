# Phase 12: Polish + Packaging

Phase 12 turns the working prototype into something that looks and
feels like a shipping piece of software. No new core eBPF programs
land in this phase; instead it closes the loop on persistence,
observability, GUI ergonomics, deployment, and the front-page README.

## Implemented

- **Persisted rate limits** — new SQLite migration `v2` adds a
  `rates` table (`pid`, `rate_bps`, `burst_bytes`, `created_at`).
  `SqliteRuleStore::upsert_rate` / `delete_rate` / `list_rates` mirror
  the existing rule API. The IPC `apply_set_rate` and
  `apply_clear_rate` handlers persist alongside the kernel-map
  update; daemon startup re-applies persisted rates, skipping PIDs
  that no longer have a `/proc/<pid>` (PID reuse defence).
- **Live throughput meter:**
  - Kernel: new `TX_BYTES: HashMap<u32, u64>` map and a 3-line
    increment in `tc_egress` after the verdict.
  - Userspace: `KernelByteCounter` wraps the map; a tokio interval
    task in `daemon::run` samples the counters every second,
    computes per-PID deltas vs. the previous snapshot, and broadcasts
    `Event::Throughput { entries: Vec<ThroughputEntry { pid, bps }> }`.
  - GUI: `SluiceApp` keeps a `HashMap<u32, u64>` of latest
    bytes-per-second; the Bandwidth list now renders
    `pid={N} rate={K KB/s} now={L KB/s} burst={B} B`.
- **Inline form validation in the Bandwidth tab** — failed parsing
  of the PID or rate fields surfaces under the form in red text;
  successful submission resets the error.
- **Recent-PID picker above the Bandwidth Add form** — every
  `Event::Connection` updates a deduped 12-entry deque of
  `(pid, exe basename)` pairs; the picker renders them as one-click
  buttons that fill the PID field.
- **systemd unit** at `packaging/sluiced.service`:
  - `Type=simple`, `Restart=on-failure`.
  - `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_PTRACE`,
    `NoNewPrivileges=true`, `ProtectSystem=strict`,
    `ReadWritePaths=/var/lib/sluice /run/sluice`,
    `ProtectHome=true`, `ProtectKernelLogs=true`.
  - `StateDirectory=sluice` and `RuntimeDirectory=sluice` so systemd
    creates the persistent and runtime dirs.
- **`cargo-deb` metadata** in `sluiced/Cargo.toml`:
  - Maintainer, license, extended description, depends.
  - Assets list ships both binaries, the eBPF bytecode at
    `/usr/lib/sluice/sluice-ebpf`, the systemd unit at
    `/lib/systemd/system/sluiced.service`, README and phases doc
    under `/usr/share/doc/sluice/`.
  - `packaging/debian/postinst` runs `systemctl daemon-reload`;
    `packaging/debian/prerm` stops + disables the service before
    removal.
- **Polished top-level README** — tagline, what-it-does bullets,
  ASCII architecture diagram, build/run quickstart, CLI cheatsheet,
  IPC protocol intro, the 12-phase table linking each `phase-N.md`,
  and the `cargo deb` packaging recipe.

## Architecture Decisions

- **Persisted rates ignore exited PIDs at reload.** PIDs are
  recycled. After a daemon restart we re-apply only entries whose
  `/proc/<pid>` still exists; dead-PID rows are kept in the DB but
  not pushed to the kernel until a future SetRate. A more robust
  identity (exe path + start_time, à la phase 3's cache) would let
  us re-apply across reboots; deferred.
- **`Event::Throughput` skipped from the events feed.** The events
  list shows `Connection` and `Prompt` records — meaningful actions.
  Throughput updates fire every second per PID and would drown the
  feed; the Bandwidth tab is where the user wants them.
- **Recent-PID picker is local, not server-pushed.** The daemon
  already broadcasts every `Event::Connection`; the picker just
  remembers the last 12 seen on the GUI side. No new IPC.
- **`#[derive(Color)]`-style red text via `iced::Color::from_rgb`.**
  iced 0.13 doesn't ship a styled "error" widget; explicit color is
  the smallest possible inline-error renderer.
- **Packaging targets only `.deb`.** Flatpak's sandbox makes eBPF
  attachment ugly (the daemon needs host kernel access; a Flatpak
  bundle wouldn't be the right packaging anyway). RPM is a `.deb`
  ⇨ `alien` away, or a dedicated `cargo-rpm` configuration in a
  follow-up. Both are scope creep for a portfolio piece.
- **Manifest assets reference relative `../target/release/...`
  paths.** `cargo deb` runs from the `sluiced/` crate dir, so paths
  are anchored there. The eBPF bytecode is built separately and
  copied — explicit rather than implicit.

## Current Limits / Future Work

- **No tray icon.** iced 0.13 doesn't ship a tray widget; integrating
  a third-party `tray-icon` crate is a clean next step but takes a
  meaningful slice of code.
- **No process-exit cleanup of `TX_BYTES` / `RATE_LIMITS`.** Both
  kernel maps grow until eviction (LRU never reaches them; capacity
  is 65,536). A `tracepoint:sched_process_exit` handler could clear
  rows, or a userspace `/proc` walk every minute. Listed as a known
  gap since phase 5.
- **No live throughput history graph.** The Bandwidth tab shows the
  current Bps; a sparkline over the last N seconds would be a nice
  upgrade. The data is already broadcast — purely a GUI affordance.
- **No RPM / Flatpak / Snap.** `.deb` ships first because that's
  what the author runs. A `cargo-generate-rpm` config is the natural
  next packager.
- **No CI artifact for `.deb`.** GitHub Actions runs fmt + clippy +
  test today; a release job that produces a tagged `.deb` is the
  obvious follow-up.
- **Inline validation only on Bandwidth.** The Rules form parses
  five fields; surfacing per-field errors there would mirror the
  Bandwidth treatment.
- **Manifest paths are crate-relative.** Building the `.deb` from
  somewhere else (CI matrix, source bundles) would break.
- **No screenshots in the README.** Adding them needs a real desktop
  session and is out of scope for code-only commits.

## Demo

End-to-end exercise of the whole stack:

```sh
# 1. Build everything
cargo run -p xtask -- build-ebpf
cargo build --workspace --release

# 2. Run the daemon under sudo
sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/release/sluiced

# 3. In another terminal, run the GUI
cargo run --release -p sluice

# 4. Click around:
#  • Events tab: see live connections from your browser, ssh, etc.
#  • Rules tab: deny `/usr/bin/curl` to GitHub (`140.82.0.0/16`).
#  • Policy tab: switch default to `ask` and watch prompts arrive.
#  • Bandwidth tab: throttle Firefox to 256 KB/s, see the live meter.

# 5. Restart the daemon — rules and rates persist via SQLite.

# 6. Build a .deb
cargo install cargo-deb
cargo deb -p sluiced
ls target/debian/
```

## Closing thoughts

This is the end of the planned 12-phase build. The repo is a
portfolio-ready demonstration of:

- **Aya eBPF** end-to-end: cgroup hooks, ring buffer, hash maps,
  LRU maps, tc-bpf classifier, BPF type sharing across kernel and
  userspace.
- **Tokio + iced**: a daemon and a GUI that reconnect cleanly,
  push events asynchronously, and stay responsive under live data.
- **SQLite via `rusqlite`**: a small versioned schema with two
  tables that survives daemon restarts.
- **Userspace ergonomics**: a clap-driven CLI, an IPC client/server,
  a tabbed GUI with form validation and a process picker.
- **Linux integration**: cgroup v2, /proc walking, tc qdiscs,
  netlink, systemd unit, `.deb` packaging.

The deliberate scope choices — forward-DNS lookup over tc-bpf
sniffing, mode-B prompt-after-allow, per-PID rather than
per-(PID, destination) — are documented per phase so a reviewer can
see what was bounded and why.
