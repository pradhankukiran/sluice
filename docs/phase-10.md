# Phase 10: Bandwidth Shaping (Kernel)

Phase 10 wires the kernel-side throttling primitive: a `tc-bpf` egress
classifier that consults a per-PID token bucket and drops packets that
exceed the configured rate. PID resolution in tc context — which has
no current task — uses a socket-cookie → PID side map populated by a
`cgroup/sock_create` program at socket creation time.

## Implemented

- **`sluice_common::TokenBucket`** — 32-byte `#[repr(C)]` POD struct
  (`rate_bps`, `burst_bytes`, `tokens`, `last_refill_ns`). Compile-time
  size assertion guards the kernel/userspace layout.
- **Kernel-side maps** (`sluice-ebpf::maps`):
  - `SOCK_PIDS: LruHashMap<u64 cookie, u32 pid>` — populated by
    `cgroup/sock_create`, consumed by the tc classifier.
  - `RATE_LIMITS: HashMap<u32 pid, TokenBucket>` — owned by userspace,
    mutated in place by the classifier.
- **`cgroup/sock_create` program** records `(cookie, current TGID)` on
  every socket creation in the attached cgroup.
- **tc-bpf egress classifier** (`sluice_tc_egress`):
  - Reads `bpf_get_socket_cookie(skb)`, looks up the owning PID.
  - Looks up the PID's `TokenBucket`; passes through if missing or if
    `rate_bps == 0` (the unlimited sentinel).
  - Refills tokens based on elapsed microseconds (capped at 10
    seconds — keeps the multiplications inside u64; the BPF target
    can't link `__multi3` from compiler-rt).
  - Drops with `TC_ACT_SHOT` when `tokens < skb.len()`, otherwise
    decrements and returns `TC_ACT_OK`.
- **`sluiced::attach::attach_cgroup_programs`** now also loads the
  `cgroup/sock_create` program.
- **`sluiced::attach::attach_tc_egress_to_all_interfaces`**:
  - Lists `/sys/class/net` (skipping `lo`, requiring `operstate ∈
    {up, unknown}`).
  - Calls `aya::programs::tc::qdisc_add_clsact` on each — failures
    (likely `EEXIST`) are logged and ignored.
  - Loads + attaches the classifier in `TcAttachType::Egress`.
- **`sluiced::kernel_rates::KernelRateLimits`** wraps the userspace
  side of `RATE_LIMITS`. `set(pid, rate_bps, burst_bytes)`,
  `clear(pid)`, `list() → Vec<(pid, rate, burst)>`. The orphan rule
  is sidestepped via a `#[repr(transparent)]` `PodTokenBucket`
  newtype that locally implements `aya::Pod`.
- **`DaemonHandle.kernel_rates: Arc<Mutex<KernelRateLimits>>`** —
  shared with the IPC server.
- **IPC additions** (`sluice-common::ipc`):
  - `Request::SetRate { pid, rate_bps, burst_bytes }`,
    `Request::ClearRate { pid }`, `Request::ListRates`.
  - `Response::RateUpdated`, `Response::RateCleared`, `Response::Rates
    { entries: Vec<RateEntry> }`.
- **Daemon IPC handlers** (`apply_set_rate` / `apply_clear_rate` /
  `apply_list_rates`) drive the underlying `KernelRateLimits`. Empty
  `burst_bytes` defaults to 1 second of rate (or 64 KiB for
  unlimited).

## Architecture Decisions

- **Cookie → PID instead of PID directly.** tc-bpf programs run in
  softirq context — `bpf_get_current_pid_tgid()` returns kernel-thread
  state, not the user task that owned the syscall. The cookie-side-map
  approach is the canonical Cilium-style answer: capture the PID at
  socket-create time, look it up at egress time. Alternatives
  considered:
  - **`bpf_skb_cgroup_id` + a userspace cgroup → PID mapping.**
    Requires moving each managed PID into its own cgroup; intrusive.
  - **`sk_storage`** (per-socket BPF storage). More elegant but
    cgroup/sock_create has to enroll each socket; net code is the same
    and a separate map is simpler to reason about.
- **`LruHashMap` for `SOCK_PIDS`.** Sockets close all the time;
  without `sock_release` cleanup the map would fill up. LRU eviction
  costs nothing (the kernel does it on insert) and the worst case is
  a stale cookie-PID pair pointing at a recycled cookie.
- **Microsecond resolution for refill math.** Nanosecond × bytes-per-
  second blows past `u64`. Microseconds with a 10-second cap keep the
  math in `u64` and avoid the `__multi3` symbol that BPF targets can't
  link.
- **Race-tolerant token math.** Two cores can simultaneously read,
  refill, and write the same bucket; we accept a few extra packets
  passing through. Per-CPU token buckets eliminate this but add
  reconciliation; not worth it for a desktop firewall.
- **Attach to all UP interfaces, ignore failures.** A virtual
  interface (`docker0`, `vboxnet0`) might not support tc-bpf; the
  daemon shouldn't refuse to start because one of them rejected the
  attach.

## Current Limits

- **First packet from a new socket leaks past the rate limit** if the
  packet egresses before `cgroup/sock_create` is attached. In practice
  the program is loaded at daemon startup so this only matters in a
  narrow window after restart.
- **No CLI rate subcommands.** `sluiced rate set/clear/list` would
  need an IPC client embedded in the CLI binary; deferred until phase
  11 (when the GUI gets sliders) ships the same client logic.
- **No GUI yet.** The IPC requests exist; phase 11 wires up the
  per-process throttle sliders.
- **Per-PID, not per-(PID, destination).** Rate is global per
  process. "Throttle Firefox to 1 MB/s only when talking to Netflix"
  isn't expressible.
- **No persisted rate config.** SQLite stores rules but not rates.
  Rates evaporate on daemon restart. Add a `rates` table when the GUI
  needs persistence.
- **Drops, not delays.** `TC_ACT_SHOT` on overrun matches the
  classic token-bucket recipe but isn't TCP-friendly — userspace TCP
  will retransmit, eventually back off, and the effective throughput
  hovers near the rate. Adding a `tc fq` or `tc tbf` qdisc downstream
  for delay-based shaping is a refinement.
- **Userspace timestamp seeds the bucket.** `KernelRateLimits::set`
  uses wall-clock ns for `last_refill_ns`. The kernel program uses
  `bpf_ktime_get_ns()` — a different epoch. The `wrapping_sub` is
  saturated by `MAX_REFILL_US`, so first-packet behaviour is at worst
  a full bucket; not a correctness bug, but it's an idiosyncrasy
  worth documenting.

## Demo (skeleton — depends on phase 11 GUI for ergonomics)

```sh
cargo run -p xtask -- build-ebpf
cargo build -p sluiced

sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced
```

In another shell, send a `SetRate` request manually (until the GUI
ships the slider):

```sh
PID=$(pgrep firefox | head -1)
echo '{"type":"request","id":1,"body":{"kind":"set_rate","pid":'"$PID"',"rate_bps":1048576,"burst_bytes":1048576}}' \
  | sudo nc -U /run/sluice/sluice.sock
```

Firefox is now capped at 1 MB/s outbound.

## Next Phase

Phase 11 wraps the rate-limit IPC into a Bandwidth tab in the GUI:
per-process throughput sliders, a live read of `Response::Rates`,
and a "remove limit" button per row. The IPC plumbing (request,
response, broadcast on change) is already in place from phase 10.
