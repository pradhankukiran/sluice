# Phase 3: PID → Executable Resolution

Phase 3 enriches every connection event with userspace process metadata
read from `/proc/<pid>/`. The kernel only gives us a 16-byte truncated
`comm` (process name) — fine for logs, but not enough to write
meaningful firewall rules. Phase 3 resolves the **canonical executable
path** and **full argv**, with a cache that handles PID reuse.

## Implemented

- **`proc_info::ProcInfo`** struct holding `pid`, `start_time` (boot
  jiffies), `exe: Option<PathBuf>`, and `cmdline: Vec<String>`.
- **`proc_info::read_start_time`** — parens-safe parser for
  `/proc/<pid>/stat` field 22. Handles process names containing `)` or
  whitespace (a real `man 5 proc` gotcha).
- **`proc_info::read_exe`** — `fs::read_link("/proc/<pid>/exe")` with
  `Option<PathBuf>` for kernel threads / exited processes / EPERM.
- **`proc_info::read_cmdline`** — splits NUL-separated argv, drops empty
  segments (handles trailing NULs and processes that pad with extra NULs
  like nginx workers).
- **`proc_cache::ProcInfoCache`** — bounded HashMap (default 1024
  entries) with FIFO eviction. Keyed by PID, with `start_time` as the
  freshness check: if the kernel recycles a PID, the cached entry is
  refreshed transparently.
- **Event handler integration** — every `ConnectEvent` now flows through
  `cache.lookup_or_fetch(event.tgid)` before logging.
- **`formatter::format_enriched_event`** — uses the resolved exe path as
  the process label when available; falls back to `comm` for kernel
  threads. Cmdline is surfaced as a structured tracing field.

## Architecture Decisions

- **`(pid, start_time)` as the cache freshness key.** PIDs wrap and get
  reused. Without a freshness check, a long-running daemon's cache would
  grow stale and silently mislabel connections after a fork-bomb cycle.
  `start_time` from `/proc/<pid>/stat` is the canonical "is this still
  the same task?" signal in Linux — same trick `htop`, `procps`, and
  `psutil` use.
- **Sync `/proc` reads, not tokio file IO.** `/proc` is a virtual
  filesystem; reads are synchronous in the kernel anyway and finish in
  microseconds. Using async file IO here would add overhead without
  any latency benefit.
- **FIFO eviction over LRU.** Cache hit rate is dominated by
  long-lived chatty processes (browsers, IDEs); they stay hot regardless
  of policy. FIFO is one HashMap + one VecDeque, no extra dep. Upgrading
  to LRU is a one-line swap to `indexmap` if profiling shows it matters.
- **`exe` is `Option<PathBuf>`, not a hard error.** Phase 4's rule
  engine needs the exe path, but the daemon should never panic on a
  missing one — kernel threads have no exe, processes can exit between
  the BPF event and our `/proc` read.

## Current Limits

- **No async refresh.** `lookup_or_fetch` is synchronous on the event
  hot path. For a desktop with O(10) connections/sec it's fine; under a
  pathological connection storm we'd want the lookups to happen on a
  worker thread.
- **No symlink chase.** `read_link` returns the immediate target; if a
  binary is invoked through a symlink chain (`/usr/bin/python →
  /etc/alternatives/python → /usr/bin/python3.12`) we record the
  innermost target, which is usually what rules should match against.
  Worth verifying against real workloads in phase 4.
- **Setuid edge cases.** `/proc/<pid>/exe` is unreadable for setuid
  binaries from a non-root daemon. Sluiced runs as root, so this is
  fine — but it's a sharp edge if we ever split the daemon further.

## Running it

Same as phase 2: `cargo run -p xtask -- build-ebpf` then run `sluiced`
under sudo. Log lines now include the full exe path:

```
INFO sluice::connect: /usr/lib/firefox/firefox pid=4040 uid=1000 -> 140.82.121.4:443 (TCP) cmdline=["firefox", "--no-remote"]
```

## Next Phase

Phase 4 adds the rules engine: a SQLite-backed rule store, a match
function (exe path + destination + port), and a default policy
(allow / deny / ask). Verdicts are still returned in userspace and the
eBPF program is still passive — the kernel-side rule cache and active
blocking arrive in phase 5.
