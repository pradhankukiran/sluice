# Phase 5: Active Blocking

Phase 5 makes the kernel-side programs *do* something. We add a
per-process verdict cache in the kernel; the connect probes look it up
and return 0 (deny) when the user has explicitly told us to. Userspace
keeps the cache populated by walking `/proc` at startup and lazily
updating on first event from a previously-unseen PID.

## Implemented

- **`VERDICTS` BPF hash map** (`BPF_MAP_TYPE_HASH`, capacity 65,536)
  keyed by TGID, valued by `Verdict::as_u32()`. Declared in
  `sluice-ebpf/src/maps.rs`.
- **Kernel-side enforcement** in `cgroup/connect4` and `cgroup/connect6`:
  read TGID, look up `VERDICTS`, return 0 (deny) when the stored
  verdict is `Verdict::Deny`. Otherwise emit the event and return 1
  (allow), preserving phase 2's passive observation.
- **`KernelVerdictMap`** wrapper around Aya's typed `HashMap<u32, u32>`
  with `set` / `has_seen` / `evaluate_and_push` methods. Owns a
  side-table of "seen PIDs" so the daemon doesn't re-walk `/proc` for
  every event from the same process.
- **`matcher::default_verdict_for_exe`** — the subset of the rule
  matcher that returns the verdict applicable when only the executable
  is known. Skips destination-specific rules because the per-PID kernel
  map can't encode them.
- **`/proc` walker** (`KernelVerdictMap::populate_from_proc`) that
  iterates `/proc/[0-9]*` at startup, evaluates exe-only rules for each
  process, and pushes verdicts to the kernel map.
- **Lazy update path** in the daemon's event handler: a process that
  starts after sluiced — or that wasn't matched by any rule at startup —
  gets its verdict evaluated on its first connection event, before the
  next event from the same PID hits the kernel.

## Architecture Decisions

- **Per-PID map, not per-(PID, dest, port).** A two-tier richer map
  (per-process *and* per-destination override) was tempting, but the
  kernel-side hash map can't natively encode wildcards. A single
  per-PID slot covers the common "block app X entirely" rule, which is
  the headline Little Snitch use case. Per-destination rules continue
  to be evaluated in userspace and logged with the
  "would-block-but-can't-yet" verdict.
- **Kernel only branches on `Deny`.** `Allow` and `Unknown` both fall
  through to "emit event + allow." This keeps the kernel program
  short-circuit logic minimal (one comparison, no branchy match). It
  also means a stale `Allow` entry in the map is harmless.
- **Lazy map population on first event.** Walking `/proc` at startup
  catches every running process, but new processes (forked after
  sluiced started) wouldn't have a verdict. We use the connect event
  itself as the "process is now interesting" signal — the first
  connect from an unseen TGID triggers an evaluate-and-push, before
  the *next* event from that PID hits the kernel.
- **First event from a new PID still slips through.** The eBPF program
  runs before the userspace lazy-push completes, so the first event
  from a brand-new PID is allowed even if the rules say deny. Phase 6
  could close the gap with a process-fork tracepoint that pre-populates
  the verdict before any connect can happen; phase 5 accepts this as a
  documented limit because it's the simplest workable model.
- **Compile-time linkage of `Verdict::Deny` into the eBPF program.**
  `const VERDICT_DENY: u32 = Verdict::Deny.as_u32();` in
  `programs/connect4.rs` shares the encoding with userspace via
  `sluice-common`, so an accidental drift between kernel and userspace
  is a compile error rather than a runtime mystery.

## Current Limits

- **Only exe-only rules are enforced in-kernel.** A rule like "deny
  curl talking to 1.1.1.1 on port 443" is still logged in userspace but
  not enforced — the kernel map is too coarse. Phase 6+ can introduce a
  per-(PID, dport, proto) override map for the common destination
  rules.
- **No process-exit cleanup.** When a process exits, its entry stays in
  the kernel map until evicted by `BPF_MAP_TYPE_HASH`'s overflow
  behavior or until sluiced restarts. Worst case: PID is reused before
  cleanup; the new task inherits the old verdict. Phase 6 will hook
  `sched_process_exit` to clear entries.
- **Hot-reload doesn't refresh the kernel map.** Editing rules via
  `sluiced rules add/rm` doesn't propagate to a running daemon — phase
  4 already noted that limit. The kernel map inherits it: it's a
  startup-time snapshot.
- **Default policy isn't pre-pushed.** With `default_policy=deny`, the
  kernel map only contains explicit deny rules; any process not in the
  map falls through to "allow" (because that's the eBPF default).
  Userspace logging still applies the deny correctly. Pre-pushing
  Verdict::Deny for every PID at startup would make the kernel
  enforce deny-by-default; that's a one-line change deferred to a later
  phase.

## End-to-end test

```sh
# Build
cargo run -p xtask -- build-ebpf
cargo build -p sluiced

# Block all curl outbound
sudo SLUICE_DB_PATH=/tmp/sluice.db ./target/debug/sluiced \
    rules add --exe /usr/bin/curl --host any --port any --proto any --verdict deny

# Run the daemon (terminal A)
sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced

# In terminal B, after the "kernel verdict map populated from /proc" line:
curl -m 3 https://example.com
# Expect: curl: (7) Couldn't connect to server   (ECONNREFUSED)
# Daemon log: a `verdict=deny` line for the connection attempt
```

## Next Phase

Phase 6 introduces the GUI: a `sluice` binary built on `iced` that
talks to `sluiced` over a Unix socket. Initially it surfaces the live
event stream and the rule list as read-only views; the prompt-on-new-
connection flow lands in phase 7.
