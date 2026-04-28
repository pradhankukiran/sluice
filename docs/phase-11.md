# Phase 11: Bandwidth Shaping (UI)

Phase 11 surfaces the kernel-side rate limiter from phase 10 in the
GUI. A new **Bandwidth** tab shows the current rate-limit table and
lets the user add or clear per-PID limits. The IPC plumbing
(`SetRate`, `ClearRate`, `RatesChanged`) was already in place; this
phase wires it into iced widgets.

## Implemented

- **`Event::RatesChanged { entries: Vec<RateEntry> }`** —
  broadcast variant pushed:
  - When the daemon successfully services a `SetRate` or `ClearRate`
    request.
  - Once at the start of every `SubscribeEvents` session, so a freshly
    connected GUI has the initial rate table without a separate
    `ListRates` request.
- **`build_rates_changed_event(handle)`** in `ipc_server` —
  shared helper for both broadcast points; reads the current
  `KernelRateLimits` snapshot.
- **GUI tab navigation** picks up a fourth tab: **Events / Rules /
  Policy / Bandwidth**. Active-tab is widened the same way as the
  others.
- **`SluiceApp.rates: Vec<RateEntry>`** state, refreshed on every
  `Event::RatesChanged`.
- **`SluiceApp.rate_form: RateForm`** holds the in-progress fields
  (`pid`, `rate_kbps`) before submission.
- **Bandwidth view** (`bandwidth_view`):
  - Scrollable list of current entries: `pid={N} rate={K KB/s}
    burst={B} B` with a **Clear** button per row.
  - Add form with two `text_input`s (PID, rate in KB/s) and an
    **Apply limit** button.
  - On submit: parses both fields, multiplies KB/s by 1024 to get
    bytes/sec, dispatches `Request::SetRate` with `burst_bytes` set
    equal to `rate_bps` (1 second of headroom). Form resets on
    successful parse.
- **`Message::ClearRate(pid)`** wired to the per-row button → sends
  `Request::ClearRate`.

## Architecture Decisions

- **KB/s in the UI, bytes/sec on the wire.** Most users think in
  KB/s for desktop bandwidth caps; the daemon stores bytes/sec to
  keep token-bucket math integer-only. The GUI is the only place
  the conversion happens.
- **Burst defaults to 1 second of rate.** A reasonable starting
  point: you tolerate 1 second's worth of burst before the bucket
  empties. Power users who want different burst can set
  `Request::SetRate { burst_bytes: ... }` directly through the IPC.
- **Push updates, not polling.** The daemon broadcasts `RatesChanged`
  on every mutation and once at subscription start. The GUI never
  asks for a snapshot; it just reacts to events. This matches how
  the Rules tab works and avoids drift between concurrent GUIs.
- **Plain `text_input` for PID.** A real "click on a process to
  manage it" flow would let the user pick from the live events
  list. Phase 11 stops at type-the-PID; richer affordances belong in
  phase 12 polish.
- **Form auto-reset on successful parse.** Mirrors the Rules tab's
  behaviour. A parse failure (non-numeric input) silently fails;
  surfacing inline errors comes with the rest of the polish pass.

## Current Limits

- **No live throughput meter.** The displayed rate is the
  *configured* rate, not "what this process is currently sending."
  A real meter needs a per-PID byte counter map populated by the
  same tc-bpf classifier and a tokio interval task that computes
  delta over time. Tractable but out of scope.
- **PID is typed by hand.** A "select a process from recent events"
  affordance would be nicer; would require a process-picker widget.
- **Rates aren't persisted across daemon restarts.** SQLite holds
  rules but not rates — phase 10 noted the same limit. A `rates`
  table + reload on start is a small follow-up.
- **No edit-in-place for existing limits.** Users delete + re-add.
  Same trade-off the Rules tab makes.
- **Burst defaults are coarse.** UI exposes only rate; burst is
  always `rate_bps` bytes. Low-rate, bursty workloads (a few KB
  every minute) can't easily express their needs through the UI.
- **No "select from running processes" picker.** Power users who
  know the PID can act; the rest of us run `pgrep firefox` first.

## Demo

```sh
# Daemon (terminal A)
cargo run -p xtask -- build-ebpf
sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced

# GUI (terminal B)
cargo run -p sluice
```

In the GUI:

1. Click **Bandwidth**.
2. Fire up `iperf3 -c some-server` somewhere (or just open a heavy
   download in Firefox). Get its PID via `pgrep`.
3. Type the PID, type `512` for 512 KB/s, click **Apply limit**.
4. Throughput drops to ~512 KB/s.
5. Click **Clear** on the row to remove the limit.

## Next Phase

Phase 12 is the polish + packaging pass:

- Tray icon + autostart so sluice doesn't need a terminal.
- `.deb` / Flatpak packaging.
- A "select from running processes" picker for the Bandwidth tab.
- Inline form validation (red text under fields with bad input).
- A live throughput meter alongside the configured rate.
- Persisted rates in SQLite (`rates` table + reload on boot).
- README screenshots, SOURCES, and a thorough end-to-end install
  script for the portfolio README.
