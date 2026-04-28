# Phase 8: Rules Manager UI

Phase 8 makes rules and policy live-mutable through the GUI. The
underlying daemon now exposes `AddRule`, `DeleteRule`, and `SetPolicy`
over IPC; rule mutations flow into SQLite, refresh the in-memory
snapshot, repopulate the kernel verdict map, and broadcast a
`RulesChanged` event so every connected GUI updates without polling.

## Implemented

- **IPC surface** (`sluice-common::ipc`):
  - `Request::AddRule { exe, host, port, protocol, verdict }` — same
    string syntax as the CLI
  - `Request::DeleteRule { id }`
  - `Request::SetPolicy { policy }`
  - `Response::RuleAdded { id }`, `Response::RuleDeleted { id }`,
    `Response::PolicyUpdated { policy }`
  - `Event::RulesChanged { rules, default_policy }` — pushed to all
    subscribers after any mutation
- **Shared parsers** (`sluiced::rules::parse`):
  - `parse_exe`, `parse_host`, `parse_port`, `parse_protocol`,
    `parse_verdict`, `parse_policy` — used by both the CLI and the IPC
    `AddRule` handler so the syntax stays in lockstep
- **Live rule state** in `sluiced::daemon`:
  - `rules: Arc<RwLock<Vec<Rule>>>` and `policy: Arc<RwLock<Policy>>`
  - Event handler reads under a brief read lock on each event
  - `fallback_verdict` is computed per-event from the current policy
- **`DaemonHandle`** now carries `rules`, `policy`, and an
  `Arc<Mutex<SqliteRuleStore>>` so the IPC server can mutate from
  the per-connection task
- **AddRule handler** parses each field, inserts into SQLite, calls
  `reload_rules` (refreshes the in-memory snapshot from the DB) and
  `refresh_kernel_map` (clears + re-evaluates against `/proc`), then
  broadcasts `RulesChanged`
- **DeleteRule + SetPolicy handlers** mirror the same shape
- **`KernelVerdictMap::clear_all`** drops every map entry by iterating
  `keys()` and calling `remove()`, so a rule deletion that revokes a
  previously-pushed `Verdict::Deny` doesn't leak the stale entry
- **GUI tab navigation** (Events / Rules / Policy) with the active tab
  visually wider
- **Rules tab**: scrollable list of `RuleSummary` with a Delete button
  per row; below: 5 `text_input` fields (exe / host / port / protocol /
  verdict) and an Add button that dispatches `Request::AddRule`. Form
  resets to sensible defaults (`any`/`any`/`any`/`any`/`deny`) after
  submission
- **Policy tab**: current default + three buttons (Allow, Deny, Ask).
  Click dispatches `Request::SetPolicy`
- **`Event::RulesChanged`** handler in the GUI overwrites local
  `rules` and `default_policy`, so a CLI `sluiced rules add` (against
  the same daemon, in another terminal) propagates without restart

## Architecture Decisions

- **`std::sync::RwLock` for rules + policy.** Reads are far more
  frequent than writes (every connect event reads, IPC mutates). Locks
  are held for microseconds; tokio async locks would add overhead
  without buying anything.
- **Refresh kernel map atomically on every mutation.** A more granular
  approach (add only what changed, evict only what no longer applies)
  is faster for huge rule sets but adds bug surface. With O(10²) rules
  and O(10²–10³) PIDs, the full refresh is a few milliseconds.
- **Snapshot-style `Event::RulesChanged`.** The event carries the full
  new list rather than a delta. Simpler for clients (replace the local
  state); the wire cost is ~one JSON line per mutation.
- **`text_input` over a structured form widget.** iced 0.13's text
  input is a single line per field — sufficient for phase 8. Phase
  12 (polish) could swap in a styled component or inline validation.
- **Form auto-reset after submit.** After `Request::AddRule`, the form
  goes back to the default skeleton so adding a second rule doesn't
  inherit the previous one's fields. Trade-off: a server-side error
  loses the user's input. Inline error display arrives later.
- **Active-tab indication via width.** iced 0.13's `button::Style`
  isn't trivially toggled mid-render; widening the active tab is a
  cheap visual hint without writing a custom widget.

## Current Limits

- **No edit-in-place.** Rules are add or delete only — to change a
  rule, delete it and add a new one. A real edit modal could come in
  phase 12 polish.
- **No "Remember" checkbox on prompts** to insert a rule alongside
  setting the kernel verdict. The user must tab to Rules and add it
  manually.
- **No inline form validation.** A typo (`/usr/bin/curl ` with a
  trailing space) errors out server-side; the GUI swallows the
  `Response::Error` (it's logged to tracing only, not surfaced).
- **Form fields are plain text inputs.** A dropdown for `verdict`
  (allow/deny) and `protocol` (any/tcp/udp) would catch typos earlier.
- **`Event::RulesChanged` is broadcast even when self-mutating.** The
  GUI that sent `AddRule` receives its own `RulesChanged`. Harmless
  but slightly wasteful.

## Demo

```sh
cargo run -p xtask -- build-ebpf
cargo build -p sluiced

sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced

# In another terminal:
cargo run -p sluice
```

In the GUI:

1. Click **Rules**. Type `exe=/usr/bin/curl host=any port=any
   protocol=any verdict=deny`, click **Add rule**.
2. Run `curl https://example.com` — gets ECONNREFUSED.
3. Click **Delete** on the rule. Re-run curl — succeeds.
4. Click **Policy → Ask**. Run a brand-new process that opens a
   socket; the GUI sprouts a "Pending prompts" row.

## Next Phase

Phase 9 introduces DNS-aware rules. We add a small eBPF program that
sniffs UDP/53 responses and pushes (IP → hostname) into a userspace
TTL cache; the matcher gains a `HostMatch::Hostname` arm that
consults the cache; the IPC adds a richer rule input that lets users
type `sluiced rules add --host github.com` and have it match
GitHub's actual IPs.
