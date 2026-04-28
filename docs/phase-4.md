# Phase 4: Rules Engine + SQLite Persistence

Phase 4 lands the userspace rules engine end-to-end: a SQLite-backed
store, a 4-axis match function, a default policy, and a CLI for
populating rules without a GUI. The eBPF program still always allows —
phase 5 plumbs verdicts back to the kernel.

## Implemented

- **`rules::types`** — `Rule`, `ExeMatch`, `HostMatch`, `PortMatch`,
  `ProtocolMatch`, plus the `Policy` enum (`Allow`/`Deny`/`Ask`).
- **`rules::matcher`** — pure-function match predicate (`matches`) and a
  linear-scan evaluator (`evaluate`). Each axis (exe, host, port,
  protocol) is matched independently.
- **CIDR matching** for both IPv4 and IPv6 (`HostMatch::Cidr`), with
  prefix lengths 0–32 / 0–128. Mixed v4/v6 never matches.
- **Hostname matching is reserved** — `HostMatch::Hostname` is stored
  but never matches in phase 4. Phase 9 (DNS reverse-resolution) lights
  it up.
- **`rules::schema`** — versioned migration runner; one migration
  registered today (initial `rules` + `settings` tables).
- **`rules::store::SqliteRuleStore`** — `open` (creates parent dir),
  `insert`, `list`, `delete`, `default_policy`, `set_default_policy`.
  Match values encoded as compact text tags so `sqlite3 rules.db
  '.dump'` stays human-readable.
- **`rules::store::resolve_db_path`** — `SLUICE_DB_PATH` env override,
  defaults to `/var/lib/sluice/rules.db`.
- **CLI subcommands** via `clap`:
  - `sluiced` (no subcommand) ≡ `sluiced run` — daemon mode
  - `sluiced rules list`
  - `sluiced rules add --exe <any|/path> --host <any|IP|CIDR|hostname>
    --port <any|N|N-M> --proto <any|tcp|udp> --verdict <allow|deny>`
  - `sluiced rules rm <id>`
  - `sluiced policy show`
  - `sluiced policy set <allow|deny|ask>`
- **Daemon hot loop** evaluates each event against the rule snapshot
  loaded at startup, falls back to the default policy, logs the verdict
  it *would* apply.

## Architecture Decisions

- **Snapshot rules at startup, not per-event.** The hot loop runs in a
  tight `cgroup/connect` cycle; querying SQLite per event would add
  meaningful latency. Phase 4 reads all rules once at startup. Live
  rule edits via the CLI take effect on the next daemon restart;
  `SIGHUP`-driven reload arrives in a later phase.
- **Linear scan over rules.** With O(10²) rules per host this is fine;
  the kernel-side cache (phase 5) will be a per-(exe,host,port)
  hash-keyed map, so userspace doesn't have to scale the same way.
- **Text-tagged DB encoding.** `host_match='cidr:10.0.0.0/8'` instead
  of separate `host_kind`/`host_value` columns. One column per axis,
  schema stays narrow, dumps stay grep-able. Trade-off: every change
  to a matcher variant is a codec change too — acceptable while the
  schema is still small.
- **`Policy::Ask` is reserved.** The variant is defined and persisted
  so the CLI surface is forward-compatible, but until phase 7 plumbs
  GUI prompts, encountering `Ask` at startup falls back to `Allow`
  with a single warning.
- **Three-binary CLI in one binary.** `sluiced run` and `sluiced rules
  add` are the same binary so the rules schema and codecs stay in
  exactly one place. The CLI subcommand path doesn't pull in eBPF or
  tokio.
- **`SqliteRuleStore::open_in_memory` is `#[cfg(test)]`.** Production
  always opens a file-backed DB so rules survive restarts; the
  in-memory variant is purely a test affordance.

## Current Limits

- **Still passive.** Verdicts are only logged. Phase 5 wires them into
  a kernel-side rule map and lets `cgroup/connect4`/`connect6` return 0
  for `Deny`.
- **No reload at runtime.** Editing rules with the CLI while the daemon
  is running has no effect until the daemon restarts.
- **No matcher precedence beyond insertion order.** The first matching
  rule wins. We have no priority/weight column; some firewalls offer
  one. Worth revisiting once we have rule conflicts in the wild.
- **No hostname matching.** Stored but ignored until phase 9.

## Examples

Insert a deny-all rule for curl talking to GitHub:

```sh
sudo sluiced rules add \
    --exe /usr/bin/curl \
    --host 140.82.0.0/16 \
    --port any \
    --proto tcp \
    --verdict deny
```

List rules:

```sh
sudo sluiced rules list
[   1] verdict=deny exe=/usr/bin/curl host=140.82.0.0/16 port=any proto=tcp
```

Switch default to deny-by-default:

```sh
sudo sluiced policy set deny
```

## Next Phase

Phase 5 syncs rules into a kernel-side BPF hash map keyed by `(exe
hash, dport, proto)`. The `cgroup/connect4`/`connect6` programs do an
O(1) map lookup; matched-deny entries return 0 (deny); everything else
is escalated to userspace via the existing ring buffer for "Ask"
prompts (which arrive in phase 7).
