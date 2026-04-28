# Phase 9: DNS-Aware Rules

Phase 9 makes `HostMatch::Hostname` rules actually match. A user can
now add a rule like

```sh
sluiced rules add --exe any --host github.com --port 443 \
                  --proto tcp --verdict deny
```

and have it apply to every IP that resolves from `github.com`.

## Implemented

- **`sluiced::dns_cache::DnsCache`** — `HashMap<String, Resolved>` with
  per-entry `expires_at`. Methods: `lookup`, `contains`, `insert`,
  `purge_expired`, `len`, `is_empty`, `stale_targets`,
  `apply_resolutions`, `refresh_for_rules`.
- **`resolve(hostname)`** — async helper around
  `tokio::net::lookup_host` that returns a sorted, deduplicated
  `Vec<IpAddr>`. The synthetic port `0` is appended internally and
  stripped from the result.
- **`refresh_shared(Arc<RwLock<DnsCache>>, &[Rule])`** — workflow that
  read-locks the cache to compute stale targets, drops the lock, runs
  the async resolves, then write-locks once at the end to apply the
  batch. This pattern is what lets the IPC mutation handler spawn a
  refresh task without violating tokio's `Send` bound on
  `RwLockWriteGuard`.
- **Matcher integration** — `matches`/`evaluate` now take an
  `Option<&DnsCache>`. The `HostMatch::Hostname(name)` arm calls
  `cache.contains(name, event_ip)`. Tests cover both the cached-hit
  and missing-cache paths.
- **Daemon startup** primes the cache against the loaded rules
  (`refresh_for_rules` on the owned `DnsCache` before wrapping it in
  `Arc<RwLock<…>>`), so the very first connection event is matched
  against fresh resolutions.
- **Daemon hot loop** read-locks the cache and passes the guard into
  `matcher::evaluate`. Read locks are uncontended in practice — the
  only writers are the IPC mutation handlers.
- **AddRule / DeleteRule handlers** spawn a background DNS refresh
  task after the SQL + kernel-map work, so newly added hostname rules
  become matchable as soon as resolution completes.

## Architecture Decisions

- **Forward lookup over reverse-mapping DNS sniffer.** A more thorough
  approach attaches a `tc-bpf` ingress program to the system's network
  interfaces, captures UDP/53 responses, parses the DNS protocol in
  userspace, and back-maps observed IPs → hostnames the application
  *actually* asked for. That correctly handles geo-DNS, CDN edges, and
  apps with their own resolvers (Go, V8, custom resolvers in some
  game clients). It's also several hundred lines of careful packet-
  parsing code, an ingress attachment per NIC, and a compatibility
  surface I'd rather not own for a portfolio milestone. Phase 9 takes
  the simpler, sufficient-for-the-demo path: resolve hostnames
  ourselves and match against the resulting IP set. The trade-off is
  documented under "Current Limits" so a reader knows it's a deliberate
  scoping choice, not an oversight.
- **Fixed 5-minute TTL.** Stdlib's resolver doesn't expose the
  authoritative DNS TTL. A 5-minute window beats DNS-rebinding
  paranoia for short-lived rule sets and matches typical CDN TTLs.
  Swapping in a real-TTL resolver (`hickory-resolver`) is a
  one-dependency change if/when it matters.
- **`std::sync::RwLock` for the cache.** Reads happen on every event
  (hot path); writes happen at startup and once per rule mutation
  (cold path). RwLock matches the access pattern. We never hold the
  guard across `.await` thanks to `refresh_shared`.
- **Resolves run inside the runtime, not `spawn_blocking`.**
  `tokio::net::lookup_host` is already a thin async wrapper that
  internally uses `getaddrinfo` on a thread pool. Calling it directly
  is the canonical recipe.
- **`stale_targets` + `apply_resolutions` split.** This is the only
  pair of methods that ever needs to span a lock release. Keeping
  them as named primitives makes the locking discipline explicit
  rather than load-bearing-comment.
- **Refresh on rule mutation is fire-and-forget.** `AddRule` returns
  `RuleAdded` immediately; the spawned task fills the cache when DNS
  responds. Worst case: a connection that races the refresh by < 1s
  matches against an empty cache and falls through to the default
  policy. Acceptable trade-off vs. blocking the request.

## Current Limits

- **No live DNS sniffing.** If an app talks to an IP that wasn't in
  *our* resolution of the rule's hostname (geo-DNS shifts, CDN
  shuffling, the app uses its own resolver), the rule misses. The
  `tc-bpf` route is the proper fix and would be a natural phase
  10.5 / 12 follow-up.
- **No reverse PTR lookups.** The matcher knows "this hostname
  resolves to these IPs," not "this IP belongs to this hostname."
  PTR lookups are slow and frequently absent for cloud IPs; reverse
  mapping would normally come from sniffing forward queries (see
  above), not from PTR.
- **TTL is uniform.** All entries expire after `DEFAULT_TTL`
  (5 minutes) regardless of the actual DNS record's TTL.
- **No periodic refresh.** Stale entries are refreshed lazily on the
  next mutation; a long-running daemon's cache won't auto-renew until
  someone touches the rules. A future tokio interval task could refresh
  every `DEFAULT_TTL` to keep things hot.
- **Resolution failures are silent for the connection.** If
  `getaddrinfo` fails (network down, hostname doesn't exist), the
  hostname rule simply doesn't match — the user sees the connection
  log line without any indication that the rule failed to resolve.
- **No `*.example.com` glob support.** Wildcard hostnames are a
  natural extension but require a different match algorithm.

## Demo

```sh
# Build & launch
cargo run -p xtask -- build-ebpf
cargo build -p sluiced

sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced rules add \
         --exe any --host github.com --port 443 --proto tcp --verdict deny

sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced
```

Daemon log on start: `DNS cache primed cached_hostnames=1`.
`curl -m 3 https://github.com` returns ECONNREFUSED.
`curl -m 3 https://example.com` succeeds.

## Next Phase

Phase 10 introduces the kernel-side bandwidth shaping primitive: a
`tc-bpf` egress program that consults a per-PID token-bucket map and
drops or delays packets that exceed the bucket's rate. The userspace
daemon refills the buckets on a tokio interval. Phase 11 wires this
into the GUI as per-process throughput sliders.
