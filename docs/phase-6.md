# Phase 6: GUI Skeleton + IPC

Phase 6 adds the second process. `sluice` is an `iced` desktop app
that talks to `sluiced` over a Unix socket and renders the live event
stream. The protocol is newline-delimited JSON so it can be debugged
with `nc -U /run/sluice/sluice.sock`.

## Implemented

- **`sluice-common::ipc`** (gated behind `feature = "std"`) — wire-format
  enums:
  - `Frame::{Request, Response, Event}` (top-level tagged envelope)
  - `Request::{Hello, Snapshot, SubscribeEvents}`
  - `Response::{Hello, Snapshot, Subscribed, Error}`
  - `Event::Connection { ... }` for live connection records
  - `RuleSummary` — flat string-typed rule for the GUI
  - `resolve_socket_path()` with `SLUICE_SOCKET_PATH` env override
- **`sluiced::ipc_server`** — `tokio::net::UnixListener` accept loop with
  one task per connection. Handles requests, streams events from the
  shared broadcast channel after `SubscribeEvents`. Sets the socket to
  mode `0666` so an unprivileged GUI can connect to a root-owned socket.
- **`tokio::sync::broadcast::Sender<Event>`** in `daemon::run`. The
  event-handler closure publishes `ipc::Event::Connection` records as
  they arrive; missing subscribers are a no-op.
- **`sluice::ipc_client`** — async client with auto-reconnect: opens the
  socket, performs `Hello → Snapshot → SubscribeEvents`, then forwards
  every server-pushed event as a `ClientMessage`.
- **`sluice::subscription`** — bridges the tokio mpsc the client uses
  into iced's `futures::channel::mpsc` via `iced::stream::channel`.
- **`sluice::app`** — minimal `iced::application` with:
  - Header showing connection state, default policy, rule count
  - Scrollable list of recent connection events (newest first, capped at
    500)

## Architecture Decisions

- **Newline-delimited JSON over the socket.** Length-prefixed bincode
  would be faster but completely opaque; JSON lets a developer paste
  `socat - UNIX-CONNECT:/run/sluice/sluice.sock` and *see* the protocol.
  The volume (≪ kHz events) makes performance immaterial.
- **Tagged enums (`#[serde(tag = "type")]`) for `Frame`.** A single
  socket carries both responses and async events; the tag tells the
  client which arm to decode without a separate channel.
- **Broadcast channel, not mpsc.** Multiple GUIs may eventually attach
  to the same daemon (e.g. tray + window). `tokio::sync::broadcast`
  fans out at no extra cost, drops slow subscribers cleanly, and
  reports lag.
- **Mode 0666 socket on `/run/sluice`.** Single-user box convention;
  sluiced runs as root, sluice runs as the user. A future hardening
  pass would `chown` to a `sluice` group instead.
- **Auto-reconnect on the client side.** The daemon may exit and
  restart; the GUI shouldn't have to. A 2-second backoff loop keeps
  the connect-handshake-subscribe state machine self-healing.
- **`Subscription::run(fn() -> Stream)` constraint.** iced's API takes
  a `fn` pointer (no captures). We work around it by reading
  configuration (socket path) inside the function via env each time it
  is started.
- **Two channels in the GUI.** `ipc_client` uses `tokio::sync::mpsc`
  because the rest of the client is tokio-native; iced uses
  `futures::channel::mpsc`. The subscription bridges them in three
  lines rather than rewriting the client around iced's flavor.

## Current Limits

- **Read-only GUI.** Phase 6 only displays the snapshot and event
  stream. There is no "Allow / Deny" prompt yet (phase 7), no rule
  editor (phase 8), no policy toggle.
- **Snapshot is a single shot.** Rule edits made via `sluiced rules add`
  while the daemon is running don't propagate to the GUI; we'd need a
  push notification or a periodic re-fetch. Phase 8 will add this.
- **Events are not persisted.** The GUI keeps the most recent 500 in
  memory; closing the app loses the history.
- **Hard-coded socket mode.** `0666` is fine for a single-user laptop
  but not for multi-user systems. Phase 12 (packaging) revisits.
- **No reconnect surface in the UI.** The header shows
  `disconnected: <reason>`, but there's no manual "Reconnect" button —
  the loop reconnects on its own every two seconds.

## Running it

Two terminals.

Terminal A (daemon, root for eBPF):

```sh
cargo run -p xtask -- build-ebpf
cargo build -p sluiced
sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced
```

Terminal B (GUI, user):

```sh
cargo run -p sluice
```

The window should report `connected — sluiced 0.1.0`, list the current
rules and policy, and stream connection events as they arrive.

To poke the wire format manually:

```sh
echo '{"type":"request","id":1,"body":{"kind":"hello"}}' \
  | sudo nc -U /run/sluice/sluice.sock
```

## Next Phase

Phase 7 wires up the prompt path: when `Policy::Ask` is the default
policy and an unrecognized process makes its first connection, the
daemon emits an `Event::Prompt { ... }`, the GUI shows a modal, and the
client posts the verdict back via a new `Request::SetVerdict`. The
kernel `VERDICTS` map then short-circuits subsequent connects from the
same process.
