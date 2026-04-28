# Phase 7: Live Prompt Dialogs

Phase 7 closes the loop between user and kernel. When `default_policy =
Ask` and an unrecognized process makes its first outbound connect, the
daemon emits an `Event::Prompt` to every connected GUI. The user
clicks **Allow** or **Deny**; the GUI sends `Request::SetVerdict`; the
daemon updates the kernel `VERDICTS` map. From that moment on, the
kernel short-circuits subsequent connects from the same PID.

## Implemented

- **`sluice-common::ipc`** extensions:
  - `Event::Prompt { pid, exe, cmdline, family, protocol, addr, dport }`
  - `Request::SetVerdict { pid, verdict }`
  - `Response::VerdictApplied { pid, verdict }`
- **Daemon prompt emission** (`sluiced::daemon`):
  - `pending_prompts: Arc<Mutex<HashSet<u32>>>` deduplicates per-PID prompts
  - When `policy=Ask` and a connection has no rule match and the PID isn't
    already pending, emit `Event::Prompt` and mark pending
  - Subsequent connects from the same PID don't re-prompt until the user
    decides
- **Daemon SetVerdict handler** (`sluiced::ipc_server`):
  - `DaemonHandle { kernel_map, pending_prompts }` shared with the IPC server
  - `apply_verdict` parses `"allow"`/`"deny"`, updates the kernel `VERDICTS`
    map, removes the PID from `pending_prompts`, replies with `VerdictApplied`
  - Errors in any step come back as `Response::Error`
- **Bidirectional `ipc_client`** (`sluice::ipc_client`):
  - `connect_and_run` now takes a `mpsc::UnboundedReceiver<Request>`
  - Inside the streaming session, `tokio::select!` on `reader.next_line` AND
    `requests.recv` so the GUI can post requests after subscribing
- **`OnceLock<UnboundedSender<Request>>`** (`sluice::subscription`):
  - Global request channel installed by the iced subscription on first run
  - `send_request(Request)` lets the iced `update` function post requests
    synchronously from any handler
- **GUI prompts UI** (`sluice::app`):
  - `pending_prompts: VecDeque<PendingPrompt>` in app state
  - `Event::Prompt` → push to list (deduped by PID)
  - Top-of-window section renders each pending prompt with **Allow** /
    **Deny** buttons
  - Clicking dispatches `SetVerdict` and removes from the list

## Architecture Decisions

- **Mode B "first-connect slips through".** The kernel can't block while
  waiting for a user, so the first event from an unprompted PID is
  allowed by the eBPF program, the user gets the prompt, and the
  verdict applies to *future* connects. Mode A (deny first → ask →
  retry) is more secure but requires either kernel-side state for "I
  asked but haven't heard back" or rejecting the syscall and waiting
  for the application to retry. Phase 7 deliberately picks the simpler
  model and documents the gap.
- **Per-PID dedup, not per-(PID, dest, port).** Little Snitch shows one
  prompt per (app, destination); sluice phase 7 shows one per app. Per-
  destination prompting needs a richer kernel map (phase 8+) and a
  more careful UI to keep the user from being spammed.
- **Verdicts don't persist as rules.** Phase 7 only updates the in-
  kernel map. After daemon restart, the verdict is gone. Phase 8 will
  add a "Remember" toggle that also inserts a rule via the existing
  `SqliteRuleStore`.
- **Global request channel via `OnceLock`.** iced's `Subscription::run`
  takes a `fn` pointer (no captures). Putting the request sender behind
  a `OnceLock` lets the synchronous `update` function post requests
  without restructuring the iced state model. Trade-off: implicit
  global, one channel per process. Acceptable for a single-window app.
- **`Arc<Mutex<KernelVerdictMap>>` instead of a channel.** `SetVerdict`
  is rare and short — a quick `.set()` on a `HashMap`-backed BPF map.
  A blocking lock is simpler than serializing through another tokio
  channel and never measurably slow.

## Current Limits

- **First connect always slips through** (the mode-B trade-off).
- **No "Remember" / rule persistence.** Verdicts are runtime-only.
- **Single-prompt-per-PID.** A process whose connections span many
  destinations gets one decision applied to all of them.
- **Allow flips kernel map to `Verdict::Allow`,** even though the
  kernel only branches on `Verdict::Deny`. Storing `Allow` is harmless
  but redundant; future work could clear the entry instead.
- **No cross-GUI sync of prompt resolution.** If two GUIs are open
  and one resolves a prompt, the other still shows it until its next
  reconnect or until a future `Event::PromptResolved` is added.
- **Process exit isn't tracked.** A user who clicks Deny on PID X,
  then later spawns a new process that happens to get the same PID,
  will inherit the old Deny entry. Phase 5 noted the same gap; phase
  9+ should hook `sched_process_exit` to clear stale entries.

## Demo

```sh
# Build & start daemon (terminal A) with Ask policy
cargo run -p xtask -- build-ebpf
cargo build -p sluiced

sudo SLUICE_DB_PATH=/tmp/sluice.db ./target/debug/sluiced policy set ask
sudo SLUICE_DB_PATH=/tmp/sluice.db \
     SLUICE_EBPF_BYTECODE=$PWD/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf \
     ./target/debug/sluiced

# In terminal B: launch the GUI
cargo run -p sluice
```

Run `curl https://example.com` in a third terminal:

1. Connection succeeds (mode B).
2. The Sluice GUI grows a "Pending prompts" section showing
   `/usr/bin/curl pid=… → 93.184.216.34:443 (tcp)`.
3. Click **Deny**. Daemon log:
   `INFO sluiced: applied verdict from GUI pid=… verdict=deny`.
4. Run `curl …` again. It now fails with `ECONNREFUSED` — the kernel
   `VERDICTS` map shorts the connect.

## Next Phase

Phase 8 builds the rule manager UI on top of the IPC plumbing: a
sortable rule list, add/edit/delete with form validation, default-
policy toggle, and a "Remember" checkbox on prompts that persists the
decision via a new `Request::AddRule`.
