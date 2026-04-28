# Phase Plan

The build is broken into 12 phases, each landing as a series of small
commits.

| # | Phase | Focus |
|---|-------|-------|
| 1 | [Workspace Skeleton](phase-1.md) | Cargo workspaces, crate stubs, CI |
| 2 | [Passive Connection Observation](phase-2.md) | `cgroup/connect4`+`connect6` probes, ring-buffer events, daemon log |
| 3 | [PID → Executable Resolution](phase-3.md) | `/proc/<pid>/exe` + cmdline lookup, start_time-keyed cache |
| 4 | [Rules Engine + SQLite](phase-4.md) | Rule schema, match logic, default policy, CLI subcommands |
| 5 | [Active Blocking](phase-5.md) | Per-PID `VERDICTS` map, kernel-side deny, /proc walker, lazy update |
| 6 | [GUI Skeleton + IPC](phase-6.md) | `iced` window + ndjson Unix socket, snapshot + live events |
| 7 | [Live Prompt Dialogs](phase-7.md) | Per-PID Prompt event, Allow/Deny round-trip, kernel map update |
| 8 | [Rules Manager UI](phase-8.md) | Live rule mutation IPC, GUI tabs, add/delete forms, policy selector |
| 9 | [DNS-Aware Rules](phase-9.md) | DnsCache forward-lookup with TTL, HostMatch::Hostname matcher path |
| 10 | [Bandwidth Shaping (Kernel)](phase-10.md) | tc-bpf egress + cookie→PID + per-PID token bucket |
| 11 | Bandwidth Shaping (UI) | Per-process throttle sliders, live throughput meters |
| 12 | Polish & Packaging | Tray icon, autostart, `.deb`/Flatpak |
