# Phase Plan

The build is broken into 12 phases, each landing as a series of small
commits.

| # | Phase | Focus |
|---|-------|-------|
| 1 | [Workspace Skeleton](phase-1.md) | Cargo workspaces, crate stubs, CI |
| 2 | [Passive Connection Observation](phase-2.md) | `cgroup/connect4`+`connect6` probes, ring-buffer events, daemon log |
| 3 | [PID → Executable Resolution](phase-3.md) | `/proc/<pid>/exe` + cmdline lookup, start_time-keyed cache |
| 4 | [Rules Engine + SQLite](phase-4.md) | Rule schema, match logic, default policy, CLI subcommands |
| 5 | Active Blocking | Kernel-side rule cache, deny verdicts, cgroup attach |
| 6 | GUI Skeleton + IPC | `iced` window, Unix-socket protocol to `sluiced` |
| 7 | Live Prompt Dialogs | "Allow this connection?" modal, verdict round-trip |
| 8 | Rules Manager UI | List, edit, delete rules; default-policy toggle |
| 9 | DNS-Aware Rules | DNS-reply sniffing, IP→hostname map, hostname matching |
| 10 | Bandwidth Shaping (Kernel) | `tc-bpf` egress, per-PID token buckets |
| 11 | Bandwidth Shaping (UI) | Per-process throttle sliders, live throughput meters |
| 12 | Polish & Packaging | Tray icon, autostart, `.deb`/Flatpak |
