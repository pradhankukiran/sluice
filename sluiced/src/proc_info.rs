// `dead_code` is allowed while phase 3 is being built up — items are
// removed from this list once `read` and the cache are wired into main.
#![allow(dead_code)]

//! Userspace process metadata sampled from `/proc/<pid>/...`.
//!
//! For every connection event the kernel gives us a 16-byte truncated
//! `comm` and a TGID. That's enough to label a log line, but not enough
//! to write meaningful firewall rules ("`firefox` could be any of three
//! browsers; the rule should match `/usr/lib/firefox/firefox`"). This
//! module fills in the gap: canonical executable path, full argv, and a
//! per-process freshness key derived from `/proc/<pid>/stat`.

use std::path::PathBuf;

/// Snapshot of userspace metadata for one process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcInfo {
    pub pid: u32,
    /// Boot-relative start time from `/proc/<pid>/stat` field 22, used as
    /// a cheap reuse-detector: when the kernel recycles a PID, the new
    /// task has a different `start_time`, so the cache invalidates itself.
    pub start_time: u64,
    /// Canonical executable path from `/proc/<pid>/exe` (a symlink). May
    /// be `None` for kernel threads or if the process exited before we
    /// resolved the link.
    pub exe: Option<PathBuf>,
    /// Argv as the kernel sees it (`/proc/<pid>/cmdline`, NUL-separated).
    /// Empty for kernel threads.
    pub cmdline: Vec<String>,
}
