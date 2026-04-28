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

use std::fs;
use std::io;
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

/// Read `/proc/<pid>/stat` and return field 22 (`starttime`).
///
/// `man 5 proc` warns: field 2 (`comm`) is parenthesised but the *content*
/// can contain any byte — including `)` and whitespace — so naive
/// `split_ascii_whitespace` breaks for processes named e.g. `bash (login)`.
/// We find the *last* `)`, then count fields from there.
pub fn read_start_time(pid: u32) -> io::Result<u64> {
    let path = format!("/proc/{pid}/stat");
    let raw = fs::read_to_string(&path)?;
    parse_start_time(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("could not parse start_time from {path}"),
        )
    })
}

fn parse_start_time(raw: &str) -> Option<u64> {
    let last_paren = raw.rfind(')')?;
    let after_comm = raw.get(last_paren + 1..)?.trim_start();
    // After comm, fields 3..N are space-separated. starttime is field 22,
    // so the 20th element (zero-indexed: 19).
    let mut iter = after_comm.split_ascii_whitespace();
    let starttime = iter.nth(19)?;
    starttime.parse().ok()
}

/// Resolve `/proc/<pid>/exe` (a symlink to the executable). Returns `None`
/// for kernel threads, exited processes, or processes the daemon can't
/// inspect (different user without `CAP_SYS_PTRACE`).
pub fn read_exe(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_stat(comm: &str, starttime: u64) -> String {
        // 1234 (comm) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 <starttime> ...
        // Fill 22 fields after comm with placeholders; field 20 (zero-index 19)
        // becomes starttime.
        let pre = "R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0";
        format!("1234 ({comm}) {pre} {starttime} 0 0 0 0 0 0\n")
    }

    #[test]
    fn parses_normal_process_name() {
        let raw = fake_stat("bash", 5_432_100);
        assert_eq!(parse_start_time(&raw), Some(5_432_100));
    }

    #[test]
    fn handles_close_paren_inside_comm() {
        let raw = fake_stat("weird ) name", 9_999);
        assert_eq!(parse_start_time(&raw), Some(9_999));
    }

    #[test]
    fn handles_spaces_inside_comm() {
        let raw = fake_stat("proc with spaces", 42);
        assert_eq!(parse_start_time(&raw), Some(42));
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(parse_start_time(""), None);
        assert_eq!(parse_start_time("no parens here"), None);
    }

    #[test]
    fn read_exe_resolves_current_process() {
        // The test binary itself must be readable via /proc/self/exe.
        let exe = read_exe(std::process::id()).expect("test binary exe");
        let canonical = std::fs::canonicalize(&exe).expect("canonicalize exe");
        assert!(canonical.is_absolute());
        assert!(
            canonical
                .file_name()
                .and_then(|s| s.to_str())
                .map(|name| name.contains("sluiced"))
                .unwrap_or(false),
            "expected sluiced test binary, got {canonical:?}"
        );
    }

    #[test]
    fn read_exe_returns_none_for_invalid_pid() {
        // PID 0 is reserved by the kernel and never a real process.
        assert_eq!(read_exe(0), None);
    }
}
