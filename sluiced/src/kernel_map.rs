//! Userspace handle for the kernel-side `VERDICTS` map plus the
//! population logic that keeps it in sync with running processes.
//!
//! Wraps Aya's typed `HashMap<u32, u32>` so callers don't have to
//! re-derive the encoding (`Verdict::as_u32`) at every call site, and
//! collects the map manipulation into one auditable surface for tests
//! and tracing.

use std::collections::HashSet;
use std::fs;

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Ebpf;
use sluice_common::Verdict;

use crate::proc_info;
use crate::rules::matcher;
use crate::rules::types::Rule;

const MAP_NAME: &str = "VERDICTS";

pub struct KernelVerdictMap {
    inner: AyaHashMap<MapData, u32, u32>,
    /// PIDs we've already evaluated against the rules at least once.
    /// Used by the daemon's lazy update path to avoid re-evaluating on
    /// every connection event from the same process.
    seen: HashSet<u32>,
}

impl KernelVerdictMap {
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        let map = bpf
            .take_map(MAP_NAME)
            .ok_or_else(|| anyhow!("eBPF object missing map `{MAP_NAME}`"))?;
        let inner: AyaHashMap<MapData, u32, u32> = AyaHashMap::try_from(map)
            .with_context(|| format!("converting `{MAP_NAME}` to HashMap"))?;
        Ok(Self {
            inner,
            seen: HashSet::new(),
        })
    }

    /// Set the kernel-side verdict for `pid`. The kernel-side connect
    /// programs only short-circuit on `Verdict::Deny`; other variants are
    /// accepted but have no effect on enforcement (they record the
    /// userspace decision so the same map can drive future logic).
    pub fn set(&mut self, pid: u32, verdict: Verdict) -> Result<()> {
        self.inner.insert(pid, verdict.as_u32(), 0)?;
        self.seen.insert(pid);
        Ok(())
    }

    /// Whether we've already evaluated rules for `pid`. The daemon hot
    /// path checks this before the more expensive evaluate-and-push
    /// dance.
    pub fn has_seen(&self, pid: u32) -> bool {
        self.seen.contains(&pid)
    }

    /// Evaluate exe-only rules for `pid` and push the result into the
    /// kernel map. Marks `pid` as seen even if no rule matched, so the
    /// caller doesn't re-evaluate it on every subsequent event.
    pub fn evaluate_and_push(&mut self, pid: u32, rules: &[Rule]) -> Result<Option<Verdict>> {
        let verdict = evaluate_for_pid(pid, rules);
        if let Some(v) = verdict {
            self.set(pid, v)?;
        } else {
            // Mark seen even when no rule matched, so the lazy path
            // doesn't repeatedly walk `/proc` for a process that no rule
            // applies to.
            self.seen.insert(pid);
        }
        Ok(verdict)
    }

    /// Walk `/proc`, evaluate rules for every numeric subdirectory, and
    /// push verdicts into the kernel map. Returns `(touched, pushed)`:
    /// the count of PIDs we evaluated and the subset that received a
    /// verdict.
    pub fn populate_from_proc(&mut self, rules: &[Rule]) -> Result<(usize, usize)> {
        let mut touched = 0;
        let mut pushed = 0;
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };
            touched += 1;
            if self.evaluate_and_push(pid, rules)?.is_some() {
                pushed += 1;
            }
        }
        Ok((touched, pushed))
    }
}

/// Pure-IO helper exposed for testing: returns the verdict the kernel map
/// would receive for `pid` given the current rule snapshot, or `None` if
/// the process is unreachable / matched by no exe-only rule.
pub fn evaluate_for_pid(pid: u32, rules: &[Rule]) -> Option<Verdict> {
    let exe = proc_info::read_exe(pid)?;
    matcher::default_verdict_for_exe(rules, &exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::types::{ExeMatch, HostMatch, PortMatch, ProtocolMatch};

    fn allow_all_curl() -> Rule {
        Rule {
            id: 0,
            exe_match: ExeMatch::Exact(std::path::PathBuf::from("/usr/bin/curl")),
            host: HostMatch::Any,
            port: PortMatch::Any,
            protocol: ProtocolMatch::Any,
            verdict: Verdict::Allow,
        }
    }

    #[test]
    fn evaluate_for_pid_returns_none_for_invalid_pid() {
        // PID 0 is reserved and can't have an exe.
        assert_eq!(evaluate_for_pid(0, &[allow_all_curl()]), None);
    }

    #[test]
    fn evaluate_for_pid_returns_none_when_no_rule_matches() {
        // The current test binary's exe path won't be `/usr/bin/curl`,
        // so the curl-only rule shouldn't apply.
        assert_eq!(
            evaluate_for_pid(std::process::id(), &[allow_all_curl()]),
            None
        );
    }
}
