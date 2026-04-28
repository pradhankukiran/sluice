// Wired into daemon::run via the populator + event handler in subsequent
// commits this phase.
#![allow(dead_code)]

//! Userspace handle for the kernel-side `VERDICTS` map.
//!
//! Wraps Aya's typed `HashMap<u32, u32>` so callers don't have to
//! re-derive the encoding (`Verdict::as_u32`) at every call site, and
//! collects the map manipulation into one auditable surface for tests
//! and tracing.

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Ebpf;
use sluice_common::Verdict;

const MAP_NAME: &str = "VERDICTS";

pub struct KernelVerdictMap {
    inner: AyaHashMap<MapData, u32, u32>,
}

impl KernelVerdictMap {
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        let map = bpf
            .take_map(MAP_NAME)
            .ok_or_else(|| anyhow!("eBPF object missing map `{MAP_NAME}`"))?;
        let inner: AyaHashMap<MapData, u32, u32> = AyaHashMap::try_from(map)
            .with_context(|| format!("converting `{MAP_NAME}` to HashMap"))?;
        Ok(Self { inner })
    }

    /// Set the kernel-side verdict for `pid`. The kernel-side connect
    /// programs only short-circuit on `Verdict::Deny`; other variants are
    /// accepted but have no effect on enforcement (they record the
    /// userspace decision so the same map can drive future logic).
    pub fn set(&mut self, pid: u32, verdict: Verdict) -> Result<()> {
        self.inner.insert(pid, verdict.as_u32(), 0)?;
        Ok(())
    }

    /// Remove the verdict for `pid` (e.g. after a process exits or a rule
    /// reload reverts a previous decision). `Ok(())` even if the entry
    /// was already absent.
    pub fn clear(&mut self, pid: u32) -> Result<()> {
        match self.inner.remove(&pid) {
            Ok(()) => Ok(()),
            Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(other) => Err(other.into()),
        }
    }
}
