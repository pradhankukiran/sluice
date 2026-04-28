//! Userspace handle for the kernel-side `TX_BYTES` map (cumulative
//! per-PID egress byte counters).
//!
//! Sampling: a tokio interval task in [`daemon`] calls
//! [`KernelByteCounter::snapshot`] every `THROUGHPUT_INTERVAL`, computes
//! the delta against the previous snapshot, and broadcasts an
//! [`Event::Throughput`] so the GUI can render a live meter.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Ebpf;

const MAP_NAME: &str = "TX_BYTES";

pub struct KernelByteCounter {
    inner: AyaHashMap<MapData, u32, u64>,
}

impl KernelByteCounter {
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        let map = bpf
            .take_map(MAP_NAME)
            .ok_or_else(|| anyhow!("eBPF object missing map `{MAP_NAME}`"))?;
        let inner: AyaHashMap<MapData, u32, u64> = AyaHashMap::try_from(map)
            .with_context(|| format!("converting `{MAP_NAME}` to HashMap"))?;
        Ok(Self { inner })
    }

    /// All `(pid, total_bytes)` pairs currently in the map. Errors per
    /// entry are silently dropped; the map can be evicted out from
    /// under us by the kernel and that's not worth surfacing.
    pub fn snapshot(&self) -> HashMap<u32, u64> {
        self.inner
            .iter()
            .filter_map(|res| res.ok())
            .collect::<HashMap<u32, u64>>()
    }
}
