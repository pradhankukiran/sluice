//! Userspace handle for the kernel-side `RATE_LIMITS` map.
//!
//! Wraps Aya's typed `HashMap<u32, TokenBucket>` so callers don't have
//! to think about the `Pod` impl orphan rule (`TokenBucket` lives in
//! `sluice-common`, `aya::Pod` is in `aya` — neither is local).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::Ebpf;
use sluice_common::TokenBucket;

const MAP_NAME: &str = "RATE_LIMITS";

/// `#[repr(transparent)]` wrapper that lets us implement `aya::Pod`
/// for `TokenBucket` without violating the orphan rule.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodTokenBucket(TokenBucket);

// SAFETY: `TokenBucket` is `#[repr(C)]` with only POD fields and a
// compile-time size assertion in `sluice-common`. No padding bytes
// carry meaning, so it is safe to copy by raw bytes the way Aya's BPF
// map operations do.
unsafe impl aya::Pod for PodTokenBucket {}

pub struct KernelRateLimits {
    inner: AyaHashMap<MapData, u32, PodTokenBucket>,
}

impl KernelRateLimits {
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        let map = bpf
            .take_map(MAP_NAME)
            .ok_or_else(|| anyhow!("eBPF object missing map `{MAP_NAME}`"))?;
        let inner: AyaHashMap<MapData, u32, PodTokenBucket> = AyaHashMap::try_from(map)
            .with_context(|| format!("converting `{MAP_NAME}` to HashMap"))?;
        Ok(Self { inner })
    }

    /// Configure (or re-configure) `pid` to be rate-limited at
    /// `rate_bps` bytes per second with a `burst_bytes` allowance. Pass
    /// `rate_bps == 0` to switch to "unlimited" without removing the
    /// entry; `clear` removes it entirely.
    pub fn set(&mut self, pid: u32, rate_bps: u64, burst_bytes: u64) -> Result<()> {
        let bucket = TokenBucket::new(rate_bps, burst_bytes, monotonic_now_ns());
        self.inner.insert(pid, PodTokenBucket(bucket), 0)?;
        Ok(())
    }

    pub fn clear(&mut self, pid: u32) -> Result<()> {
        match self.inner.remove(&pid) {
            Ok(()) => Ok(()),
            Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(other) => Err(other.into()),
        }
    }

    /// Iterate every entry as `(pid, rate_bps, burst_bytes)`.
    /// Errors per-entry are silently skipped — the kernel can evict
    /// concurrently, so a missing key is benign.
    pub fn list(&self) -> Vec<(u32, u64, u64)> {
        self.inner
            .iter()
            .filter_map(|res| res.ok())
            .map(|(pid, b)| (pid, b.0.rate_bps, b.0.burst_bytes))
            .collect()
    }
}

/// `bpf_ktime_get_ns()` is monotonic since boot. Stdlib doesn't expose
/// the same clock directly, but `Instant` does — except `Instant`
/// can't be converted to `u64` ns. The closest userspace equivalent
/// for seeding `last_refill_ns` is the wall clock; the kernel-side
/// program tolerates an initial timestamp that's slightly in the
/// future or past because the elapsed-time calculation uses
/// `wrapping_sub` and the result is bounded by `MAX_REFILL_US`.
fn monotonic_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
