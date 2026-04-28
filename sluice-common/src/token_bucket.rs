//! Per-PID token bucket shared between the tc-bpf egress classifier
//! (kernel side) and the userspace daemon.
//!
//! Layout is `#[repr(C)]` and contains only POD fields so the struct
//! can be stored in a `BPF_MAP_TYPE_HASH` and read on both sides
//! without any serialization layer.

/// 32-byte token-bucket record kept in `RATE_LIMITS`.
///
/// On every egress packet the kernel-side tc program:
///
/// 1. Computes how many bytes' worth of tokens have accumulated since
///    `last_refill_ns`, capped at `burst_bytes`.
/// 2. Subtracts the packet length from `tokens`.
/// 3. Drops the packet (`TC_ACT_SHOT`) when the bucket is empty,
///    otherwise lets it through.
///
/// `rate_bps == 0` is the "unlimited" sentinel and is treated as
/// "always pass."
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    /// Configured rate in bytes per second. `0` means no limit.
    pub rate_bps: u64,
    /// Maximum tokens the bucket holds; cap on burst size.
    pub burst_bytes: u64,
    /// Tokens currently available.
    pub tokens: u64,
    /// `bpf_ktime_get_ns()` value at the most recent refill.
    pub last_refill_ns: u64,
}

const _: () = {
    assert!(core::mem::size_of::<TokenBucket>() == 32);
};

impl TokenBucket {
    /// Build a fresh bucket for the given rate, starting full.
    pub const fn new(rate_bps: u64, burst_bytes: u64, now_ns: u64) -> Self {
        Self {
            rate_bps,
            burst_bytes,
            tokens: burst_bytes,
            last_refill_ns: now_ns,
        }
    }

    /// True iff the bucket is configured to pass everything through
    /// without rate-limiting.
    pub const fn is_unlimited(&self) -> bool {
        self.rate_bps == 0
    }
}
