//! tc-bpf classifier on egress: per-PID token-bucket rate limiting.
//!
//! On every egress packet:
//!
//! 1. Read the packet's socket cookie.
//! 2. Look up `SOCK_PIDS[cookie]` to find the owning PID.
//! 3. Look up `RATE_LIMITS[pid]` to find the configured bucket.
//! 4. Refill the bucket based on elapsed time, capped at `burst_bytes`.
//! 5. If the bucket has enough tokens for `skb.len()`, decrement and
//!    return `TC_ACT_OK`; otherwise drop with `TC_ACT_SHOT`.
//!
//! Mutations on the bucket use `get_ptr_mut` and are unprotected by
//! locks — concurrent tc-bpf invocations on multiple cores can race
//! and slightly over-allow. For a single-user desktop's workload this
//! is fine; per-CPU buckets are an upgrade path.

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, gen::bpf_get_socket_cookie},
    macros::classifier,
    programs::TcContext,
};

use crate::maps::{RATE_LIMITS, SOCK_PIDS, TX_BYTES};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

const NS_PER_US: u64 = 1_000;
const US_PER_S: u64 = 1_000_000;
/// Cap elapsed time used for refill at 10 seconds. Idle beyond that
/// just refills to burst — exact arithmetic isn't needed and bounding
/// keeps the multiplications inside u64 on the BPF target (no 128-bit
/// ops; `__multi3` isn't available).
const MAX_REFILL_US: u64 = 10 * US_PER_S;

#[classifier]
pub fn sluice_tc_egress(ctx: TcContext) -> i32 {
    decide(&ctx).unwrap_or(TC_ACT_OK)
}

fn decide(ctx: &TcContext) -> Option<i32> {
    // Get the socket cookie from the skb. Cookie 0 means "no socket"
    // (raw control traffic, etc.) — pass through.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.skb.skb as *mut _) };
    if cookie == 0 {
        return Some(TC_ACT_OK);
    }

    let pid = unsafe { SOCK_PIDS.get(&cookie) }.copied()?;

    // Increment the per-PID byte counter regardless of whether the
    // bucket lets the packet through — userspace can compute "drop
    // rate" later if it wants. Races between cores produce undercount
    // but never go backwards.
    let pkt_len = ctx.len() as u64;
    let prev = unsafe { TX_BYTES.get(&pid) }.copied().unwrap_or(0);
    let _ = TX_BYTES.insert(&pid, &(prev + pkt_len), 0);

    let bucket_ptr = RATE_LIMITS.get_ptr_mut(&pid)?;
    // SAFETY: `get_ptr_mut` returns a valid map pointer (`Some`) only
    // when an entry exists; we hold it for the duration of this
    // single-CPU softirq invocation.
    let bucket = unsafe { &mut *bucket_ptr };

    // rate_bps == 0 is the "unlimited" sentinel; no work, just pass.
    if bucket.rate_bps == 0 {
        return Some(TC_ACT_OK);
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let elapsed_ns = now_ns.wrapping_sub(bucket.last_refill_ns);
    let mut elapsed_us = elapsed_ns / NS_PER_US;
    if elapsed_us > MAX_REFILL_US {
        elapsed_us = MAX_REFILL_US;
    }
    // tokens to add = rate_bps * elapsed_us / 1e6. With elapsed_us
    // capped at 1e7 and rate_bps bounded by what userspace allows
    // (well under 1e10 in practice), this fits in u64 without overflow.
    let added = bucket.rate_bps * elapsed_us / US_PER_S;
    let mut tokens = bucket.tokens + added;
    if tokens > bucket.burst_bytes {
        tokens = bucket.burst_bytes;
    }
    bucket.last_refill_ns = now_ns;

    if tokens >= pkt_len {
        bucket.tokens = tokens - pkt_len;
        Some(TC_ACT_OK)
    } else {
        bucket.tokens = tokens;
        Some(TC_ACT_SHOT)
    }
}
