//! eBPF maps shared between programs in this object.

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, RingBuf},
};
use sluice_common::TokenBucket;

/// 1 MiB ring buffer carrying `ConnectEvent` records to userspace.
///
/// Ring-buffer size must be a power-of-two multiple of the page size; 1 MiB
/// satisfies that on every Linux page configuration we care about (4K/16K/64K).
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Per-process verdict cache. Userspace populates this with the result of
/// evaluating exe-only rules against each running process; the connect
/// programs do an O(1) lookup keyed by TGID and short-circuit on
/// `Verdict::Deny`. Capacity is generous — a desktop typically has
/// ~hundreds of processes; phones / busy servers, low thousands.
#[map]
pub static VERDICTS: HashMap<u32, u32> = HashMap::with_max_entries(65_536, 0);

/// Socket cookie → owning TGID. Populated by the `cgroup/sock_create`
/// program at socket creation time. The tc-bpf egress classifier uses
/// this to attribute packets to PIDs (tc-bpf runs in softirq context
/// so `bpf_get_current_pid_tgid` would be wrong).
///
/// LRU-evicting because we don't currently track socket close —
/// long-running daemons would otherwise grow this map indefinitely.
#[map]
pub static SOCK_PIDS: LruHashMap<u64, u32> = LruHashMap::with_max_entries(131_072, 0);

/// Per-PID token-bucket state for egress rate limiting. Configured by
/// userspace via the `RateLimits` wrapper; mutated in-place by the
/// tc-bpf classifier on every packet.
#[map]
pub static RATE_LIMITS: HashMap<u32, TokenBucket> = HashMap::with_max_entries(65_536, 0);
