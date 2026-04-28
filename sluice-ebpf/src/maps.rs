//! eBPF maps shared between programs in this object.

use aya_ebpf::{
    macros::map,
    maps::{HashMap, RingBuf},
};

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
