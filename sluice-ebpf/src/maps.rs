//! eBPF maps shared between programs in this object.

use aya_ebpf::{macros::map, maps::RingBuf};

/// 1 MiB ring buffer carrying `ConnectEvent` records to userspace.
///
/// Ring-buffer size must be a power-of-two multiple of the page size; 1 MiB
/// satisfies that on every Linux page configuration we care about (4K/16K/64K).
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);
