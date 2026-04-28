//! Wire format for connection-attempt events emitted by the eBPF program
//! into a ring buffer and consumed by the userspace daemon.
//!
//! The struct is `#[repr(C)]` and contains only POD fields so it can be
//! safely shared across the kernel/userspace boundary as raw bytes.

/// IPv4.
pub const FAMILY_INET: u16 = 2;
/// IPv6.
pub const FAMILY_INET6: u16 = 10;

/// TCP.
pub const PROTO_TCP: u8 = 6;
/// UDP.
pub const PROTO_UDP: u8 = 17;

/// Length of `task_struct->comm` in the kernel.
pub const COMM_LEN: usize = 16;

/// A connection-attempt event captured in the kernel.
///
/// The `addr` field holds the destination address in network-byte order:
/// the first 4 bytes for `FAMILY_INET`, all 16 bytes for `FAMILY_INET6`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConnectEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub family: u16,
    pub protocol: u8,
    pub _pad0: u8,
    pub dport: u16,
    pub _pad1: u16,
    pub addr: [u8; 16],
    pub comm: [u8; COMM_LEN],
}

const _: () = {
    // Compile-time size pin so accidental field reorderings are caught early.
    // 8 + 4*4 + 2 + 1 + 1 + 2 + 2 + 16 + 16 = 64 bytes.
    assert!(core::mem::size_of::<ConnectEvent>() == 64);
};
