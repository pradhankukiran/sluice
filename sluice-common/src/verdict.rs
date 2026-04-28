//! Verdict the eBPF program reads from a per-rule map to decide whether to
//! permit an outbound connection.

/// Encoded as a `u32` in eBPF maps so the kernel-side program can branch on
/// it without pulling in Rust enum machinery.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// No rule has been recorded yet — the eBPF program should escalate to
    /// userspace via the event ring buffer and apply the daemon's default
    /// policy in the meantime.
    Unknown = 0,
    /// Permit the connection.
    Allow = 1,
    /// Block the connection (the cgroup/connect program returns 0).
    Deny = 2,
}

impl Verdict {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn from_u32(value: u32) -> Self {
        match value {
            1 => Verdict::Allow,
            2 => Verdict::Deny,
            _ => Verdict::Unknown,
        }
    }
}
