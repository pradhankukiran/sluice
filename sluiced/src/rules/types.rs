//! Userspace rule-engine data types.
//!
//! Each [`Rule`] is a 4-tuple match — `(exe, host, port, protocol)` —
//! producing a single [`Verdict`]. Multiple destinations or executables
//! are expressed as multiple rules rather than richer per-rule sets,
//! both for storage simplicity and for the kernel-side flat layout that
//! arrives in phase 5.

use std::net::IpAddr;
use std::path::PathBuf;

pub use sluice_common::Verdict;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    /// Database row id. `0` for un-persisted rules built in memory.
    pub id: i64,
    pub exe_match: ExeMatch,
    pub host: HostMatch,
    pub port: PortMatch,
    pub protocol: ProtocolMatch,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExeMatch {
    /// Match any executable.
    Any,
    /// Exact canonical-path match.
    Exact(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostMatch {
    /// Match any destination.
    Any,
    /// Match a single literal IP (v4 or v6).
    Ip(IpAddr),
    /// CIDR block: `network`/`prefix_len`. Both v4 and v6 supported.
    Cidr { network: IpAddr, prefix_len: u8 },
    /// Hostname pattern. Phase 4 stores it but never matches; phase 9
    /// (DNS) wires up reverse-resolution and enables this branch.
    Hostname(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortMatch {
    Any,
    Single(u16),
    /// Inclusive on both ends.
    Range {
        start: u16,
        end_inclusive: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolMatch {
    Any,
    Tcp,
    Udp,
}

/// Policy applied when no rule matches a connection.
///
/// `Ask` requires the GUI prompt path that arrives in phase 7; in phase 4
/// it falls back to `Allow` with a warning log so the daemon stays
/// usable without a UI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    Allow,
    Deny,
    Ask,
}

impl Policy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Policy::Allow => "allow",
            Policy::Deny => "deny",
            Policy::Ask => "ask",
        }
    }

    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Policy::Allow),
            "deny" => Some(Policy::Deny),
            "ask" => Some(Policy::Ask),
            _ => None,
        }
    }
}
