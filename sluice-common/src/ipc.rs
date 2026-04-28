//! Wire format for IPC between `sluiced` (privileged daemon) and
//! `sluice` (unprivileged GUI).
//!
//! Each frame is one JSON object terminated by a `\n` so both ends can
//! use line-buffered IO. The schema is intentionally string-typed for
//! verdicts/protocols/families — easy to evolve, easy to read with
//! `socat` or `nc -U /run/sluice/sluice.sock`.
//!
//! This module is `std`-gated; the `sluice-ebpf` (kernel-side) crate
//! depends on `sluice-common` with `default-features = false` and
//! never compiles this code.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const SOCKET_ENV: &str = "SLUICE_SOCKET_PATH";
pub const DEFAULT_SOCKET_PATH: &str = "/run/sluice/sluice.sock";

/// Resolve the Unix socket path used by both daemon and GUI. The daemon
/// creates the socket; the GUI connects to it. Override via the
/// `SLUICE_SOCKET_PATH` environment variable for development without
/// `/run/sluice` write access.
pub fn resolve_socket_path() -> PathBuf {
    std::env::var(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH))
}

/// Top-level wire frame. Tagged so the same socket can carry both
/// request/response pairs and asynchronous server-pushed events.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    /// Client → server.
    Request {
        /// Correlates a response with the request that produced it.
        id: u64,
        body: Request,
    },
    /// Server → client, paired with a prior `Request`.
    Response { id: u64, body: Response },
    /// Server → client, asynchronous (no `id`). Used for the event
    /// stream after a successful `SubscribeEvents`.
    Event(Event),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// Health check / handshake.
    Hello,
    /// Read the current rule list and default policy.
    Snapshot,
    /// Begin streaming `Event::Connection` records as they arrive in
    /// the daemon. The server replies with `Response::Subscribed` and
    /// thereafter pushes events asynchronously on the same socket.
    SubscribeEvents,
    /// Set the kernel-side verdict for `pid` in response to a prompt.
    /// Verdict applies starting with the *next* connect from that PID.
    SetVerdict {
        pid: u32,
        /// Either `"allow"` or `"deny"`.
        verdict: String,
    },
    /// Insert a new rule. Field strings use the same syntax as the CLI:
    /// `exe`: `any | <abs path>`; `host`: `any | <ip> | <ip>/<prefix> | <hostname>`;
    /// `port`: `any | N | N-M`; `protocol`: `any | tcp | udp`;
    /// `verdict`: `allow | deny`.
    AddRule {
        exe: String,
        host: String,
        port: String,
        protocol: String,
        verdict: String,
    },
    /// Delete a rule by id.
    DeleteRule { id: i64 },
    /// Set the default policy.
    SetPolicy {
        /// `allow | deny | ask`.
        policy: String,
    },
    /// Configure (or reconfigure) per-PID egress rate limit. The rate
    /// is bytes per second; `burst_bytes` is the bucket capacity. Pass
    /// `rate_bps == 0` to switch to "unlimited" without removing the
    /// entry.
    SetRate {
        pid: u32,
        rate_bps: u64,
        burst_bytes: u64,
    },
    /// Remove the per-PID rate-limit entry entirely.
    ClearRate { pid: u32 },
    /// Snapshot the current per-PID rate limit table.
    ListRates,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Hello {
        version: String,
    },
    Snapshot {
        rules: Vec<RuleSummary>,
        default_policy: String,
    },
    Subscribed,
    VerdictApplied {
        pid: u32,
        verdict: String,
    },
    RuleAdded {
        id: i64,
    },
    RuleDeleted {
        id: i64,
    },
    PolicyUpdated {
        policy: String,
    },
    RateUpdated {
        pid: u32,
        rate_bps: u64,
        burst_bytes: u64,
    },
    RateCleared {
        pid: u32,
    },
    Rates {
        entries: Vec<RateEntry>,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateEntry {
    pub pid: u32,
    pub rate_bps: u64,
    pub burst_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// One outbound connection attempt.
    Connection {
        timestamp_ns: u64,
        pid: u32,
        exe: Option<String>,
        cmdline: Vec<String>,
        family: String,
        protocol: String,
        addr: String,
        dport: u16,
        verdict: String,
    },
    /// Daemon is asking the GUI to decide what to do with `pid`. Sent
    /// once per PID under `default_policy=ask`; the GUI replies with
    /// `Request::SetVerdict`. Subsequent connections from the same PID
    /// short-circuit in the kernel once a verdict is recorded.
    Prompt {
        pid: u32,
        exe: Option<String>,
        cmdline: Vec<String>,
        family: String,
        protocol: String,
        addr: String,
        dport: u16,
    },
    /// Pushed to all subscribers when rules or the default policy
    /// change (via the CLI on a separate `sluiced` invocation, or via
    /// AddRule/DeleteRule/SetPolicy). Carries the full new snapshot so
    /// clients can refresh without a separate `Snapshot` request.
    RulesChanged {
        rules: Vec<RuleSummary>,
        default_policy: String,
    },
}

/// Compact rule representation for the GUI. Mirrors the fields the user
/// types into `sluiced rules add` rather than the SQLite encoding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSummary {
    pub id: i64,
    pub exe: String,
    pub host: String,
    pub port: String,
    pub protocol: String,
    pub verdict: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_request_roundtrips_through_json() {
        let f = Frame::Request {
            id: 7,
            body: Request::Snapshot,
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: Frame = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn socket_path_env_override_wins() {
        // SAFETY: tests in this binary run sequentially within one process.
        unsafe { std::env::set_var(SOCKET_ENV, "/tmp/sluice-ipc-test.sock") };
        assert_eq!(
            resolve_socket_path(),
            PathBuf::from("/tmp/sluice-ipc-test.sock")
        );
        unsafe { std::env::remove_var(SOCKET_ENV) };
        assert_eq!(resolve_socket_path(), PathBuf::from(DEFAULT_SOCKET_PATH));
    }

    #[test]
    fn set_verdict_request_roundtrips() {
        let f = Frame::Request {
            id: 42,
            body: Request::SetVerdict {
                pid: 1234,
                verdict: "deny".to_string(),
            },
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: Frame = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn add_rule_request_roundtrips() {
        let f = Frame::Request {
            id: 11,
            body: Request::AddRule {
                exe: "/usr/bin/curl".to_string(),
                host: "any".to_string(),
                port: "443".to_string(),
                protocol: "tcp".to_string(),
                verdict: "deny".to_string(),
            },
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: Frame = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn rules_changed_event_uses_snake_case_tag() {
        let e = Event::RulesChanged {
            rules: vec![],
            default_policy: "deny".to_string(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            s.contains(r#""kind":"rules_changed""#),
            "kind tag should be snake_case: {s}"
        );
    }

    #[test]
    fn prompt_event_uses_snake_case_tag() {
        let e = Event::Prompt {
            pid: 1234,
            exe: Some("/usr/bin/curl".to_string()),
            cmdline: vec!["curl".to_string(), "https://x".to_string()],
            family: "ipv4".to_string(),
            protocol: "tcp".to_string(),
            addr: "1.2.3.4".to_string(),
            dport: 443,
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            s.contains(r#""kind":"prompt""#),
            "kind tag should be snake_case: {s}"
        );
    }

    #[test]
    fn event_uses_snake_case_tag() {
        let e = Event::Connection {
            timestamp_ns: 0,
            pid: 1,
            exe: None,
            cmdline: vec![],
            family: "ipv4".to_string(),
            protocol: "tcp".to_string(),
            addr: "1.1.1.1".to_string(),
            dport: 53,
            verdict: "allow".to_string(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            s.contains(r#""kind":"connection""#),
            "kind tag should be snake_case: {s}"
        );
    }
}
