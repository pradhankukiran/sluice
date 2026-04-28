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

use serde::{Deserialize, Serialize};

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
    Response {
        id: u64,
        body: Response,
    },
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
    Error {
        message: String,
    },
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
