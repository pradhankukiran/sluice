//! Newline-delimited JSON IPC server, listening on a Unix socket.
//!
//! One task per connection. Clients send `Frame::Request`s; the server
//! responds with paired `Frame::Response`s. After a successful
//! `Request::SubscribeEvents`, the connection enters streaming mode and
//! the server pushes `Frame::Event` records as they arrive on the
//! shared broadcast channel.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use sluice_common::event::{
    ConnectEvent, COMM_LEN, FAMILY_INET, FAMILY_INET6, PROTO_TCP, PROTO_UDP,
};
use sluice_common::ipc::{Event, Frame, Request, Response, RuleSummary};
use sluice_common::Verdict;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::proc_info::ProcInfo;
use crate::rules::types::{ExeMatch, HostMatch, PortMatch, ProtocolMatch, Rule};

const SOCKET_MODE: u32 = 0o666;

/// Snapshot data the server can hand to clients in response to
/// `Request::Snapshot`. The daemon owns the source of truth and clones
/// this when it spins up the IPC server.
#[derive(Clone)]
pub struct Snapshot {
    pub rules: Vec<RuleSummary>,
    pub default_policy: String,
}

pub async fn serve(
    socket_path: &Path,
    snapshot: Arc<Snapshot>,
    events_tx: broadcast::Sender<Event>,
) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating ipc socket parent dir {}", parent.display()))?;
    }
    // Remove any stale socket from a previous run; bind would otherwise
    // fail with EADDRINUSE.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding unix socket at {}", socket_path.display()))?;

    // Make the socket world-rw so an unprivileged GUI can connect to a
    // root-owned daemon socket. On a single-user box this is fine; a
    // future hardening pass would group-restrict and `chown` instead.
    let mut perms = std::fs::metadata(socket_path)?.permissions();
    perms.set_mode(SOCKET_MODE);
    std::fs::set_permissions(socket_path, perms)?;

    tracing::info!(
        path = %socket_path.display(),
        mode = format!("{:o}", SOCKET_MODE),
        "ipc socket listening"
    );

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accepting ipc connection")?;
        let snapshot = Arc::clone(&snapshot);
        let events_tx = events_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, snapshot, events_tx).await {
                tracing::warn!(error = %err, "ipc client closed with error");
            }
        });
    }
}

async fn handle_client(
    stream: UnixStream,
    snapshot: Arc<Snapshot>,
    events_tx: broadcast::Sender<Event>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    while let Some(line) = reader.next_line().await? {
        let frame: Frame = match serde_json::from_str(&line) {
            Ok(f) => f,
            Err(err) => {
                send_frame(
                    &mut write_half,
                    &Frame::Response {
                        id: 0,
                        body: Response::Error {
                            message: format!("malformed frame: {err}"),
                        },
                    },
                )
                .await?;
                continue;
            }
        };

        match frame {
            Frame::Request { id, body } => match body {
                Request::Hello => {
                    send_frame(
                        &mut write_half,
                        &Frame::Response {
                            id,
                            body: Response::Hello {
                                version: env!("CARGO_PKG_VERSION").to_string(),
                            },
                        },
                    )
                    .await?;
                }
                Request::Snapshot => {
                    send_frame(
                        &mut write_half,
                        &Frame::Response {
                            id,
                            body: Response::Snapshot {
                                rules: snapshot.rules.clone(),
                                default_policy: snapshot.default_policy.clone(),
                            },
                        },
                    )
                    .await?;
                }
                Request::SubscribeEvents => {
                    send_frame(
                        &mut write_half,
                        &Frame::Response {
                            id,
                            body: Response::Subscribed,
                        },
                    )
                    .await?;
                    let rx = events_tx.subscribe();
                    return stream_events(reader, write_half, rx).await;
                }
            },
            // Servers shouldn't see Response/Event frames; reject loudly
            // so the client realises it has the protocol backwards.
            Frame::Response { .. } | Frame::Event(_) => {
                send_frame(
                    &mut write_half,
                    &Frame::Response {
                        id: 0,
                        body: Response::Error {
                            message: "client sent server-only frame".to_string(),
                        },
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn stream_events(
    mut reader: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut rx: broadcast::Receiver<Event>,
) -> Result<()> {
    loop {
        tokio::select! {
            evt = rx.recv() => {
                let evt = match evt {
                    Ok(e) => e,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "ipc subscriber lagged");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                send_frame(&mut writer, &Frame::Event(evt)).await?;
            }
            line = reader.next_line() => {
                match line? {
                    // Client may continue sending requests; phase 6 just
                    // ignores them. Phase 7 will dispatch verdicts here.
                    Some(_) => continue,
                    None => break,
                }
            }
        }
    }
    Ok(())
}

async fn send_frame(writer: &mut tokio::net::unix::OwnedWriteHalf, frame: &Frame) -> Result<()> {
    let mut json = serde_json::to_vec(frame).context("encoding frame")?;
    json.push(b'\n');
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

// ---------- adapters from internal types to IPC types ----------

pub fn build_snapshot(rules: &[Rule], default_policy: &str) -> Snapshot {
    Snapshot {
        rules: rules.iter().map(rule_summary).collect(),
        default_policy: default_policy.to_string(),
    }
}

pub fn build_connection_event(e: &ConnectEvent, info: &ProcInfo, verdict: Verdict) -> Event {
    Event::Connection {
        timestamp_ns: e.timestamp_ns,
        pid: e.tgid,
        exe: info.exe.as_ref().map(|p| p.display().to_string()),
        cmdline: info.cmdline.clone(),
        family: family_str(e.family).to_string(),
        protocol: protocol_str(e.protocol).to_string(),
        addr: format_addr(e),
        dport: e.dport,
        verdict: verdict_label(verdict).to_string(),
    }
}

fn rule_summary(rule: &Rule) -> RuleSummary {
    RuleSummary {
        id: rule.id,
        exe: format_exe(&rule.exe_match),
        host: format_host(&rule.host),
        port: format_port(&rule.port),
        protocol: format_protocol(&rule.protocol),
        verdict: verdict_label(rule.verdict).to_string(),
    }
}

fn format_exe(m: &ExeMatch) -> String {
    match m {
        ExeMatch::Any => "any".to_string(),
        ExeMatch::Exact(p) => p.display().to_string(),
    }
}

fn format_host(m: &HostMatch) -> String {
    match m {
        HostMatch::Any => "any".to_string(),
        HostMatch::Ip(ip) => ip.to_string(),
        HostMatch::Cidr {
            network,
            prefix_len,
        } => format!("{network}/{prefix_len}"),
        HostMatch::Hostname(h) => h.clone(),
    }
}

fn format_port(m: &PortMatch) -> String {
    match m {
        PortMatch::Any => "any".to_string(),
        PortMatch::Single(p) => p.to_string(),
        PortMatch::Range {
            start,
            end_inclusive,
        } => format!("{start}-{end_inclusive}"),
    }
}

fn format_protocol(m: &ProtocolMatch) -> String {
    match m {
        ProtocolMatch::Any => "any".to_string(),
        ProtocolMatch::Tcp => "tcp".to_string(),
        ProtocolMatch::Udp => "udp".to_string(),
    }
}

fn family_str(family: u16) -> &'static str {
    match family {
        FAMILY_INET => "ipv4",
        FAMILY_INET6 => "ipv6",
        _ => "?",
    }
}

fn protocol_str(proto: u8) -> &'static str {
    match proto {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        _ => "?",
    }
}

const fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::Unknown => "unknown",
    }
}

fn format_addr(e: &ConnectEvent) -> String {
    match e.family {
        FAMILY_INET => Ipv4Addr::new(e.addr[0], e.addr[1], e.addr[2], e.addr[3]).to_string(),
        FAMILY_INET6 => Ipv6Addr::from(e.addr).to_string(),
        _ => {
            // Best-effort: render the comm bytes so the user can at
            // least see *which* process logged an unknown family.
            let null_pos = e.comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
            format!(
                "(family={}, comm={})",
                e.family,
                String::from_utf8_lossy(&e.comm[..null_pos])
            )
        }
    }
}
