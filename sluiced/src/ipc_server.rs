//! Newline-delimited JSON IPC server, listening on a Unix socket.
//!
//! One task per connection. Clients send `Frame::Request`s; the server
//! responds with paired `Frame::Response`s. After a successful
//! `Request::SubscribeEvents`, the connection enters streaming mode and
//! the server pushes `Frame::Event` records as they arrive on the
//! shared broadcast channel.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use sluice_common::event::{
    ConnectEvent, COMM_LEN, FAMILY_INET, FAMILY_INET6, PROTO_TCP, PROTO_UDP,
};
use sluice_common::ipc::{Event, Frame, Request, Response, RuleSummary};
use sluice_common::Verdict;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::kernel_map::KernelVerdictMap;
use crate::proc_info::ProcInfo;
use crate::rules::store::SqliteRuleStore;
use crate::rules::types::{ExeMatch, HostMatch, Policy, PortMatch, ProtocolMatch, Rule};

/// Shared state the IPC server mutates on behalf of clients. `store`
/// is wired in for the AddRule / DeleteRule handlers in the next
/// commit; for now it would otherwise warn dead.
#[derive(Clone)]
pub struct DaemonHandle {
    pub kernel_map: Arc<Mutex<KernelVerdictMap>>,
    pub pending_prompts: Arc<Mutex<HashSet<u32>>>,
    pub rules: Arc<RwLock<Vec<Rule>>>,
    pub policy: Arc<RwLock<Policy>>,
    #[allow(dead_code)]
    pub store: Arc<Mutex<SqliteRuleStore>>,
}

impl DaemonHandle {
    /// Pull the latest rule list from SQLite into the in-memory snapshot.
    fn reload_rules(&self) -> anyhow::Result<()> {
        let store = self
            .store
            .lock()
            .map_err(|e| anyhow::anyhow!("store mutex poisoned: {e}"))?;
        let new_rules = store.list()?;
        let mut guard = self
            .rules
            .write()
            .map_err(|e| anyhow::anyhow!("rules lock poisoned: {e}"))?;
        *guard = new_rules;
        Ok(())
    }

    /// Clear the kernel map and re-evaluate every running process
    /// against the current rule snapshot. Called after rule mutation
    /// so existing connections get the new verdict on their next attempt.
    fn refresh_kernel_map(&self) -> anyhow::Result<()> {
        let rules_guard = self
            .rules
            .read()
            .map_err(|e| anyhow::anyhow!("rules lock poisoned: {e}"))?;
        let mut km = self
            .kernel_map
            .lock()
            .map_err(|e| anyhow::anyhow!("kernel_map mutex poisoned: {e}"))?;
        km.clear_all()?;
        let (_, _) = km.populate_from_proc(&rules_guard)?;
        Ok(())
    }
}

const SOCKET_MODE: u32 = 0o666;

pub async fn serve(
    socket_path: &Path,
    events_tx: broadcast::Sender<Event>,
    handle: DaemonHandle,
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
        let events_tx = events_tx.clone();
        let handle = handle.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, events_tx, handle).await {
                tracing::warn!(error = %err, "ipc client closed with error");
            }
        });
    }
}

async fn handle_client(
    stream: UnixStream,
    events_tx: broadcast::Sender<Event>,
    handle: DaemonHandle,
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
                    let snapshot = build_snapshot_response(&handle);
                    send_frame(
                        &mut write_half,
                        &Frame::Response {
                            id,
                            body: snapshot,
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
                    return stream_events(reader, write_half, rx, handle, events_tx).await;
                }
                Request::SetVerdict { pid, verdict } => {
                    let response = apply_verdict(&handle, pid, &verdict);
                    send_frame(&mut write_half, &Frame::Response { id, body: response }).await?;
                }
                Request::AddRule {
                    exe,
                    host,
                    port,
                    protocol,
                    verdict,
                } => {
                    let response =
                        apply_add_rule(&handle, &exe, &host, &port, &protocol, &verdict);
                    if matches!(response, Response::RuleAdded { .. }) {
                        let _ = events_tx.send(build_rules_changed_event(&handle));
                    }
                    send_frame(&mut write_half, &Frame::Response { id, body: response }).await?;
                }
                Request::DeleteRule { id: rule_id } => {
                    let response = apply_delete_rule(&handle, rule_id);
                    if matches!(response, Response::RuleDeleted { .. }) {
                        let _ = events_tx.send(build_rules_changed_event(&handle));
                    }
                    send_frame(&mut write_half, &Frame::Response { id, body: response }).await?;
                }
                Request::SetPolicy { policy } => {
                    let response = apply_set_policy(&handle, &policy);
                    if matches!(response, Response::PolicyUpdated { .. }) {
                        let _ = events_tx.send(build_rules_changed_event(&handle));
                    }
                    send_frame(&mut write_half, &Frame::Response { id, body: response }).await?;
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
    handle: DaemonHandle,
    events_tx_for_stream: broadcast::Sender<Event>,
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
                let line = match line? {
                    Some(l) => l,
                    None => break,
                };
                let frame: Frame = match serde_json::from_str(&line) {
                    Ok(f) => f,
                    Err(err) => {
                        tracing::warn!(error = %err, "malformed frame in stream");
                        continue;
                    }
                };
                if let Frame::Request { id, body } = frame {
                    let response = match body {
                        Request::SetVerdict { pid, verdict } => apply_verdict(&handle, pid, &verdict),
                        Request::AddRule {
                            exe,
                            host,
                            port,
                            protocol,
                            verdict,
                        } => {
                            let resp = apply_add_rule(&handle, &exe, &host, &port, &protocol, &verdict);
                            if matches!(resp, Response::RuleAdded { .. }) {
                                let _ = events_tx_for_stream.send(build_rules_changed_event(&handle));
                            }
                            resp
                        }
                        Request::DeleteRule { id: rule_id } => {
                            let resp = apply_delete_rule(&handle, rule_id);
                            if matches!(resp, Response::RuleDeleted { .. }) {
                                let _ = events_tx_for_stream.send(build_rules_changed_event(&handle));
                            }
                            resp
                        }
                        Request::SetPolicy { policy } => {
                            let resp = apply_set_policy(&handle, &policy);
                            if matches!(resp, Response::PolicyUpdated { .. }) {
                                let _ = events_tx_for_stream.send(build_rules_changed_event(&handle));
                            }
                            resp
                        }
                        // Hello/Snapshot/SubscribeEvents during a stream
                        // are ignored; clients should only send
                        // SetVerdict / AddRule / DeleteRule / SetPolicy.
                        Request::Hello | Request::Snapshot | Request::SubscribeEvents => continue,
                    };
                    send_frame(&mut writer, &Frame::Response { id, body: response }).await?;
                }
            }
        }
    }
    Ok(())
}

fn apply_add_rule(
    handle: &DaemonHandle,
    exe: &str,
    host: &str,
    port: &str,
    protocol: &str,
    verdict: &str,
) -> Response {
    use crate::rules::parse;

    let exe_match = match parse::parse_exe(exe) {
        Ok(v) => v,
        Err(e) => {
            return Response::Error {
                message: format!("exe: {e}"),
            }
        }
    };
    let host_match = match parse::parse_host(host) {
        Ok(v) => v,
        Err(e) => {
            return Response::Error {
                message: format!("host: {e}"),
            }
        }
    };
    let port_match = match parse::parse_port(port) {
        Ok(v) => v,
        Err(e) => {
            return Response::Error {
                message: format!("port: {e}"),
            }
        }
    };
    let protocol_match = match parse::parse_protocol(protocol) {
        Ok(v) => v,
        Err(e) => {
            return Response::Error {
                message: format!("protocol: {e}"),
            }
        }
    };
    let verdict_value = match parse::parse_verdict(verdict) {
        Ok(v) => v,
        Err(e) => {
            return Response::Error {
                message: format!("verdict: {e}"),
            }
        }
    };

    let rule = Rule {
        id: 0,
        exe_match,
        host: host_match,
        port: port_match,
        protocol: protocol_match,
        verdict: verdict_value,
    };

    let id = match handle
        .store
        .lock()
        .map_err(|e| anyhow::anyhow!("store mutex poisoned: {e}"))
        .and_then(|s| s.insert(&rule))
    {
        Ok(id) => id,
        Err(e) => {
            return Response::Error {
                message: format!("insert failed: {e}"),
            }
        }
    };

    if let Err(e) = handle.reload_rules() {
        tracing::warn!(error = %e, "reload_rules failed after AddRule");
    }
    if let Err(e) = handle.refresh_kernel_map() {
        tracing::warn!(error = %e, "refresh_kernel_map failed after AddRule");
    }

    tracing::info!(rule_id = id, "rule added via IPC");
    Response::RuleAdded { id }
}

fn apply_delete_rule(handle: &DaemonHandle, id: i64) -> Response {
    let removed = match handle
        .store
        .lock()
        .map_err(|e| anyhow::anyhow!("store mutex poisoned: {e}"))
        .and_then(|s| s.delete(id))
    {
        Ok(b) => b,
        Err(e) => {
            return Response::Error {
                message: format!("delete failed: {e}"),
            }
        }
    };

    if !removed {
        return Response::Error {
            message: format!("no rule with id {id}"),
        };
    }

    if let Err(e) = handle.reload_rules() {
        tracing::warn!(error = %e, "reload_rules failed after DeleteRule");
    }
    if let Err(e) = handle.refresh_kernel_map() {
        tracing::warn!(error = %e, "refresh_kernel_map failed after DeleteRule");
    }

    tracing::info!(rule_id = id, "rule deleted via IPC");
    Response::RuleDeleted { id }
}

fn apply_set_policy(handle: &DaemonHandle, raw: &str) -> Response {
    use crate::rules::parse;
    let policy = match parse::parse_policy(raw) {
        Ok(p) => p,
        Err(e) => {
            return Response::Error {
                message: format!("{e}"),
            }
        }
    };

    if let Err(e) = handle
        .store
        .lock()
        .map_err(|e| anyhow::anyhow!("store mutex poisoned: {e}"))
        .and_then(|s| s.set_default_policy(policy))
    {
        return Response::Error {
            message: format!("set_default_policy failed: {e}"),
        };
    }

    if let Ok(mut guard) = handle.policy.write() {
        *guard = policy;
    }

    tracing::info!(policy = policy.as_str(), "default policy updated via IPC");
    Response::PolicyUpdated {
        policy: policy.as_str().to_string(),
    }
}

fn apply_verdict(handle: &DaemonHandle, pid: u32, verdict: &str) -> Response {
    let verdict_value = match verdict {
        "allow" => Verdict::Allow,
        "deny" => Verdict::Deny,
        other => {
            return Response::Error {
                message: format!("invalid verdict `{other}`; expected allow|deny"),
            };
        }
    };

    if let Err(err) = handle
        .kernel_map
        .lock()
        .map_err(|e| anyhow::anyhow!("kernel_map mutex poisoned: {e}"))
        .and_then(|mut km| km.set(pid, verdict_value))
    {
        return Response::Error {
            message: format!("kernel map update failed: {err}"),
        };
    }

    if let Ok(mut pending) = handle.pending_prompts.lock() {
        pending.remove(&pid);
    }

    tracing::info!(
        pid,
        verdict = verdict_label(verdict_value),
        "applied verdict from GUI"
    );

    Response::VerdictApplied {
        pid,
        verdict: verdict_label(verdict_value).to_string(),
    }
}

async fn send_frame(writer: &mut tokio::net::unix::OwnedWriteHalf, frame: &Frame) -> Result<()> {
    let mut json = serde_json::to_vec(frame).context("encoding frame")?;
    json.push(b'\n');
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

// ---------- adapters from internal types to IPC types ----------

fn build_snapshot_response(handle: &DaemonHandle) -> Response {
    let rules = match handle.rules.read() {
        Ok(g) => g.iter().map(rule_summary).collect(),
        Err(_) => Vec::new(),
    };
    let default_policy = handle
        .policy
        .read()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|_| "allow".to_string());
    Response::Snapshot {
        rules,
        default_policy,
    }
}

pub fn build_rules_changed_event(handle: &DaemonHandle) -> Event {
    let rules = match handle.rules.read() {
        Ok(g) => g.iter().map(rule_summary).collect(),
        Err(_) => Vec::new(),
    };
    let default_policy = handle
        .policy
        .read()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|_| "allow".to_string());
    Event::RulesChanged {
        rules,
        default_policy,
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

pub fn build_prompt_event(e: &ConnectEvent, info: &ProcInfo) -> Event {
    Event::Prompt {
        pid: e.tgid,
        exe: info.exe.as_ref().map(|p| p.display().to_string()),
        cmdline: info.cmdline.clone(),
        family: family_str(e.family).to_string(),
        protocol: protocol_str(e.protocol).to_string(),
        addr: format_addr(e),
        dport: e.dport,
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
