//! Daemon entry point — what `sluiced run` (or no subcommand) executes.
//!
//! Splits cleanly from the CLI subcommand handlers so non-daemon code
//! paths (`rules add`, `policy show`, ...) don't drag in eBPF or tokio.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use sluice_common::ipc::{self, resolve_socket_path};
use sluice_common::Verdict;
use tokio::sync::broadcast;

use crate::attach;
use crate::cgroup;
use crate::dns_cache::DnsCache;
use crate::ebpf_loader;
use crate::formatter;
use crate::ipc_server;
use crate::kernel_map::KernelVerdictMap;
use crate::kernel_rates::KernelRateLimits;
use crate::proc_cache::ProcInfoCache;
use crate::ring_reader::EventReader;
use crate::rules::matcher;
use crate::rules::store::{resolve_db_path, SqliteRuleStore};
use crate::rules::types::Policy;

const EVENT_BROADCAST_CAPACITY: usize = 1024;

pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_async())
}

async fn run_async() -> Result<()> {
    tracing::info!("sluiced {} starting up", env!("CARGO_PKG_VERSION"));

    let db_path = resolve_db_path();
    tracing::info!(path = %db_path.display(), "rules database path");
    let store = SqliteRuleStore::open(&db_path)?;
    let initial_rules = store.list()?;
    let initial_policy = store.default_policy()?;
    tracing::info!(
        rule_count = initial_rules.len(),
        default_policy = initial_policy.as_str(),
        "rule store loaded"
    );

    // Rules and policy live behind RwLock so the IPC server can mutate
    // them at runtime; the event handler reads them on every event,
    // which keeps the daemon honest across `AddRule` / `SetPolicy`
    // requests without a separate reload step.
    let rules = Arc::new(RwLock::new(initial_rules));
    let policy = Arc::new(RwLock::new(initial_policy));
    let store = Arc::new(Mutex::new(store));

    // Pre-resolve every hostname referenced by current rules so the
    // matcher can apply HostMatch::Hostname rules from the very first
    // event. Failures here are logged inside refresh_for_rules and do
    // not block daemon startup.
    let dns_cache = {
        let mut cache = DnsCache::new();
        let snapshot = rules.read().expect("rules lock").clone();
        cache.refresh_for_rules(&snapshot).await;
        Arc::new(RwLock::new(cache))
    };
    tracing::info!(
        cached_hostnames = dns_cache.read().expect("dns lock").len(),
        "DNS cache primed"
    );

    let cgroup_root = cgroup::resolve()?;
    tracing::info!(path = %cgroup_root.display(), "cgroup v2 root resolved");

    let bytecode_path = ebpf_loader::bytecode_path();
    tracing::info!(path = %bytecode_path.display(), "eBPF bytecode path");
    let mut bpf = ebpf_loader::load()?;
    tracing::info!("eBPF object loaded");

    let mut kernel_map = KernelVerdictMap::from_ebpf(&mut bpf)?;
    {
        let rules_guard = rules.read().expect("rules lock");
        let (touched, pushed) = kernel_map.populate_from_proc(&rules_guard)?;
        tracing::info!(
            pids_seen = touched,
            verdicts_pushed = pushed,
            "kernel verdict map populated from /proc"
        );
    }
    let kernel_map = Arc::new(Mutex::new(kernel_map));
    let kernel_rates = {
        let mut k = KernelRateLimits::from_ebpf(&mut bpf)?;
        // Reload persisted rates, skipping PIDs that no longer exist.
        let persisted = store
            .lock()
            .expect("store mutex")
            .list_rates()
            .unwrap_or_default();
        let mut reapplied = 0;
        for (pid, rate_bps, burst) in persisted {
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                tracing::info!(pid, "skipping persisted rate for exited PID");
                continue;
            }
            if let Err(err) = k.set(pid, rate_bps, burst) {
                tracing::warn!(pid, error = %err, "failed to reapply persisted rate");
            } else {
                reapplied += 1;
            }
        }
        tracing::info!(reapplied, "persisted rate limits reloaded");
        Arc::new(Mutex::new(k))
    };
    let pending_prompts: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

    let programs = attach::attach_cgroup_programs(&mut bpf, &cgroup_root)?;
    for name in &programs {
        tracing::info!(program = name, "attached to cgroup");
    }
    let tc_attached = attach::attach_tc_egress_to_all_interfaces(&mut bpf)?;
    tracing::info!(
        interfaces = tc_attached.len(),
        "tc-bpf egress classifier attached"
    );

    // Spin up the IPC server before entering the event loop so the GUI
    // can connect as soon as `sluiced` reports it's ready.
    let (events_tx, _) = broadcast::channel::<ipc::Event>(EVENT_BROADCAST_CAPACITY);
    let socket_path = resolve_socket_path();
    let daemon_handle = ipc_server::DaemonHandle {
        kernel_map: Arc::clone(&kernel_map),
        kernel_rates: Arc::clone(&kernel_rates),
        pending_prompts: Arc::clone(&pending_prompts),
        rules: Arc::clone(&rules),
        policy: Arc::clone(&policy),
        store: Arc::clone(&store),
        dns_cache: Arc::clone(&dns_cache),
    };
    let ipc_handle = {
        let events_tx = events_tx.clone();
        let socket_path = socket_path.clone();
        let daemon_handle = daemon_handle.clone();
        tokio::spawn(async move {
            if let Err(err) = ipc_server::serve(&socket_path, events_tx, daemon_handle).await {
                tracing::error!(error = %err, "ipc server failed");
            }
        })
    };
    tracing::info!(socket = %socket_path.display(), "ipc server spawned");

    let mut reader = EventReader::from_ebpf(&mut bpf)?;
    let mut cache = ProcInfoCache::with_default_capacity();
    tracing::info!("event reader ready, watching for connections");

    tokio::select! {
        result = reader.run(|event| {
            let info = cache.lookup_or_fetch(event.tgid);

            // Snapshot the current rules + policy under their read locks.
            // Both are very lightly contended — only mutated by the IPC
            // server on AddRule / SetPolicy.
            let rules_guard = match rules.read() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let current_policy = match policy.read() {
                Ok(g) => *g,
                Err(poisoned) => *poisoned.into_inner(),
            };

            // Lazy population: a process that started after our `/proc`
            // walk hits this path on its first outbound connect. We push
            // its verdict so subsequent connects from the same PID
            // short-circuit in the kernel.
            if let Ok(mut km) = kernel_map.lock() {
                if !km.has_seen(event.tgid) {
                    if let Err(err) = km.evaluate_and_push(event.tgid, &rules_guard) {
                        tracing::warn!(
                            pid = event.tgid,
                            error = %err,
                            "failed to push lazy verdict to kernel map"
                        );
                    }
                }
            }

            let dns_guard = dns_cache.read().ok();
            let rule_verdict =
                matcher::evaluate(&rules_guard, event, info, dns_guard.as_deref());

            // Under Ask, an unmatched event triggers a one-shot prompt
            // (deduped per PID) and resolves to "allow" for *this*
            // connection. Subsequent connects from the same PID will
            // honour the user's verdict once SetVerdict updates the
            // kernel map.
            if rule_verdict.is_none() && current_policy == Policy::Ask {
                let newly_pending = pending_prompts
                    .lock()
                    .map(|mut set| set.insert(event.tgid))
                    .unwrap_or(false);
                if newly_pending {
                    let _ = events_tx.send(ipc_server::build_prompt_event(event, info));
                }
            }

            let fallback_verdict = match current_policy {
                Policy::Allow => Verdict::Allow,
                Policy::Deny => Verdict::Deny,
                Policy::Ask => Verdict::Allow,
            };
            let verdict = rule_verdict.unwrap_or(fallback_verdict);
            tracing::info!(
                target: "sluice::connect",
                verdict = verdict_str(verdict),
                cmdline = ?info.cmdline,
                "{}",
                formatter::format_enriched_event(event, info),
            );

            // Best-effort: a missing subscriber means no GUI is
            // connected, which is fine. `send` errors only when *no*
            // receivers exist, so ignoring is correct.
            let _ = events_tx.send(ipc_server::build_connection_event(event, info, verdict));
        }) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }

    ipc_handle.abort();
    let _ = std::fs::remove_file(&socket_path);

    Ok(())
}

const fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::Unknown => "unknown",
    }
}
