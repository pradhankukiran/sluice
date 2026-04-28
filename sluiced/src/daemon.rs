//! Daemon entry point — what `sluiced run` (or no subcommand) executes.
//!
//! Splits cleanly from the CLI subcommand handlers so non-daemon code
//! paths (`rules add`, `policy show`, ...) don't drag in eBPF or tokio.

use anyhow::Result;
use sluice_common::Verdict;

use crate::attach;
use crate::cgroup;
use crate::ebpf_loader;
use crate::formatter;
use crate::kernel_map::KernelVerdictMap;
use crate::proc_cache::ProcInfoCache;
use crate::ring_reader::EventReader;
use crate::rules::matcher;
use crate::rules::store::{resolve_db_path, SqliteRuleStore};
use crate::rules::types::Policy;

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
    let rules = store.list()?;
    let policy = store.default_policy()?;
    tracing::info!(
        rule_count = rules.len(),
        default_policy = policy.as_str(),
        "rule store loaded"
    );
    let fallback_verdict = match policy {
        Policy::Allow => Verdict::Allow,
        Policy::Deny => Verdict::Deny,
        Policy::Ask => {
            tracing::warn!(
                "default_policy=ask requires the GUI prompt path (phase 7); \
                 phase 4 falls back to allow"
            );
            Verdict::Allow
        }
    };

    let cgroup_root = cgroup::resolve()?;
    tracing::info!(path = %cgroup_root.display(), "cgroup v2 root resolved");

    let bytecode_path = ebpf_loader::bytecode_path();
    tracing::info!(path = %bytecode_path.display(), "eBPF bytecode path");
    let mut bpf = ebpf_loader::load()?;
    tracing::info!("eBPF object loaded");

    let mut kernel_map = KernelVerdictMap::from_ebpf(&mut bpf)?;
    let (touched, pushed) = kernel_map.populate_from_proc(&rules)?;
    tracing::info!(
        pids_seen = touched,
        verdicts_pushed = pushed,
        "kernel verdict map populated from /proc"
    );

    let programs = attach::attach_connect_programs(&mut bpf, &cgroup_root)?;
    for name in &programs {
        tracing::info!(program = name, "attached to cgroup");
    }

    let mut reader = EventReader::from_ebpf(&mut bpf)?;
    let mut cache = ProcInfoCache::with_default_capacity();
    tracing::info!("event reader ready, watching for connections");

    tokio::select! {
        result = reader.run(|event| {
            let info = cache.lookup_or_fetch(event.tgid);

            // Lazy population: a process that started after our `/proc`
            // walk hits this path on its first outbound connect. We push
            // its verdict so subsequent connects from the same PID
            // short-circuit in the kernel.
            if !kernel_map.has_seen(event.tgid) {
                if let Err(err) = kernel_map.evaluate_and_push(event.tgid, &rules) {
                    tracing::warn!(
                        pid = event.tgid,
                        error = %err,
                        "failed to push lazy verdict to kernel map"
                    );
                }
            }

            let verdict = matcher::evaluate(&rules, event, info).unwrap_or(fallback_verdict);
            tracing::info!(
                target: "sluice::connect",
                verdict = verdict_str(verdict),
                cmdline = ?info.cmdline,
                "{}",
                formatter::format_enriched_event(event, info),
            );
        }) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }

    Ok(())
}

const fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::Unknown => "unknown",
    }
}
