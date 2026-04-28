//! `sluiced` — the privileged sluice daemon.

mod attach;
mod cgroup;
mod ebpf_loader;
mod formatter;
mod proc_cache;
mod proc_info;
mod ring_reader;
mod rules;

use anyhow::Result;

use crate::proc_cache::ProcInfoCache;
use crate::ring_reader::EventReader;
use crate::rules::matcher;
use crate::rules::store::{resolve_db_path, SqliteRuleStore};
use crate::rules::types::{Policy, Verdict};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

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
