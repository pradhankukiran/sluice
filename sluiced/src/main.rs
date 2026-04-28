//! `sluiced` — the privileged sluice daemon.

mod attach;
mod cgroup;
mod ebpf_loader;
mod formatter;
mod ring_reader;

use anyhow::Result;

use crate::ring_reader::EventReader;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("sluiced {} starting up", env!("CARGO_PKG_VERSION"));

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
    tracing::info!("event reader ready, watching for connections");

    tokio::select! {
        result = reader.run(|event| {
            tracing::info!(target: "sluice::connect", "{}", formatter::format_event(event));
        }) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }

    Ok(())
}
