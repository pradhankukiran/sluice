//! `sluiced` — the privileged sluice daemon.

mod cgroup;

use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("sluiced {} starting up", env!("CARGO_PKG_VERSION"));

    let cgroup_root = cgroup::resolve()?;
    tracing::info!(path = %cgroup_root.display(), "cgroup v2 root resolved");

    Ok(())
}
