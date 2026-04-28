//! `sluice` — the GUI front-end.
//!
//! Phase 1 only ships the binary skeleton. The empty window and IPC to
//! `sluiced` arrive in phase 6.

use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("sluice GUI {} starting up", env!("CARGO_PKG_VERSION"));
    tracing::info!("phase 1 skeleton — no UI yet");
    Ok(())
}
