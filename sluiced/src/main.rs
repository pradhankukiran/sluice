//! `sluiced` — the privileged sluice daemon.
//!
//! Phase 1 only ships the binary skeleton: it initializes logging and exits.
//! Subsequent phases will load eBPF programs, manage the rules database,
//! and serve the GUI over a Unix socket.

use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("sluiced {} starting up", env!("CARGO_PKG_VERSION"));
    tracing::info!("phase 1 skeleton — no eBPF programs attached yet");
    Ok(())
}
