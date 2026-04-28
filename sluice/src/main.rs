//! `sluice` — the GUI front-end.

mod ipc_client;

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
