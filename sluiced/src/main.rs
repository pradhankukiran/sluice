//! `sluiced` — the privileged sluice daemon.

mod attach;
mod cgroup;
mod cli;
mod daemon;
mod ebpf_loader;
mod formatter;
mod kernel_map;
mod proc_cache;
mod proc_info;
mod ring_reader;
mod rules;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => daemon::run(),
        Command::Rules { action } => cli::run_rules(action),
        Command::Policy { action } => cli::run_policy(action),
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
