// Subcommand handlers go live in subsequent commits; the dispatcher
// itself is in use as soon as `main` calls `Cli::parse()`.
#![allow(dead_code)]

//! Command-line surface.
//!
//! Sluiced is multi-mode: with no subcommand it runs as the eBPF daemon
//! (`sluiced` ≡ `sluiced run`); with `rules` / `policy` subcommands it
//! mutates the local SQLite database and exits. The mutating
//! subcommands let operators populate rules without a GUI — the GUI
//! arrives in phase 6.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "sluiced",
    version,
    about = "Sluice — per-process Linux network gate (daemon)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the sluice daemon. This is the default when no subcommand
    /// is given.
    Run,

    /// Manage rules in the local SQLite database.
    Rules {
        #[command(subcommand)]
        action: RulesCommand,
    },

    /// Manage the default policy.
    Policy {
        #[command(subcommand)]
        action: PolicyCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum RulesCommand {
    /// List every stored rule, in id order.
    List,

    /// Insert a new rule.
    Add {
        /// Executable to match. Either `any` or an absolute path.
        #[arg(long)]
        exe: String,

        /// Destination to match. One of: `any`, an IP address (v4 or v6),
        /// a CIDR block (`10.0.0.0/8`), or a hostname (matched once
        /// phase 9 lands DNS support).
        #[arg(long)]
        host: String,

        /// Destination port. One of: `any`, a single port (`443`), or
        /// an inclusive range (`8000-8100`).
        #[arg(long)]
        port: String,

        /// Protocol filter: `any`, `tcp`, or `udp`.
        #[arg(long, default_value = "any")]
        proto: String,

        /// Verdict to apply when the rule matches: `allow` or `deny`.
        #[arg(long)]
        verdict: String,
    },

    /// Delete a rule by id.
    Rm {
        /// Rule id (as shown by `rules list`).
        id: i64,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Print the current default policy.
    Show,
    /// Set the default policy.
    Set {
        /// One of: `allow`, `deny`, `ask`.
        policy: String,
    },
}
