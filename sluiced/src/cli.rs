//! Command-line surface.
//!
//! Sluiced is multi-mode: with no subcommand it runs as the eBPF daemon
//! (`sluiced` ≡ `sluiced run`); with `rules` / `policy` subcommands it
//! mutates the local SQLite database and exits. The mutating
//! subcommands let operators populate rules without a GUI — the GUI
//! arrives in phase 6.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::rules::parse::{
    parse_exe, parse_host, parse_policy, parse_port, parse_protocol, parse_verdict,
};
use crate::rules::store::{resolve_db_path, SqliteRuleStore};
use crate::rules::types::{ExeMatch, HostMatch, PortMatch, ProtocolMatch, Rule, Verdict};

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

// ---------- subcommand handlers ----------

pub fn run_rules(action: RulesCommand) -> Result<()> {
    let store = SqliteRuleStore::open(&resolve_db_path())?;
    match action {
        RulesCommand::List => list_rules(&store),
        RulesCommand::Add {
            exe,
            host,
            port,
            proto,
            verdict,
        } => add_rule(&store, &exe, &host, &port, &proto, &verdict),
        RulesCommand::Rm { id } => rm_rule(&store, id),
    }
}

pub fn run_policy(action: PolicyCommand) -> Result<()> {
    let store = SqliteRuleStore::open(&resolve_db_path())?;
    match action {
        PolicyCommand::Show => show_policy(&store),
        PolicyCommand::Set { policy } => set_policy(&store, &policy),
    }
}

fn list_rules(store: &SqliteRuleStore) -> Result<()> {
    let rules = store.list()?;
    if rules.is_empty() {
        println!("(no rules)");
        return Ok(());
    }
    for r in rules {
        println!("{}", format_rule(&r));
    }
    Ok(())
}

fn rm_rule(store: &SqliteRuleStore, id: i64) -> Result<()> {
    if store.delete(id)? {
        println!("removed rule {id}");
    } else {
        println!("no rule with id {id}");
    }
    Ok(())
}

fn add_rule(
    store: &SqliteRuleStore,
    exe: &str,
    host: &str,
    port: &str,
    proto: &str,
    verdict: &str,
) -> Result<()> {
    let rule = Rule {
        id: 0,
        exe_match: parse_exe(exe)?,
        host: parse_host(host)?,
        port: parse_port(port)?,
        protocol: parse_protocol(proto)?,
        verdict: parse_verdict(verdict)?,
    };
    let id = store.insert(&rule)?;
    println!("added rule {id}");
    Ok(())
}

fn show_policy(store: &SqliteRuleStore) -> Result<()> {
    println!("{}", store.default_policy()?.as_str());
    Ok(())
}

fn set_policy(store: &SqliteRuleStore, raw: &str) -> Result<()> {
    let policy = parse_policy(raw)?;
    store.set_default_policy(policy)?;
    println!("default policy set to {}", policy.as_str());
    Ok(())
}

// ---------- pretty-printing ----------

fn format_rule(r: &Rule) -> String {
    format!(
        "[{id:>4}] verdict={verdict} exe={exe} host={host} port={port} proto={proto}",
        id = r.id,
        verdict = match r.verdict {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Unknown => "unknown",
        },
        exe = format_exe(&r.exe_match),
        host = format_host(&r.host),
        port = format_port(&r.port),
        proto = format_protocol(&r.protocol),
    )
}

fn format_exe(m: &ExeMatch) -> String {
    match m {
        ExeMatch::Any => "any".to_string(),
        ExeMatch::Exact(p) => p.display().to_string(),
    }
}

fn format_host(m: &HostMatch) -> String {
    match m {
        HostMatch::Any => "any".to_string(),
        HostMatch::Ip(ip) => ip.to_string(),
        HostMatch::Cidr {
            network,
            prefix_len,
        } => format!("{network}/{prefix_len}"),
        HostMatch::Hostname(h) => h.to_string(),
    }
}

fn format_port(m: &PortMatch) -> String {
    match m {
        PortMatch::Any => "any".to_string(),
        PortMatch::Single(p) => p.to_string(),
        PortMatch::Range {
            start,
            end_inclusive,
        } => format!("{start}-{end_inclusive}"),
    }
}

fn format_protocol(m: &ProtocolMatch) -> String {
    match m {
        ProtocolMatch::Any => "any".to_string(),
        ProtocolMatch::Tcp => "tcp".to_string(),
        ProtocolMatch::Udp => "udp".to_string(),
    }
}
