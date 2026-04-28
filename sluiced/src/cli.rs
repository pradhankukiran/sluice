//! Command-line surface.
//!
//! Sluiced is multi-mode: with no subcommand it runs as the eBPF daemon
//! (`sluiced` ≡ `sluiced run`); with `rules` / `policy` subcommands it
//! mutates the local SQLite database and exits. The mutating
//! subcommands let operators populate rules without a GUI — the GUI
//! arrives in phase 6.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use crate::rules::store::{resolve_db_path, SqliteRuleStore};
use crate::rules::types::{ExeMatch, HostMatch, Policy, PortMatch, ProtocolMatch, Rule, Verdict};

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
    let policy = Policy::from_str_strict(raw)
        .ok_or_else(|| anyhow!("invalid policy {raw}; expected allow|deny|ask"))?;
    store.set_default_policy(policy)?;
    println!("default policy set to {}", policy.as_str());
    Ok(())
}

// ---------- input parsers ----------

fn parse_exe(s: &str) -> Result<ExeMatch> {
    if s == "any" {
        return Ok(ExeMatch::Any);
    }
    if !s.starts_with('/') {
        return Err(anyhow!(
            "exe must be `any` or an absolute path, got `{s}`"
        ));
    }
    Ok(ExeMatch::Exact(std::path::PathBuf::from(s)))
}

fn parse_host(s: &str) -> Result<HostMatch> {
    use std::net::IpAddr;
    use std::str::FromStr;

    if s == "any" {
        return Ok(HostMatch::Any);
    }
    if let Some((net, prefix)) = s.split_once('/') {
        let network = IpAddr::from_str(net)
            .map_err(|e| anyhow!("invalid CIDR network `{net}`: {e}"))?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|e| anyhow!("invalid CIDR prefix `{prefix}`: {e}"))?;
        return Ok(HostMatch::Cidr {
            network,
            prefix_len,
        });
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(HostMatch::Ip(ip));
    }
    // Anything else is taken as a hostname pattern. Phase 9 wires up
    // matching against DNS-resolved names.
    Ok(HostMatch::Hostname(s.to_string()))
}

fn parse_port(s: &str) -> Result<PortMatch> {
    if s == "any" {
        return Ok(PortMatch::Any);
    }
    if let Some((start, end)) = s.split_once('-') {
        return Ok(PortMatch::Range {
            start: start
                .parse()
                .map_err(|e| anyhow!("invalid port range start `{start}`: {e}"))?,
            end_inclusive: end
                .parse()
                .map_err(|e| anyhow!("invalid port range end `{end}`: {e}"))?,
        });
    }
    Ok(PortMatch::Single(
        s.parse()
            .map_err(|e| anyhow!("invalid port `{s}`: {e}"))?,
    ))
}

fn parse_protocol(s: &str) -> Result<ProtocolMatch> {
    Ok(match s {
        "any" => ProtocolMatch::Any,
        "tcp" => ProtocolMatch::Tcp,
        "udp" => ProtocolMatch::Udp,
        other => return Err(anyhow!("invalid protocol `{other}`; expected any|tcp|udp")),
    })
}

fn parse_verdict(s: &str) -> Result<Verdict> {
    Ok(match s {
        "allow" => Verdict::Allow,
        "deny" => Verdict::Deny,
        other => return Err(anyhow!("invalid verdict `{other}`; expected allow|deny")),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn parse_exe_accepts_any_or_absolute_path() {
        assert_eq!(parse_exe("any").unwrap(), ExeMatch::Any);
        assert_eq!(
            parse_exe("/usr/bin/curl").unwrap(),
            ExeMatch::Exact(std::path::PathBuf::from("/usr/bin/curl"))
        );
        assert!(parse_exe("relative/path").is_err());
    }

    #[test]
    fn parse_host_distinguishes_ip_cidr_hostname() {
        assert_eq!(parse_host("any").unwrap(), HostMatch::Any);
        assert_eq!(
            parse_host("1.2.3.4").unwrap(),
            HostMatch::Ip(IpAddr::from_str("1.2.3.4").unwrap())
        );
        assert_eq!(
            parse_host("10.0.0.0/8").unwrap(),
            HostMatch::Cidr {
                network: IpAddr::from_str("10.0.0.0").unwrap(),
                prefix_len: 8,
            }
        );
        assert_eq!(
            parse_host("example.com").unwrap(),
            HostMatch::Hostname("example.com".to_string())
        );
    }

    #[test]
    fn parse_port_accepts_any_single_range() {
        assert_eq!(parse_port("any").unwrap(), PortMatch::Any);
        assert_eq!(parse_port("443").unwrap(), PortMatch::Single(443));
        assert_eq!(
            parse_port("8000-8100").unwrap(),
            PortMatch::Range {
                start: 8000,
                end_inclusive: 8100,
            }
        );
        assert!(parse_port("not-a-number").is_err());
    }

    #[test]
    fn parse_verdict_rejects_unknown() {
        assert_eq!(parse_verdict("allow").unwrap(), Verdict::Allow);
        assert_eq!(parse_verdict("deny").unwrap(), Verdict::Deny);
        assert!(parse_verdict("ask").is_err());
        assert!(parse_verdict("garbage").is_err());
    }
}
