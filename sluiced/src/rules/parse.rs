//! Shared parsers for the human-typed rule syntax used by both the CLI
//! (`sluiced rules add --exe …`) and the IPC `AddRule` request.

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Result};

use crate::rules::types::{ExeMatch, HostMatch, Policy, PortMatch, ProtocolMatch, Verdict};

pub fn parse_exe(s: &str) -> Result<ExeMatch> {
    if s == "any" {
        return Ok(ExeMatch::Any);
    }
    if !s.starts_with('/') {
        return Err(anyhow!("exe must be `any` or an absolute path, got `{s}`"));
    }
    Ok(ExeMatch::Exact(PathBuf::from(s)))
}

pub fn parse_host(s: &str) -> Result<HostMatch> {
    if s == "any" {
        return Ok(HostMatch::Any);
    }
    if let Some((net, prefix)) = s.split_once('/') {
        let network =
            IpAddr::from_str(net).map_err(|e| anyhow!("invalid CIDR network `{net}`: {e}"))?;
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

pub fn parse_port(s: &str) -> Result<PortMatch> {
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
        s.parse().map_err(|e| anyhow!("invalid port `{s}`: {e}"))?,
    ))
}

pub fn parse_protocol(s: &str) -> Result<ProtocolMatch> {
    Ok(match s {
        "any" => ProtocolMatch::Any,
        "tcp" => ProtocolMatch::Tcp,
        "udp" => ProtocolMatch::Udp,
        other => return Err(anyhow!("invalid protocol `{other}`; expected any|tcp|udp")),
    })
}

pub fn parse_verdict(s: &str) -> Result<Verdict> {
    Ok(match s {
        "allow" => Verdict::Allow,
        "deny" => Verdict::Deny,
        other => return Err(anyhow!("invalid verdict `{other}`; expected allow|deny")),
    })
}

pub fn parse_policy(s: &str) -> Result<Policy> {
    Policy::from_str_strict(s)
        .ok_or_else(|| anyhow!("invalid policy `{s}`; expected allow|deny|ask"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_accepts_any_or_absolute_path() {
        assert_eq!(parse_exe("any").unwrap(), ExeMatch::Any);
        assert_eq!(
            parse_exe("/usr/bin/curl").unwrap(),
            ExeMatch::Exact(PathBuf::from("/usr/bin/curl"))
        );
        assert!(parse_exe("relative/path").is_err());
    }

    #[test]
    fn host_distinguishes_ip_cidr_hostname() {
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
    fn port_accepts_any_single_range() {
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
    fn verdict_rejects_unknown() {
        assert_eq!(parse_verdict("allow").unwrap(), Verdict::Allow);
        assert_eq!(parse_verdict("deny").unwrap(), Verdict::Deny);
        assert!(parse_verdict("ask").is_err());
    }

    #[test]
    fn policy_accepts_three_values() {
        assert_eq!(parse_policy("allow").unwrap(), Policy::Allow);
        assert_eq!(parse_policy("deny").unwrap(), Policy::Deny);
        assert_eq!(parse_policy("ask").unwrap(), Policy::Ask);
        assert!(parse_policy("nope").is_err());
    }
}
