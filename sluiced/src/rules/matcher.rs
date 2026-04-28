//! Rule-matching predicate. Pure function over `(Rule, ConnectEvent,
//! ProcInfo)`; exercised by both unit tests and the `RuleStore` lookup
//! path in the daemon hot loop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use sluice_common::event::{ConnectEvent, FAMILY_INET, FAMILY_INET6, PROTO_TCP, PROTO_UDP};

use crate::proc_info::ProcInfo;
use crate::rules::types::{ExeMatch, HostMatch, PortMatch, ProtocolMatch, Rule, Verdict};

/// True if every axis of `rule` matches the event/process pair.
pub fn matches(rule: &Rule, event: &ConnectEvent, info: &ProcInfo) -> bool {
    matches_exe(&rule.exe_match, info)
        && matches_host(&rule.host, event)
        && matches_port(&rule.port, event)
        && matches_protocol(&rule.protocol, event)
}

/// Linear scan over `rules` returning the first matching rule's verdict.
/// `None` means no rule applied — the caller falls back to the default
/// policy.
pub fn evaluate(rules: &[Rule], event: &ConnectEvent, info: &ProcInfo) -> Option<Verdict> {
    rules
        .iter()
        .find(|r| matches(r, event, info))
        .map(|r| r.verdict)
}

/// Verdict the kernel-side per-PID cache can encode for `exe`.
///
/// The kernel map only short-circuits on a `Verdict::Deny` value, and it
/// stores one verdict per PID — meaning we can only push a rule whose
/// host/port/protocol axes are all `Any`. Per-destination rules stay
/// userspace-only until phase 5+ adds a richer kernel map.
pub fn default_verdict_for_exe(rules: &[Rule], exe: &Path) -> Option<Verdict> {
    rules.iter().find_map(|r| {
        let exe_matches = match &r.exe_match {
            ExeMatch::Any => true,
            ExeMatch::Exact(p) => p == exe,
        };
        let unconditional = matches!(r.host, HostMatch::Any)
            && matches!(r.port, PortMatch::Any)
            && matches!(r.protocol, ProtocolMatch::Any);
        if exe_matches && unconditional {
            Some(r.verdict)
        } else {
            None
        }
    })
}

fn matches_exe(m: &ExeMatch, info: &ProcInfo) -> bool {
    match m {
        ExeMatch::Any => true,
        ExeMatch::Exact(want) => info.exe.as_ref() == Some(want),
    }
}

fn matches_host(m: &HostMatch, event: &ConnectEvent) -> bool {
    let Some(event_ip) = extract_ip(event) else {
        return false;
    };
    match m {
        HostMatch::Any => true,
        HostMatch::Ip(ip) => *ip == event_ip,
        HostMatch::Cidr {
            network,
            prefix_len,
        } => ip_in_cidr(event_ip, *network, *prefix_len),
        // Hostname matching requires DNS reverse-resolution; phase 9.
        HostMatch::Hostname(_) => false,
    }
}

fn matches_port(m: &PortMatch, event: &ConnectEvent) -> bool {
    let p = event.dport;
    match m {
        PortMatch::Any => true,
        PortMatch::Single(want) => *want == p,
        PortMatch::Range {
            start,
            end_inclusive,
        } => p >= *start && p <= *end_inclusive,
    }
}

fn matches_protocol(m: &ProtocolMatch, event: &ConnectEvent) -> bool {
    match m {
        ProtocolMatch::Any => true,
        ProtocolMatch::Tcp => event.protocol == PROTO_TCP,
        ProtocolMatch::Udp => event.protocol == PROTO_UDP,
    }
}

fn extract_ip(event: &ConnectEvent) -> Option<IpAddr> {
    match event.family {
        FAMILY_INET => Some(IpAddr::V4(Ipv4Addr::new(
            event.addr[0],
            event.addr[1],
            event.addr[2],
            event.addr[3],
        ))),
        FAMILY_INET6 => Some(IpAddr::V6(Ipv6Addr::from(event.addr))),
        _ => None,
    }
}

fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(addr), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            let addr_n = u32::from(addr);
            let net_n = u32::from(net);
            let mask = mask_v4(prefix_len);
            (addr_n & mask) == (net_n & mask)
        }
        (IpAddr::V6(addr), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            let addr_n = u128::from(addr);
            let net_n = u128::from(net);
            let mask = mask_v6(prefix_len);
            (addr_n & mask) == (net_n & mask)
        }
        _ => false,
    }
}

fn mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_common::event::COMM_LEN;
    use std::path::PathBuf;
    use std::str::FromStr;

    fn make_event(family: u16, addr: [u8; 16], dport: u16, protocol: u8) -> ConnectEvent {
        ConnectEvent {
            timestamp_ns: 0,
            pid: 1,
            tgid: 1,
            uid: 0,
            gid: 0,
            family,
            protocol,
            _pad0: 0,
            dport,
            _pad1: 0,
            addr,
            comm: [0u8; COMM_LEN],
        }
    }

    fn ipv4_event(a: u8, b: u8, c: u8, d: u8, port: u16) -> ConnectEvent {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[a, b, c, d]);
        make_event(FAMILY_INET, addr, port, PROTO_TCP)
    }

    fn ipv6_event(addr: [u8; 16], port: u16) -> ConnectEvent {
        make_event(FAMILY_INET6, addr, port, PROTO_TCP)
    }

    fn proc_with_exe(path: &str) -> ProcInfo {
        ProcInfo {
            pid: 1,
            start_time: 0,
            exe: Some(PathBuf::from(path)),
            cmdline: vec![],
        }
    }

    fn proc_no_exe() -> ProcInfo {
        ProcInfo {
            pid: 1,
            start_time: 0,
            exe: None,
            cmdline: vec![],
        }
    }

    fn rule(
        exe_match: ExeMatch,
        host: HostMatch,
        port: PortMatch,
        protocol: ProtocolMatch,
        verdict: Verdict,
    ) -> Rule {
        Rule {
            id: 0,
            exe_match,
            host,
            port,
            protocol,
            verdict,
        }
    }

    fn allow_any() -> Rule {
        rule(
            ExeMatch::Any,
            HostMatch::Any,
            PortMatch::Any,
            ProtocolMatch::Any,
            Verdict::Allow,
        )
    }

    // ---- exe matcher --------------------------------------------------

    #[test]
    fn exe_any_matches_anything() {
        assert!(matches_exe(&ExeMatch::Any, &proc_with_exe("/usr/bin/curl")));
        assert!(matches_exe(&ExeMatch::Any, &proc_no_exe()));
    }

    #[test]
    fn exe_exact_matches_exact_path_only() {
        let m = ExeMatch::Exact(PathBuf::from("/usr/bin/curl"));
        assert!(matches_exe(&m, &proc_with_exe("/usr/bin/curl")));
        assert!(!matches_exe(&m, &proc_with_exe("/usr/bin/wget")));
        assert!(!matches_exe(&m, &proc_no_exe()));
    }

    // ---- host matcher -------------------------------------------------

    #[test]
    fn host_any_matches_any_event() {
        let event = ipv4_event(1, 2, 3, 4, 80);
        assert!(matches_host(&HostMatch::Any, &event));
    }

    #[test]
    fn host_ip_matches_exact_v4() {
        let event = ipv4_event(140, 82, 121, 4, 443);
        let m = HostMatch::Ip(IpAddr::from_str("140.82.121.4").unwrap());
        assert!(matches_host(&m, &event));
        let other = HostMatch::Ip(IpAddr::from_str("1.1.1.1").unwrap());
        assert!(!matches_host(&other, &event));
    }

    #[test]
    fn host_ip_matches_exact_v6() {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = 0x01;
        let event = ipv6_event(addr, 443);
        let m = HostMatch::Ip(IpAddr::from_str("2001::1").unwrap());
        assert!(matches_host(&m, &event));
    }

    #[test]
    fn host_cidr_v4_matches_inside_block() {
        let event = ipv4_event(10, 0, 0, 42, 22);
        let m = HostMatch::Cidr {
            network: IpAddr::from_str("10.0.0.0").unwrap(),
            prefix_len: 8,
        };
        assert!(matches_host(&m, &event));
    }

    #[test]
    fn host_cidr_v4_excludes_outside_block() {
        let event = ipv4_event(11, 0, 0, 1, 22);
        let m = HostMatch::Cidr {
            network: IpAddr::from_str("10.0.0.0").unwrap(),
            prefix_len: 8,
        };
        assert!(!matches_host(&m, &event));
    }

    #[test]
    fn host_cidr_prefix_zero_matches_everything() {
        let event = ipv4_event(8, 8, 8, 8, 53);
        let m = HostMatch::Cidr {
            network: IpAddr::from_str("0.0.0.0").unwrap(),
            prefix_len: 0,
        };
        assert!(matches_host(&m, &event));
    }

    #[test]
    fn host_cidr_prefix_thirty_two_acts_like_exact() {
        let event = ipv4_event(1, 1, 1, 1, 53);
        let m = HostMatch::Cidr {
            network: IpAddr::from_str("1.1.1.1").unwrap(),
            prefix_len: 32,
        };
        assert!(matches_host(&m, &event));
        let other_event = ipv4_event(1, 1, 1, 2, 53);
        assert!(!matches_host(&m, &other_event));
    }

    #[test]
    fn host_cidr_v4_does_not_match_v6_event() {
        let mut addr = [0u8; 16];
        addr[12..16].copy_from_slice(&[10, 0, 0, 1]); // ::ffff:10.0.0.1-ish
        let event = ipv6_event(addr, 22);
        let m = HostMatch::Cidr {
            network: IpAddr::from_str("10.0.0.0").unwrap(),
            prefix_len: 8,
        };
        assert!(!matches_host(&m, &event));
    }

    #[test]
    fn host_hostname_never_matches_in_phase_4() {
        let event = ipv4_event(1, 2, 3, 4, 80);
        let m = HostMatch::Hostname("example.com".to_string());
        assert!(!matches_host(&m, &event));
    }

    // ---- port matcher -------------------------------------------------

    #[test]
    fn port_single() {
        let event = ipv4_event(1, 1, 1, 1, 443);
        assert!(matches_port(&PortMatch::Single(443), &event));
        assert!(!matches_port(&PortMatch::Single(80), &event));
    }

    #[test]
    fn port_range_inclusive_bounds() {
        let event_low = ipv4_event(1, 1, 1, 1, 8000);
        let event_high = ipv4_event(1, 1, 1, 1, 8100);
        let event_below = ipv4_event(1, 1, 1, 1, 7999);
        let event_above = ipv4_event(1, 1, 1, 1, 8101);
        let m = PortMatch::Range {
            start: 8000,
            end_inclusive: 8100,
        };
        assert!(matches_port(&m, &event_low));
        assert!(matches_port(&m, &event_high));
        assert!(!matches_port(&m, &event_below));
        assert!(!matches_port(&m, &event_above));
    }

    // ---- protocol matcher --------------------------------------------

    #[test]
    fn protocol_specific() {
        let tcp = make_event(FAMILY_INET, [0; 16], 0, PROTO_TCP);
        let udp = make_event(FAMILY_INET, [0; 16], 0, PROTO_UDP);
        assert!(matches_protocol(&ProtocolMatch::Tcp, &tcp));
        assert!(!matches_protocol(&ProtocolMatch::Udp, &tcp));
        assert!(matches_protocol(&ProtocolMatch::Udp, &udp));
    }

    // ---- evaluate (full pipeline) ------------------------------------

    #[test]
    fn evaluate_returns_first_matching_rule() {
        let event = ipv4_event(140, 82, 121, 4, 443);
        let info = proc_with_exe("/usr/lib/firefox/firefox");

        let deny_github = rule(
            ExeMatch::Any,
            HostMatch::Cidr {
                network: IpAddr::from_str("140.82.0.0").unwrap(),
                prefix_len: 16,
            },
            PortMatch::Any,
            ProtocolMatch::Tcp,
            Verdict::Deny,
        );

        let rules = vec![deny_github, allow_any()];
        assert_eq!(evaluate(&rules, &event, &info), Some(Verdict::Deny));
    }

    #[test]
    fn default_verdict_finds_unconditional_deny_for_exe() {
        let curl = std::path::PathBuf::from("/usr/bin/curl");
        let rules = vec![rule(
            ExeMatch::Exact(curl.clone()),
            HostMatch::Any,
            PortMatch::Any,
            ProtocolMatch::Any,
            Verdict::Deny,
        )];
        assert_eq!(default_verdict_for_exe(&rules, &curl), Some(Verdict::Deny));
    }

    #[test]
    fn default_verdict_skips_destination_specific_rules() {
        let curl = std::path::PathBuf::from("/usr/bin/curl");
        let rules = vec![rule(
            ExeMatch::Exact(curl.clone()),
            HostMatch::Ip(IpAddr::from_str("1.1.1.1").unwrap()),
            PortMatch::Any,
            ProtocolMatch::Any,
            Verdict::Deny,
        )];
        // Destination-specific deny isn't enforceable in the per-PID
        // kernel map, so we report None.
        assert_eq!(default_verdict_for_exe(&rules, &curl), None);
    }

    #[test]
    fn default_verdict_picks_first_matching_rule() {
        let curl = std::path::PathBuf::from("/usr/bin/curl");
        let rules = vec![
            rule(
                ExeMatch::Any,
                HostMatch::Any,
                PortMatch::Any,
                ProtocolMatch::Any,
                Verdict::Allow,
            ),
            rule(
                ExeMatch::Exact(curl.clone()),
                HostMatch::Any,
                PortMatch::Any,
                ProtocolMatch::Any,
                Verdict::Deny,
            ),
        ];
        assert_eq!(default_verdict_for_exe(&rules, &curl), Some(Verdict::Allow));
    }

    #[test]
    fn evaluate_returns_none_when_nothing_matches() {
        let event = ipv4_event(1, 2, 3, 4, 80);
        let info = proc_no_exe();
        let strict = rule(
            ExeMatch::Exact(PathBuf::from("/never/real")),
            HostMatch::Any,
            PortMatch::Any,
            ProtocolMatch::Any,
            Verdict::Allow,
        );
        assert_eq!(evaluate(&[strict], &event, &info), None);
    }
}
