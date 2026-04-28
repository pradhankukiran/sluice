// `evaluate` lights up alongside `RuleStore` — until then `matches` is
// the only public entry. Allow until the store and main wiring land.
#![allow(dead_code)]

//! Rule-matching predicate. Pure function over `(Rule, ConnectEvent,
//! ProcInfo)`; exercised by both unit tests and the `RuleStore` lookup
//! path in later commits this phase.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
