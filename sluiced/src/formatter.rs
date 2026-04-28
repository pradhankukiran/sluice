//! Render a [`ConnectEvent`] as a human-readable single-line string for
//! logging. The format is stable so tests can assert against it.

use std::net::{Ipv4Addr, Ipv6Addr};

use sluice_common::event::{
    ConnectEvent, COMM_LEN, FAMILY_INET, FAMILY_INET6, PROTO_TCP, PROTO_UDP,
};

pub fn format_event(e: &ConnectEvent) -> String {
    format!(
        "{comm} pid={pid} uid={uid} -> {dst} ({proto})",
        comm = comm_str(&e.comm),
        pid = e.tgid,
        uid = e.uid,
        dst = format_destination(e),
        proto = format_protocol(e.protocol),
    )
}

fn comm_str(comm: &[u8; COMM_LEN]) -> String {
    let null_pos = comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
    String::from_utf8_lossy(&comm[..null_pos]).into_owned()
}

fn format_protocol(proto: u8) -> &'static str {
    match proto {
        PROTO_TCP => "TCP",
        PROTO_UDP => "UDP",
        _ => "?",
    }
}

fn format_destination(e: &ConnectEvent) -> String {
    match e.family {
        FAMILY_INET => {
            let ip = Ipv4Addr::new(e.addr[0], e.addr[1], e.addr[2], e.addr[3]);
            format!("{ip}:{}", e.dport)
        }
        FAMILY_INET6 => {
            let ip = Ipv6Addr::from(e.addr);
            format!("[{ip}]:{}", e.dport)
        }
        other => format!("(family={other}):{}", e.dport),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(family: u16, addr: [u8; 16], dport: u16) -> ConnectEvent {
        let mut comm = [0u8; COMM_LEN];
        let bytes = b"firefox";
        comm[..bytes.len()].copy_from_slice(bytes);
        ConnectEvent {
            timestamp_ns: 0,
            pid: 4242,
            tgid: 4040,
            uid: 1000,
            gid: 1000,
            family,
            protocol: PROTO_TCP,
            _pad0: 0,
            dport,
            _pad1: 0,
            addr,
            comm,
        }
    }

    #[test]
    fn ipv4_event_formats_dotted_quad() {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[140, 82, 121, 4]); // GitHub
        let event = sample(FAMILY_INET, addr, 443);
        assert_eq!(
            format_event(&event),
            "firefox pid=4040 uid=1000 -> 140.82.121.4:443 (TCP)"
        );
    }

    #[test]
    fn ipv6_event_formats_bracketed() {
        // 2001:db8::1
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 0x01;
        let event = sample(FAMILY_INET6, addr, 443);
        assert_eq!(
            format_event(&event),
            "firefox pid=4040 uid=1000 -> [2001:db8::1]:443 (TCP)"
        );
    }

    #[test]
    fn truncated_comm_does_not_overrun() {
        let mut comm = [b'x'; COMM_LEN];
        // No null terminator at all — comm fills the full 16 bytes.
        let mut event = sample(FAMILY_INET, [0; 16], 80);
        event.comm = comm;
        // Smoke test: we should print all 16 bytes.
        let s = format_event(&event);
        assert!(s.contains(&"x".repeat(COMM_LEN)));
        // Touch comm to suppress unused_mut.
        comm[0] = 0;
        assert_eq!(comm[0], 0);
    }
}
