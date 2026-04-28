//! Render a [`ConnectEvent`] as a human-readable single-line string for
//! logging. The format is stable so tests can assert against it.

use std::net::{Ipv4Addr, Ipv6Addr};

use sluice_common::event::{
    ConnectEvent, COMM_LEN, FAMILY_INET, FAMILY_INET6, PROTO_TCP, PROTO_UDP,
};

use crate::proc_info::ProcInfo;

/// Render a connection event with the resolved executable path from
/// [`ProcInfo`] as the process label. Falls back to the kernel's 16-byte
/// `comm` for kernel threads or processes that exited before we resolved
/// `/proc/<pid>/exe`.
pub fn format_enriched_event(e: &ConnectEvent, info: &ProcInfo) -> String {
    let label = info
        .exe
        .as_ref()
        .map(|exe| exe.display().to_string())
        .unwrap_or_else(|| comm_str(&e.comm));
    format!(
        "{label} pid={pid} uid={uid} -> {dst} ({proto})",
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
        let info = fake_proc_info(None);
        assert_eq!(
            format_enriched_event(&event, &info),
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
        let info = fake_proc_info(None);
        assert_eq!(
            format_enriched_event(&event, &info),
            "firefox pid=4040 uid=1000 -> [2001:db8::1]:443 (TCP)"
        );
    }

    fn fake_proc_info(exe: Option<&str>) -> ProcInfo {
        ProcInfo {
            pid: 4040,
            start_time: 0,
            exe: exe.map(std::path::PathBuf::from),
            cmdline: vec![],
        }
    }

    #[test]
    fn enriched_event_prefers_exe_path_over_comm() {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[140, 82, 121, 4]);
        let event = sample(FAMILY_INET, addr, 443);
        let info = fake_proc_info(Some("/usr/lib/firefox/firefox"));
        assert_eq!(
            format_enriched_event(&event, &info),
            "/usr/lib/firefox/firefox pid=4040 uid=1000 -> 140.82.121.4:443 (TCP)"
        );
    }

    #[test]
    fn enriched_event_falls_back_to_comm_when_exe_missing() {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        let event = sample(FAMILY_INET, addr, 53);
        let info = fake_proc_info(None);
        // comm in `sample` is "firefox".
        assert!(format_enriched_event(&event, &info).starts_with("firefox pid="));
    }

    #[test]
    fn truncated_comm_does_not_overrun() {
        let comm = [b'x'; COMM_LEN];
        // No null terminator at all — comm fills the full 16 bytes.
        let mut event = sample(FAMILY_INET, [0; 16], 80);
        event.comm = comm;
        let info = fake_proc_info(None);
        let s = format_enriched_event(&event, &info);
        assert!(s.contains(&"x".repeat(COMM_LEN)));
    }
}
