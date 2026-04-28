//! `cgroup/connect4` program.
//!
//! Fires on every IPv4 outbound `connect()` from any process in the attached
//! cgroup. Phase 2 is passive: we record the attempt and always allow.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::cgroup_sock_addr,
    programs::SockAddrContext,
};
use sluice_common::event::{ConnectEvent, COMM_LEN, FAMILY_INET, PROTO_TCP};

use crate::maps::EVENTS;

/// Allow the connection.
const ACTION_ALLOW: i32 = 1;

#[cgroup_sock_addr(connect4)]
pub fn sluice_connect4(ctx: SockAddrContext) -> i32 {
    let _ = emit_event(&ctx);
    ACTION_ALLOW
}

fn emit_event(ctx: &SockAddrContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    // The verifier permits direct field access on the `bpf_sock_addr`
    // context pointer for cgroup_sock_addr programs.
    //
    // `user_ip4` is a `__u32` whose in-memory bytes are the IPv4 address in
    // network byte order. On a little-endian eBPF target, `to_ne_bytes()`
    // returns those memory bytes unchanged, so `addr[0..4]` ends up holding
    // the address ready for `Ipv4Addr::from`.
    //
    // `user_port` is a `__u32` whose first two memory bytes hold the port
    // in network byte order; the remaining two are zero. We pull those two
    // bytes and decode big-endian to get the host-order port.
    let (user_ip4, user_port) = unsafe {
        let sa = ctx.sock_addr;
        ((*sa).user_ip4, (*sa).user_port)
    };

    let ip4_ne = user_ip4.to_ne_bytes();
    let mut addr = [0u8; 16];
    addr[0] = ip4_ne[0];
    addr[1] = ip4_ne[1];
    addr[2] = ip4_ne[2];
    addr[3] = ip4_ne[3];

    let port_ne = user_port.to_ne_bytes();
    let dport = u16::from_be_bytes([port_ne[0], port_ne[1]]);

    let event = ConnectEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        // `bpf_get_current_pid_tgid()` returns `(tgid << 32) | pid`. We
        // store kernel-side pid/tgid; userspace displays tgid as "PID".
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        family: FAMILY_INET,
        protocol: PROTO_TCP,
        _pad0: 0,
        dport,
        _pad1: 0,
        addr,
        comm,
    };

    EVENTS.output(&event, 0)
}
