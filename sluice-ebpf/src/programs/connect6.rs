//! `cgroup/connect6` program.
//!
//! IPv6 counterpart to `connect4`. The `user_ip6` field is a `[__u32; 4]`
//! whose underlying 16 bytes are the address in network byte order; on the
//! little-endian eBPF target, the in-memory bytes can be copied directly.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::cgroup_sock_addr,
    programs::SockAddrContext,
};
use sluice_common::event::{ConnectEvent, COMM_LEN, FAMILY_INET6, PROTO_TCP};
use sluice_common::Verdict;

use crate::maps::{EVENTS, VERDICTS};

/// Allow the connection.
const ACTION_ALLOW: i32 = 1;
/// Deny the connection — kernel returns ECONNREFUSED to the caller.
const ACTION_DENY: i32 = 0;

const VERDICT_DENY: u32 = Verdict::Deny.as_u32();

#[cgroup_sock_addr(connect6)]
pub fn sluice_connect6(ctx: SockAddrContext) -> i32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let deny_in_kernel = unsafe { VERDICTS.get(&tgid) }
        .map(|v| *v == VERDICT_DENY)
        .unwrap_or(false);

    let _ = emit_event(&ctx);

    if deny_in_kernel {
        ACTION_DENY
    } else {
        ACTION_ALLOW
    }
}

fn emit_event(ctx: &SockAddrContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    let (user_ip6, user_port) = unsafe {
        let sa = ctx.sock_addr;
        ((*sa).user_ip6, (*sa).user_port)
    };

    // Each __u32 element of user_ip6 is in network byte order. Unrolling
    // so the verifier doesn't have to reason about a loop bound.
    let mut addr = [0u8; 16];
    let w0 = user_ip6[0].to_ne_bytes();
    let w1 = user_ip6[1].to_ne_bytes();
    let w2 = user_ip6[2].to_ne_bytes();
    let w3 = user_ip6[3].to_ne_bytes();
    addr[0] = w0[0];
    addr[1] = w0[1];
    addr[2] = w0[2];
    addr[3] = w0[3];
    addr[4] = w1[0];
    addr[5] = w1[1];
    addr[6] = w1[2];
    addr[7] = w1[3];
    addr[8] = w2[0];
    addr[9] = w2[1];
    addr[10] = w2[2];
    addr[11] = w2[3];
    addr[12] = w3[0];
    addr[13] = w3[1];
    addr[14] = w3[2];
    addr[15] = w3[3];

    let port_ne = user_port.to_ne_bytes();
    let dport = u16::from_be_bytes([port_ne[0], port_ne[1]]);

    let event = ConnectEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        family: FAMILY_INET6,
        protocol: PROTO_TCP,
        _pad0: 0,
        dport,
        _pad1: 0,
        addr,
        comm,
    };

    EVENTS.output(&event, 0)
}
