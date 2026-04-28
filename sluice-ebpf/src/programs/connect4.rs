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

fn emit_event(_ctx: &SockAddrContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

    let event = ConnectEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        // bpf_get_current_pid_tgid() returns `(tgid << 32) | pid`. We treat
        // the `pid` field as the kernel thread id and `tgid` as the
        // userspace-visible process id (what `ps` shows).
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        family: FAMILY_INET,
        protocol: PROTO_TCP,
        _pad0: 0,
        dport: 0,
        _pad1: 0,
        addr: [0u8; 16],
        comm,
    };

    EVENTS.output(&event, 0)
}
