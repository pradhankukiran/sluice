//! `cgroup/sock_create` program.
//!
//! Fires whenever a process in the attached cgroup creates a socket
//! (TCP, UDP, or any other AF_INET/AF_INET6 socket). We grab the
//! current TGID and the socket's cookie and store them in `SOCK_PIDS`
//! so the tc-bpf egress classifier can attribute packets to the
//! issuing process even though tc-bpf runs in softirq context.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, gen::bpf_get_socket_cookie},
    macros::cgroup_sock,
    programs::SockContext,
};

use crate::maps::SOCK_PIDS;

/// `cgroup/sock_create` programs return `1` to allow the socket
/// creation; `0` would block it. We never block — only observe.
const ALLOW: i32 = 1;

#[cgroup_sock(sock_create)]
pub fn sluice_sock_create(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as *mut _) };
    if cookie == 0 {
        return ALLOW;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // BPF_ANY = update existing or insert.
    let _ = SOCK_PIDS.insert(&cookie, &tgid, 0);
    ALLOW
}
