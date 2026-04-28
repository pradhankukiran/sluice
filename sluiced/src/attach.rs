//! Attach the kernel-side eBPF programs.
//!
//! - `cgroup/connect4` and `cgroup/connect6` for the verdict + event path.
//! - `cgroup/sock_create` for socket-cookie → PID resolution.
//! - tc-bpf egress classifier for per-PID rate limiting (separately
//!   attached per interface, see [`attach_tc_egress_to_all_interfaces`]).
//!
//! Returned link ids are dropped immediately — the kernel keeps each
//! program attached as long as the program fd inside `Ebpf` stays
//! alive. The daemon holds the `Ebpf` for its lifetime.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use aya::programs::{tc, CgroupAttachMode, CgroupSock, CgroupSockAddr, SchedClassifier, TcAttachType};
use aya::Ebpf;

const PROG_CONNECT4: &str = "sluice_connect4";
const PROG_CONNECT6: &str = "sluice_connect6";
const PROG_SOCK_CREATE: &str = "sluice_sock_create";
const PROG_TC_EGRESS: &str = "sluice_tc_egress";

/// Attach the cgroup-scoped programs (connect4/6, sock_create) to the
/// cgroup v2 root. Returns the program names that were attached.
pub fn attach_cgroup_programs(bpf: &mut Ebpf, cgroup_root: &Path) -> Result<Vec<&'static str>> {
    let cgroup = File::open(cgroup_root)
        .with_context(|| format!("opening cgroup root {}", cgroup_root.display()))?;

    Ok(vec![
        load_and_attach_sock_addr(bpf, PROG_CONNECT4, &cgroup)?,
        load_and_attach_sock_addr(bpf, PROG_CONNECT6, &cgroup)?,
        load_and_attach_sock(bpf, PROG_SOCK_CREATE, &cgroup)?,
    ])
}

fn load_and_attach_sock_addr(
    bpf: &mut Ebpf,
    name: &'static str,
    cgroup: &File,
) -> Result<&'static str> {
    let prog: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .with_context(|| format!("eBPF object missing program `{name}`"))?
        .try_into()
        .with_context(|| format!("program `{name}` is not a CgroupSockAddr"))?;

    prog.load().with_context(|| format!("loading `{name}`"))?;
    let _link = prog
        .attach(cgroup, CgroupAttachMode::Single)
        .with_context(|| format!("attaching `{name}` to cgroup"))?;
    Ok(name)
}

fn load_and_attach_sock(
    bpf: &mut Ebpf,
    name: &'static str,
    cgroup: &File,
) -> Result<&'static str> {
    let prog: &mut CgroupSock = bpf
        .program_mut(name)
        .with_context(|| format!("eBPF object missing program `{name}`"))?
        .try_into()
        .with_context(|| format!("program `{name}` is not a CgroupSock"))?;

    prog.load().with_context(|| format!("loading `{name}`"))?;
    let _link = prog
        .attach(cgroup, CgroupAttachMode::Single)
        .with_context(|| format!("attaching `{name}` to cgroup"))?;
    Ok(name)
}

/// Install the `clsact` qdisc on `interface` if it isn't already there
/// and attach the tc-bpf egress classifier. Idempotent on the qdisc
/// side: re-running on an interface that already has clsact is fine —
/// the netlink layer returns `EEXIST` which we treat as success.
pub fn attach_tc_egress(bpf: &mut Ebpf, interface: &str) -> Result<()> {
    // qdisc_add_clsact returns Err on EEXIST; ignore that case.
    if let Err(err) = tc::qdisc_add_clsact(interface) {
        tracing::debug!(
            interface,
            error = %err,
            "qdisc_add_clsact failed (already installed?)"
        );
    }

    let prog: &mut SchedClassifier = bpf
        .program_mut(PROG_TC_EGRESS)
        .with_context(|| format!("eBPF object missing program `{PROG_TC_EGRESS}`"))?
        .try_into()
        .with_context(|| format!("program `{PROG_TC_EGRESS}` is not a SchedClassifier"))?;

    if !is_loaded(prog) {
        prog.load()
            .with_context(|| format!("loading `{PROG_TC_EGRESS}`"))?;
    }

    let _link = prog
        .attach(interface, TcAttachType::Egress)
        .with_context(|| format!("attaching `{PROG_TC_EGRESS}` to {interface} egress"))?;
    Ok(())
}

/// Walk `/sys/class/net`, attach the tc-bpf egress classifier to every
/// non-loopback interface that's UP. Returns the interface names that
/// were attached. Errors per-interface are logged and skipped — a
/// failure on `vboxnet0` shouldn't take down sluiced.
pub fn attach_tc_egress_to_all_interfaces(bpf: &mut Ebpf) -> Result<Vec<String>> {
    let interfaces = list_attachable_interfaces()?;
    let mut attached = Vec::new();
    for iface in interfaces {
        match attach_tc_egress(bpf, &iface) {
            Ok(()) => {
                tracing::info!(interface = %iface, "tc-bpf egress attached");
                attached.push(iface);
            }
            Err(err) => {
                tracing::warn!(
                    interface = %iface,
                    error = %err,
                    "tc-bpf egress attachment failed"
                );
            }
        }
    }
    Ok(attached)
}

fn list_attachable_interfaces() -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net").context("listing /sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str == "lo" {
            continue;
        }
        // Only attach if the interface is up.
        let operstate_path = entry.path().join("operstate");
        let operstate = std::fs::read_to_string(&operstate_path)
            .unwrap_or_else(|_| String::from("unknown"));
        let operstate = operstate.trim();
        if operstate == "up" || operstate == "unknown" {
            out.push(name_str.to_string());
        }
    }
    out.sort();
    Ok(out)
}

fn is_loaded(prog: &SchedClassifier) -> bool {
    // Aya re-rejects `load()` on an already-loaded program. There's no
    // public accessor for the loaded state, but `fd()` returns Err when
    // unloaded — cheap probe.
    prog.fd().is_ok()
}
