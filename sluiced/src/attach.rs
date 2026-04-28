//! Attach `cgroup/connect4` and `cgroup/connect6` programs to the cgroup
//! v2 root.
//!
//! Aya's `Ebpf::program_mut(name)` returns a generic `Program`; we narrow
//! it to `CgroupSockAddr` before calling `.load()` and `.attach(cgroup_fd,
//! CgroupAttachMode)`. Returned link ids are kept alive for the lifetime
//! of the daemon so the kernel keeps the program attached.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf;

const PROG_CONNECT4: &str = "sluice_connect4";
const PROG_CONNECT6: &str = "sluice_connect6";

/// Returns the names of the programs that were attached, in order.
pub fn attach_connect_programs(bpf: &mut Ebpf, cgroup_root: &Path) -> Result<Vec<&'static str>> {
    let cgroup = File::open(cgroup_root)
        .with_context(|| format!("opening cgroup root {}", cgroup_root.display()))?;

    Ok(vec![
        load_and_attach(bpf, PROG_CONNECT4, &cgroup)?,
        load_and_attach(bpf, PROG_CONNECT6, &cgroup)?,
    ])
}

fn load_and_attach(bpf: &mut Ebpf, name: &'static str, cgroup: &File) -> Result<&'static str> {
    let prog: &mut CgroupSockAddr = bpf
        .program_mut(name)
        .with_context(|| format!("eBPF object missing program `{name}`"))?
        .try_into()
        .with_context(|| format!("program `{name}` is not a CgroupSockAddr"))?;

    prog.load().with_context(|| format!("loading `{name}`"))?;

    // The returned link id is held inside the kernel by the program fd
    // stored in `bpf`; dropping the id locally does not detach.
    let _link = prog
        .attach(cgroup, CgroupAttachMode::Single)
        .with_context(|| format!("attaching `{name}` to cgroup"))?;

    Ok(name)
}
