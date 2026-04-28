#![no_std]
#![no_main]

//! Kernel-side sluice eBPF programs.
//!
//! Phase 1 ships only the no_std/no_main scaffolding and a panic handler.
//! Real probes (`cgroup/connect4`, `cgroup/connect6`, `tc-bpf` egress) land
//! in subsequent phases.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // eBPF programs cannot panic — the verifier rejects unbounded loops and
    // there is no runtime to handle them. Loop forever; in practice this
    // path is never reached because the verifier prunes panic branches.
    loop {}
}
