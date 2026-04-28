//! `xtask` — orchestrates builds that span the userspace workspace and the
//! standalone `sluice-ebpf` crate.
//!
//! Subcommands:
//!
//! - `build-ebpf`   — build the kernel-side crate for `bpfel-unknown-none`.
//! - `build`        — build eBPF then userspace.
//! - `run-daemon`   — `cargo run -p sluiced` (after building eBPF).
//! - `run-gui`      — `cargo run -p sluice`.

use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().ok_or_else(|| anyhow!(usage()))?;
    let rest: Vec<String> = args.collect();

    match cmd.as_str() {
        "build-ebpf" => build_ebpf(&rest),
        "build" => {
            build_ebpf(&rest)?;
            build_userspace(&rest)
        }
        "run-daemon" => {
            build_ebpf(&rest)?;
            cargo_run("sluiced", &rest)
        }
        "run-gui" => cargo_run("sluice", &rest),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        other => bail!("unknown subcommand: {other}\n\n{}", usage()),
    }
}

fn usage() -> String {
    "usage: cargo run -p xtask -- <build-ebpf|build|run-daemon|run-gui>".to_string()
}

fn build_ebpf(extra: &[String]) -> Result<()> {
    let ebpf_dir = workspace_root()?.join("sluice-ebpf");
    let mut cmd = Command::new("cargo");
    // The outer `cargo run -p xtask` exports `RUSTUP_TOOLCHAIN` and
    // `CARGO_*` env vars that pin us to the userspace stable toolchain.
    // The nested cargo invocation needs to re-resolve from the eBPF crate's
    // own `rust-toolchain.toml` (nightly + rust-src for `-Z build-std`),
    // so strip those overrides before spawning.
    cmd.env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("CARGO_MANIFEST_DIR")
        .env_remove("CARGO_TARGET_DIR")
        .arg("build")
        .arg("--release")
        .args(extra)
        .current_dir(&ebpf_dir);
    run(cmd, "cargo build (sluice-ebpf)")
}

fn build_userspace(extra: &[String]) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--workspace").args(extra);
    run(cmd, "cargo build (userspace)")
}

fn cargo_run(package: &str, extra: &[String]) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("run").arg("-p").arg(package).arg("--").args(extra);
    run(cmd, &format!("cargo run -p {package}"))
}

fn run(mut cmd: Command, label: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn `{label}`"))?;
    if !status.success() {
        bail!("`{label}` exited with {status}");
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    // The xtask binary is launched as `cargo run -p xtask`, so CARGO_MANIFEST_DIR
    // points at `xtask/`. Its parent is the workspace root.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("could not determine workspace root from {manifest:?}"))
}
