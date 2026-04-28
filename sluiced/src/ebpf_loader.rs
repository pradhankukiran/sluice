//! Locate the compiled `sluice-ebpf` bytecode and load it through Aya.
//!
//! Lookup order:
//!
//! 1. `SLUICE_EBPF_BYTECODE` environment variable (explicit override).
//! 2. Compile-time path inside the workspace —
//!    `<workspace>/sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf`.
//!    This is what `cargo run -p sluiced` and `cargo run -p xtask -- run-daemon`
//!    pick up after the eBPF crate has been built.

use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::Ebpf;

const ENV_OVERRIDE: &str = "SLUICE_EBPF_BYTECODE";

/// Compile-time fallback path. Resolved relative to the `sluiced` crate so
/// `cargo run -p sluiced` works without setting an env var.
const DEFAULT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sluice-ebpf/target/bpfel-unknown-none/release/sluice-ebpf",
);

pub fn bytecode_path() -> PathBuf {
    env::var(ENV_OVERRIDE)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PATH))
}

/// Load the eBPF object from disk into an [`Ebpf`] handle. Programs and
/// maps are not yet attached — callers chain `.program_mut(...).load()` and
/// `.attach(...)` themselves.
pub fn load() -> Result<Ebpf> {
    let path = bytecode_path();
    Ebpf::load_file(&path).with_context(|| {
        format!(
            "loading sluice-ebpf bytecode from {}. \
             Build it with `cargo run -p xtask -- build-ebpf` or set {ENV_OVERRIDE}.",
            path.display()
        )
    })
}
