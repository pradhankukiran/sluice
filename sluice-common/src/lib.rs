#![cfg_attr(not(feature = "std"), no_std)]

//! Types shared between the sluice eBPF programs (kernel side) and the
//! userspace daemon / GUI.
//!
//! Anything in this crate is `no_std`-compatible so it can be used from the
//! `sluice-ebpf` crate, which compiles for `bpfel-unknown-none` and cannot
//! depend on libstd.
