//! Sluice rule engine — userspace.
//!
//! Phase 4 lives entirely in userspace: the daemon evaluates each
//! `ConnectEvent` against a `RuleStore` and *logs* the verdict it would
//! apply. The eBPF program still always allows. Active blocking, with a
//! kernel-side rule cache, arrives in phase 5.
//!
//! Submodules:
//!
//! - [`types`]   — `Rule`, `HostMatch`, `PortMatch`, `ProtocolMatch`,
//!   plus a re-export of [`sluice_common::Verdict`].
//! - [`matcher`] — predicate that decides whether a [`Rule`] applies to a
//!   given `(ConnectEvent, ProcInfo)` pair.
//! - [`store`]   — `SqliteRuleStore` persistence layer.
//! - [`policy`]  — default policy when no rule matches.
//! - [`schema`]  — SQL DDL + migrations.

// Submodule files (`types`, `matcher`, etc.) land in subsequent commits
// this phase. This `mod.rs` exists now to anchor the directory.
