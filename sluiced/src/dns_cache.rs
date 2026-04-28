//! Hostname → IP TTL cache.
//!
//! Phase 9 takes the *forward-lookup* path: for every rule with
//! `HostMatch::Hostname(h)`, we resolve `h` via the system resolver
//! (`getaddrinfo`) at startup and on mutation, store the answer with a
//! fixed TTL, and let the matcher check whether a connection's
//! destination IP is in the resolved set.
//!
//! A more thorough alternative — sniffing live DNS responses with a
//! `tc-bpf` ingress program and back-mapping observed IPs to the
//! hostnames the application *actually* requested — is documented as
//! future work in `docs/phase-9.md`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::lookup_host;

use crate::rules::types::{HostMatch, Rule};

/// How long a resolution is reused before the cache forces a refresh.
/// Stdlib's resolver hides per-record TTLs, so we apply a uniform
/// conservative window.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
struct Resolved {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

#[derive(Default)]
pub struct DnsCache {
    entries: HashMap<String, Resolved>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the cached IPs for `hostname`. Returns `None` if missing
    /// or stale; the caller should trigger a `refresh` and try again.
    pub fn lookup(&self, hostname: &str) -> Option<&[IpAddr]> {
        let entry = self.entries.get(hostname)?;
        if Instant::now() >= entry.expires_at {
            return None;
        }
        Some(&entry.addrs)
    }

    /// Whether `addr` is among the cached resolutions for `hostname`.
    /// Returns `false` when the entry is missing or stale.
    pub fn contains(&self, hostname: &str, addr: IpAddr) -> bool {
        self.lookup(hostname)
            .map(|addrs| addrs.contains(&addr))
            .unwrap_or(false)
    }

    /// Replace (or insert) the cached entry for `hostname`. Used by
    /// the resolver helper after a successful `getaddrinfo`.
    pub fn insert(&mut self, hostname: &str, addrs: Vec<IpAddr>, ttl: Duration) {
        let expires_at = Instant::now() + ttl;
        self.entries
            .insert(hostname.to_string(), Resolved { addrs, expires_at });
    }

    /// Drop entries whose TTL has lapsed. Cheap to call; runs O(n).
    /// Currently exercised only by the test suite — a periodic refresh
    /// task is mentioned as future work in `docs/phase-9.md`.
    #[cfg(test)]
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, v| v.expires_at > now);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Hostnames referenced by `rules` whose cache entry is missing or
    /// stale. Returned in a stable order; callers feed this list into
    /// [`resolve`] outside any lock and then push the results back via
    /// [`apply_resolutions`].
    pub fn stale_targets(&self, rules: &[Rule]) -> Vec<String> {
        let now = Instant::now();
        let mut targets: Vec<String> = rules
            .iter()
            .filter_map(|r| match &r.host {
                HostMatch::Hostname(h) => Some(h.clone()),
                _ => None,
            })
            .filter(|h| match self.entries.get(h) {
                Some(entry) => entry.expires_at <= now,
                None => true,
            })
            .collect();
        targets.sort();
        targets.dedup();
        targets
    }

    /// Insert a batch of resolutions, replacing any existing entries.
    pub fn apply_resolutions(&mut self, resolutions: Vec<(String, Vec<IpAddr>)>, ttl: Duration) {
        for (name, addrs) in resolutions {
            self.insert(&name, addrs, ttl);
        }
    }

    /// Owned-mut variant of the refresh workflow. Used at daemon
    /// startup when the cache is not yet behind an `Arc<RwLock>`. Holds
    /// `&mut self` across await points; do not call from contexts where
    /// the cache is shared.
    pub async fn refresh_for_rules(&mut self, rules: &[Rule]) {
        let targets = self.stale_targets(rules);
        for hostname in targets {
            match resolve(&hostname).await {
                Ok(addrs) => self.insert(&hostname, addrs, DEFAULT_TTL),
                Err(err) => {
                    tracing::warn!(hostname, error = %err, "DNS resolve failed");
                }
            }
        }
    }
}

/// Refresh a shared `DnsCache` against the given rules without ever
/// holding the write lock across `.await`. Lock-then-snapshot, resolve,
/// lock-then-apply — the pattern that lets this run inside a
/// `tokio::spawn` whose future must be `Send`.
pub async fn refresh_shared(cache: Arc<RwLock<DnsCache>>, rules: &[Rule]) {
    let targets = match cache.read() {
        Ok(g) => g.stale_targets(rules),
        Err(_) => return,
    };
    let mut resolved: Vec<(String, Vec<IpAddr>)> = Vec::with_capacity(targets.len());
    for hostname in targets {
        match resolve(&hostname).await {
            Ok(addrs) => resolved.push((hostname, addrs)),
            Err(err) => {
                tracing::warn!(hostname, error = %err, "DNS resolve failed");
            }
        }
    }
    if !resolved.is_empty() {
        if let Ok(mut g) = cache.write() {
            g.apply_resolutions(resolved, DEFAULT_TTL);
        }
    }
}

/// Resolve `hostname` through the system resolver. Returns IP addresses
/// only — the synthetic port `0` is stripped.
pub async fn resolve(hostname: &str) -> Result<Vec<IpAddr>> {
    let target = format!("{hostname}:0");
    let iter = lookup_host(target.as_str())
        .await
        .with_context(|| format!("resolving {hostname}"))?;
    let mut out: Vec<IpAddr> = iter.map(|s: SocketAddr| s.ip()).collect();
    // Stable order makes tests deterministic and matchers consistent.
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::thread::sleep;

    #[test]
    fn lookup_returns_inserted_entry() {
        let mut cache = DnsCache::new();
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ];
        cache.insert("example.com", addrs.clone(), Duration::from_secs(60));
        assert_eq!(cache.lookup("example.com"), Some(addrs.as_slice()));
    }

    #[test]
    fn lookup_returns_none_when_expired() {
        let mut cache = DnsCache::new();
        cache.insert(
            "example.com",
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            Duration::from_millis(20),
        );
        sleep(Duration::from_millis(40));
        assert!(cache.lookup("example.com").is_none());
    }

    #[test]
    fn contains_checks_resolved_set() {
        let mut cache = DnsCache::new();
        let addr = IpAddr::from_str("140.82.121.4").unwrap();
        cache.insert("github.com", vec![addr], Duration::from_secs(60));
        assert!(cache.contains("github.com", addr));
        assert!(!cache.contains("github.com", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!cache.contains("not-cached.example", addr));
    }

    #[test]
    fn purge_expired_drops_only_stale_entries() {
        let mut cache = DnsCache::new();
        cache.insert(
            "fresh",
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            Duration::from_secs(60),
        );
        cache.insert(
            "stale",
            vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
            Duration::from_millis(10),
        );
        sleep(Duration::from_millis(30));
        cache.purge_expired();
        assert!(cache.lookup("fresh").is_some());
        assert!(cache.lookup("stale").is_none());
    }

    #[tokio::test]
    async fn resolve_localhost_returns_loopback() {
        // `localhost` is in /etc/hosts on every reasonable system, so
        // this test doesn't depend on external DNS.
        let addrs = resolve("localhost").await.unwrap();
        assert!(addrs.iter().any(|ip| ip.is_loopback()));
    }

    #[tokio::test]
    async fn refresh_resolves_only_hostname_rules() {
        use crate::rules::types::{ExeMatch, PortMatch, ProtocolMatch, Verdict};

        let rules = vec![
            // No hostname; refresh should ignore.
            Rule {
                id: 1,
                exe_match: ExeMatch::Any,
                host: HostMatch::Any,
                port: PortMatch::Any,
                protocol: ProtocolMatch::Any,
                verdict: Verdict::Allow,
            },
            // Hostname rule referencing localhost (in /etc/hosts).
            Rule {
                id: 2,
                exe_match: ExeMatch::Any,
                host: HostMatch::Hostname("localhost".to_string()),
                port: PortMatch::Any,
                protocol: ProtocolMatch::Any,
                verdict: Verdict::Deny,
            },
        ];
        let mut cache = DnsCache::new();
        cache.refresh_for_rules(&rules).await;
        assert_eq!(cache.len(), 1);
        assert!(cache.lookup("localhost").is_some());
    }
}
