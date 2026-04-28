// Wired into main / CLI in subsequent commits this phase.
#![allow(dead_code)]

//! SQLite-backed [`Rule`] persistence.
//!
//! Match values (`ExeMatch`, `HostMatch`, ...) are stored as compact text
//! tags so the DB stays human-inspectable with `sqlite3 rules.db
//! '.dump rules'`. Encoding/decoding lives in this file; the rest of the
//! daemon never sees the wire format.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection, Row};

use crate::rules::schema::apply_migrations;
use crate::rules::types::{ExeMatch, HostMatch, Policy, PortMatch, ProtocolMatch, Rule, Verdict};

/// Phase 4 default when the `default_policy` setting is unset. Allows
/// connections so the daemon remains a passive observer; the operator
/// can switch to `Deny` or (post-phase-7) `Ask` via `policy set`.
const DEFAULT_POLICY: Policy = Policy::Allow;
const SETTING_DEFAULT_POLICY: &str = "default_policy";

pub struct SqliteRuleStore {
    conn: Connection,
}

impl SqliteRuleStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db parent dir {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite db at {}", path.display()))?;
        apply_migrations(&conn).context("applying schema migrations")?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory sqlite")?;
        apply_migrations(&conn).context("applying schema migrations")?;
        Ok(Self { conn })
    }

    /// Insert a rule. The `id` field on the input is ignored; the new
    /// row's auto-increment id is returned.
    pub fn insert(&self, rule: &Rule) -> Result<i64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn.execute(
            "INSERT INTO rules
                 (exe_match, host_match, port_match, protocol_match, verdict, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                encode_exe(&rule.exe_match),
                encode_host(&rule.host),
                encode_port(&rule.port),
                encode_protocol(&rule.protocol),
                encode_verdict(rule.verdict)?,
                now,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list(&self) -> Result<Vec<Rule>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, exe_match, host_match, port_match, protocol_match, verdict
             FROM rules
             ORDER BY id",
        )?;
        let rows: Vec<rusqlite::Result<Result<Rule>>> = stmt
            .query_map([], |row| Ok(decode_rule(row)))?
            .collect();
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    pub fn delete(&self, id: i64) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        Ok(n > 0)
    }

    /// Read the configured default policy. Returns [`DEFAULT_POLICY`]
    /// when the setting is absent or contains an unrecognized value.
    pub fn default_policy(&self) -> Result<Policy> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![SETTING_DEFAULT_POLICY],
                |row| row.get(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map(Some)?
            .flatten();

        Ok(raw
            .as_deref()
            .and_then(Policy::from_str_strict)
            .unwrap_or(DEFAULT_POLICY))
    }

    pub fn set_default_policy(&self, policy: Policy) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![SETTING_DEFAULT_POLICY, policy.as_str()],
        )?;
        Ok(())
    }
}

// ---------- codecs (free fns kept private to this module) ----------

const TAG_ANY: &str = "any";

fn encode_exe(m: &ExeMatch) -> String {
    match m {
        ExeMatch::Any => TAG_ANY.to_string(),
        ExeMatch::Exact(p) => format!("exact:{}", p.display()),
    }
}

fn decode_exe(s: &str) -> Result<ExeMatch> {
    if s == TAG_ANY {
        return Ok(ExeMatch::Any);
    }
    if let Some(rest) = s.strip_prefix("exact:") {
        return Ok(ExeMatch::Exact(PathBuf::from(rest)));
    }
    Err(anyhow!("unknown exe_match encoding: {s}"))
}

fn encode_host(m: &HostMatch) -> String {
    match m {
        HostMatch::Any => TAG_ANY.to_string(),
        HostMatch::Ip(ip) => format!("ip:{ip}"),
        HostMatch::Cidr {
            network,
            prefix_len,
        } => format!("cidr:{network}/{prefix_len}"),
        HostMatch::Hostname(h) => format!("host:{h}"),
    }
}

fn decode_host(s: &str) -> Result<HostMatch> {
    if s == TAG_ANY {
        return Ok(HostMatch::Any);
    }
    if let Some(rest) = s.strip_prefix("ip:") {
        return Ok(HostMatch::Ip(
            IpAddr::from_str(rest).with_context(|| format!("parsing ip:{rest}"))?,
        ));
    }
    if let Some(rest) = s.strip_prefix("cidr:") {
        let (net, prefix) = rest
            .split_once('/')
            .ok_or_else(|| anyhow!("cidr encoding missing `/`: {rest}"))?;
        return Ok(HostMatch::Cidr {
            network: IpAddr::from_str(net).with_context(|| format!("parsing cidr net {net}"))?,
            prefix_len: prefix
                .parse()
                .with_context(|| format!("parsing cidr prefix {prefix}"))?,
        });
    }
    if let Some(rest) = s.strip_prefix("host:") {
        return Ok(HostMatch::Hostname(rest.to_string()));
    }
    Err(anyhow!("unknown host_match encoding: {s}"))
}

fn encode_port(m: &PortMatch) -> String {
    match m {
        PortMatch::Any => TAG_ANY.to_string(),
        PortMatch::Single(p) => format!("single:{p}"),
        PortMatch::Range {
            start,
            end_inclusive,
        } => format!("range:{start}-{end_inclusive}"),
    }
}

fn decode_port(s: &str) -> Result<PortMatch> {
    if s == TAG_ANY {
        return Ok(PortMatch::Any);
    }
    if let Some(rest) = s.strip_prefix("single:") {
        return Ok(PortMatch::Single(rest.parse()?));
    }
    if let Some(rest) = s.strip_prefix("range:") {
        let (start, end) = rest
            .split_once('-')
            .ok_or_else(|| anyhow!("range encoding missing `-`: {rest}"))?;
        return Ok(PortMatch::Range {
            start: start.parse()?,
            end_inclusive: end.parse()?,
        });
    }
    Err(anyhow!("unknown port_match encoding: {s}"))
}

fn encode_protocol(m: &ProtocolMatch) -> String {
    match m {
        ProtocolMatch::Any => TAG_ANY.to_string(),
        ProtocolMatch::Tcp => "tcp".to_string(),
        ProtocolMatch::Udp => "udp".to_string(),
    }
}

fn decode_protocol(s: &str) -> Result<ProtocolMatch> {
    Ok(match s {
        TAG_ANY => ProtocolMatch::Any,
        "tcp" => ProtocolMatch::Tcp,
        "udp" => ProtocolMatch::Udp,
        other => return Err(anyhow!("unknown protocol_match encoding: {other}")),
    })
}

fn encode_verdict(v: Verdict) -> Result<String> {
    Ok(match v {
        Verdict::Allow => "allow".to_string(),
        Verdict::Deny => "deny".to_string(),
        Verdict::Unknown => {
            return Err(anyhow!(
                "Verdict::Unknown is not a valid stored rule verdict"
            ))
        }
    })
}

fn decode_verdict(s: &str) -> Result<Verdict> {
    Ok(match s {
        "allow" => Verdict::Allow,
        "deny" => Verdict::Deny,
        other => return Err(anyhow!("unknown verdict encoding: {other}")),
    })
}

fn decode_rule(row: &Row) -> Result<Rule> {
    let id: i64 = row.get(0)?;
    let exe_match: String = row.get(1)?;
    let host_match: String = row.get(2)?;
    let port_match: String = row.get(3)?;
    let protocol_match: String = row.get(4)?;
    let verdict: String = row.get(5)?;
    Ok(Rule {
        id,
        exe_match: decode_exe(&exe_match)?,
        host: decode_host(&host_match)?,
        port: decode_port(&port_match)?,
        protocol: decode_protocol(&protocol_match)?,
        verdict: decode_verdict(&verdict)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule() -> Rule {
        Rule {
            id: 0,
            exe_match: ExeMatch::Exact(PathBuf::from("/usr/bin/curl")),
            host: HostMatch::Cidr {
                network: IpAddr::from_str("10.0.0.0").unwrap(),
                prefix_len: 8,
            },
            port: PortMatch::Range {
                start: 8000,
                end_inclusive: 8100,
            },
            protocol: ProtocolMatch::Tcp,
            verdict: Verdict::Deny,
        }
    }

    #[test]
    fn insert_and_list_roundtrip() {
        let store = SqliteRuleStore::open_in_memory().unwrap();
        let id = store.insert(&sample_rule()).unwrap();
        assert!(id > 0);

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        let mut expected = sample_rule();
        expected.id = id;
        assert_eq!(listed[0], expected);
    }

    #[test]
    fn delete_removes_rule() {
        let store = SqliteRuleStore::open_in_memory().unwrap();
        let id = store.insert(&sample_rule()).unwrap();
        assert!(store.delete(id).unwrap());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn delete_returns_false_for_missing_id() {
        let store = SqliteRuleStore::open_in_memory().unwrap();
        assert!(!store.delete(9999).unwrap());
    }

    #[test]
    fn rejects_unknown_verdict_on_insert() {
        let store = SqliteRuleStore::open_in_memory().unwrap();
        let mut r = sample_rule();
        r.verdict = Verdict::Unknown;
        assert!(store.insert(&r).is_err());
    }

    #[test]
    fn default_policy_starts_at_allow() {
        let store = SqliteRuleStore::open_in_memory().unwrap();
        assert_eq!(store.default_policy().unwrap(), Policy::Allow);
    }

    #[test]
    fn default_policy_persists() {
        let store = SqliteRuleStore::open_in_memory().unwrap();
        store.set_default_policy(Policy::Deny).unwrap();
        assert_eq!(store.default_policy().unwrap(), Policy::Deny);

        store.set_default_policy(Policy::Ask).unwrap();
        assert_eq!(store.default_policy().unwrap(), Policy::Ask);
    }

    #[test]
    fn encodes_all_host_match_variants() {
        let cases: Vec<(HostMatch, &str)> = vec![
            (HostMatch::Any, "any"),
            (
                HostMatch::Ip(IpAddr::from_str("1.2.3.4").unwrap()),
                "ip:1.2.3.4",
            ),
            (
                HostMatch::Cidr {
                    network: IpAddr::from_str("10.0.0.0").unwrap(),
                    prefix_len: 8,
                },
                "cidr:10.0.0.0/8",
            ),
            (
                HostMatch::Hostname("example.com".to_string()),
                "host:example.com",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(encode_host(&input), expected);
            assert_eq!(decode_host(expected).unwrap(), input);
        }
    }
}
