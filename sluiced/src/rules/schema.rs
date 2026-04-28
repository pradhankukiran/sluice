//! SQL schema and migration runner.
//!
//! Migrations are applied idempotently via a `schema_version` row. New
//! versions are appended to [`MIGRATIONS`] — the runner advances the
//! schema one step at a time, recording each applied version, so the
//! daemon survives upgrades without manual SQL.

use rusqlite::{params, Connection, Result};

/// Each entry is the DDL/DML to advance the schema *to* that 1-based
/// version (index 0 → version 1, index 1 → version 2, ...).
const MIGRATIONS: &[&str] = &[
    // v1 — initial rules + settings tables.
    r#"
    CREATE TABLE rules (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        exe_match       TEXT NOT NULL,
        host_match      TEXT NOT NULL,
        port_match      TEXT NOT NULL,
        protocol_match  TEXT NOT NULL,
        verdict         TEXT NOT NULL,
        created_at      INTEGER NOT NULL
    );
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    "#,
];

pub fn apply_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );",
    )?;

    let current: u32 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;

    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let target = (i as u32) + 1;
        if target > current {
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                params![target],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_in_memory() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn fresh_db_advances_to_latest_version() {
        let conn = open_in_memory();
        apply_migrations(&conn).unwrap();

        let version: u32 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as u32);
    }

    #[test]
    fn rerunning_migrations_is_idempotent() {
        let conn = open_in_memory();
        apply_migrations(&conn).unwrap();
        apply_migrations(&conn).unwrap();
        apply_migrations(&conn).unwrap();

        let version_count: u32 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version_count, MIGRATIONS.len() as u32);
    }

    #[test]
    fn rules_table_is_created_with_expected_columns() {
        let conn = open_in_memory();
        apply_migrations(&conn).unwrap();

        // PRAGMA table_info returns one row per column.
        let mut stmt = conn.prepare("PRAGMA table_info(rules)").unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(
            names,
            vec![
                "id",
                "exe_match",
                "host_match",
                "port_match",
                "protocol_match",
                "verdict",
                "created_at",
            ]
        );
    }
}
