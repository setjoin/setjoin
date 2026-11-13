use crate::store::OfflineError;
/// Generic offline-core schema — tables every encrypted store carries.
///
/// Mail app schema (mc_messages / mc_bodies / mc_search) is NOT here; it is
/// applied by the TS layer through the bridge (Task 8 migrations). These three
/// tables are offline-core infrastructure, independent of the application.
use rusqlite::Connection;

/// Create the generic offline-core tables inside the encrypted store.
///
/// Idempotent via CREATE TABLE IF NOT EXISTS. Safe to call on every open.
pub fn apply_generic(conn: &Connection) -> Result<(), OfflineError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS oc_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oc_outbound (
            id         INTEGER PRIMARY KEY,
            payload    TEXT    NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        CREATE TABLE IF NOT EXISTS oc_sync_issues (
            id         INTEGER PRIMARY KEY,
            kind       TEXT    NOT NULL,
            detail     TEXT,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );",
    )?;
    Ok(())
}
