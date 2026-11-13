use crate::GuardError;
use rusqlite::Connection;

pub fn apply_migrations(conn: &Connection) -> Result<(), GuardError> {
    // secure_delete=ON zeroes freed content on every DELETE so deleted ciphertext
    // (TOTP seeds, vault items, secure-store values) is not recoverable from the
    // file's free list — load-bearing for the remote-wipe guarantee (mark_wiped
    // also VACUUMs + truncates the WAL). Per-connection, so set on every open.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;",
    )?;
    // This is a PLAINTEXT SQLite file (rusqlite 'bundled', no SQLCipher); secrecy
    // is column-level, not whole-DB. seed_enc/uri_enc/data_enc hold AES-256-GCM
    // ciphertext, and label/issuer/kind hold base64(AES-256-GCM) ciphertext too
    // (encrypt/decrypt in db::store) so the file can't enumerate which services a
    // user holds. Legacy plaintext rows are upgraded by migrate_plaintext_metadata.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS totp_accounts (
            id          TEXT PRIMARY KEY,
            label       TEXT NOT NULL,
            issuer      TEXT NOT NULL DEFAULT '',
            seed_enc    BLOB NOT NULL,
            uri_enc     BLOB NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            sort_order  INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS vault_items (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            data_enc    BLOB NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
    "#,
    )?;
    Ok(())
}
