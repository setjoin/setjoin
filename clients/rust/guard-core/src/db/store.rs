use crate::{GuardError, TotpAccount};
use aes_gcm::{
    aead::{Aead, Generate},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rusqlite::Connection;

// Nonce prefix length for AES-256-GCM
const NONCE_LEN: usize = 12;

/// Encrypt a string to a base64(AES-256-GCM) blob for storage in a TEXT column.
/// Used for the column-level metadata encryption (label/issuer/kind) and the
/// secure key/value store, so the plaintext SQLite file holds no cleartext.
pub fn enc_text(key: &[u8; 32], plaintext: &str) -> Result<String, GuardError> {
    Ok(B64.encode(encrypt(key, plaintext.as_bytes())?))
}

/// Inverse of `enc_text`: base64-decode then AES-256-GCM-decrypt to a string.
pub fn dec_text(key: &[u8; 32], stored: &str) -> Result<String, GuardError> {
    let ct = B64
        .decode(stored.as_bytes())
        .map_err(|e| GuardError::Crypto(e.to_string()))?;
    let plain = decrypt(key, &ct)?;
    String::from_utf8(plain).map_err(|e| GuardError::Crypto(e.to_string()))
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, GuardError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| GuardError::Crypto(e.to_string()))?;
    let nonce = Nonce::generate();
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| GuardError::Crypto(e.to_string()))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, GuardError> {
    if data.len() < NONCE_LEN {
        return Err(GuardError::Crypto("blob too short".into()));
    }
    let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| GuardError::Crypto(e.to_string()))?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| GuardError::Crypto("nonce length mismatch".into()))?;
    let nonce = Nonce::from(nonce_arr);
    cipher
        .decrypt(&nonce, ct)
        .map_err(|_| GuardError::WrongPassphrase)
}

pub fn insert_totp(
    conn: &Connection,
    key: &[u8; 32],
    id: &str,
    label: &str,
    issuer: &str,
    uri: &str,
    seed: &str,
) -> Result<(), GuardError> {
    let seed_enc = encrypt(key, seed.as_bytes())?;
    let uri_enc = encrypt(key, uri.as_bytes())?;
    conn.execute(
        "INSERT OR REPLACE INTO totp_accounts (id,label,issuer,seed_enc,uri_enc)
         VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![
            id,
            enc_text(key, label)?,
            enc_text(key, issuer)?,
            seed_enc,
            uri_enc
        ],
    )?;
    Ok(())
}

pub fn list_totp_accounts(
    conn: &Connection,
    key: &[u8; 32],
) -> Result<Vec<TotpAccount>, GuardError> {
    let mut stmt = conn.prepare(
        "SELECT id,label,issuer FROM totp_accounts ORDER BY sort_order ASC, created_at ASC",
    )?;
    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, label, issuer)| {
            Ok(TotpAccount {
                id,
                label: dec_text(key, &label)?,
                issuer: dec_text(key, &issuer)?,
                icon: String::new(),
            })
        })
        .collect()
}

pub fn get_totp_uri(conn: &Connection, key: &[u8; 32], id: &str) -> Result<String, GuardError> {
    let uri_enc: Vec<u8> = conn
        .query_row(
            "SELECT uri_enc FROM totp_accounts WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .map_err(|_| GuardError::NotFound)?;
    let plain = decrypt(key, &uri_enc)?;
    String::from_utf8(plain).map_err(|e| GuardError::Crypto(e.to_string()))
}

pub fn delete_totp(conn: &Connection, id: &str) -> Result<(), GuardError> {
    conn.execute("DELETE FROM totp_accounts WHERE id = ?1", [id])?;
    Ok(())
}

// ── Secure key/value store ──────────────────────────────────────────────
//
// Small encrypted key/value pairs persisted in the `meta` table. Keys are
// namespaced with `ss:` so they never collide with internal meta keys
// (`kdf_params`, `ecdh_sk_enc`). The value column is `TEXT`, so the AES-GCM
// ciphertext is base64-encoded before storage. The data is only readable
// while the vault key is held (i.e. while unlocked).

const META_KV_PREFIX: &str = "ss:";

fn meta_kv_key(key: &str) -> String {
    format!("{META_KV_PREFIX}{key}")
}

/// Fetch and decrypt a secure store value. Returns `None` if the key is absent.
pub fn meta_get(
    conn: &Connection,
    key: &[u8; 32],
    name: &str,
) -> Result<Option<String>, GuardError> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [meta_kv_key(name)],
            |r| r.get(0),
        )
        .ok();
    match stored {
        None => Ok(None),
        Some(b64) => dec_text(key, &b64).map(Some),
    }
}

/// Encrypt and persist a secure store value, overwriting any existing entry.
pub fn meta_set(
    conn: &Connection,
    key: &[u8; 32],
    name: &str,
    value: &str,
) -> Result<(), GuardError> {
    conn.execute(
        "INSERT OR REPLACE INTO meta (key,value) VALUES (?1,?2)",
        rusqlite::params![meta_kv_key(name), enc_text(key, value)?],
    )?;
    Ok(())
}

/// Remove a secure store value. No-op if absent.
pub fn meta_delete(conn: &Connection, name: &str) -> Result<(), GuardError> {
    conn.execute("DELETE FROM meta WHERE key = ?1", [meta_kv_key(name)])?;
    Ok(())
}

/// One-time, idempotent upgrade of pre-encryption rows: older builds stored
/// totp_accounts.label/issuer and vault_items.kind in cleartext. Encrypt them in
/// place under the vault key. Gated by the `metadata_enc` meta flag, so it runs
/// once per DB; on a fresh or already-migrated DB it is a no-op + flag set.
/// Called from `GuardCore::new` after the key is derived.
pub fn migrate_plaintext_metadata(conn: &Connection, key: &[u8; 32]) -> Result<(), GuardError> {
    let done = conn
        .query_row("SELECT value FROM meta WHERE key='metadata_enc'", [], |r| {
            r.get::<_, String>(0)
        })
        .map(|v| v == "1")
        .unwrap_or(false);
    if done {
        return Ok(());
    }

    let totp: Vec<(String, String, String)> = {
        let mut stmt = conn.prepare("SELECT id,label,issuer FROM totp_accounts")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (id, label, issuer) in totp {
        conn.execute(
            "UPDATE totp_accounts SET label=?2, issuer=?3 WHERE id=?1",
            rusqlite::params![id, enc_text(key, &label)?, enc_text(key, &issuer)?],
        )?;
    }

    let items: Vec<(String, String)> = {
        let mut stmt = conn.prepare("SELECT id,kind FROM vault_items")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (id, kind) in items {
        conn.execute(
            "UPDATE vault_items SET kind=?2 WHERE id=?1",
            rusqlite::params![id, enc_text(key, &kind)?],
        )?;
    }

    conn.execute(
        "INSERT OR REPLACE INTO meta (key,value) VALUES ('metadata_enc','1')",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod namespace_tests {
    use super::*;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        super::super::schema::apply_migrations(&conn).unwrap();
        conn
    }

    /// The secure-store API reaches ONLY the `ss:`-prefixed key space: a
    /// renderer-influenced secure-store key can neither read nor overwrite the
    /// internal meta rows guard-core itself owns (`kdf_params`, `ecdh_sk_enc`,
    /// `metadata_enc`, `wiped`). This namespace isolation is what the shell
    /// layers' `mam:` renderer denial (Electron `handlers/securestore.ts`,
    /// HarmonyOS `BridgeProxy.ets`) is built on: the MAM enrolment secrets are
    /// plain keys in this same namespace, writable only through the trusted
    /// host layer (`mam.ts` / Tauri `mam.rs` / ArkTS `Mam.ets`).
    #[test]
    fn secure_store_keys_cannot_reach_internal_meta_keys() {
        let conn = test_conn();
        let key = [7u8; 32];
        // Internal rows exist exactly as guard-core writes them (no ss: prefix).
        conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES ('kdf_params','salt$argon2id'), ('ecdh_sk_enc','private-key')",
            [],
        )
        .unwrap();

        // The secure-store API cannot see them:
        assert_eq!(meta_get(&conn, &key, "kdf_params").unwrap(), None);
        assert_eq!(meta_get(&conn, &key, "ecdh_sk_enc").unwrap(), None);
        // A same-named secure-store write lands in the namespace instead:
        meta_set(&conn, &key, "kdf_params", "attacker").unwrap();
        let internal: String = conn
            .query_row("SELECT value FROM meta WHERE key='kdf_params'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            internal, "salt$argon2id",
            "internal kdf_params must be untouched"
        );
        let namespaced: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='ss:kdf_params'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dec_text(&key, &namespaced).unwrap(), "attacker");
        // ...and a same-named secure-store delete cannot remove the internal row:
        meta_delete(&conn, "kdf_params").unwrap();
        let still: String = conn
            .query_row("SELECT value FROM meta WHERE key='kdf_params'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            still, "salt$argon2id",
            "internal kdf_params must survive the delete"
        );
    }

    /// `mam:*` enrolment secrets (written ONLY by the trusted host layer) live
    /// in this same `ss:` namespace — pinned so the renderer-facing denial keeps
    /// covering exactly where the values actually live.
    #[test]
    fn mam_secret_keys_round_trip_inside_the_ss_namespace() {
        let conn = test_conn();
        let key = [9u8; 32];
        meta_set(&conn, &key, "mam:hmac_secret", "d3adb33f").unwrap();
        assert_eq!(
            meta_get(&conn, &key, "mam:hmac_secret").unwrap().as_deref(),
            Some("d3adb33f")
        );
        let raw: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key='ss:mam:hmac_secret'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dec_text(&key, &raw).unwrap(), "d3adb33f");
    }
}
