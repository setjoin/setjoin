//! First-boot restore engine (port of frozen Go's `internal/restore`, #305): manifest
//! verification, safe-config restore, the single-flight restore job and verified blob copies.
use crate::{digest, store::Store};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use setjoin_pg::{workers::WorkerConnection, Type};
use std::collections::{BTreeMap, HashSet};

pub const MAX_METADATA_BYTES: usize = 64 << 20;
/// ASCII of "REST": the single-flight advisory lock key.
const LOCK_KEY: i64 = 0x5245_5354;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct BlobManifest {
    pub timestamp: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub hashes: Vec<String>,
    pub count: i64,
    pub total_size: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub primary_keys: BTreeMap<String, String>,
}

/// Go's `backup.BackupManifest`; field order is the canonical-JSON order the signature covers.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Index {
    pub schema_version: i64,
    pub timestamp: String,
    pub config_size_bytes: i64,
    pub config_sha256: String,
    pub blob_manifest: BlobManifest,
    pub blob_count: i64,
    pub blob_total_size_bytes: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signing_key_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signing_public_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// Go's `VerifyEmbeddedManifest`.
pub fn verify_embedded(index: &Index) -> Result<(), String> {
    if index.schema_version == 0 && index.signature.is_empty() {
        return Ok(()); // legacy backup
    }
    if index.schema_version != 1
        || index.signature.is_empty()
        || index.signing_public_key.is_empty()
        || index.signing_key_id.is_empty()
    {
        return Err("backup manifest signature metadata is incomplete".into());
    }
    let public = STANDARD_NO_PAD
        .decode(&index.signing_public_key)
        .ok()
        .filter(|p| p.len() == 32)
        .ok_or("backup manifest public key is invalid")?;
    if index.signing_key_id != digest(&public) {
        return Err("backup manifest signing key ID mismatch".into());
    }
    let signature = STANDARD_NO_PAD
        .decode(&index.signature)
        .ok()
        .filter(|s| s.len() == 64)
        .ok_or("backup manifest signature encoding is invalid")?;
    let mut unsigned = index.clone();
    unsigned.signature.clear();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
        .verify(crate::json(&unsigned).as_bytes(), &signature)
        .map_err(|_| "backup manifest signature verification failed".to_string())
}

pub async fn download_manifest(backup: &Store) -> Result<Index, String> {
    let data = backup
        .get("backup-manifest.json", MAX_METADATA_BYTES)
        .await
        .map_err(|e| format!("download backup-manifest.json: {e}"))?;
    let index: Index =
        serde_json::from_slice(&data).map_err(|e| format!("parse backup-manifest.json: {e}"))?;
    verify_embedded(&index).map_err(|e| format!("verify backup-manifest.json: {e}"))?;
    Ok(index)
}

#[derive(Deserialize)]
struct ConfigEntry {
    #[serde(default)]
    value: String,
    #[serde(default)]
    encrypted: bool,
}

/// Apply only reducer-classified safe configuration; returns how many keys were safe.
pub async fn restore_config(conn: &WorkerConnection, backup: &Store) -> Result<i64, String> {
    let data = backup
        .get("config.json", MAX_METADATA_BYTES)
        .await
        .map_err(|e| format!("download config.json: {e}"))?;
    let config: BTreeMap<String, ConfigEntry> =
        serde_json::from_slice(&data).map_err(|e| format!("parse config.json: {e}"))?;
    let manifest = download_manifest(backup)
        .await
        .map_err(|e| format!("config restore requires a verifiable backup manifest: {e}"))?;
    if manifest.config_size_bytes != data.len() as i64 || manifest.config_sha256 != digest(&data) {
        return Err("config.json does not match the signed backup manifest".into());
    }
    conn.batch("BEGIN")
        .await
        .map_err(|e| format!("begin config restore: {e}"))?;
    let mut applied = 0;
    for (key, entry) in &config {
        let result = conn
            .query(
                "SELECT restore_config_apply($1,$2::jsonb,$3,$4)",
                &[
                    (key, Type::TEXT),
                    (&entry.value, Type::TEXT),
                    (&entry.encrypted, Type::BOOL),
                    (&false, Type::BOOL),
                ],
            )
            .await;
        match result {
            Ok(rows) => {
                if rows
                    .first()
                    .is_some_and(|r| r.get::<_, String>(0) == "safe")
                {
                    applied += 1;
                }
            }
            Err(e) => {
                let _ = conn.batch("ROLLBACK").await;
                return Err(format!("restore config key {key:?}: {e}"));
            }
        }
    }
    conn.batch("COMMIT")
        .await
        .map_err(|e| format!("commit config restore: {e}"))?;
    Ok(applied)
}

pub async fn user_count(conn: &WorkerConnection) -> Result<i64, String> {
    let rows = conn.query("SELECT COUNT(*) FROM users", &[]).await?;
    Ok(rows.first().map_or(0, |r| r.get::<_, i64>(0)))
}

pub async fn domain_count(conn: &WorkerConnection) -> Result<i64, String> {
    let rows = conn.query("SELECT COUNT(*) FROM domains", &[]).await?;
    Ok(rows.first().map_or(0, |r| r.get::<_, i64>(0)))
}

/// Claim the single restore slot (advisory lock, then one `running` row if none is live).
pub async fn start_job(conn: &WorkerConnection, restore_type: &str) -> Result<i64, String> {
    conn.batch("BEGIN")
        .await
        .map_err(|e| format!("begin: {e}"))?;
    let claim = async {
        conn.query("SELECT pg_advisory_xact_lock($1)", &[(&LOCK_KEY, Type::INT8)])
            .await
            .map_err(|e| format!("acquire restore lock: {e}"))?;
        let rows = conn
            .query(
                "SELECT EXISTS(SELECT 1 FROM restore_jobs WHERE status IN ('pending', 'running'))",
                &[],
            )
            .await
            .map_err(|e| format!("check in-progress: {e}"))?;
        if rows.first().is_some_and(|r| r.get::<_, bool>(0)) {
            return Err("a restore is already in progress".to_string());
        }
        let rows = conn
            .query(
                "INSERT INTO restore_jobs (status, restore_type, started_at) VALUES ('running', $1, now()) RETURNING id",
                &[(&restore_type, Type::TEXT)],
            )
            .await
            .map_err(|e| format!("insert restore_jobs: {e}"))?;
        Ok(rows[0].get::<_, i64>(0))
    }
    .await;
    match claim {
        Ok(id) => {
            conn.batch("COMMIT")
                .await
                .map_err(|e| format!("commit: {e}"))?;
            Ok(id)
        }
        Err(e) => {
            let _ = conn.batch("ROLLBACK").await;
            Err(e)
        }
    }
}

pub async fn finish_job(
    conn: &WorkerConnection,
    id: i64,
    error: Option<&str>,
) -> Result<(), String> {
    match error {
        Some(message) => {
            let log = serde_json::to_string(&[message]).unwrap();
            conn.execute(
                "UPDATE restore_jobs SET status = 'failed', completed_at = now(), error_log = $1::jsonb WHERE id = $2",
                &[(&log, Type::TEXT), (&id, Type::INT8)],
            )
            .await?;
        }
        None => {
            conn.execute(
                "UPDATE restore_jobs SET status = 'completed', completed_at = now() WHERE id = $1",
                &[(&id, Type::INT8)],
            )
            .await?;
        }
    }
    Ok(())
}

/// A canonical lowercase hex SHA-256: the only shape a blob key may take.
pub fn valid_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Resolves and validates the canonical primary object key for `hash`:
/// only bare `<hash>` or `blobs/<hash>` are permitted (preventing path traversal).
/// Legacy manifests without `primary_keys` default to `blobs/<hash>`.
pub fn primary_key_for_hash(hash: &str, recorded: Option<&str>) -> Result<String, String> {
    if !valid_hash(hash) {
        return Err(format!(
            "blob {hash:?}: not a canonical sha-256 hash \u{2014} rejected"
        ));
    }
    let prefixed = format!("blobs/{hash}");
    match recorded.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(prefixed),
        Some(k) if k == hash => Ok(hash.to_owned()),
        Some(k) if k == prefixed => Ok(prefixed),
        Some(other) => Err(format!(
            "blob {hash}: invalid primary key layout {other:?} \u{2014} rejected"
        )),
    }
}

/// Manifest blobs absent (or corrupt) in `primary`, each verified on fetch and after write.
pub async fn restore_from_manifest(
    primary: &Store,
    backup: &Store,
    manifest: &Index,
) -> (i64, Vec<String>) {
    let m = &manifest.blob_manifest;
    if m.count != m.hashes.len() as i64 || manifest.blob_count != m.hashes.len() as i64 {
        return (
            0,
            vec!["backup manifest blob counts do not match the hash inventory".into()],
        );
    }
    let mut errors = Vec::new();
    let mut missing: Vec<(String, String)> = Vec::new();
    let mut seen = HashSet::new();
    for h in &m.hashes {
        if !valid_hash(h) {
            errors.push(format!(
                "blob {h:?}: not a canonical sha-256 hash \u{2014} rejected"
            ));
            continue;
        }
        if !seen.insert(h.clone()) {
            errors.push(format!("blob {h}: duplicate manifest entry"));
            continue;
        }
        let primary_key = match primary_key_for_hash(h, m.primary_keys.get(h).map(String::as_str)) {
            Ok(key) => key,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };
        let present = match primary.head(&primary_key).await {
            Ok(size) => verify_digest_at(primary, &primary_key, h, size)
                .await
                .is_ok(),
            Err(_) => false,
        };
        if !present {
            missing.push((h.clone(), primary_key));
        }
    }
    let (restored, more) = restore_missing_blobs_with_keys(primary, backup, &missing).await;
    errors.extend(more);
    (restored, errors)
}

pub async fn restore_missing_blobs(
    primary: &Store,
    backup: &Store,
    hashes: &[String],
) -> (i64, Vec<String>) {
    let items: Vec<(String, String)> = hashes
        .iter()
        .map(|h| (h.clone(), format!("blobs/{h}")))
        .collect();
    restore_missing_blobs_with_keys(primary, backup, &items).await
}

/// Restores each `(hash, primary_key)` from backup's `blobs/<hash>` into `primary_key`
/// (bare `<hash>` or `blobs/<hash>`), verifying SHA-256 + size before and after copy (#551).
pub async fn restore_missing_blobs_with_keys(
    primary: &Store,
    backup: &Store,
    items: &[(String, String)],
) -> (i64, Vec<String>) {
    let mut restored = 0;
    let mut errors = Vec::new();
    for (hash, requested_key) in items {
        let primary_key = match primary_key_for_hash(hash, Some(requested_key.as_str())) {
            Ok(key) => key,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };
        let backup_key = format!("blobs/{hash}");
        let size = match backup.head(&backup_key).await {
            Ok(size) => size,
            Err(e) => {
                errors.push(format!("blob {hash}: backup head: {e}"));
                continue;
            }
        };
        if let Err(e) = verify_digest_at(backup, &backup_key, hash, size).await {
            errors.push(format!("blob {hash}: backup verification: {e}"));
            continue;
        }
        if let Err(e) = primary
            .copy_from_key(backup, &backup_key, &primary_key, size)
            .await
        {
            errors.push(format!("blob {hash}: primary put/read close: {e}"));
            continue;
        }
        if let Err(e) = verify_digest_at(primary, &primary_key, hash, size).await {
            errors.push(format!("blob {hash}: post-write verification: {e}"));
            continue;
        }
        restored += 1;
    }
    (restored, errors)
}

async fn verify_digest_at(store: &Store, key: &str, hash: &str, size: u64) -> Result<(), String> {
    let (got, n) = store.body_digest(key).await?;
    if n != size {
        return Err(format!("size mismatch (expected {size}, got {n})"));
    }
    if got != hash {
        return Err(format!("sha-256 mismatch (got {got})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn restore_round_trip_preserves_bare_and_prefixed_key_layouts() {
        let tmp = std::env::temp_dir().join(format!(
            "setjoin-restore-layout-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let primary_dir = tmp.join("primary");
        let backup_dir = tmp.join("backup");
        std::fs::create_dir_all(&primary_dir).expect("create primary dir");
        std::fs::create_dir_all(&backup_dir).expect("create backup dir");

        let primary = Store::driver(
            "posix",
            "",
            "",
            primary_dir.to_str().expect("primary utf8"),
            "",
            "",
        )
        .expect("primary posix store");
        let backup = Store::driver(
            "posix",
            "",
            "",
            backup_dir.to_str().expect("backup utf8"),
            "",
            "",
        )
        .expect("backup posix store");

        let bare_bytes = b"bare mailbox_io raw message bytes".to_vec();
        let bare_hash = digest(&bare_bytes);
        let prefixed_bytes = b"legacy prefixed blob bytes".to_vec();
        let prefixed_hash = digest(&prefixed_bytes);

        // Backup store always stores objects under `blobs/<sha>`.
        backup
            .put(&format!("blobs/{bare_hash}"), bare_bytes.clone())
            .await
            .expect("seed bare blob in backup");
        backup
            .put(&format!("blobs/{prefixed_hash}"), prefixed_bytes.clone())
            .await
            .expect("seed prefixed blob in backup");

        let mut primary_keys = BTreeMap::new();
        primary_keys.insert(bare_hash.clone(), bare_hash.clone());
        let manifest = Index {
            schema_version: 0,
            blob_manifest: BlobManifest {
                timestamp: "20261127T000000Z".into(),
                kind: "incr".into(),
                hashes: vec![bare_hash.clone(), prefixed_hash.clone()],
                count: 2,
                total_size: (bare_bytes.len() + prefixed_bytes.len()) as i64,
                primary_keys,
            },
            blob_count: 2,
            blob_total_size_bytes: (bare_bytes.len() + prefixed_bytes.len()) as i64,
            ..Default::default()
        };

        let (restored, errors) = restore_from_manifest(&primary, &backup, &manifest).await;
        assert!(errors.is_empty(), "unexpected restore errors: {errors:?}");
        assert_eq!(restored, 2);

        // Bare blob must land at `<sha>` (NOT `blobs/<sha>`).
        assert_eq!(
            primary.get(&bare_hash, 1024).await.expect("read bare key"),
            bare_bytes
        );
        assert!(
            primary.head(&format!("blobs/{bare_hash}")).await.is_err(),
            "bare blob must not be written under blobs/ prefix"
        );

        // Prefixed blob must land at `blobs/<sha>` (NOT bare `<sha>`).
        assert_eq!(
            primary
                .get(&format!("blobs/{prefixed_hash}"), 1024)
                .await
                .expect("read prefixed key"),
            prefixed_bytes
        );
        assert!(
            primary.head(&prefixed_hash).await.is_err(),
            "prefixed blob must not be written under bare key"
        );

        // Re-running restore_from_manifest is idempotent (0 missing).
        let (restored_again, errors_again) =
            restore_from_manifest(&primary, &backup, &manifest).await;
        assert!(errors_again.is_empty());
        assert_eq!(restored_again, 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
