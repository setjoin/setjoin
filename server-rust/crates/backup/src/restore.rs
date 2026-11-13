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
    let mut missing = Vec::new();
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
        let present = match primary.head(&format!("blobs/{h}")).await {
            Ok(size) => verify_digest(primary, h, size).await.is_ok(),
            Err(_) => false,
        };
        if !present {
            missing.push(h.clone());
        }
    }
    let (restored, more) = restore_missing_blobs(primary, backup, &missing).await;
    errors.extend(more);
    (restored, errors)
}

pub async fn restore_missing_blobs(
    primary: &Store,
    backup: &Store,
    hashes: &[String],
) -> (i64, Vec<String>) {
    let mut restored = 0;
    let mut errors = Vec::new();
    for hash in hashes {
        if !valid_hash(hash) {
            errors.push(format!(
                "blob {hash:?}: not a canonical sha-256 hash \u{2014} rejected"
            ));
            continue;
        }
        let key = format!("blobs/{hash}");
        let size = match backup.head(&key).await {
            Ok(size) => size,
            Err(e) => {
                errors.push(format!("blob {hash}: backup head: {e}"));
                continue;
            }
        };
        if let Err(e) = verify_digest(backup, hash, size).await {
            errors.push(format!("blob {hash}: backup verification: {e}"));
            continue;
        }
        if let Err(e) = primary.copy_from(backup, &key, size).await {
            errors.push(format!("blob {hash}: primary put/read close: {e}"));
            continue;
        }
        if let Err(e) = verify_digest(primary, hash, size).await {
            errors.push(format!("blob {hash}: post-write verification: {e}"));
            continue;
        }
        restored += 1;
    }
    (restored, errors)
}

async fn verify_digest(store: &Store, hash: &str, size: u64) -> Result<(), String> {
    let (got, n) = store.body_digest(&format!("blobs/{hash}")).await?;
    if n != size {
        return Err(format!("size mismatch (expected {size}, got {n})"));
    }
    if got != hash {
        return Err(format!("sha-256 mismatch (got {got})"));
    }
    Ok(())
}
