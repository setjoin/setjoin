//! Frozen application recovery-set envelopes and their object verification.
use crate::{digest, hex, hmac, json, store::Store};
use serde::{Deserialize, Serialize};
#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Artifact {
    pub object_key: String,
    pub size: i64,
    pub sha256: String,
}
#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ProtectedKey {
    pub mode: String,
    pub key_id: String,
    pub fingerprint: String,
}
#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Counts {
    pub blobs: i64,
    pub blob_bytes: i64,
    pub users: i64,
    pub mailboxes: i64,
}
#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Manifest {
    pub version: i32,
    pub recovery_set_id: String,
    pub installation_id: String,
    pub timeline_id: String,
    pub source_release_id: String,
    pub schema_version: i32,
    pub created_at: String,
    pub expires_at: String,
    pub database: Artifact,
    pub database_restore_list: Artifact,
    pub blobs: Artifact,
    pub configuration: Artifact,
    pub protected_key_evidence: ProtectedKey,
    pub feature_toggle_sha256: String,
    pub counts: Counts,
    pub representative_ids: Option<Vec<String>>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Envelope {
    pub manifest: Manifest,
    pub manifest_sha256: String,
    pub hmac_sha256: String,
}
pub fn time(t: chrono::DateTime<chrono::Utc>) -> String {
    let fraction = format!("{:09}", t.timestamp_subsec_nanos());
    format!(
        "{}{}Z",
        t.format("%Y-%m-%dT%H:%M:%S"),
        if t.timestamp_subsec_nanos() == 0 {
            String::new()
        } else {
            format!(".{}", fraction.trim_end_matches('0'))
        }
    )
}
fn digest_shape(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn stable(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn uuid(s: &str) -> bool {
    let s = s.strip_prefix("urn:uuid:").unwrap_or(s);
    let s = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(s);
    (s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        || (s.len() == 36
            && s.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            }))
}
fn artifact_valid(a: &Artifact) -> bool {
    a.size >= 0
        && digest_shape(&a.sha256)
        && !a.object_key.is_empty()
        && a.object_key.len() <= 512
        && !a.object_key.contains('\\')
        && !a.object_key.starts_with('/')
        && a.object_key
            .split('/')
            .all(|s| !matches!(s, "" | "." | ".."))
}
fn validate(m: &Manifest) -> Result<(), String> {
    if m.version != 1 {
        return Err("unsupported recovery set manifest version".into());
    }
    for (id, msg) in [
        (&m.recovery_set_id, "invalid recovery set id"),
        (&m.installation_id, "invalid installation id"),
        (&m.timeline_id, "invalid timeline id"),
    ] {
        if !uuid(id) {
            return Err(msg.into());
        }
    }
    let created = chrono::DateTime::parse_from_rfc3339(&m.created_at).ok();
    let expires = chrono::DateTime::parse_from_rfc3339(&m.expires_at).ok();
    if !stable(&m.source_release_id)
        || m.schema_version <= 0
        || created.is_none()
        || expires.is_none()
        || expires <= created
        || expires.unwrap() - created.unwrap() > chrono::Duration::hours(24)
    {
        return Err("invalid recovery set identity or freshness".into());
    }
    if [
        m.counts.blobs,
        m.counts.blob_bytes,
        m.counts.users,
        m.counts.mailboxes,
    ]
    .iter()
    .any(|n| *n < 0)
        || !digest_shape(&m.feature_toggle_sha256)
        || m.representative_ids.as_ref().is_some_and(|v| v.len() > 64)
    {
        return Err("invalid recovery set counts".into());
    }
    if !matches!(
        m.protected_key_evidence.mode.as_str(),
        "encrypted" | "external"
    ) {
        return Err("protected-key evidence is required".into());
    }
    if !stable(&m.protected_key_evidence.key_id)
        || !digest_shape(&m.protected_key_evidence.fingerprint)
    {
        return Err("invalid protected-key evidence".into());
    }
    let mut keys = std::collections::BTreeSet::new();
    for a in [
        &m.database,
        &m.database_restore_list,
        &m.blobs,
        &m.configuration,
    ] {
        if !artifact_valid(a) {
            return Err("invalid recovery artifact".into());
        }
        if !keys.insert(&a.object_key) {
            return Err("duplicate recovery artifact key".into());
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for id in m.representative_ids.as_deref().unwrap_or_default() {
        if !stable(id) || !ids.insert(id) {
            return Err("invalid representative id evidence".into());
        }
    }
    Ok(())
}
pub fn seal(manifest: Manifest, key: &[u8]) -> Result<Envelope, String> {
    validate(&manifest)?;
    if key.len() < 32 {
        return Err("recovery set HMAC key must be at least 32 bytes".into());
    }
    let raw = json(&manifest);
    Ok(Envelope {
        manifest,
        manifest_sha256: digest(raw.as_bytes()),
        hmac_sha256: hex(&hmac(key, raw.as_bytes())),
    })
}
pub async fn artifact(store: &Store, key: &str) -> Result<Artifact, String> {
    let size = store.head(key).await?;
    let (hash, n) = store.body_digest(key).await?;
    if n != size {
        return Err("recovery artifact changed while hashing".into());
    }
    Ok(Artifact {
        object_key: key.into(),
        size: size as i64,
        sha256: hash,
    })
}
pub async fn verify_artifact(store: &Store, a: &Artifact) -> Result<(), String> {
    if !artifact_valid(a) {
        return Err("invalid recovery artifact".into());
    }
    let size = store.head(&a.object_key).await?;
    if size as i64 != a.size {
        return Err(format!("size mismatch: expected {} got {size}", a.size));
    }
    let (hash, n) = store.body_digest(&a.object_key).await?;
    if n as i64 != a.size || hash != a.sha256 {
        return Err("artifact digest mismatch".into());
    }
    Ok(())
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Inventory {
    #[serde(rename = "type")]
    kind: String,
    hashes: Option<Vec<String>>,
    count: i64,
    total_size: i64,
    #[serde(rename = "timestamp")]
    _timestamp: String,
}
pub async fn verify_components(store: &Store, m: &Manifest) -> Result<(), String> {
    for a in [
        &m.database,
        &m.database_restore_list,
        &m.blobs,
        &m.configuration,
    ] {
        verify_artifact(store, a)
            .await
            .map_err(|e| format!("verify {}: {e}", a.object_key))?;
    }
    let verify = async {
        if m.blobs.size > 256 << 20 {
            return Err("blob inventory exceeds size limit".to_owned());
        }
        let raw = store.get(&m.blobs.object_key, 256 << 20).await?;
        let i: Inventory =
            serde_json::from_slice(&raw).map_err(|_| "invalid blob inventory JSON")?;
        let hashes = i.hashes.as_deref().unwrap_or_default();
        if !matches!(i.kind.as_str(), "full" | "incr") {
            return Err("invalid blob inventory type".into());
        }
        if i.count != hashes.len() as i64
            || i.count != m.counts.blobs
            || i.total_size != m.counts.blob_bytes
        {
            return Err("blob inventory counts do not match recovery manifest".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0i64;
        for hash in hashes {
            if !digest_shape(hash) {
                return Err("blob inventory contains invalid digest".into());
            }
            if !seen.insert(hash) {
                return Err("blob inventory contains duplicate digest".into());
            }
            let key = format!("blobs/{hash}");
            let size = store
                .head(&key)
                .await
                .map_err(|e| format!("head {key}: {e}"))?;
            let (got, n) = store
                .body_digest(&key)
                .await
                .map_err(|e| format!("read {key}: {e}"))?;
            if n != size || got != *hash {
                return Err(format!("blob {hash} failed content verification"));
            }
            total = total
                .checked_add(
                    size.try_into()
                        .map_err(|_| "blob inventory size overflow")?,
                )
                .ok_or("blob inventory size overflow")?;
        }
        if total != i.total_size {
            return Err("blob inventory byte count does not match stored objects".into());
        }
        Ok(())
    }
    .await;
    verify.map_err(|e| format!("verify blob inventory: {e}"))
}
pub async fn commit(store: &Store, m: Manifest, key: &[u8]) -> Result<Envelope, String> {
    verify_components(store, &m).await?;
    let e = seal(m, key)?;
    store
        .put(
            &format!("recovery-sets/{}/manifest.json", e.manifest.recovery_set_id),
            json(&e).into_bytes(),
        )
        .await
        .map_err(|e| format!("write recovery set commit point: {e}"))?;
    Ok(e)
}
pub async fn load_verified(
    store: &Store,
    id: &str,
    key: &[u8],
    installation: &str,
    timeline: &str,
) -> Result<Envelope, String> {
    if !uuid(id) {
        return Err("invalid recovery set id".into());
    }
    let raw = store
        .get(&format!("recovery-sets/{id}/manifest.json"), 1 << 20)
        .await
        .map_err(|e| format!("read recovery set: {e}"))?;
    let e: Envelope =
        serde_json::from_slice(&raw).map_err(|_| "invalid recovery set envelope JSON")?;
    validate(&e.manifest)?;
    if key.len() < 32 || !digest_shape(&e.manifest_sha256) || !digest_shape(&e.hmac_sha256) {
        return Err("invalid recovery set envelope".into());
    }
    let bytes = json(&e.manifest);
    if digest(bytes.as_bytes()) != e.manifest_sha256 {
        return Err("recovery set manifest digest mismatch".into());
    }
    let signature = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&e.hmac_sha256[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    ring::hmac::verify(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
        bytes.as_bytes(),
        &signature,
    )
    .map_err(|_| "recovery set HMAC mismatch")?;
    let now = chrono::Utc::now();
    let created = chrono::DateTime::parse_from_rfc3339(&e.manifest.created_at)
        .unwrap()
        .with_timezone(&chrono::Utc);
    let expires = chrono::DateTime::parse_from_rfc3339(&e.manifest.expires_at)
        .unwrap()
        .with_timezone(&chrono::Utc);
    if created > now + chrono::Duration::minutes(1)
        || now - created > chrono::Duration::hours(24)
        || now >= expires
    {
        return Err("recovery set is stale".into());
    }
    if !installation.is_empty() && e.manifest.installation_id != installation {
        return Err("recovery set installation mismatch".into());
    }
    if !timeline.is_empty() && e.manifest.timeline_id != timeline {
        return Err("recovery set timeline mismatch".into());
    }
    if e.manifest.recovery_set_id != id {
        return Err("recovery set manifest does not match the requested recovery set id".into());
    }
    verify_components(store, &e.manifest).await?;
    Ok(e)
}
