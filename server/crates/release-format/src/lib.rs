//! Frozen Go release wire format, shared by the publisher and updater.
mod json;
mod model;
mod trust;
pub use trust::*;
mod validation;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
pub use model::*;
use ring::digest::{digest, SHA256};
use std::io::Read;
pub use validation::{parse_version, version_in_range};

pub const MAX_DOCUMENT_BYTES: usize = 1 << 20;
pub const MIN_VERIFICATION_THRESHOLD: usize = 2;

/// Go encoding/json field order and HTML/JavaScript escaping are signed bytes.
pub fn marshal_go<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_string(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .into_bytes())
}
pub fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_DOCUMENT_BYTES,
            "empty or oversized document"
        );
        let m: Self = json::decode(bytes)?;
        m.validate()?;
        Ok(m)
    }
    /// CI-only pre-hash schema: supplied sizes, digests and signatures are forbidden.
    pub fn parse_draft(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_DOCUMENT_BYTES,
            "empty or oversized document"
        );
        let m: Self = json::decode(bytes)?;
        let mut checked = m.clone();
        for a in checked.artifacts.iter_mut().flatten() {
            ensure!(
                a.size == 0 && a.sha256.is_empty(),
                "draft artifact must not provide size or digest"
            );
            a.size = 1;
            a.sha256 = "0".repeat(64);
        }
        for migration in checked.migrations.iter_mut().flatten() {
            ensure!(
                migration.sha256.is_empty(),
                "draft migration must not provide a digest"
            );
            migration.sha256 = "0".repeat(64);
        }
        ensure!(
            checked.signatures.as_deref().unwrap_or_default().is_empty(),
            "manifest draft must not contain signatures"
        );
        checked.validate()?;
        Ok(m)
    }
    pub fn marshal(&self) -> Result<Vec<u8>> {
        self.validate()?;
        marshal_go(self)
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut unsigned = self.clone();
        unsigned.signatures = None;
        marshal_go(&unsigned)
    }
    pub fn sign_with(
        &mut self,
        id: &str,
        signer: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<()> {
        ensure!(validation::identifier(id), "invalid signer");
        ensure!(
            !self
                .signatures
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|s| s.key_id == id),
            "manifest already has signature from {id:?}"
        );
        let raw = signer(&self.canonical()?)?;
        ensure!(
            raw.len() == 64,
            "sign manifest: signer returned invalid signature"
        );
        let signatures = self.signatures.get_or_insert_default();
        signatures.push(Signature {
            key_id: id.into(),
            algorithm: "ed25519".into(),
            value: STANDARD_NO_PAD.encode(raw),
        });
        signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(())
    }
}
/// Streaming exact-size verification rejects both truncated and appended artifacts.
pub fn verify_artifact(mut reader: impl Read, artifact: &Artifact) -> Result<()> {
    ensure!(
        artifact.size > 0 && validation::is_digest(&artifact.sha256),
        "invalid expected metadata"
    );
    let mut hash = ring::digest::Context::new(&SHA256);
    let mut remaining = artifact.size;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        let n = reader.read(&mut buffer[..limit])?;
        ensure!(
            n > 0,
            "artifact {:?} size mismatch: read {} of {} bytes",
            artifact.id,
            artifact.size - remaining,
            artifact.size
        );
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    ensure!(
        reader.read(&mut buffer[..1])? == 0,
        "artifact {:?} exceeds declared size",
        artifact.id
    );
    let actual: String = hash
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    ensure!(
        actual == artifact.sha256,
        "artifact {:?} digest mismatch",
        artifact.id
    );
    Ok(())
}

/// Exact size and SHA-256 for a streaming publisher inventory.
pub fn hash_artifact(mut reader: impl Read) -> Result<(u64, String)> {
    let mut context = ring::digest::Context::new(&SHA256);
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("artifact size overflow"))?;
        context.update(&buffer[..count]);
    }
    Ok((
        size,
        context
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    ))
}
