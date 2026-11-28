use crate::*;
use chrono::{DateTime, Utc};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    Release,
    Entitlement,
    Organization,
    Recovery,
    AuditChain,
    OfflineUpdate,
}
#[derive(Clone, Debug)]
pub struct TrustedKey {
    pub id: String,
    pub purpose: Purpose,
    pub public_key: Vec<u8>,
    pub test_only: bool,
    pub organization_artifact_set: BTreeSet<String>,
}
#[derive(Debug)]
pub struct TrustStore {
    keys: BTreeMap<String, TrustedKey>,
    allow_test_roots: bool,
}
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub now: DateTime<Utc>,
    pub channel: String,
    pub current_version: String,
    pub platform: String,
    pub architecture: String,
    pub last_metadata_version: u64,
    pub last_metadata_digest: String,
    /// Caller policy. Production update consumers must supply at least 2.
    pub minimum_threshold: usize,
}
impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            channel: String::new(),
            current_version: String::new(),
            platform: String::new(),
            architecture: String::new(),
            last_metadata_version: 0,
            last_metadata_digest: String::new(),
            minimum_threshold: 0,
        }
    }
}
#[derive(Debug)]
pub struct VerifiedManifest {
    pub manifest: Manifest,
    pub canonical_bytes: Vec<u8>,
    pub digest: String,
    pub signer_key_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootDocument {
    schema_version: i64,
    purpose: Purpose,
    keys: Vec<RootKey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootKey {
    id: String,
    algorithm: String,
    public_key: String,
    #[serde(default)]
    test_only: bool,
}
impl TrustStore {
    pub fn new(keys: Vec<TrustedKey>, allow_test_roots: bool) -> Result<Self> {
        let mut store = Self {
            keys: BTreeMap::new(),
            allow_test_roots,
        };
        for key in keys {
            ensure!(
                validation::identifier(&key.id) && key.public_key.len() == 32,
                "invalid trusted key"
            );
            ensure!(
                !key.test_only || allow_test_roots,
                "test trust root {:?} is forbidden by production policy",
                key.id
            );
            ensure!(
                !store.keys.contains_key(&key.id),
                "duplicate trusted key {:?}",
                key.id
            );
            store.keys.insert(key.id.clone(), key);
        }
        Ok(store)
    }
    pub fn parse_roots(bytes: &[u8], purpose: Purpose, allow_test_roots: bool) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_DOCUMENT_BYTES,
            "empty or oversized document"
        );
        let document: RootDocument = crate::json::decode(bytes)?;
        ensure!(
            document.schema_version == 1 && document.purpose == purpose,
            "trust root schema or purpose mismatch"
        );
        ensure!(
            (1..=16).contains(&document.keys.len()),
            "trust root key count must be between 1 and 16"
        );
        Self::new(
            document
                .keys
                .into_iter()
                .map(|k| {
                    ensure!(
                        k.algorithm == "ed25519",
                        "invalid or duplicate trust root key"
                    );
                    Ok(TrustedKey {
                        id: k.id,
                        purpose,
                        public_key: decode_base64(&k.public_key)?,
                        test_only: k.test_only,
                        organization_artifact_set: BTreeSet::new(),
                    })
                })
                .collect::<Result<_>>()?,
            allow_test_roots,
        )
    }
    pub fn verify_manifest(
        &self,
        bytes: &[u8],
        options: &VerifyOptions,
    ) -> Result<VerifiedManifest> {
        self.verify_manifest_for_purpose(bytes, options, Purpose::Release)
    }
    pub fn verify_manifest_for_purpose(
        &self,
        bytes: &[u8],
        o: &VerifyOptions,
        purpose: Purpose,
    ) -> Result<VerifiedManifest> {
        ensure!(
            matches!(purpose, Purpose::Release | Purpose::OfflineUpdate),
            "manifest verification does not support key purpose"
        );
        let manifest = Manifest::parse(bytes)?;
        let canonical_bytes = manifest.canonical()?;
        let digest = sha256(&canonical_bytes);
        ensure!(
            o.now >= validation::timestamp(&manifest.published_at)?,
            "release metadata is not yet valid"
        );
        ensure!(
            o.now < validation::timestamp(&manifest.expires_at)?,
            "release metadata is expired"
        );
        ensure!(
            o.channel.is_empty() || o.channel == manifest.channel,
            "wrong release channel"
        );
        ensure!(
            o.platform.is_empty()
                || manifest
                    .platforms
                    .as_deref()
                    .unwrap_or_default()
                    .contains(&o.platform),
            "wrong platform"
        );
        ensure!(
            o.architecture.is_empty()
                || manifest
                    .architectures
                    .as_deref()
                    .unwrap_or_default()
                    .contains(&o.architecture),
            "wrong architecture"
        );
        if !o.current_version.is_empty() {
            ensure!(
                version_in_range(
                    &o.current_version,
                    &manifest.compatibility.source_version_range
                )
                .unwrap_or(false),
                "incompatible source version"
            );
            ensure!(
                parse_version(&o.current_version)?
                    .compare(&parse_version(&manifest.previous_version_floor)?)
                    != std::cmp::Ordering::Less,
                "source version is below the signed rollback floor"
            );
        }
        ensure!(
            manifest.metadata_version >= o.last_metadata_version,
            "release metadata rollback detected"
        );
        ensure!(
            manifest.metadata_version != o.last_metadata_version
                || o.last_metadata_digest.is_empty()
                || o.last_metadata_digest == digest,
            "release metadata equivocation detected"
        );
        let mut vendor = BTreeSet::new();
        let mut signers = Vec::new();
        for sig in manifest.signatures.as_deref().unwrap_or_default() {
            let Some(key) = self.keys.get(&sig.key_id) else {
                continue;
            };
            if key.test_only && !self.allow_test_roots {
                continue;
            }
            if !verify_signature(&key.public_key, &canonical_bytes, &sig.value) {
                continue;
            }
            if key.purpose == Purpose::Organization {
                let repacks: Vec<_> = manifest
                    .artifacts
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .filter(|a| a.organization_repack)
                    .collect();
                ensure!(
                    !repacks.is_empty()
                        && repacks
                            .iter()
                            .all(|a| key.organization_artifact_set.contains(&a.class)),
                    "organization key {:?} is not authorized for this artifact set",
                    key.id
                );
            } else if key.purpose == purpose {
                vendor.insert(&key.id);
            }
            signers.push(key.id.clone());
        }
        ensure!(
            vendor.len() >= (manifest.signing.threshold as usize).max(o.minimum_threshold),
            "release signature threshold not met"
        );
        signers.sort();
        Ok(VerifiedManifest {
            manifest,
            canonical_bytes,
            digest,
            signer_key_ids: signers,
        })
    }
    pub fn verify_detached(
        &self,
        purpose: Purpose,
        id: &str,
        message: &[u8],
        signature: &str,
    ) -> Result<()> {
        let key = self
            .keys
            .get(id)
            .filter(|k| k.purpose == purpose && (!k.test_only || self.allow_test_roots))
            .ok_or_else(|| anyhow::anyhow!("untrusted signing key"))?;
        ensure!(
            verify_signature(&key.public_key, message, signature),
            "invalid signature"
        );
        Ok(())
    }
}
// Go RawStdEncoding permits CR/LF and nonzero unused trailing bits, but no padding.
// The standard library decoder handles those via an explicit compatible config.
pub fn decode_base64(s: &str) -> Result<Vec<u8>> {
    use base64::{
        alphabet,
        engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    };
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    );
    Ok(engine.decode(s.replace(['\r', '\n'], ""))?)
}
fn verify_signature(key: &[u8], message: &[u8], signature: &str) -> bool {
    decode_base64(signature).is_ok_and(|sig| {
        UnparsedPublicKey::new(&ED25519, key)
            .verify(message, &sig)
            .is_ok()
    })
}
