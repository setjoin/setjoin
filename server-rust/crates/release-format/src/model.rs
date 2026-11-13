use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Signature {
    #[serde(rename = "key_id", deserialize_with = "null_default")]
    pub key_id: String,
    #[serde(rename = "algorithm", deserialize_with = "null_default")]
    pub algorithm: String,
    #[serde(rename = "value", deserialize_with = "null_default")]
    pub value: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SigningPolicy {
    #[serde(rename = "threshold", deserialize_with = "null_default")]
    pub threshold: i64,
    #[serde(rename = "rotation_key_ids", skip_serializing_if = "empty_list")]
    pub rotation_key_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Compatibility {
    #[serde(rename = "source_version_range", deserialize_with = "null_default")]
    pub source_version_range: String,
    #[serde(rename = "postgres_range", deserialize_with = "null_default")]
    pub postgres_range: String,
    #[serde(
        rename = "minimum_client",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "null_default"
    )]
    pub minimum_client: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Artifact {
    #[serde(rename = "id", deserialize_with = "null_default")]
    pub id: String,
    #[serde(rename = "class", deserialize_with = "null_default")]
    pub class: String,
    #[serde(rename = "platform", deserialize_with = "null_default")]
    pub platform: String,
    #[serde(rename = "architecture", deserialize_with = "null_default")]
    pub architecture: String,
    #[serde(rename = "size", deserialize_with = "null_default")]
    pub size: u64,
    #[serde(rename = "sha256", deserialize_with = "null_default")]
    pub sha256: String,
    #[serde(rename = "media_type", deserialize_with = "null_default")]
    pub media_type: String,
    #[serde(rename = "cohort", deserialize_with = "null_default")]
    pub cohort: String,
    #[serde(rename = "target", deserialize_with = "null_default")]
    pub target: String,
    #[serde(
        rename = "compatible_with_core",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "null_default"
    )]
    pub compatible_with_core: String,
    #[serde(
        rename = "organization_repack",
        skip_serializing_if = "is_false",
        deserialize_with = "null_default"
    )]
    pub organization_repack: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Migration {
    #[serde(rename = "id", deserialize_with = "null_default")]
    pub id: String,
    #[serde(rename = "from_schema", deserialize_with = "null_default")]
    pub from_schema: i64,
    #[serde(rename = "to_schema", deserialize_with = "null_default")]
    pub to_schema: i64,
    #[serde(rename = "sha256", deserialize_with = "null_default")]
    pub sha256: String,
    #[serde(rename = "class", deserialize_with = "null_default")]
    pub class: String,
    #[serde(rename = "compatibility_evidence", deserialize_with = "null_default")]
    pub compatibility_evidence: String,
    #[serde(rename = "transaction_required", deserialize_with = "null_default")]
    pub transaction_required: bool,
    #[serde(rename = "previous_binary_evidence", deserialize_with = "null_default")]
    pub previous_binary_evidence: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryRequirements {
    #[serde(rename = "maximum_age_seconds", deserialize_with = "null_default")]
    pub maximum_age_seconds: u64,
    #[serde(rename = "minimum_free_bytes", deserialize_with = "null_default")]
    pub minimum_free_bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthGates {
    #[serde(rename = "preflight")]
    pub preflight: Option<Vec<String>>,
    #[serde(rename = "readiness")]
    pub readiness: Option<Vec<String>>,
    #[serde(rename = "data_contract")]
    pub data_contract: Option<Vec<String>>,
    #[serde(rename = "post_commit")]
    pub post_commit: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeatureRegistryContract {
    #[serde(rename = "catalog_digest", deserialize_with = "null_default")]
    pub catalog_digest: String,
    #[serde(rename = "compatible_modes")]
    pub compatible_modes: Option<Vec<String>>,
    #[serde(rename = "compatible_rollback_digests")]
    pub compatible_rollback_digests: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseNotes {
    #[serde(rename = "summary", deserialize_with = "null_default")]
    pub summary: String,
    #[serde(rename = "downtime_minimum_seconds", deserialize_with = "null_default")]
    pub downtime_minimum_seconds: u64,
    #[serde(rename = "downtime_maximum_seconds", deserialize_with = "null_default")]
    pub downtime_maximum_seconds: u64,
    #[serde(rename = "support_channel", deserialize_with = "null_default")]
    pub support_channel: String,
    #[serde(rename = "known_blockers", skip_serializing_if = "empty_list")]
    pub known_blockers: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Manifest {
    #[serde(rename = "schema_version", deserialize_with = "null_default")]
    pub schema_version: i64,
    #[serde(rename = "release_id", deserialize_with = "null_default")]
    pub release_id: String,
    #[serde(rename = "version", deserialize_with = "null_default")]
    pub version: String,
    #[serde(rename = "channel", deserialize_with = "null_default")]
    pub channel: String,
    #[serde(rename = "published_at", deserialize_with = "null_default")]
    pub published_at: String,
    #[serde(rename = "expires_at", deserialize_with = "null_default")]
    pub expires_at: String,
    #[serde(rename = "metadata_version", deserialize_with = "null_default")]
    pub metadata_version: u64,
    #[serde(rename = "previous_version_floor", deserialize_with = "null_default")]
    pub previous_version_floor: String,
    #[serde(rename = "platforms")]
    pub platforms: Option<Vec<String>>,
    #[serde(rename = "architectures")]
    pub architectures: Option<Vec<String>>,
    #[serde(rename = "compatibility", deserialize_with = "null_default")]
    pub compatibility: Compatibility,
    #[serde(rename = "schema_from", deserialize_with = "null_default")]
    pub schema_from: i64,
    #[serde(rename = "schema_to", deserialize_with = "null_default")]
    pub schema_to: i64,
    #[serde(rename = "artifacts")]
    pub artifacts: Option<Vec<Artifact>>,
    #[serde(rename = "migrations")]
    pub migrations: Option<Vec<Migration>>,
    #[serde(rename = "health_gates", deserialize_with = "null_default")]
    pub health_gates: HealthGates,
    #[serde(rename = "feature_registry", skip_serializing_if = "Option::is_none")]
    pub feature_registry: Option<FeatureRegistryContract>,
    #[serde(rename = "recovery", deserialize_with = "null_default")]
    pub recovery: RecoveryRequirements,
    #[serde(rename = "notes", deserialize_with = "null_default")]
    pub notes: ReleaseNotes,
    #[serde(rename = "signing", deserialize_with = "null_default")]
    pub signing: SigningPolicy,
    #[serde(rename = "signatures")]
    pub signatures: Option<Vec<Signature>>,
}

fn null_default<'de, D: serde::Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
fn is_false(v: &bool) -> bool {
    !v
}
fn empty_list<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_none_or(Vec::is_empty)
}
