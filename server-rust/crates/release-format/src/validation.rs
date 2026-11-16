use crate::*;
use chrono::{DateTime, SecondsFormat, Utc};
use regex::Regex;
use std::{cmp::Ordering, collections::HashSet, sync::LazyLock};

static IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$").unwrap());
static VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$").unwrap()
});
static GATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]{0,63}$").unwrap());
pub(crate) fn identifier(s: &str) -> bool {
    IDENT.is_match(s)
}
pub(crate) fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn list<T>(v: &Option<Vec<T>>) -> &[T] {
    v.as_deref().unwrap_or_default()
}
fn sorted(name: &str, values: &[String]) -> Result<()> {
    ensure!(
        values.iter().all(|v| identifier(v)),
        "{name} contains invalid value"
    );
    ensure!(
        values.windows(2).all(|w| w[0] < w[1]),
        "{name} must be sorted and unique"
    );
    Ok(())
}
pub(crate) fn timestamp(value: &str) -> Result<DateTime<Utc>> {
    let t = DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc);
    ensure!(
        value.len() == 20
            && t.timestamp_subsec_nanos() == 0
            && t.to_rfc3339_opts(SecondsFormat::Secs, true) == value,
        "must be canonical UTC RFC3339 seconds"
    );
    Ok(t)
}
#[derive(Clone, Debug)]
pub struct Version {
    numbers: [u64; 3],
    pre: Vec<String>,
}
fn numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}
pub fn parse_version(s: &str) -> Result<Version> {
    let c = VERSION
        .captures(s)
        .ok_or_else(|| anyhow::anyhow!("invalid semantic version {s:?}"))?;
    let numbers = [c[1].parse()?, c[2].parse()?, c[3].parse()?];
    let pre: Vec<String> = c
        .get(4)
        .map(|p| p.as_str().split('.').map(str::to_owned).collect())
        .unwrap_or_default();
    ensure!(
        !pre.iter()
            .any(|p| p.len() > 1 && p.starts_with('0') && numeric(p)),
        "numeric prerelease identifiers cannot have leading zeroes"
    );
    Ok(Version { numbers, pre })
}
impl Version {
    pub fn compare(&self, other: &Self) -> Ordering {
        let numbers = self.numbers.cmp(&other.numbers);
        if numbers != Ordering::Equal {
            return numbers;
        }
        if self.pre.is_empty() || other.pre.is_empty() {
            return other.pre.is_empty().cmp(&self.pre.is_empty()).reverse();
        }
        for (a, b) in self.pre.iter().zip(&other.pre) {
            if a == b {
                continue;
            }
            return match (numeric(a), numeric(b)) {
                // Go ignores ParseUint's overflow error (its returned value saturates).
                (true, true) => {
                    if a.parse::<u64>().unwrap_or(u64::MAX) < b.parse::<u64>().unwrap_or(u64::MAX) {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                }
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => a.cmp(b),
            };
        }
        self.pre.len().cmp(&other.pre.len())
    }
}
fn constraints(raw: &str) -> Result<Vec<(&str, Version)>> {
    let parts: Vec<_> = raw.split_whitespace().collect();
    ensure!(
        !parts.is_empty() && parts.len() <= 4,
        "version range requires one to four constraints"
    );
    parts
        .into_iter()
        .map(|part| {
            let op = [">=", "<=", ">", "<", "="]
                .into_iter()
                .find(|op| part.starts_with(op))
                .unwrap_or("");
            Ok((op, parse_version(&part[op.len()..])?))
        })
        .collect()
}
pub fn version_in_range(version: &str, range: &str) -> Result<bool> {
    let v = parse_version(version)?;
    Ok(constraints(range)?.iter().all(|(op, b)| match *op {
        ">=" => v.compare(b) != Ordering::Less,
        "<=" => v.compare(b) != Ordering::Greater,
        ">" => v.compare(b) == Ordering::Greater,
        "<" => v.compare(b) == Ordering::Less,
        _ => v.compare(b) == Ordering::Equal,
    }))
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported release manifest schema {}",
            self.schema_version
        );
        ensure!(identifier(&self.release_id), "invalid release_id");
        parse_version(&self.version)?;
        ensure!(
            matches!(self.channel.as_str(), "community" | "enterprise"),
            "invalid channel"
        );
        let published = timestamp(&self.published_at)?;
        let expires = timestamp(&self.expires_at)?;
        ensure!(expires > published, "expires_at must be after published_at");
        ensure!(
            self.metadata_version > 0,
            "metadata_version must be positive"
        );
        parse_version(&self.previous_version_floor)?;
        sorted("platforms", list(&self.platforms))?;
        sorted("architectures", list(&self.architectures))?;
        ensure!(
            !list(&self.platforms).is_empty() && !list(&self.architectures).is_empty(),
            "platforms and architectures must not be empty"
        );
        constraints(&self.compatibility.source_version_range)?;
        constraints(&self.compatibility.postgres_range)?;
        if !self.compatibility.minimum_client.is_empty() {
            parse_version(&self.compatibility.minimum_client)?;
        }
        ensure!(
            self.schema_from >= 0 && self.schema_to >= self.schema_from,
            "invalid schema range"
        );
        let artifacts = list(&self.artifacts);
        ensure!(
            !artifacts.is_empty() && artifacts.len() <= 256,
            "artifacts count must be between 1 and 256"
        );
        let mut seen = HashSet::new();
        let mut fixed = HashSet::new();
        let mut core = HashSet::new();
        let mut previous = "";
        for a in artifacts {
            ensure!(
                identifier(&a.id) && a.id != "." && a.id != "..",
                "artifact id is path-like or invalid"
            );
            ensure!(seen.insert(&a.id), "duplicate artifact id");
            ensure!(previous <= a.id.as_str(), "artifacts must be sorted by id");
            previous = &a.id;
            ensure!(
                a.size > 0
                    && is_digest(&a.sha256)
                    && !a.media_type.is_empty()
                    && a.media_type.len() <= 128,
                "artifact has invalid size, digest, or media type"
            );
            ensure!(
                list(&self.platforms).contains(&a.platform)
                    && list(&self.architectures).contains(&a.architecture),
                "artifact platform or architecture is undeclared"
            );
            let target = match a.class.as_str() {
                "mailserverd" => "core_mailserverd",
                "authserverd" => "core_authserverd",
                "mailctl" => "core_mailctl",
                "webmail" => "core_webmail",
                "migration" => "core_migrations",
                "recovery_guide" => "recovery_guide",
                "sbom" => "release_sbom",
                "provenance" => "release_provenance",
                "sidecar" => "compatible_sidecar",
                "setjoin-gateway" => "core_setjoin_gateway",
                "setjoin-auth" => "core_setjoin_auth",
                _ => "",
            };
            // Go's missing map key is the empty string, including for unknown classes.
            ensure!(a.target == target, "artifact has invalid class/target pair");
            if a.target != "core_migrations" && a.target != "compatible_sidecar" {
                ensure!(fixed.insert(&a.target), "artifacts share fixed target");
            }
            if a.cohort == "core" {
                core.insert(a.class.as_str());
            } else {
                ensure!(identifier(&a.cohort), "artifact has invalid cohort");
            }
            if !a.compatible_with_core.is_empty() {
                constraints(&a.compatible_with_core)?;
            }
            ensure!(
                a.class != "sidecar" || !a.compatible_with_core.is_empty(),
                "sidecar artifact must declare core compatibility"
            );
        }
        if !core.is_empty() {
            for c in ["mailserverd", "authserverd", "mailctl", "webmail"] {
                ensure!(core.contains(c), "core cohort is missing {c}");
            }
        }
        for c in ["sbom", "provenance", "recovery_guide"] {
            ensure!(
                artifacts.iter().filter(|a| a.class == c).count() == 1,
                "release must contain exactly one {c} artifact"
            );
        }
        let migrations = list(&self.migrations);
        ensure!(migrations.len() <= 256, "too many migrations");
        let mut last = self.schema_from;
        let mut seen = HashSet::new();
        for m in migrations {
            ensure!(
                identifier(&m.id) && seen.insert(&m.id),
                "invalid or duplicate migration id"
            );
            ensure!(
                m.from_schema == last
                    && m.to_schema > m.from_schema
                    && m.to_schema <= self.schema_to,
                "migration is out of order"
            );
            last = m.to_schema;
            ensure!(
                is_digest(&m.sha256) && m.class == "expand",
                "migration is not an attested expand migration"
            );
            ensure!(
                identifier(&m.compatibility_evidence) && identifier(&m.previous_binary_evidence),
                "migration lacks compatibility evidence"
            );
            ensure!(m.transaction_required, "migration is nontransactional");
            ensure!(
                artifacts
                    .iter()
                    .any(|a| a.id == m.id && a.class == "migration" && a.sha256 == m.sha256),
                "migration does not match a hashed migration artifact"
            );
        }
        ensure!(
            last == self.schema_to,
            "migration chain ends at wrong schema"
        );
        for (name, gates) in [
            ("preflight", &self.health_gates.preflight),
            ("readiness", &self.health_gates.readiness),
            ("data_contract", &self.health_gates.data_contract),
            ("post_commit", &self.health_gates.post_commit),
        ] {
            ensure!(
                !list(gates).is_empty() && list(gates).len() <= 32,
                "{name} gates count must be between 1 and 32"
            );
            sorted(name, list(gates))?;
            ensure!(list(gates).iter().all(|v| GATE.is_match(v)), "invalid gate");
        }
        ensure!(
            self.schema_to < 183 || self.feature_registry.is_some(),
            "release must declare feature registry compatibility"
        );
        if let Some(f) = &self.feature_registry {
            ensure!(
                is_digest(&f.catalog_digest),
                "feature registry catalog digest is invalid"
            );
            let modes = list(&f.compatible_modes);
            let digests = list(&f.compatible_rollback_digests);
            ensure!(
                (1..=2).contains(&modes.len())
                    && modes.iter().all(|m| m == "observe" || m == "enforce")
                    && modes.windows(2).all(|w| w[0] < w[1])
                    && modes.iter().any(|m| m == "observe"),
                "invalid feature registry compatible modes"
            );
            ensure!(
                (1..=16).contains(&digests.len())
                    && digests.iter().all(|d| is_digest(d))
                    && digests.windows(2).all(|w| w[0] < w[1]),
                "invalid feature registry rollback digests"
            );
        }
        ensure!(
            (1..=30 * 24 * 60 * 60).contains(&self.recovery.maximum_age_seconds),
            "recovery maximum age must be between one second and 30 days"
        );
        ensure!(
            self.notes.downtime_maximum_seconds >= self.notes.downtime_minimum_seconds,
            "downtime maximum must not be less than minimum"
        );
        ensure!(
            !self.notes.summary.is_empty()
                && self.notes.summary.len() <= 4096
                && self.notes.support_channel.len() <= 256,
            "invalid release notes"
        );
        ensure!(
            (1..=8).contains(&self.signing.threshold),
            "signature threshold must be between 1 and 8"
        );
        sorted("rotation_key_ids", list(&self.signing.rotation_key_ids))?;
        ensure!(list(&self.signatures).len() <= 16, "too many signatures");
        let mut seen = HashSet::new();
        for s in list(&self.signatures) {
            ensure!(
                identifier(&s.key_id) && s.algorithm == "ed25519" && !s.value.is_empty(),
                "invalid signature entry"
            );
            ensure!(seen.insert(&s.key_id), "duplicate signature key_id");
        }
        Ok(())
    }
}
