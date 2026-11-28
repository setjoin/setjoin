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
fn compare_numeric(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
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
            let cmp = match (numeric(a), numeric(b)) {
                (true, true) => compare_numeric(a, b),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                _ => a.cmp(b),
            };
            if cmp != Ordering::Equal {
                return cmp;
            }
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
        let mut classes = HashSet::new();
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
            let Some(target) = (match a.class.as_str() {
                "mailserverd" => Some("core_mailserverd"),
                "authserverd" => Some("core_authserverd"),
                "mailctl" => Some("core_mailctl"),
                "webmail" => Some("core_webmail"),
                "migration" => Some("core_migrations"),
                "recovery_guide" => Some("recovery_guide"),
                "sbom" => Some("release_sbom"),
                "provenance" => Some("release_provenance"),
                "sidecar" => Some("compatible_sidecar"),
                "setjoin-gateway" => Some("core_setjoin_gateway"),
                "setjoin-server" => Some("core_setjoin_server"),
                "setjoin-auth" => Some("core_setjoin_auth"),
                "setjoind" => Some("core_setjoind"),
                _ => None,
            }) else {
                anyhow::bail!("unknown artifact class {:?}", a.class);
            };
            ensure!(a.target == target, "artifact has invalid class/target pair");
            classes.insert(a.class.as_str());
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
        ensure!(
            !(classes.contains("setjoin-server") && classes.contains("setjoin-gateway")),
            "release mixes setjoin-gateway and setjoin-server"
        );
        ensure!(
            !(classes.contains("setjoin-server")
                && (classes.contains("mailserverd") || classes.contains("authserverd"))),
            "release mixes setjoin-server with legacy Go binaries"
        );
        ensure!(
            !(classes.contains("setjoind")
                && (classes.contains("mailserverd")
                    || classes.contains("authserverd")
                    || classes.contains("setjoin-gateway"))),
            "release mixes setjoind with legacy Go binaries"
        );
        if classes.contains("setjoind") {
            ensure!(
                classes.contains("setjoin-server") == classes.contains("setjoin-auth"),
                "release with setjoind must include both shims or neither"
            );
        }
        if !core.is_empty() {
            let required: &[&str] = if core.contains("setjoind") {
                if core.contains("setjoin-server") || core.contains("setjoin-auth") {
                    &[
                        "setjoind",
                        "setjoin-server",
                        "setjoin-auth",
                        "mailctl",
                        "webmail",
                    ]
                } else {
                    &["setjoind", "mailctl", "webmail"]
                }
            } else if core.contains("setjoin-server") {
                &["setjoin-server", "setjoin-auth", "mailctl", "webmail"]
            } else {
                &["mailserverd", "authserverd", "mailctl", "webmail"]
            };
            for c in required {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn base_manifest() -> Value {
        let doc: Value =
            serde_json::from_str(include_str!("../tests/goldens/updater-fixtures.json")).unwrap();
        doc["samples"][0]["manifest"].clone()
    }

    fn make_artifact(template: &Value, id: &str, class: &str, target: &str) -> Value {
        let mut a = template.clone();
        a["id"] = id.into();
        a["class"] = class.into();
        a["target"] = target.into();
        a["cohort"] = "core".into();
        a["media_type"] = "application/octet-stream".into();
        a
    }

    fn build_rust_manifest(extra: &[(&str, &str, &str)]) -> Manifest {
        let mut mv = base_manifest();
        let template = mv["artifacts"][0].clone();
        let mut arts: Vec<Value> = mv["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| {
                !matches!(
                    a["class"].as_str(),
                    Some("mailserverd" | "authserverd" | "setjoin-gateway")
                )
            })
            .cloned()
            .collect();
        for (id, class, target) in extra {
            arts.push(make_artifact(&template, id, class, target));
        }
        arts.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        mv["artifacts"] = Value::Array(arts);
        Manifest::parse(&serde_json::to_vec(&mv).unwrap()).unwrap_or_else(|e| {
            // Return invalid manifest by parsing draft so validate() can be asserted directly.
            let m: Manifest = serde_json::from_value(mv).unwrap();
            let _ = e;
            m
        })
    }

    #[test]
    fn four_cohorts_validate_and_invalid_mixes_or_half_shims_fail_closed() {
        // 1. Release N-1 split
        let split = build_rust_manifest(&[
            ("setjoin-auth", "setjoin-auth", "core_setjoin_auth"),
            ("setjoin-server", "setjoin-server", "core_setjoin_server"),
        ]);
        split.validate().expect("Release N-1 split valid");

        // 2. Release N expand (setjoind + both shims)
        let expand = build_rust_manifest(&[
            ("setjoind", "setjoind", "core_setjoind"),
            ("setjoin-auth", "setjoin-auth", "core_setjoin_auth"),
            ("setjoin-server", "setjoin-server", "core_setjoin_server"),
        ]);
        expand.validate().expect("Release N expand valid");

        // 3. Release N+1 contract (setjoind-only)
        let unified = build_rust_manifest(&[("setjoind", "setjoind", "core_setjoind")]);
        unified.validate().expect("Release N+1 unified valid");

        // 4. Half-shim cohorts MUST fail closed
        let half_server = build_rust_manifest(&[
            ("setjoind", "setjoind", "core_setjoind"),
            ("setjoin-server", "setjoin-server", "core_setjoin_server"),
        ]);
        let err = half_server.validate().unwrap_err().to_string();
        assert!(err.contains("both shims or neither"), "{err}");

        let half_auth = build_rust_manifest(&[
            ("setjoind", "setjoind", "core_setjoind"),
            ("setjoin-auth", "setjoin-auth", "core_setjoin_auth"),
        ]);
        let err = half_auth.validate().unwrap_err().to_string();
        assert!(err.contains("both shims or neither"), "{err}");

        // 5. Mixing setjoind with ANY legacy Go binary MUST fail closed
        for (id, class, target) in [
            ("mailserverd", "mailserverd", "core_mailserverd"),
            ("authserverd", "authserverd", "core_authserverd"),
            ("setjoin-gateway", "setjoin-gateway", "core_setjoin_gateway"),
        ] {
            let mixed = build_rust_manifest(&[
                ("setjoind", "setjoind", "core_setjoind"),
                (id, class, target),
            ]);
            let err = mixed.validate().unwrap_err().to_string();
            assert!(err.contains("mixes setjoind with legacy Go"), "{err}");
        }
    }

    #[test]
    fn unknown_artifact_class_is_rejected_even_with_empty_target() {
        for (class, target) in [
            ("unknown-class", ""),
            ("future_binary", ""),
            ("", ""),
            ("unknown-class", "core_unknown"),
        ] {
            let mut mv = base_manifest();
            let template = mv["artifacts"][0].clone();
            let mut arts = mv["artifacts"].as_array().unwrap().clone();
            let mut extra = make_artifact(&template, "z-unknown-artifact", class, target);
            extra["cohort"] = "extras".into();
            arts.push(extra);
            arts.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            mv["artifacts"] = Value::Array(arts);
            let raw = serde_json::to_vec(&mv).unwrap();
            let err = Manifest::parse(&raw)
                .expect_err("unknown artifact class must be rejected")
                .to_string();
            assert!(
                err.contains("unknown artifact class"),
                "unexpected error for class={class:?} target={target:?}: {err}"
            );
        }
    }

    #[test]
    fn prerelease_numeric_overflow_ordering_is_total_transitive_and_antisymmetric() {
        // Strictly ascending SemVer 2.0.0 order spanning normal u64, u64::MAX,
        // u64::MAX+1, much larger decimal integers, alphanumeric identifiers, and release.
        let primary = [
            "1.0.0-0",
            "1.0.0-2",
            "1.0.0-10",
            "1.0.0-18446744073709551614", // u64::MAX - 1
            "1.0.0-18446744073709551615", // u64::MAX
            "1.0.0-18446744073709551616", // u64::MAX + 1
            "1.0.0-18446744073709551616.1",
            "1.0.0-18446744073709551616.2",
            "1.0.0-18446744073709551616.18446744073709551616",
            "1.0.0-18446744073709551616.18446744073709551617",
            "1.0.0-18446744073709551617", // u64::MAX + 2
            "1.0.0-99999999999999999998",
            "1.0.0-99999999999999999999",
            "1.0.0-100000000000000000000",
            "1.0.0-9999999999999999999999999999999999999999",
            "1.0.0-alpha",
            "1.0.0",
        ];
        let parsed: Vec<Version> = primary.iter().map(|s| parse_version(s).unwrap()).collect();
        for (i, a) in parsed.iter().enumerate() {
            for (j, b) in parsed.iter().enumerate() {
                assert_eq!(
                    a.compare(b),
                    i.cmp(&j),
                    "expected {} {:?} {}",
                    primary[i],
                    i.cmp(&j),
                    primary[j]
                );
                // Antisymmetry check
                assert_eq!(
                    a.compare(b),
                    b.compare(a).reverse(),
                    "antisymmetry violated for {} vs {}",
                    primary[i],
                    primary[j]
                );
            }
        }
        // Transitivity check across all triples (i < j < k)
        for i in 0..parsed.len() {
            for j in (i + 1)..parsed.len() {
                for k in (j + 1)..parsed.len() {
                    assert_eq!(parsed[i].compare(&parsed[j]), Ordering::Less);
                    assert_eq!(parsed[j].compare(&parsed[k]), Ordering::Less);
                    assert_eq!(parsed[i].compare(&parsed[k]), Ordering::Less);
                }
            }
        }
        assert!(version_in_range(
            "1.0.0-18446744073709551617",
            ">1.0.0-18446744073709551616 <1.0.0-99999999999999999999"
        )
        .unwrap());
        assert!(!version_in_range(
            "1.0.0-18446744073709551616",
            ">1.0.0-18446744073709551617"
        )
        .unwrap());
    }
}
