//! Frozen Go's defaults → YAML → existing-key environment configuration (#414).
//! EnvironmentFile processing belongs to systemd, as it does for Go.
mod runtime;
pub use runtime::Runtime;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub struct Settings {
    values: BTreeMap<String, Value>,
    file_keys: BTreeSet<String>,
}
impl Settings {
    pub fn load(environment: &BTreeMap<String, String>) -> Result<Self, String> {
        let ordered: Vec<(String, String)> =
            environment.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        Self::load_ordered(&ordered)
    }
    pub fn load_ordered(environment: &[(String, String)]) -> Result<Self, String> {
        let yaml = match environment
            .iter()
            .rev()
            .find(|(k, _)| k == "SETJOIN_CONFIG")
            .map(|(_, v)| v.as_str())
            .filter(|p| !p.is_empty())
        {
            Some(path) => std::fs::read_to_string(path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    format!("open {path}: no such file or directory")
                } else {
                    format!("open {path}: {error}")
                }
            })?,
            None => String::new(),
        };
        Self::parse_ordered(&yaml, environment)
    }
    pub fn set_network_mode(&mut self, mode: String) {
        self.values.insert("network.mode".into(), mode.into());
    }

    pub fn parse(yaml: &str, environment: &BTreeMap<String, String>) -> Result<Self, String> {
        let ordered: Vec<(String, String)> =
            environment.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        Self::parse_ordered(yaml, &ordered)
    }
    pub fn parse_ordered(yaml: &str, environment: &[(String, String)]) -> Result<Self, String> {
        let env_get = |k: &str| {
            environment
                .iter()
                .rev()
                .find(|(name, _)| name == k)
                .map(|(_, value)| value.as_str())
        };
        let env_has = |k: &str| environment.iter().any(|(name, _)| name == k);
        let mut values: BTreeMap<String, Value> =
            serde_json::from_str(include_str!("defaults.json")).expect("Go defaults");
        // LoadBase seeds these defaults from env BEFORE the YAML layer. In
        // particular, a YAML DB_DSN does not rewrite a previously seeded worker DSN.
        for (key, name, fallback) in [
            ("db.direct_dsn", "DB_DIRECT_DSN", "DB_DSN"),
            ("db.worker_dsn", "DB_WORKER_DSN", "DB_DSN"),
            ("db.owner_dsn", "DB_OWNER_DSN", "DB_DSN"),
        ] {
            let value = env_get(name)
                .filter(|v| !v.is_empty())
                .or_else(|| env_get(fallback));
            if let Some(value) = value {
                values.insert(key.into(), value.to_owned().into());
            }
        }
        let mut file = BTreeMap::new();
        if !yaml.trim().is_empty() {
            let normalized_yaml = normalize_yaml_underscore_numbers(yaml);
            let value: Value =
                serde_saphyr::from_str(&normalized_yaml).map_err(|e| format!("yaml: {e}"))?;
            if !value.is_null() && !value.is_object() {
                return Err("yaml: configuration must be a mapping".into());
            }
            flatten("", &value, &mut file);
        }
        let mut file_keys: BTreeSet<String> = file.keys().cloned().collect();
        values.extend(file);
        for (name, value) in environment {
            let key = transform(name);
            let key = if values.contains_key(&key) {
                Some(key)
            } else {
                let candidates: Vec<_> = values
                    .keys()
                    .filter(|key| key.replace('.', "_").eq_ignore_ascii_case(name))
                    .cloned()
                    .collect();
                (candidates.len() == 1).then(|| candidates[0].clone())
            };
            if let Some(key) = key {
                file_keys.insert(key.clone());
                values.insert(key, value.clone().into());
            }
        }
        for (key, name, default) in [
            ("s3.endpoint", "MINIO_ENDPOINT", "127.0.0.1:9000"),
            ("s3.access_key", "MINIO_ACCESS_KEY", ""),
            ("s3.secret_key", "MINIO_SECRET_KEY", ""),
            ("s3.bucket", "MINIO_BUCKET", "mailblobs"),
        ] {
            if values.get(key).and_then(Value::as_str) == Some(default) {
                if let Some(value) = env_get(name).filter(|v| !v.is_empty()) {
                    values.insert(key.into(), value.to_owned().into());
                    file_keys.insert(key.into());
                }
            }
        }
        // Mirror Go config.go:615-620 and 634-637 fallback rules when the explicit env vars are absent.
        if !env_has("INTERNAL_DOMAINS")
            && values.get("internal.domains").and_then(Value::as_str) == Some("localhost")
        {
            if let Some(host) = env_get("HOSTNAME").filter(|v| !v.is_empty()) {
                values.insert("internal.domains".into(), host.to_owned().into());
                file_keys.insert("internal.domains".into());
            }
        }
        if !env_has("WORM_LEGAL_HOLD_ENABLED") {
            let worm_mode_non_empty = values
                .get("worm.mode")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty());
            values.insert(
                "worm.legal_hold_enabled".into(),
                Value::Bool(worm_mode_non_empty),
            );
            if worm_mode_non_empty || file_keys.contains("worm.legal_hold_enabled") {
                file_keys.insert("worm.legal_hold_enabled".into());
            }
        }
        Ok(Self { values, file_keys })
    }
    pub fn string(&self, key: &str) -> String {
        match self.values.get(key) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Bool(b)) => b.to_string(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    }
    pub fn boolean(&self, key: &str) -> bool {
        match self.values.get(key) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Number(n)) => {
                n.as_f64() == Some(1.0) || n.as_i64() == Some(1) || n.as_u64() == Some(1)
            }
            Some(Value::String(s)) => matches!(s.as_str(), "1" | "t" | "T" | "true" | "TRUE" | "True"),
            _ => false,
        }
    }
    /// The client-visible configuration projection recorded by the Go overlay.
    pub fn projection(&self) -> Value {
        let mut out = serde_json::Map::new();
        for key in [
            "network.mode",
            "website.dir",
            "scim.enabled",
            "ad.sync_enabled",
            "ldap.sync_enabled",
            "imap.tls_addr",
            "auth.login_field",
            "auth.login_domain_hint",
            "crypto.algorithm_profile",
        ] {
            let value = if key.starts_with("auth.login_") {
                // Go declares these fields but never decodes them from koanf.
                String::new()
            } else if key.ends_with("enabled") {
                self.boolean(key).to_string()
            } else {
                self.string(key)
            };
            out.insert(key.into(), value.into());
        }
        out.into()
    }
    /// Bridge existing startup adapters to resolved file/env keys, including
    /// aliases such as SCIM__ENABLED. Defaults alone do not populate env. Call only
    /// once, BEFORE constructing the async runtime or starting any tasks.
    pub fn install_startup_environment(&self) {
        for key in &self.file_keys {
            if key.starts_with("auth.login_") {
                continue;
            }
            let name = key.replace('.', "_").to_ascii_uppercase();
            let env_value = if key == "s3.secure"
                && matches!(
                    self.values.get(key.as_str()),
                    Some(Value::Bool(_) | Value::Number(_))
                ) {
                if self.boolean(key) {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                }
            } else if key == "worm.retention_days" {
                canonical_worm_retention_value(self.values.get(key.as_str()))
                    .unwrap_or_else(|| self.string(key))
            } else {
                self.string(key)
            };
            std::env::set_var(&name, env_value);
            // Existing protocol adapters use Go's field-oriented spelling.
            match key.as_str() {
                "tls.cert" => std::env::set_var("TLS_CERT_FILE", self.string(key)),
                "tls.key" => std::env::set_var("TLS_KEY_FILE", self.string(key)),
                _ => {}
            }
        }
    }
}
fn valid_underscore_digits(s: &str, pred: fn(u8) -> bool) -> bool {
    let bytes = s.as_bytes();
    let mut saw_digit = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' {
            if i == 0 || i + 1 == bytes.len() || bytes[i - 1] == b'_' || bytes[i + 1] == b'_' {
                return false;
            }
        } else if pred(b) {
            saw_digit = true;
        } else {
            return false;
        }
    }
    saw_digit
}

fn normalize_go_yaml_number(raw: &str) -> Option<String> {
    if !raw.contains('_') {
        return None;
    }
    let unsigned = raw.strip_prefix(['+', '-']).unwrap_or(raw);
    if let Some(hex) = unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X")) {
        let digits = hex.strip_prefix('_').unwrap_or(hex);
        if valid_underscore_digits(digits, |b| b.is_ascii_hexdigit()) {
            return Some(raw.replace('_', ""));
        }
        return None;
    }
    if let Some(oct) = unsigned.strip_prefix("0o").or_else(|| unsigned.strip_prefix("0O")) {
        let digits = oct.strip_prefix('_').unwrap_or(oct);
        if valid_underscore_digits(digits, |b| matches!(b, b'0'..=b'7')) {
            return Some(raw.replace('_', ""));
        }
        return None;
    }
    if let Some(bin) = unsigned.strip_prefix("0b").or_else(|| unsigned.strip_prefix("0B")) {
        let digits = bin.strip_prefix('_').unwrap_or(bin);
        if valid_underscore_digits(digits, |b| matches!(b, b'0' | b'1')) {
            return Some(raw.replace('_', ""));
        }
        return None;
    }
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(idx) => {
            let exp_raw = &unsigned[idx + 1..];
            let exp = exp_raw.strip_prefix(['+', '-']).unwrap_or(exp_raw);
            if !valid_underscore_digits(exp, |b| b.is_ascii_digit()) {
                return None;
            }
            (&unsigned[..idx], Some(exp))
        }
        None => (unsigned, None),
    };
    let int_ok = |part: &str| {
        part == "0"
            || (part.as_bytes().first().is_some_and(|b| matches!(b, b'1'..=b'9'))
                && valid_underscore_digits(part, |b| b.is_ascii_digit()))
    };
    if let Some((int_part, frac_part)) = mantissa.split_once('.') {
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        if !int_part.is_empty() && !int_ok(int_part) {
            return None;
        }
        if !frac_part.is_empty() && !valid_underscore_digits(frac_part, |b| b.is_ascii_digit()) {
            return None;
        }
        return Some(raw.replace('_', ""));
    }
    if int_ok(mantissa) && exponent.is_some() {
        return Some(raw.replace('_', ""));
    }
    if int_ok(mantissa) {
        return Some(raw.replace('_', ""));
    }
    None
}

fn normalize_yaml_underscore_numbers(yaml: &str) -> String {
    use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle};

    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for item in Parser::new_from_str(yaml) {
        let Ok((event, span)) = item else {
            return yaml.to_owned();
        };
        let Event::Scalar(text, ScalarStyle::Plain, _, tag) = event else {
            continue;
        };
        let tag_ok = tag.as_ref().is_none_or(|t| {
            t.handle() == "tag:yaml.org,2002:" && matches!(t.suffix(), "int" | "float")
        });
        if !tag_ok {
            continue;
        }
        let Some(normalized) = normalize_go_yaml_number(text.as_ref()) else {
            continue;
        };
        let (Some(start), Some(end)) = (span.start.byte_offset(), span.end.byte_offset()) else {
            continue;
        };
        if yaml.get(start..end) == Some(text.as_ref()) {
            edits.push((start, end, normalized));
        }
    }
    if edits.is_empty() {
        return yaml.to_owned();
    }
    edits.sort_by_key(|(start, _, _)| *start);
    let mut out = String::with_capacity(yaml.len());
    let mut cursor = 0usize;
    for (start, end, replacement) in edits {
        if start < cursor {
            continue;
        }
        out.push_str(&yaml[cursor..start]);
        out.push_str(&replacement);
        cursor = end;
    }
    out.push_str(&yaml[cursor..]);
    out
}

fn canonical_worm_retention_value(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else {
                n.as_f64()
                    .filter(|f| {
                        f.is_finite()
                            && *f >= (i64::MIN as f64)
                            && *f < 9_223_372_036_854_775_808.0
                    })
                    .map(|f| (*f as i64).to_string())
            }
        }
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let normalized = normalize_go_yaml_number(trimmed).unwrap_or_else(|| trimmed.to_owned());
            let (neg, unsigned) = if let Some(rest) = normalized.strip_prefix('-') {
                (true, rest)
            } else if let Some(rest) = normalized.strip_prefix('+') {
                (false, rest)
            } else {
                (false, normalized.as_str())
            };
            let parsed = if let Some(hex) =
                unsigned.strip_prefix("0x").or_else(|| unsigned.strip_prefix("0X"))
            {
                i64::from_str_radix(hex, 16)
                    .ok()
                    .and_then(|v| if neg { v.checked_neg() } else { Some(v) })
            } else if let Some(oct) =
                unsigned.strip_prefix("0o").or_else(|| unsigned.strip_prefix("0O"))
            {
                i64::from_str_radix(oct, 8)
                    .ok()
                    .and_then(|v| if neg { v.checked_neg() } else { Some(v) })
            } else if let Some(bin) =
                unsigned.strip_prefix("0b").or_else(|| unsigned.strip_prefix("0B"))
            {
                i64::from_str_radix(bin, 2)
                    .ok()
                    .and_then(|v| if neg { v.checked_neg() } else { Some(v) })
            } else {
                normalized.parse::<i64>().ok()
            };
            if let Some(days) = parsed {
                return Some(days.to_string());
            }
            normalized
                .parse::<f64>()
                .ok()
                .filter(|f| {
                    f.is_finite() && *f >= (i64::MIN as f64) && *f < 9_223_372_036_854_775_808.0
                })
                .map(|f| (f as i64).to_string())
        }
        _ => None,
    }
}

fn transform(name: &str) -> String {
    let mut key = name.to_lowercase().replace("__", ".");
    if let Some(at) = key.find('_') {
        key.replace_range(at..=at, ".");
    }
    key
}
fn flatten(prefix: &str, value: &Value, out: &mut BTreeMap<String, Value>) {
    if let Value::Object(map) = value {
        for (key, value) in map {
            // koanf's nested lookup does not address a literal dotted YAML key.
            if key.contains('.') {
                continue;
            }
            let key = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            flatten(&key, value, out);
        }
    } else if !prefix.is_empty() {
        out.insert(prefix.into(), value.clone());
    }
}

/// Go's three-second startup detection: Baidu-only means China, GitHub
/// reachable means global, neither means airgap. Reload does not re-probe.
pub async fn detect_network_mode() -> String {
    async fn reachable(address: &str) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .is_ok_and(|r| r.is_ok())
    }
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        if reachable("baidu.com:443").await && !reachable("github.com:443").await {
            "china"
        } else if reachable("github.com:443").await {
            "global"
        } else {
            "airgap"
        }
    })
    .await
    .unwrap_or("airgap")
    .into()
}

impl Settings {
    /// Validation at Go's reload boundary. Required deployment credentials are
    /// checked here even when the front door itself can boot without local routes.
    pub fn validate(&self) -> Result<(), String> {
        let get = |key| self.string(key);
        let profile = get("crypto.algorithm_profile");
        if get("db.dsn").is_empty() {
            return Err("DB_DSN is required".into());
        }
        if !matches!(profile.as_str(), "" | "standard" | "smx" | "hybrid") {
            return Err("CRYPTO_ALGORITHM_PROFILE must be standard, smx, or hybrid".into());
        }
        let floor = if profile == "smx" { 16 } else { 32 };
        if get("jwt.secret").len() < floor {
            return Err(format!(
                "JWT_SECRET must be at least {floor} characters for profile {profile}"
            ));
        }
        let key = get("db.encryption_key");
        if !key.is_empty() && key.len() < floor {
            return Err(if profile == "smx" {
                "DB_ENCRYPTION_KEY must be at least 16 characters for profile smx"
            } else {
                "DB_ENCRYPTION_KEY must be at least 32 characters or empty"
            }
            .into());
        }
        if profile == "smx" && get("sm2.private_key_file").is_empty() {
            return Err("SM2_PRIVATE_KEY_FILE is required for profile smx".into());
        }
        if get("tls.cert").is_empty() != get("tls.key").is_empty() {
            return Err("TLS_CERT and TLS_KEY must both be set or both empty".into());
        }
        for (name, key) in [
            ("JWT_MAIL_ATTACHMENT_SECRET", "jwt.mail_attachment_secret"),
            (
                "JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET",
                "jwt.mail_attachment_previous_secret",
            ),
            (
                "JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET",
                "jwt.link_protect_token_previous_secret",
            ),
        ] {
            let secret = get(key);
            if !secret.is_empty() && secret.len() < floor {
                return Err(format!(
                    "{name} must be at least {floor} characters for profile {profile}"
                ));
            }
        }
        let raw = get("jwt.link_protect_token_version");
        let raw = raw.trim();
        let version = if raw.is_empty() {
            0
        } else {
            raw.parse::<i64>().map_err(|_|format!("JWT_LINK_PROTECT_TOKEN_VERSION: invalid integer {} — it selects the link-protect token key generation (a malformed value must not silently fall back to version 1)",setjoin_contracts::go_quote::quote(raw.as_bytes())))?
        };
        if version < 0 {
            return Err(format!("JWT_LINK_PROTECT_TOKEN_VERSION must be >= 1 (got {version}) — it selects the link-protect token key generation"));
        }
        if !get("jwt.link_protect_token_previous_secret").is_empty() && version <= 1 {
            return Err("JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET is set but JWT_LINK_PROTECT_TOKEN_VERSION=1 has no previous generation — bump the version (rotating the gateway secret at the same time) to open the overlap window, or remove the previous secret".into());
        }
        if get("s3.access_key").is_empty() || get("s3.secret_key").is_empty() {
            return Err("MINIO_ACCESS_KEY and MINIO_SECRET_KEY must be set".into());
        }
        let mode = get("sandbox.fail_mode");
        if !matches!(mode.as_str(), "" | "open" | "closed") {
            return Err(format!("SANDBOX_FAIL_MODE must be \"open\" or \"closed\" (got {}) — an unknown spelling must not fail open",setjoin_contracts::go_quote::quote(mode.as_bytes())));
        }
        let algorithm = get("smime.encrypt_algorithm");
        if !matches!(algorithm.as_str(), "" | "aes-256-gcm" | "aes-256-cbc") {
            return Err(format!(
                "SMIME_ENCRYPT_ALGORITHM must be \"aes-256-gcm\" or \"aes-256-cbc\" (got {})",
                setjoin_contracts::go_quote::quote(algorithm.as_bytes())
            ));
        }
        if get("smtp.inbound_addr").is_empty()
            && get("smtp.submission_addr").is_empty()
            && get("imap.addr").is_empty()
        {
            return Err(
                "at least one of SMTP_INBOUND_ADDR, SMTP_SUBMISSION_ADDR, or IMAP_ADDR must be set"
                    .into(),
            );
        }
        for (key, name, label) in [
            ("imap.addr", "IMAP_ADDR", "IMAP authentication"),
            (
                "smtp.submission_addr",
                "SMTP_SUBMISSION_ADDR",
                "submission authentication",
            ),
        ] {
            let address = get(key);
            if !address.is_empty()
                && (get("tls.cert").is_empty() || get("tls.key").is_empty())
                && !loopback_listener(&address)
            {
                return Err(format!("TLS_CERT and TLS_KEY are required when {name} listens beyond loopback; {label} must not be exposed without STARTTLS"));
            }
        }
        Ok(())
    }
}
fn loopback_listener(address: &str) -> bool {
    address
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback())
        || address
            .strip_prefix("localhost:")
            .is_some_and(|port| !port.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::Settings;
    use std::collections::BTreeMap;

    #[test]
    fn settings_boolean_matches_koanf_numeric_one() {
        let numeric = Settings::parse("s3:\n  secure: 1.0\n", &BTreeMap::new()).unwrap();
        assert!(numeric.boolean("s3.secure"));

        let quoted = Settings::parse("s3:\n  secure: \"1.0\"\n", &BTreeMap::new()).unwrap();
        assert!(!quoted.boolean("s3.secure"));
    }

    #[test]
    fn settings_parse_ordered_preserves_last_slot_alias_precedence() {
        let worm_on = Settings::parse_ordered(
            "",
            &[
                ("WORM__MODE".into(), String::new()),
                ("WORM_MODE".into(), "compliance".into()),
            ],
        )
        .unwrap();
        assert_eq!(worm_on.string("worm.mode"), "compliance");
        assert!(worm_on.boolean("worm.legal_hold_enabled"));

        let worm_off = Settings::parse_ordered(
            "",
            &[
                ("WORM_MODE".into(), "compliance".into()),
                ("WORM__MODE".into(), String::new()),
            ],
        )
        .unwrap();
        assert_eq!(worm_off.string("worm.mode"), "");
        assert!(!worm_off.boolean("worm.legal_hold_enabled"));

        let bucket_single = Settings::parse_ordered(
            "",
            &[
                ("S3__BUCKET".into(), "first".into()),
                ("S3_BUCKET".into(), "second".into()),
            ],
        )
        .unwrap();
        assert_eq!(bucket_single.string("s3.bucket"), "second");

        let bucket_double = Settings::parse_ordered(
            "",
            &[
                ("S3_BUCKET".into(), "first".into()),
                ("S3__BUCKET".into(), "second".into()),
            ],
        )
        .unwrap();
        assert_eq!(bucket_double.string("s3.bucket"), "second");
    }

    #[test]
    fn yaml_underscore_numbers_and_canonical_retention_match_go() {
        let float_one = Settings::parse("s3:\n  secure: 1_0e-1\n", &BTreeMap::new()).unwrap();
        assert!(float_one.boolean("s3.secure"));

        let tagged_float =
            Settings::parse("s3:\n  secure: !!float 1_0e-1\n", &BTreeMap::new()).unwrap();
        assert!(tagged_float.boolean("s3.secure"));

        let hex_one = Settings::parse("s3:\n  secure: 0x_1\n", &BTreeMap::new()).unwrap();
        assert!(hex_one.boolean("s3.secure"));

        let quoted = Settings::parse("s3:\n  secure: \"1_0e-1\"\n", &BTreeMap::new()).unwrap();
        assert!(!quoted.boolean("s3.secure"));

        let str_tagged =
            Settings::parse("s3:\n  secure: !!str 1_0e-1\n", &BTreeMap::new()).unwrap();
        assert!(!str_tagged.boolean("s3.secure"));

        let yaml_retention =
            Settings::parse("worm:\n  retention_days: 3650.0\n", &BTreeMap::new()).unwrap();
        assert_eq!(
            super::canonical_worm_retention_value(yaml_retention.values.get("worm.retention_days"))
                .as_deref(),
            Some("3650")
        );

        let mut env = BTreeMap::new();
        env.insert("WORM_RETENTION_DAYS".into(), "3650.0".into());
        let env_retention = Settings::parse("", &env).unwrap();
        assert_eq!(
            super::canonical_worm_retention_value(env_retention.values.get("worm.retention_days"))
                .as_deref(),
            Some("3650")
        );
    }
}
