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
        let yaml = match environment.get("SETJOIN_CONFIG").filter(|p| !p.is_empty()) {
            Some(path) => std::fs::read_to_string(path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    format!("open {path}: no such file or directory")
                } else {
                    format!("open {path}: {error}")
                }
            })?,
            None => String::new(),
        };
        Self::parse(&yaml, environment)
    }
    pub fn set_network_mode(&mut self, mode: String) {
        self.values.insert("network.mode".into(), mode.into());
    }

    pub fn parse(yaml: &str, environment: &BTreeMap<String, String>) -> Result<Self, String> {
        let mut values: BTreeMap<String, Value> =
            serde_json::from_str(include_str!("defaults.json")).expect("Go defaults");
        // LoadBase seeds these defaults from env BEFORE the YAML layer. In
        // particular, a YAML DB_DSN does not rewrite a previously seeded worker DSN.
        for (key, name, fallback) in [
            ("db.direct_dsn", "DB_DIRECT_DSN", "DB_DSN"),
            ("db.worker_dsn", "DB_WORKER_DSN", "DB_DSN"),
            ("db.owner_dsn", "DB_OWNER_DSN", "DB_DSN"),
        ] {
            let value = environment
                .get(name)
                .filter(|v| !v.is_empty())
                .or_else(|| environment.get(fallback));
            if let Some(value) = value {
                values.insert(key.into(), value.clone().into());
            }
        }
        let mut file = BTreeMap::new();
        if !yaml.trim().is_empty() {
            let value: Value = serde_saphyr::from_str(yaml).map_err(|e| format!("yaml: {e}"))?;
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
                if let Some(value) = environment.get(name).filter(|v| !v.is_empty()) {
                    values.insert(key.into(), value.clone().into());
                    file_keys.insert(key.into());
                }
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
        matches!(
            self.string(key).as_str(),
            "1" | "t" | "T" | "true" | "TRUE" | "True"
        )
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
            std::env::set_var(&name, self.string(key));
            // Existing protocol adapters use Go's field-oriented spelling.
            match key.as_str() {
                "tls.cert" => std::env::set_var("TLS_CERT_FILE", self.string(key)),
                "tls.key" => std::env::set_var("TLS_KEY_FILE", self.string(key)),
                _ => {}
            }
        }
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
