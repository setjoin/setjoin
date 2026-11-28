//! EK01 `system_config` secret codec (#379), byte-compatible with frozen Go
//! `mailserver/internal/admin/config_secret.go` over `shared/cryptokey`.
//!
//! A sealed value is a JSON record
//! `{"format":"setjoin-config-secret","version":1,"keyVersion":N,"sourceKey":S,
//! "ciphertext":base64url-nopad(EK01 envelope)}` stored in `system_config.value`.
//! The envelope is authenticated with the AAD
//! `setjoin-system-config-v1 \0 deployment \0 source \0 configKey \0 keyVersion`.
//! Key material is never logged, formatted or placed in an error.

mod envelope;
mod sm4;

pub use envelope::{CryptoProfile, EnvelopeError};

use base64::engine::{general_purpose::GeneralPurposeConfig, DecodePaddingMode, GeneralPurpose};
use base64::{alphabet, Engine};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// `format` discriminator of a sealed record (Go `ConfigSecretEnvelopeFormat`).
pub const ENVELOPE_FORMAT: &str = "setjoin-config-secret";
/// Record version (Go `ConfigSecretEnvelopeVersion`).
pub const ENVELOPE_VERSION: i64 = 1;
const AAD_DOMAIN: &str = "setjoin-system-config-v1";

/// Go's `base64.RawURLEncoding`: no padding, trailing bits tolerated.
const RAW_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// Failure classes, with Go's messages in `Display` (key bytes never appear).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSecretError {
    /// Invalid keyring or configuration, checked when the codec is built.
    Keyring(String),
    /// The record is not a JSON object of the envelope shape.
    NotEnvelope { config_key: String, detail: String },
    /// `format` or `version` is not the supported one.
    UnsupportedFormat { config_key: String },
    /// `sourceKey` does not match the source derived from the config key.
    SourceMismatch { config_key: String },
    /// The record names a key version that is neither active nor retiring.
    UnavailableKeyVersion { config_key: String, version: u32 },
    /// `ciphertext` is not base64url.
    InvalidCiphertextEncoding { config_key: String, detail: String },
    /// Authentication or envelope parsing failed (wrong key, AAD, truncation, tamper).
    Decrypt {
        config_key: String,
        cause: EnvelopeError,
    },
    /// Decryption succeeded but the plaintext is not JSON.
    InvalidPlaintext { config_key: String },
    /// Sealing failed.
    Encrypt {
        config_key: String,
        cause: EnvelopeError,
    },
}

fn quoted(s: &str) -> String {
    let mut out = String::from("\"");
    envelope::push_escaped(&mut out, s);
    out.push('"');
    out
}

impl fmt::Display for ConfigSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keyring(msg) => f.write_str(msg),
            Self::NotEnvelope { config_key, detail } => {
                write!(
                    f,
                    "config secret {} is not an envelope: {detail}",
                    quoted(config_key)
                )
            }
            Self::UnsupportedFormat { config_key } => write!(
                f,
                "config secret {} has unsupported envelope format/version",
                quoted(config_key)
            ),
            Self::SourceMismatch { config_key } => {
                write!(
                    f,
                    "config secret {} source binding mismatch",
                    quoted(config_key)
                )
            }
            Self::UnavailableKeyVersion {
                config_key,
                version,
            } => write!(
                f,
                "config secret {} requires unavailable key version {version}",
                quoted(config_key)
            ),
            Self::InvalidCiphertextEncoding { config_key, detail } => write!(
                f,
                "config secret {} has invalid ciphertext encoding: {detail}",
                quoted(config_key)
            ),
            Self::Decrypt { config_key, cause } => {
                write!(f, "decrypt config secret {}: {cause}", quoted(config_key))
            }
            Self::InvalidPlaintext { config_key } => write!(
                f,
                "config secret {} decrypted to invalid JSON",
                quoted(config_key)
            ),
            Self::Encrypt { config_key, cause } => {
                write!(f, "encrypt config secret {}: {cause}", quoted(config_key))
            }
        }
    }
}

impl std::error::Error for ConfigSecretError {}

fn keyring_err<T>(msg: impl Into<String>) -> Result<T, ConfigSecretError> {
    Err(ConfigSecretError::Keyring(msg.into()))
}

/// Raw key material for [`ConfigSecretCodec::new`]. Keys are the configured strings'
/// bytes (not hex-decoded), exactly as Go uses them. `Debug` redacts them.
pub struct ConfigSecretKeyring {
    pub deployment_id: String,
    pub active_version: u32,
    pub active_key: Vec<u8>,
    pub active_profile: CryptoProfile,
    pub retiring_keys: BTreeMap<u32, Vec<u8>>,
}

impl fmt::Debug for ConfigSecretKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigSecretKeyring")
            .field("deployment_id", &self.deployment_id)
            .field("active_version", &self.active_version)
            .field("active_profile", &self.active_profile)
            .field(
                "retiring_versions",
                &self.retiring_keys.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Drop for ConfigSecretKeyring {
    fn drop(&mut self) {
        self.active_key.zeroize();
        for key in self.retiring_keys.values_mut() {
            key.zeroize();
        }
    }
}

/// Seals and opens `system_config` secrets for one deployment.
pub struct ConfigSecretCodec {
    deployment_id: String,
    active_version: u32,
    active_key: Zeroizing<Vec<u8>>,
    active_profile: CryptoProfile,
    retiring: BTreeMap<u32, Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for ConfigSecretCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigSecretCodec")
            .field("deployment_id", &self.deployment_id)
            .field("active_version", &self.active_version)
            .finish_non_exhaustive()
    }
}

/// Parses `IDENTITY_CONFIG_SECRET_RETIRING_KEYS`: a JSON object of version to key.
/// Like Go: blank is empty, `null` is empty, a `null` key is the empty string (later
/// rejected as too short), versions are plain base-10 u32 and non-zero. Two spellings
/// of one version ("1" and "01") are refused; Go keeps a random one of them.
pub fn parse_retiring_keys(raw: &str) -> Result<BTreeMap<u32, Vec<u8>>, ConfigSecretError> {
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    let object: Option<BTreeMap<String, Option<String>>> =
        serde_json::from_str(raw).map_err(|_| {
            ConfigSecretError::Keyring(
                "identity config secret retiring keys must be a JSON object".into(),
            )
        })?;
    let mut out = BTreeMap::new();
    for (raw_version, key) in object.unwrap_or_default() {
        let valid = !raw_version.is_empty() && raw_version.bytes().all(|b| b.is_ascii_digit());
        let version = valid
            .then(|| raw_version.parse::<u32>().ok())
            .flatten()
            .filter(|v| *v != 0);
        let Some(version) = version else {
            return keyring_err(format!(
                "identity config secret retiring key version {} is invalid",
                quoted(&raw_version)
            ));
        };
        if out
            .insert(version, key.unwrap_or_default().into_bytes())
            .is_some()
        {
            return keyring_err(format!(
                "identity config secret retiring key version {} is duplicated",
                quoted(&raw_version)
            ));
        }
    }
    Ok(out)
}

/// Builds the keyring from the same settings Go reads (`mailserverd`):
/// `CRYPTO_ALGORITHM_PROFILE` (default `standard`, unknown values are refused as in
/// Go's startup validation), `IDENTITY_CONFIG_SECRET_KEY_VERSION` (default 1),
/// `IDENTITY_CONFIG_SECRET_KEY` falling back to `DB_ENCRYPTION_KEY`, and
/// `IDENTITY_CONFIG_SECRET_RETIRING_KEYS`. `get` is the caller's configuration source
/// (the process environment via [`keyring_from_env`]); `deployment_id` is
/// `system_config` key `identity.deployment_id`. The version accepts only plain
/// decimal digits (Go also takes hex/octal spellings; those fail closed here).
pub fn keyring_from_lookup(
    deployment_id: &str,
    get: impl Fn(&str) -> Option<String>,
) -> Result<ConfigSecretKeyring, ConfigSecretError> {
    let profile = match get("CRYPTO_ALGORITHM_PROFILE").as_deref() {
        None | Some("") | Some("standard") => CryptoProfile::Standard,
        Some("smx") => CryptoProfile::Smx,
        Some("hybrid") => CryptoProfile::Hybrid,
        Some(_) => return keyring_err("CRYPTO_ALGORITHM_PROFILE must be standard, smx, or hybrid"),
    };
    let version = match get("IDENTITY_CONFIG_SECRET_KEY_VERSION") {
        None => Some(1),
        Some(raw) => {
            let digits = raw.strip_prefix('+').unwrap_or(&raw);
            let plain = digits == "0" || (!digits.starts_with('0') && !digits.is_empty());
            (plain && digits.bytes().all(|b| b.is_ascii_digit()))
                .then(|| digits.parse::<u32>().ok())
                .flatten()
        }
    };
    let Some(version) = version.filter(|v| *v != 0) else {
        return keyring_err("identity connector secret key version must be positive");
    };
    let mut active = get("IDENTITY_CONFIG_SECRET_KEY").unwrap_or_default();
    if active.is_empty() {
        active = get("DB_ENCRYPTION_KEY").unwrap_or_default();
    }
    let retiring =
        parse_retiring_keys(&get("IDENTITY_CONFIG_SECRET_RETIRING_KEYS").unwrap_or_default())
            .map_err(|e| {
                ConfigSecretError::Keyring(format!(
                    "parse identity connector retiring keyring: {e}"
                ))
            })?;
    Ok(ConfigSecretKeyring {
        deployment_id: deployment_id.to_owned(),
        active_version: version,
        active_key: active.into_bytes(),
        active_profile: profile,
        retiring_keys: retiring,
    })
}

/// [`keyring_from_lookup`] over the process environment.
pub fn keyring_from_env(deployment_id: &str) -> Result<ConfigSecretKeyring, ConfigSecretError> {
    keyring_from_lookup(deployment_id, |name| std::env::var(name).ok())
}

/// Go `cryptokey.EncryptColumn`: seals one column value (no AAD) from the RAW master
/// secret into an EK01 envelope. Webhook signing secrets use this form
/// (`webhook_subscriptions.secret_enc`), stamped beside a key-version id by the caller.
pub fn seal_column(
    plaintext: &[u8],
    master: &[u8],
    profile: CryptoProfile,
) -> Result<Vec<u8>, EnvelopeError> {
    envelope::seal(profile, master, plaintext, &[])
}

/// Go `cryptokey.DecryptColumn`: opens an EK01 column envelope sealed without AAD.
pub fn open_column(envelope: &[u8], master: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    envelope::open(envelope, master, &[])
}

/// Shape check only, like Go `IsConfigSecretEnvelope`: format and version match.
pub fn is_config_secret_envelope(value: &[u8]) -> bool {
    match parse_record(value) {
        Ok(record) => record.format == ENVELOPE_FORMAT && record.version == ENVELOPE_VERSION,
        Err(_) => false,
    }
}

struct Record {
    format: String,
    version: i64,
    key_version: u32,
    source_key: String,
    ciphertext: String,
}

fn parse_record(stored: &[u8]) -> Result<Record, String> {
    let value: Value = serde_json::from_slice(stored).map_err(|e| e.to_string())?;
    let mut record = Record {
        format: String::new(),
        version: 0,
        key_version: 0,
        source_key: String::new(),
        ciphertext: String::new(),
    };
    let object = match value {
        Value::Null => return Ok(record),
        Value::Object(object) => object,
        other => {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type admin.configSecretRecord",
                kind_name(&other)
            ))
        }
    };
    let text = |name: &str, slot: &mut String| -> Result<(), String> {
        match object.get(name) {
            None | Some(Value::Null) => Ok(()),
            Some(Value::String(s)) => {
                slot.clone_from(s);
                Ok(())
            }
            Some(other) => Err(format!(
                "json: cannot unmarshal {} into Go struct field configSecretRecord.{name} of type string",
                kind_name(other)
            )),
        }
    };
    text("format", &mut record.format)?;
    text("sourceKey", &mut record.source_key)?;
    text("ciphertext", &mut record.ciphertext)?;
    match object.get("version") {
        None | Some(Value::Null) => {}
        Some(Value::Number(n)) if n.as_i64().is_some() => record.version = n.as_i64().unwrap_or(0),
        Some(other) => {
            return Err(format!(
            "json: cannot unmarshal {} into Go struct field configSecretRecord.version of type int",
            kind_name(other)
        ))
        }
    }
    match object.get("keyVersion") {
        None | Some(Value::Null) => {}
        Some(Value::Number(n)) if n.as_u64().is_some_and(|v| v <= u64::from(u32::MAX)) => {
            record.key_version = n.as_u64().unwrap_or(0) as u32
        }
        Some(other) => {
            return Err(format!(
                "json: cannot unmarshal {} into Go struct field configSecretRecord.keyVersion of type uint32",
                kind_name(other)
            ))
        }
    }
    Ok(record)
}

fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The `sourceKey` Go binds a config key to.
pub fn source_key(config_key: &str) -> String {
    if config_key.starts_with("ad_sync_") {
        "legacy:ad".into()
    } else if config_key.starts_with("ldap_sync_") {
        "legacy:ldap".into()
    } else if config_key.starts_with("tls_") {
        "legacy:tls".into()
    } else if let Some(rest) = config_key.strip_prefix("identity_source.") {
        rest.into()
    } else {
        "legacy:system".into()
    }
}

/// Go `encoding/json` string escaping (HTML-safe: `<`, `>`, `&`, U+2028, U+2029).
fn go_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl ConfigSecretCodec {
    /// Validates and copies key material (Go `NewConfigSecretCodec`).
    pub fn new(keyring: ConfigSecretKeyring) -> Result<Self, ConfigSecretError> {
        let deployment_id = keyring.deployment_id.trim().to_owned();
        if deployment_id.is_empty() || deployment_id.len() > 255 {
            return keyring_err("config secret deployment ID must be 1..255 characters");
        }
        if keyring.active_version == 0 {
            return keyring_err("config secret active key version must be non-zero");
        }
        let min = keyring.active_profile.key_len();
        if keyring.active_key.len() < min {
            return keyring_err(format!(
                "config secret active key must be at least {min} bytes"
            ));
        }
        let mut retiring = BTreeMap::new();
        for (version, key) in &keyring.retiring_keys {
            if *version == 0 || *version == keyring.active_version {
                return keyring_err(format!(
                    "invalid retiring config secret key version {version}"
                ));
            }
            if key.len() < 16 {
                return keyring_err(format!(
                    "retiring config secret key version {version} is too short"
                ));
            }
            retiring.insert(*version, Zeroizing::new(key.clone()));
        }
        Ok(Self {
            deployment_id,
            active_version: keyring.active_version,
            active_key: Zeroizing::new(keyring.active_key.clone()),
            active_profile: keyring.active_profile,
            retiring,
        })
    }

    /// Non-secret identifier stamped beside newly sealed values.
    pub fn active_version(&self) -> u32 {
        self.active_version
    }

    fn aad(&self, source: &str, config_key: &str, key_version: u32) -> Vec<u8> {
        [
            AAD_DOMAIN,
            &self.deployment_id,
            source,
            config_key,
            &key_version.to_string(),
        ]
        .join("\0")
        .into_bytes()
    }

    /// Seals one raw JSON value with the active key; the result is the JSON record
    /// to store in `system_config.value`. Like Go, the plaintext is not validated here.
    pub fn encrypt(
        &self,
        config_key: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ConfigSecretError> {
        let source = source_key(config_key);
        let aad = self.aad(&source, config_key, self.active_version);
        let sealed = envelope::seal(self.active_profile, &self.active_key, plaintext, &aad)
            .map_err(|cause| ConfigSecretError::Encrypt {
                config_key: config_key.into(),
                cause,
            })?;
        Ok(self.record(config_key, &source, &sealed))
    }

    fn record(&self, _config_key: &str, source: &str, sealed: &[u8]) -> Vec<u8> {
        format!(
            "{{\"format\":{},\"version\":{ENVELOPE_VERSION},\"keyVersion\":{},\"sourceKey\":{},\"ciphertext\":\"{}\"}}",
            go_json_string(ENVELOPE_FORMAT),
            self.active_version,
            go_json_string(source),
            RAW_URL.encode(sealed)
        )
        .into_bytes()
    }

    /// Opens a stored record. Malformed records, other deployments, other config
    /// keys or sources, unknown key versions, wrong keys and tampering all fail.
    pub fn decrypt(&self, config_key: &str, stored: &[u8]) -> Result<Vec<u8>, ConfigSecretError> {
        let owned = || config_key.to_owned();
        let record = parse_record(stored).map_err(|detail| ConfigSecretError::NotEnvelope {
            config_key: owned(),
            detail,
        })?;
        if record.format != ENVELOPE_FORMAT || record.version != ENVELOPE_VERSION {
            return Err(ConfigSecretError::UnsupportedFormat {
                config_key: owned(),
            });
        }
        if record.source_key != source_key(config_key) {
            return Err(ConfigSecretError::SourceMismatch {
                config_key: owned(),
            });
        }
        let key: &[u8] = if record.key_version == self.active_version {
            &self.active_key[..]
        } else if let Some(key) = self.retiring.get(&record.key_version) {
            key
        } else {
            return Err(ConfigSecretError::UnavailableKeyVersion {
                config_key: owned(),
                version: record.key_version,
            });
        };
        // Go's base64 reader skips CR and LF.
        let cleaned: String = record
            .ciphertext
            .chars()
            .filter(|c| *c != '\r' && *c != '\n')
            .collect();
        let sealed = RAW_URL.decode(cleaned.as_bytes()).map_err(|e| {
            ConfigSecretError::InvalidCiphertextEncoding {
                config_key: owned(),
                detail: e.to_string(),
            }
        })?;
        let aad = self.aad(&record.source_key, config_key, record.key_version);
        let plaintext =
            envelope::open(&sealed, key, &aad).map_err(|cause| ConfigSecretError::Decrypt {
                config_key: owned(),
                cause,
            })?;
        if serde_json::from_slice::<Value>(&plaintext).is_err() {
            return Err(ConfigSecretError::InvalidPlaintext {
                config_key: owned(),
            });
        }
        Ok(plaintext)
    }

    /// Deterministic-nonce sealing for recorded-vector tests only.
    #[cfg(test)]
    pub(crate) fn encrypt_with_nonce(
        &self,
        config_key: &str,
        nonce: &[u8; 12],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let source = source_key(config_key);
        let aad = self.aad(&source, config_key, self.active_version);
        let sealed = envelope::seal_with_nonce(
            self.active_profile,
            &self.active_key,
            nonce,
            plaintext,
            &aad,
        )
        .expect("seal");
        self.record(config_key, &source, &sealed)
    }
}

#[cfg(test)]
mod tests;
