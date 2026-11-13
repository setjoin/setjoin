//! Slice `tls` (#323): Go's `admin.TLSHandler` (status, config read and write, certificate
//! import audit) and `admin.TLSPolicyHandler` (outbound policy read and write).
//!
//! `system_config` is global, so there is no tenant filter; the gateway adapter checks the
//! console gate (`requireMailPerm` for reads, `requireSecurityWrite` for writes) before any of
//! this runs. Writes are receipted reducers (`rust_mailsec_tls_policy_set`,
//! `rust_mailsec_tls_config_set`) or one audit statement (certificate import). Go's TLS
//! `ConfigStore` is built without a secrets codec, so a secret (`_enc`) value can never be
//! written through it (500); only the console's `[ENCRYPTED]` echo of a stored secret passes.
use super::{command, deadline, done, envelope, invalid, s, scope};
use serde_json::{Map, Value};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const REDACTED: &str = "[ENCRYPTED]";

/// Go's `isSecretConfigKey`.
fn is_secret(key: &str) -> bool {
    key.ends_with("_enc") || key == "assist.api_key"
}

// ---- Go encoding/json value rendering ----

/// `strconv.FormatFloat(f, 'f'|'e', -1, 64)` as `encoding/json` chooses it.
pub fn go_float(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let a = f.abs();
    if !(1e-6..1e21).contains(&a) {
        let text = format!("{f:e}");
        let (mantissa, exp) = text.split_once('e').expect("exponent");
        let exp: i32 = exp.parse().expect("exponent digits");
        // Go writes at least two exponent digits, then cleans "e-07" to "e-7".
        return if exp >= 0 {
            format!("{mantissa}e+{exp:02}")
        } else {
            format!("{mantissa}e-{}", -exp)
        };
    }
    format!("{f}")
}

/// `json.Marshal` of a value decoded into `interface{}`: numbers went through float64, map keys
/// are sorted, strings are HTML-escaped.
pub fn go_marshal(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => go_float(n.as_f64().unwrap_or(0.0)),
        Value::String(text) => super::go_escape(&s(text)),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(go_marshal).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            format!(
                "{{{}}}",
                sorted
                    .iter()
                    .map(|(k, v)| format!("{}:{}", super::go_escape(&s(k)), go_marshal(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

// ---- outbound TLS policy ----

/// `validateTLSPolicyRequest`: the 400 detail, or `None` when valid.
pub fn validate_policy(
    enforce: &Option<Vec<String>>,
    skip: &Option<Vec<String>>,
    mode: &str,
) -> Option<String> {
    if enforce.is_none() {
        return Some("enforce_domains must be an array".into());
    }
    if skip.is_none() {
        return Some("skip_domains must be an array".into());
    }
    if mode.is_empty() {
        return Some("global_mode is required".into());
    }
    if mode != "enforce" && mode != "opportunistic" {
        return Some(format!(
            "global_mode must be 'enforce' or 'opportunistic', got {}",
            setjoin_contracts::go_quote::quote(mode.as_bytes())
        ));
    }
    None
}

/// `json.Unmarshal(raw, &[]string)` with its error ignored: a non-array leaves nil, a bad
/// element stays empty while the rest still decode.
fn lenient_strings(raw: &str) -> Option<Vec<String>> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(items)) => Some(
            items
                .into_iter()
                .map(|v| match v {
                    Value::String(text) => text,
                    _ => String::new(),
                })
                .collect(),
        ),
        _ => None,
    }
}

async fn stored(worker: &ScopedExecutor, key: &str) -> Option<String> {
    let rows = worker
        .read(
            "SELECT value::text FROM system_config WHERE key = $1",
            &[(&key, Type::TEXT)],
        )
        .await
        .ok()?;
    rows.first()?.try_get::<_, String>(0).ok()
}

/// `GET /admin/outbound-tls-policy`: every failed key read falls back to the default.
pub async fn policy_get(worker: &ScopedExecutor) -> String {
    let enforce = match stored(worker, "outbound_tls_enforce_domains").await {
        Some(raw) => lenient_strings(&raw),
        None => None,
    }
    .unwrap_or_default();
    let skip = match stored(worker, "outbound_tls_skip_domains").await {
        Some(raw) => lenient_strings(&raw),
        None => None,
    }
    .unwrap_or_default();
    let mode = match stored(worker, "outbound_tls_global_mode").await {
        Some(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(Value::String(text)) => text,
            _ => String::new(),
        },
        None => String::new(),
    };
    let mode = if mode.is_empty() {
        "opportunistic".to_owned()
    } else {
        mode
    };
    let list = |items: &[String]| items.iter().map(|d| s(d)).collect::<Vec<_>>().join(",");
    done(format!(
        "{{\"enforce_domains\":[{}],\"skip_domains\":[{}],\"global_mode\":{}}}",
        list(&enforce),
        list(&skip),
        s(&mode)
    ))
}

/// `PUT /admin/outbound-tls-policy` after validation: the three upserts and the notification.
pub async fn policy_put(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    enforce: &[String],
    skip: &[String],
    mode: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let list = |items: &[String]| {
        format!(
            "[{}]",
            items.iter().map(|d| s(d)).collect::<Vec<_>>().join(",")
        )
    };
    let (enforce_json, skip_json, mode_json) = (list(enforce), list(skip), s(mode));
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("tls.policy.put"),
        &envelope(
            &auth,
            operation,
            &format!("tls.policy.put:{enforce_json}:{skip_json}:{mode_json}"),
        ),
        &auth,
        deadline(),
        "SELECT rust_mailsec_tls_policy_set($4::text::jsonb,$5::text::jsonb,$6::text::jsonb) \
         WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[
            (&enforce_json, Type::TEXT),
            (&skip_json, Type::TEXT),
            (&mode_json, Type::TEXT),
        ],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}

// ---- tls_* configuration ----

/// Go's `configStringForResponse` after `redactConfigValue`.
fn config_text(key: &str, value: &str, encrypted: bool) -> String {
    if encrypted || is_secret(key) {
        return REDACTED.into();
    }
    match serde_json::from_str::<Value>(value) {
        Ok(Value::String(text)) => text,
        // json.Unmarshal of null into a string succeeds and leaves it empty.
        Ok(Value::Null) => String::new(),
        _ => value.into(),
    }
}

/// `GET /admin/tls/config`: `GetByPrefix("tls_")` (the `_` is a LIKE wildcard, as in Go).
pub async fn config_get(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE 'tls_%' ORDER BY key",
            &[],
        )
        .await?;
    let mut config: BTreeMap<String, String> = BTreeMap::new();
    for row in &rows {
        let key: String = row.try_get(0).map_err(|_| invalid())?;
        let value: String = row.try_get(1).map_err(|_| invalid())?;
        let encrypted: bool = row.try_get(2).map_err(|_| invalid())?;
        let text = config_text(&key, &value, encrypted);
        config.insert(key, text);
    }
    let body = config
        .iter()
        .map(|(k, v)| format!("{}:{}", s(k), s(v)))
        .collect::<Vec<_>>()
        .join(",");
    Ok(done(format!("{{{body}}}")))
}

/// Why the write could not run; every case answers Go's `500 database error`.
#[derive(Debug)]
pub enum SetError {
    Prepare(String),
    Outcome(CommandOutcome<(), StatementFailure>),
}

/// `PUT /admin/tls/config`: only `tls_*` keys are kept; `ConfigStore.BatchSet` preserves a
/// secret key when the console echoes the redaction sentinel, refuses any other secret value,
/// and upserts the rest; Go then writes the `tls_config_set` audit row, here in the same transaction.
pub async fn config_set(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    values: &Map<String, Value>,
    operation: [u8; 16],
) -> Result<(), SetError> {
    let mut filtered: Vec<(&String, &Value)> = values
        .iter()
        .filter(|(k, _)| k.starts_with("tls_"))
        .collect();
    filtered.sort_by(|a, b| a.0.cmp(b.0));
    let (mut keys, mut texts, mut flags) = (vec![], vec![], vec![]);
    for (key, value) in &filtered {
        let marshalled = go_marshal(value);
        if is_secret(key) {
            if value.as_str() == Some(REDACTED) {
                let present = worker
                    .read(
                        "SELECT 1 FROM system_config WHERE key = $1",
                        &[(*key, Type::TEXT)],
                    )
                    .await
                    .map_err(|e| SetError::Prepare(e.message))?;
                if present.is_empty() {
                    return Err(SetError::Prepare(format!(
                        "cannot preserve absent config secret {key:?}"
                    )));
                }
                continue;
            }
            // Go wires `NewConfigStore(pool, effects)` with no codec for TLS.
            return Err(SetError::Prepare(format!(
                "encrypt config secret {key:?}: codec is not configured"
            )));
        } else {
            texts.push(marshalled);
            flags.push(false);
        }
        keys.push((*key).clone());
    }
    let audited: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();
    let after =
        serde_json::json!({"description": "TLS configuration", "keys": audited}).to_string();
    let notes = audited.join(",");
    let auth = scope(actor);
    let outcome = setjoin_pg::run_receipted_command(
        worker,
        command("tls.config.put"),
        &envelope(&auth, operation, &format!("tls.config.put:{notes}")),
        &auth,
        deadline(),
        "SELECT rust_mailsec_tls_config_set($4::text[],$5::text[],$6::boolean[],$2::bigint,$7::text,$8::text::jsonb,$9::text) \
         WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[
            (&keys, Type::TEXT_ARRAY),
            (&texts, Type::TEXT_ARRAY),
            (&flags, Type::BOOL_ARRAY),
            (&ip, Type::TEXT),
            (&after, Type::TEXT),
            (&notes, Type::TEXT),
        ],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await;
    match outcome {
        CommandOutcome::Committed(()) => Ok(()),
        other => Err(SetError::Outcome(other)),
    }
}

/// The `tls_cert_import` core audit row Go writes after the files are on disk.
pub async fn import_audit(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    ip: &str,
    cert_path: &str,
    key_path: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let after = format!(
        "{{\"certPath\":{},\"keyPath\":{}}}",
        s(cert_path),
        s(key_path)
    );
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("tls.cert.import"),
        &envelope(&auth, operation, &format!("tls.cert.import:{after}")),
        &auth,
        deadline(),
        "SELECT audit_write($2,'tls_cert_import','system_config',NULL,NULL,$4::text::jsonb,NULLIF($5::text,'')::inet,'','core') \
         WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&after, Type::TEXT), (&ip, Type::TEXT)],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}

/// `{"certPath":..,"keyPath":..}` (a map, so sorted keys).
pub fn import_body(cert_path: &str, key_path: &str) -> String {
    done(format!(
        "{{\"certPath\":{},\"keyPath\":{}}}",
        s(cert_path),
        s(key_path)
    ))
}

// ---- status ----

/// Go's `getConfig`: the scalar text of one key, "" on any error or absence.
async fn config_value(worker: &ScopedExecutor, key: &str) -> String {
    match worker
        .read(
            "SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = $1), '')",
            &[(&key, Type::TEXT)],
        )
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, String>(0).ok())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
}

/// What `GET /admin/tls/status` read from `system_config`; the certificate lookup that
/// follows touches the file system, so the adapter finishes it.
pub struct StatusInput {
    pub challenge: String,
    pub domains: Vec<String>,
    pub email: String,
    pub dns_provider: String,
    pub cache_dir: String,
    pub enabled: bool,
}

/// Go's `splitCSV`: nil (JSON `null`) for the empty string.
fn split_csv(text: &str) -> Vec<String> {
    if text.is_empty() {
        return vec![];
    }
    text.split(',').map(|p| p.trim().to_owned()).collect()
}

pub async fn status_input(worker: &ScopedExecutor) -> StatusInput {
    let challenge = config_value(worker, "tls_autocert_challenge").await;
    let domains = config_value(worker, "tls_autocert_domains").await;
    let email = config_value(worker, "tls_autocert_email").await;
    let dns_provider = config_value(worker, "tls_dns_provider").await;
    let cache_dir = config_value(worker, "tls_autocert_cache_dir").await;
    StatusInput {
        enabled: !challenge.is_empty() && !domains.is_empty(),
        domains: split_csv(&domains),
        challenge: if challenge.is_empty() {
            "none".into()
        } else {
            challenge
        },
        email,
        dns_provider,
        cache_dir,
    }
}

/// `filepath.Join(dir, name)` for a plain file name: joined, then lexically cleaned.
fn join_clean(dir: &str, name: &str) -> String {
    let rooted = dir.starts_with('/');
    let mut parts: Vec<&str> = vec![];
    for part in dir.split('/').chain(std::iter::once(name)) {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

/// `certCachePath(cacheDir, domain)`: the SHA-256-hashed cache file path.
pub fn cert_cache_path(cache_dir: &str, domain: &str) -> String {
    let digest: String = Sha256::digest(domain.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    join_clean(cache_dir, &digest)
}

pub(crate) fn rfc3339(time: x509_parser::time::ASN1Time) -> String {
    let t = time.to_datetime();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// `readCertInfo`: the first PEM block must be a CERTIFICATE that parses; anything else is
/// "no certificate". `now` is Unix seconds.
pub fn cert_info(path: &str, now: i64) -> Option<CertInfo> {
    let data = std::fs::read(path).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&data).ok()?;
    if pem.label != "CERTIFICATE" {
        return None;
    }
    let cert = crate::certificate::parse(&pem.contents).ok()?;
    let not_after = cert.validity().not_after;
    let remaining = (not_after.timestamp() - now) as f64 / 3600.0 / 24.0;
    Some(CertInfo {
        subject: crate::certificate::common_name(cert.subject()),
        issuer: crate::certificate::common_name(cert.issuer()),
        not_before: rfc3339(cert.validity().not_before),
        not_after: rfc3339(not_after),
        days_left: remaining.trunc() as i64,
    })
}

pub fn status_body(input: &StatusInput, cert: Option<&CertInfo>) -> String {
    let domains = if input.domains.is_empty() {
        "null".to_owned()
    } else {
        format!(
            "[{}]",
            input
                .domains
                .iter()
                .map(|d| s(d))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let cert = cert.map_or(String::new(), |c| {
        format!(
            ",\"cert_info\":{{\"subject\":{},\"issuer\":{},\"not_before\":{},\"not_after\":{},\"days_left\":{}}}",
            s(&c.subject),
            s(&c.issuer),
            s(&c.not_before),
            s(&c.not_after),
            c.days_left
        )
    });
    done(format!(
        "{{\"enabled\":{},\"challenge\":{},\"domains\":{domains},\"email\":{},\"dns_provider\":{}{cert},\"cache_dir\":{}}}",
        input.enabled,
        s(&input.challenge),
        s(&input.email),
        s(&input.dns_provider),
        s(&input.cache_dir)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_render_like_go() {
        for (f, want) in [
            (0.0, "0"),
            (1.0, "1"),
            (1.5, "1.5"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1.5e22, "1.5e+22"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1.25e-10, "1.25e-10"),
            (-2.5, "-2.5"),
        ] {
            assert_eq!(go_float(f), want, "{f}");
        }
    }

    #[test]
    fn marshal_sorts_keys_and_escapes_html() {
        let v: Value = serde_json::from_str(r#"{"b":[1,"<a>"],"a":{"z":null,"y":true}}"#).unwrap();
        assert_eq!(
            go_marshal(&v),
            r#"{"a":{"y":true,"z":null},"b":[1,"\u003ca\u003e"]}"#
        );
    }

    #[test]
    fn cache_path_cleans_like_filepath_join() {
        assert_eq!(join_clean("/a//b/./c/", "x"), "/a/b/c/x");
        assert_eq!(join_clean("/a/b/../c", "x"), "/a/c/x");
        assert_eq!(join_clean("rel/", "x"), "rel/x");
    }

    const FIXTURE: &str = "-----BEGIN CERTIFICATE-----\nMIIBvTCCAWOgAwIBAgIUeTsVydbKk2JhFxxWUH2SpAhMa9kwCgYIKoZIzj0EAwIw\nMzEXMBUGA1UECgwOU2V0am9pbiBPcmFjbGUxGDAWBgNVBAMMD3Rscy1vcmFjbGUu\ndGVzdDAgFw0yNjExMDMxMjU4MzBaGA8yMDk1MDQxNTEyNTgzMFowMzEXMBUGA1UE\nCgwOU2V0am9pbiBPcmFjbGUxGDAWBgNVBAMMD3Rscy1vcmFjbGUudGVzdDBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABFme8wfeFa3l6j63tPkbzV70HdtDxb1KVfhg\nQJYT8wRJB5xrpb8Gp9WJ3ivSJUKecfUrx/t5ABoLihU6g5a01xqjUzBRMB0GA1Ud\nDgQWBBRLDw9lvjbFwf8EVrrNPbuqx0F4hTAfBgNVHSMEGDAWgBRLDw9lvjbFwf8E\nVrrNPbuqx0F4hTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBGi\nSxI25ek6TMsn9qbHXjo6zsaEggo4Trl2UcNxx4obAiEA7D/adTkpQAambjZr/GEv\n3szZWVRFwOqP6f4Iq3S89i8=\n-----END CERTIFICATE-----";

    #[test]
    fn certificate_info_reads_the_first_block() {
        let dir = std::env::temp_dir().join(format!("mailsec-tls-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.pem");
        std::fs::write(&good, FIXTURE).unwrap();
        let now = 1_793_710_710 + 36 * 3600;
        let info = cert_info(good.to_str().unwrap(), now).expect("certificate");
        assert_eq!(info.subject, "tls-oracle.test");
        assert_eq!(info.issuer, "tls-oracle.test");
        assert_eq!(info.not_before, "2026-11-03T12:58:30Z");
        assert_eq!(info.not_after, "2095-04-15T12:58:30Z");
        assert_eq!(info.days_left, (3953710710 - now) / 86400);
        let junk = dir.join("junk.pem");
        std::fs::write(&junk, format!("junk\n{FIXTURE}")).unwrap();
        assert!(
            cert_info(junk.to_str().unwrap(), now).is_some(),
            "junk before the block is skipped"
        );
        std::fs::write(&junk, "not a certificate").unwrap();
        assert!(cert_info(junk.to_str().unwrap(), now).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lenient_strings_keep_going_after_a_bad_element() {
        assert_eq!(
            lenient_strings(r#"["a",1,null,"b"]"#),
            Some(vec!["a".into(), "".into(), "".into(), "b".into()])
        );
        assert_eq!(lenient_strings(r#""x""#), None);
        assert_eq!(lenient_strings("null"), None);
    }
}
