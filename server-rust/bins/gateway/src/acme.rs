//! Release N+1 (#560) fail-closed retirement guard for built-in ACME (`setjoin-acme`).
//!
//! Built-in ACME (`crates/acme`, `setjoin-acme.socket`, `acme-renewal` worker,
//! HTTP-01 / TLS-ALPN-01 / DNS-01 issuance) was deprecated in Release N (#559)
//! and retired in Release N+1 (#560). Setjoin now serves TLS exclusively via
//! pure-`rustls` atomic PEM hot-reloading (`TLS_CERT`/`TLS_KEY` or
//! `TLS_CERT_FILE`/`TLS_KEY_FILE`).

use std::collections::BTreeSet;
use std::ffi::OsStr;

pub const RENEWAL: &str = "acme-renewal";

fn listed(list: &str, name: &str) -> bool {
    list.split(',').any(|s| s.trim() == name)
}

/// Go `strconv.ParseBool` / Rust bool parity for `TLS_AUTOCERT_ROLLOUT`.
fn is_truthy_rollout(value: &str) -> bool {
    matches!(value.trim(), "1" | "t" | "T" | "TRUE" | "true" | "True")
}

/// Returns true if an `OsStr` contains any byte other than ASCII whitespace,
/// safely handling non-Unicode secret values without ever decoding them into UTF-8.
fn os_is_non_empty(value: &OsStr) -> bool {
    value
        .as_encoded_bytes()
        .iter()
        .any(|b| !b.is_ascii_whitespace())
}

/// Release N+1 (#560) fail-closed startup guard for retired built-in ACME settings,
/// reading raw `OsStr` pairs (safe for non-Unicode environment values).
///
/// Refuses any non-empty variable whose name starts with `ACME_`, `TLS_DNS_`, or
/// `TLS_AUTOCERT_` (exempting `TLS_AUTOCERT_CACHE_DIR`, which `POST /admin/tls/import-cert`
/// still reads from `gateway.env`, and preserving Go/Rust bool parity on
/// `TLS_AUTOCERT_ROLLOUT`), plus `RUST_WORKERS_ON=acme-renewal`.
///
/// Reports ONLY sorted, deduplicated trigger names (never environment values,
/// valid UTF-8 or non-Unicode) and points operators to
/// `docs/guides/EDGE_TLS_ACME_MIGRATION.md` and `TLS_CERT`/`TLS_KEY`
/// (`TLS_CERT_FILE`/`TLS_KEY_FILE`). Returns `None` when only static PEM files
/// or proxy-terminated TLS are configured.
pub fn retirement_error_os<I, K, V>(vars: I) -> Option<String>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let mut triggers: BTreeSet<String> = BTreeSet::new();

    for (raw_key, raw_val) in vars {
        let key_os = raw_key.as_ref();
        let val_os = raw_val.as_ref();
        let key_bytes = key_os.as_encoded_bytes();

        if key_bytes == b"TLS_AUTOCERT_CACHE_DIR" {
            continue;
        }
        if key_bytes == b"TLS_AUTOCERT_ROLLOUT" {
            match val_os.to_str() {
                Some(s) if is_truthy_rollout(s) => {
                    triggers.insert("TLS_AUTOCERT_ROLLOUT".to_owned());
                }
                Some(_) => {
                    triggers.remove("TLS_AUTOCERT_ROLLOUT");
                }
                // Non-Unicode value must fail closed here rather than falling
                // through to std::env::vars(), which would panic with the value.
                None => {
                    triggers.insert("TLS_AUTOCERT_ROLLOUT".to_owned());
                }
            }
            continue;
        }
        if key_bytes == b"RUST_WORKERS_ON" {
            let lossy = val_os.to_string_lossy();
            if listed(&lossy, RENEWAL) {
                triggers.insert("RUST_WORKERS_ON=acme-renewal".to_owned());
            } else {
                triggers.remove("RUST_WORKERS_ON=acme-renewal");
            }
            continue;
        }
        if key_bytes.starts_with(b"ACME_")
            || key_bytes.starts_with(b"TLS_DNS_")
            || key_bytes.starts_with(b"TLS_AUTOCERT_")
        {
            let name = key_os.to_string_lossy().into_owned();
            if os_is_non_empty(val_os) {
                triggers.insert(name);
            } else {
                triggers.remove(&name);
            }
        }
    }

    if triggers.is_empty() {
        return None;
    }
    let joined: Vec<&str> = triggers.iter().map(String::as_str).collect();
    Some(format!(
        "built-in ACME (setjoin-acme, triggers=[{}]) was retired in Release N+1 (#560). Remove all ACME_*/TLS_AUTOCERT_*/TLS_DNS_* variables and `acme-renewal`, configure TLS_CERT/TLS_KEY (or TLS_CERT_FILE/TLS_KEY_FILE) with an edge TLS/ACME terminator (Caddy or certbot) exporting hot-reloaded PEM files; see docs/guides/EDGE_TLS_ACME_MIGRATION.md.",
        joined.join(",")
    ))
}

/// Convenience entry point scanning the live process environment via `std::env::vars_os()`.
/// Must be called before `std::env::vars()` so non-Unicode legacy secrets fail closed
/// cleanly instead of panicking.
pub fn retirement_error_from_env() -> Option<String> {
    retirement_error_os(std::env::vars_os())
}

#[cfg(test)]
mod retirement_guard_tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn silent_when_only_static_pem_is_configured() {
        let env = [
            ("TLS_CERT", "/etc/mail/tls/server.pem"),
            ("TLS_KEY", "/etc/mail/tls/server-key.pem"),
            ("TLS_CERT_FILE", "/etc/mail/tls/server.pem"),
            ("TLS_KEY_FILE", "/etc/mail/tls/server-key.pem"),
            ("TLS_AUTOCERT_CACHE_DIR", "/var/cache/mailserver/autocert"),
            ("RUST_WORKERS_ON", "http-tls,cert-monitor"),
            ("TLS_AUTOCERT_ROLLOUT", "false"),
            ("ACME_DOMAINS", "   "),
            ("TLS_DNS_API_TOKEN", ""),
        ];
        let err = retirement_error_os(env);
        assert!(err.is_none(), "static PEM must not fail: {err:?}");
    }

    #[test]
    fn each_legacy_trigger_fails_closed_without_leaking_secrets() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "TLS_AUTOCERT_DOMAINS",
                "mail.example.test",
                "TLS_AUTOCERT_DOMAINS",
            ),
            (
                "TLS_AUTOCERT_EMAIL",
                "ops@example.test",
                "TLS_AUTOCERT_EMAIL",
            ),
            (
                "TLS_AUTOCERT_KEY_FILE",
                "/etc/mail/acme-account.key",
                "TLS_AUTOCERT_KEY_FILE",
            ),
            (
                "TLS_AUTOCERT_CHALLENGE",
                "http-01",
                "TLS_AUTOCERT_CHALLENGE",
            ),
            ("TLS_DNS_PROVIDER", "cloudflare", "TLS_DNS_PROVIDER"),
            (
                "TLS_DNS_CONFIG",
                r#"{"CF_API_TOKEN":"sentinel-secret-560"}"#,
                "TLS_DNS_CONFIG",
            ),
            ("TLS_DNS_RESOLVERS", "1.1.1.1:53", "TLS_DNS_RESOLVERS"),
            (
                "TLS_DNS_API_TOKEN",
                "sentinel-secret-560-api-token",
                "TLS_DNS_API_TOKEN",
            ),
            (
                "TLS_DNS_TSIG_SECRET",
                "sentinel-secret-560-tsig",
                "TLS_DNS_TSIG_SECRET",
            ),
            ("ACME_DOMAINS", "mail.example.test", "ACME_DOMAINS"),
            ("ACME_EMAIL", "ops@example.test", "ACME_EMAIL"),
            ("ACME_CHALLENGE", "dns-01", "ACME_CHALLENGE"),
            ("ACME_CACHE_DIR", "/var/cache/acme", "ACME_CACHE_DIR"),
            ("ACME_DNS_PROVIDER", "cloudflare", "ACME_DNS_PROVIDER"),
            (
                "ACME_CUSTOM_FLAG",
                "sentinel-secret-560",
                "ACME_CUSTOM_FLAG",
            ),
            (
                "RUST_WORKERS_ON",
                "http-tls,acme-renewal",
                "RUST_WORKERS_ON=acme-renewal",
            ),
        ];
        for &(key, val, expected_trigger) in cases {
            let msg = retirement_error_os([(key, val)])
                .unwrap_or_else(|| panic!("expected retirement error for {expected_trigger}"));
            assert!(
                msg.contains(expected_trigger),
                "missing trigger {expected_trigger} in: {msg}"
            );
            assert!(
                msg.contains("docs/guides/EDGE_TLS_ACME_MIGRATION.md"),
                "missing migration guide path in: {msg}"
            );
            assert!(
                msg.contains("TLS_CERT_FILE") && msg.contains("TLS_KEY_FILE"),
                "missing TLS_CERT_FILE/TLS_KEY_FILE guidance in: {msg}"
            );
            assert!(msg.contains("#560"), "missing #560 reference in: {msg}");
            assert!(
                !msg.contains("sentinel-secret-560"),
                "secret value leaked into retirement error: {msg}"
            );
        }
    }

    #[test]
    fn triggers_are_sorted_and_deduplicated() {
        let msg = retirement_error_os([
            ("TLS_DNS_TSIG_SECRET", "s1"),
            ("ACME_EMAIL", "ops@example.test"),
            ("TLS_DNS_API_TOKEN", "s2"),
            ("TLS_DNS_TSIG_SECRET", "s3"),
        ])
        .expect("expected retirement error");
        assert!(
            msg.contains("triggers=[ACME_EMAIL,TLS_DNS_API_TOKEN,TLS_DNS_TSIG_SECRET]"),
            "triggers not sorted/deduplicated: {msg}"
        );
        assert!(!msg.contains("s1") && !msg.contains("s2") && !msg.contains("s3"));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_secret_value_fails_closed_without_panicking_or_leaking() {
        let mut raw = b"raw-secret-prefix-".to_vec();
        raw.extend_from_slice(&[0xff, 0xfe, 0x80]);
        let secret = OsString::from_vec(raw.clone());
        let msg = retirement_error_os([(OsString::from("TLS_DNS_TSIG_SECRET"), secret)])
            .expect("non-Unicode secret must trigger retirement error");
        assert!(msg.contains("TLS_DNS_TSIG_SECRET"), "{msg}");
        assert!(
            !msg.contains("raw-secret-prefix"),
            "non-Unicode secret value leaked: {msg}"
        );

        let rollout_msg = retirement_error_os([(
            OsString::from("TLS_AUTOCERT_ROLLOUT"),
            OsString::from_vec(raw),
        )])
        .expect("non-Unicode TLS_AUTOCERT_ROLLOUT must fail closed");
        assert!(
            rollout_msg.contains("TLS_AUTOCERT_ROLLOUT"),
            "{rollout_msg}"
        );
        assert!(
            !rollout_msg.contains("raw-secret-prefix"),
            "non-Unicode rollout value leaked: {rollout_msg}"
        );
    }

    #[test]
    fn rollout_flag_matches_go_rust_bool_parity() {
        for truthy in ["1", "t", "T", "TRUE", "true", "True", " TRUE "] {
            let msg = retirement_error_os([("TLS_AUTOCERT_ROLLOUT", truthy)])
                .unwrap_or_else(|| panic!("expected trigger for TLS_AUTOCERT_ROLLOUT={truthy:?}"));
            assert!(msg.contains("TLS_AUTOCERT_ROLLOUT"), "{msg}");
        }
        for falsy in ["", "0", "f", "F", "false", "FALSE", "False", "no", "yes"] {
            assert!(
                retirement_error_os([("TLS_AUTOCERT_ROLLOUT", falsy)]).is_none(),
                "unexpected error for TLS_AUTOCERT_ROLLOUT={falsy:?}"
            );
        }
    }
}
