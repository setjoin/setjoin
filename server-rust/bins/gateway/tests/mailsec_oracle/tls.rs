//! Slice `tls` (#323): TLS status, `tls_*` configuration, certificate import and the
//! outbound TLS policy. `system_config` is global, so a case stashes every `tls%` and
//! `outbound_tls%` row, seeds its own, and `teardown` puts the stash back. The certificate
//! cache directory is a per-case host directory mounted at the same path into the Go
//! container, so Go and Rust read and write the very same files.
use super::{Req, Seed};
use crate::common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::fixture::Account;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBvTCCAWOgAwIBAgIUeTsVydbKk2JhFxxWUH2SpAhMa9kwCgYIKoZIzj0EAwIw\nMzEXMBUGA1UECgwOU2V0am9pbiBPcmFjbGUxGDAWBgNVBAMMD3Rscy1vcmFjbGUu\ndGVzdDAgFw0yNjExMDMxMjU4MzBaGA8yMDk1MDQxNTEyNTgzMFowMzEXMBUGA1UE\nCgwOU2V0am9pbiBPcmFjbGUxGDAWBgNVBAMMD3Rscy1vcmFjbGUudGVzdDBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABFme8wfeFa3l6j63tPkbzV70HdtDxb1KVfhg\nQJYT8wRJB5xrpb8Gp9WJ3ivSJUKecfUrx/t5ABoLihU6g5a01xqjUzBRMB0GA1Ud\nDgQWBBRLDw9lvjbFwf8EVrrNPbuqx0F4hTAfBgNVHSMEGDAWgBRLDw9lvjbFwf8E\nVrrNPbuqx0F4hTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBGi\nSxI25ek6TMsn9qbHXjo6zsaEggo4Trl2UcNxx4obAiEA7D/adTkpQAambjZr/GEv\n3szZWVRFwOqP6f4Iq3S89i8=\n-----END CERTIFICATE-----";
const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgC2pGDY0ZIGMQWFHg\nLCe8vS59NebOjL0n69B7ThNghzuhRANCAARZnvMH3hWt5eo+t7T5G81e9B3bQ8W9\nSlX4YECWE/MESQeca6W/BqfVid4r0iVCnnH1K8f7eQAaC4oVOoOWtNca\n-----END PRIVATE KEY-----";
const BOUNDARY: &str = "XTLSORACLEBOUNDARY";
const KEYS: &str = "key LIKE 'tls%' OR key LIKE 'outbound\\_tls%'";

/// The certificate cache directory of a case (same path in Go's container and Rust).
pub fn dir(a: &Account) -> PathBuf {
    std::env::temp_dir().join(format!("gofree-mailsec4-tls-{}", a.user))
}

/// Process environment and mounts Go needs to see the same directory.
pub fn go_env(a: &Account) -> Vec<(&'static str, String)> {
    let path = dir(a).display().to_string();
    vec![
        ("TLS_AUTOCERT_CACHE_DIR", path.clone()),
        ("--volume", format!("{path}:{path}")),
    ]
}

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "status" => ("GET", "/admin/tls/status"),
        "config-get" => ("GET", "/admin/tls/config"),
        "config-put" => ("PUT", "/admin/tls/config"),
        "import-cert" => ("POST", "/admin/tls/import-cert"),
        "policy-get" => ("GET", "/admin/outbound-tls-policy"),
        "policy-put" => ("PUT", "/admin/outbound-tls-policy"),
        _ => panic!("unknown tls action {action}"),
    }
}

pub fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "config-put" | "import-cert" | "policy-put" => vec!["security.write"],
        _ => vec!["mail.pipeline"],
    }
}

pub fn wanted(action: &str, label: &str) -> Option<u16> {
    Some(match (action, label) {
        (_, "denied") => 403,
        (
            "config-put",
            "invalid-json" | "array-body" | "string-body" | "number-body" | "invalid-number",
        ) => 400,
        ("config-put", "sentinel-absent" | "secret") => 500,
        (
            "import-cert",
            "not-multipart" | "no-boundary" | "missing-cert" | "missing-key" | "no-filename"
            | "too-large" | "swapped",
        ) => 400,
        ("import-cert", "dir-blocked" | "key-blocked") => 500,
        (
            "policy-put",
            "invalid-json" | "trailing" | "array-body" | "missing-enforce" | "null-enforce"
            | "null-mode" | "missing-skip" | "missing-mode" | "bad-mode" | "bad-mode-quote"
            | "enforce-wrong-type" | "mode-number",
        ) => 400,
        ("config-put" | "policy-put", _) => 204,
        _ => 200,
    })
}

async fn insert(
    owner: &tokio_postgres::Client,
    key: &str,
    value: &str,
    encrypted: bool,
) -> Result<(), BoxError> {
    owner
        .execute(
            "INSERT INTO system_config(key,value,encrypted,description) VALUES($1,$2::text::jsonb,$3,'oracle seed') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=EXCLUDED.encrypted",
            &[&key, &value, &encrypted],
        )
        .await?;
    Ok(())
}

async fn codec(
    owner: &tokio_postgres::Client,
) -> Result<setjoin_config_secret::ConfigSecretCodec, BoxError> {
    let deployment: String = owner
        .query_one(
            "SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'",
            &[],
        )
        .await?
        .get(0);
    let keyring = setjoin_config_secret::keyring_from_lookup(&deployment, |name| {
        (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
    })
    .map_err(|e| e.to_string())?;
    Ok(setjoin_config_secret::ConfigSecretCodec::new(keyring).map_err(|e| e.to_string())?)
}

fn cache_file(dir: &std::path::Path, domain: &str) -> PathBuf {
    let digest: String = Sha256::digest(domain.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    dir.join(digest)
}

pub async fn seed(
    owner: &tokio_postgres::Client,
    a: &Account,
    _b: &Account,
    action: &str,
    label: &str,
) -> Result<Seed, BoxError> {
    let stash: Vec<String> = owner
        .query(
            &format!("SELECT to_jsonb(s)::text FROM system_config s WHERE {KEYS}"),
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM system_config WHERE {KEYS}; COMMIT;"))
        .await?;
    let dir = dir(a);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let dir_text = serde_json::to_string(&dir.display().to_string())?;
    let baseline = !matches!(
        (action, label),
        ("config-get", "empty") | ("policy-get", _) | ("policy-put", _)
    );
    if baseline {
        insert(owner, "tls_auto_renew", "true", false).await?;
        insert(owner, "tls_autocert_challenge", "\"tls-alpn-01\"", false).await?;
        insert(owner, "tls_autocert_domains", "\"\"", false).await?;
        insert(owner, "tls_autocert_email", "\"\"", false).await?;
        insert(owner, "tls_mode", "\"none\"", false).await?;
    }
    match (action, label) {
        ("status", l)
            if matches!(
                l,
                "enabled-nocert"
                    | "enabled-cert"
                    | "cert-garbage"
                    | "cert-wrong-block"
                    | "cert-after-junk"
                    | "no-cache-dir"
                    | "challenge-only"
                    | "typed-values"
            ) || l.starts_with("cert-strict-") =>
        {
            let set = |key: &'static str, value: String| async move {
                insert(owner, key, &value, false).await
            };
            match l {
                "challenge-only" => set("tls_autocert_challenge", "\"http-01\"".into()).await?,
                "typed-values" => {
                    set("tls_autocert_challenge", "5".into()).await?;
                    set("tls_autocert_domains", "[\"x\"]".into()).await?;
                    set("tls_autocert_cache_dir", dir_text.clone()).await?;
                }
                _ => {
                    set("tls_autocert_challenge", "\"http-01\"".into()).await?;
                    set("tls_autocert_domains", "\"a.test, b.test\"".into()).await?;
                    set("tls_autocert_email", "\"ops@a.test\"".into()).await?;
                    set("tls_dns_provider", "\"cloudflare\"".into()).await?;
                    if l != "no-cache-dir" {
                        set("tls_autocert_cache_dir", dir_text.clone()).await?;
                    }
                    match l {
                        "enabled-cert" => std::fs::write(cache_file(&dir, "a.test"), CERT)?,
                        l if l.starts_with("cert-strict-") => std::fs::write(cache_file(&dir, "a.test"), super::certificates::pem(&l[12..]))?,
                        "cert-garbage" => {
                            std::fs::write(cache_file(&dir, "a.test"), "not a certificate")?
                        }
                        "cert-wrong-block" => std::fs::write(cache_file(&dir, "a.test"), KEY)?,
                        "cert-after-junk" => {
                            std::fs::write(cache_file(&dir, "a.test"), format!("junk\n{CERT}\n"))?
                        }
                        _ => {}
                    }
                }
            }
        }
        ("config-get", l) if matches!(l, "success" | "ignored-query") => {
            let envelope = r#"{"format":"x","ciphertext":"abc"}"#;
            insert(owner, "tls_secret_enc", envelope, true).await?;
            insert(owner, "tls_plain_enc", "\"visible-by-suffix\"", false).await?;
            insert(owner, "tls_flagged", "\"visible-by-flag\"", true).await?;
            insert(owner, "tls_num", "5", false).await?;
            insert(owner, "tls_obj", r#"{"a":1,"b":[1,2]}"#, false).await?;
            insert(owner, "tls_null", "null", false).await?;
            insert(
                owner,
                "tls_text",
                "\"hello <b> & \\u2028 \\\"q\\\"\"",
                false,
            )
            .await?;
            insert(owner, "tls_empty", "\"\"", false).await?;
            insert(owner, "tlsx_wild", "\"wildcard\"", false).await?;
            insert(owner, "not_tls_key", "\"outside\"", false).await?;
        }
        ("config-put", l) => {
            if matches!(l, "overwrite") {
                insert(owner, "tls_a", "\"old\"", false).await?;
                insert(owner, "tls_keep", "\"kept\"", false).await?;
            }
            if l == "sentinel-preserve" || l == "sentinel-mixed" {
                let sealed = codec(owner)
                    .await?
                    .encrypt("tls_dns_token_enc", b"\"old-secret\"")
                    .map_err(|e| e.to_string())?;
                insert(
                    owner,
                    "tls_dns_token_enc",
                    &String::from_utf8(sealed)?,
                    true,
                )
                .await?;
            }
        }
        ("import-cert", l) => {
            let imported = dir.join("imported");
            match l {
                "existing" => {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::create_dir_all(&imported)?;
                    for name in ["custom.cert.pem", "custom.key.pem"] {
                        std::fs::write(
                            imported.join(name),
                            "OLD CONTENT THAT IS LONGER THAN THE NEW ONE ".repeat(80),
                        )?;
                        std::fs::set_permissions(
                            imported.join(name),
                            std::fs::Permissions::from_mode(0o644),
                        )?;
                    }
                }
                "dir-blocked" => std::fs::write(&imported, "a file where the directory belongs")?,
                "key-blocked" => {
                    std::fs::create_dir_all(imported.join("custom.key.pem"))?;
                }
                _ => {}
            }
        }
        ("policy-get", l) => match l {
            "set" => {
                insert(
                    owner,
                    "outbound_tls_enforce_domains",
                    r#"["a.test","b.test"]"#,
                    false,
                )
                .await?;
                insert(owner, "outbound_tls_skip_domains", r#"["c.test"]"#, false).await?;
                insert(owner, "outbound_tls_global_mode", "\"enforce\"", false).await?;
            }
            "bad-types" => {
                insert(owner, "outbound_tls_enforce_domains", "\"x\"", false).await?;
                insert(
                    owner,
                    "outbound_tls_skip_domains",
                    r#"["a",1,null,["b"],"c"]"#,
                    false,
                )
                .await?;
                insert(owner, "outbound_tls_global_mode", "5", false).await?;
            }
            "null-values" => {
                insert(owner, "outbound_tls_enforce_domains", "null", false).await?;
                insert(owner, "outbound_tls_skip_domains", "null", false).await?;
                insert(owner, "outbound_tls_global_mode", "null", false).await?;
            }
            "empty-mode" => insert(owner, "outbound_tls_global_mode", "\"\"", false).await?,
            "html" => {
                insert(
                    owner,
                    "outbound_tls_enforce_domains",
                    r#"["a&b<c>.test"]"#,
                    false,
                )
                .await?;
                insert(
                    owner,
                    "outbound_tls_global_mode",
                    "\"opportunistic\"",
                    false,
                )
                .await?;
            }
            "partial" => {
                insert(
                    owner,
                    "outbound_tls_skip_domains",
                    r#"["only-skip.test"]"#,
                    false,
                )
                .await?
            }
            _ => {}
        },
        ("policy-put", "overwrite") => {
            insert(
                owner,
                "outbound_tls_enforce_domains",
                r#"["old.test"]"#,
                false,
            )
            .await?;
            insert(
                owner,
                "outbound_tls_skip_domains",
                r#"["old-skip.test"]"#,
                false,
            )
            .await?;
            insert(owner, "outbound_tls_global_mode", "\"enforce\"", false).await?;
        }
        _ => {}
    }
    Ok(Seed {
        stash,
        names: vec![],
        vars: Default::default(),
    })
}

pub async fn teardown(
    owner: &tokio_postgres::Client,
    a: &Account,
    seed: &Seed,
) -> Result<(), BoxError> {
    owner
        .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM system_config WHERE {KEYS} OR key = 'not_tls_key';"))
        .await?;
    for row in &seed.stash {
        owner
            .execute("INSERT INTO system_config SELECT * FROM jsonb_populate_record(NULL::system_config, $1::text::jsonb)", &[row])
            .await?;
    }
    owner.batch_execute("COMMIT;").await?;
    // The imported files were written as root by the Go container; the directory tree is ours.
    let _ = std::fs::remove_dir_all(dir(a));
    Ok(())
}

fn multipart(parts: &[(&str, Option<&str>, &str)]) -> String {
    let mut out = String::new();
    for (name, file, content) in parts {
        out += &format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"");
        if let Some(file) = file {
            out += &format!("; filename=\"{file}\"");
        }
        out += &format!("\r\n\r\n{content}\r\n");
    }
    out + &format!("--{BOUNDARY}--\r\n")
}

pub fn request(action: &str, label: &str, _seed: &Seed) -> Req {
    let (_, pattern) = route(action);
    let mut headers: Vec<(String, String)> = vec![];
    let mut recorded_body = String::new();
    let body = match (action, label) {
        ("config-put", l) => match l {
            "success" | "repeat" => r#"{"tls_a":"x","tls_b":5,"tls_c":true,"tls_d":null,"tls_e":{"z":1,"a":[1.5e300,"<&>"]},"tls_big":12345678901234567890,"tls_exp":1e21,"tls_small":1e-7,"tls_neg":-0.5,"other":"ignored"}"#.into(),
            "overwrite" => r#"{"tls_a":"new","tls_added":1}"#.into(),
            "secret" => r#"{"tls_dns_token_enc":"s3cret","tls_obj_enc":{"k":"v"},"tls_plain":"visible"}"#.into(),
            "sentinel-preserve" => r#"{"tls_dns_token_enc":"[ENCRYPTED]"}"#.into(),
            "sentinel-mixed" => r#"{"tls_dns_token_enc":"[ENCRYPTED]","tls_other":"value"}"#.into(),
            "sentinel-absent" => r#"{"tls_never_set_enc":"[ENCRYPTED]"}"#.into(),
            "non-tls-only" => r#"{"other":1,"x_tls":2,"TLS_upper":3}"#.into(),
            "null-body" => "null".into(),
            "empty-object" => "{}".into(),
            "invalid-json" => "{".into(),
            "array-body" => r#"["tls_a"]"#.into(),
            "string-body" => r#""tls_a""#.into(),
            "number-body" => "5".into(),
            "invalid-number" => r#"{"tls_n":1e999}"#.into(),
            "trailing" => r#"{"tls_t":"v"} {"tls_u":"w"} garbage"#.into(),
            "duplicate-keys" => r#"{"tls_d":"1","tls_d":"2"}"#.into(),
            "escape" => "{\"tls_<k>&\":\"<v>&\\u2028 \\u00e9 \\\"q\\\"\"}".into(),
            _ => "{\"tls_default\":\"v\"}".into(),
        },
        ("policy-put", l) => match l {
            "success" | "repeat" | "overwrite" => r#"{"enforce_domains":["a.test","b.test"],"skip_domains":["c.test"],"global_mode":"enforce"}"#.into(),
            "opportunistic" => r#"{"enforce_domains":[],"skip_domains":[],"global_mode":"opportunistic"}"#.into(),
            "html-escape" => r#"{"enforce_domains":["a&b<c>.test","caf\u00e9.test"],"skip_domains":[],"global_mode":"enforce"}"#.into(),
            "invalid-json" => "{".into(),
            "trailing" => r#"{"enforce_domains":[],"skip_domains":[],"global_mode":"enforce"} {}"#.into(),
            "array-body" => "[]".into(),
            "missing-enforce" => r#"{"skip_domains":[],"global_mode":"enforce"}"#.into(),
            "null-enforce" => r#"{"enforce_domains":null,"skip_domains":[],"global_mode":"enforce"}"#.into(),
            "missing-skip" => r#"{"enforce_domains":[],"global_mode":"enforce"}"#.into(),
            "missing-mode" => r#"{"enforce_domains":[],"skip_domains":[]}"#.into(),
            "bad-mode" => r#"{"enforce_domains":[],"skip_domains":[],"global_mode":"strict"}"#.into(),
            "bad-mode-quote" => "{\"enforce_domains\":[],\"skip_domains\":[],\"global_mode\":\"x\\\"\\t\\u00e9\\u0001\"}".into(),
            "enforce-wrong-type" => r#"{"enforce_domains":"a.test","skip_domains":[],"global_mode":"enforce"}"#.into(),
            "mode-number" => r#"{"enforce_domains":[],"skip_domains":[],"global_mode":5}"#.into(),
            "key-case" => r#"{"ENFORCE_DOMAINS":["a.test"],"Skip_Domains":[],"GLOBAL_MODE":"enforce","extra":1}"#.into(),
            "null-elements" => r#"{"enforce_domains":[null,"a.test"],"skip_domains":[null],"global_mode":"enforce"}"#.into(),
            "null-mode" => r#"{"enforce_domains":[],"skip_domains":[],"global_mode":null}"#.into(),
            _ => r#"{"enforce_domains":[],"skip_domains":[],"global_mode":"enforce"}"#.into(),
        },
        ("import-cert", l) => {
            let ct = format!("multipart/form-data; boundary={BOUNDARY}");
            match l {
                "not-multipart" => "{}".to_string(),
                "no-boundary" => {
                    headers.push(("content-type".into(), "multipart/form-data".into()));
                    "x".into()
                }
                "missing-cert" => {
                    headers.push(("content-type".into(), ct));
                    multipart(&[("key", Some("k.pem"), KEY)])
                }
                "missing-key" => {
                    headers.push(("content-type".into(), ct));
                    multipart(&[("cert", Some("c.pem"), CERT)])
                }
                "no-filename" => {
                    headers.push(("content-type".into(), ct));
                    multipart(&[("cert", None, CERT), ("key", Some("k.pem"), KEY)])
                }
                "swapped" => {
                    headers.push(("content-type".into(), ct));
                    multipart(&[("file", Some("c.pem"), CERT), ("other", Some("k.pem"), KEY)])
                }
                "duplicate-cert" => {
                    headers.push(("content-type".into(), ct));
                    multipart(&[("cert", Some("one.pem"), "FIRST CERT"), ("cert", Some("two.pem"), "SECOND CERT"), ("key", Some("k.pem"), KEY)])
                }
                "too-large" => {
                    headers.push(("content-type".into(), ct));
                    recorded_body = "<11 MiB multipart body>".into();
                    multipart(&[("cert", Some("c.pem"), &"A".repeat(11 << 20)), ("key", Some("k.pem"), KEY)])
                }
                "empty-files" => {
                    headers.push(("content-type".into(), ct));
                    multipart(&[("cert", Some("c.pem"), ""), ("key", Some("k.pem"), "")])
                }
                _ => {
                    headers.push(("content-type".into(), ct));
                    multipart(&[("cert", Some("c.pem"), CERT), ("key", Some("k.pem"), KEY)])
                }
            }
        }
        _ => String::new(),
    };
    let query = if label == "ignored-query" {
        "?limit=-1&x=%zz"
    } else {
        ""
    };
    Req {
        path: pattern.to_string(),
        query: query.to_string(),
        recorded_query: String::new(),
        recorded_body,
        body,
        headers,
    }
}

pub async fn snapshot(
    owner: &tokio_postgres::Client,
    a: &Account,
    _b: &Account,
    _seed: &Seed,
) -> Result<Value, BoxError> {
    let codec = codec(owner).await?;
    let mut config = vec![];
    for row in owner
        .query(
            &format!("SELECT key, value::text, encrypted, description FROM system_config WHERE {KEYS} ORDER BY key"),
            &[],
        )
        .await?
    {
        let key: String = row.get(0);
        let text: String = row.get(1);
        let encrypted: bool = row.get(2);
        // A sealed value carries a random nonce: compare what it opens to instead.
        let value = if setjoin_config_secret::is_config_secret_envelope(text.as_bytes()) {
            match codec.decrypt(&key, text.as_bytes()) {
                Ok(plain) => json!({"sealed": String::from_utf8_lossy(&plain)}),
                Err(error) => json!({"sealed": "unopenable", "error": error.to_string()}),
            }
        } else {
            serde_json::from_str(&text)?
        };
        config.push(json!({"key":key,"value":value,"encrypted":encrypted,"description":row.get::<_, Option<String>>(3)}));
    }
    let imported = dir(a).join("imported");
    let mut files = vec![];
    if let Ok(meta) = std::fs::metadata(&imported) {
        use std::os::unix::fs::PermissionsExt;
        files.push(json!({"name":".","kind":if meta.is_dir() {"dir"} else {"file"},"mode":format!("{:o}", meta.permissions().mode() & 0o7777)}));
        if meta.is_dir() {
            let mut names: Vec<_> = std::fs::read_dir(&imported)?
                .filter_map(Result::ok)
                .collect();
            names.sort_by_key(|e| e.file_name());
            for entry in names {
                let meta = entry.metadata()?;
                let content = if meta.is_file() {
                    let bytes = std::fs::read(entry.path())?;
                    json!({"sha256":Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>(),"bytes":bytes.len()})
                } else {
                    json!({"kind":"dir"})
                };
                files.push(json!({"name":entry.file_name().to_string_lossy(),"mode":format!("{:o}", meta.permissions().mode() & 0o7777),"content":content}));
            }
        }
    }
    Ok(json!({"config":config,"files":files}))
}
