//! Source document, secret and dry-run cases of the `idv2-sources` write oracle.
use super::write::{Ctx, Plan};
use super::{ALPHA_KEY, BETA_KEY, GAMMA_KEY};
use crate::common::BoxError;
use serde_json::json;

const IDEM: &str = "95300000-0000-4000-8000-000000000001";
const IDEM_OTHER: &str = "95300000-0000-4000-8000-000000000002";
const REASON: &str = "admin7 reason <&>";
const NEW_KEY: &str = "admin7-new";
const DELTA_KEY: &str = "admin7-probead";
pub const PROBE_BASE: &str = "DC=probe,DC=example,DC=test";
/// Port of the fake directory a `probe-*` dry run points its source at (#400).
pub static PROBE_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

/// Dry runs of an AD or LDAP source whose secrets are set probe the directory.
pub fn is_probe(action: &str, label: &str) -> bool {
    action == "dry-run" && label.starts_with("probe-")
}

pub fn is_write(action: &str) -> bool {
    matches!(
        action,
        "create" | "put" | "plan" | "secret-set" | "secret-rotate" | "dry-run" | "mappings-put"
    )
}

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "create" => ("POST", "/admin/identity/v2/sources"),
        "put" => ("PUT", "/admin/identity/v2/sources/{sourceKey}"),
        "plan" => ("POST", "/admin/identity/v2/sources/plan"),
        "secret-set" => (
            "PUT",
            "/admin/identity/v2/sources/{sourceKey}/secrets/{name}",
        ),
        "secret-rotate" => (
            "POST",
            "/admin/identity/v2/sources/{sourceKey}/secrets/{name}/rotate",
        ),
        "dry-run" => ("POST", "/admin/identity/v2/sources/{sourceKey}/dry-run"),
        "mappings-put" => ("PUT", "/admin/identity/group-mappings/{type}/{id}"),
        _ => panic!("unknown idv2 source action {action}"),
    }
}

fn doc(key: &str, name: &str, spec: serde_json::Value) -> serde_json::Value {
    json!({"apiVersion": "setjoin.io/v1", "kind": "IdentitySource", "metadata": {"sourceKey": key, "displayName": name}, "spec": spec})
}

const LDAP_SPEC: &str = r#"{"type":"ldap","baseDN":"dc=example,dc=test","subjectAttribute":"entryUUID","endpoint":{"host":"ldap.test","port":636,"tls":"ldaps"}}"#;

/// Seals the stored documents the cases start from (what Go's apply would have stored).
pub async fn seal_fixtures(
    owner: &tokio_postgres::Client,
    codec: &setjoin_config_secret::ConfigSecretCodec,
    action: &str,
    label: &str,
) -> Result<(), BoxError> {
    if !is_write(action) {
        return Ok(());
    }
    let gamma_secret = matches!((action, label), ("dry-run", "success" | "repeat"));
    let gamma_doc = if label == "invalid-doc" {
        r#"{"apiVersion":"setjoin.io/v1"}"#.to_owned()
    } else {
        r#"{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"admin7-gamma","displayName":"Admin7 Gamma"},"spec":{"type":"scim"}}"#.to_owned()
    };
    let probe = is_probe(action, label);
    let port = PROBE_PORT.load(std::sync::atomic::Ordering::SeqCst);
    let secret_text = if label == "probe-bad-secret" {
        "!!!"
    } else {
        "c2VjcmV0"
    };
    let source_spec = |kind: &str, subject: &str| {
        format!(
            r#"{{"type":"{kind}","baseDN":"{PROBE_BASE}","subjectAttribute":"{subject}","bindDN":"CN=svc,{PROBE_BASE}","endpoint":{{"host":"127.0.0.1","port":{port},"tls":"ldaps"}}}}"#
        )
    };
    let beta_spec = if probe {
        source_spec("ldap", "entryUUID")
    } else {
        LDAP_SPEC.to_owned()
    };
    if probe {
        // A draft LDAP source at generation 1 (what a fresh source looks like) and an AD twin.
        owner.batch_execute("UPDATE identity_sources SET state='draft',generation=1,last_failure_at=NULL,last_error_code=NULL WHERE source_key='admin7-beta'").await?;
        owner
            .execute(
                "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,generation,mapping_version) \
                 VALUES($1,'Admin7 Probe AD','ad','{\"authenticate\": true, \"provision_lifecycle\": false, \"stable_immutable_subject\": true}'::jsonb,'draft',1,2)",
                &[&DELTA_KEY],
            )
            .await?;
    }
    let delta_spec = source_spec("ad", "objectGUID");
    let gamma_secrets = if gamma_secret {
        r#"{"bearerToken":"dG9r"}"#
    } else {
        "{}"
    };
    for (key, plain) in [
        (ALPHA_KEY, r#"{"document":{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"admin7-alpha","displayName":"Admin7 Alpha <&>"},"spec":{"type":"local"}},"secrets":{}}"#.to_owned()),
        (BETA_KEY, format!(r#"{{"document":{{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{{"sourceKey":"admin7-beta","displayName":"Admin7 Beta"}},"spec":{beta_spec}}},"secrets":{{"bindPassword":"{secret_text}"}}}}"#)),
        (GAMMA_KEY, format!(r#"{{"document":{gamma_doc},"secrets":{gamma_secrets}}}"#)),
    ] {
        let sealed = codec.encrypt(&format!("identity_source.{key}"), plain.as_bytes())?;
        owner
            .execute("UPDATE identity_sources SET config_envelope=$2,config_key_version=1 WHERE source_key=$1", &[&key, &sealed])
            .await?;
    }
    if probe {
        let plain = format!(
            r#"{{"document":{{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{{"sourceKey":"{DELTA_KEY}","displayName":"Admin7 Probe AD"}},"spec":{delta_spec}}},"secrets":{{"bindPassword":"{secret_text}"}}}}"#
        );
        let sealed = codec.encrypt(&format!("identity_source.{DELTA_KEY}"), plain.as_bytes())?;
        owner
            .execute("UPDATE identity_sources SET config_envelope=$2,config_key_version=1 WHERE source_key=$1", &[&DELTA_KEY, &sealed])
            .await?;
    }
    Ok(())
}

/// Group-mapping fixtures: one SAML registration and one OIDC provider.
pub async fn mapping_fixtures(
    owner: &tokio_postgres::Client,
    action: &str,
) -> Result<(), BoxError> {
    if action != "mappings-put" {
        return Ok(());
    }
    owner
        .batch_execute(
            "INSERT INTO saml_sp_registrations(idp_entity_id,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings,enabled) VALUES \
             ('admin7-idp-a','https://idp.test/sso','\\x00'::bytea,'sp-a','https://sp.test/acs','[{\"idp_group\": \"old\"}]'::jsonb,true); \
             INSERT INTO system_config(key,value) VALUES ('oidc_provider_admin7a_config','{\"name\": \"admin7-oidc-a\", \"client_id\": \"c1\", \"scopes\": [\"openid\"]}'::jsonb) ON CONFLICT (key) DO NOTHING;",
        )
        .await?;
    Ok(())
}

fn mappings_plan(c: &Ctx<'_>) -> Plan {
    let label = c.label;
    let mut headers: Vec<(String, String)> = vec![
        ("content-type".into(), "application/json".into()),
        ("x-audit-reason".into(), REASON.into()),
    ];
    let (mut kind, mut id) = ("saml".to_string(), "admin7-idp-a".to_string());
    let mut body = r#"[{"idp_group":"eng","distribution_group_id":5,"department_id":9},{"IDP_GROUP":"ops <&>"}]"#.to_string();
    let mut wanted = 204;
    let mut repeat = false;
    match label {
        "repeat" => repeat = true,
        "oidc" => {
            kind = "oidc".into();
            id = "admin7a".into()
        }
        "with-role" => body = r#"[{"idp_group":"audit","admin_role":"auditor"}]"#.into(),
        "role-no-manage" => {
            body = r#"[{"idp_group":"audit","admin_role":"auditor"}]"#.into();
            wanted = 403
        }
        "role-perm-missing" => {
            body = r#"[{"idp_group":"audit","admin_role":"read_only"}]"#.into();
            wanted = 403
        }
        "unknown-role" => {
            body = r#"[{"idp_group":"audit","admin_role":"root"}]"#.into();
            wanted = 400
        }
        "invalid-type" => {
            kind = "ldap".into();
            wanted = 400
        }
        "oidc-missing" => {
            kind = "oidc".into();
            id = "admin7zz".into();
            wanted = 404
        }
        "saml-missing" => id = "admin7-nothing".into(),
        "bad-json" => {
            body = "[{\"idp_group\":".into();
            wanted = 400
        }
        "null-body" => body = "null".into(),
        "not-array" => {
            body = r#"{"idp_group":"eng"}"#.into();
            wanted = 400
        }
        "bad-type" => {
            body = r#"[{"idp_group":7}]"#.into();
            wanted = 400
        }
        "empty-group" => {
            body = r#"[{"idp_group":"  "}]"#.into();
            wanted = 400
        }
        "control-char" => {
            body = "[{\"idp_group\":\"a\\u0001b\"}]".into();
            wanted = 400
        }
        "long-group" => {
            body = format!("[{{\"idp_group\":\"{}\"}}]", "g".repeat(1025));
            wanted = 400
        }
        "too-many" => {
            body = format!("[{}]", vec!["{\"idp_group\":\"g\"}"; 101].join(","));
            wanted = 400
        }
        "trailing" => body = r#"[{"idp_group":"eng"}] garbage"#.into(),
        "scoped" | "denied" => wanted = 403,
        _ => {}
    }
    let shown = if label == "long-group" {
        "[{\"idp_group\":\"<1025 g>\"}]".to_string()
    } else if label == "too-many" {
        "[101 x {\"idp_group\":\"g\"}]".to_string()
    } else {
        body.clone()
    };
    headers.retain(|_| true);
    let path = "/admin/identity/group-mappings/{type}/{id}"
        .replace("{type}", &kind)
        .replace("{id}", &id);
    Plan {
        method: "PUT",
        path,
        headers,
        body,
        shown_body: shown,
        repeat,
        repeat_headers: vec![],
        wanted,
    }
}

pub fn plan(c: &Ctx<'_>) -> Plan {
    if c.action == "mappings-put" {
        return mappings_plan(c);
    }
    let (action, label) = (c.action, c.label);
    let (method, pattern) = route(action);
    let mut headers: Vec<(String, String)> = vec![
        ("content-type".into(), "application/json".into()),
        ("x-audit-reason".into(), REASON.into()),
        ("idempotency-key".into(), IDEM.into()),
    ];
    let mut wanted = 200;
    let mut repeat = false;
    let mut repeat_headers: Vec<(String, String)> = vec![];
    let mut key = match action {
        "create" | "plan" => NEW_KEY.to_string(),
        "put" => GAMMA_KEY.to_string(),
        "secret-set" | "secret-rotate" => BETA_KEY.to_string(),
        "dry-run" if label == "probe-ad" => DELTA_KEY.to_string(),
        "dry-run" if label.starts_with("probe-") => BETA_KEY.to_string(),
        _ => GAMMA_KEY.to_string(),
    };
    let mut name = "bindPassword".to_string();
    // The document a create/put/plan carries, and its generation header.
    let mut document = match (action, label) {
        ("create", "ad") => doc(&key, "Admin7 New", serde_json::from_str(r#"{"type":"ad","baseDN":"dc=x","subjectAttribute":"objectGUID","endpoint":{"host":"h","port":636,"tls":"ldaps"}}"#).unwrap()),
        ("create", "exists") => doc(GAMMA_KEY, "Admin7 Gamma", json!({"type": "scim"})),
        ("put" | "plan", "unchanged") => doc(ALPHA_KEY, "Admin7 Alpha <&>", json!({"type": "local"})),
        ("plan", "changed") => doc(ALPHA_KEY, "Admin7 Alpha <&>", json!({"type": "local", "passwordPolicy": {"minLength": 12}})),
        ("put", "not-draft") => doc(ALPHA_KEY, "Admin7 Alpha <&>", json!({"type": "local", "passwordPolicy": {"minLength": 12}})),
        ("put", _) => doc(GAMMA_KEY, "Admin7 Gamma \u{e9}", json!({"type": "scim", "deletionPolicy": "suspend"})),
        (_, _) => doc(&key, "Admin7 New", json!({"type": "scim"})),
    };
    match label {
        "bad-api-version" => document["apiVersion"] = json!("v2"),
        "bad-metadata" => document["metadata"]["sourceKey"] = json!("-bad"),
        "spec-no-type" => document["spec"] = json!({"baseDN": "x"}),
        "spec-unknown-field" => document["spec"] = json!({"type": "scim", "endpoint": {}}),
        "unknown-type" => document["spec"] = json!({"type": "ftp"}),
        "bad-endpoint" => document["spec"] = serde_json::from_str(r#"{"type":"ad","baseDN":"dc=x","subjectAttribute":"objectGUID","endpoint":{"host":"h","port":0,"tls":"ldaps"}}"#).unwrap(),
        "bad-ad-subject" => document["spec"] = serde_json::from_str(r#"{"type":"ad","baseDN":"dc=x","subjectAttribute":"cn","endpoint":{"host":"h","port":636,"tls":"ldaps"}}"#).unwrap(),
        "bad-capability" => document["spec"] = json!({"type": "scim", "capabilities": {"fly": true}}),
        "unknown-field-doc" => document["extra"] = json!(1),
        // Decode errors whose text is Go's `encoding/json` wording (#412).
        "doc-string" => document = json!("x"),
        "doc-array" => document = json!([1]),
        "doc-number" => document = json!(5),
        "doc-bool" => document = json!(true),
        "doc-api-type" => document["apiVersion"] = json!(5),
        "doc-kind-type" => document["kind"] = json!(true),
        "doc-kind-object" => document["kind"] = json!({"a": 1}),
        "doc-metadata-string" => document["metadata"] = json!("x"),
        "doc-metadata-array" => document["metadata"] = json!([1]),
        "doc-key-type" => document["metadata"]["sourceKey"] = json!(7),
        "doc-display-type" => document["metadata"]["displayName"] = json!([1]),
        "doc-type-before-unknown" => {
            document["apiVersion"] = json!(5);
            document["extra"] = json!(1);
        }
        "doc-unknown-before-type" => {
            document["aaa"] = json!(1);
            document["apiVersion"] = json!(5);
        }
        "doc-metadata-unknown-before-type" => {
            document["metadata"] = serde_json::from_str(r#"{"bogus":1,"sourceKey":7}"#).unwrap()
        }
        "doc-metadata-type-before-unknown" => {
            document["metadata"] = serde_json::from_str(r#"{"sourceKey":7,"bogus":1}"#).unwrap()
        }
        "path-mismatch" => key = "admin7-other-key".to_string(),
        _ => {}
    }
    let document_text = document.to_string();
    let generation = match (action, label) {
        ("put", "stale") | ("secret-set" | "secret-rotate" | "dry-run", "stale") => "9".to_string(),
        ("put", "not-draft") => "3".to_string(),
        ("put", "unchanged") => "3".to_string(),
        ("secret-set" | "secret-rotate", _) => "5".to_string(),
        _ => "1".to_string(),
    };
    let mut body = match action {
        "create" | "put" => {
            json!({"document": document, "reason": REASON, "idempotencyKey": IDEM}).to_string()
        }
        "plan" => document_text.clone(),
        "dry-run" => {
            json!({"expectedGeneration": generation, "idempotencyKey": IDEM, "reason": REASON})
                .to_string()
        }
        _ => "new-secret".to_string(),
    };
    if matches!(action, "put" | "secret-set" | "secret-rotate" | "dry-run")
        || (action == "create" && label == "exists")
    {
        headers.push(("if-match".into(), format!("\"{generation}\"")));
    }
    if matches!(action, "secret-set" | "secret-rotate") {
        headers.retain(|(k, _)| k != "content-type");
        headers.push(("content-type".into(), "application/octet-stream".into()));
        headers.push(("x-identity-reason".into(), REASON.into()));
    }
    if action == "plan" {
        headers.retain(|(k, _)| matches!(k.as_str(), "content-type"));
    }
    if action == "create" {
        wanted = 201;
    }
    let mut shown = body.clone();
    match label {
        "repeat" => {
            repeat = true;
            if action == "create" {
                repeat_headers.push(("if-match".into(), "\"1\"".into()));
            }
        }
        "scoped" | "denied" => wanted = 403,
        "bad-json" => {
            body = "{\"document\":".into();
            shown = body.clone();
            wanted = 400
        }
        "unknown-field" => {
            body = body.replacen('{', "{\"extra\":1,", 1);
            shown = body.clone();
            wanted = 400
        }
        "doc-null" => {
            body = if action == "plan" {
                "null".into()
            } else {
                json!({"document": null, "reason": REASON, "idempotencyKey": IDEM}).to_string()
            };
            shown = body.clone();
            wanted = 400;
        }
        "doc-missing" => {
            body = json!({"reason": REASON, "idempotencyKey": IDEM}).to_string();
            shown = body.clone();
            wanted = 400
        }
        "bad-api-version" | "bad-metadata" | "spec-no-type" | "spec-unknown-field"
        | "unknown-type" | "bad-endpoint" | "bad-ad-subject" | "bad-capability"
        | "unknown-field-doc" | "path-mismatch" | "doc-string" | "doc-array" | "doc-number"
        | "doc-bool" | "doc-api-type" | "doc-kind-type" | "doc-kind-object"
        | "doc-metadata-string" | "doc-metadata-array" | "doc-key-type" | "doc-display-type"
        | "doc-type-before-unknown" | "doc-unknown-before-type"
        | "doc-metadata-unknown-before-type" | "doc-metadata-type-before-unknown" => {
            wanted = 400
        }
        "if-match-new" => {
            headers.push(("if-match".into(), "\"1\"".into()));
            wanted = 412
        }
        "key-mismatch" => {
            headers.retain(|(k, _)| k != "idempotency-key");
            headers.push(("idempotency-key".into(), IDEM_OTHER.into()));
            wanted = 400
        }
        "bad-idem" => {
            headers.retain(|(k, _)| k != "idempotency-key");
            headers.push(("idempotency-key".into(), "nope".into()));
            wanted = 400
        }
        "reason-mismatch" => {
            headers.retain(|(k, _)| k != "x-audit-reason");
            headers.push(("x-audit-reason".into(), "another".into()));
            wanted = 400
        }
        "oversize" => {
            if matches!(action, "secret-set" | "secret-rotate") {
                body = "x".repeat(70000);
                shown = "<70000 x>".into();
                wanted = 413;
            } else {
                body = json!({"document": document, "reason": "x".repeat(70000), "idempotencyKey": IDEM}).to_string();
                shown =
                    "{\"document\":<doc>,\"reason\":\"<70000 x>\",\"idempotencyKey\":...}".into();
                wanted = 413;
            }
        }
        "stale" => {
            wanted = if matches!(action, "dry-run") {
                412
            } else {
                412
            }
        }
        "no-if-match" => {
            headers.retain(|(k, _)| k != "if-match");
            wanted = 412
        }
        "not-draft" => {
            key = ALPHA_KEY.to_string();
            wanted = 409
        }
        "bad-media" => {
            headers.retain(|(k, _)| k != "content-type");
            headers.push(("content-type".into(), "text/plain".into()));
            wanted = 415
        }
        "bad-name" => {
            name = "nope".into();
            wanted = 400
        }
        "bad-key" => {
            key = "-bad".into();
            wanted = 400
        }
        "missing-source" => {
            key = "admin7-nothing".into();
            wanted = 404
        }
        "empty" => {
            body.clear();
            shown.clear();
            wanted = 400
        }
        "not-configured" => {
            key = GAMMA_KEY.into();
            name = "bearerToken".into();
            wanted = 409
        }
        "set-gamma" => {
            key = GAMMA_KEY.into();
            name = "bearerToken".into();
            wanted = if action == "secret-set" { 202 } else { 409 }
        }
        "blockers" => wanted = 200,
        "invalid-doc" => wanted = 409,
        "success" if matches!(action, "secret-set" | "secret-rotate" | "dry-run") => {
            wanted = if action == "dry-run" { 202 } else { 202 }
        }
        "changed" | "unchanged" | "success" | "exists" | "ad" => {}
        "etag-match" => {}
        _ => {}
    }
    if action == "dry-run" && label == "repeat" {
        // Validation bumps the generation, so the identical second request is stale.
        wanted = 412;
    }
    if action == "dry-run" && label == "success" {
        wanted = 202;
    }
    if is_probe(action, label) && matches!(label, "probe-reachable" | "probe-ad") {
        wanted = 202;
    }
    if action == "dry-run" && label == "blockers" {
        wanted = 200;
    }
    if action == "dry-run" && label == "missing-source" {
        wanted = 404;
    }
    if action == "put" && label == "success" {
        wanted = 200;
    }
    if action == "create" && label == "exists" {
        wanted = 200;
    }
    if matches!(action, "secret-set" | "secret-rotate") && label != "stale" {
        let current = if key == GAMMA_KEY { "1" } else { "5" };
        headers.retain(|(k, _)| k != "if-match");
        if label != "no-if-match" {
            headers.push(("if-match".into(), format!("\"{current}\"")));
        }
    }
    if matches!(action, "secret-set" | "secret-rotate") && label == "repeat" {
        // The first call bumps the generation, so the identical second one is stale.
        wanted = 412;
    }
    if action == "put" && label == "repeat" {
        // The first PUT bumps the generation, so the identical second one is stale.
        wanted = 412;
    }
    if action == "create" && label == "repeat" {
        wanted = 409;
    }
    let path = pattern
        .replace("{sourceKey}", &key)
        .replace("{name}", &name);
    Plan {
        method,
        path,
        headers,
        body,
        shown_body: shown,
        repeat,
        repeat_headers,
        wanted,
    }
}

/// The fake directory behind a `probe-*` case. Its test CA is trusted by this
/// process and, through `GOFREE_ORACLE_EXTRA_ENV`, by the recorded Go process.
pub async fn start_probe_directory(
    label: &str,
) -> Result<Option<setjoin_conformance::ldap_fake::FakeLdap>, BoxError> {
    use setjoin_conformance::ldap_fake::{Entry, FakeLdap, Transport, CA_PEM};
    let ca = std::env::temp_dir().join("setjoin-idv2-probe-ca.pem");
    std::fs::write(&ca, CA_PEM)?;
    std::env::set_var("SSL_CERT_FILE", &ca);
    std::env::set_var(
        "GOFREE_ORACLE_EXTRA_ENV",
        "SSL_CERT_FILE=/src/server-rust/tests/conformance/directory-sync/ldap-fixture/ca.pem",
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    PROBE_PORT.store(
        listener.local_addr()?.port(),
        std::sync::atomic::Ordering::SeqCst,
    );
    if label == "probe-down" {
        return Ok(None);
    }
    let fake = FakeLdap::on(listener, Transport::Ldaps)?;
    fake.set_credentials(
        &format!("CN=svc,{PROBE_BASE}"),
        if label == "probe-bad-password" {
            "other"
        } else {
            "secret"
        },
    );
    let dn = |cn: &str| format!("CN={cn},OU=People,{PROBE_BASE}");
    let guid: Vec<u8> = (1..=16).collect();
    fake.set_entries(vec![
        Entry::new(
            &dn("ann"),
            &[
                ("objectClass", "person"),
                ("cn", "ann"),
                ("mail", "ann@probe.test"),
                ("entryUUID", "u-ann"),
            ],
        ),
        Entry::new(
            &dn("amy"),
            &[
                ("objectClass", "user"),
                ("objectCategory", "person"),
                ("mail", "amy@probe.test"),
                ("uSNChanged", "7"),
            ],
        )
        .with_bin("objectGUID", &guid),
    ]);
    fake.fail_search(label == "probe-search-failure");
    Ok(Some(fake))
}
