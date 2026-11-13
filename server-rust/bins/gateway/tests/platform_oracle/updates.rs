//! F08 slice `updates-deploy` (#300) oracle: a table-driven runner over the shared
//! Platform harness. Each case names one request, its persona, its seed rows and the
//! table whose rows are the observed effect. Record mode runs frozen Go behind the front
//! door; replay serves the same request from Rust with no Go upstream.
use super::{masked, pin_load_values, record, SERIAL};
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    platform_updates::PlatformUpdatesRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct Probe {
    inner: PlatformUpdatesRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
    wrong_schema: bool,
    target_method: &'static str,
    target_path: String,
}
impl Intercept for Probe {
    fn shutdown(&self) {
        self.inner.shutdown();
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let changed = self.changed_status
            && r.method().as_str() == self.target_method
            && r.uri().path() == self.target_path;
        let wrong_schema = self.wrong_schema;
        let future = self.inner.handle(r, c);
        Box::pin(async move {
            let mut response = future.await;
            if wrong_schema {
                assert_eq!(response.status(), hyper::StatusCode::OK, "schema mutant requires the real successful response");
                let headers=response.headers().clone();
                use http_body_util::BodyExt;
                let bytes=response.into_body().collect().await.expect("schema mutant body").to_bytes();
                let mut body:Value=serde_json::from_slice(&bytes).expect("context JSON");
                body["schemaVersion"]=json!(body["schemaVersion"].as_i64().expect("actual schema")+1);
                let body=body.to_string();
                let length=body.len().to_string();
                response=Response::new(common::full(body));
                *response.headers_mut()=headers;
                response.headers_mut().insert("content-length",length.parse().unwrap());
            }
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

/// One request and what it must observe.
pub struct Case {
    pub method: &'static str,
    pub pattern: &'static str,
    /// Values for `{id}` style placeholders, in order.
    pub fill: Vec<String>,
    pub query: String,
    pub perm: &'static str,
    pub body: String,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    /// SQL executed (as the owner) before the request, after Go has started.
    pub seed: Vec<String>,
    pub boot_seed: Vec<String>,
    /// SQL executed afterwards on every path.
    pub cleanup: Vec<String>,
    /// SQL returning one `jsonb::text` row per observed effect row.
    pub effects: &'static str,
    pub table: &'static str,
    pub extra_effects: Vec<(&'static str, String)>,
    pub channels: Vec<&'static str>,
    pub status: u16,
    /// `(from, to)` text substitutions applied to the response body before comparing.
    pub replace: Vec<(String, String)>,
    /// Extra access-token claims (`acr`, `amr`, `iat`).
    pub claims: Value,
}

// Dynamic cryptographic fields are verified at the DB/HTTP seam BEFORE masking.
// This independent protocol-string literal is checked against frozen Go at recording.
fn open_bindings(value: &mut Value, table: &str, bearer: &str, body: &str) -> Result<(), BoxError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(bearer.split('.').nth(1).ok_or("missing JWT payload")?)?,
    )?;
    let at = chrono::DateTime::from_timestamp(claims["iat"].as_i64().ok_or("invalid iat")?, 0)
        .ok_or("invalid JWT time")?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let message = format!(
        "setjoin-mail-recovery-step-up-v1\n{}\n{}\n{at}\n455abcde-abcd-4abc-8abc-000000000041",
        claims["uid"].as_i64().ok_or("missing uid")?,
        claims["jti"].as_str().ok_or("missing jti")?
    );
    let digest = format!("\\x{:x}", Sha256::digest(message.as_bytes()));
    let sent: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let rows = if value.is_array() {
        value
    } else {
        &mut value[table]
    };
    for row in rows.as_array_mut().ok_or("invalid open snapshot")? {
        if row["step_up_binding"].as_str() != Some(&digest) {
            return Err(
                "stored step-up binding does not bind the verified bearer and canonical incident"
                    .into(),
            );
        }
        let actual = chrono::DateTime::parse_from_rfc3339(
            row["expires_at"].as_str().ok_or("missing expiry")?,
        )?;
        let expected = chrono::DateTime::parse_from_rfc3339(
            sent["expiresAt"].as_str().ok_or("missing sent expiry")?,
        )?;
        if actual.timestamp_micros() != expected.timestamp_micros() {
            return Err("stored incident expiry differs from request".into());
        }
        row["step_up_binding"] = json!("<verified-step-up-binding>");
    }
    Ok(())
}

// Mailbox and user sequences may overlap: normalize each currency by its own key.
fn mailbox_names(value: &mut Value, names: &[(i64, &str)]) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.as_str(), "mailbox_id" | "mailboxId") {
                    let id = value
                        .as_i64()
                        .or_else(|| value.as_str().and_then(|s| s.parse().ok()));
                    if let Some((_, name)) = names.iter().find(|(n, _)| Some(*n) == id) {
                        *value = json!(name);
                    }
                } else {
                    mailbox_names(value, names);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                mailbox_names(value, names);
            }
        }
        _ => {}
    }
}

fn accept_refs(
    value: &mut Value,
    table: Option<&str>,
    tags: &[(i64, String)],
    message: Option<i64>,
    mailbox: i64,
) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let id = value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|s| s.parse().ok()));
                if let Some(id) = id {
                    let tag = matches!(key.as_str(), "folder_id" | "tag_id")
                        || (key == "id" && table == Some("tags"));
                    let msg = matches!(
                        key.as_str(),
                        "recovered_message_id" | "message_id" | "entity_id"
                    ) || (key == "id" && table == Some("messages"));
                    if tag {
                        if let Some((_, name)) = tags.iter().find(|(n, _)| *n == id) {
                            *value = json!(format!("<tag:{name}>"));
                        }
                    } else if msg && Some(id) == message {
                        *value = json!("<message>");
                    } else if key == "id" && table == Some("message_attachments") && id > 0 {
                        *value = json!("<attachment>");
                    } else if key == "id" && table == Some("mailboxes") && id == mailbox {
                        *value = json!("<other-mailbox>");
                    }
                } else {
                    accept_refs(value, table, tags, message, mailbox);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                accept_refs(value, table, tags, message, mailbox);
            }
        }
        _ => {}
    }
}

// Project run-specific fixture identities from immutable BEFORE rows. The
// producer checks newly generated message/audit links before calling this.
fn accept_recording(value: &mut Value) {
    let mut fixture_messages = vec![];
    let effects = if value.get("observation").is_some() {
        &value["observation"]["effects"]
    } else {
        &value["effects"]
    };
    if let Some(effects) = effects.as_array() {
        for effect in effects {
            if effect["table"] == "messages" {
                for row in effect["before"].as_array().into_iter().flatten() {
                    if let Some(id) = row["id"].as_i64() {
                        fixture_messages.push((
                            id,
                            row["raw_ref"]
                                .as_str()
                                .unwrap_or("")
                                .trim_start_matches("raw-")
                                .to_owned(),
                        ));
                    }
                }
            }
        }
    }
    for (ordinal, (_, uuid)) in fixture_messages.iter().enumerate() {
        if uuid.len() == 36 {
            *value = serde_json::from_str(
                &value
                    .to_string()
                    .replace(uuid, &format!("<fixture-{ordinal}>")),
            )
            .expect("fixture UUID projection");
        }
    }
    let effects = if value.get("observation").is_some() {
        &mut value["observation"]["effects"]
    } else {
        &mut value["effects"]
    };
    if let Some(effects) = effects.as_array_mut() {
        for effect in effects {
            let table = effect["table"].as_str().unwrap_or("").to_owned();
            for key in if table == "mailboxes" {
                vec!["domain_id"]
            } else if table == "mail_recovery_quarantine_artifacts" {
                vec!["fork_consented_by"]
            } else {
                vec![]
            } {
                let old = effect["before"]
                    .as_array()
                    .and_then(|rows| rows.first())
                    .and_then(|row| row.get(key))
                    .filter(|n| n.is_number())
                    .cloned();
                for stage in ["before", "after"] {
                    if let Some(rows) = effect[stage].as_array_mut() {
                        for row in rows {
                            if old.as_ref().is_some_and(|old| row.get(key) == Some(old)) {
                                row[key] = json!(if key == "domain_id" {
                                    "<other-domain>"
                                } else {
                                    "<other>"
                                });
                            }
                        }
                    }
                }
            }
            for stage in ["before", "after"] {
                if let Some(rows) = effect[stage].as_array_mut() {
                    for row in rows {
                        if table == "mailboxes" && row["sending_quota_reset_at"].is_string() {
                            row["sending_quota_reset_at"] = json!("<date>");
                        }
                        if table == "tags"
                            && row["imap_uid_validity"].as_i64().is_some_and(|n| n > 0)
                        {
                            row["imap_uid_validity"] = json!("<uid-validity>");
                        }
                        for (ordinal, (id, _)) in fixture_messages.iter().enumerate() {
                            for key in if table == "messages" {
                                vec!["id"]
                            } else {
                                vec!["message_id", "entity_id"]
                            } {
                                if row.get(key) == Some(&json!(id)) {
                                    row[key] = json!(format!("<fixture-message-{ordinal}>"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let effects = if value.get("observation").is_some() {
        &mut value["observation"]["effects"]
    } else {
        &mut value["effects"]
    };
    if let Some(effects) = effects.as_array_mut() {
        for effect in effects {
            if effect["table"] == "message_tags" {
                for stage in ["before", "after"] {
                    if let Some(rows) = effect[stage].as_array_mut() {
                        rows.sort_by_key(Value::to_string);
                    }
                }
            }
        }
    }
    if let Some(rows) = value["observation"]["audit"].as_array_mut() {
        for row in rows {
            if row["action"] == "mail_recovery_artifact_accept" {
                if row["target_id"].as_i64().is_some_and(|n| n > 0) {
                    row["target_id"] = json!("<message>");
                }
                if row["after_state"]["mailboxId"]
                    .as_str()
                    .is_some_and(|s| s.parse::<i64>().is_ok())
                {
                    row["after_state"]["mailboxId"] = json!("<other-mailbox>");
                }
            }
        }
    }
}
// Schema metadata advances while the frozen recording remains immutable. The
// actual wire value is independently checked against the DB before this view.
fn context_observation(observation: &mut Value) -> Result<(), BoxError> {
    let Some(response) = observation.get_mut("response") else { return Ok(()); };
    let Some(body) = response.get("body").and_then(Value::as_str) else { return Ok(()); };
    let marker = "\"schemaVersion\": <schema-version>";
    if body.contains(marker) { return Ok(()); }
    let pattern = regex::Regex::new(r#""schemaVersion"\s*:\s*[0-9]+"#)?;
    let count = pattern.find_iter(body).count();
    if count == 0 && response["status"] != json!(200) { return Ok(()); }
    if count != 1 { return Err("recovery context must expose exactly one numeric schema version".into()); }
    let body = pattern.replace(body, marker).into_owned();
    if response["headers"].get("content-length").is_some() {
        response["headers"]["content-length"] = json!([body.len().to_string()]);
    }
    response["body"] = json!(body);
    Ok(())
}
fn context_record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let mut expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let mut actual = value.clone();
        if let Some(observation) = expected.get_mut("observation") { context_observation(observation)?; }
        if let Some(observation) = actual.get_mut("observation") { context_observation(observation)?; }
        golden::compare(&expected, &actual)?;
        Ok(())
    } else { record(path, value) }
}
fn accept_record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let mut expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let mut actual = value.clone();
        accept_recording(&mut expected);
        accept_recording(&mut actual);
        golden::compare(&expected, &actual)?;
        Ok(())
    } else {
        record(path, value)
    }
}

pub fn group(action: &str) -> &'static str {
    match action {
        a if a.starts_with("retired-") => "retired",
        a if a.starts_with("updates-") => "updates",
        a if a.starts_with("upgrades-") => "upgrades",
        a if a.starts_with("recovery-") => "recovery",
        a if a.starts_with("airgap-") => "airgap",
        a if a.starts_with("deploy-") => "deploy",
        _ => "updates",
    }
}

fn specs(action: &str, label: &str, user: i64, other: i64) -> Option<Case> {
    let _ = (user, other);
    let base = |method, pattern, perm, status| Case {
        method,
        pattern,
        fill: vec![],
        query: String::new(),
        perm,
        body: String::new(),
        content_type: "application/json",
        headers: vec![],
        seed: vec![],
        boot_seed: vec![],
        cleanup: vec![],
        effects: "SELECT jsonb_build_object('n',count(*))::text FROM upgrade_history",
        table: "upgrade_history",
        extra_effects: vec![],
        channels: vec!["admin:alert"],
        status,
        replace: vec![],
        claims: json!({}),
    };
    let mut c = match action {
        "retired-auto-update-get" => base("GET", "/admin/system/auto-update", "backup.read", 410),
        "retired-auto-update-put" => base("PUT", "/admin/system/auto-update", "system.config", 410),
        "retired-maintenance-get" => base(
            "GET",
            "/admin/system/maintenance-window",
            "backup.read",
            410,
        ),
        "retired-maintenance-put" => base(
            "PUT",
            "/admin/system/maintenance-window",
            "system.config",
            410,
        ),
        "retired-upgrade-check" => {
            base("POST", "/admin/system/upgrade/check", "system.upgrade", 410)
        }
        "retired-upgrade-apply" => {
            base("POST", "/admin/system/upgrade/apply", "system.upgrade", 410)
        }
        "retired-upgrade-rollback" => base(
            "POST",
            "/admin/system/upgrade/rollback",
            "system.upgrade",
            410,
        ),
        "updates-history" => base("GET", "/admin/system/upgrade/status", "backup.read", 200),
        "updates-summary" => base("GET", "/admin/updates/summary", "backup.read", 200),
        "updates-devices" => base("GET", "/admin/updates/devices", "backup.read", 200),
        "updates-push" => base("POST", "/admin/updates/push", "system.upgrade", 204),
        "upgrades-console" => base("GET", "/admin/system/upgrades", "system.upgrade", 200),
        "upgrades-recovery-context" => base(
            "GET",
            "/admin/system/upgrades/recovery-context",
            "system.upgrade",
            200,
        ),
        "upgrades-intent-read" => base(
            "GET",
            "/admin/system/upgrades/intents/{id}",
            "system.upgrade",
            200,
        ),
        "upgrades-diagnostics" => base(
            "GET",
            "/admin/system/upgrades/intents/{id}/diagnostics",
            "system.upgrade",
            200,
        ),
        "upgrades-challenge-complete" => base(
            "POST",
            "/admin/system/upgrades/challenges/complete",
            "system.upgrade",
            200,
        ),
        "upgrades-preview" => base(
            "POST",
            "/admin/system/upgrades/preview",
            "system.upgrade",
            200,
        ),
        "upgrades-challenge" => base(
            "POST",
            "/admin/system/upgrades/challenges",
            "system.upgrade",
            200,
        ),
        "upgrades-intent-request" => base(
            "POST",
            "/admin/system/upgrades/intents",
            "system.upgrade",
            202,
        ),
        "upgrades-intent-cancel" => base(
            "POST",
            "/admin/system/upgrades/intents/{id}/cancel",
            "system.upgrade",
            200,
        ),
        "upgrades-recovery-set" => base(
            "POST",
            "/admin/system/upgrades/recovery-sets",
            "system.upgrade",
            201,
        ),
        "upgrades-restore-proof" => base(
            "POST",
            "/admin/system/upgrades/restore-proofs",
            "system.upgrade",
            201,
        ),
        "deploy-cancel" => base("POST", "/admin/deploy/cancel", "system.upgrade", 204),
        "deploy-start" => base("POST", "/admin/deploy/start", "system.upgrade", 202),
        "deploy-status" => base("GET", "/admin/deploy/status", "system.upgrade", 200),
        "airgap-upload" => base(
            "POST",
            "/admin/updates/airgap/upload",
            "system.upgrade",
            200,
        ),
        "airgap-file" => base("GET", "/updates/{slug}/{filename}", "system.upgrade", 200),
        "airgap-feed" => base("GET", "/updates/appcast", "system.upgrade", 200),
        "recovery-list" => base(
            "GET",
            "/admin/system/recovery/incidents",
            "system.recovery",
            200,
        ),
        "recovery-signals" => base(
            "GET",
            "/admin/system/recovery/signals",
            "system.recovery",
            200,
        ),
        "recovery-artifacts" => base(
            "GET",
            "/admin/system/recovery/incidents/{id}/artifacts",
            "system.recovery",
            200,
        ),
        "recovery-approve" => base(
            "POST",
            "/admin/system/recovery/incidents/{id}/approve",
            "system.recovery",
            200,
        ),
        "recovery-close" => base(
            "POST",
            "/admin/system/recovery/incidents/{id}/close",
            "system.recovery",
            200,
        ),
        "recovery-accept" => base(
            "POST",
            "/admin/system/recovery/artifacts/{id}/accept",
            "system.recovery",
            200,
        ),
        "recovery-open" => base(
            "POST",
            "/admin/system/recovery/incidents",
            "system.recovery",
            201,
        ),
        _ => return None,
    };
    if action == "airgap-feed" && label == "invalid-query" { c.query="?since=not-a-time&limit=invalid".into(); }
    if action == "airgap-feed" && matches!(label, "invalid" | "head") {
        c.method = "HEAD";
        c.status = 405;
    }
    if matches!(action, "deploy-cancel" | "deploy-start" | "deploy-status") {
        // #542: the cancel fence is durable; no case may inherit another's.
        // A run cancelled by an earlier case's teardown can persist its step and fence late.
        for statement in ["DELETE FROM deploy_remote_fence", "DELETE FROM deployment_steps WHERE step_name IN('ssh_check','install_packages','configure_replication','configure_pgpool','configure_seaweedfs','start_services','verify')"] {
            c.boot_seed.push(statement.into());
        }
        c.cleanup.push("DELETE FROM deploy_remote_fence".into());
    }
    if action == "deploy-cancel" {
        c.table = "deployment_steps";
        c.effects = "SELECT to_jsonb(s)::text FROM deployment_steps s ORDER BY step_name";
        c.cleanup.push("DELETE FROM deployment_steps WHERE step_name IN('ssh_check','install_packages','configure_replication','configure_pgpool','configure_seaweedfs','start_services','verify')".into());
        if label == "invalid" {
            c.body = "ignored invalid JSON".into();
        }
    }
    if action == "deploy-start" {
        c.table = "deployment_steps";
        c.effects = "SELECT to_jsonb(s)::text FROM deployment_steps s ORDER BY step_name";
        c.cleanup.push("DELETE FROM deployment_steps WHERE step_name IN('ssh_check','install_packages','configure_replication','configure_pgpool','configure_seaweedfs','start_services','verify')".into());
        c.body=json!({"nodes":(1..=3).map(|i|json!({"host":format!("{{{{ssh-node-{i}}}}}"),"role":if i==1{"primary"}else{"standby"},"ssh_user":"root","ssh_key":if label=="bad-key" {"gofree-plat2b-missing-key"}else{"{{ssh-inline-key}}"},"password":"gofree-plat2b-node-password"})).collect::<Vec<_>>()}).to_string();
        if label == "duplicate-nodes" {
            c.body = format!("{},\"nodes\":[{{\"role\":\"standby\"}},null,{{}}]}}", c.body.trim_end_matches('}'));
        }
        if label == "invalid" {
            c.body = "{\"nodes\":[]}".into();
            c.status = 400;
        }
    }
    if action == "deploy-status" {
        c.table = "deployment_steps";
        c.effects="SELECT to_jsonb(s)::text FROM deployment_steps s WHERE step_name LIKE 'gofree_plat2b_%' ORDER BY step_name";
        if label != "empty" {
            c.boot_seed.push("INSERT INTO deployment_steps(step_name,status,output,error) VALUES('gofree_plat2b_a','running','legacy private output','legacy secret'),('gofree_plat2b_b','done','legacy successful output','')".into());
            c.cleanup
                .push("DELETE FROM deployment_steps WHERE step_name LIKE 'gofree_plat2b_%'".into());
        }
        if label == "invalid" {
            c.query = "?limit=%zz&profile=garbage".into();
        }
    }
    if action == "airgap-upload" {
        c.content_type = "multipart/form-data; boundary=gofree-plat2b-boundary";
        c.body=format!("--gofree-plat2b-boundary\r\nContent-Disposition: form-data; name=\"slug\"\r\n\r\nlinux-amd64\r\n--gofree-plat2b-boundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n--gofree-plat2b-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"bundle-v2.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n{}\r\n--gofree-plat2b-boundary--\r\n","{{offline-metadata}}",String::from_utf8_lossy(super::airgap::UPLOADED));
        match label {
            "invalid" => {
                c.body = "bad multipart".into();
                c.status = 400;
            }
            "repeat" | "rollback" => c.status = 409,
            "missing-slug" => {
                c.body = c.body.replace("linux-amd64\r\n", "\r\n");
                c.status = 400;
            }
            "traversal" => {
                c.body = c.body.replace("linux-amd64\r\n", "../escape\r\n");
                c.status = 400;
            }
            "bad-metadata" => {
                c.body = c.body.replace("{{offline-metadata}}", "{}");
                c.status = 400;
            }
            "bad-signature" => c.status = 400,
            "hash-mismatch" => {
                c.body = c.body.replace(
                    "Setjoin offline update replacement",
                    "Changed offline update replacement",
                );
                c.status = 400;
            }
            "no-roots" => c.status = 503,
            _ => {}
        }
    }
    if action == "airgap-file" {
        c.fill = vec!["linux-amd64".into(), "bundle.bin".into()];
        match label {
            "invalid" => {
                c.fill[1] = "missing.bin".into();
                c.status = 404;
            }
            "range" => {
                c.headers.push(("range", "bytes=8-14".into()));
                c.status = 206;
            }
            "bad-range" => {
                c.headers.push(("range", "bytes=999-1000".into()));
                c.status = 416;
            }
            "not-modified" => {
                c.headers
                    .push(("if-modified-since", "Thu, 01 Oct 2026 00:00:00 GMT".into()));
                c.status = 304;
            }
            "head" => {
                c.method = "HEAD";
                c.status = 405;
            }
            "expired" | "tampered" => c.status = 404,
            _ => {}
        }
    }
    if label == "scoped" && matches!(action, "deploy-start" | "deploy-cancel" | "deploy-status" | "airgap-upload") {
        // #542: an organization-wide system.upgrade grant is required.
        c.status = 403;
    }
    if action.starts_with("recovery-") {
        c.effects = "SELECT jsonb_build_object('n',count(*))::text FROM mail_recovery_incidents";
        c.table = "mail_recovery_incidents";
        if label == "invalid" {
            c.query = "?limit=bad".into();
            c.status = 400;
        }
        if label == "scoped" {
            c.status = 403;
        }
        if label == "disabled" {
            c.query = "?limit=bad".into();
            c.status = 404;
        }
        if label == "cached" {
            c.status = 200;
            c.seed.push("BEGIN; SET LOCAL session_replication_role='replica'; UPDATE feature_toggles SET enabled=false WHERE key='feature.client_recovery_ingest'; COMMIT".into());
        }
        if action == "recovery-list" {
            match label {
                "bad-cursor" => {
                    c.query = "?before=not-a-time".into();
                    c.status = 400;
                }
                "bad-status" => {
                    c.query = "?status=OPEN".into();
                    c.status = 400;
                }
                "large" => {
                    for n in 61..=63 {
                        let uuid = format!("45500000-0000-4000-8000-{n:012}");
                        c.seed.push(format!("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) SELECT '{uuid}',installation_id,1,2,repeat('x',1024),{other},decode(repeat('aa',32),'hex'),now()+interval '1 day','{uuid}' FROM upgrade_control_state"));
                        c.cleanup.push(format!(
                            "DELETE FROM mail_recovery_incidents WHERE id='{uuid}'"
                        ));
                    }
                }
                _ => {}
            }
            if label == "large" {
                c.replace.push((
                    format!("\"openedBy\": \"{other}\""),
                    "\"openedBy\": \"<other>\"".into(),
                ));
            }
        }
        if action == "recovery-list" && label == "filtered" {
            c.query = "?status=closed&before=2026-10-03T00:00:00Z&limit=1".into();
            for (n, status, day) in [(1, "closed", 1), (2, "open", 2), (3, "closed", 4)] {
                let uuid = format!("45500000-0000-4000-8000-{n:012}");
                c.seed.push(format!("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key,status,created_at) SELECT '{uuid}',installation_id,1,2,'oracle recovery list',{other},decode(repeat('aa',32),'hex'),'2026-10-{day:02}T00:00:00Z'::timestamptz+interval '1 day','{uuid}','{status}','2026-10-{day:02}T00:00:00Z' FROM upgrade_control_state"));
                c.cleanup.push(format!(
                    "DELETE FROM mail_recovery_incidents WHERE id='{uuid}'"
                ));
            }
            c.replace.push((
                format!("\"openedBy\": \"{other}\""),
                "\"openedBy\": \"<other>\"".into(),
            ));
        }
    }
    if action == "recovery-artifacts" {
        const INCIDENT: &str = "45500000-0000-4000-8000-000000000011";
        c.fill = vec![INCIDENT.into()];
        c.effects = "SELECT to_jsonb(a)::text FROM mail_recovery_quarantine_artifacts a WHERE incident_id='45500000-0000-4000-8000-000000000011' ORDER BY id";
        c.table = "mail_recovery_quarantine_artifacts";
        c.seed.push(format!("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) SELECT '{INCIDENT}',installation_id,1,2,'oracle recovery artifacts',{other},decode(repeat('aa',32),'hex'),now()+interval '1 day','{INCIDENT}' FROM upgrade_control_state"));
        c.cleanup.push(format!(
            "DELETE FROM mail_recovery_incidents WHERE id='{INCIDENT}'"
        ));
        if label == "invalid" {
            c.fill = vec!["not-an-id".into()];
            c.query.clear();
        }
        if label == "invalid-limit" {
            c.query = "?limit=bad".into();
            c.status = 400;
        }
        if label == "missing" {
            c.fill = vec!["45500000-0000-4000-8000-000000000012".into()];
            c.status = 400;
        }
        if matches!(label, "compact" | "urn" | "wrapped") {
            let alias = "455abcde-abcd-4abc-8abc-000000000011";
            c.seed.push(c.seed[0].replace(INCIDENT, alias));
            c.cleanup.push(format!(
                "DELETE FROM mail_recovery_incidents WHERE id='{alias}'"
            ));
            c.fill = vec![match label {
                "compact" => alias.replace('-', "").to_ascii_uppercase(),
                "urn" => format!("URN:UUID:{}", alias.to_ascii_uppercase()),
                _ => format!("x{alias}y"),
            }];
        }
        if label == "nil" {
            c.fill = vec!["00000000-0000-0000-0000-000000000000".into()];
            c.status = 400;
        }
    }
    if action == "recovery-approve" {
        const INCIDENT: &str = "45500000-0000-4000-8000-000000000021";
        const REASON: &str = "oracle recovery approval";
        c.fill = vec![INCIDENT.into()];
        c.query.clear();
        c.body = json!({"reason":REASON}).to_string();
        c.headers.push(("x-audit-reason", REASON.into()));
        c.effects = "SELECT to_jsonb(i)::text FROM mail_recovery_incidents i WHERE id='45500000-0000-4000-8000-000000000021' ORDER BY id";
        let opener = if label == "self" { user } else { other };
        c.seed.push(format!("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,approval_required,expires_at,idempotency_key) SELECT '{INCIDENT}',installation_id,1,2,'oracle recovery approval',{opener},decode(repeat('aa',32),'hex'),true,now()+interval '1 day','{INCIDENT}' FROM upgrade_control_state"));
        c.cleanup.push(format!(
            "DELETE FROM mail_recovery_incidents WHERE id='{INCIDENT}'"
        ));
        for (id, name) in [(user, "<admin>"), (other, "<other>")] {
            c.replace.push((
                format!("\"approvedBy\": \"{id}\""),
                format!("\"approvedBy\": \"{name}\""),
            ));
        }
        match label {
            "invalid" => c.body = "{\"reason\":42}".into(),
            "bad-id" => {
                c.fill = vec!["bad-id".into()];
                c.status = 400;
            }
            // The unknown field is rejected before identity lookup. Keep the exact
            // arbitrary poison value recorded from Go, independent of fixture sequences.
            "unknown-field" => {
                c.body = json!({"reason":REASON,"actorId":196}).to_string();
                c.status = 400;
            }
            "bad-reason" => {
                c.body = json!({"reason":"a different reason"}).to_string();
                c.status = 400;
            }
            "self" => c.status = 403,
            _ => {}
        }
    }
    if action == "recovery-close" {
        const INCIDENT: &str = "45500000-0000-4000-8000-000000000031";
        const SESSION: &str = "45500000-0000-4000-8000-000000000032";
        const REASON: &str = "oracle recovery closure";
        c.fill = vec![INCIDENT.into()];
        c.query.clear();
        c.body = json!({"reason":REASON}).to_string();
        c.headers.push(("x-audit-reason", REASON.into()));
        c.effects = "SELECT to_jsonb(i)::text FROM mail_recovery_incidents i WHERE id='45500000-0000-4000-8000-000000000031' ORDER BY id";
        c.extra_effects.push(("mail_recovery_upload_sessions",format!("SELECT to_jsonb(s)::text FROM mail_recovery_upload_sessions s WHERE id='{SESSION}' ORDER BY id")));
        c.channels = vec!["mail_recovery_incident_changed"];
        c.seed.push(format!("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) SELECT '{INCIDENT}',installation_id,1,2,'oracle recovery closure',{other},decode(repeat('aa',32),'hex'),now()+interval '1 day','{INCIDENT}' FROM upgrade_control_state"));
        c.seed.push(format!("INSERT INTO mail_recovery_upload_sessions(id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key) SELECT '{SESSION}','{INCIDENT}',id,{other},'{SESSION}',decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),'received',1,1,'{{}}',now(),now()+interval '1 hour','{SESSION}' FROM mailboxes WHERE user_id={other} AND is_primary"));
        c.cleanup.push(format!(
            "DELETE FROM mail_recovery_upload_sessions WHERE id='{SESSION}'"
        ));
        c.cleanup.push(format!(
            "DELETE FROM mail_recovery_incidents WHERE id='{INCIDENT}'"
        ));
        if label == "invalid" {
            c.body = "{\"reason\":42}".into();
        }
        if label == "bad-id" {
            c.fill = vec!["bad-id".into()];
            c.status = 400;
        }
    }
    if action == "recovery-accept" {
        const INCIDENT: &str = "45500000-0000-4000-8000-000000000051";
        const SESSION: &str = "45500000-0000-4000-8000-000000000052";
        const ARTIFACT: &str = "45500000-0000-4000-8000-000000000053";
        const REASON: &str = "oracle recovery acceptance";
        // Frozen Go's quota refresh runs at boot; give both fixtures the
        // already-accounted two ten-byte messages before observing the request.
        c.seed.push(format!(
            "UPDATE mailboxes SET used_bytes=20 WHERE user_id={other}"
        ));
        c.fill = vec![ARTIFACT.into()];
        c.query.clear();
        c.body = json!({"resolution":"accept","reason":REASON}).to_string();
        c.headers.push(("x-audit-reason", REASON.into()));
        c.table = "mail_recovery_quarantine_artifacts";
        c.effects="SELECT to_jsonb(q)::text FROM mail_recovery_quarantine_artifacts q WHERE id='45500000-0000-4000-8000-000000000053'";
        c.channels = vec!["mail_recovery_incident_changed", "tag:{{other-mailbox}}"];
        c.seed.push(format!("INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) SELECT '{INCIDENT}',installation_id,1,2,'oracle recovery acceptance',{user},decode(repeat('aa',32),'hex'),now()+interval '1 day','{INCIDENT}' FROM upgrade_control_state"));
        c.seed.push(format!("INSERT INTO mail_recovery_incident_accounts(incident_id,mailbox_id,affected_user_id,evidence_token_sha256) SELECT '{INCIDENT}',id,{other},decode(repeat('aa',32),'hex') FROM mailboxes WHERE user_id={other} AND is_primary"));
        c.seed.push(format!("INSERT INTO mail_recovery_upload_sessions(id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,receipt,consented_at,expires_at,idempotency_key,status) SELECT '{SESSION}','{INCIDENT}',id,{other},'{SESSION}',decode(repeat('d5',32),'hex'),decode(repeat('b5',32),'hex'),decode(repeat('c5',32),'hex'),'received',123,127,'{{}}',now(),now()+interval '1 hour','{SESSION}','quarantined' FROM mailboxes WHERE user_id={other} AND is_primary"));
        c.seed.push(format!("INSERT INTO mail_recovery_quarantine_artifacts(id,session_id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,raw_mime_size,raw_ref,receipt,signed_timeline,signed_boot_epoch,parsed_headers,blob_inventory,malware_status) SELECT '{ARTIFACT}',id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,123,repeat('c5',32),receipt,2,'{SESSION}','{{\"messageId\":\"<plat2b-recovered@example.test>\",\"fromAddr\":\"sender@example.test\",\"subject\":\"Recovered fixture\",\"bodyText\":\"Oracle body\",\"toAddrs\":[\"recipient@example.test\"],\"receivedAt\":\"2026-10-02T10:00:00Z\"}}','[{{\"sha256\":\"{}\",\"objectRef\":\"{}\",\"size\":\"4\",\"role\":\"attachment\",\"blobId\":\"fixture.txt\"}}]','clean' FROM mail_recovery_upload_sessions WHERE id='{SESSION}'","e5".repeat(32),"e5".repeat(32)));
        for (table,filter,order) in [
            ("mail_recovery_ledger",format!("incident_id='{INCIDENT}'"),"quarantine_id"),
            ("messages",format!("mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other})"),"id"),
            ("tags",format!("mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other})"),"name"),
            ("message_tags",format!("message_id IN(SELECT id FROM messages WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other}))"),"tag_id"),
            ("message_attachments",format!("message_id IN(SELECT id FROM messages WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other}))"),"id"),
            ("blobs","sha256=repeat('e5',32)".into(),"sha256"),
            ("mailboxes",format!("user_id={other}"),"id"),
            ("jmap_changes_journal",format!("mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other})"),"state_seq"),
        ] { c.extra_effects.push((table,format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {filter} ORDER BY {order}"))); }
        c.cleanup.push(format!("DELETE FROM mail_recovery_ledger WHERE incident_id='{INCIDENT}'; DELETE FROM mail_recovery_quarantine_artifacts WHERE id='{ARTIFACT}'; DELETE FROM mail_recovery_upload_sessions WHERE id='{SESSION}'; DELETE FROM mail_recovery_incidents WHERE id='{INCIDENT}'"));
        c.cleanup.push(format!("DELETE FROM message_attachments WHERE message_id IN(SELECT id FROM messages WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other})); DELETE FROM messages WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other}); DELETE FROM blobs WHERE sha256=repeat('e5',32)"));
        match label {
            "invalid" => c.body = "{\"resolution\":42}".into(),
            "bad-id" => {
                c.fill = vec!["bad-id".into()];
                c.status = 400;
            }
            "bad-resolution" => {
                c.body = json!({"resolution":"reject","reason":REASON}).to_string();
                c.status = 400;
            }
            "infected" => {
                c.seed.push(format!("UPDATE mail_recovery_quarantine_artifacts SET malware_status='infected' WHERE id='{ARTIFACT}'"));
                c.status = 403;
            }
            "unapproved" => {
                c.seed.push(format!("UPDATE mail_recovery_incidents SET approval_required=true WHERE id='{INCIDENT}'"));
                c.status = 403;
            }
            "fork-without-consent" => {
                c.seed.push(format!("UPDATE mail_recovery_quarantine_artifacts SET status='fork_conflict' WHERE id='{ARTIFACT}'"));
                c.status = 403;
            }
            "fork-consented" => {
                c.body = json!({"resolution":"accept_fork","reason":REASON}).to_string();
                c.seed.push(format!("UPDATE mail_recovery_quarantine_artifacts SET status='fork_conflict',fork_consented_by={other},fork_consented_at=now() WHERE id='{ARTIFACT}'"));
            }
            _ => {}
        }
    }
    if action == "recovery-open" {
        const INCIDENT: &str = "455abcde-abcd-4abc-8abc-000000000041";
        const KEY: &str = "45500000-0000-4000-8000-000000000042";
        const REASON: &str = "oracle recovery opening";
        c.query.clear();
        let mut body = json!({"incidentId":INCIDENT,"mailboxIds":["{{other-mailbox}}"],"evidence":{"{{other-mailbox}}":"aa".repeat(32)},"minimumTimeline":"1","maximumTimeline":"2","expiresAt":"{{now+24h}}","reason":REASON,"approvalRequired":false,"idempotencyKey":KEY});
        c.headers.push(("x-audit-reason", REASON.into()));
        c.headers.push(("idempotency-key", KEY.into()));
        c.claims = json!({"acr":"aal2","amr":["pwd","otp","mfa"]});
        c.effects = "SELECT to_jsonb(i)::text FROM mail_recovery_incidents i WHERE id='455abcde-abcd-4abc-8abc-000000000041' ORDER BY id";
        c.extra_effects.push(("mail_recovery_incident_accounts",format!("SELECT to_jsonb(a)::text FROM mail_recovery_incident_accounts a WHERE incident_id='{INCIDENT}' ORDER BY mailbox_id")));
        c.channels = vec!["mail_recovery_incident_changed"];
        c.seed.push(format!("INSERT INTO continuity_client_witnesses(mailbox_id,token_sha256,installation_id,timeline_generation,state_watermark,issued_at,boot_epoch,signal_class) SELECT mb.id,decode(repeat('aa',32),'hex'),control.installation_id,2,1,now(),'45500000-0000-4000-8000-000000000043','client_observed_newer_timeline' FROM mailboxes mb CROSS JOIN upgrade_control_state control WHERE mb.user_id={other} AND mb.is_primary"));
        c.cleanup.push(format!(
            "DELETE FROM mail_recovery_incidents WHERE id='{INCIDENT}'"
        ));
        c.cleanup.push(format!("DELETE FROM continuity_client_witnesses WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id={other}) AND token_sha256=decode(repeat('aa',32),'hex')"));
        match label {
            "no-step-up" => {
                c.claims = json!({});
                c.status = 403;
            }
            "bad-scope" => {
                body["minimumTimeline"] = json!("01");
                c.status = 400;
            }
            "bad-mailbox" => {
                body["mailboxIds"] = json!(["01"]);
                c.status = 400;
            }
            "bad-expiry" => {
                body["expiresAt"] = json!("{{now+192h}}");
                c.status = 400;
            }
            "bad-evidence" => {
                body["evidence"] = json!({"{{other-mailbox}}":"AA".repeat(32)});
                c.status = 400;
            }
            "wrong-evidence" => {
                body["evidence"] = json!({"{{other-mailbox}}":"bb".repeat(32)});
                c.status = 400;
            }
            "compact-incident" => {
                body["incidentId"] = json!(INCIDENT.replace('-', "").to_ascii_uppercase())
            }
            "approval" => body["approvalRequired"] = json!(true),
            "short-expiry" => body["expiresAt"] = json!("{{now+2h}}"),
            _ => {}
        }
        c.body = body.to_string();
        if label == "invalid" {
            c.body = "{\"incidentId\":42}".into();
        }
    }
    updates(&mut c, action, label, user);
    upgrades(&mut c, action, label);
    if label == "denied" {
        c.status = 403;
    }
    if label == "ignored-query" {
        c.query = "?limit=-1&q=%00&x=%zz".into();
    }
    if label == "body" && c.method != "GET" {
        c.body = "{\"enabled\":true,\"path\":\"/tmp/x\"}".into();
    }
    if label == "accept-language" {
        c.headers.push(("accept-language", "fr-CA,fr;q=0.8".into()));
    }
    Some(c)
}

const HISTORY: &str = "INSERT INTO upgrade_history(id,from_version,to_version,mode,ddl_classification,status,started_at,completed_at,downtime_ms,error_message) OVERRIDING SYSTEM VALUE VALUES ";
const DEVICES: &str = "INSERT INTO devices(id,user_id,device_name,platform,os_version,app_version,fingerprint,last_seen) OVERRIDING SYSTEM VALUE VALUES ";

/// Seed rows and requests for the client-update and upgrade-history routes.
fn updates(c: &mut Case, action: &str, label: &str, user: i64) {
    if !action.starts_with("updates-") {
        return;
    }
    let device = |id: i64, name: &str, platform: &str, version: &str, seen: &str| {
        format!("({id},{user},{name},{platform},'14.1',{version},'plat2-{id}',{seen})")
    };
    let quote = |t: &str| {
        if t == "NULL" {
            t.to_string()
        } else {
            format!("'{t}'")
        }
    };
    let dev = |id: i64, name: &str, platform: &str, version: &str, seen: &str| {
        device(
            id,
            &quote(name),
            &quote(platform),
            &quote(version),
            &quote(seen),
        )
    };
    c.cleanup.push("DELETE FROM devices WHERE id>=9100 AND id<9200; DELETE FROM upgrade_history WHERE id>=9200 AND id<9300".into());
    c.seed
        .push("DELETE FROM devices; DELETE FROM upgrade_history".into());
    match action {
        "updates-history" => {
            c.effects = "SELECT jsonb_build_object('id',id,'status',status,'downtime',downtime_ms)::text FROM upgrade_history ORDER BY id";
            c.table = "upgrade_history";
            let rows = match label {
                "empty" | "denied" => vec![],
                "null-downtime" => vec![
                    "(9201,'v1','v2','hot_reload','additive_only','success','2026-10-03T10:00:00Z','2026-10-03T10:00:09Z',NULL,'late')",
                    "(9202,'v0','v1','full_restart','has_breaking','failed','2026-10-02T10:00:00Z',NULL,7,'older')",
                ],
                _ => vec![
                    "(9201,'v1','v2','hot_reload','additive_only','success','2026-10-01T10:00:00Z','2026-10-01T10:00:05Z',120,NULL)",
                    "(9202,'v2','v3','full_restart','has_breaking','failed','2026-10-02T09:00:00.123456Z',NULL,0,'boom <x> & y')",
                    "(9203,'v3','v4','hot_reload','additive_only','rolled_back','2026-10-03T08:30:00.5Z','2026-10-03T10:00:00.5Z',5,'')",
                ],
            };
            if !rows.is_empty() {
                c.seed.push(format!("{HISTORY}{}", rows.join(",")));
            }
        }
        _ => {
            c.effects = "SELECT jsonb_build_object('id',id,'name',device_name,'platform',platform,'version',app_version)::text FROM devices ORDER BY id";
            c.table = "devices";
            let rows: Vec<String> = match (action, label) {
                (_, "empty" | "denied") if action != "updates-push" => vec![],
                ("updates-summary", "null-platform") => vec![
                    dev(9101, "a", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9102, "b", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9103, "c", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9104, "d", "NULL", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9105, "e", "NULL", "v2.0", "2026-10-01T10:00:00Z"),
                    dev(9106, "f", "android", "v2.0", "2026-10-01T10:00:00Z"),
                ],
                ("updates-summary", _) => vec![
                    dev(9101, "a", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9102, "b", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9103, "c", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9104, "d", "android", "v2.0", "2026-10-01T10:00:00Z"),
                    dev(9105, "e", "android", "v2.0", "2026-10-01T10:00:00Z"),
                    dev(9106, "f", "macos", "NULL", "2026-10-01T10:00:00Z"),
                ],
                ("updates-devices", "null-seen") => vec![dev(9101, "a", "ios", "v1.0", "NULL")],
                ("updates-devices", "null-name") => vec![
                    dev(9101, "a", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9102, "NULL", "ios", "v1.0", "2026-10-03T10:00:00Z"),
                    dev(9103, "c", "ios", "v1.0", "2026-10-02T10:00:00Z"),
                ],
                ("updates-devices", "null-os") => vec![
                    format!(
                        "(9101,{user},'a','ios',NULL,'v1.0','plat2-9101','2026-10-03T10:00:00Z')"
                    ),
                    dev(9102, "b", "ios", "v1.0", "2026-10-02T10:00:00Z"),
                ],
                ("updates-devices", _) => vec![
                    dev(9101, "a", "ios", "v1.0", "2026-10-01T10:00:00Z"),
                    dev(9102, "b", "android", "v2.0", "2026-10-02T10:00:00Z"),
                    dev(9103, "c", "macos", "v1.0", "2026-10-03T10:00:00Z"),
                    dev(9104, "d", "ios", "v1.0", "NULL"),
                ],
                _ => vec![dev(9101, "a", "ios", "v1.0", "2026-10-01T10:00:00Z")],
            };
            if !rows.is_empty() {
                c.seed.push(format!("{DEVICES}{}", rows.join(",")));
            }
        }
    }
    if action == "updates-devices" {
        c.query = match label {
            "paging" => "?limit=2&offset=1".into(),
            "bad-paging" => "?limit=abc&offset=-5".into(),
            "big-limit" => "?limit=101&offset=0".into(),
            "huge-offset" => "?limit=5&offset=99999999999".into(),
            "ignored-query" => "?limit=-1&q=%00&x=%zz".into(),
            _ => String::new(),
        };
    }
    if action == "updates-push" {
        c.channels = vec!["admin:alert", "update_available"];
        let same = |t: &str| t.to_string();
        c.body = match label {
            "bad-json" => same("{\"device_ids\":"),
            "bad-type" => same("{\"device_ids\":[\"a\"]}"),
            "bad-float" => same("{\"device_ids\":[1.5]}"),
            "empty-ids" => same("{\"device_ids\":[],\"version\":\"v9\"}"),
            "missing" => same("{}"),
            "null-body" => same("null"),
            "array-body" => same("[1]"),
            "folded" => same("{\"DEVICE_IDS\":[9101],\"Version\":null,\"MESSAGE\":null} trailing"),
            "unknown-key" => same("{\"device_ids\":[9101,9102,9103],\"x\":{\"y\":[1]}}"),
            "empty-body" => String::new(),
            _ => same("{\"device_ids\":[9101,9102],\"version\":\"v9 <b>\",\"message\":\"hi\"}"),
        };
        c.status = match label {
            "denied" => 403,
            "bad-json" | "bad-type" | "bad-float" | "empty-ids" | "missing" | "null-body"
            | "array-body" | "empty-body" => 400,
            _ => 204,
        };
    }
}

const SET_ID: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const PROOF_ID: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const KEY: &str = "cccccccc-0000-4000-8000-000000000003";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REASON: &str = "planned maintenance window";
const CHECKS: &str = "{\"database\":true,\"databaseRestoreList\":true,\"blobs\":true,\"configuration\":true,\"protectedKey\":true,\"featureToggles\":true,\"hmac\":true}";

fn swap(c: &mut Case, from: &str, to: &str) {
    c.body = c.body.replace(from, to);
}

/// An admin token (the governed grants are the only authority) with extra claims.
fn token(user: i64, extra: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token_with(user, extra.clone());
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

/// Requests for the upgrade control plane. Bodies may carry `{{timeline}}` and
/// `{{now[+-]Nh|m}}` tokens, resolved when the request is sent.
fn upgrades(c: &mut Case, action: &str, label: &str) {
    let Some(name) = action.strip_prefix("upgrades-") else {
        return;
    };
    c.effects = "SELECT jsonb_build_object('set',recovery_set_id,'status',status,'schema',schema_version)::text FROM upgrade_recovery_sets ORDER BY recovery_set_id";
    c.table = "upgrade_recovery_sets";
    c.channels = vec![
        "admin:alert",
        "upgrade_recovery_set_changed",
        "upgrade_changed",
    ];
    c.cleanup.push(format!("DELETE FROM upgrade_restore_proofs WHERE proof_id='{PROOF_ID}'; DELETE FROM upgrade_recovery_sets WHERE recovery_set_id='{SET_ID}'; DELETE FROM upgrade_challenges WHERE false; UPDATE audit_policy SET reason_required_areas=array_remove(reason_required_areas,'system') WHERE id=1"));
    c.seed.push(format!("DELETE FROM upgrade_restore_proofs WHERE proof_id='{PROOF_ID}'; DELETE FROM upgrade_recovery_sets WHERE recovery_set_id='{SET_ID}'"));
    if matches!(
        name,
        "preview"
            | "challenge"
            | "intent-request"
            | "intent-cancel"
            | "recovery-set"
            | "restore-proof"
    ) {
        c.headers.push(("x-audit-reason", REASON.into()));
    }
    let id_path = |c: &mut Case, v: &str| c.fill = vec![v.into()];
    match name {
        "intent-read" | "diagnostics" => id_path(
            c,
            match label {
                "zero" => "0",
                "word" => "abc",
                "padded" => "01",
                "huge" => "99999999999999999999",
                _ => "1",
            },
        ),
        "intent-cancel" => id_path(
            c,
            match label {
                "zero" => "0",
                "word" => "abc",
                _ => "1",
            },
        ),
        _ => {}
    }
    let body = match name {
        "preview" => format!("{{\"releaseId\":\"rel-1\",\"reason\":\"{REASON}\"}}"),
        "challenge" => format!("{{\"releaseId\":\"rel-1\",\"reason\":\"{REASON}\",\"previewDigest\":\"{DIGEST}\",\"idempotencyKey\":\"{KEY}\"}}"),
        "intent-request" => format!("{{\"releaseId\":\"rel-1\",\"reason\":\"{REASON}\",\"previewDigest\":\"{DIGEST}\",\"elevationId\":\"{KEY}\",\"idempotencyKey\":\"{KEY}\"}}"),
        "challenge-complete" => "{\"challengeId\":\"ffffffff-0000-4000-8000-000000000006\"}".to_string(),
        "intent-cancel" => format!("{{\"expectedGeneration\":\"1\",\"reason\":\"{REASON}\"}}"),
        "recovery-set" => format!("{{\"recoverySetId\":\"{SET_ID}\",\"timelineId\":\"{{{{timeline}}}}\",\"sourceReleaseId\":\"rel-0\",\"schemaVersion\":7,\"manifestDigest\":\"{DIGEST}\",\"checks\":{CHECKS},\"createdAt\":\"{{{{now}}}}\",\"expiresAt\":\"{{{{now+2h}}}}\",\"reason\":\"{REASON}\"}}"),
        "restore-proof" => format!("{{\"proofId\":\"{PROOF_ID}\",\"recoverySetId\":\"{SET_ID}\",\"targetId\":\"target-1\",\"checks\":{{\"isolated\":true,\"schema\":true,\"login\":true,\"mail\":true,\"blob\":true,\"productionEndpointsAbsent\":true}},\"provedAt\":\"{{{{now}}}}\",\"reason\":\"{REASON}\"}}"),
        _ => String::new(),
    };
    c.body = body.clone();
    if name == "challenge-complete" {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        c.claims = match label {
            "weak" | "denied" => json!({}),
            "stale" => json!({"acr":"aal2","amr":["pwd","otp","mfa"],"iat":now - 3600}),
            "single-factor" => json!({"acr":"aal2","amr":["pwd","mfa"]}),
            "no-mfa" => json!({"acr":"aal2","amr":["pwd","otp"]}),
            "aal1" => json!({"acr":"aal1","amr":["pwd","otp","mfa"]}),
            "extensions" => {
                json!({"acr":"aal2","amr":["pwd","otp","mfa","hwk","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13"]})
            }
            "duplicates" => json!({"acr":"aal2","amr":["pwd","pwd","mfa"]}),
            _ => json!({"acr":"aal2","amr":["pwd","otp","mfa"]}),
        };
    }
    match (name, label) {
        ("challenge-complete", "bad-id") => c.body = "{\"challengeId\":\"nope\"}".into(),
        ("challenge-complete", "nil-id") => {
            c.body = "{\"challengeId\":\"00000000-0000-0000-0000-000000000000\"}".into()
        }
        ("challenge-complete", "no-id") => c.body = "{}".into(),
        ("preview", "ready") => {
            c.seed.push(format!("UPDATE feature_toggles SET enabled=true WHERE key='feature.transactional_upgrades_catalog'; INSERT INTO upgrade_release_catalog(release_id,version,channel,platform,architecture,manifest_digest,manifest,metadata_version,catalog_generation,verified_by_key_ids,verified_at,metadata_expires_at) VALUES('rel-1','2.2.0','community','linux','amd64',decode('{DIGEST}','hex'),'{{}}'::jsonb,1,1,ARRAY['k1'],now()-interval '1 hour',now()+interval '1 day'); INSERT INTO upgrade_readiness(release_id,manifest_digest,readiness_generation,status,source_version,source_schema_version,target_schema_version,checks,blocker_count,expires_at,checked_by_user_id) VALUES('rel-1',decode('{DIGEST}','hex'),1,'ready','2.1.3',7,8,'{{}}'::jsonb,0,now()+interval '10 minutes',(SELECT min(id) FROM users)); INSERT INTO upgrade_recovery_sets(recovery_set_id,installation_id,timeline_id,source_release_id,schema_version,manifest_digest,status,checks,created_at,expires_at,recorded_by_user_id) SELECT '{SET_ID}',installation_id,timeline_id,'rel-0',7,decode('{DIGEST}','hex'),'verified','{CHECKS}'::jsonb,now(),now()+interval '2 hours',(SELECT min(id) FROM users) FROM upgrade_control_state"));
            c.cleanup.push("DELETE FROM upgrade_readiness WHERE release_id='rel-1'; DELETE FROM upgrade_release_catalog WHERE release_id='rel-1'; UPDATE feature_toggles SET enabled=false WHERE key='feature.transactional_upgrades_catalog'".into());
        }
        (_, "bad-json") => c.body = "{\"reason\":".into(),
        (_, "unknown-field") => c.body = "{\"surprise\":1}".into(),
        (_, "two-values") => c.body = format!("{body} {{}}"),
        (_, "array-body") => c.body = "[1]".into(),
        (_, "null-body") => c.body = "null".into(),
        (_, "bad-type") => c.body = "{\"reason\":5}".into(),
        (_, "no-reason-header") => c.headers.retain(|(n, _)| *n != "x-audit-reason"),
        (_, "reason-mismatch") => c.headers = vec![("x-audit-reason", "a different reason".into())],
        (_, "reason-short") => {
            c.headers = vec![("x-audit-reason", "short".into())];
            c.body = c.body.replace(REASON, "short");
        }
        (_, "reason-required") => {
            c.seed.push("UPDATE audit_policy SET reason_required_areas=array_append(reason_required_areas,'system') WHERE id=1".into());
            c.headers.clear();
        }
        ("preview" | "challenge" | "intent-request", "bad-schedule") => {
            c.body = c
                .body
                .replacen("\"reason\"", "\"scheduleAt\":\"tomorrow\",\"reason\"", 1)
        }
        ("preview" | "challenge" | "intent-request", "schedule") => {
            c.body = c.body.replacen(
                "\"reason\"",
                "\"scheduleAt\":\"2030-01-02T03:04:05.123456789+01:00\",\"reason\"",
                1,
            )
        }
        ("challenge" | "intent-request", "bad-digest") => swap(c, DIGEST, "XYZ"),
        ("intent-request", "bad-elevation") => {
            c.body = c.body.replacen(
                &format!("\"elevationId\":\"{KEY}\""),
                "\"elevationId\":\"nope\"",
                1,
            )
        }
        ("challenge" | "intent-request", "key-mismatch") => c.headers.push((
            "idempotency-key",
            "dddddddd-0000-4000-8000-000000000004".into(),
        )),
        ("challenge" | "intent-request", "key-nil") => {
            c.body = c.body.replace(KEY, "00000000-0000-0000-0000-000000000000");
            c.headers.push((
                "idempotency-key",
                "00000000-0000-0000-0000-000000000000".into(),
            ));
        }
        ("challenge" | "intent-request", _) if label != "denied" => {
            c.headers.push(("idempotency-key", KEY.into()))
        }
        ("intent-cancel", "bad-generation") => swap(c, "\"1\"", "\"01\""),
        ("recovery-set", "bad-digest") => swap(c, DIGEST, "xyz"),
        ("recovery-set", "bad-identity") => swap(c, SET_ID, "not-a-uuid"),
        ("recovery-set", "huge-schema") => {
            swap(c, "\"schemaVersion\":7", "\"schemaVersion\":99999999999")
        }
        ("recovery-set", "float-schema") => swap(c, "\"schemaVersion\":7", "\"schemaVersion\":7.5"),
        ("recovery-set", "bad-time") => swap(
            c,
            "\"createdAt\":\"{{now}}\"",
            "\"createdAt\":\"yesterday\"",
        ),
        ("recovery-set", "stale") => swap(
            c,
            "\"createdAt\":\"{{now}}\"",
            "\"createdAt\":\"{{now-48h}}\"",
        ),
        ("recovery-set", "short-checks") => swap(c, CHECKS, "{\"database\":true}"),
        ("recovery-set", "bad-checks") => swap(c, CHECKS, "{\"database\":\"yes\"}"),
        ("recovery-set", "no-checks") => swap(c, &format!("\"checks\":{CHECKS},"), ""),
        ("recovery-set", "wrong-timeline") => {
            swap(c, "{{timeline}}", "eeeeeeee-0000-4000-8000-000000000005")
        }
        ("recovery-set", "repeat") => {}
        ("restore-proof", "bad-identity") => swap(c, PROOF_ID, "nope"),
        ("restore-proof", "no-set") => {}
        ("restore-proof", "bad-time") => {
            swap(c, "\"provedAt\":\"{{now}}\"", "\"provedAt\":\"later\"")
        }
        _ => {}
    }
    if name == "restore-proof"
        && label != "no-set"
        && label != "denied"
        && !label.starts_with("bad")
        && !matches!(
            label,
            "unknown-field"
                | "two-values"
                | "array-body"
                | "null-body"
                | "no-reason-header"
                | "reason-mismatch"
                | "reason-short"
                | "reason-required"
                | "scoped"
        )
    {
        c.seed.push(format!("INSERT INTO upgrade_recovery_sets(recovery_set_id,installation_id,timeline_id,source_release_id,schema_version,manifest_digest,status,checks,created_at,expires_at,recorded_by_user_id) SELECT '{SET_ID}',installation_id,timeline_id,'rel-0',7,decode('{DIGEST}','hex'),'verified','{CHECKS}'::jsonb,now()-interval '10 minutes',now()+interval '2 hours',(SELECT min(id) FROM users) FROM upgrade_control_state"));
    }
    // Go's own answer is recorded; the reducers decide most statuses.
    c.status = 0;
}

/// The preview digest hashes run-time values, so its hex is pinned.
fn pin_digests(text: &str) -> String {
    let mut out = text.to_owned();
    for marker in ["\"previewDigest\":\"", "\"previewDigest\": \""] {
        let mut from = 0;
        while let Some(i) = out[from..].find(marker) {
            let start = from + i + marker.len();
            if out.len() < start + 64 || !out.is_char_boundary(start + 64) {
                break;
            }
            // The request body names its own digest; only a run-specific one is replaced.
            if &out[start..start + 64]
                != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            {
                out.replace_range(start..start + 64, &"0".repeat(64));
            }
            from = start + 64;
        }
    }
    out
}

/// Run-specific `mailbox:<id>` / `user:<id>` identities in the recovery context.
fn pin_identities(text: &str) -> String {
    // The context counts every account in the database and lists up to eight of them.
    let mut text = text.to_owned();
    if let Some(i) = text.find("\"representativeIds\": [") {
        let start = i + "\"representativeIds\": [".len();
        if let Some(len) = text[start..].find(']') {
            text.replace_range(start..start + len, "<ids>");
        }
    }
    for key in ["\"users\": ", "\"mailboxes\": "] {
        if let Some(i) = text.find(key) {
            let start = i + key.len();
            let digits = text[start..].bytes().take_while(u8::is_ascii_digit).count();
            text.replace_range(start..start + digits, "<n>");
        }
    }
    let text = text.as_str();
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = ["mailbox:", "user:"]
        .iter()
        .filter_map(|m| rest.find(m).map(|i| (i, *m)))
        .min()
    {
        let (at, marker) = i;
        let end = at + marker.len();
        out.push_str(&rest[..end]);
        let digits = rest[end..].bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            out.push_str("<id>");
        }
        rest = &rest[end + digits..];
    }
    out.push_str(rest);
    out
}

/// Replace run-time ISO timestamps in a document with `<timestamp>`; the fixed `2026-10-0x`
/// seeds stay readable.
fn scrub_times(text: &str) -> String {
    let b = text.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let shaped = i + 19 <= b.len()
            && (0..4).all(|k| digit(i + k))
            && b[i + 4] == b'-'
            && digit(i + 5)
            && digit(i + 6)
            && b[i + 7] == b'-'
            && digit(i + 8)
            && digit(i + 9)
            && b[i + 10] == b'T'
            && digit(i + 11)
            && digit(i + 12)
            && b[i + 13] == b':'
            && digit(i + 14)
            && digit(i + 15)
            && b[i + 16] == b':'
            && digit(i + 17)
            && digit(i + 18);
        if !shaped {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let mut end = i + 19;
        if b.get(end) == Some(&b'.') {
            end += 1;
            while digit(end) {
                end += 1;
            }
        }
        if b.get(end) == Some(&b'Z') {
            end += 1;
        } else if matches!(b.get(end), Some(b'+' | b'-'))
            && digit(end + 1)
            && digit(end + 2)
            && b.get(end + 3) == Some(&b':')
        {
            end += 6;
        }
        if text[i..].starts_with("2026-10-0") {
            out.push_str(&text[i..end]);
        } else {
            out.push_str("<timestamp>");
        }
        i = end;
    }
    out
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("plat2-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "plat2-admin").await?;
    let b = fixture::account(&owner, "plat2-other").await?;
    let case = specs(action, label, a.user, b.user).ok_or("unknown updates action")?;
    let peer = if matches!(action, "deploy-start" | "deploy-cancel") {
        Some(
            super::deploy::Peer::start(if action == "deploy-cancel" {
                "hold"
            } else {
                label
            })
            .await?,
        )
    } else {
        None
    };
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let domain_names = [
        (domain_of(a.domain).await?, "host-a.test"),
        (domain_of(b.domain).await?, "host-b.test"),
    ];
    let control = owner
        .query_opt(
            "SELECT installation_id::text, timeline_id::text FROM upgrade_control_state",
            &[],
        )
        .await?
        .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)));
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        if let Some((installation, timeline)) = &control {
            out = out
                .replace(installation.as_str(), "<installation>")
                .replace(timeline.as_str(), "<timeline>");
        }
        out = out.replace(
            &format!("\"actorId\": \"{}\"", a.user),
            "\"actorId\": \"<admin>\"",
        );
        let out = peer.as_ref().map(|peer| peer.names(&out)).unwrap_or(out);
        let out = if action == "recovery-signals" {
            super::mask_uuids(&out)
        } else {
            out
        };
        let out = if action.starts_with("deploy-") {
            out.replace("0001-01-01T00:00:00Z", "<zero-time>")
        } else {
            out
        };
        pin_identities(&pin_digests(&scrub_times(&out)))
    };
    // Resolve `{{timeline}}` and `{{now[+-]Nh}}` in a request body.
    let mut sent_body = case.body.clone();
    sent_body = sent_body
        .replace("{{admin-mailbox}}", &a.mailbox.to_string())
        .replace("{{other-mailbox}}", &b.mailbox.to_string());
    if let Some((_, timeline)) = &control {
        sent_body = sent_body.replace("{{timeline}}", timeline);
    }
    while let Some(start) = sent_body.find("{{now") {
        let end = sent_body[start..].find("}}").ok_or("unterminated token")? + start;
        let offset = sent_body[start + 5..end].trim_end_matches('h').to_owned();
        let hours: i64 = if offset.is_empty() {
            0
        } else {
            offset.parse()?
        };
        let moment: String = owner
            .query_one(
                "SELECT to_char((now() + make_interval(hours => $1::int)) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
                &[&(hours as i32)],
            )
            .await?
            .get(0);
        sent_body.replace_range(start..end + 2, &moment);
    }
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        "scoped" => (vec![case.perm], Some(b.domain)),
        _ => (vec![case.perm], None),
    };
    let role = format!("plat2-role-{}", a.user);
    owner
        .execute(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)",
            &[&role, &permissions, &scope],
        )
        .await?;
    owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2", &[&a.user, &role]).await?;
    // #542: the deploy and airgap-upload routes now need an organization-wide system.upgrade
    // grant, so the scoped cases observe the process state (and start the cancel fixture's
    // deployment) through a second, organization-wide admin: the other fixture user.
    let probe_role = format!("plat2-probe-{}", b.user);
    let probe_user = if label == "scoped" && action.starts_with("deploy-") {
        owner.execute("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,NULL)", &[&probe_role, &vec![case.perm]]).await?;
        owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2", &[&b.user, &probe_role]).await?;
        b.user
    } else { a.user };
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F08'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let users: Vec<(i64, &str)> = vec![(a.user, "<admin>"), (b.user, "<other>")];
    let recovery_flag = if action.starts_with("recovery-") {
        let old = owner
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
                &[],
            )
            .await?
            .map(|r| r.get::<_, bool>(0));
        owner.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.client_recovery_ingest',true) ON CONFLICT(key) DO UPDATE SET enabled=true").await?;
        if label == "disabled" {
            owner.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.client_recovery_ingest'").await?;
        }
        Some(old)
    } else {
        None
    };
    let airgap = if action.starts_with("airgap-") {
        Some(super::airgap::Fixture::new(a.user, label)?)
    } else {
        None
    };
    let suppressed = if matches!(fault,Some("no-notify"|"statement-failure")) {
        let function = match action {
            "recovery-open" => "mail_recovery_incident_open",
            "recovery-approve" => "mail_recovery_incident_approve",
            "recovery-close" => "mail_recovery_incident_close",
            "recovery-accept" => "mail_recovery_artifact_ingest",
            _ => return Err("unsupported notification fault".into()),
        };
        let original: String = owner
            .query_one(
                "SELECT pg_get_functiondef(oid) FROM pg_proc WHERE proname=$1",
                &[&function],
            )
            .await?
            .get(0);
        if fault==Some("statement-failure") {
            // Fail only after the success path queued its writes/audit/notify.
            let at=original.rfind("RETURN jsonb_build_object").ok_or("missing reducer success return")?;
            let injected=format!("{}RAISE EXCEPTION 'gofree-plat2b late statement failure' USING ERRCODE='XX000';\n{}",&original[..at],&original[at..]);
            owner.batch_execute(&injected).await?;
        } else {
            if !original.contains("PERFORM app_notify(") {return Err("notification seam missing".into());}
            owner.batch_execute("CREATE FUNCTION public.gofree_plat2b_no_notify(text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'").await?;
            owner.batch_execute(&original.replace("PERFORM app_notify(","PERFORM public.gofree_plat2b_no_notify(")).await?;
        }
        Some((function,original))
    } else {
        None
    };
    let mut commit_wire = None;
    let result = async {
        for statement in &case.boot_seed {owner.batch_execute(statement).await?;}
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = if let Some(peer)=&peer {common::go_oracle::start_named_with_env(&db,s3,"gofree-plat2-http",&peer.environment()).await?}else if let Some(fixture)=&airgap {common::go_oracle::start_named_with_env(&db,s3,"gofree-plat2-http",&fixture.environment()).await?}else{common::go_oracle::start_named(&db, s3, None, "gofree-plat2-http").await?};
        let recording = go.is_some();
        if let Some(peer)=&peer {sent_body=peer.body(&sent_body)?;}
        if let Some(fixture)=&airgap {sent_body=sent_body.replace("{{offline-metadata}}",&fixture.upload_metadata);}
        let patient = std::time::Duration::from_secs(30);
        let exec = ScopedExecutor::from_dsn_with(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
            setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
        )
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
        let mut concrete = case.pattern.to_owned();
        for value in &case.fill {
            let start=concrete.find('{').ok_or("missing route placeholder")?;
            let end=start+concrete[start..].find('}').ok_or("unclosed route placeholder")?;
            concrete.replace_range(start..=end,value);
        }
        let recovery_dsn = if matches!(fault,Some("commit-before"|"commit-after")) {
            if recording { return Err("COMMIT-loss cases require native replay".into()); }
            let cut = if fault==Some("commit-after") {common::commit::CommitCut::AfterCommit}else{common::commit::CommitCut::BeforeCommit};
            if let Ok(path)=std::env::var("GOFREE_RESOURCE_LEDGER") {
                use std::io::Write;
                writeln!(std::fs::OpenOptions::new().append(true).open(path)?,"Owned gofree-plat2b in-process COMMIT wire proxy ({cut:?}); joined or aborted after case")?;
            }
            let (dsn, task) = common::commit::commit_cut_proxy(&db.dsn,cut).await;
            commit_wire = Some(task);
            dsn
        } else { db.dsn.clone() };
        let adapter = Probe {
            inner: PlatformUpdatesRoute::new(exec, Arc::new(common::recovery_keys()), "mailserver".into())
                .with_recovery(common::patient_exec(&recovery_dsn, if commit_wire.is_some(){1}else{4})?.with_audit_keys("22".repeat(32), String::new()), true, Some(db.dsn.clone())).await.with_deploy(common::patient_exec(&db.dsn,4)?,peer.as_ref().map(|p|setjoin_platform::deploy::Config::fixed(p.host_key.clone(),"a".repeat(64),("test-access".into(),"test-secret".into()))).unwrap_or_else(setjoin_platform::deploy::Config::environment)).await.with_airgap(airgap.as_ref().map(|f|setjoin_platform::airgap::Store::load(f.root.join("store"),f.root.join("trust.json")).map(Arc::new)).transpose()?),
            changed_status: mutant,
            wrong_schema: fault==Some("wrong-schema"),
            target_method:case.method,
            target_path:format!("/api{concrete}"),
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F08" && r["slice"] == "updates-deploy" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: go.as_ref().map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        for statement in &case.seed {
            owner.batch_execute(statement).await?;
        }
        let effects = async |c: &tokio_postgres::Client| -> Result<Value, BoxError> {
            let primary = json!(super::rows(c, case.effects).await?);
            if case.extra_effects.is_empty() { return Ok(primary); }
            let mut tables = serde_json::Map::new();
            tables.insert(case.table.into(), primary);
            for (table, sql) in &case.extra_effects { tables.insert((*table).into(), json!(super::rows(c,sql).await?)); }
            Ok(Value::Object(tables))
        };
        let bearer = token(a.user, &case.claims);
        if label == "repeat" {
            let uri = format!("/api{concrete}{}", case.query);
            let mut request = Request::builder()
                .method(case.method)
                .uri(uri)
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", case.content_type)
                .header("x-request-id", "gofree-plat2-oracle")
                .header("authorization", format!("Bearer {bearer}"));
            for (name, value) in &case.headers {
                request = request.header(*name, value.as_str());
            }
            let first = common::send(address, request.body(common::full(sent_body.clone()))?).await;
            let first_status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if action=="airgap-upload" {airgap.as_ref().ok_or("missing fixture")?.response(first_status,std::str::from_utf8(&data)?)?;}
            let expected_first=if action=="airgap-upload" {200}else{case.status};
            if case.status != 0 && first_status != expected_first {
                return Err(format!("initial {action}: {first_status} {data:?}").into());
            }
            if action == "deploy-start" {
                let deadline=std::time::Instant::now()+std::time::Duration::from_secs(20);
                loop {
                    let response=common::send(address,Request::get("/api/admin/deploy/status").header("host","mail.test").header("authorization",format!("Bearer {bearer}")).body(common::full(""))?).await;
                    let state:Value=serde_json::from_slice(&common::body_bytes(response).await)?;
                    if matches!(state["status"].as_str(),Some("done"|"failed")){break;}
                    if std::time::Instant::now()>deadline{return Err("repeat deployment did not finish".into());}
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
        let warmup=if action=="deploy-cancel" && !matches!(label,"denied"|"empty") {
            let peer=peer.as_ref().ok_or("missing SSH peer")?;
            let template=json!({"nodes":(1..=3).map(|i|json!({"host":format!("{{{{ssh-node-{i}}}}}"),"role":if i==1{"primary"}else{"standby"},"ssh_user":"root","ssh_key":"{{ssh-inline-key}}","password":"gofree-plat2b-node-password"})).collect::<Vec<_>>()}).to_string();
            let body=peer.body(&template)?;
            let response=common::send(address,Request::post("/api/admin/deploy/start").header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {}",token(probe_user,&case.claims))).body(common::full(body.clone()))?).await;
            let accepted=response.status()==202;let _=common::body_bytes(response).await;
            if !accepted{return Err("cancel warmup deployment was not accepted".into());}
            let start=std::time::Instant::now();while peer.command_count()==0 {if start.elapsed()>std::time::Duration::from_secs(15){return Err("cancel warmup did not reach SSH command".into());}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
            Some(body)
        }else{None};
        let before_process=if let Some(peer)=peer.as_ref().filter(|_|label!="denied"){Some(peer.state(address,&token(probe_user,&case.claims)).await?)}else{None};
        let before_files=airgap.as_ref().map(super::airgap::Fixture::snapshot).transpose()?;
        let before = effects(&owner).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut listeners = vec![];
        for channel in &case.channels {
            let concrete=channel.replace("{{other-mailbox}}",&b.mailbox.to_string());
            listeners.push((concrete.clone(), db.listen(&concrete).await?));
        }
        let uri = format!("/api{concrete}{}", case.query);
        let build = || -> Result<Request<Body>, BoxError> {
            let mut request = Request::builder()
                .method(case.method)
                .uri(uri.clone())
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", case.content_type)
                .header("x-request-id", "gofree-plat2-oracle")
                .header("authorization", format!("Bearer {bearer}"));
            for (name, value) in &case.headers {
                request = request.header(*name, value.as_str());
            }
            Ok(request.body(common::full(sent_body.clone()))?)
        };
        let response = common::send(address, build()?).await;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let mut raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if action=="upgrades-recovery-context" && (status==200 || mutant) {
            let body:Value=serde_json::from_str(&raw)?;
            let schema:i64=owner.query_one("SELECT COALESCE(max(version),0)::bigint FROM schema_migrations",&[]).await?.get(0);
            if body["schemaVersion"].as_i64()!=Some(schema) {
                return Err("recovery context schema version does not match the live database".into());
            }
        }
        if action=="airgap-upload" {raw=airgap.as_ref().ok_or("missing fixture")?.response(status,&raw)?;}
        let after_process=if let Some(peer)=peer.as_ref().filter(|_|label!="denied") {
            let started=std::time::Instant::now();
            loop {let state=peer.state(address,&token(probe_user,&case.claims)).await?;
                if (status!=202 && !mutant) || matches!(state["status"].as_str(),Some("done"|"failed")){break Some(state);}
                if started.elapsed()>std::time::Duration::from_secs(30){return Err("deployment did not finish on fake SSH peer".into());}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }else{None};
        let retry=if action=="deploy-cancel"&&label=="fence" {
            let response=common::send(address,Request::post("/api/admin/deploy/start").header("host","mail.test").header("origin","http://mail.test").header("content-type","application/json").header("authorization",format!("Bearer {bearer}")).body(common::full(warmup.clone().ok_or("missing warmup")?))?).await;
            let status=response.status().as_u16();let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            Some(json!({"status":status,"body":names(&body),"state":masked(peer.as_ref().unwrap().state(address,&bearer).await?,&users,&names)?}))
        }else{None};
        let after = effects(&owner).await?;
        let tags:Vec<(i64,String)>=if action=="recovery-accept" {owner.query("SELECT id,name FROM tags WHERE mailbox_id=$1",&[&b.mailbox]).await?.iter().map(|r|(r.get(0),r.get(1))).collect()}else{vec![]};
        let message:Option<i64>=if action=="recovery-accept" {owner.query_opt("SELECT id FROM messages WHERE mailbox_id=$1 AND message_id='<plat2b-recovered@example.test>'",&[&b.mailbox]).await?.map(|r|r.get(0))}else{None};
        let mut audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last])
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        for row in &mut audit {
            if action=="recovery-accept" && row["action"]=="mail_recovery_artifact_accept" {
                if row["target_id"].as_i64()!=message || row["after_state"]["mailboxId"]!=json!(b.mailbox.to_string()) {return Err("accept audit does not link the recovered message and affected mailbox".into());}
            }
            if row["id"].as_i64().is_none_or(|n| n <= 0) {
                return Err("invalid audit id".into());
            }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                    row[key] = json!("<checksum>");
                }
            }
            *row = masked(row.clone(), &users, &names)?;
        }
        let mut notify = vec![];
        for (channel, listener) in &mut listeners {
            for event in listener.drain(&owner).await? {
                let payload = serde_json::from_str::<Value>(&event).unwrap_or(json!(event));
                let channel=channel.replace(&format!("tag:{}",b.mailbox),"tag:<other-mailbox>");
                notify.push(json!({"channel":channel,"payload":masked(payload, &users, &names)?}));
            }
        }
        if !mutant && fault.is_none() && case.status != 0 && status != case.status {
            return Err(format!("Go {action}/{label}: expected {}, got {status}: {raw}", case.status).into());
        }
        if action=="recovery-accept" {
            for row in &mut audit { accept_refs(row,None,&tags,message,b.mailbox); }
            for event in &mut notify { accept_refs(event,None,&tags,message,b.mailbox); }
        }
        let mut text = names(&raw);
        if let Some(message)=message { text=text.replace(&format!("\"messageId\": \"{message}\""),"\"messageId\": \"<message>\""); }
        for (from, to) in &case.replace {
            text = text.replace(from.as_str(), to);
        }
        text = pin_load_values(&text);
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        if case.method!="HEAD" || label=="invalid" {if let Some(length) = headers.get_mut("content-length") {
            *length = json!([text.len().to_string()]);
        }}
        let (mut before, mut after) = (before, after);
        if action == "recovery-open" {
            open_bindings(&mut before, case.table, &bearer, &sent_body)?;
            open_bindings(&mut after, case.table, &bearer, &sent_body)?;
        }
        if action=="recovery-accept" {
            for value in [&mut before,&mut after] {
                if let Some(rows)=value["mailboxes"].as_array_mut() {for row in rows {if row["domain_id"]==json!(b.domain) {row["domain_id"]=json!("<other-domain>");}}}
                for (table,rows) in value.as_object_mut().ok_or("accept tables")? { accept_refs(rows,Some(table.as_str()),&tags,message,b.mailbox); }
            }
        }
        let mailboxes = [(a.mailbox,"<admin-mailbox>"),(b.mailbox,"<other-mailbox>")];
        if action.starts_with("recovery-") { mailbox_names(&mut before,&mailboxes); mailbox_names(&mut after,&mailboxes); }
        let (before, after) = (masked(before, &users, &names)?, masked(after, &users, &names)?);
        let effects = if case.extra_effects.is_empty() {
            json!([{"table":case.table,"before":before,"after":after}])
        } else {
            json!(std::iter::once(case.table).chain(case.extra_effects.iter().map(|(t,_)| *t)).map(|table|
                json!({"table":table,"before":before[table],"after":after[table]})
            ).collect::<Vec<_>>())
        };
        let mut req = json!({"method":case.method,"path":case.pattern,"external_path":format!("/api{concrete}")});
        if !case.body.is_empty() {
            req["body"] = json!(names(&case.body));
        }
        if !case.query.is_empty() {
            req["query"] = json!(case.query);
        }
        let mut observation = json!({"request":req,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if action=="upgrades-recovery-context" { context_observation(&mut observation)?; }
        if let Some(peer)=&peer {
            if matches!(label,"invalid-utf8"|"truncated-utf8") {
                observation["deploy_status_wire"] = json!(names(&peer.state_wire(address,&bearer).await?));
            }
            observation["ssh"]=peer.observation()?;
            if let Some(retry)=retry {observation["retry"]=retry;}
            let before=masked(json!(before_process),&users,&names)?;let after=masked(json!(after_process),&users,&names)?;
            observation["effects"].as_array_mut().ok_or("effects array")?.push(json!({"table":"deploy_process_state","before":before,"after":after}));
        }
        if let Some(fixture)=&airgap { observation["effects"].as_array_mut().ok_or("effects array")?.push(json!({"table":"airgap_files","before":before_files,"after":fixture.snapshot()?})); }
        if action=="recovery-accept" { let mut wrapper=json!({"observation":observation});accept_recording(&mut wrapper);observation=wrapper["observation"].take(); }
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F08\"} 0") {
                return Err(format!("F08 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let stem = if action.starts_with(group(action)) { format!("{action}-{label}") } else { format!("{}-{action}-{label}", group(action)) };
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/platform/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{stem}.json"));
        let row_file = dir.join(format!("{stem}-row-effects.json"));
        let route_name = format!("{} {}", if case.method=="HEAD" {"GET"}else{case.method}, case.pattern);
        let record: fn(&std::path::Path,&Value)->Result<(),BoxError> = match action {
            "recovery-accept" => accept_record,
            "upgrades-recovery-context" => context_record,
            _ => record,
        };
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let mut expected = common::golden_doc(&file, "observation", &observation);
            if action=="upgrades-recovery-context" { context_observation(&mut expected["observation"])?; }
            if action=="recovery-accept" {accept_recording(&mut expected);}
            if let Some(body) = expected["observation"]["response"]["body"].as_str() {
                expected["observation"]["response"]["body"] = json!(pin_load_values(body));
            }
            if matches!(fault,Some("commit-before"|"commit-after")) {
                let cut = tokio::time::timeout(std::time::Duration::from_secs(10),commit_wire.take().ok_or("missing COMMIT proxy")?).await???;
                let committed = fault==Some("commit-after");
                if (cut==common::commit::CommitCut::AfterCommit)!=committed || status!=503 || raw!="{\"type\":\"about:blank\",\"title\":\"Service Unavailable\",\"status\":503,\"detail\":\"operation outcome unknown\",\"instance\":\"\"}\n" {
                    return Err(format!("COMMIT loss must return HTTP Unknown, never success: status={status}, cut={cut:?}, body={raw:?}").into());
                }
                let operation=observation["response"]["headers"]["x-operation-id"][0].as_str().ok_or("Unknown response omitted operation ID")?;
                if operation.len()!=32 || !operation.bytes().all(|b|b.is_ascii_hexdigit()) { return Err("invalid Unknown operation ID".into()); }
                let command=match action {
                    "recovery-open"=>"mail_recovery_incident_open",
                    "recovery-approve"=>"mail_recovery_incident_approve",
                    "recovery-close"=>"mail_recovery_incident_close",
                    "recovery-accept"=>"mail_recovery_artifact_ingest",
                    _=>return Err("unsupported COMMIT-loss route".into()),
                };
                let receipt:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F08' AND command=$2)",&[&operation,&command]).await?.get(0);
                if receipt!=committed { return Err("durable receipt disagrees with actual COMMIT outcome".into()); }
                if committed {
                    for key in ["effects","audit","notify"] { golden::compare(&expected["observation"][key],&observation[key])?; }
                } else {
                    for effect in observation["effects"].as_array().ok_or("effect snapshots")? { golden::compare(&effect["before"],&effect["after"])?; }
                    if observation["audit"]!=json!([]) || observation["notify"]!=json!([]) {return Err("aborted transaction published audit/notify effects".into());}
                }
                eprintln!("COMMIT-LOSS-VERIFIED: {route_name} :: {}",fault.unwrap());
                return Ok(());
            }
            if fault==Some("statement-failure") {
                if status!=500 {return Err(format!("late statement failure must return500, got{status}").into());}
                for effect in observation["effects"].as_array().ok_or("effect snapshots")? { golden::compare(&effect["before"],&effect["after"])?; }
                if observation["audit"]!=json!([]) || observation["notify"]!=json!([]) {return Err("failed statement published audit/notify effects".into());}
                let count:i64=owner.query_one("SELECT count(*) FROM rust_operation_receipts WHERE family='F08' AND operation_id::text<>ALL($1)",&[&receipts]).await?.get(0);
                if count!=0 {return Err("failed statement committed a receipt".into());}
                eprintln!("STATEMENT-ROLLBACK-VERIFIED: {route_name}");
                return Ok(());
            }
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") {
                    return Err(format!("mutant failed outside response status: {error}").into());
                }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(fault) = fault {
                eprintln!("FAULT-OBSERVED {fault}: {status}");
                let error = compared.err().ok_or("planted family fault survived")?;
                if fault=="no-notify" && !error.contains("/notify") { return Err(format!("notification fault failed outside notify: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: {fault}");
                return Ok(());
            }
            compared?;
            let mut expected = common::golden_doc(&row_file, "effects", &observation["effects"]);
            if action=="recovery-accept" {accept_recording(&mut expected);}
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    if let Some(task) = commit_wire { task.abort(); }
    if let Some((function,original)) = suppressed {
        owner.batch_execute(&original).await?;
        let restored:String=owner.query_one("SELECT pg_get_functiondef(oid) FROM pg_proc WHERE proname=$1",&[&function]).await?.get(0);
        if restored!=original {return Err("reducer definition did not restore exactly".into());}
        if fault==Some("no-notify") {owner.batch_execute("DROP FUNCTION public.gofree_plat2b_no_notify(text,text)").await?;}
    }
    if let Some(old) = recovery_flag {
        if let Some(enabled) = old {
            owner.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.client_recovery_ingest'", &[&enabled]).await?;
        } else {
            owner
                .batch_execute(
                    "DELETE FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
                )
                .await?;
        }
    }
    for statement in &case.cleanup {
        owner.batch_execute(statement).await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F08' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role])
        .await?;
    if probe_user == b.user {
        owner.execute("DELETE FROM admin_role_assignments WHERE user_id=$1", &[&b.user]).await?;
        owner.execute("DELETE FROM admin_role_groups WHERE name=$1", &[&probe_role]).await?;
    }
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}
