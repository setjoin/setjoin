//! Write half of the `idv2-sources` oracle: source lifecycle, job cancel and conflict
//! decision. The fixture is the read oracle's; this module builds the request, runs it
//! (twice for `repeat`), and observes the wire, the rows the reducers changed
//! (before/after) and the notifications they sent.
use super::{
    admin_token, mask_text, masked, record, scrub_instants, ALPHA_KEY, BETA_KEY, C1, C2, C3,
    GAMMA_KEY, J_DONE, J_OTHER, J_RUNNING, J_UPGRADE, MISSING_UUID,
};
use crate::common::{self, BoxError};
use hyper::Request;
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};

pub const DELTA_KEY: &str = "admin7-delta";
const IDEM: &str = "95300000-0000-4000-8000-000000000001";
const IDEM_OTHER: &str = "95300000-0000-4000-8000-000000000002";
const REASON: &str = "admin7 reason <&>";

pub fn is_write(action: &str) -> bool {
    matches!(
        action,
        "pause" | "resume" | "retire" | "activate" | "cancel" | "decision"
    ) || super::write2::is_write(action)
}

pub struct Ctx<'a> {
    pub codec: &'a setjoin_config_secret::ConfigSecretCodec,
    pub address: std::net::SocketAddr,
    pub recording: bool,
    pub db: &'a Db,
    pub owner: &'a tokio_postgres::Client,
    pub users: &'a [(i64, &'a str)],
    pub names: &'a dyn Fn(&str) -> String,
    pub admin: i64,
    pub other_domain: i64,
    pub action: &'a str,
    pub label: &'a str,
    pub mutant: bool,
    pub fault: Option<&'a str>,
}

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "pause" => ("POST", "/admin/identity/v2/sources/{sourceKey}/pause"),
        "resume" => ("POST", "/admin/identity/v2/sources/{sourceKey}/resume"),
        "retire" => ("POST", "/admin/identity/v2/sources/{sourceKey}/retire"),
        "activate" => ("POST", "/admin/identity/v2/sources/{sourceKey}/activate"),
        "cancel" => ("POST", "/admin/identity/v2/jobs/{id}/cancel"),
        "decision" => ("POST", "/admin/identity/v2/conflicts/{id}/decision"),
        other => super::write2::route(other),
    }
}

/// Permissions of the governing role for a case.
pub fn permissions(action: &str, label: &str) -> Vec<&'static str> {
    if action == "mappings-put" {
        return match label {
            "denied" => vec!["users.read"],
            "with-role" | "unknown-role" => vec![
                "users.read",
                "audit.read",
                "identity.write",
                "roles.manage",
                "reports.read",
            ],
            "role-perm-missing" => {
                vec!["users.read", "audit.read", "identity.write", "roles.manage"]
            }
            _ => vec!["users.read", "audit.read", "identity.write"],
        };
    }
    if super::write2::is_write(action) && label != "denied" {
        return vec!["users.read", "audit.read", "identity.write"];
    }
    match label {
        "denied" => vec!["users.read"],
        _ if action == "cancel" => vec!["users.read", "audit.read", "audit.export"],
        _ => vec!["users.read", "audit.read", "identity.write"],
    }
}

/// The fixtures every write case adds on top of the read fixture (jobs, a validated source).
pub async fn fixtures(
    owner: &tokio_postgres::Client,
    a: i64,
    b: i64,
    alpha: i64,
) -> Result<(), BoxError> {
    owner
        .execute(
            "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,generation,mapping_version) VALUES \
             ('admin7-delta','Admin7 Delta','scim','{\"authenticate\": false, \"provision_lifecycle\": true, \"stable_immutable_subject\": true}'::jsonb,'validated',2,1)",
            &[],
        )
        .await?;
    for (id, kind, state, actor, source, key) in [
        (J_DONE, "diagnostics", "completed", a, Some(alpha), 1u8),
        (J_RUNNING, "diagnostics", "queued", a, Some(alpha), 2),
        (J_OTHER, "diagnostics", "completed", b, Some(alpha), 3),
        (J_UPGRADE, "upgrade_backfill", "completed", a, None, 4),
    ] {
        owner
            .execute(
                "INSERT INTO identity_jobs(id,kind,state,actor_user_id,source_id,snapshot_id,idempotency_key,request_digest,request,progress,next_action,reason,cancel_requested,created_at,updated_at,completed_at,expires_at) \
                 VALUES($1::text::uuid,$2,$3,$4,$5,$1::text::uuid,('95200000-0000-4000-8000-00000000000'||$6::text)::uuid,decode(repeat('0e',32),'hex'),'{\"sourceKey\": \"admin7-alpha\"}'::jsonb,'{\"failed\": 0, \"processed\": 7}'::jsonb,'wait','seeded',false,\
                 '2026-10-01T00:00:00Z','2026-10-01T00:00:00Z',CASE WHEN $3='queued' THEN NULL ELSE '2026-10-02T00:00:00.5Z'::timestamptz END,'2026-10-07T00:00:00Z')",
                &[&id, &kind, &state, &actor, &source, &key.to_string()],
            )
            .await?;
    }
    Ok(())
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

/// Every row a write route can change, for the fixture only.
async fn snapshot(
    c: &tokio_postgres::Client,
    codec: &setjoin_config_secret::ConfigSecretCodec,
    mappings: bool,
    with_envelopes: bool,
) -> Result<Value, BoxError> {
    let mut envelopes = Vec::new();
    for row in c.query("SELECT source_key, config_key_version, config_envelope FROM identity_sources WHERE source_key LIKE 'admin7-%' AND config_envelope IS NOT NULL AND octet_length(config_envelope) > 0 ORDER BY source_key", &[]).await? {
        let key: String = row.get(0);
        let sealed: Vec<u8> = row.get(2);
        let plain = match codec.decrypt(&format!("identity_source.{key}"), &sealed) {
            Ok(bytes) => serde_json::from_slice::<Value>(&bytes).unwrap_or_else(|_| json!("<not json>")),
            Err(_) => json!("<undecryptable>"),
        };
        let port = super::write2::PROBE_PORT.load(std::sync::atomic::Ordering::SeqCst);
        let plain = if port == 0 {
            plain
        } else {
            serde_json::from_str(&plain.to_string().replace(&format!("\"port\":{port}"), "\"port\":\"<probe-port>\""))?
        };
        envelopes.push(json!({"key": key, "key_version": row.get::<_, i64>(1), "plaintext": plain}));
    }
    let mut out = json!({
        "envelopes": envelopes,
        "sources": rows(c, "SELECT jsonb_build_object('key',source_key,'state',state,'generation',generation,'mapping_version',mapping_version,'updated_by',updated_by,'config_key_version',config_key_version)::text FROM identity_sources WHERE source_key LIKE 'admin7-%' ORDER BY source_key").await?,
        "events": rows(c, "SELECT jsonb_build_object('action',e.action,'reason',e.reason,'actor_user_id',e.actor_user_id,'user_id',e.user_id,'source',s.source_key,'has_link',e.link_id IS NOT NULL,'generation',e.metadata->'generation')::text FROM identity_link_events e JOIN identity_sources s ON s.id=e.source_id WHERE s.source_key LIKE 'admin7-%' AND e.action NOT IN ('link_activated','source_created','link_detached') ORDER BY e.id").await?,
        "operations": rows(c, "SELECT jsonb_build_object('key',o.idempotency_key,'source',s.source_key,'actor_user_id',o.actor_user_id,'operation',o.operation,'result',o.result-'sourceId')::text FROM identity_source_operations o JOIN identity_sources s ON s.id=o.source_id WHERE s.source_key LIKE 'admin7-%' ORDER BY o.idempotency_key").await?,
        "candidates": rows(c, "SELECT jsonb_build_object('id',id,'status',status,'generation',generation,'decided_by',decided_by,'reason',decision_reason,'decided',decided_at IS NOT NULL)::text FROM identity_match_candidates WHERE id::text LIKE '95000000-%' ORDER BY id").await?,
        "decisions": rows(c, "SELECT jsonb_build_object('candidate',candidate_id,'decision',decision,'reason',reason,'decided_by',decided_by,'has_person',person_id IS NOT NULL,'has_link',link_id IS NOT NULL)::text FROM identity_match_decisions WHERE candidate_id::text LIKE '95000000-%' ORDER BY occurred_at,id").await?,
        "links": rows(c, "SELECT jsonb_build_object('user_id',l.user_id,'source',s.source_key,'state',l.state,'subject',l.external_subject)::text FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE s.source_key LIKE 'admin7-%' ORDER BY s.source_key,l.external_subject").await?,
        "jobs": rows(c, "SELECT jsonb_build_object('id',id,'state',state,'cancel_requested',cancel_requested,'next_action',next_action,'terminal',completed_at IS NOT NULL)::text FROM identity_jobs WHERE id::text LIKE '95100000-%' ORDER BY id").await?,
    });
    if !with_envelopes {
        out.as_object_mut().expect("snapshot").remove("envelopes");
    }
    if mappings {
        out["saml"] = json!(rows(c, "SELECT jsonb_build_object('idp',idp_entity_id,'group_mappings',group_mappings)::text FROM saml_sp_registrations WHERE idp_entity_id LIKE 'admin7-%' ORDER BY idp_entity_id").await?);
        out["oidc"] = json!(rows(c, "SELECT jsonb_build_object('key',key,'value',value)::text FROM system_config WHERE key LIKE 'oidc_provider_admin7%' ORDER BY key").await?);
        out["authority"] = json!(rows(c, "SELECT jsonb_build_object('value',value)::text FROM system_config WHERE key='sso_admin_role_grant_authority'").await?);
    }
    Ok(out)
}

pub struct Plan {
    pub method: &'static str,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub shown_body: String,
    pub repeat: bool,
    /// Headers added to the second request of a `repeat`.
    pub repeat_headers: Vec<(String, String)>,
    pub wanted: u16,
}

fn plan(c: &Ctx<'_>) -> Plan {
    if super::write2::is_write(c.action) {
        return super::write2::plan(c);
    }
    let (action, label) = (c.action, c.label);
    let lifecycle = matches!(action, "pause" | "resume" | "retire" | "activate");
    let (_, pattern) = route(action);
    let mut headers: Vec<(String, String)> = vec![
        ("content-type".into(), "application/json".into()),
        ("x-audit-reason".into(), REASON.into()),
        ("idempotency-key".into(), IDEM.into()),
    ];
    let mut wanted = if action == "decision" { 200 } else { 202 };
    let mut repeat = false;
    let target = match (action, label) {
        (_, "missing-source") => "admin7-nothing".to_string(),
        (_, "bad-source-key") => "-bad".to_string(),
        ("pause", "illegal") => GAMMA_KEY.to_string(),
        ("pause", _) => ALPHA_KEY.to_string(),
        ("resume", _) => BETA_KEY.to_string(),
        ("retire", _) => GAMMA_KEY.to_string(),
        ("activate", _) => DELTA_KEY.to_string(),
        ("cancel", l) => match l {
            "other-actor" => J_OTHER.to_string(),
            "missing" => "95100000-0000-4000-8000-0000000000ff".to_string(),
            "bad-id" => "bad".to_string(),
            "kind-denied" => J_UPGRADE.to_string(),
            "terminal" => J_DONE.to_string(),
            _ => J_RUNNING.to_string(),
        },
        ("decision", l) => match l {
            "foreign" => C3.to_string(),
            "no-user" | "soft-link" => C2.to_string(),
            "missing" => MISSING_UUID.to_string(),
            "bad-conflict-id" => "bad".to_string(),
            _ => C1.to_string(),
        },
        _ => String::new(),
    };
    let generation = match (action, label) {
        (_, "stale") => "999".to_string(),
        ("pause", "illegal") => "1".to_string(),
        ("pause", _) => "3".to_string(),
        ("resume", _) => "5".to_string(),
        ("retire", _) => "1".to_string(),
        ("activate", _) => "2".to_string(),
        _ => "3".to_string(),
    };
    if lifecycle || action == "decision" {
        headers.push(("if-match".into(), format!("\"{generation}\"")));
    }
    let mut body = if lifecycle {
        json!({"expectedGeneration": generation, "idempotencyKey": IDEM, "reason": REASON})
            .to_string()
    } else if action == "decision" {
        let decision = match label {
            "defer" => "defer",
            "bad-decision" => "approve",
            "link-no-person" | "soft-link" => "link",
            _ => "reject",
        };
        let mut v = json!({"decision": decision, "expectedGeneration": generation, "idempotencyKey": IDEM, "reason": REASON});
        match label {
            "soft-link" | "bad-person-zero" => {
                v["personId"] = json!(if label == "soft-link" {
                    c.admin.to_string()
                } else {
                    "0".into()
                });
            }
            "person-on-reject" => {
                v["personId"] = json!("7");
            }
            "bad-person" => {
                v["personId"] = json!("x");
            }
            _ => {}
        }
        v.to_string()
    } else {
        String::new()
    };
    let mut shown = body.clone();
    if label == "soft-link" {
        shown = shown.replace(&c.admin.to_string(), "<admin>");
    }
    let mut set_wanted = |w: u16| wanted = w;
    match label {
        "repeat" => repeat = true,
        "scoped" => set_wanted(if action == "decision" { 200 } else { 403 }),
        "denied" => set_wanted(403),
        "bad-json" => {
            body = "{\"expectedGeneration\":".into();
            shown = body.clone();
            set_wanted(400)
        }
        "unknown-field" => {
            body = body.replacen('{', "{\"extra\":1,", 1);
            shown = body.clone();
            set_wanted(400)
        }
        "typed" => {
            body = body.replace(&format!("\"{generation}\""), &generation);
            shown = body.clone();
            set_wanted(400)
        }
        "trailing" => {
            body.push_str(" {}");
            shown = body.clone();
            set_wanted(400)
        }
        "null-body" => {
            body = "null".into();
            shown = body.clone();
            set_wanted(400)
        }
        "oversize" => {
            shown = format!("{{\"reason\":\"<70000 x>\"}}");
            body = format!("{{\"reason\":\"{}\"}}", "x".repeat(70000));
            set_wanted(413)
        }
        "bad-generation" => {
            body = body.replace(&format!("\"{generation}\""), "\"0\"");
            shown = body.clone();
            set_wanted(400)
        }
        "no-if-match" => {
            headers.retain(|(k, _)| k != "if-match");
            set_wanted(412)
        }
        "key-mismatch" => {
            headers.retain(|(k, _)| k != "idempotency-key");
            headers.push(("idempotency-key".into(), IDEM_OTHER.into()));
            set_wanted(400)
        }
        "bad-key" => {
            headers.retain(|(k, _)| k != "idempotency-key");
            headers.push(("idempotency-key".into(), "not-a-uuid".into()));
            body = body.replace(IDEM, "not-a-uuid");
            shown = body.clone();
            set_wanted(400)
        }
        "reason-mismatch" => {
            headers.retain(|(k, _)| k != "x-audit-reason");
            headers.push(("x-audit-reason".into(), "another reason".into()));
            set_wanted(400)
        }
        "reason-required" => {
            headers.retain(|(k, _)| k != "x-audit-reason");
            set_wanted(400)
        }
        "stale" | "illegal" | "idem-reuse" => set_wanted(409),
        "missing-source" | "bad-source-key" => set_wanted(400),
        "etag-match" => {
            headers.push(("if-none-match".into(), "\"4\"".into()));
            set_wanted(304)
        }
        "other-actor" | "missing" | "foreign" => set_wanted(404),
        "bad-id" | "bad-conflict-id" | "bad-decision" | "link-no-person" | "person-on-reject"
        | "bad-person" | "bad-person-zero" => set_wanted(400),
        "kind-denied" | "no-user" => set_wanted(403),
        "soft-link" => set_wanted(422),
        _ => {}
    }
    if action == "cancel" {
        body.clear();
        shown.clear();
        headers.retain(|(k, _)| k == "content-type" || k == "if-none-match");
        if label == "etag-match" {
            set_wanted(304)
        }
    }
    let path = pattern
        .replace("{sourceKey}", &target)
        .replace("{id}", &target);
    Plan {
        method: "POST",
        path,
        headers,
        body,
        shown_body: shown,
        repeat,
        repeat_headers: vec![],
        wanted,
    }
}

/// Runs one case; a planted family fault (`no-notify`) replaces `app_notify` with a no-op
/// for the case only and must make the golden comparison fail.
pub async fn case(c: Ctx<'_>) -> Result<(), BoxError> {
    // The mint-authority record is seeded configuration: put it back after every case.
    let saved: Option<(String, bool, Option<String>)> = c
        .owner
        .query(
            "SELECT value::text,encrypted,description FROM system_config WHERE key='sso_admin_role_grant_authority'",
            &[],
        )
        .await?
        .first()
        .map(|r| (r.get(0), r.get(1), r.get(2)));
    let result = case_faulted(Ctx { ..c }).await;
    c.owner
        .execute(
            "DELETE FROM system_config WHERE key='sso_admin_role_grant_authority'",
            &[],
        )
        .await?;
    if let Some((value, encrypted, description)) = saved {
        c.owner
            .execute("INSERT INTO system_config(key,value,encrypted,description) VALUES('sso_admin_role_grant_authority',$1::text::jsonb,$2,$3)", &[&value, &encrypted, &description])
            .await?;
    }
    result
}

async fn case_faulted(c: Ctx<'_>) -> Result<(), BoxError> {
    if c.recording && c.fault.is_some() {
        return Ok(());
    }
    if c.fault != Some("no-notify") {
        return case_inner(c).await;
    }
    let saved: String = c
        .owner
        .query_one(
            "SELECT pg_get_functiondef('public.app_notify(text,text)'::regprocedure)",
            &[],
        )
        .await?
        .get(0);
    c.owner.batch_execute("CREATE OR REPLACE FUNCTION public.app_notify(p_channel text, p_payload text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN NULL; END; $$").await?;
    let result = case_inner(Ctx { ..c }).await;
    c.owner.batch_execute(&saved).await?;
    result
}

async fn case_inner(c: Ctx<'_>) -> Result<(), BoxError> {
    let p = plan(&c);
    let (_, pattern) = route(c.action);
    let method = p.method;
    // Per-case database setup.
    match (c.action, c.label) {
        (_, "reason-required") => {
            c.owner.batch_execute("UPDATE audit_policy SET reason_required_areas = reason_required_areas || ARRAY['identity']::text[] WHERE id=1 AND NOT ('identity'=ANY(reason_required_areas))").await?;
        }
        ("pause", "idem-reuse") => {
            c.owner.batch_execute(&format!("INSERT INTO identity_source_operations(idempotency_key,source_id,actor_user_id,operation,request_digest,result) SELECT '{IDEM}'::uuid,id,{},'retire',decode(repeat('0f',32),'hex'),'{{}}'::jsonb FROM identity_sources WHERE source_key='admin7-alpha'", c.admin)).await?;
        }
        ("cancel", "running-job") => {
            c.owner.batch_execute("UPDATE identity_jobs SET state='running',worker_id=gen_random_uuid(),lease_expires_at=now()+interval '1 hour',started_at='2026-10-01T00:00:01Z' WHERE id::text='95100000-0000-4000-8000-000000000002'").await?;
        }
        _ => {}
    }
    super::write2::seal_fixtures(c.owner, c.codec, c.action, c.label).await?;
    super::write2::mapping_fixtures(c.owner, c.action).await?;

    let mut notify_listener = c.db.listen("config_changed").await?;
    let before = snapshot(
        c.owner,
        c.codec,
        c.action == "mappings-put",
        super::write2::is_write(c.action),
    )
    .await?;
    let audit_from: i64 = c
        .owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let send = |extra: Vec<(String, String)>| {
        let token = admin_token(c.admin);
        let uri = format!("/api{}", p.path);
        let mut headers = p.headers.clone();
        headers.extend(extra);
        let body = p.body.clone();
        async move {
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("x-request-id", "gofree-admin7-oracle")
                .header("authorization", format!("Bearer {token}"));
            for (k, v) in headers {
                request = request.header(k, v);
            }
            Ok::<_, BoxError>(common::send(c.address, request.body(common::full(body))?).await)
        }
    };
    let (mut first_status, mut first_text) = (None, None);
    if p.repeat {
        let first = send(vec![]).await?;
        first_status = Some(first.status().as_u16());
        first_text = Some(String::from_utf8(common::body_bytes(first).await.to_vec())?);
    }
    let response = send(p.repeat_headers.clone()).await?;
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for name in response.headers().keys() {
        headers.insert(
            name.to_string(),
            json!(response
                .headers()
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect::<Vec<_>>()),
        );
    }
    let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    if c.recording && status != p.wanted {
        return Err(format!(
            "Go {}/{}: expected {}, got {status}: {raw}",
            c.action, c.label, p.wanted
        )
        .into());
    }
    let after = snapshot(
        c.owner,
        c.codec,
        c.action == "mappings-put",
        super::write2::is_write(c.action),
    )
    .await?;
    let notify_raw = notify_listener.drain(c.owner).await?;
    let mut audit: Vec<Value> = c
        .owner
        .query(
            "SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",
            &[&audit_from],
        )
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
        .collect::<Result<_, _>>()?;
    for row in &mut audit {
        if row["id"].as_i64().is_none_or(|n| n <= 0) {
            return Err("invalid audit id".into());
        }
        row["id"] = json!("<audit>");
        for key in ["checksum", "prev_checksum"] {
            if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                row[key] = json!("<checksum>");
            }
        }
        let shown = masked(row.clone(), c.users, c.names)?;
        *row = serde_json::from_str(
            &shown
                .to_string()
                .replace(&format!("domain={}", c.other_domain), "domain=<scope>"),
        )?;
    }
    let mut notify = Vec::new();
    for event in notify_raw {
        let payload: Value = serde_json::from_str(&event)?;
        let mut payload = masked(payload, c.users, c.names)?;
        // The notified source row id is sequence-issued.
        if let Some(object) = payload.as_object_mut() {
            for key in ["key", "source_id"] {
                if object.contains_key(key) {
                    object.insert(key.to_string(), json!("<source>"));
                }
            }
        }
        notify.push(json!({"channel":"config_changed","payload":payload}));
    }
    let wire_etag = headers.get("etag").cloned();
    if let Some(date) = headers.get_mut("date") {
        *date = json!(["<timestamp>"]);
    }
    if let Some(tag) = headers.get_mut("etag") {
        // Source and decision writes version by generation, a job cancel by the body hash.
        if tag[0].as_str().is_some_and(|t| t.len() == 66) {
            *tag = json!(["<etag>"]);
        }
    }
    let _ = wire_etag;
    let volatile = |raw: &str| -> String {
        let mut text = scrub_instants(&mask_text(&(c.names)(raw), c.users));
        // Source row ids in the reducer's result are sequence-issued.
        for marker in ["\"sourceId\":\"", "\"sourceId\": \""] {
            if let Some(at) = text.find(marker) {
                let from = at + marker.len();
                if let Some(len) = text[from..].find('"') {
                    text.replace_range(from..from + len, "<source-id>");
                }
            }
        }
        text
    };
    let text = volatile(&raw);
    if let Some(length) = headers.get_mut("content-length") {
        if length[0] != raw.len().to_string() {
            return Err("bad wire length".into());
        }
        *length = json!([text.len().to_string()]);
    }
    let (before, after) = (
        masked(before, c.users, c.names)?,
        masked(after, c.users, c.names)?,
    );
    let effects = json!([{"table":"identity","before":before,"after":after}]);
    let mut request =
        json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
    let shown_headers: Vec<&str> = p.headers.iter().map(|(k, _)| k.as_str()).collect();
    request["headers"] = json!(shown_headers);
    if !p.shown_body.is_empty() {
        request["body"] = json!((c.names)(&p.shown_body));
    }
    let mut observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
    if let (Some(s), Some(t)) = (first_status, first_text) {
        observation["first"] = json!({"status": s, "body": volatile(&t)});
    }
    // Cleanup of per-case policy changes.
    if c.label == "reason-required" {
        c.owner.batch_execute("UPDATE audit_policy SET reason_required_areas = array_remove(reason_required_areas,'identity') WHERE id=1").await?;
    }
    if !c.recording {
        let metrics = common::send(
            c.address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
        if !metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0")
        {
            return Err(format!("F01 replay forwarded to Go: {metrics}").into());
        }
    }
    let name = format!("{}-{}", c.action, c.label);
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/admin-identity/goldens");
    std::fs::create_dir_all(&dir)?;
    let file = dir.join(format!("idv2-{name}.json"));
    let row_file = dir.join(format!("idv2-{name}-row-effects.json"));
    let route_name = format!("{method} {pattern}");
    if c.recording {
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        record(
            &file,
            &json!({"format":1,"route":route_name,"case":c.label,"go_source":source,"observation":observation}),
        )?;
        record(
            &row_file,
            &json!({"format":1,"route":route_name,"case":format!("{}-row-effects", c.label),"go_source":source,"effects":observation["effects"]}),
        )?;
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
        let compared = golden::compare(&expected["observation"], &observation);
        if c.mutant {
            let error = compared.err().ok_or("planted status mutant survived")?;
            if !error.contains("/response/status") {
                return Err(format!("mutant failed outside response status: {error}").into());
            }
            eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
            return Ok(());
        }
        if let Some(fault) = c.fault {
            compared.err().ok_or("planted family fault survived")?;
            eprintln!("MUTANT-REJECTED: {route_name} :: {fault}");
            return Ok(());
        }
        compared?;
        let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
        golden::compare(&expected["effects"], &observation["effects"])?;
        eprintln!("GOLDEN-REPLAY: {route_name} :: {}", c.label);
    }
    Ok(())
}
