//! F01 slice `idv2-sources`, read half: frozen-Go oracle for the identity v2 list and
//! detail routes (sources, people, conflicts, events). Record mode runs the covered Go
//! binary behind the front door; replay serves the same requests from Rust with no Go
//! upstream. Reads change no rows, so an observation is the wire plus the audit rows a
//! denial writes.
//!
//! Parallel safety: cases share the fixed `admin7-*` sources, the F01 receipts and the
//! admin audit window, so each holds `SERIAL` for its whole run.
use crate::common::{self, BoxError};
pub mod trans;
pub mod write;
pub mod write2;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_identity_v2::AdminIdentityV2Route, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: AdminIdentityV2Route<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
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

fn secret_env(name: &str) -> Option<String> {
    (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
}

fn route(action: &str) -> &'static str {
    match action {
        "sources" => "/admin/identity/v2/sources",
        "people" => "/admin/identity/v2/people",
        "person" => "/admin/identity/v2/people/{id}",
        "conflicts" => "/admin/identity/v2/conflicts",
        "conflict" => "/admin/identity/v2/conflicts/{id}",
        "events" => "/admin/identity/v2/events",
        "mappings" => "/admin/identity/group-mappings",
        "inventory" => "/admin/identity/inventory",
        "export" => "/admin/identity/v2/inventory/export",
        "job" => "/admin/identity/v2/jobs/{id}",
        "results" => "/admin/identity/v2/jobs/{id}/results",
        "source" => "/admin/identity/v2/sources/{sourceKey}",
        "source-export" => "/admin/identity/v2/sources/{sourceKey}/export",
        w if trans::handles(w) => trans::route(w).1,
        w if write::is_write(w) => write::route(w).1,
        _ => panic!("unknown idv2 action {action}"),
    }
}

const PERM: i64 = 950001;
const ALPHA_KEY: &str = "admin7-alpha";
const BETA_KEY: &str = "admin7-beta";
const GAMMA_KEY: &str = "admin7-gamma";
const C1: &str = "95000000-0000-4000-8000-000000000001";
const C2: &str = "95000000-0000-4000-8000-000000000002";
const C3: &str = "95000000-0000-4000-8000-000000000003";
const C4: &str = "95000000-0000-4000-8000-000000000004";
const MISSING_UUID: &str = "95000000-0000-4000-8000-0000000000ff";
const MISSING: i64 = 99999999;
const J_DONE: &str = "95100000-0000-4000-8000-000000000001";
const J_RUNNING: &str = "95100000-0000-4000-8000-000000000002";
const J_OTHER: &str = "95100000-0000-4000-8000-000000000003";
const J_UPGRADE: &str = "95100000-0000-4000-8000-000000000004";
const J_MISSING: &str = "95100000-0000-4000-8000-0000000000ff";

/// The actions added with the second half of the slice (no list options).
fn plain(action: &str) -> bool {
    matches!(
        action,
        "person"
            | "conflict"
            | "mappings"
            | "inventory"
            | "export"
            | "job"
            | "results"
            | "source"
            | "source-export"
    )
}

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Run-specific ids named by the key that carries them, in a rendered JSON text
/// (compact from Go's encoder or spaced from jsonb).
fn mask_text(text: &str, users: &[(i64, &str)]) -> String {
    let mut out = text.to_owned();
    for (id, name) in users {
        for key in ["userId", "personId", "decidedBy", "actorUserId"] {
            for sep in [":", ": "] {
                out = out.replace(
                    &format!("\"{key}\"{sep}\"{id}\""),
                    &format!("\"{key}\"{sep}\"{name}\""),
                );
            }
        }
    }
    // Sequence-issued ids (events, decisions, links) differ per run.
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(at) = rest.find('"') {
        result.push_str(&rest[..at + 1]);
        rest = &rest[at + 1..];
        let Some(end) = rest.find('"') else { break };
        let key = &rest[..end];
        let after = &rest[end + 1..];
        result.push_str(key);
        result.push('"');
        rest = after;
        if matches!(key, "id" | "linkId") {
            let trimmed = rest.trim_start_matches([':', ' ']);
            if let Some(body) = trimmed.strip_prefix('"') {
                if let Some(close) = body.find('"') {
                    let value = &body[..close];
                    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                        let skipped = rest.len() - trimmed.len();
                        result.push_str(&rest[..skipped]);
                        result.push_str("\"<n>\"");
                        rest = &body[close + 1..];
                    }
                }
            }
        }
    }
    result.push_str(rest);
    result
}

/// Replace every opaque cursor with its readable, volatile-free form.
fn mask_cursors(text: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let marker = "\"nextCursor\":\"";
    let Some(start) = text.find(marker) else {
        return text.to_owned();
    };
    let from = start + marker.len();
    let Some(len) = text[from..].find('"') else {
        return text.to_owned();
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(&text[from..from + len])
        .expect("cursor");
    let mut cursor: Value = serde_json::from_slice(&decoded).expect("cursor json");
    cursor["expires"] = json!("<expires>");
    cursor["binding"] = json!("<binding>");
    if cursor["number"].is_number() {
        cursor["number"] = json!("<n>");
    }
    let readable = format!("<cursor {}>", cursor);
    let mut out = text.to_owned();
    out.replace_range(from..from + len, &readable.replace('"', "'"));
    out
}

fn mask(v: &mut Value, users: &[(i64, &str)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    let user = matches!(
                        k.as_str(),
                        "user_id"
                            | "actor_id"
                            | "actor"
                            | "granted_by"
                            | "created_by"
                            | "decided_by"
                            | "updated_by"
                            | "actor_user_id"
                            | "authorized_by"
                    );
                    if user {
                        if let Some((_, name)) = users.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    }
                } else {
                    mask(x, users);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, users)),
        Value::String(s) => {
            if timestamp_like(s) {
                *s = "<timestamp>".into();
            }
        }
        _ => {}
    }
}
fn masked(
    mut v: Value,
    users: &[(i64, &str)],
    names: &dyn Fn(&str) -> String,
) -> Result<Value, BoxError> {
    v = serde_json::from_str(&names(&v.to_string()))?;
    mask(&mut v, users);
    Ok(v)
}

async fn clean(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM identity_source_operations WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'admin7-%'); \
             DELETE FROM identity_job_results WHERE job_id::text LIKE '95100000-%'; \
             UPDATE audit_policy SET reason_required_areas = array_remove(reason_required_areas,'identity') WHERE id=1; \
             DELETE FROM identity_jobs WHERE id::text LIKE '95100000-%'; \
             DELETE FROM saml_sp_registrations WHERE idp_entity_id LIKE 'admin7-%'; \
             DELETE FROM system_config WHERE key LIKE 'oidc_provider_admin7%'; \
             UPDATE system_config SET value='\"\"'::jsonb WHERE key='ad_sync_password_enc'; \
             DELETE FROM identity_match_decisions WHERE candidate_id::text LIKE '95000000-%'; \
             DELETE FROM identity_match_candidates WHERE id::text LIKE '95000000-%'; \
             DELETE FROM identity_link_events WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'admin7-%'); \
             DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); \
             DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; \
             DELETE FROM user_lifecycle_authorities WHERE link_id IN (SELECT l.id FROM user_identity_links l JOIN identity_sources s ON s.id=l.source_id WHERE s.source_key LIKE 'admin7-%'); \
             DELETE FROM user_identity_links WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'admin7-%'); \
             DELETE FROM identity_sources WHERE source_key LIKE 'admin7-%'; \
             DELETE FROM admin_role_assignments WHERE role_group_id=950001; DELETE FROM admin_role_groups WHERE id=950001; COMMIT;",
        )
        .await?;
    Ok(())
}

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind).await
}

async fn run_inner(action: &str, kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let fault = kind.strip_suffix("-no-notify-fault").map(|_| "no-notify");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let label = label.strip_suffix("-no-notify-fault").unwrap_or(label);
    let Some(db) = Db::for_case("admin7-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    clean(&owner).await?;
    let a = fixture::account(&owner, "admin7-admin").await?;
    let b = fixture::account(&owner, "admin7-other").await?;
    let t = fixture::account(&owner, "admin7-third").await?;
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
        (domain_of(t.domain).await?, "host-t.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    let users: Vec<(i64, &str)> = vec![
        (a.user, "<admin>"),
        (b.user, "<other>"),
        (t.user, "<third>"),
    ];
    // The governing role: users.read (and audit.read), global or narrowed to the other domain.
    let permissions: Vec<&str> = match label {
        _ if trans::handles(action) => trans::permissions(action, label),
        _ if write::is_write(action) => write::permissions(action, label),
        "denied"
            if matches!(
                action,
                "mappings"
                    | "inventory"
                    | "export"
                    | "job"
                    | "results"
                    | "source"
                    | "source-export"
            ) =>
        {
            vec!["roles.manage"]
        }
        "denied" => vec!["identity.write"],
        _ if plain(action) && !matches!(action, "person" | "conflict") => {
            vec!["users.read", "audit.read", "audit.export"]
        }
        _ => vec!["users.read", "audit.read"],
    };
    let scope: Option<i64> = match label {
        "foreign" | "scoped" | "no-user" | "soft-link-scoped" => Some(b.domain),
        _ => None,
    };
    owner
        .execute(
            "INSERT INTO admin_role_groups(id,name,permissions,domain_scope) OVERRIDING SYSTEM VALUE VALUES($1,'admin7-perm',$2,$3)",
            &[&PERM, &permissions, &scope],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &PERM],
        )
        .await?;
    // Sources: alpha active with a cursor and health facts, beta paused after a failure, gamma draft.
    for (key, name, kind_, state, generation, with_cursor, failure) in [
        (
            ALPHA_KEY,
            "Admin7 Alpha <&>",
            "local",
            "active",
            3i64,
            true,
            false,
        ),
        (BETA_KEY, "Admin7 Beta", "ldap", "paused", 5, false, true),
        (GAMMA_KEY, "Admin7 Gamma", "scim", "draft", 1, false, false),
    ] {
        owner
            .execute(
                "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,generation,mapping_version,last_success_at,last_failure_at,last_error_code,committed_cursor,committed_cursor_digest) \
                 VALUES($1,$2,$3,'{\"authenticate\": true, \"provision_lifecycle\": false, \"stable_immutable_subject\": true}'::jsonb,$4,$5,2,\
                 CASE WHEN $1<>'admin7-gamma' THEN '2026-10-01T10:00:00.250Z'::timestamptz END,\
                 CASE WHEN $7 THEN '2026-10-02T11:00:00Z'::timestamptz END, CASE WHEN $7 THEN 'connect_failed' END,\
                 CASE WHEN $6 THEN '{\"offset\": 7}'::jsonb END, CASE WHEN $6 THEN decode(repeat('ab',32),'hex') END)",
                &[&key, &name, &kind_, &state, &generation, &with_cursor, &failure],
            )
            .await?;
    }
    let source_id = |key: &'static str| {
        let owner = &owner;
        async move {
            Ok::<i64, BoxError>(
                owner
                    .query_one(
                        "SELECT id FROM identity_sources WHERE source_key=$1",
                        &[&key],
                    )
                    .await?
                    .get(0),
            )
        }
    };
    let (alpha, beta) = (source_id(ALPHA_KEY).await?, source_id(BETA_KEY).await?);
    // Links: other (active, lifecycle authority = alpha), third (active), admin (detached from beta).
    let link = |user: i64, source: i64, subject: &'static str, state: &'static str| {
        let owner = &owner;
        async move {
            Ok::<i64, BoxError>(
                owner
                    .query_one(
                        "INSERT INTO user_identity_links(user_id,source_id,external_subject,purposes,state,link_method,detached_at,detached_reason,detached_by) \
                         VALUES($1,$2,$3,ARRAY['authenticate','provision'],$4,'operator',\
                         CASE WHEN $4='detached' THEN '2026-10-03T00:00:00Z'::timestamptz END, CASE WHEN $4='detached' THEN 'moved' END, NULL) RETURNING id",
                        &[&user, &source, &subject, &state],
                    )
                    .await?
                    .get(0),
            )
        }
    };
    let link_b = link(b.user, alpha, "admin7-subject-b", "active").await?;
    link(t.user, alpha, "admin7-subject-t", "active").await?;
    link(a.user, beta, "admin7-subject-a", "detached").await?;
    // Account creation already gave every user a local authority; the other user's follows alpha.
    owner
        .execute(
            "UPDATE user_lifecycle_authorities SET authority_kind='source',link_id=$2 WHERE user_id=$1",
            &[&b.user, &link_b],
        )
        .await?;
    // Candidates (fixed ids and times): other pending/hard on alpha, nobody deferred/soft on
    // alpha, admin pending/composite on beta, third rejected (never listed).
    owner
        .execute(
            "INSERT INTO identity_match_candidates(id,source_id,external_subject,candidate_user_id,evidence_class,evidence_digest,redacted_explanation,status,generation,expires_at,created_at,decided_by,decided_at,decision_idempotency_key,decision_request_digest,decision_reason) VALUES \
             ($1::text::uuid,$5,'admin7-ext-1',$7,'hard',decode(repeat('01',32),'hex'),'admin7 hard anchor <match>','pending',3,'2031-01-01T00:00:00Z','2026-10-04T08:00:00.5Z',NULL,NULL,NULL,NULL,NULL), \
             ($2::text::uuid,$5,'admin7-ext-2',NULL,'soft',decode(repeat('02',32),'hex'),'admin7 soft name match','deferred',3,'2031-01-01T00:00:00Z','2026-10-04T09:00:00Z',$8,'2026-10-05T00:00:00Z',gen_random_uuid(),decode(repeat('0a',32),'hex'),'later'), \
             ($3::text::uuid,$6,'admin7-ext-3',$8,'composite',decode(repeat('03',32),'hex'),'admin7 composite','pending',5,'2031-01-01T00:00:00Z','2026-10-04T09:00:00Z',NULL,NULL,NULL,NULL,NULL), \
             ($4::text::uuid,$5,'admin7-ext-4',$9,'hard',decode(repeat('04',32),'hex'),'admin7 rejected','rejected',3,'2031-01-01T00:00:00Z','2026-10-04T10:00:00Z',$8,'2026-10-05T00:00:00Z',gen_random_uuid(),decode(repeat('0b',32),'hex'),'no')",
            &[&C1, &C2, &C3, &C4, &alpha, &beta, &b.user, &a.user, &t.user],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO identity_match_decisions(candidate_id,decided_by,idempotency_key,request_digest,decision,reason,result,occurred_at) VALUES \
             ($1::text::uuid,$3,gen_random_uuid(),decode(repeat('0c',32),'hex'),'defer','earlier','{}'::jsonb,'2026-10-04T12:00:00Z'), \
             ($2::text::uuid,$3,gen_random_uuid(),decode(repeat('0d',32),'hex'),'defer','later','{}'::jsonb,'2026-10-05T00:00:00Z')",
            &[&C1, &C2, &a.user],
        )
        .await?;
    // Events: two share one instant (ties break on id), one carries sub-second time and metadata.
    owner
        .execute(
            "INSERT INTO identity_link_events(occurred_at,user_id,source_id,link_id,action,reason,correlation_id,metadata) VALUES \
             ('2026-10-06T00:00:00Z',$1,$3,$5,'link_activated','seeded','96000000-0000-4000-8000-000000000001','{\"k\": 1}'::jsonb), \
             ('2026-10-06T00:00:00Z',NULL,$3,NULL,'source_created','seeded <&>','96000000-0000-4000-8000-000000000002','{}'::jsonb), \
             ('2026-10-07T00:00:00.123456Z',$2,$4,NULL,'link_detached','moved','96000000-0000-4000-8000-000000000003','{\"note\": \"<x>\", \"n\": [1, 2]}'::jsonb)",
            &[&b.user, &a.user, &alpha, &beta, &link_b],
        )
        .await?;
    if write::is_write(action) {
        write::fixtures(&owner, a.user, b.user, alpha).await?;
    }
    // Second half of the slice: jobs, sealed source documents, group mappings.
    if matches!(action, "job" | "results") {
        for (id, kind, state, actor, source, key) in [
            (J_DONE, "diagnostics", "completed", a.user, Some(alpha), 1u8),
            (J_RUNNING, "diagnostics", "queued", a.user, Some(alpha), 2),
            (J_OTHER, "diagnostics", "completed", b.user, Some(alpha), 3),
            (J_UPGRADE, "upgrade_backfill", "completed", a.user, None, 4),
        ] {
            owner
                .execute(
                    "INSERT INTO identity_jobs(id,kind,state,actor_user_id,source_id,snapshot_id,idempotency_key,request_digest,request,progress,next_action,reason,cancel_requested,created_at,updated_at,completed_at,expires_at) \
                     VALUES($1::text::uuid,$2,$3,$4,$5,$1::text::uuid,('95200000-0000-4000-8000-00000000000'||$6::text)::uuid,decode(repeat('0e',32),'hex'),'{\"sourceKey\": \"admin7-alpha\"}'::jsonb,'{\"failed\": 0, \"processed\": 7}'::jsonb,'wait <&>','seeded',false,\
                     '2026-10-01T00:00:00Z','2026-10-01T00:00:00Z',CASE WHEN $3='queued' THEN NULL ELSE '2026-10-02T00:00:00.5Z'::timestamptz END,'2026-10-07T00:00:00Z')",
                    &[&id, &kind, &state, &actor, &source, &key.to_string()],
                )
                .await?;
        }
        owner
            .execute(
                "INSERT INTO identity_job_results(job_id,sequence,user_id,state,result,created_at) VALUES \
                 ($1::text::uuid,1,$2,'completed','{\"ok\": true, \"note\": \"<x>\"}'::jsonb,'2026-10-03T00:00:00Z'), \
                 ($1::text::uuid,2,$3,'failed','{\"error\": \"conflict\"}'::jsonb,'2026-10-03T00:00:01Z'), \
                 ($1::text::uuid,3,NULL,'skipped','{}'::jsonb,'2026-10-03T00:00:02Z')",
                &[&J_DONE, &b.user, &t.user],
            )
            .await?;
    }
    if matches!(action, "source" | "source-export") {
        let deployment: String = owner
            .query_one(
                "SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'",
                &[],
            )
            .await?
            .get(0);
        let codec = setjoin_config_secret::ConfigSecretCodec::new(
            setjoin_config_secret::keyring_from_lookup(&deployment, secret_env)?,
        )?;
        owner
            .execute(
                "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,generation,mapping_version) VALUES \
                 ('admin7-delta','Admin7 Delta','scim','{\"authenticate\": false, \"provision_lifecycle\": true, \"stable_immutable_subject\": true}'::jsonb,'draft',1,1),('admin7-epsilon','Admin7 Epsilon','ad','{\"authenticate\": false, \"provision_lifecycle\": true, \"stable_immutable_subject\": true}'::jsonb,'draft',1,1)",
                &[],
            )
            .await?;
        for (key, plain, junk) in [
            (
                ALPHA_KEY,
                r#"{"document":{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"admin7-alpha","displayName":"Admin7 Alpha <&>"},"spec":{"type":"local"}},"secrets":null}"#,
                false,
            ),
            (
                BETA_KEY,
                r#"{"document":{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"admin7-beta","displayName":"Admin7 Beta"},"spec":{"type":"ldap","baseDN":"dc=example,dc=test"}},"secrets":{"bindPassword":"s3cret","unknown":"x","empty":""}}"#,
                false,
            ),
            (
                "admin7-delta",
                r#"{"document":{"spec":{"type":"scim"}},"secrets":{"bearerToken":""}}"#,
                false,
            ),
            (
                "admin7-epsilon",
                r#"{"document":{"spec":{"type":"ad"}},"extra":1}"#,
                true,
            ),
        ] {
            let _ = junk;
            let sealed = codec.encrypt(&format!("identity_source.{key}"), plain.as_bytes())?;
            owner
                .execute(
                    "UPDATE identity_sources SET config_envelope=$2,config_key_version=1 WHERE source_key=$1",
                    &[&key, &sealed],
                )
                .await?;
        }
        // A garbled envelope for the "corrupt" case.
        owner
            .execute(
                "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,generation,mapping_version,config_envelope,config_key_version) VALUES ('admin7-zeta','Admin7 Zeta','oidc','{\"authenticate\": false, \"provision_lifecycle\": true, \"stable_immutable_subject\": true}'::jsonb,'draft',1,1,'not an envelope'::bytea,1)",
                &[],
            )
            .await?;
    }
    if matches!(action, "inventory" | "export") {
        // The inventory golden reports the AD connector secret as encrypted: seed it here rather
        // than relying on state another suite left behind (cleanup restores the empty seed).
        owner
            .execute(
                "UPDATE system_config SET value='{\"format\": \"setjoin-config-secret\", \"version\": 1, \"ciphertext\": \"admin7\"}'::jsonb WHERE key='ad_sync_password_enc'",
                &[],
            )
            .await?;
    }
    if action == "mappings" {
        owner
            .execute(
                "INSERT INTO saml_sp_registrations(idp_entity_id,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings,enabled) VALUES \
                 ('admin7-idp-a','https://idp.test/sso','\\x00'::bytea,'sp-a','https://sp.test/acs','[{\"idp_group\": \"eng <&>\", \"distribution_group_id\": 5, \"admin_role\": \"auditor\", \"department_id\": 9, \"extra\": 1}, {\"IDP_GROUP\": \"ops\"}, {\"idp_group\": 7, \"admin_role\": \"\"}, \"bad\", null]'::jsonb,true), \
                 ('admin7-idp-b','https://idp.test/sso','\\x00'::bytea,'sp-b','https://sp.test/acs',NULL,true), \
                 ('admin7-idp-c','https://idp.test/sso','\\x00'::bytea,'sp-c','https://sp.test/acs','{\"not\": \"array\"}'::jsonb,true), \
                 ('admin7-idp-off','https://idp.test/sso','\\x00'::bytea,'sp-d','https://sp.test/acs','[{\"idp_group\": \"hidden\"}]'::jsonb,false)",
                &[],
            )
            .await?;
        owner
            .execute(
                "INSERT INTO system_config(key,value) VALUES \
                 ('oidc_provider_admin7a_config','{\"name\": \"admin7-oidc-a\", \"group_mappings\": [{\"idp_group\": \"g1\", \"department_id\": 3}, {\"idp_group\": \"g2\"}]}'::jsonb), \
                 ('oidc_provider_admin7b_config','{\"name\": \"admin7-oidc-b\"}'::jsonb), \
                 ('oidc_provider_admin7c_config','{\"name\": 5}'::jsonb), \
                 ('oidc_provider_admin7d_config','{\"name\": \"admin7-oidc-d\", \"group_mappings\": [{\"idp_group\": 1}]}'::jsonb), \
                 ('oidc_provider_admin7e_config','\"text\"'::jsonb)",
                &[],
            )
            .await?;
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        // `probe-*` dry runs reach a fake directory (#400); both sides trust its test CA.
        let _directory = if write2::is_probe(action, label) {
            write2::start_probe_directory(label).await?
        } else {
            None
        };
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin7-http").await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let timeouts = || setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        // CAE is exercised on the real request credential (#405), without a private toggle view.
        let exec_dsn=db.app.as_deref().unwrap_or(&db.dsn).to_owned();
        let exec = ScopedExecutor::from_dsn_with(&exec_dsn, 4, timeouts())
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker = ScopedExecutor::from_dsn_with(&db.dsn, 4, timeouts())
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let runtime=setjoin_gateway::runtime_access::RuntimeAccess::new(exec.clone(),Arc::new(common::recovery_keys()),"mailserver".into())
            .with_workers(worker.clone(),setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?)
            .with_direct(db.direct.clone());
        let adapter = Probe {
            inner: AdminIdentityV2Route { exec, worker, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into(), secrets: setjoin_gateway::admin_identity_v2::SourceSecrets::new(secret_env).with_probe(Arc::new(setjoin_gateway::directory_sync::DirectoryProbe(setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?))) },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && (r["slice"] == "idv2-sources" || r["slice"] == "idv2-transitions") {
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
            RouteTable::proxy_all().with(adapter).with_runtime(runtime),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        if trans::handles(action) {
            let codec_source = setjoin_config_secret::keyring_from_lookup(
                &owner.query_one("SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'", &[]).await?.get::<_, String>(0),
                secret_env,
            )?;
            let codec = setjoin_config_secret::ConfigSecretCodec::new(codec_source)?;
            let outcome = trans::case(write::Ctx {
                codec: &codec,
                address,
                recording,
                db: &db,
                owner: &owner,
                users: &users,
                names: &names,
                admin: a.user,
                other_domain: b.domain,
                action,
                label,
                mutant,
                fault,
            })
            .await;
            server.abort();
            return outcome;
        }
        if write::is_write(action) {
            let codec_source = setjoin_config_secret::keyring_from_lookup(
                &owner.query_one("SELECT value #>> '{}' FROM system_config WHERE key='identity.deployment_id'", &[]).await?.get::<_, String>(0),
                secret_env,
            )?;
            let codec = setjoin_config_secret::ConfigSecretCodec::new(codec_source)?;
            let outcome = write::case(write::Ctx {
                codec: &codec,
                address,
                recording,
                db: &db,
                owner: &owner,
                users: &users,
                names: &names,
                admin: a.user,
                other_domain: b.domain,
                action,
                label,
                mutant,
                fault,
            })
            .await;
            server.abort();
            return outcome;
        }
        let pattern = route(action);
        let detail = plain(action);
        let id_part = match (action, label) {
            ("source" | "source-export", l) => match l {
                "bad-key" => "-bad".to_string(),
                "missing" => "admin7-nothing".to_string(),
                "with-secrets" => BETA_KEY.to_string(),
                "draft" => "admin7-delta".to_string(),
                "unknown-field" => "admin7-epsilon".to_string(),
                "corrupt" => "admin7-zeta".to_string(),
                "no-envelope" => GAMMA_KEY.to_string(),
                _ => ALPHA_KEY.to_string(),
            },
            ("job" | "results", l) => match l {
                "bad-id" => "bad".to_string(),
                "nil-id" => "00000000-0000-0000-0000-000000000000".to_string(),
                "missing" => J_MISSING.to_string(),
                "running" => J_RUNNING.to_string(),
                "other-actor" => J_OTHER.to_string(),
                "kind-denied" => J_UPGRADE.to_string(),
                "uppercase" => J_DONE.to_uppercase(),
                _ => J_DONE.to_string(),
            },
            (_, "bad-id") => "bad".to_string(),
            ("conflict", "nil-id") => "00000000-0000-0000-0000-000000000000".to_string(),
            ("person", "missing") => MISSING.to_string(),
            ("person", "zero-id") => "0".to_string(),
            ("person", "foreign") => a.user.to_string(),
            ("person", _) => b.user.to_string(),
            ("conflict", "missing") => MISSING_UUID.to_string(),
            ("conflict", "foreign") => C3.to_string(),
            ("conflict", "soft") => C2.to_string(),
            ("conflict", "rejected") => C4.to_string(),
            ("conflict", "uppercase") => C1.to_uppercase(),
            ("conflict", "compact") => C1.replace('-', ""),
            ("conflict", _) => C1.to_string(),
            _ => String::new(),
        };
        let path = pattern.replace("{id}", &id_part).replace("{sourceKey}", &id_part);
        // The default filter confines every list to the fixture rows.
        let narrow = match action { "sources" => "admin7-alpha", "people" => "admin7-other", "conflicts" => "composite", _ => "link_" };
        let one = match action { "sources" => "admin7-beta", "people" => "admin7-admin", "conflicts" => "admin7-x", _ => "admin7-beta" };
        let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
        let query_for = |extra: &str| -> String {
            if detail { return String::new(); }
            format!("?filter={}{}", enc("admin7"), extra)
        };
        let q = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| format!("&{k}={}", enc(v))).collect::<String>();
        let state_value = match action { "sources" => "active", "people" => "disabled", _ => "deferred" };
        let mut headers_in: Vec<(String, String)> = vec![];
        let send_raw = |uri: String, extra: Vec<(String, String)>| {
            let non_admin = false;
            let token = if non_admin { common::recovery_token(a.user) } else { admin_token(a.user) };
            async move {
                let mut request = Request::builder().method("GET").uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("x-request-id", "gofree-admin7-oracle").header("authorization", format!("Bearer {token}"));
                for (k, v) in extra { request = request.header(k, v); }
                Ok::<_, BoxError>(common::send(address, request.body(common::full(""))?).await)
            }
        };
        let uri = |query: &str| format!("/api{path}{query}");
        // A cursor minted by this very route for the same filters (limit 1, two or more rows exist).
        let first_cursor = || async {
            let response = send_raw(uri(&query_for("&limit=1")), vec![]).await?;
            let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            let value: Value = serde_json::from_str(&body)?;
            Ok::<String, BoxError>(value["nextCursor"].as_str().ok_or_else(|| format!("no nextCursor in {body}"))?.to_owned())
        };
        let rewrite_cursor = |cursor: &str, expires: i64| {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let mut v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(cursor).unwrap()).unwrap();
            v["expires"] = json!(expires);
            URL_SAFE_NO_PAD.encode(v.to_string())
        };
        let raw_cursor = |text: &str| { use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine}; URL_SAFE_NO_PAD.encode(text) };
        let query = match label {
            "success" | "foreign" | "scoped" | "denied" | "etag-match" | "etag-miss" | "etag-star" => query_for(""),
            "filter" => query_for("").replace("filter=admin7", &format!("filter={}", enc(narrow))),
            "state" => query_for(&q(&[("state", state_value)])),
            "source" => query_for(&q(&[("source", one)])),
            "sort" => query_for(&q(&[("sort", pattern_sort(action))])),
            "limit" => query_for("&limit=1"),
            "limit-max" => query_for("&limit=500"),
            "limit-plus" => query_for("&limit=%2B2"),
            "page2" => { let c = first_cursor().await?; query_for(&format!("&limit=1&cursor={c}")) }
            "bad-limit" => query_for("&limit=0"),
            "bad-limit-text" => query_for("&limit=abc"),
            "over-limit" => query_for("&limit=501"),
            "bad-sort" => query_for("&sort=name"),
            "unknown-param" => query_for("&bogus=1"),
            "repeated" => query_for("&limit=1&limit=2"),
            "bad-state" => query_for("&state=nope"),
            "long-filter" => format!("?filter={}", "x".repeat(300)),
            "non-utf8-filter" => "?filter=%FF%FEbad".to_owned(),
            "non-utf8-source" => query_for("&source=a%FF"),
            "non-utf8-state" => query_for("&state=%FF"),
            "non-utf8-cursor" => query_for("&cursor=%FF"),
            "non-utf8-name" => query_for("&%FF=1"),
            "non-utf8-limit" => query_for("&limit=%FF"),
            "non-utf8-sort" => query_for("&sort=%FF"),
            "bad-source" => query_for("&source=-bad"),
            "long-source" => query_for(&format!("&source=a{}", "b".repeat(64))),
            "semicolon" => query_for("&limit=1;limit=2"),
            "bad-cursor" => query_for("&cursor=!!"),
            "cursor-mismatch" => { let c = first_cursor().await?; query_for(&format!("&limit=1&source=admin7-alpha&cursor={c}")) }
            "cursor-expired" => { let c = first_cursor().await?; query_for(&format!("&limit=1&cursor={}", rewrite_cursor(&c, 1))) }
            "cursor-shape" => query_for(&format!("&cursor={}", raw_cursor("{\"v\":1,\"bogus\":1}"))),
            "cursor-trailing" => query_for(&format!("&cursor={}", raw_cursor("{\"v\":1} x"))),
            "cursor-empty" => query_for(&format!("&cursor={}", raw_cursor("{}"))),
            "cursor-null" => query_for(&format!("&cursor={}", raw_cursor("null"))),
            "cursor-version" => { let c = first_cursor().await?; use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine}; let mut v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&c)?)?; v["v"] = json!(2); query_for(&format!("&limit=1&cursor={}", URL_SAFE_NO_PAD.encode(v.to_string()))) }
            "cursor-fields" => { let c = first_cursor().await?; use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine}; let mut v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&c)?)?; match action { "sources" => v["text"] = json!(""), "people" => v["number"] = json!(0), _ => { v["time"] = json!("not-a-time"); v["number"] = json!(1); v["id"] = json!("x"); } } query_for(&format!("&limit=1&cursor={}", URL_SAFE_NO_PAD.encode(v.to_string()))) }
            "bad-id" | "nil-id" | "missing" | "zero-id" | "soft" | "rejected" | "uppercase" | "compact" => String::new(),
            "page" => "?after=1&limit=1".into(),
            "page-limit" => "?limit=2".into(),
            "after-end" => "?after=3".into(),
            "bad-after" => "?after=-1".into(),
            "bad-after-text" => "?after=x".into(),
            "bad-limit-job" => "?limit=0".into(),
            "over-limit-job" => "?limit=501".into(),
            "bad-limit-job-text" => "?limit=abc".into(),
            "running" | "other-actor" | "kind-denied" | "bad-key" | "with-secrets" | "draft" | "unknown-field" | "corrupt" | "no-envelope" => String::new(),
            _ => return Err(format!("unknown label {label}").into()),
        };
        if label == "etag-match" || label == "etag-star" || label == "etag-miss" {
            let first = send_raw(uri(&query), vec![]).await?;
            let etag = first.headers().get("etag").ok_or("no etag")?.to_str()?.to_owned();
            headers_in.push(("if-none-match".into(), match label { "etag-match" => format!("\"nope\", {etag}"), "etag-star" => "*".into(), _ => "\"nope\"".into() }));
        }
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let response = send_raw(uri(&query), headers_in.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            let mut shown = masked(row.clone(), &users, &names)?;
            shown = serde_json::from_str(&shown.to_string().replace(&format!("domain={}", b.domain), "domain=<scope>").replace(&format!("/people/{}", b.user), "/people/<other>"))?;
            *row = shown;
        }
        let second_half = matches!(action, "mappings" | "inventory" | "export" | "job" | "results" | "source" | "source-export");
        let wanted = if second_half { match label {
            "denied" | "scoped" | "kind-denied" => 403,
            "bad-id" | "nil-id" | "bad-after" | "bad-after-text" | "bad-limit-job" | "over-limit-job" | "bad-limit-job-text" | "bad-key" => 400,
            "missing" | "other-actor" => 404,
            "etag-match" | "etag-star" => 304,
            "corrupt" | "unknown-field" => 500,
            _ => 200,
        } } else { match (action, label) {
            (_, "denied") | ("events", "scoped" | "foreign") => 403,
            (_, "non-utf8-filter") => 500,
            (_, "non-utf8-source" | "non-utf8-state" | "non-utf8-cursor" | "non-utf8-name" | "non-utf8-limit" | "non-utf8-sort") => 400,
            (_, "bad-limit" | "bad-limit-text" | "over-limit" | "bad-sort" | "unknown-param" | "repeated" | "bad-state" | "long-filter" | "bad-source" | "long-source" | "bad-cursor" | "cursor-mismatch" | "cursor-shape" | "cursor-trailing" | "cursor-version" | "cursor-fields" | "bad-id" | "nil-id" | "zero-id") => 400,
            ("events", "state") => 400,
            (_, "cursor-empty" | "cursor-null") => 400,
            (_, "cursor-expired") => 410,
            ("person", "missing" | "foreign") | ("conflict", "missing" | "foreign") => 404,
            (_, "etag-match" | "etag-star") => 304,
            _ => 200,
        } };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // Volatile text: user ids by key, sequence ids, cursors, instants taken from now().
        let mut text = mask_cursors(&mask_text(&names(&raw), &users));
        text = text.replace(&format!("domain={}", b.domain), "domain=<scope>");
        text = scrub_instants(&text);
        let wire_etag = headers.get("etag").cloned().unwrap_or(Value::Null);
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(tag) = headers.get_mut("etag") {
            if tag[0].as_str().is_none_or(|t| t.len() != 66) { return Err("bad etag".into()); }
            *tag = json!(["<etag>"]);
        }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        if action == "export" && status == 200 {
            // The digest, the strong ETag and the embedded `sha256` follow the (volatile)
            // body; check them against the wire body, then mask the run-specific values.
            use base64::Engine as _;
            use sha2::Digest as _;
            let sum = sha2::Sha256::digest(raw.as_bytes());
            let hex: String = sum.iter().map(|b| format!("{b:02x}")).collect();
            if headers["digest"][0] != format!("sha-256={}", base64::engine::general_purpose::STANDARD.encode(sum))
                || wire_etag[0] != format!("\"{hex}\"")
            {
                return Err(format!("export digest or etag does not follow the body: {:?} {:?} {hex}", headers["digest"], wire_etag).into());
            }
            headers.insert("digest".into(), json!(["<digest>"]));
            // The schema version advances with the repository while the frozen recording stays
            // immutable: the wire value must equal the database's, then both sides are masked.
            let database: i64 = owner.query_one("SELECT max(version)::bigint FROM schema_migrations", &[]).await?.get(0);
            let wire = serde_json::from_str::<Value>(&text)?["schemaVersion"].as_i64();
            if wire != Some(database) {
                return Err(format!("export schemaVersion {wire:?} != database {database}").into());
            }
            let at = text.find("\"sha256\": \"").ok_or("export sha256 field")? + 11;
            text.replace_range(at..at + 64, "<sha256>");
        }
        if action == "inventory" && status == 200 {
            let report: Value = serde_json::from_str(&text)?;
            let count = |sql: &'static str| {
                let owner = &owner;
                async move { Ok::<i64, BoxError>(owner.query_one(sql, &[]).await?.get(0)) }
            };
            let expected = json!({
                "people": {
                    "total": count("SELECT count(*) FROM users").await?,
                    "enabled": count("SELECT count(*) FROM users WHERE enabled").await?,
                    "disabled": count("SELECT count(*) FROM users WHERE NOT enabled").await?,
                    "guests": count("SELECT count(*) FROM guest_accounts").await?,
                    "members": count("SELECT count(*) FROM users u WHERE NOT EXISTS (SELECT 1 FROM guest_accounts g WHERE g.user_id=u.id)").await?,
                },
                "mailboxes": {
                    "shared": count("SELECT count(*) FROM mailboxes WHERE user_id IS NULL AND resource_type IS NULL").await?,
                    "resources": count("SELECT count(*) FROM mailboxes WHERE user_id IS NULL AND resource_type IS NOT NULL").await?,
                },
            });
            for (section, fields) in expected.as_object().unwrap() {
                for (field, value) in fields.as_object().unwrap() {
                    if report[section][field] != *value {
                        return Err(format!("inventory {section}.{field}: {} != database {value}", report[section][field]).into());
                    }
                }
            }
            // Whole-database counts differ per run; their order and names are kept.
            let mut masked = String::new();
            let mut rest = text.as_str();
            while let Some(at) = rest.find("\":") {
                masked.push_str(&rest[..at + 2]);
                rest = &rest[at + 2..];
                let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
                if digits > 0 && !masked.ends_with("\"schemaVersion\":") {
                    masked.push_str("\"<n>\"");
                    rest = &rest[digits..];
                }
            }
            masked.push_str(rest);
            text = masked;
        }
        let mut request = json!({"method":"GET","path":pattern,"external_path":format!("/api{pattern}")});
        if !query.is_empty() {
            let shown = match query.find("cursor=") {
                Some(at) if !matches!(label, "bad-cursor" | "cursor-shape" | "cursor-trailing" | "cursor-empty" | "cursor-null") => format!("{}cursor=<cursor>", &query[..at]),
                _ => query.clone(),
            };
            request["query"] = json!(shown);
        }
        if !headers_in.is_empty() { request["headers"] = json!(["if-none-match"]); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":[],"audit":audit,"notify":[]});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0") {
                return Err(format!("F01 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/admin-identity/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("idv2-{name}.json"));
        let route_name = format!("GET {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            let compared = golden::compare(&mask_schema_version(expected["observation"].clone()), &mask_schema_version(observation.clone()));
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            compared?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup runs on every path and touches only this case's rows.
    clean(&owner).await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1", &[&PERM]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&PERM],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&PERM])
        .await?;
    for account in [&a, &b, &t] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

fn pattern_sort(action: &str) -> &'static str {
    match action {
        "sources" => "sourceKey",
        "people" => "userId",
        "conflicts" => "-createdAt",
        _ => "-occurredAt",
    }
}

/// Instants taken from `now()` (user creation, last login) differ per run; the
/// fixtures use only 2026-10-0x and 2031 instants.
fn scrub_instants(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let looks = i + 19 <= b.len()
            && b[i..i + 4].iter().all(u8::is_ascii_digit)
            && b[i + 4] == b'-'
            && b[i + 7] == b'-'
            && b[i + 10] == b'T'
            && b[i + 13] == b':'
            && b[i + 16] == b':'
            && text.is_char_boundary(i);
        if looks {
            let mut end = i + 19;
            while end < b.len()
                && (b[end].is_ascii_digit() || matches!(b[end], b'.' | b'Z' | b'+' | b'-' | b':'))
            {
                end += 1;
            }
            let stamp = &text[i..end];
            if stamp.starts_with("2026-10-0") || stamp.starts_with("2031-") {
                out.push_str(stamp);
            } else {
                out.push_str("<timestamp>");
            }
            i = end;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Verification mode compares immutable Go observations instead of rewriting them.
fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}

/// Masks the numeric `schemaVersion` of an export body (see the check beside the export branch).
fn mask_schema_version(mut observation: Value) -> Value {
    let pattern = regex::Regex::new(r#""schemaVersion"\s*:\s*[0-9]+"#).unwrap();
    if let Some(body) = observation["response"]["body"].as_str() {
        let masked = pattern.replace(body, "\"schemaVersion\": <schema-version>").into_owned();
        observation["response"]["body"] = json!(masked);
    }
    observation
}
