//! Slice `idv2-transitions` oracle (#370): the fourteen transition routes. Each case builds
//! its transition state with the real reducers (preview, step-up, request, approve,
//! execute, effect claim and fail, rollback preview), then drives one request through the
//! front door and observes the wire, the rows the reducers changed (before/after), the
//! admin audit rows and the notifications. Random ids, digests and sequence-issued numbers
//! are replaced by placeholders after the observation is complete.
use super::write::Ctx;
use super::{record, scrub_instants};
use crate::common::{self, BoxError};
use hyper::Request;
use serde_json::{json, Value};
use setjoin_conformance::golden;

const REASON: &str = "admin8 reason <&>";
pub const PERM_B: i64 = 950002;
pub const PERM_SENSITIVE: i64 = 950003;

pub fn handles(action: &str) -> bool {
    action.starts_with("t-")
}

pub fn route(action: &str) -> (&'static str, &'static str) {
    let base = "/admin/identity/v2/transitions";
    match action {
        "t-list" => ("GET", "/admin/identity/v2/transitions"),
        "t-read" => ("GET", "/admin/identity/v2/transitions/{id}"),
        "t-report" => ("GET", "/admin/identity/v2/transitions/{id}/report"),
        "t-preview" => ("POST", "/admin/identity/v2/transitions/preview"),
        "t-issue" => (
            "POST",
            "/admin/identity/v2/transitions/{id}/step-up/challenge",
        ),
        "t-complete" => (
            "POST",
            "/admin/identity/v2/transitions/{id}/step-up/complete",
        ),
        "t-request" => ("POST", "/admin/identity/v2/transitions/{id}/request"),
        "t-approve" => ("POST", "/admin/identity/v2/transitions/{id}/approve"),
        "t-deny" => ("POST", "/admin/identity/v2/transitions/{id}/deny"),
        "t-execute" => ("POST", "/admin/identity/v2/transitions/{id}/execute"),
        "t-cancel" => ("POST", "/admin/identity/v2/transitions/{id}/cancel"),
        "t-rollback-preview" => (
            "POST",
            "/admin/identity/v2/transitions/{id}/rollback-preview",
        ),
        "t-rollback" => ("POST", "/admin/identity/v2/transitions/{id}/rollback"),
        "t-retry" => (
            "POST",
            "/admin/identity/v2/transitions/{id}/effects/{effectId}/retry",
        ),
        _ => {
            let _ = base;
            panic!("unknown transition action {action}")
        }
    }
}

/// Permissions of the governing role.
pub fn permissions(action: &str, label: &str) -> Vec<&'static str> {
    match (action, label) {
        ("t-report", "denied") => vec!["users.read"],
        ("t-report", _) => vec!["users.read", "audit.export"],
        ("t-list" | "t-read", "denied") => vec!["identity.write"],
        ("t-list" | "t-read", _) => vec!["users.read"],
        (_, "denied") => vec!["users.read"],
        _ => vec!["users.read", "identity.write"],
    }
}

fn db(e: tokio_postgres::Error) -> String {
    e.as_db_error().map_or_else(
        || e.to_string(),
        |d| format!("{} {} ({:?})", d.code().code(), d.message(), d.where_()),
    )
}

fn key(n: u32) -> String {
    format!("95400000-0000-4000-8000-{n:012}")
}

async fn text(c: &tokio_postgres::Client, sql: &str) -> Result<String, BoxError> {
    Ok(c.query_one(sql, &[]).await?.get::<_, String>(0))
}

async fn json_of(c: &tokio_postgres::Client, sql: &str) -> Result<Value, BoxError> {
    Ok(serde_json::from_str(&text(c, sql).await?)?)
}

/// What the case's request needs from the fixture.
#[derive(Default, Clone)]
struct Prep {
    tid: String,
    digest: String,
    elevation: String,
    challenge: String,
    effect: String,
    generation: i64,
    approval: Option<String>,
    target: i64,
}

struct Fx<'a> {
    c: &'a Ctx<'a>,
    a: i64,
    b: i64,
    target: i64,
    target2: i64,
    source: (i64, i64),
}

fn sha(text: &str) -> String {
    format!("decode('{}','hex')", {
        use sha2::Digest as _;
        sha2::Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    })
}

impl Fx<'_> {
    /// Preview by `actor` (a reducer call, as the route's reducer would do it).
    async fn preview(&self, actor: i64, target: i64, n: u32) -> Result<Prep, BoxError> {
        let v = match json_of(
            self.c.owner,
            &format!(
                "SELECT identity_transition_preview({actor},{target},'{REASON}','{}')::text",
                key(n)
            ),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let reach: bool = self
                    .c
                    .owner
                    .query_one("SELECT admin_can_reach($1,$2)", &[&actor, &target])
                    .await?
                    .get(0);
                let assignments: i64 = self
                    .c
                    .owner
                    .query_one(
                        "SELECT count(*) FROM admin_role_assignments WHERE user_id=$1",
                        &[&actor],
                    )
                    .await?
                    .get(0);
                return Err(format!("preview by {actor} of {target} (n={n}): reach={reach} assignments={assignments}: {e}").into());
            }
        };
        let tid = v["transitionId"]
            .as_str()
            .ok_or("no transitionId")?
            .to_owned();
        let digest = v["previewDigest"].as_str().ok_or("no digest")?.to_owned();
        let generation = self.generation(&tid).await?;
        Ok(Prep {
            tid,
            digest,
            generation,
            target,
            ..Prep::default()
        })
    }
    async fn generation(&self, tid: &str) -> Result<i64, BoxError> {
        Ok(self
            .c
            .owner
            .query_one(
                "SELECT transition_generation FROM identity_transitions WHERE id=$1::text::uuid",
                &[&tid],
            )
            .await?
            .get(0))
    }
    async fn challenge(&self, actor: i64, p: &Prep, n: u32) -> Result<String, BoxError> {
        let v = json_of(
            self.c.owner,
            &format!(
                "SELECT identity_transition_challenge_issue({actor},'{}','{}','{}')::text",
                p.tid,
                p.digest,
                key(n)
            ),
        )
        .await?;
        Ok(v["challengeId"]
            .as_str()
            .ok_or("no challengeId")?
            .to_owned())
    }
    /// A one-use elevation for `actor`, as step-up completion would mint it.
    async fn elevate(
        &self,
        actor: i64,
        tid: &str,
        digest: &str,
        n: u32,
    ) -> Result<String, BoxError> {
        let p = Prep {
            tid: tid.into(),
            digest: digest.into(),
            ..Prep::default()
        };
        let challenge = self.challenge(actor, &p, n).await?;
        let session = sha("admin8-session");
        let factor = sha(&format!("admin8-factor-{n}"));
        let v = json_of(
            self.c.owner,
            &format!(
                "SELECT identity_transition_challenge_complete({actor},'{tid}','{challenge}','{digest}',{session},{factor},ARRAY['pwd','otp','mfa']::text[],'aal2','{}')::text",
                key(n + 500)
            ),
        )
        .await?;
        Ok(v["elevationId"]
            .as_str()
            .ok_or("no elevationId")?
            .to_owned())
    }
    async fn request(
        &self,
        actor: i64,
        p: &Prep,
        elevation: &str,
        n: u32,
    ) -> Result<Value, BoxError> {
        json_of(
            self.c.owner,
            &format!(
                "SELECT identity_transition_request({actor},'{}','{}','{elevation}','{REASON}','{}')::text",
                p.tid, p.digest, key(n)
            ),
        )
        .await
    }
    /// Preview, elevation, request: a non-protected transition becomes `authorized`.
    async fn authorized(&self, actor: i64, target: i64, n: u32) -> Result<Prep, BoxError> {
        let mut p = self.preview(actor, target, n).await?;
        let e = self.elevate(actor, &p.tid, &p.digest, n + 10).await?;
        self.request(actor, &p, &e, n + 20).await?;
        p.elevation = self.elevate(actor, &p.tid, &p.digest, n + 30).await?;
        p.generation = self.generation(&p.tid).await?;
        Ok(p)
    }
    /// An executed transition whose livekit effect failed (`failed_recoverable`).
    async fn failed(&self, actor: i64, target: i64, n: u32) -> Result<Prep, BoxError> {
        let mut p = self.authorized(actor, target, n).await?;
        json_of(
            self.c.owner,
            &format!(
                "SELECT identity_transition_execute({actor},'{}','{}','{}',NULL,'{REASON}','{}')::text",
                p.tid, p.digest, p.elevation, key(n + 40)
            ),
        )
        .await?;
        let claim = json_of(
            self.c.owner,
            "SELECT identity_transition_effect_claim('admin8-worker',120)::text",
        )
        .await?;
        let effect = claim["effectId"]
            .as_str()
            .ok_or("no effect claimed")?
            .to_owned();
        json_of(
            self.c.owner,
            &format!(
                "SELECT identity_transition_effect_fail('admin8-worker','{}','{effect}','admin8_livekit','simulated failure')::text",
                p.tid
            ),
        )
        .await?;
        p.effect = effect;
        p.generation = self.generation(&p.tid).await?;
        Ok(p)
    }
    async fn set_approver(&self, approvers: &[i64], named: i64) -> Result<(), BoxError> {
        let list = approvers
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        self.c
            .owner
            .batch_execute(&format!(
                "UPDATE system_config SET value='[{list}]'::jsonb WHERE key='ca_break_glass_user_ids'; \
                 UPDATE approval_policies SET enabled=true, conditions='{{\"protected\":true}}'::jsonb, \
                 approver_spec=jsonb_build_object('kind','named','user_id',{named}) WHERE consumer_type='identity.transition'"
            ))
            .await?;
        Ok(())
    }
    async fn protect(&self, target: i64) -> Result<(), BoxError> {
        self.c
            .owner
            .execute(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
                &[&target, &PERM_SENSITIVE],
            )
            .await?;
        Ok(())
    }
}

/// The saved state a case changes outside its own rows.
struct Saved {
    toggles: Vec<(String, bool)>,
    break_glass: String,
    policy: (bool, String, String),
}

/// The schema defaults this oracle changes: the three transition toggles off, the
/// `identity.transition` policy disabled with its default approver, no break-glass users.
/// Restoring fixed defaults (not the values found) keeps a killed run from poisoning the
/// next one, and the other identity oracles rely on them.
async fn save(_c: &tokio_postgres::Client) -> Result<Saved, BoxError> {
    Ok(Saved {
        toggles: [
            "feature.identity_model_v2",
            "feature.identity_transitions",
            "feature.cae_runtime",
        ]
        .iter()
        .map(|k| ((*k).to_owned(), false))
        .collect(),
        break_glass: "[]".to_owned(),
        policy: (
            false,
            "{\"protected\": true}".to_owned(),
            "{\"kind\": \"default_admin\"}".to_owned(),
        ),
    })
}

async fn restore(c: &tokio_postgres::Client, s: &Saved, users: &[i64]) -> Result<(), BoxError> {
    restore_settings(c, s).await?;
    cleanup_rows(c, users).await
}

async fn restore_settings(c: &tokio_postgres::Client, s: &Saved) -> Result<(), BoxError> {
    for (key, enabled) in &s.toggles {
        c.execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[key, enabled],
        )
        .await?;
    }
    c.execute(
        "UPDATE system_config SET value=$1::text::jsonb WHERE key='ca_break_glass_user_ids'",
        &[&s.break_glass],
    )
    .await?;
    c.execute(
        "UPDATE approval_policies SET enabled=$1,conditions=$2::text::jsonb,approver_spec=$3::text::jsonb WHERE consumer_type='identity.transition'",
        &[&s.policy.0, &s.policy.1, &s.policy.2],
    )
    .await?;
    Ok(())
}

async fn cleanup_rows(c: &tokio_postgres::Client, users: &[i64]) -> Result<(), BoxError> {
    let list = users
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let cleanup = c.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM identity_job_results WHERE job_id IN (SELECT id FROM identity_jobs WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list}))); \
         DELETE FROM identity_jobs WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list})); \
         DELETE FROM identity_transition_effect_targets WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list})); \
         DELETE FROM identity_transition_effects WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list})); \
         DELETE FROM identity_transition_steps WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list})); \
         DELETE FROM identity_transition_idempotency WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list})); \
         DELETE FROM identity_link_events WHERE user_id IN ({list}) OR actor_user_id IN ({list}) OR link_id IN (SELECT id FROM user_identity_links WHERE user_id IN ({list})); \
         DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); \
         DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; \
         DELETE FROM identity_transition_elevations WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list})); \
         DELETE FROM identity_transition_challenges WHERE transition_id IN (SELECT id FROM identity_transitions WHERE user_id IN ({list})); \
         DELETE FROM identity_transitions WHERE user_id IN ({list}); \
         DELETE FROM approval_requests WHERE consumer_type='identity.transition'; \
         DELETE FROM identity_attribute_authority WHERE user_id IN ({list}); \
         DELETE FROM identity_entitlement_grants WHERE user_id IN ({list}); \
         DELETE FROM user_lifecycle_authorities WHERE user_id IN ({list}); \
         DELETE FROM user_identity_links WHERE user_id IN ({list}); \
         DELETE FROM sessions WHERE user_id IN ({list}); \
         DELETE FROM admin_role_assignments WHERE role_group_id IN ({PERM_B},{PERM_SENSITIVE}); \
         DELETE FROM admin_role_groups WHERE id IN ({PERM_B},{PERM_SENSITIVE}); COMMIT; \
         "
    ))
    .await;
    if let Err(e) = cleanup {
        let _ = c.batch_execute("ROLLBACK").await;
        return Err(format!("restore (replica batch): {}", db(e)).into());
    }
    // The directory-created people go with their mailboxes (outside the replica role, so
    // the mailbox triggers run).
    let targets = users
        .iter()
        .skip(2)
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if !targets.is_empty() {
        c.batch_execute(&format!(
            "DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id IN ({targets})); \
             DELETE FROM mailboxes WHERE user_id IN ({targets}); \
             DELETE FROM users WHERE id IN ({targets});"
        ))
        .await
        .map_err(|e| format!("restore (people): {}", db(e)))?;
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

/// Every row a transition route can change, for the fixture users only.
async fn snapshot(c: &tokio_postgres::Client, users: &[i64]) -> Result<Value, BoxError> {
    let list = users
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let owned = format!("t.user_id IN ({list})");
    Ok(json!({
        "transitions": rows(c, &format!("SELECT jsonb_build_object('user_id',t.user_id,'kind',t.kind,'state',t.state,'protected',t.protected,'generation',t.transition_generation,'actor_user_id',t.actor_user_id,'decided_by',t.approved_by_user_id,'reason',t.reason,'failure',t.failure_code,'boundary',t.rollback_boundary,'preview_digest',encode(t.preview_digest,'hex'),'rollback_digest',encode(t.rollback_preview_digest,'hex'),'rollback_reason',t.rollback_reason,'has_approval',t.approval_request_id IS NOT NULL,'has_rollback_approval',t.rollback_approval_request_id IS NOT NULL,'requester_elevation',t.requester_elevation_id IS NOT NULL,'approver_elevation',t.approver_elevation_id IS NOT NULL,'execution_elevation',t.execution_elevation_id IS NOT NULL,'rollback_requester_elevation',t.rollback_requester_elevation_id IS NOT NULL,'rollback_execution_elevation',t.rollback_execution_elevation_id IS NOT NULL,'authorized_generation',t.authorized_generation,'committed',t.committed_at IS NOT NULL,'completed',t.completed_at IS NOT NULL)::text FROM identity_transitions t WHERE {owned} ORDER BY t.created_at,t.id")).await?,
        "steps": rows(c, &format!("SELECT jsonb_build_object('user_id',t.user_id,'ordinal',s.ordinal,'stage',s.stage,'state',s.state,'attempts',s.attempt_count,'error',s.error_code)::text FROM identity_transition_steps s JOIN identity_transitions t ON t.id=s.transition_id WHERE {owned} ORDER BY t.created_at,t.id,s.ordinal")).await?,
        "effects": rows(c, &format!("SELECT jsonb_build_object('user_id',t.user_id,'kind',e.effect_kind,'state',e.state,'attempts',e.attempt_count,'error',e.last_error_code,'worker',e.worker_id IS NOT NULL)::text FROM identity_transition_effects e JOIN identity_transitions t ON t.id=e.transition_id WHERE {owned} ORDER BY t.created_at,t.id,e.effect_kind")).await?,
        "events": rows(c, &format!("SELECT jsonb_build_object('user_id',e.user_id,'actor_user_id',e.actor_user_id,'action',e.action,'reason',e.reason,'metadata',e.metadata)::text FROM identity_link_events e WHERE e.transition_id IS NOT NULL AND e.user_id IN ({list}) ORDER BY e.id")).await?,
        "challenges": rows(c, &format!("SELECT jsonb_build_object('actor_user_id',h.actor_user_id,'generation',h.transition_generation,'digest',encode(h.preview_digest,'hex'),'completed',h.completed_at IS NOT NULL,'invalidated',h.invalidated_at IS NOT NULL,'has_elevation',h.elevation_id IS NOT NULL,'idempotency_key',h.idempotency_key)::text FROM identity_transition_challenges h JOIN identity_transitions t ON t.id=h.transition_id WHERE {owned} ORDER BY h.issued_at,h.id")).await?,
        "elevations": rows(c, &format!("SELECT jsonb_build_object('actor_user_id',e.actor_user_id,'generation',e.transition_generation,'amr',e.amr,'acr',e.acr,'consumed',e.consumed_at IS NOT NULL,'invalidated',e.invalidated_at IS NOT NULL,'session_digest',encode(e.session_digest,'hex'),'factor_digest',encode(e.factor_digest,'hex'),'idempotency_key',e.idempotency_key)::text FROM identity_transition_elevations e JOIN identity_transitions t ON t.id=e.transition_id WHERE {owned} ORDER BY e.issued_at,e.id")).await?,
        "approvals": rows(c, "SELECT jsonb_build_object('status',status,'requester_user_id',requester_user_id,'decided_by',decided_by_user_id,'approver_ref',approver_ref,'comment',decision_comment)::text FROM approval_requests WHERE consumer_type='identity.transition' ORDER BY id").await?,
    }))
}

fn wanted(action: &str, label: &str) -> u16 {
    let ok = match action {
        "t-request" | "t-execute" | "t-retry" | "t-rollback" => 202,
        _ => 200,
    };
    match label {
        "denied" => 403,
        "scoped" => match action {
            "t-list" => 200,
            "t-report" => 403,
            _ => 404,
        },
        "nil-id" if action == "t-report" => 404,
        "cursor-expired" => 410,
        "missing" => 404,
        "semicolon" => 200,
        "missing-user" => 409,
        "repeat" if matches!(action, "t-request" | "t-rollback-preview" | "t-retry") => 409,
        "repeat" if matches!(action, "t-approve" | "t-deny") => 403,
        "etag-match" | "etag-star" => 304,
        "oversize" => 413,
        "no-if-match" => 412,
        "no-aal2" | "weak-amr" | "expired-iat" | "not-authorized" | "not-approver"
        | "bad-elevation-id" => 403,
        "stale" if matches!(action, "t-approve" | "t-deny") => 403,
        "repeat" if action == "t-cancel" => 409,
        "stale" | "wrong-state" | "not-failed" => 409,
        "non-utf8-filter" => 500,
        "non-utf8-source" | "non-utf8-state" | "non-utf8-cursor" | "non-utf8-name"
        | "bad-limit" | "bad-limit-text" | "over-limit" | "bad-sort" | "unknown-param"
        | "repeated" | "bad-state" | "long-state" | "long-filter" | "bad-source"
        | "long-source" | "bad-cursor" | "cursor-mismatch" | "bad-id" | "nil-id" | "bad-json"
        | "unknown-field" | "typed" | "trailing" | "null-body" | "bad-digest"
        | "bad-generation" | "reason-mismatch" | "reason-required" | "key-mismatch" | "bad-key"
        | "bad-elevation" | "bad-approval" | "bad-user" | "bad-target" | "bad-challenge"
        | "bad-effect" | "no-approval" | "missing-key" => 400,
        _ => ok,
    }
}

struct Plan {
    method: &'static str,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
    shown_body: String,
    query: String,
    repeat: bool,
    aal2: Option<Vec<&'static str>>,
}

fn aal2_token(user: i64, acr: &str, amr: &[&str], age: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    claims["acr"] = json!(acr);
    claims["amr"] = json!(amr);
    claims["iat"] = json!(now - age);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn plan(action: &str, label: &str, p: &Prep, other_user: i64) -> Plan {
    let (method, pattern) = route(action);
    let id = match label {
        "bad-id" => "bad".to_string(),
        "nil-id" => "00000000-0000-0000-0000-000000000000".to_string(),
        "missing" => key(9999),
        "uppercase" => p.tid.to_uppercase(),
        _ => p.tid.clone(),
    };
    let effect = match label {
        "bad-effect" => "bad".to_string(),
        "not-failed" => key(9998),
        _ => p.effect.clone(),
    };
    let mut path = pattern.replace("{id}", &id).replace("{effectId}", &effect);
    let write = method == "POST";
    let uses_reason = !matches!(action, "t-issue" | "t-complete");
    let mut headers: Vec<(String, String)> = vec![];
    let mut body = String::new();
    let mut shown = String::new();
    let mut query = String::new();
    let mut repeat = false;
    let mut aal2 = None;
    let digest = if label == "stale" {
        "0".repeat(64)
    } else {
        p.digest.clone()
    };
    let generation = if label == "stale" {
        "999".to_string()
    } else {
        p.generation.to_string()
    };
    let k1 = key(1);
    if write {
        headers.push(("content-type".into(), "application/json".into()));
        headers.push(("idempotency-key".into(), k1.clone()));
        if uses_reason {
            headers.push(("x-audit-reason".into(), REASON.into()));
        }
        let fence_digest = matches!(
            action,
            "t-issue"
                | "t-complete"
                | "t-request"
                | "t-approve"
                | "t-deny"
                | "t-execute"
                | "t-rollback"
        );
        headers.push((
            "if-match".into(),
            if fence_digest {
                format!("\"{digest}\"")
            } else {
                format!("\"{generation}\"")
            },
        ));
        body = match action {
            "t-preview" => json!({"userId": p.target.to_string(), "reason": REASON, "idempotencyKey": k1}).to_string(),
            "t-issue" => json!({"previewDigest": digest, "idempotencyKey": k1}).to_string(),
            "t-complete" => {
                aal2 = Some(vec!["pwd", "otp", "mfa"]);
                json!({"challengeId": p.challenge, "previewDigest": digest, "idempotencyKey": k1}).to_string()
            }
            "t-request" | "t-approve" | "t-deny" => {
                json!({"previewDigest": digest, "elevationId": p.elevation, "reason": REASON, "idempotencyKey": k1}).to_string()
            }
            "t-execute" => json!({"previewDigest": digest, "elevationId": p.elevation, "reason": REASON, "idempotencyKey": k1}).to_string(),
            "t-rollback" => {
                json!({"previewDigest": digest, "elevationId": p.elevation, "approvalRequestId": p.approval, "reason": REASON, "idempotencyKey": k1}).to_string()
            }
            _ => json!({"expectedGeneration": generation, "reason": REASON, "idempotencyKey": k1}).to_string(),
        };
        shown = body.clone();
        macro_rules! set {
            ($e:expr) => {{
                let text: String = $e;
                body = text.clone();
                shown = text;
            }};
        }
        let strip =
            |headers: &mut Vec<(String, String)>, name: &str| headers.retain(|(k, _)| k != name);
        match label {
            "repeat" => repeat = true,
            "bad-json" => set!("{\"reason\":".into()),
            "unknown-field" => set!(body.replacen('{', "{\"extra\":1,", 1)),
            "typed" => {
                let t = if action == "t-preview" {
                    body.replace(&format!("\"{}\"", p.target), &p.target.to_string())
                } else {
                    body.replace(&format!("\"{generation}\""), &generation)
                };
                set!(t)
            }
            "trailing" => set!(format!("{body} {{}}")),
            "null-body" => set!("null".into()),
            "oversize" => {
                shown = "{\"reason\":\"<70000 x>\"}".into();
                body = format!("{{\"reason\":\"{}\"}}", "x".repeat(70000));
            }
            "bad-digest" => {
                let upper = digest.to_uppercase();
                headers.retain(|(k, _)| k != "if-match");
                headers.push(("if-match".into(), format!("\"{upper}\"")));
                set!(body.replace(&digest, &upper))
            }
            "bad-generation" => set!(body.replace(&format!("\"{generation}\""), "\"0\"")),
            "no-if-match" => strip(&mut headers, "if-match"),
            "key-mismatch" => {
                strip(&mut headers, "idempotency-key");
                headers.push(("idempotency-key".into(), key(2)));
            }
            "missing-key" => strip(&mut headers, "idempotency-key"),
            "bad-key" => {
                strip(&mut headers, "idempotency-key");
                headers.push(("idempotency-key".into(), "not-a-uuid".into()));
                set!(body.replace(&k1, "not-a-uuid"))
            }
            "reason-mismatch" => {
                strip(&mut headers, "x-audit-reason");
                headers.push(("x-audit-reason".into(), "another reason".into()));
            }
            "reason-required" => strip(&mut headers, "x-audit-reason"),
            "bad-elevation" => set!(body.replace(&p.elevation, "not-a-uuid")),
            "bad-elevation-id" => set!(body.replace(&p.elevation, &key(7777))),
            "bad-approval" => set!(body.replacen(
                "\"idempotencyKey\"",
                "\"approvalRequestId\":\"x\",\"idempotencyKey\"",
                1
            )),
            "no-approval" => {
                set!(body.replace(&format!("\"approvalRequestId\":{},", json!(p.approval)), ""))
            }
            "bad-challenge" => set!(body.replace(&p.challenge, "bad")),
            "bad-user" => set!(body.replace(&format!("\"{}\"", p.target), "\"0\"")),
            "missing-user" => set!(body.replace(&format!("\"{}\"", p.target), "\"99999999\"")),
            "bad-target" => set!(body.replacen(
                "\"idempotencyKey\"",
                "\"targetLinkId\":\"x\",\"idempotencyKey\"",
                1
            )),
            "header-key" => set!(body.replace(&k1, "")),
            "no-aal2" => aal2 = Some(vec!["pwd"]),
            "weak-amr" => aal2 = Some(vec!["pwd", "mfa"]),
            _ => {}
        }
        let _ = other_user;
        // The shown body carries run-specific ids: show them by name.
        shown = shown
            .replace(
                &format!("\"userId\":\"{}\"", p.target),
                "\"userId\":\"<target>\"",
            )
            .replace(
                &format!("\"userId\":{}", p.target),
                "\"userId\":\"<target>\"",
            );
        if let Some(approval) = &p.approval {
            shown = shown.replace(
                &format!("\"approvalRequestId\":\"{approval}\""),
                "\"approvalRequestId\":\"<approvalRequestId>\"",
            );
        }
        shown = shown.replace(&digest.to_uppercase(), "<DIGEST>");
        if label == "no-aal2" {
            aal2 = Some(vec![]);
        }
    } else {
        match label {
            "etag-match" | "etag-star" | "etag-miss" => {}
            "filter" => query = format!("?filter={}", enc("previewed")),
            "state" => query = "?state=previewed".into(),
            "source" => query = format!("?source={}", enc("legacy:scim")),
            "sort" => query = "?sort=-createdAt".into(),
            "limit" => query = "?limit=1".into(),
            "page2" => query = "?limit=1&cursor=<cursor>".into(),
            "bad-limit" => query = "?limit=0".into(),
            "bad-limit-text" => query = "?limit=abc".into(),
            "over-limit" => query = "?limit=501".into(),
            "bad-sort" => query = "?sort=name".into(),
            "unknown-param" => query = "?bogus=1".into(),
            "repeated" => query = "?limit=1&limit=2".into(),
            "bad-state" => query = "?state=nope".into(),
            "long-state" => query = format!("?state={}", "x".repeat(33)),
            "long-filter" => query = format!("?filter={}", "x".repeat(300)),
            "non-utf8-filter" => query = "?filter=%FF%FEbad".into(),
            "non-utf8-source" => query = "?source=a%FF".into(),
            "non-utf8-state" => query = "?state=%FF".into(),
            "non-utf8-cursor" => query = "?cursor=%FF".into(),
            "non-utf8-name" => query = "?%FF=1".into(),
            "bad-source" => query = "?source=-bad".into(),
            "long-source" => query = format!("?source=a{}", "b".repeat(64)),
            "semicolon" => query = "?limit=1;limit=2".into(),
            "bad-cursor" => query = "?cursor=!!".into(),
            "cursor-mismatch" | "cursor-expired" => query = "?limit=1&cursor=<cursor>".into(),
            _ => {}
        }
        path = format!("{path}{query}");
    }
    Plan {
        method,
        path,
        headers,
        body,
        shown_body: shown,
        query,
        repeat,
        aal2,
    }
}

/// Prepares the transition(s) a case needs and returns what its request refers to.
async fn prepare(fx: &Fx<'_>, action: &str, label: &str) -> Result<Prep, BoxError> {
    // `scoped` cases are driven by a role that cannot reach the target, so the fixture
    // transitions are made by the other administrator, who can.
    let maker = if label == "scoped" { fx.b } else { fx.a };
    let target = fx.target;
    let mut p = match action {
        "t-list" => {
            let first = fx.preview(maker, target, 3).await?;
            fx.preview(maker, fx.target2, 4).await?;
            first
        }
        "t-read" | "t-report"
            if label == "executed" || action == "t-report" && label == "success" =>
        {
            let mut p = fx.failed(maker, target, 3).await?;
            p.generation = fx.generation(&p.tid).await?;
            p
        }
        "t-request" if label == "protected" => {
            fx.protect(target).await?;
            fx.set_approver(&[fx.b], fx.b).await?;
            let mut p = fx.preview(maker, target, 3).await?;
            p.elevation = fx.elevate(maker, &p.tid, &p.digest, 13).await?;
            p
        }
        "t-request" => {
            let mut p = fx.preview(maker, target, 3).await?;
            p.elevation = fx.elevate(maker, &p.tid, &p.digest, 13).await?;
            p
        }
        "t-approve" | "t-deny" => {
            // B asks, A (the break-glass approver and the caller) decides.
            fx.protect(target).await?;
            fx.set_approver(&[fx.a], fx.a).await?;
            let mut p = fx.preview(fx.b, target, 3).await?;
            let e = fx.elevate(fx.b, &p.tid, &p.digest, 13).await?;
            fx.request(fx.b, &p, &e, 23).await?;
            if label == "not-approver" {
                // The caller loses the break-glass role after the request was filed.
                fx.set_approver(&[fx.b], fx.a).await?;
            }
            p.elevation = if label == "scoped" {
                key(7001)
            } else {
                fx.elevate(fx.a, &p.tid, &p.digest, 33).await?
            };
            p
        }
        "t-execute" if label == "not-authorized" => {
            let mut p = fx.preview(maker, target, 3).await?;
            p.elevation = fx.elevate(maker, &p.tid, &p.digest, 13).await?;
            p
        }
        "t-execute" => fx.authorized(maker, target, 3).await?,
        "t-rollback-preview" if label == "wrong-state" => fx.preview(maker, target, 3).await?,
        "t-retry" | "t-rollback-preview" => fx.failed(maker, target, 3).await?,
        "t-rollback" => {
            // Forward failure, rollback preview, approved rollback request (B approves).
            let approver = if maker == fx.a { fx.b } else { fx.a };
            fx.set_approver(&[fx.a, fx.b], approver).await?;
            let mut p = fx.failed(maker, target, 3).await?;
            let v = json_of(
                fx.c.owner,
                &format!(
                    "SELECT identity_transition_rollback_preview({maker},'{}',{},'{REASON}','{}')::text",
                    p.tid, p.generation, key(60)
                ),
            )
            .await?;
            let rollback_digest = v["rollback"]["previewDigest"]
                .as_str()
                .or(v["previewDigest"].as_str())
                .ok_or("no rollback digest")?
                .to_owned();
            p.digest = rollback_digest;
            let e = fx.elevate(maker, &p.tid, &p.digest, 63).await?;
            let r = fx.request(maker, &p, &e, 73).await?;
            let approval = r["rollback"]["approvalRequestId"]
                .as_str()
                .ok_or("no rollback approval id")?
                .to_owned();
            if label == "scoped" {
                // The scoped caller cannot reach the person, so the route answers 404 first.
                p.approval = Some(approval);
                p.elevation = key(7002);
                return Ok(p);
            }
            let e2 = fx.elevate(approver, &p.tid, &p.digest, 83).await?;
            json_of(
                fx.c.owner,
                &format!(
                    "SELECT identity_transition_approve({approver},'{}','{}','{e2}','{REASON}','{}')::text",
                    p.tid, p.digest, key(93)
                ),
            )
            .await?;
            p.approval = Some(approval);
            p.elevation = fx.elevate(maker, &p.tid, &p.digest, 103).await?;
            p.generation = fx.generation(&p.tid).await?;
            p
        }
        "t-complete" => {
            let mut p = fx.preview(maker, target, 3).await?;
            p.challenge = fx.challenge(maker, &p, 13).await?;
            p
        }
        "t-preview" => Prep {
            target,
            ..Prep::default()
        },
        _ => fx.preview(maker, target, 3).await?,
    };
    p.target = target;
    Ok(p)
}

/// Keys whose numeric value is a user id (shown by alias) ...
const USER_KEYS: [&str; 10] = [
    "personId",
    "requestedBy",
    "approvedBy",
    "userId",
    "user_id",
    "actor_user_id",
    "approved_by_user_id",
    "decided_by",
    "requester_user_id",
    "approver_ref",
];
/// ... and keys whose numeric value is a sequence-issued id (always a placeholder).
const OPAQUE_KEYS: [&str; 18] = [
    "authorityLinkId",
    "mailboxId",
    "id",
    "oldLinkId",
    "oldSourceId",
    "linkId",
    "sourceLinkId",
    "targetLinkId",
    "sourceId",
    "targetSourceId",
    "source_id",
    "link_id",
    "target_source_id",
    "target_link_id",
    "approvalRequestId",
    "approval_request_id",
    "rollback_approval_request_id",
    "request_id",
];

/// Replaces sequence-issued numbers under known keys (users by alias), random uuids,
/// 64-digit hex digests and display codes by placeholders, numbered by first appearance.
fn volatile(text: &str, users: &[(i64, &str)], seen: &mut Vec<String>) -> String {
    let mut out = text.to_owned();
    // Numbers (quoted or not) under the numeric keys.
    for key in USER_KEYS
        .iter()
        .chain(OPAQUE_KEYS.iter())
        .chain(["target_id"].iter())
    {
        let alias = USER_KEYS.contains(key);
        for sep in [":", ": "] {
            for quote in ["\"", ""] {
                let needle = format!("\"{key}\"{sep}{quote}");
                let mut result = String::with_capacity(out.len());
                let mut rest = out.as_str();
                while let Some(at) = rest.find(&needle) {
                    result.push_str(&rest[..at + needle.len()]);
                    rest = &rest[at + needle.len()..];
                    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
                    let closed = quote.is_empty() || rest[digits..].starts_with('"');
                    if digits > 0 && closed {
                        let value: i64 = rest[..digits].parse().unwrap_or(-1);
                        let shown = match users.iter().find(|(id, _)| alias && *id == value) {
                            Some((_, name)) => (*name).to_owned(),
                            None => format!("<{key}>"),
                        };
                        if quote.is_empty() {
                            result.push_str(&format!("\"{shown}\""));
                        } else {
                            result.push_str(&shown);
                        }
                        rest = &rest[digits..];
                    }
                }
                result.push_str(rest);
                out = result;
            }
        }
    }
    let mut result = String::with_capacity(out.len());
    let bytes = out.as_bytes();
    let mut i = 0;
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    while i < bytes.len() {
        let uuid = i + 36 <= bytes.len()
            && out.is_char_boundary(i)
            && [8, 13, 18, 23].iter().all(|k| bytes[i + k] == b'-')
            && bytes[i..i + 36]
                .iter()
                .enumerate()
                .all(|(n, b)| [8, 13, 18, 23].contains(&n) || is_hex(*b))
            && (i == 0 || !is_hex(bytes[i - 1]));
        let digest = !uuid
            && i + 64 <= bytes.len()
            && bytes[i..i + 64].iter().all(|b| is_hex(*b))
            && (i == 0 || !is_hex(bytes[i - 1]))
            && (i + 64 == bytes.len() || !is_hex(bytes[i + 64]));
        if uuid {
            let value = &out[i..i + 36];
            // The fixtures' own ids (`95x00000-0000-4000-8000-…`) stay literal. A bare prefix test
            // (`9500…`, `9540…`) also passed a random uuid through one time in 32768, which shifted
            // every `<uuidN>`/`<digestN>` after it by one (#472).
            if value.starts_with("95") && &value[8..24] == "-0000-4000-8000-" {
                result.push_str(value);
            } else {
                let at = seen.iter().position(|s| s == value).unwrap_or_else(|| {
                    seen.push(value.to_owned());
                    seen.len() - 1
                });
                result.push_str(&format!("<uuid{}>", at + 1));
            }
            i += 36;
        } else if digest {
            let value = out[i..i + 64].to_owned();
            let at = seen.iter().position(|s| *s == value).unwrap_or_else(|| {
                seen.push(value);
                seen.len() - 1
            });
            result.push_str(&format!("<digest{}>", at + 1));
            i += 64;
        } else {
            let ch = out[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }
    // The display code is the first eight hex digits of the challenge id.
    let mut text = result;
    for marker in ["\"displayCode\":\"", "\"displayCode\": \""] {
        while let Some(at) = text.find(marker) {
            let from = at + marker.len();
            let Some(len) = text[from..].find('"') else {
                break;
            };
            if &text[from..from + len] == "<display>" {
                break;
            }
            text.replace_range(from..from + len, "<display>");
        }
    }
    scrub_instants(&text)
}

/// Leftovers of an earlier failed run (this oracle's people, transitions, roles).
async fn preclean(c: &tokio_postgres::Client) -> Result<(), BoxError> {
    let sql = format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM identity_transition_effect_targets; DELETE FROM identity_transition_effects; DELETE FROM identity_transition_steps; \
         DELETE FROM identity_transition_idempotency; \
         DELETE FROM identity_link_events WHERE transition_id IS NOT NULL OR link_id IN (SELECT l.id FROM user_identity_links l JOIN users u ON u.id=l.user_id WHERE u.email LIKE 'admin8-target-%'); \
         DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); \
         DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; \
         DELETE FROM identity_transition_elevations; DELETE FROM identity_transition_challenges; \
         DELETE FROM identity_transitions; DELETE FROM approval_requests WHERE consumer_type='identity.transition'; \
         DELETE FROM admin_role_assignments WHERE role_group_id IN ({PERM_B},{PERM_SENSITIVE}); DELETE FROM admin_role_groups WHERE id IN ({PERM_B},{PERM_SENSITIVE}); \
         DELETE FROM identity_attribute_authority WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin8-target-%'); \
         DELETE FROM identity_entitlement_grants WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin8-target-%'); \
         DELETE FROM user_lifecycle_authorities WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin8-target-%'); \
         DELETE FROM user_identity_links WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin8-target-%'); COMMIT; \
         DELETE FROM messages WHERE mailbox_id IN (SELECT m.id FROM mailboxes m JOIN users u ON u.id=m.user_id WHERE u.email LIKE 'admin8-target-%'); \
         DELETE FROM mailboxes WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'admin8-target-%'); \
         DELETE FROM users WHERE email LIKE 'admin8-target-%';"
    );
    if let Err(e) = c.batch_execute(&sql).await {
        let _ = c.batch_execute("ROLLBACK").await;
        return Err(format!("preclean: {}", db(e)).into());
    }
    Ok(())
}

pub async fn case(c: Ctx<'_>) -> Result<(), BoxError> {
    preclean(c.owner).await?;
    let saved = save(c.owner).await?;
    restore_settings(c.owner, &saved).await?;
    let a = c.admin;
    let b = c.users[1].0;
    let third = c.users[2].0;
    let domain: String = c
        .owner
        .query_one(
            "SELECT d.name FROM users u JOIN domains d ON d.id=u.domain_id WHERE u.id=$1",
            &[&third],
        )
        .await?
        .get(0);
    let mut users = vec![a, b];
    let result = case_inner(&c, &domain, &mut users).await;
    // The case's own rows go on every path.
    let cleanup = restore(c.owner, &saved, &users).await;
    if let (Err(e), Err(r)) = (&result, &cleanup) {
        eprintln!("case failed: {e}; restore also failed: {r}");
    }
    result?;
    cleanup
}

async fn case_inner(c: &Ctx<'_>, domain: &str, users: &mut Vec<i64>) -> Result<(), BoxError> {
    let a = c.admin;
    let b = c.users[1].0;
    let owner = c.owner;
    owner
        .batch_execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.identity_model_v2','feature.identity_transitions','feature.cae_runtime')")
        .await?;
    // The gateway now enforces the real CAE runtime chain before these commands (#405).
    owner
        .batch_execute(&format!(
            "INSERT INTO admin_role_groups(id,name,permissions,domain_scope) OVERRIDING SYSTEM VALUE VALUES({PERM_B},'admin8-b','{{users.read}}',NULL),({PERM_SENSITIVE},'admin8-sensitive','{{identity.write}}',NULL); \
             INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES({b},{PERM_B},{b})"
        ))
        .await?;
    // Two linked people the directory sync would have created, with local recovery proof.
    let source = owner
        .query_one(
            "SELECT id,generation FROM identity_sources WHERE source_key='legacy:scim'",
            &[],
        )
        .await?;
    let mut ids = vec![];
    for (n, subject) in ["admin8-subject-1", "admin8-subject-2"].iter().enumerate() {
        let generation: i64 = owner
            .query_one(
                "SELECT generation FROM identity_sources WHERE source_key='legacy:scim'",
                &[],
            )
            .await?
            .get(0);
        let applied = json_of(
            owner,
            &format!(
                "SELECT identity_source_scim_apply({},{generation},gen_random_uuid(),'{subject}','{{\"operation\":\"upsert\",\"email\":\"admin8-target-{}@{domain}\",\"displayName\":\"Admin8 Target {}\",\"enabled\":true}}'::jsonb)::text",
                source.get::<_, i64>(0),
                n + 1,
                n + 1
            ),
        )
        .await?;
        let user: i64 = applied["userId"].as_str().ok_or("no userId")?.parse()?;
        owner
            .execute(
                "UPDATE users SET password_hash='local-recovery-proof' WHERE id=$1",
                &[&user],
            )
            .await?;
        ids.push(user);
        users.push(user);
    }
    let fx = Fx {
        c,
        a,
        b,
        target: ids[0],
        target2: ids[1],
        source: (source.get(0), source.get(1)),
    };
    let _ = fx.source;
    let prep = prepare(&fx, c.action, c.label).await?;
    let aliases: Vec<(i64, &str)> = vec![
        (a, "<admin>"),
        (b, "<other>"),
        (ids[0], "<target>"),
        (ids[1], "<target2>"),
    ];

    let mut plan = plan(c.action, c.label, &prep, b);
    let mut cursor_note = String::new();
    // A list cursor minted by the same route for the same options.
    let send = |plan_path: String,
                headers: Vec<(String, String)>,
                body: String,
                token: String,
                method: &'static str| {
        let address = c.address;
        async move {
            let mut request = Request::builder()
                .method(method)
                .uri(format!("/api{plan_path}"))
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("x-request-id", "gofree-admin8-oracle")
                .header("authorization", format!("Bearer {token}"));
            for (k, v) in headers {
                request = request.header(k, v);
            }
            Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
        }
    };
    let admin = super::admin_token(a);
    if plan.path.contains("<cursor>") {
        let base = plan.path.split('?').next().unwrap().to_owned();
        let minted = send(
            format!("{base}?limit=1"),
            vec![],
            String::new(),
            admin.clone(),
            "GET",
        )
        .await?;
        let body = String::from_utf8(common::body_bytes(minted).await.to_vec())?;
        let value: Value = serde_json::from_str(&body)?;
        let mut cursor = value["nextCursor"]
            .as_str()
            .ok_or_else(|| format!("no nextCursor in {body}"))?
            .to_owned();
        if c.label == "cursor-mismatch" {
            plan.path = format!("{base}?limit=1&source=legacy:scim&cursor={cursor}");
        } else if c.label == "cursor-expired" {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let mut v: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&cursor)?)?;
            v["expires"] = json!(1);
            cursor = URL_SAFE_NO_PAD.encode(v.to_string());
            plan.path = plan.path.replace("<cursor>", &cursor);
        } else {
            plan.path = plan.path.replace("<cursor>", &cursor);
        }
        cursor_note = "<cursor>".into();
    }
    let etag_header = if matches!(c.label, "etag-match" | "etag-star" | "etag-miss") {
        let first = send(
            plan.path.clone(),
            vec![],
            String::new(),
            admin.clone(),
            "GET",
        )
        .await?;
        let etag = first
            .headers()
            .get("etag")
            .ok_or("no etag")?
            .to_str()?
            .to_owned();
        Some(match c.label {
            "etag-match" => format!("\"nope\", {etag}"),
            "etag-star" => "*".to_owned(),
            _ => "\"nope\"".to_owned(),
        })
    } else {
        None
    };
    if let Some(value) = &etag_header {
        plan.headers.push(("if-none-match".into(), value.clone()));
    }
    // Per-case database setup.
    if c.label == "reason-required" {
        owner.batch_execute("UPDATE audit_policy SET reason_required_areas = reason_required_areas || ARRAY['identity']::text[] WHERE id=1 AND NOT ('identity'=ANY(reason_required_areas))").await?;
    }
    let token = match &plan.aal2 {
        Some(amr) if c.label == "expired-iat" => aal2_token(a, "aal2", amr, 400),
        Some(amr) if c.label == "no-aal2" => aal2_token(a, "aal1", amr, 10),
        Some(amr) => aal2_token(a, "aal2", amr, 10),
        None => admin.clone(),
    };
    let mut approval_created = c.db.listen("approval_created").await?;
    let mut approval_decided = c.db.listen("approval_decided").await?;
    let before = snapshot(owner, users).await?;
    let audit_from: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let (mut first_status, mut first_text) = (None, None);
    if plan.repeat {
        let first = send(
            plan.path.clone(),
            plan.headers.clone(),
            plan.body.clone(),
            token.clone(),
            plan.method,
        )
        .await?;
        first_status = Some(first.status().as_u16());
        first_text = Some(String::from_utf8(common::body_bytes(first).await.to_vec())?);
    }
    let response = send(
        plan.path.clone(),
        plan.headers.clone(),
        plan.body.clone(),
        token.clone(),
        plan.method,
    )
    .await?;
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
    let want = wanted(c.action, c.label);
    if c.recording && status != want && std::env::var_os("GOFREE_ORACLE_LEARN").is_none() {
        return Err(format!(
            "Go {}/{}: expected {want}, got {status}: {raw}",
            c.action, c.label
        )
        .into());
    }
    if std::env::var_os("GOFREE_ORACLE_LEARN").is_some() {
        eprintln!(
            "LEARN {}/{} -> {status} {}",
            c.action,
            c.label,
            raw.chars().take(300).collect::<String>()
        );
    }
    let after = snapshot(owner, users).await?;
    let mut notify = Vec::new();
    for (channel, listener) in [
        ("approval_created", &mut approval_created),
        ("approval_decided", &mut approval_decided),
    ] {
        for event in listener.drain(owner).await? {
            notify.push(
                json!({"channel": channel, "payload": serde_json::from_str::<Value>(&event)?}),
            );
        }
    }
    let audit: Vec<Value> = owner
        .query(
            "SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",
            &[&audit_from],
        )
        .await?
        .iter()
        .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
        .collect::<Result<_, _>>()?;
    let mut audit = audit;
    for row in &mut audit {
        row["id"] = json!("<audit>");
        for key in ["checksum", "prev_checksum"] {
            if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                row[key] = json!("<checksum>");
            }
        }
    }
    // The digests the step-up recorded are the ones the verified token implies.
    let mut bindings = Value::Null;
    if c.action == "t-complete" && status == 200 {
        use sha2::Digest as _;
        let iat: i64 = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap())?)?;
            claims["iat"].as_i64().unwrap_or(0)
        };
        let _ = iat;
        let row = owner
            .query_one("SELECT encode(session_digest,'hex'),encode(factor_digest,'hex') FROM identity_transition_elevations WHERE actor_user_id=$1 AND transition_id=$2::text::uuid ORDER BY issued_at DESC LIMIT 1", &[&a, &prep.tid])
            .await?;
        let stamp = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let claims: Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap())?)?;
            let secs = claims["iat"].as_i64().unwrap_or(0);
            owner.query_one("SELECT to_char(to_timestamp($1::double precision) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')", &[&(secs as f64)]).await?.get::<_, String>(0)
        };
        let session = format!(
            "{:x}",
            sha2::Sha256::digest(
                format!("setjoin-identity-transition-session-v1\n{a}\nblobs1-test\n{stamp}")
                    .as_bytes()
            )
        );
        let factor = format!(
            "{:x}",
            sha2::Sha256::digest(
                format!(
                    "setjoin-identity-transition-factor-v1\n{a}\n{}\n{}\n{}\naal2\nmfa,otp,pwd\nblobs1-test",
                    prep.tid, prep.challenge, prep.digest
                )
                .as_bytes()
            )
        );
        bindings = json!({"session_matches": row.get::<_, String>(0) == session, "factor_matches": row.get::<_, String>(1) == factor});
        if bindings["session_matches"] != json!(true) || bindings["factor_matches"] != json!(true) {
            return Err(format!(
                "step-up bindings differ from the verified-token formula: {bindings}"
            )
            .into());
        }
    }
    let wire_etag = headers.get("etag").cloned();
    let _ = wire_etag;
    if let Some(date) = headers.get_mut("date") {
        *date = json!(["<timestamp>"]);
    }
    let mut seen: Vec<String> = Vec::new();
    let masked_raw = volatile(&super::mask_cursors(&(c.names)(&raw)), &aliases, &mut seen);
    if let Some(length) = headers.get_mut("content-length") {
        if length[0] != raw.len().to_string() {
            return Err("bad wire length".into());
        }
        *length = json!([masked_raw.len().to_string()]);
    }
    let (method, pattern) = route(c.action);
    let mut request =
        json!({"method": method, "path": pattern, "external_path": format!("/api{pattern}")});
    let shown_headers: Vec<&str> = plan.headers.iter().map(|(k, _)| k.as_str()).collect();
    if !shown_headers.is_empty() {
        request["headers"] = json!(shown_headers);
    }
    if !plan.query.is_empty() {
        request["query"] = json!(plan.query);
    }
    if !plan.shown_body.is_empty() {
        request["body"] = json!(plan.shown_body);
    }
    let _ = cursor_note;
    let masked_first = first_text
        .as_ref()
        .map(|t| volatile(&(c.names)(t), &aliases, &mut seen));
    let mut observation = json!({
        "request": request,
        "response": {"status": status, "headers": headers, "body": masked_raw},
        "effects": [{"table": "identity", "before": before, "after": after}],
        "audit": audit,
        "notify": notify,
    });
    if bindings != Value::Null {
        observation["bindings"] = bindings;
    }
    if let (Some(s), Some(t)) = (first_status, masked_first) {
        observation["first"] = json!({"status": s, "body": t});
    }
    // One pass over the finished observation: names, domains, ids, digests, instants.
    let mut text = (c.names)(&observation.to_string())
        .replace(&format!("domain={}", c.other_domain), "domain=<scope>");
    text = volatile(&text, &aliases, &mut seen);
    let observation: Value = serde_json::from_str(&text)?;
    // Etag headers carry digests or generations; they were masked with the rest.
    if c.label == "reason-required" {
        owner.batch_execute("UPDATE audit_policy SET reason_required_areas = array_remove(reason_required_areas,'identity') WHERE id=1").await?;
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
    let writes = method == "POST";
    if c.recording {
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        record(
            &file,
            &json!({"format":1,"route":route_name,"case":c.label,"go_source":source,"observation":observation}),
        )?;
        if writes {
            record(
                &row_file,
                &json!({"format":1,"route":route_name,"case":format!("{}-row-effects", c.label),"go_source":source,"effects":observation["effects"]}),
            )?;
        }
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
        compared?;
        if writes {
            let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
            golden::compare(&expected["effects"], &observation["effects"])?;
        }
        eprintln!("GOLDEN-REPLAY: {route_name} :: {}", c.label);
    }
    Ok(())
}
