//! F12 administrative compliance authority. Organization-wide in frozen Go.
#![forbid(unsafe_code)]
pub mod members;
pub mod workers;

pub mod channels;
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, ReceiptCommand, ScopedExecutor, StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};

pub const VIEW: &str = "chat.compliance_view";
pub const MANAGE: &str = "chat.compliance_manage";
/// Sealed verified actor and the required live compliance permission.
pub struct ComplianceAuthority {
    actor: AuthContext,
    permission: &'static str,
    signed: bool,
}
impl ComplianceAuthority {
    pub fn actor(&self) -> &AuthContext {
        &self.actor
    }
}

pub async fn authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    manage: bool,
) -> Result<Option<ComplianceAuthority>, StatementFailure> {
    let permissions = if actor.signed_admin() {
        let user = actor.user_id();
        exec.read("SELECT DISTINCT unnest(rg.permissions) FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",&[(&user,Type::INT8)]).await?.into_iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>()
    } else {
        actor.signed_permissions().to_vec()
    };
    let permission = if permissions.iter().any(|p| p == MANAGE) {
        MANAGE
    } else if !manage && permissions.iter().any(|p| p == VIEW) {
        VIEW
    } else {
        return Ok(None);
    };
    Ok(Some(ComplianceAuthority {
        actor: actor.clone(),
        permission,
        signed: !actor.signed_admin(),
    }))
}

/// One existing reducer owns the complete Go transaction and chain audit.
pub async fn hold(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
    on: bool,
    reason: Option<String>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    command(exec,scope,"chat_channel_set_hold",operation,
        "SELECT chat_channel_set_hold($2,$4,$5,$6) WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL AND ($7 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$2 AND $8=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))",
        &[(&channel,Type::INT8),(&on,Type::BOOL),(&reason,Type::TEXT),(&scope.signed,Type::BOOL),(&scope.permission,Type::TEXT)]).await
}

async fn command(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    name: &'static str,
    operation: [u8; 16],
    sql: &str,
    params: &[setjoin_pg::Param<'_>],
) -> CommandOutcome<(), StatementFailure> {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(scope.actor.user_id()).expect("verified actor"),
        MailboxId::new(scope.actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(name.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F12",
            command: name,
        },
        &envelope,
        &auth,
        Instant::now() + Duration::from_secs(30),
        sql,
        params,
        |rows| {
            if rows.is_empty() {
                Err(StatementFailure {
                    hint: None,
                    sqlstate: Some("42501".into()),
                    message: "compliance authority changed".into(),
                })
            } else {
                Ok(())
            }
        },
    )
    .await
}

/// Frozen Go's durable best-effort middleware denial audit. Email is signed
/// token provenance; permission is current database authority, never that email.
pub async fn denied(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    path: &str,
    manage: bool,
    operation: [u8; 16],
) {
    let missing = if manage {
        MANAGE.to_owned()
    } else {
        format!("{VIEW}|{MANAGE}")
    };
    let before =
        serde_json::json!({"actor":actor.email(),"target":path,"missingPermission":missing})
            .to_string();
    let scope = ComplianceAuthority {
        actor: actor.clone(),
        permission: MANAGE,
        signed: false,
    };
    let _=command(exec,&scope,"console.denied",operation,
        "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint IS NOT NULL AND $2::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&before,Type::TEXT),(&path,Type::TEXT)]).await;
}

/// Existing reducer owns the retention override, trigger rails and chain act.
pub async fn retention(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
    days: Option<i32>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    command(exec,scope,"chat_channel_set_retention",operation,
        "SELECT chat_channel_set_retention($2,$4,$5) WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL AND ($6 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$2 AND $7=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))",
        &[(&channel,Type::INT8),(&days,Type::INT4),(&scope.signed,Type::BOOL),(&scope.permission,Type::TEXT)]).await
}

/// Go commits this one-statement knob preset independently of classification.
/// A missing channel is still a successful zero-row preset, as in frozen Go.
pub async fn classification_knobs(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
    days: i32,
    worm: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    command(exec,scope,"classification.knobs",operation,
        "WITH changed AS (UPDATE chat_channels SET retention_days=$5,worm_mode=$6 WHERE id=$4 AND ($7 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$2 AND $8=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until))) RETURNING id) SELECT (SELECT count(*) FROM changed) WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL AND ($7 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$2 AND $8=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))",
        &[(&channel,Type::INT8),(&days,Type::INT4),(&worm,Type::TEXT),(&scope.signed,Type::BOOL),(&scope.permission,Type::TEXT)]).await
}

pub async fn classification(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
    class: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    command(exec,scope,"chat_channel_set_classification",operation,
        "SELECT chat_channel_set_classification($2,$4,$5) WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL AND ($6 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$2 AND $7=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))",
        &[(&channel,Type::INT8),(&class,Type::TEXT),(&scope.signed,Type::BOOL),(&scope.permission,Type::TEXT)]).await
}

const LIST_CHANNELS: &str = r#"
SELECT c.id, c.kind, c.name,
       c.classification, c.retention_days, c.worm_mode,
       chat_hold_active(c.id) AS legal_hold,   -- REPOINTED (A4b spec §2.3): predicate truth, never the raw boolean
       c.legal_hold_reason, c.last_purged_seq,
       chat_effective_retention(c.id) AS effective_retention_days,
       (SELECT count(*) FROM chat_channel_members m WHERE m.channel_id = c.id) AS member_count,
       (SELECT count(*) FROM chat_case_hold_channels hc
          JOIN chat_case_holds h ON h.id = hc.hold_id AND h.released_at IS NULL
         WHERE hc.channel_id = c.id) AS case_hold_count,
       COALESCE((
         SELECT jsonb_agg(jsonb_build_object('userId', u.id,
                                             'displayName', u.display_name,
                                             'email', u.email)
                          ORDER BY u.display_name)
           FROM (SELECT m2.user_id FROM chat_channel_members m2
                  WHERE m2.channel_id = c.id ORDER BY m2.user_id LIMIT 8) lim
           JOIN users u ON u.id = lim.user_id
       ), '[]'::jsonb)::text AS participants
  FROM chat_channels c
 WHERE ($1::bigint IS NULL OR EXISTS (SELECT 1 FROM chat_channel_members m3
                                       WHERE m3.channel_id = c.id AND m3.user_id = $1))
   AND ($2::text IS NULL OR c.name ILIKE '%'||$2||'%'
        OR EXISTS (SELECT 1 FROM chat_channel_members m4 JOIN users u2 ON u2.id = m4.user_id
                    WHERE m4.channel_id = c.id
                      AND (u2.email ILIKE '%'||$2||'%' OR u2.display_name ILIKE '%'||$2||'%')))
 AND ($6 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$5 AND $7=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))
 ORDER BY c.id
 LIMIT $3 OFFSET $4"#;

pub async fn list(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    user: Option<i64>,
    query: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<serde_json::Value, StatementFailure> {
    let rows = exec
        .read(
            LIST_CHANNELS,
            &[
                (&user, Type::INT8),
                (&query, Type::TEXT),
                (&limit, Type::INT8),
                (&offset, Type::INT8),
                (&scope.actor.user_id(), Type::INT8),
                (&scope.signed, Type::BOOL),
                (&scope.permission, Type::TEXT),
            ],
        )
        .await?;
    let mut out = Vec::new();
    for row in rows {
        let participants: String = row.get(12);
        let mut v = serde_json::json!({"id":row.get::<_,i64>(0),"kind":row.get::<_,String>(1),"classification":row.get::<_,String>(3),"legalHold":row.get::<_,bool>(6),"lastPurgedSeq":row.get::<_,i64>(8),"memberCount":row.get::<_,i64>(10),"caseHoldCount":row.get::<_,i64>(11),"participants":serde_json::from_str::<serde_json::Value>(&participants).map_err(|_|StatementFailure{hint:None,sqlstate:None,message:"invalid participant JSON".into()})?});
        for (index, key) in [(2, "name"), (5, "wormMode"), (7, "legalHoldReason")] {
            if let Some(text) = row.get::<_, Option<String>>(index) {
                v[key] = text.into();
            }
        }
        for (index, key) in [(4, "retentionDays"), (9, "effectiveRetentionDays")] {
            if let Some(n) = row.get::<_, Option<i32>>(index) {
                v[key] = n.into();
            }
        }
        out.push(v);
    }
    Ok(out.into())
}

/// Go's independent, best-effort audited read. Never turns a successful read
/// into a failure; request data cannot supply the actor or action name.
pub async fn audit_read(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    action: &'static str,
    target: Option<i64>,
    ip: &str,
    operation: [u8; 16],
) {
    let _=command(exec,scope,action,operation,
        "SELECT audit_write($2,$4,'chat_channel',$5,NULL,NULL,$6::text::inet,'','core') WHERE $1::bigint IS NOT NULL AND $3::text IS NOT NULL",
        &[(&action,Type::TEXT),(&target,Type::INT8),(&ip,Type::TEXT)]).await;
}

pub async fn audit(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
    before: Option<i64>,
    limit: i64,
) -> Result<serde_json::Value, StatementFailure> {
    let rows=exec.read(r#"SELECT id,to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),user_id,COALESCE(ip::text,''),action,target_type,target_id,before_state::text,after_state::text,notes FROM chat_audit_log WHERE channel_id=$1 AND ($2::bigint IS NULL OR id<$2) AND ($5 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$4 AND $6=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until))) ORDER BY id DESC LIMIT $3"#,
        &[(&channel,Type::INT8),(&before,Type::INT8),(&limit,Type::INT8),(&scope.actor.user_id(),Type::INT8),(&scope.signed,Type::BOOL),(&scope.permission,Type::TEXT)]).await?;
    let mut out = Vec::new();
    for row in rows {
        let mut v = serde_json::json!({"id":row.get::<_,i64>(0),"occurredAt":row.get::<_,String>(1),"action":row.get::<_,String>(4)});
        for (index, key) in [(2, "userId"), (6, "targetId")] {
            if let Some(id) = row.get::<_, Option<i64>>(index) {
                v[key] = id.into();
            }
        }
        for (index, key) in [(5, "targetType"), (9, "notes")] {
            if let Some(s) = row.get::<_, Option<String>>(index) {
                v[key] = s.into();
            }
        }
        let ip: String = row.get(3);
        if !ip.is_empty() {
            v["ip"] = ip.into();
        }
        for (index, key) in [(7, "beforeState"), (8, "afterState")] {
            if let Some(s) = row.get::<_, Option<String>>(index) {
                v[key] = serde_json::from_str(&s).map_err(|_| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "invalid audit JSON".into(),
                })?;
            }
        }
        out.push(v);
    }
    Ok(out.into())
}

fn result_error() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid compliance result".into(),
    }
}

/// Explicit cross-tenant compliance read under the verified live grant. The
/// worker credential is intentional; deny-all audit RLS is never disabled.
async fn compliance_read(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
    sql: &str,
    extra: &[setjoin_pg::Param<'_>],
) -> Result<Vec<setjoin_pg::Row>, StatementFailure> {
    let actor = scope.actor.user_id();
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor).expect("verified actor"),
        MailboxId::new(scope.actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    );
    let mut params: Vec<setjoin_pg::Param<'_>> = vec![
        (&channel, Type::INT8),
        (&actor, Type::INT8),
        (&scope.signed, Type::BOOL),
        (&scope.permission, Type::TEXT),
    ];
    params.extend(extra.iter().map(|(p, t)| (*p, t.clone())));
    let guarded=format!("SELECT * FROM ({sql}) compliance_result WHERE $2::bigint IS NOT NULL AND ($3 OR EXISTS(SELECT 1 FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$2 AND $4=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)))");
    exec.read_scoped(&auth, &guarded, &params).await
}

pub struct ChainSummary {
    pub checked: i64,
    pub valid: bool,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub first_invalid: Option<i64>,
    pub key_version: &'static str,
}
pub async fn chain_summary(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
) -> Result<ChainSummary, StatementFailure> {
    let rows = compliance_read(
        exec,
        scope,
        channel,
        "SELECT row_id,valid FROM verify_chat_audit_chain($1)",
        &[],
    )
    .await?;
    let mut out = ChainSummary {
        checked: 0,
        valid: true,
        from: None,
        to: None,
        first_invalid: None,
        key_version: "v2",
    };
    for row in rows {
        let id: i64 = row.try_get(0).map_err(|_| result_error())?;
        let valid: bool = row.try_get(1).map_err(|_| result_error())?;
        out.checked += 1;
        out.from = out.from.or(Some(id));
        out.to = Some(id);
        if !valid {
            out.valid = false;
            out.first_invalid = out.first_invalid.or(Some(id));
        }
    }
    let rows=compliance_read(exec,scope,channel,"SELECT coalesce(current_setting('app.audit_hmac_key',true),'')<>'' WHERE $1::bigint IS NOT NULL",&[]).await?;
    let has: bool = rows
        .first()
        .ok_or_else(result_error)?
        .try_get(0)
        .map_err(|_| result_error())?;
    if has {
        out.key_version = "v3";
    }
    Ok(out)
}

/// Same ordered notary, chain and anchor checks as frozen Go. A broken or
/// truncated chain never receives anchor verdicts derived from that evidence.
pub async fn verify(
    exec: &ScopedExecutor,
    scope: &ComplianceAuthority,
    channel: i64,
) -> Result<serde_json::Value, StatementFailure> {
    use serde_json::{json, Value};
    let rows=compliance_read(exec,scope,channel,"SELECT (after_state->'heads'->$1::text)::text FROM admin_audit_log WHERE action='chat.chain_notary' ORDER BY id DESC LIMIT 1",&[]).await?;
    let notary = rows
        .first()
        .and_then(|r| r.get::<_, Option<String>>(0))
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| {
            let checksum = v.get("checksum")?.as_str()?.to_owned();
            if checksum.is_empty() {
                return None;
            }
            let id = match v.get("id") {
                None | Some(Value::Null) => 0,
                Some(id) => id.as_i64()?,
            };
            Some(json!({"id":id,"checksum":checksum}))
        });
    let rows=compliance_read(exec,scope,channel,"SELECT id,after_state->>'_checksum' FROM chat_audit_log WHERE channel_id=$1 ORDER BY id DESC LIMIT 1",&[]).await?;
    let live = if let Some(row) = rows.first() {
        Some(
            json!({"id":row.try_get::<_,i64>(0).map_err(|_|result_error())?,"checksum":row.try_get::<_,String>(1).map_err(|_|result_error())?}),
        )
    } else {
        None
    };
    let mut truncated = false;
    if let Some(ref notary) = notary {
        let id = notary["id"].as_i64().ok_or_else(result_error)?;
        if live
            .as_ref()
            .and_then(|v| v["id"].as_i64())
            .is_none_or(|last| last < id)
        {
            truncated = true;
        } else {
            let rows=compliance_read(exec,scope,channel,"SELECT after_state->>'_checksum' FROM chat_audit_log WHERE channel_id=$1 AND id=$5",&[(&id,Type::INT8)]).await?;
            let sum = rows.first().and_then(|r| r.get::<_, Option<String>>(0));
            truncated = sum.as_deref() != notary["checksum"].as_str();
        }
    }
    let summary = chain_summary(exec, scope, channel).await?;
    let mut out = json!({"channelId":channel,"checked":summary.checked,"fromId":summary.from,"toId":summary.to,"chainValid":summary.valid,"firstInvalid":summary.first_invalid,"keyVersion":summary.key_version,"truncationDetected":truncated});
    if let Some(notary) = notary {
        out["notarizedHead"] = notary;
    }
    if let Some(live) = live {
        out["liveHead"] = live;
    }
    if truncated || !summary.valid {
        return Ok(out);
    }
    let rows=compliance_read(exec,scope,channel,"SELECT anchor_id,id_from,id_to,valid,reconciled_from_purge,revisions_unchained FROM chat_chain_anchor_verify($1)",&[]).await?;
    let mut anchors = Vec::new();
    for row in rows {
        anchors.push(json!({"anchorId":row.get::<_,i64>(0),"idFrom":row.get::<_,i64>(1),"idTo":row.get::<_,i64>(2),"valid":row.get::<_,bool>(3),"reconciledFromPurge":row.get::<_,i32>(4),"revisionsUnchained":row.get::<_,i32>(5)}));
    }
    out["anchors"] = anchors.into();
    Ok(out)
}

pub async fn enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    let rows=exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.chat_compliance'),false)",&[]).await?;
    rows.first()
        .ok_or_else(result_error)?
        .try_get(0)
        .map_err(|_| result_error())
}
