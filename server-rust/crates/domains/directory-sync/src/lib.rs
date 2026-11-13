//! Directory sync (F02): AD administration reads and writes.
//!
//! Foundation dependencies only. The actor and mailbox come from the sealed
//! auth context; request ids name targets but never grant authority. Permissions
//! and domain scope are resolved live, as Go's auth chain does for admin tokens.
#![forbid(unsafe_code)]
pub mod ad;
pub mod catalog;
pub mod ldap;
pub mod observers;
pub mod scim;
use serde_json::{json, Map, Value};
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, Param, ReceiptCommand, ScopedExecutor, StatementFailure,
    Type,
};
use sha2::{Digest as _, Sha256};

/// Go's `admin.ConsoleScopes[ConsoleAuth]`, in registration order.
pub const AUTH_CONSOLE: [&str; 4] = [
    "users.read",
    "identity.write",
    "access.policy_read",
    "access.policy_write",
];
pub const IDENTITY_WRITE: [&str; 1] = ["identity.write"];

const CONFLICTS: &str = include_str!("conflicts.sql");
const RESOLVE_ONE: &str = include_str!("resolve_one.sql");
const RESOLVE_ALL: &str = include_str!("resolve_all.sql");
const FIELD_DELETE: &str = include_str!("field_policy_delete.sql");
const FIELD_UPSERT: &str = include_str!("field_policy_upsert.sql");
const TIMESTAMP: &str = "to_char(l.sync_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', l.sync_at AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char(l.sync_at AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'";

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}
pub(crate) fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid directory result".into(),
    }
}

/// Live request-time projection of governed grants for a verified admin.
/// Non-admin tokens keep their signed claims, as Go's resolver skips them.
pub struct Authority {
    permissions: Vec<String>,
    domain_scope: i64,
}
impl Authority {
    pub fn allows_any(&self, wanted: &[&str]) -> bool {
        wanted
            .iter()
            .any(|w| self.permissions.iter().any(|p| p == w))
    }
    /// 0 is global, as Go's `DomainScopeFromContext`.
    pub fn domain_scope(&self) -> i64 {
        self.domain_scope
    }
}
pub async fn authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Authority, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(Authority {
            permissions: actor.signed_permissions().to_vec(),
            domain_scope: actor.signed_domain_scope().unwrap_or(0),
        });
    }
    let user = actor.user_id();
    let rows = exec
        .read(
            "SELECT COALESCE((SELECT array_agg(DISTINCT p) FROM public.admin_role_assignments ra \
             JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id CROSS JOIN LATERAL unnest(rg.permissions) p \
             WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND public.admin_assignment_active(ra.eligible,ra.activated_until)),'{}'::text[]), \
             (SELECT MIN(COALESCE(ra.domain_override,rg.domain_scope)) FROM public.admin_role_assignments ra \
             JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id \
             WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND public.admin_assignment_active(ra.eligible,ra.activated_until))",
            &[(&user, Type::INT8)],
        )
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    Ok(Authority {
        permissions: row.get(0),
        domain_scope: row.get::<_, Option<i64>>(1).unwrap_or(0),
    })
}

/// Go writes the same durable console-denial audit row, best effort.
pub async fn console_denied(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before =
        json!({"actor":actor.email(),"target":path,"missingPermission":permission}).to_string();
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(before.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F02",
            command: "console.denied",
        },
        &envelope,
        &auth,
        deadline(),
        "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&before, Type::TEXT), (&path, Type::TEXT)],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}
pub(crate) fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

/// encoding/json output: HTML escapes applied, RawMessage fields compacted.
pub fn go_json(value: &Value) -> String {
    go_escape(&serde_json::to_string(value).expect("JSON value")) + "\n"
}
pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
fn compact(text: &str) -> String {
    let (mut out, mut quoted, mut escaped) = (String::with_capacity(text.len()), false, false);
    for ch in text.chars() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            out.push(ch);
        } else if !ch.is_ascii_whitespace() {
            out.push(ch);
        }
    }
    out
}

/// Go's `redactConfigValue` + `configStringForResponse` for AD/LDAP rows.
fn config_text(key: &str, value: &str, encrypted: bool) -> String {
    if encrypted || key.ends_with("_enc") || key == "assist.api_key" {
        return "[ENCRYPTED]".into();
    }
    match serde_json::from_str::<Value>(value) {
        Ok(Value::String(text)) => text,
        // json.Unmarshal of null into a string succeeds and leaves it empty.
        Ok(Value::Null) => String::new(),
        _ => value.into(),
    }
}
/// Which directory's configuration or ledger a read serves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Ad,
    Ldap,
}
impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Ad => "ad",
            Source::Ldap => "ldap",
        }
    }
}

pub async fn config(exec: &ScopedExecutor, source: Source) -> Result<String, StatementFailure> {
    // Go's AD read also lists the `enable_*_reset` toggles; LDAP reads its prefix only.
    let sql = match source {
        Source::Ad => "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE 'ad_sync_%' OR key LIKE 'enable_%_reset'",
        Source::Ldap => "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE 'ldap_sync_%'",
    };
    let rows = exec.read(sql, &[]).await?;
    let mut out = Map::new();
    for row in rows {
        let (key, value, encrypted): (String, String, bool) = (row.get(0), row.get(1), row.get(2));
        let text = config_text(&key, &value, encrypted);
        out.insert(key, Value::String(text));
    }
    Ok(go_json(&Value::Object(out)))
}

pub async fn sync_log(
    exec: &ScopedExecutor,
    source: Source,
    domain_scope: i64,
    limit: i64,
) -> Result<String, StatementFailure> {
    if domain_scope != 0 {
        return Ok("[]\n".into());
    }
    let sql = format!(
        "SELECT l.source, l.users_checked, l.users_created, l.users_updated, l.users_disabled, \
         l.fields_skipped, CASE WHEN l.error IS NULL THEN 0 ELSE 1 END, COALESCE(l.duration_ms, 0), \
         {TIMESTAMP}, COALESCE(l.details, '{{}}'::jsonb)::text \
         FROM identity_sync_log l WHERE l.source = $1 ORDER BY l.sync_at DESC LIMIT $2"
    );
    let source = source.name();
    let rows = exec
        .read(&sql, &[(&source, Type::TEXT), (&limit, Type::INT8)])
        .await?;
    let mut out = Vec::new();
    for row in rows {
        let int = |i| row.get::<_, i32>(i);
        let details: String = row.get(9);
        let mut item = Map::new();
        item.insert("source".into(), json!(row.get::<_, String>(0)));
        item.insert("checked".into(), json!(int(1)));
        item.insert("created".into(), json!(int(2)));
        item.insert("updated".into(), json!(int(3)));
        item.insert("disabled".into(), json!(int(4)));
        item.insert("skipped".into(), json!(int(5)));
        item.insert("errors".into(), json!(int(6)));
        item.insert("durationSeconds".into(), json!(int(7) / 1000));
        item.insert("syncedAt".into(), json!(row.get::<_, String>(8)));
        // Placeholder keeps Go's sorted key position; swapped for raw text below.
        item.insert("details".into(), json!("\u{0}details"));
        let text = serde_json::to_string(&Value::Object(item)).map_err(|_| invalid())?;
        out.push(text.replace("\"\\u0000details\"", &compact(&details)));
    }
    Ok(go_escape(&format!("[{}]", out.join(","))) + "\n")
}

/// Test-only (feature `oracle-mutants`, mutant `dirsync-conflicts-unscoped`): frozen Go's
/// unfiltered conflict statements.
fn mutated(sql: &str) -> String {
    if setjoin_contracts::mutants::on("dirsync-conflicts-unscoped") {
        sql.replace("admin_org_wide_grant(", "true OR admin_org_wide_grant(")
    } else {
        sql.to_owned()
    }
}

/// Owner-approved security fix 2026-11-05 (#510): only the conflicts of users the caller reaches
/// through a grant that carries an Auth-console permission (or everyone under an org-wide grant);
/// the list, resolve-one and resolve-all statements share the permission-aware reach.
pub async fn conflicts(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let admin = actor.user_id();
    let rows = exec.read(&mutated(CONFLICTS), &[(&admin, Type::INT8)]).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({"id":row.get::<_,i64>(0),"userId":row.get::<_,i64>(1),"email":row.get::<_,String>(2),
            "field":row.get::<_,String>(3),"localValue":row.get::<_,String>(4),
            "remoteValue":row.get::<_,String>(5),"detectedAt":row.get::<_,String>(6)})
        })
        .collect();
    Ok(go_json(&Value::Array(items)))
}

pub fn resolution(wire: &str) -> Option<&'static str> {
    match wire {
        "keep_local" => Some("kept_local"),
        "accept_remote" => Some("accepted_remote"),
        _ => None,
    }
}

pub(crate) fn envelope(
    auth: &MailboxAuthContext,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}
fn count(rows: &[setjoin_pg::Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// Go's one UPDATE; the number of rows decides 204 or 404 at the edge.
pub async fn resolve_conflict(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    resolution: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F02",
            command: "ad_conflict_resolve",
        },
        &envelope(
            &auth,
            operation,
            &format!("{id}:{resolution}"),
        ),
        &auth,
        deadline(),
        &mutated(RESOLVE_ONE),
        &[(&id, Type::INT8), (&resolution, Type::TEXT)],
        count,
    )
    .await
}
pub async fn resolve_all(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    resolution: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F02",
            command: "ad_conflict_resolve_all",
        },
        &envelope(
            &auth,
            operation,
            &format!("all:{resolution}"),
        ),
        &auth,
        deadline(),
        &mutated(RESOLVE_ALL),
        &[(&resolution, Type::TEXT)],
        count,
    )
    .await
}

/// Owner-approved security fix 2026-11-05 (#376): the read repeats the actor's reach of the
/// target user inside the statement (frozen Go answered any Auth-console caller, so a
/// domain-scoped admin could read a foreign user's field policies).
pub async fn field_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
) -> Result<String, StatementFailure> {
    let admin = actor.user_id();
    // #529: reach through a grant that carries one of the route's permissions only.
    let sql = if setjoin_contracts::mutants::on("fieldpolicy-get-foreign") {
        "SELECT field, policy FROM field_policy WHERE user_id = $1 AND $2::bigint > 0"
    } else if setjoin_contracts::mutants::on("fieldpolicy-any-grant") {
        "SELECT field, policy FROM field_policy WHERE user_id = $1 AND public.admin_can_reach($2, $1)"
    } else {
        "SELECT field, policy FROM field_policy WHERE user_id = $1 AND public.admin_can_reach_perm($2, $1, '{users.read,identity.write,access.policy_read,access.policy_write}'::text[])"
    };
    let rows = exec
        .read(sql, &[(&user, Type::INT8), (&admin, Type::INT8)])
        .await?;
    let mut out = Map::new();
    for row in rows {
        out.insert(row.get::<_, String>(0), Value::String(row.get(1)));
    }
    Ok(go_json(&Value::Object(out)))
}

/// Go's pre-check `admin_can_reach(actor, target)`; the write repeats it in
/// the same statement so a revoked grant cannot slip between check and write.
pub async fn reach(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
) -> Result<bool, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            "SELECT public.admin_can_reach($1,$2)",
            &[(&user, Type::INT8), (&target, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}
/// `reach` through the route's own permission (#529): the Auth-console read list for the
/// field-policy GET, `identity.write` for the PUT. Frozen Go accepted any grant.
pub async fn reach_perm(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    perms: &[&str],
) -> Result<bool, StatementFailure> {
    if setjoin_contracts::mutants::on("fieldpolicy-any-grant") {
        return reach(exec, actor, target).await;
    }
    let user = actor.user_id();
    let perms: Vec<String> = perms.iter().map(|p| (*p).to_owned()).collect();
    let rows = exec
        .read(
            "SELECT public.admin_can_reach_perm($1,$2,$3::text[])",
            &[(&user, Type::INT8), (&target, Type::INT8), (&perms, Type::TEXT_ARRAY)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}
/// The field-policy write statement; the restored-bug mutant `fieldpolicy-any-grant` swaps the
/// permission-aware reach back to Go's any-grant `admin_can_reach`.
fn write_sql(managed: bool) -> &'static str {
    let sql = if managed { FIELD_DELETE } else { FIELD_UPSERT };
    if setjoin_contracts::mutants::on("fieldpolicy-any-grant") {
        return Box::leak(
            sql.replace(
                "public.admin_can_reach_perm($2, $4, '{identity.write}'::text[])",
                "public.admin_can_reach($2, $4)",
            )
            .into_boxed_str(),
        );
    }
    sql
}
pub async fn set_field_policy(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
    field: &str,
    policy: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let managed = policy == "ad_managed";
    let clear: [Param<'_>; 2] = [(&user, Type::INT8), (&field, Type::TEXT)];
    let set: [Param<'_>; 3] = [
        (&user, Type::INT8),
        (&field, Type::TEXT),
        (&policy, Type::TEXT),
    ];
    let params: &[Param<'_>] = if managed { &clear } else { &set };
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F02",
            command: if managed {
                "ad_field_policy_clear"
            } else {
                "ad_field_policy_set"
            },
        },
        &envelope(&auth, operation, &format!("{user}:{field}:{policy}")),
        &auth,
        deadline(),
        write_sql(managed),
        params,
        count,
    )
    .await
}

/// `Some(None)` is an existing user with no principal; `None` is no user.
pub async fn principal_current(
    exec: &ScopedExecutor,
    user: i64,
) -> Result<Option<Option<String>>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT krb5_principal FROM users WHERE id = $1",
            &[(&user, Type::INT8)],
        )
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}
/// Go's reducer call, unchanged: the user-row lock, live reach+permission
/// recheck, compare-and-swap, audit and notify commit in its transaction.
pub async fn set_principal(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    target: i64,
    new_principal: &str,
    old_principal: Option<&str>,
    ip: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F02",
            command: "ad_principal_set",
        },
        &envelope(&auth, operation, &format!("{target}:{new_principal}")),
        &auth,
        deadline(),
        "SELECT ad_principal_set($2,$4,$5,$6,$7::text::inet) WHERE $1::bigint>0 AND $3::text<>''",
        &[
            (&target, Type::INT8),
            (&new_principal, Type::TEXT),
            (&old_principal, Type::TEXT),
            (&ip, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)
        },
    )
    .await
}
