//! Admin identity (F01): users slice.
//!
//! Foundation dependencies only. The actor and mailbox come from the sealed auth
//! context; request ids name targets but never grant authority. Permissions and
//! domain scope are resolved live, as Go's auth chain does for admin tokens.
//! Responses are rendered in `encoding/json` field order (structs) or sorted key
//! order (maps), HTML-escaped, with the trailing newline of Go's `Encoder`.
#![forbid(unsafe_code)]
pub mod access_reviews;
pub mod idv2;
pub mod idv2_ops;
pub mod idv2_source;
pub mod idv2_transitions;
pub mod idv2_upgrade;
pub mod idv2_writes;
pub mod lifecycle;
pub mod org_policies;
pub mod roles;
pub mod scope_sets;
pub mod sod;
use serde_json::json;
use setjoin_authz::AuthContext;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, MailboxId, OperationId},
};
use setjoin_pg::{
    CommandOutcome, MailboxAuthContext, Param, ReceiptCommand, Row, ScopedExecutor,
    StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};

/// Go's `admin.ConsoleScopes[ConsoleAuth]`, in registration order.
pub const AUTH_CONSOLE: [&str; 4] = [
    "users.read",
    "identity.write",
    "access.policy_read",
    "access.policy_write",
];
/// `requireSignInPerm`: the Auth console scopes followed by the Logs console's.
pub const SIGN_IN: [&str; 5] = [
    "users.read",
    "identity.write",
    "access.policy_read",
    "access.policy_write",
    "audit.read",
];
pub const USERS_CREATE: [&str; 1] = ["users.create"];
/// Go's `DomainGlobalOnlyScopes`: refused to any domain-scoped principal.
const GLOBAL_ONLY: [&str; 2] = ["audit.read", "audit.export"];
pub const APPS: [&str; 7] = [
    "mail", "calendar", "contacts", "tasks", "chat", "drive", "meet",
];

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified actor"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}
fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid admin identity result".into(),
    }
}

/// Live request-time projection of governed grants for a verified admin.
/// Non-admin tokens keep their signed claims, as Go's resolver skips them.
pub struct Authority {
    permissions: Vec<String>,
    /// Go's `claims.GlobalPermissions`: permissions of assignments that are neither
    /// domain nor OU/set scoped (empty for a non-admin token, which Go never resolves).
    global: Vec<String>,
    domain_scope: i64,
}
impl Authority {
    pub fn allows_any(&self, wanted: &[&str]) -> bool {
        wanted
            .iter()
            .any(|w| self.permissions.iter().any(|p| p == w))
    }
    /// Go's `requireAnyUnscopedIdentityAdmin` permission half: any of `wanted` is held
    /// by an organization-global assignment.
    pub fn global_any(&self, wanted: &[&str]) -> bool {
        wanted.iter().any(|w| self.global.iter().any(|p| p == w))
    }
    /// 0 is global, as Go's `DomainScopeFromContext`.
    pub fn domain_scope(&self) -> i64 {
        self.domain_scope
    }
    /// Go's `denyDomainScopedForGlobalOnly`: true when the surface names an
    /// organization-wide-only permission and the principal is domain scoped.
    pub fn refused_for_scope(&self, required: &[&str]) -> bool {
        self.domain_scope > 0 && required.iter().any(|p| GLOBAL_ONLY.contains(p))
    }
}
pub async fn authority(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Authority, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(Authority {
            permissions: actor.signed_permissions().to_vec(),
            global: Vec::new(),
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
             AND public.admin_assignment_active(ra.eligible,ra.activated_until)), \
             COALESCE((SELECT array_agg(DISTINCT p) FROM public.admin_role_assignments ra \
             JOIN public.admin_role_groups rg ON rg.id=ra.role_group_id CROSS JOIN LATERAL unnest(rg.permissions) p \
             WHERE ra.user_id=$1 AND (ra.expires_at IS NULL OR ra.expires_at>now()) \
             AND public.admin_assignment_active(ra.eligible,ra.activated_until) \
             AND COALESCE(ra.domain_override,rg.domain_scope) IS NULL AND ra.scope_type IS NULL),'{}'::text[])",
            &[(&user, Type::INT8)],
        )
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    Ok(Authority {
        permissions: row.get(0),
        global: row.get(2),
        domain_scope: row.get::<_, Option<i64>>(1).unwrap_or(0),
    })
}

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}
fn envelope(auth: &MailboxAuthContext, operation: [u8; 16], payload: &str) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}
fn count(rows: &[Row]) -> Result<i64, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
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
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "console.denied",
        },
        &envelope(&auth, operation, &before),
        &auth,
        deadline(),
        "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[(&before, Type::TEXT), (&path, Type::TEXT)],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}

/// encoding/json HTML escaping of an already rendered document.
pub fn go_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
/// Go's `encoding/json` key folding for the characters that fold across ASCII.
pub(crate) fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ſ' => 's',
            '\u{212a}' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}
fn s(text: &str) -> String {
    serde_json::to_string(text).expect("string")
}
fn done(text: String) -> String {
    go_escape(&text) + "\n"
}
/// RFC 3339 with Go's trimmed fractional seconds (`time.Time` JSON), UTC.
fn nano(column: &str) -> String {
    format!(
        "to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', {column} AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char({column} AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'"
    )
}
fn seconds(column: &str) -> String {
    format!("to_char({column} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
}

/// `GET /admin/users`: one page plus Go's best-effort manageable/self flags.
pub async fn users(
    exec: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
    q: &str,
    limit: i64,
    offset: i64,
) -> Result<String, StatementFailure> {
    let pattern = (!q.is_empty()).then(|| format!("%{q}%"));
    let sql = format!(
        "SELECT id, email, display_name, enabled, is_local_admin, department_id, {} FROM users \
         WHERE ($1::text IS NULL OR email ILIKE $1 OR display_name ILIKE $1) AND ($2::bigint = 0 OR domain_id = $2) \
         ORDER BY id DESC LIMIT $3 OFFSET $4",
        nano("created_at")
    );
    let rows = exec
        .read(
            &sql,
            &[
                (&pattern, Type::TEXT),
                (&domain_scope, Type::INT8),
                (&limit, Type::INT8),
                (&offset, Type::INT8),
            ],
        )
        .await?;
    struct Item {
        id: i64,
        text: [String; 3],
        flags: Option<(bool, bool, Option<i64>)>,
        department: Option<i64>,
        enabled: bool,
        admin: bool,
    }
    let mut items = Vec::new();
    for row in &rows {
        // Go skips a row that fails to scan (a NULL in a non-pointer column).
        let (Ok(id), Ok(email), Ok(name), Ok(enabled), Ok(admin), Ok(created)) = (
            row.try_get::<_, i64>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, String>(2),
            row.try_get::<_, bool>(3),
            row.try_get::<_, bool>(4),
            row.try_get::<_, String>(6),
        ) else {
            continue;
        };
        items.push(Item {
            id,
            text: [email, name, created],
            flags: None,
            department: row.try_get::<_, Option<i64>>(5).ok().flatten(),
            enabled,
            admin,
        });
    }
    if !items.is_empty() {
        let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
        let flags = exec
            .read(
                "SELECT u.id, (u.id = $2::bigint) AS is_self, \
                 CASE WHEN a.is_super THEN true ELSE ea.perms <@ a.perms AND NOT (cardinality(ea.perms) > 0 AND a.scope IS NOT NULL AND ea.scope IS NULL) AND (cardinality(a.perms) = 0 OR admin_can_reach($2, u.id)) END AS manageable, \
                 (SELECT m.id FROM mailboxes m WHERE m.user_id=u.id AND m.is_primary ORDER BY m.id LIMIT 1) AS mailbox_id \
                 FROM unnest($1::bigint[]) AS u(id) CROSS JOIN LATERAL admin_effective_authority(u.id) AS ea \
                 CROSS JOIN (SELECT EXISTS(SELECT 1 FROM admin_role_assignments WHERE user_id=$2 AND role_group_id=1 AND (expires_at IS NULL OR expires_at > now())) AS is_super, a0.perms, a0.scope FROM admin_effective_authority($2) AS a0) a",
                &[(&ids, Type::INT8_ARRAY), (&actor, Type::INT8)],
            )
            .await;
        // Go logs and serves the page without flags when this query fails.
        if let Ok(flags) = flags {
            for row in flags {
                let (Ok(id), Ok(is_self), Ok(manageable)) = (
                    row.try_get::<_, i64>(0),
                    row.try_get::<_, bool>(1),
                    row.try_get::<_, bool>(2),
                ) else {
                    continue;
                };
                let mailbox = row.try_get::<_, Option<i64>>(3).ok().flatten();
                if let Some(item) = items.iter_mut().find(|i| i.id == id) {
                    item.flags = Some((is_self, manageable, mailbox));
                }
            }
        }
    }
    let out: Vec<String> = items
        .iter()
        .map(|i| {
            let (is_self, manageable, mailbox) = i.flags.unwrap_or((false, false, None));
            format!(
                "{{\"id\":{},\"email\":{},\"displayName\":{},\"enabled\":{},\"isLocalAdmin\":{}{},\"createdAt\":{}{},\"manageable\":{},\"isSelf\":{}}}",
                i.id,
                s(&i.text[0]),
                s(&i.text[1]),
                i.enabled,
                i.admin,
                i.department.map(|d| format!(",\"departmentId\":{d}")).unwrap_or_default(),
                s(&i.text[2]),
                mailbox.map(|m| format!(",\"mailboxId\":{m}")).unwrap_or_default(),
                manageable,
                is_self
            )
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}`; `None` is Go's 404 (missing or out of scope).
pub async fn user(
    exec: &ScopedExecutor,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let sql = format!(
        "SELECT id, email, display_name, enabled, is_local_admin, department_id, {} FROM users \
         WHERE id = $1 AND ($2::bigint = 0 OR domain_id = $2)",
        nano("created_at")
    );
    let rows = exec
        .read(&sql, &[(&id, Type::INT8), (&domain_scope, Type::INT8)])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    // A scan failure is a database error in Go's Get.
    let scan = || -> Result<String, StatementFailure> {
        let department = row
            .try_get::<_, Option<i64>>(5)
            .map_err(|_| invalid())?
            .map(|d| format!(",\"departmentId\":{d}"))
            .unwrap_or_default();
        Ok(format!(
            "{{\"id\":{},\"email\":{},\"displayName\":{},\"enabled\":{},\"isLocalAdmin\":{}{},\"createdAt\":{},\"manageable\":false,\"isSelf\":false}}",
            row.try_get::<_, i64>(0).map_err(|_| invalid())?,
            s(&row.try_get::<_, String>(1).map_err(|_| invalid())?),
            s(&row.try_get::<_, String>(2).map_err(|_| invalid())?),
            row.try_get::<_, bool>(3).map_err(|_| invalid())?,
            row.try_get::<_, bool>(4).map_err(|_| invalid())?,
            department,
            s(&row.try_get::<_, String>(6).map_err(|_| invalid())?),
        ))
    };
    Ok(Some(done(scan()?)))
}

/// `GET /admin/users/{id}/aliases`: map rows, so keys sort alphabetically.
pub async fn aliases(
    exec: &ScopedExecutor,
    domain_scope: i64,
    id: i64,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT a.id, a.email, a.is_primary FROM aliases a JOIN mailboxes m ON m.id = a.mailbox_id \
             JOIN users u ON u.id = m.user_id WHERE m.user_id = $1 AND ($2::bigint = 0 OR u.domain_id = $2) \
             ORDER BY a.is_primary DESC, a.email",
            &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            Some(format!(
                "{{\"email\":{},\"id\":{},\"isPrimary\":{}}}",
                s(&r.try_get::<_, String>(1).ok()?),
                r.try_get::<_, i64>(0).ok()?,
                r.try_get::<_, bool>(2).ok()?
            ))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}/quota`; `None` is Go's 404 for every failure.
pub async fn quota(exec: &ScopedExecutor, domain_scope: i64, id: i64) -> Option<String> {
    let rows = exec
        .read(
            "SELECT quota_bytes, used_bytes, sending_quota_day, sending_sent_today FROM mailboxes \
             WHERE user_id = $1 AND is_primary = TRUE AND ($2::bigint = 0 OR domain_id = $2) LIMIT 1",
            &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    Some(done(format!(
        "{{\"quotaBytes\":{},\"usedBytes\":{},\"sendingQuotaDay\":{},\"sendingSentToday\":{}}}",
        row.try_get::<_, i64>(0).ok()?,
        row.try_get::<_, i64>(1).ok()?,
        row.try_get::<_, i32>(2).ok()?,
        row.try_get::<_, i32>(3).ok()?
    )))
}

/// `GET /admin/users/{id}/app-passwords`.
pub async fn app_passwords(
    exec: &ScopedExecutor,
    domain_scope: i64,
    id: i64,
) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id, name, {}, {}, {}, {} FROM app_passwords WHERE user_id = $1 \
         AND ($2::bigint = 0 OR user_id IN (SELECT id FROM users WHERE id = $1 AND domain_id = $2)) \
         ORDER BY revoked_at NULLS FIRST, created_at DESC",
        nano("created_at"),
        nano("last_used_at"),
        nano("expires_at"),
        nano("revoked_at")
    );
    let rows = exec
        .read(&sql, &[(&id, Type::INT8), (&domain_scope, Type::INT8)])
        .await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            let optional = |i: usize, key: &str| -> Option<String> {
                r.try_get::<_, Option<String>>(i)
                    .ok()?
                    .map(|v| format!(",\"{key}\":{}", s(&v)))
                    .or(Some(String::new()))
            };
            Some(format!(
                "{{\"id\":{},\"name\":{},\"createdAt\":{}{}{}{}}}",
                r.try_get::<_, i64>(0).ok()?,
                s(&r.try_get::<_, String>(1).ok()?),
                s(&r.try_get::<_, String>(2).ok()?),
                optional(3, "lastUsedAt")?,
                optional(4, "expiresAt")?,
                optional(5, "revokedAt")?
            ))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}/app-access`; an error is Go's 500.
pub async fn app_access(
    exec: &ScopedExecutor,
    domain_scope: i64,
    id: i64,
) -> Result<String, StatementFailure> {
    let guest = exec
        .read(
            "SELECT COALESCE((SELECT is_guest_account(u.id) FROM users u WHERE u.id = $1 \
             AND ($2::bigint = 0 OR COALESCE(guest_account_host_domain(u.id), u.domain_id) = $2)), FALSE)",
            &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await?;
    let guest: bool = guest
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let rows = exec
        .read(
            "SELECT app, enabled FROM user_app_entitlements WHERE user_id = $1 AND ($2::bigint = 0 OR user_id IN \
             (SELECT u.id FROM users u WHERE u.id = $1 AND COALESCE(guest_account_host_domain(u.id), u.domain_id) = $2))",
            &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await?;
    let explicit: Vec<(String, bool)> = rows
        .iter()
        .filter_map(|r| {
            Some((
                r.try_get::<_, String>(0).ok()?,
                r.try_get::<_, bool>(1).ok()?,
            ))
        })
        .collect();
    let out: Vec<String> = APPS
        .iter()
        .map(|app| {
            let enabled = explicit
                .iter()
                .rev()
                .find(|(a, _)| a == app)
                .map(|(_, e)| *e)
                .unwrap_or(!guest);
            format!("{{\"app\":{},\"enabled\":{enabled}}}", s(app))
        })
        .collect();
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/users/{id}/sessions`; the target must exist inside the scope.
pub async fn sessions(
    exec: &ScopedExecutor,
    domain_scope: i64,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let exists = exec
        .read(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND ($2::bigint = 0 OR domain_id = $2))",
            &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await?;
    if !exists
        .first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)?
    {
        return Ok(None);
    }
    let sql = format!(
        "SELECT id, kind, client_id, device, location, {}, auth_method FROM (\
         SELECT id::text AS id, 'oauth' AS kind, COALESCE(client_id,'') AS client_id, '' AS device, '' AS location, \
         COALESCE(last_used_at, issued_at) AS last_used_at, COALESCE(last_used_protocol,'') AS auth_method FROM oauth_tokens \
         WHERE user_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) AND previous_token_hash IS NULL \
         AND token_type IN ('refresh','xoauth2','app_password') \
         UNION ALL \
         SELECT id, 'web', '', COALESCE(user_agent,''), COALESCE(host(ip),''), last_seen_at, COALESCE(auth_method,'') FROM sessions \
         WHERE user_id = $1 AND expires_at > now()) s ORDER BY s.last_used_at DESC NULLS LAST",
        seconds("last_used_at")
    );
    let rows = exec.read(&sql, &[(&id, Type::INT8)]).await?;
    let out: Vec<String> = rows
        .iter()
        .filter_map(|r| {
            Some(format!(
                "{{\"id\":{},\"kind\":{},\"client_id\":{},\"device\":{},\"location\":{},\"last_used_at\":{},\"auth_method\":{}}}",
                s(&r.try_get::<_, String>(0).ok()?),
                s(&r.try_get::<_, String>(1).ok()?),
                s(&r.try_get::<_, String>(2).ok()?),
                s(&r.try_get::<_, String>(3).ok()?),
                s(&r.try_get::<_, String>(4).ok()?),
                s(&r.try_get::<_, String>(5).ok()?),
                s(&r.try_get::<_, String>(6).ok()?)
            ))
        })
        .collect();
    Ok(Some(done(format!("{{\"sessions\":[{}]}}", out.join(",")))))
}

/// Go's quota `UPDATE`; the number of rows decides 204 or 404 at the edge.
pub async fn set_quota(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    user: i64,
    quota_bytes: Option<i64>,
    sending_day: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let mut sets = Vec::new();
    let mut params: Vec<Param<'_>> = vec![(&user, Type::INT8), (&domain_scope, Type::INT8)];
    if let Some(bytes) = quota_bytes.as_ref() {
        params.push((bytes, Type::INT8));
        sets.push(format!("quota_bytes = ${}", params.len() + 3));
    }
    if let Some(day) = sending_day.as_ref() {
        params.push((day, Type::INT8));
        sets.push(format!("sending_quota_day = ${}", params.len() + 3));
    }
    let sql = format!(
        "WITH updated AS (UPDATE mailboxes SET {} WHERE user_id = $4 AND is_primary = TRUE \
         AND ($5::bigint = 0 OR domain_id = $5) AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING 1) \
         SELECT count(*)::bigint FROM updated",
        sets.join(", ")
    );
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "user_quota_set",
        },
        &envelope(
            &auth,
            operation,
            &format!("{user}:{quota_bytes:?}:{sending_day:?}:{domain_scope}"),
        ),
        &auth,
        deadline(),
        &sql,
        &params,
        count,
    )
    .await
}

/// Go's primary-mailbox resolution before an alias insert: `(mailbox, domain)`.
pub async fn primary_mailbox(
    exec: &ScopedExecutor,
    domain_scope: i64,
    user: i64,
) -> Option<(i64, i64)> {
    let rows = exec
        .read(
            "SELECT id, domain_id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE \
             AND ($2::bigint = 0 OR domain_id = $2) LIMIT 1",
            &[(&user, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    Some((row.try_get(0).ok()?, row.try_get(1).ok()?))
}

/// Owner-approved security fix 2026-11-05 (#373): whether `email` belongs to the domain that
/// owns `mailbox`. A domain-scoped admin (`domain_scope > 0`) may only bind such addresses;
/// the domain is read from the mailbox row, never from the request.
pub async fn alias_domain_allowed(
    exec: &ScopedExecutor,
    domain_scope: i64,
    mailbox: i64,
    email: &str,
) -> bool {
    if domain_scope <= 0 || setjoin_contracts::mutants::on("alias-foreign-domain") {
        return true;
    }
    exec.read(
        "SELECT EXISTS (SELECT 1 FROM mailboxes m JOIN domains d ON d.id = m.domain_id \
         WHERE m.id = $1 AND m.domain_id = $2 AND lower(d.name) = lower(split_part($3::text, '@', 2)))",
        &[(&mailbox, Type::INT8), (&domain_scope, Type::INT8), (&email, Type::TEXT)],
    )
    .await
    .ok()
    .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// Go's alias `INSERT`, repeating the primary-mailbox and scope predicates in
/// the same statement (R3). No row means the mailbox vanished since the read.
pub async fn add_alias(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    user: i64,
    mailbox: i64,
    email: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<i64>, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "user_alias_add",
        },
        &envelope(&auth, operation, &format!("{user}:{mailbox}:{email}")),
        &auth,
        deadline(),
        // Owner-approved security fix 2026-11-05 (#373): a domain-scoped admin binds only
        // addresses of the mailbox's own domain (the domain name comes from the row, never the
        // request); frozen Go checked only the mailbox, so a foreign address could be claimed.
        if setjoin_contracts::mutants::on("alias-foreign-domain") {
            "WITH inserted AS (INSERT INTO aliases (mailbox_id, email, domain_id) \
             SELECT m.id, $7, m.domain_id FROM mailboxes m WHERE m.id = $4 AND m.user_id = $5 AND m.is_primary = TRUE \
             AND ($6::bigint = 0 OR m.domain_id = $6) AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id) \
             SELECT id FROM inserted"
        } else {
            "WITH inserted AS (INSERT INTO aliases (mailbox_id, email, domain_id) \
             SELECT m.id, $7, m.domain_id FROM mailboxes m WHERE m.id = $4 AND m.user_id = $5 AND m.is_primary = TRUE \
             AND ($6::bigint = 0 OR (m.domain_id = $6 AND EXISTS (SELECT 1 FROM domains d WHERE d.id = m.domain_id \
                  AND lower(d.name) = lower(split_part($7::text, '@', 2))))) \
             AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id) \
             SELECT id FROM inserted"
        },
        &[
            (&mailbox, Type::INT8),
            (&user, Type::INT8),
            (&domain_scope, Type::INT8),
            (&email, Type::TEXT),
        ],
        |rows| match rows.len() {
            0 => Ok(None),
            1 => Ok(rows[0].try_get::<_, i64>(0).ok()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// Go's alias `DELETE`: success whether or not a row matched.
pub async fn remove_alias(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    user: i64,
    alias: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "user_alias_remove",
        },
        &envelope(&auth, operation, &format!("{user}:{alias}:{domain_scope}")),
        &auth,
        deadline(),
        "WITH removed AS (DELETE FROM aliases WHERE id = $4 AND mailbox_id IN (SELECT id FROM mailboxes \
         WHERE user_id = $5 AND is_primary = TRUE AND ($6::bigint = 0 OR domain_id = $6)) \
         AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING 1) SELECT count(*)::bigint FROM removed",
        &[
            (&alias, Type::INT8),
            (&user, Type::INT8),
            (&domain_scope, Type::INT8),
        ],
        count,
    )
    .await
}

/// Go's `set_app_entitlement` reducer call, unchanged. For scoped admins Go
/// checks the target's domain inside the same transaction; the same predicate
/// guards the call here, and no row means the target is missing or out of scope.
pub async fn set_app_access(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    user: i64,
    app: &str,
    enabled: bool,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F01",
            command: "set_app_entitlement",
        },
        &envelope(&auth, operation, &format!("{user}:{app}:{enabled}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT set_app_entitlement($4, $5, $7, $2) FROM (SELECT 1 WHERE $1::bigint > 0 AND $3::text <> '' \
         AND ($6::bigint = 0 OR EXISTS (SELECT 1 FROM users u WHERE u.id = $4 AND COALESCE(guest_account_host_domain(u.id), u.domain_id) = $6))) g) r",
        &[
            (&user, Type::INT8),
            (&app, Type::TEXT),
            (&domain_scope, Type::INT8),
            (&enabled, Type::BOOL),
        ],
        count,
    )
    .await
}
