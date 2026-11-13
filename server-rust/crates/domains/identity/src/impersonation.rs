//! Direct authserver impersonation: live governed grant, then strict tier descent.
use crate::issuance::SessionProof;
use serde_json::{json, Value};
use setjoin_pg::{ScopedExecutor, Type};
pub struct Denied {
    pub status: u16,
    pub detail: &'static str,
    pub instance: bool,
}
fn denied(status: u16, detail: &'static str) -> Denied {
    Denied {
        status,
        detail,
        instance: true,
    }
}
pub struct Target {
    user: i64,
    email: String,
    guest: bool,
}
impl Target {
    pub fn email(&self) -> &str {
        &self.email
    }
    pub fn claims(&self, actor: &SessionProof, issuer: &str, now: i64, jti: &str) -> Value {
        let mut c = json!({"uid":self.user,"email":self.email,"typ":"access","jti":jti,"act":actor.user(),"iss":issuer,"sub":self.user.to_string(),"aud":["mailserver-gateway"],"iat":now,"nbf":now,"exp":now+900});
        if self.guest {
            c["acct"] = json!("guest");
        }
        c
    }
}
async fn audit(
    exec: &ScopedExecutor,
    actor: &SessionProof,
    ip: &str,
    event: &str,
    target: i64,
    reason: Option<&str>,
    email: Option<&str>,
) {
    let mut metadata = if reason == Some("missing_permission") {
        json!({"permission":"users.impersonate"})
    } else {
        json!({"target_user_id":target})
    };
    if let Some(reason) = reason {
        metadata["reason"] = json!(reason);
    }
    if let Some(email) = email {
        metadata["target_email"] = json!(email);
    }
    let _=exec.protocol_statement("INSERT INTO audit_log(user_id,source_ip,event_type,metadata) VALUES($1,$2::text::inet,$3,$4::text::jsonb)",&[(&actor.user(),Type::INT8),(&ip,Type::TEXT),(&event,Type::TEXT),(&metadata.to_string(),Type::TEXT)]).await;
}
pub async fn authorize(
    exec: &ScopedExecutor,
    actor: &SessionProof,
    raw_target: &str,
    ip: &str,
) -> Result<Target, Denied> {
    let gate = |detail| Denied {
        status: 403,
        detail,
        instance: false,
    };
    if actor.claims().get("admin").and_then(Value::as_bool) != Some(true) {
        return Err(gate("admin access required"));
    }
    // The grant and its domain scope come from the same live assignments: a global
    // grant (no domain on any granting assignment) is unrestricted, otherwise the
    // target must live in one of the granting assignments' domains.
    let grant=exec.read("SELECT count(*), COALESCE(bool_or(COALESCE(ra.domain_override,rg.domain_scope) IS NULL),false), COALESCE(array_agg(DISTINCT COALESCE(ra.domain_override,rg.domain_scope)) FILTER (WHERE COALESCE(ra.domain_override,rg.domain_scope) IS NOT NULL),'{}'::bigint[]) FROM admin_role_assignments ra JOIN admin_role_groups rg ON rg.id=ra.role_group_id WHERE ra.user_id=$1 AND 'users.impersonate'=ANY(rg.permissions) AND (ra.expires_at IS NULL OR ra.expires_at>now()) AND admin_assignment_active(ra.eligible,ra.activated_until)",&[(&actor.user(),Type::INT8)]).await.map_err(|_|gate("Forbidden"))?;
    if grant[0].get::<_, i64>(0) == 0 {
        // The direct mount's auditor records the path's target when parseable.
        audit(
            exec,
            actor,
            ip,
            "admin_impersonate_denied",
            raw_target.parse().unwrap_or(0),
            Some("missing_permission"),
            None,
        )
        .await;
        return Err(gate("Forbidden"));
    }
    let global_grant = grant[0].get::<_, bool>(1);
    let granted_domains: Vec<i64> = grant[0].get(2);
    let target = raw_target
        .parse::<i64>()
        .map_err(|_| denied(400, "invalid user ID"))?;
    if target == actor.user() {
        return Err(denied(400, "cannot impersonate yourself"));
    }
    let rows=exec.read("SELECT enabled,EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND (ra.expires_at IS NULL OR ra.expires_at>now())),EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND ra.role_group_id=1 AND (ra.expires_at IS NULL OR ra.expires_at>now())) FROM users WHERE id=$1",&[(&actor.user(),Type::INT8)]).await.map_err(|_|denied(403,"admin access required"))?;
    let row = rows
        .first()
        .ok_or_else(|| denied(403, "admin access required"))?;
    if !row.get::<_, bool>(0) || !row.get::<_, bool>(1) {
        return Err(denied(403, "admin access required"));
    }
    let actor_rank = if row.get::<_, bool>(2) { 4 } else { 3 };
    // Owner-approved security fix 2026-11-05 (#495): a domain-scoped grant only
    // reaches targets in its own domains (frozen Go did not constrain the target).
    let rows=exec.read("SELECT email,EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND (ra.expires_at IS NULL OR ra.expires_at>now())),EXISTS(SELECT 1 FROM admin_role_assignments ra WHERE ra.user_id=users.id AND ra.role_group_id=1 AND (ra.expires_at IS NULL OR ra.expires_at>now())),domain_id FROM users WHERE id=$1",&[(&target,Type::INT8)]).await.map_err(|_|denied(404,"user not found"))?;
    let row = rows.first().ok_or_else(|| denied(404, "user not found"))?;
    let target_domain: Option<i64> = row.get(3);
    if !global_grant
        && !target_domain.is_some_and(|d| granted_domains.contains(&d))
        && !setjoin_contracts::mutants::on("impersonate-foreign-domain")
    {
        audit(
            exec,
            actor,
            ip,
            "admin_impersonate_denied",
            target,
            Some("domain_scope"),
            None,
        )
        .await;
        return Err(denied(
            403,
            "cannot impersonate a user outside your domain scope",
        ));
    }
    let rank = if row.get::<_, bool>(2) {
        4
    } else if row.get::<_, bool>(1) {
        3
    } else {
        0
    };
    if rank >= actor_rank {
        audit(
            exec,
            actor,
            ip,
            "admin_impersonate_denied",
            target,
            Some("privilege_escalation"),
            None,
        )
        .await;
        return Err(denied(
            403,
            "cannot impersonate a user with equal or higher privilege",
        ));
    }
    let guest = exec
        .read("SELECT is_guest_account($1)", &[(&target, Type::INT8)])
        .await
        .map_err(|_| denied(500, "account type resolution failed"))?[0]
        .get(0);
    Ok(Target {
        user: target,
        email: row.get(0),
        guest,
    })
}
pub async fn record(exec: &ScopedExecutor, actor: &SessionProof, target: &Target, ip: &str) {
    audit(
        exec,
        actor,
        ip,
        "admin_impersonate",
        target.user,
        None,
        Some(&target.email),
    )
    .await;
}
