//! CA-2 device lockdown console (Go's `admin.DeviceLockdownHandler` over
//! `shared/device`): the org-wide approval queue, a per-user device list and the
//! lifecycle transitions. Reads run on the request pool with no actor GUC, as Go's
//! do (`devices` admits every SELECT to admins); the transition is the existing
//! `device_enroll_transition` reducer (state, `device_enroll_events` row, core
//! audit row and, on revoke, the `ca_notify_policy_change` notify) in one
//! receipted command, so the authz device gates (#405) read the same rows.
//!
//! Owner-approved security fix 2026-11-05 (#435): frozen Go ignored the grant's domain
//! scope on this console. The queue, the per-user list and the transition now confine a
//! domain-scoped admin to devices of users inside its reach (`admin_can_reach_perm`: the
//! domain comes from the stored owner of the device row, permission-aware, OU and
//! scope-set narrowing included; an organization-wide grant reaches everyone). The
//! transition repeats the reach in the mutating statement (R3); a foreign device answers
//! exactly like a missing one.
use super::{command, deadline, done, envelope, invalid, nano, opt, s, scope, StatementFailure};
use setjoin_authz::AuthContext;
use setjoin_contracts::mutants;
use setjoin_pg::{CommandOutcome, Param, Rejection, ScopedExecutor, Type};

/// The reach predicate over a device owner column: the caller's grants carrying
/// `permission` must reach that user (`admin_can_reach_perm`). The restored-bug mutant
/// (`lockdown-foreign-target`, test builds only) drops it as frozen Go did.
fn reach(owner: &str, actor: &str, permission: &str) -> String {
    if mutants::on("lockdown-foreign-target") {
        return "true".into();
    }
    format!("admin_can_reach_perm({actor}, {owner}, ARRAY['{permission}'])")
}

/// `GET /admin/devices/queue`: Go's `ListApprovalQueue`.
pub async fn queue(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    state: &str,
    query: &str,
    limit: i64,
) -> Result<String, StatementFailure> {
    let state = if state.is_empty() { "enrolled" } else { state };
    let limit = if limit <= 0 { 100 } else { limit.min(500) };
    let like = format!("%{query}%");
    let sql = format!(
        "SELECT d.id, d.user_id, COALESCE(u.email,''), COALESCE(u.display_name,''), \
         COALESCE(d.device_name,''), COALESCE(d.platform,''), d.enroll_state, \
         d.enrolled_by, eb.email, d.approved_by, ab.email, {}, \
         {}, {}, {} \
         FROM devices d JOIN users u ON u.id = d.user_id \
         LEFT JOIN users eb ON eb.id = d.enrolled_by LEFT JOIN users ab ON ab.id = d.approved_by \
         WHERE d.enroll_state = $1::text AND ($2::text = '%%' OR u.email ILIKE $2::text OR u.display_name ILIKE $2::text) \
         AND ({}) \
         ORDER BY (SELECT MIN(created_at) FROM device_enroll_events e WHERE e.device_id = d.id AND e.to_state = d.enroll_state) DESC NULLS LAST, d.id DESC \
         LIMIT $3::bigint",
        nano("d.approved_at"),
        nano("(SELECT MAX(created_at) FROM device_enroll_events e WHERE e.device_id = d.id)"),
        nano("(SELECT MIN(created_at) FROM device_enroll_events e WHERE e.device_id = d.id AND e.to_state = d.enroll_state)"),
        nano("d.revoked_at"),
        reach("d.user_id", "$4::bigint", "mam.read"),
    );
    let user = actor.user_id();
    let params: [Param<'_>; 4] = [
        (&state, Type::TEXT),
        (&like, Type::TEXT),
        (&limit, Type::INT8),
        (&user, Type::INT8),
    ];
    let rows = exec.read(&sql, &params).await?;
    let mut items = Vec::new();
    for row in &rows {
        let n = |i: usize| -> Result<Option<i64>, StatementFailure> {
            row.try_get(i).map_err(|_| invalid())
        };
        let t = |i: usize| -> Result<String, StatementFailure> {
            row.try_get(i).map_err(|_| invalid())
        };
        let o = |i: usize| -> Result<Option<String>, StatementFailure> {
            row.try_get(i).map_err(|_| invalid())
        };
        let id: i64 = row.try_get(0).map_err(|_| invalid())?;
        let user: i64 = row.try_get(1).map_err(|_| invalid())?;
        let mut item = format!(
            "{{\"id\":{id},\"user_id\":{user},\"user_email\":{},\"user_display_name\":{},\"device_name\":{},\"platform\":{},\"enroll_state\":{}",
            s(&t(2)?), s(&t(3)?), s(&t(4)?), s(&t(5)?), s(&t(6)?)
        );
        if let Some(v) = n(7)? {
            item.push_str(&format!(",\"enrolled_by\":{v}"));
        }
        if let Some(v) = opt(&o(8)?) {
            item.push_str(&format!(",\"enrolled_by_email\":{v}"));
        }
        if let Some(v) = n(9)? {
            item.push_str(&format!(",\"approved_by\":{v}"));
        }
        if let Some(v) = opt(&o(10)?) {
            item.push_str(&format!(",\"approved_by_email\":{v}"));
        }
        for (key, i) in [
            ("approved_at", 11),
            ("last_seen_at", 12),
            ("requested_at", 13),
            ("revoked_at", 14),
        ] {
            if let Some(v) = opt(&o(i)?) {
                item.push_str(&format!(",\"{key}\":{v}"));
            }
        }
        item.push('}');
        items.push(item);
    }
    Ok(done(format!("[{}]", items.join(","))))
}

/// `GET /admin/devices?user_id=`: Go's `ListDevicesForUser`.
pub async fn devices_of(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
) -> Result<String, StatementFailure> {
    let sql = format!(
        "SELECT id, user_id, COALESCE(device_name,''), COALESCE(platform,''), enroll_state, {} \
         FROM devices WHERE user_id = $1 AND ({}) ORDER BY id",
        nano("revoked_at"),
        reach("user_id", "$2::bigint", "mam.read")
    );
    let actor = actor.user_id();
    let rows = exec
        .read(&sql, &[(&user, Type::INT8), (&actor, Type::INT8)])
        .await?;
    let mut items = Vec::new();
    for row in &rows {
        let id: i64 = row.try_get(0).map_err(|_| invalid())?;
        let owner: i64 = row.try_get(1).map_err(|_| invalid())?;
        let t = |i: usize| -> Result<String, StatementFailure> {
            row.try_get(i).map_err(|_| invalid())
        };
        let revoked: Option<String> = row.try_get(5).map_err(|_| invalid())?;
        let mut item = format!(
            "{{\"id\":{id},\"user_id\":{owner},\"device_name\":{},\"platform\":{},\"enroll_state\":{}",
            s(&t(2)?), s(&t(3)?), s(&t(4)?)
        );
        if let Some(v) = opt(&revoked) {
            item.push_str(&format!(",\"revoked_at\":{v}"));
        }
        item.push('}');
        items.push(item);
    }
    Ok(done(format!("[{}]", items.join(","))))
}

/// Go's `caErrorStatus`/`caErrorDetail` for the transition: BZ095 is a 409 with
/// the reducer HINT (message when empty); 23514 a 400 with its hint; anything
/// else a 500 `request failed`.
pub fn transition_refusal(error: &Rejection<StatementFailure>) -> (u16, String) {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return (500, "request failed".into());
    };
    let text = |hint: &Option<String>| match hint.as_deref() {
        Some(h) if !h.is_empty() => h.to_owned(),
        _ => e.message.clone(),
    };
    match e.sqlstate.as_deref() {
        Some("BZ095") => (409, text(&e.hint)),
        Some("23514") => (400, text(&e.hint)),
        _ => (500, "request failed".into()),
    }
}

/// `POST /admin/devices/{id}/{action}` with `to` one of enrolled|approved|revoked.
pub async fn transition(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    device: i64,
    to: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let sql = format!(
        "SELECT rust_device_enroll_transition($2::bigint, $4::bigint, $5::text, $6::text, {})::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        reach("(SELECT d.user_id FROM devices d WHERE d.id = $4::bigint)", "$2::bigint", "mam.write")
    );
    setjoin_pg::run_receipted_command(
        exec,
        command("device_enroll_transition"),
        &envelope(&auth, operation, &format!("{device}\n{to}\n{reason}")),
        &auth,
        deadline(),
        &sql,
        &[
            (&device, Type::INT8),
            (&to, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}
