//! CA-2 device lockdown console (Go's `admin.DeviceLockdownHandler` over
//! `shared/device`): the org-wide approval queue, a per-user device list and the
//! lifecycle transitions.
use super::{command, deadline, done, envelope, invalid, opt, s, sql, StatementFailure};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::mutants;
use setjoin_pg::{CommandOutcome, Rejection};

/// `GET /admin/devices/queue`: Go's `ListApprovalQueue`.
pub async fn queue(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    state: &str,
    query: &str,
    limit: i64,
) -> Result<String, StatementFailure> {
    let state = if state.is_empty() { "enrolled" } else { state };
    let limit = if limit <= 0 { 100 } else { limit.min(500) };
    let like = format!("%{query}%");
    let user = proof.actor().get();
    let contract = if mutants::on("lockdown-foreign-target") {
        &sql::LOCKDOWN_QUEUE_MUTANT
    } else {
        &sql::LOCKDOWN_QUEUE
    };
    let rows = factory
        .run_admin_read_contract(proof, contract, &[&state, &like, &limit, &user])
        .await?;
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
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    user: i64,
) -> Result<String, StatementFailure> {
    let actor = proof.actor().get();
    let contract = if mutants::on("lockdown-foreign-target") {
        &sql::LOCKDOWN_DEVICES_OF_MUTANT
    } else {
        &sql::LOCKDOWN_DEVICES_OF
    };
    let rows = factory
        .run_admin_read_contract(proof, contract, &[&user, &actor])
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
    factory: &TxFactory,
    user: &UserPrincipal,
    device: i64,
    to: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    let contract = if mutants::on("lockdown-foreign-target") {
        &sql::LOCKDOWN_TRANSITION_MUTANT
    } else {
        &sql::LOCKDOWN_TRANSITION
    };
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{device}\n{to}\n{reason}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            &[&actor, &device, &to, &reason],
            Some(command("device_enroll_transition")),
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
