//! Platform slice `webhooks` (#302): the admin CRUD of webhook subscriptions
//! (`/admin/webhooks*`), Go's `admin.WebhooksHandler`.
//!
//! Reads render in Go's struct order (`encoding/json`, HTML-escaped). Create is Go's whole
//! transaction (one `INSERT`), delete is one `DELETE` with the ownership predicate in the
//! same WHERE; both are single receipted statements. Rotation seals in Rust (the master key
//! never enters SQL), so Go's `SELECT .. FOR UPDATE` + `UPDATE` pair becomes a read under
//! the actor followed by ONE `UPDATE` pinned to the exact values read (id + user_id + the
//! three secret cells): a concurrent rotation turns it into a no-op and the loop re-reads,
//! so rotations still serialize with no check-then-mutate window.
use super::{command, deadline, done, envelope, invalid, sql};
use crate::webhook_secret::{generate_secret, SecretCodec};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `wh.EventCatalog()` in registration order: `(type, category, source)`.
pub const CATALOG: [(&str, &str, &str); 25] = [
    ("user.created", "admin", "mailserver/auth"),
    ("user.deleted", "admin", "mailserver/auth"),
    ("user.updated", "admin", "mailserver/auth"),
    ("auth.login_failed", "admin", "mailserver/auth"),
    ("auth.login", "admin", "mailserver/auth"),
    ("mailbox.quota_warning", "admin", "mailserver/gateway"),
    ("system.health_alert", "admin", "mailserver/gateway"),
    ("migration.completed", "admin", "mailserver/gateway"),
    ("migration.failed", "admin", "mailserver/gateway"),
    ("mail.received", "mailbox", "mailserver/gateway"),
    ("mail.sent", "mailbox", "mailserver/gateway"),
    ("mail.rule_triggered", "mailbox", "mailserver/gateway"),
    ("calendar.invitation", "mailbox", "mailserver/gateway"),
    ("mailbox.suspended", "admin", "mailserver/lifecycle"),
    ("mailbox.resumed", "admin", "mailserver/lifecycle"),
    ("mailbox.detached", "admin", "mailserver/lifecycle"),
    ("mailbox.reconnected", "admin", "mailserver/lifecycle"),
    ("mailbox.purge_scheduled", "admin", "mailserver/lifecycle"),
    ("mailbox.purge_cancelled", "admin", "mailserver/lifecycle"),
    ("mailbox.purged", "admin", "mailserver/lifecycle"),
    ("mailwork.claimed", "mailbox", "mailserver/mailwork"),
    ("mailwork.assigned", "mailbox", "mailserver/mailwork"),
    ("mailwork.handed_off", "mailbox", "mailserver/mailwork"),
    ("mailwork.completed", "mailbox", "mailserver/mailwork"),
    ("mailwork.sla_breached", "mailbox", "mailserver/mailwork"),
];

/// `wh.IsKnownEventType`.
pub fn is_known_event_type(event: &str) -> bool {
    CATALOG.iter().any(|(kind, _, _)| *kind == event)
}

/// Go's string encoding: `encoding/json` writes `\b` and `\f` as `\u0008` and `\u000c`.
fn gs(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `GET /admin/webhooks/events`: each catalog entry is a map, so keys render sorted.
pub fn event_catalog() -> String {
    let items: Vec<String> = CATALOG
        .iter()
        .map(|(kind, category, source)| {
            format!(
                "{{\"category\":{},\"source\":{},\"type\":{}}}",
                gs(category),
                gs(source),
                gs(kind)
            )
        })
        .collect();
    done(format!("[{}]", items.join(",")))
}

/// `GET /admin/webhooks`: every subscription, newest first (`AdminReadTx` crosses RLS).
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::WEBHOOKS_LIST, &[])
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for row in &rows {
        let user: Option<i64> = row.try_get(1).map_err(bad)?;
        let types: String = row.try_get(3).map_err(bad)?;
        let types = match serde_json::from_str::<serde_json::Value>(&types) {
            Ok(serde_json::Value::Array(list)) => format!(
                "[{}]",
                list.iter()
                    .map(|t| gs(t.as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            _ => "null".into(),
        };
        out.push(format!(
            "{{\"id\":{}{},\"url\":{},\"eventTypes\":{},\"scope\":{},\"isActive\":{},\"createdAt\":{},\"updatedAt\":{}}}",
            row.try_get::<_, i64>(0).map_err(bad)?,
            user.map_or(String::new(), |u| format!(",\"userId\":{u}")),
            gs(&row.try_get::<_, String>(2).map_err(bad)?),
            types,
            gs(&row.try_get::<_, String>(4).map_err(bad)?),
            row.try_get::<_, bool>(5).map_err(bad)?,
            gs(&row.try_get::<_, String>(6).map_err(bad)?),
            gs(&row.try_get::<_, String>(7).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// `GET /admin/webhooks/{id}/deliveries`: the newest 200 attempts of one subscription.
pub async fn deliveries(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::WEBHOOKS_DELIVERIES, &[&id])
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for row in &rows {
        let code: Option<i32> = row.try_get(3).map_err(bad)?;
        let latency: Option<i32> = row.try_get(4).map_err(bad)?;
        let error: Option<String> = row.try_get(7).map_err(bad)?;
        out.push(format!(
            "{{\"id\":{},\"eventId\":{},\"eventType\":{}{}{},\"attempt\":{},\"status\":{}{},\"createdAt\":{}}}",
            row.try_get::<_, i64>(0).map_err(bad)?,
            gs(&row.try_get::<_, String>(1).map_err(bad)?),
            gs(&row.try_get::<_, String>(2).map_err(bad)?),
            code.map_or(String::new(), |c| format!(",\"responseCode\":{c}")),
            latency.map_or(String::new(), |l| format!(",\"latencyMs\":{l}")),
            row.try_get::<_, i32>(5).map_err(bad)?,
            gs(&row.try_get::<_, String>(6).map_err(bad)?),
            error.map_or(String::new(), |e| format!(",\"errorMessage\":{}", gs(&e))),
            gs(&row.try_get::<_, String>(8).map_err(bad)?),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// A refusal of the create body that Go answers with a 400 problem.
pub fn create_refusal(
    url: &str,
    event_types: &[String],
    scope_name: &str,
) -> Result<(), &'static str> {
    if url.is_empty() || event_types.is_empty() {
        return Err("url and eventTypes required");
    }
    if scope_name != "self" && scope_name != "organization" {
        return Err("scope must be self or organization");
    }
    if event_types.len() > CATALOG.len() {
        return Err("eventTypes exceeds the catalog");
    }
    let mut seen = std::collections::HashSet::new();
    for kind in event_types {
        if !is_known_event_type(kind) {
            return Err("unknown event type");
        }
        if !seen.insert(kind.as_str()) {
            return Err("duplicate event type");
        }
    }
    Ok(())
}

/// What a failed create or rotation maps to.
pub enum Failure {
    /// `secret generation failed` / `secret sealing failed`: 500 with that detail.
    Detail(&'static str),
    /// A stored secret that cannot be handled; the detail is Go's.
    Stored(&'static str),
    NotFound,
    Database,
}

/// A command's answer: the rendered body, a refusal, or an unknown commit outcome.
pub enum Outcome {
    Done(String),
    Failed(Failure),
    Unknown(setjoin_contracts::ids::OperationId),
}

/// `POST /admin/webhooks` after validation: the new id and the one-time plaintext secret.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    codec: &SecretCodec,
    url: &str,
    event_types: &[String],
    scope_name: &str,
    operation: [u8; 16],
) -> Outcome {
    let Ok(secret) = generate_secret() else {
        return Outcome::Failed(Failure::Detail("secret generation failed"));
    };
    let Ok(sealed) = codec.seal(&secret) else {
        return Outcome::Failed(Failure::Detail("secret sealing failed"));
    };
    let types = format!(
        "[{}]",
        event_types
            .iter()
            .map(|t| gs(t))
            .collect::<Vec<_>>()
            .join(",")
    );
    let owner = user.user().get();
    let key_id = codec.active_key_id();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{url}:{types}:{scope_name}"),
    );
    let outcome = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::WEBHOOKS_CREATE,
            &[&owner, &url, &sealed, &key_id, &types, &scope_name],
            Some(command("webhook_create")),
            |rows| match rows.as_slice() {
                [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
                _ => Err(invalid()),
            },
        )
        .await;
    match outcome {
        CommandOutcome::Committed(id) => Outcome::Done(done(format!(
            "{{\"id\":{id},\"scope\":{},\"secret\":{},\"url\":{}}}",
            gs(scope_name),
            gs(&secret),
            gs(url)
        ))),
        CommandOutcome::RolledBack(_) => Outcome::Failed(Failure::Database),
        CommandOutcome::Unknown { operation } => Outcome::Unknown(operation),
    }
}

/// `DELETE /admin/webhooks/{id}`: only the creator's own row; true when a row went.
pub async fn delete(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let owner = user.user().get();
    let env = envelope(user.user(), user.generation(), operation, &id.to_string());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::WEBHOOKS_DELETE,
            &[&id, &owner],
            Some(command("webhook_delete")),
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

/// `POST /admin/webhooks/{id}/rotate-secret`: the new plaintext secret, rendered.
pub async fn rotate(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    codec: &SecretCodec,
    id: i64,
    operation: [u8; 16],
) -> Outcome {
    let Ok(secret) = generate_secret() else {
        return Outcome::Failed(Failure::Detail("secret generation failed"));
    };
    let Ok(sealed_new) = codec.seal(&secret) else {
        return Outcome::Failed(Failure::Detail("secret sealing failed"));
    };
    let owner = user.user().get();
    for attempt in 0u16..5 {
        let rows = match factory
            .run_user_read_contract(user, &sql::WEBHOOKS_ROTATE_READ, &[&id, &owner])
            .await
        {
            Ok(rows) => rows,
            Err(_) => return Outcome::Failed(Failure::Database),
        };
        let Some(row) = rows.first() else {
            return Outcome::Failed(Failure::NotFound);
        };
        let (Ok(legacy), Ok(stored), Ok(key)) = (
            row.try_get::<_, Option<String>>(0),
            row.try_get::<_, Option<Vec<u8>>>(1),
            row.try_get::<_, Option<String>>(2),
        ) else {
            return Outcome::Failed(Failure::Database);
        };
        let sealed_prev: Option<Vec<u8>> = match (&stored, &key, &legacy) {
            (Some(envelope), Some(key), _) => {
                let Ok(prev) = codec.open(envelope, key) else {
                    return Outcome::Failed(Failure::Stored("previous secret cannot be opened"));
                };
                match codec.seal(&prev) {
                    Ok(bytes) => Some(bytes),
                    Err(_) => return Outcome::Failed(Failure::Detail("secret sealing failed")),
                }
            }
            (Some(_), None, _) => {
                return Outcome::Failed(Failure::Stored("stored secret has no key id"))
            }
            (None, _, Some(plain)) => match codec.seal(plain) {
                Ok(bytes) => Some(bytes),
                Err(_) => return Outcome::Failed(Failure::Detail("secret sealing failed")),
            },
            (None, _, None) => None,
        };
        let key_id = codec.active_key_id();
        let mut op = operation;
        op[14..16].copy_from_slice(&attempt.to_be_bytes());
        let env = envelope(user.user(), user.generation(), op, &id.to_string());
        let outcome = factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &sql::WEBHOOKS_ROTATE_UPDATE,
                &[
                    &id,
                    &owner,
                    &sealed_prev,
                    &key_id,
                    &sealed_new,
                    &legacy,
                    &stored,
                    &key,
                ],
                Some(command("webhook_rotate_secret")),
                |rows| Ok(!rows.is_empty()),
            )
            .await;
        match outcome {
            CommandOutcome::Committed(true) => {
                return Outcome::Done(done(format!("{{\"secret\":{}}}", gs(&secret))))
            }
            CommandOutcome::Committed(false) => continue,
            CommandOutcome::RolledBack(_) => return Outcome::Failed(Failure::Database),
            CommandOutcome::Unknown { operation } => return Outcome::Unknown(operation),
        }
    }
    Outcome::Failed(Failure::Database)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_renders_sorted_maps() {
        let text = event_catalog();
        assert!(text.starts_with(
            "[{\"category\":\"admin\",\"source\":\"mailserver/auth\",\"type\":\"user.created\"},"
        ));
        assert_eq!(text.matches("\"type\"").count(), 25);
    }

    #[test]
    fn create_validation_order_matches_go() {
        let kinds = |s: &[&str]| s.iter().map(|k| k.to_string()).collect::<Vec<_>>();
        assert_eq!(
            create_refusal("", &kinds(&["user.created"]), "self"),
            Err("url and eventTypes required")
        );
        assert_eq!(
            create_refusal("u", &[], "self"),
            Err("url and eventTypes required")
        );
        assert_eq!(
            create_refusal("u", &kinds(&["user.created"]), "x"),
            Err("scope must be self or organization")
        );
        assert_eq!(
            create_refusal("u", &kinds(&["nope"]), "self"),
            Err("unknown event type")
        );
        assert_eq!(
            create_refusal("u", &kinds(&["user.created", "user.created"]), "self"),
            Err("duplicate event type")
        );
        assert_eq!(
            create_refusal("u", &kinds(&["user.created"]), "organization"),
            Ok(())
        );
    }
}
