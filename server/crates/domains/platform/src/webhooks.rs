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
use super::{done, invalid, sql};
use crate::webhook_secret::{generate_secret, SecretCodec};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{Row, StatementFailure};

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

/// Prepared values for `POST /admin/webhooks` (`sql::WEBHOOKS_CREATE`).
pub struct PreparedCreate {
    pub secret: String,
    pub sealed: Vec<u8>,
    pub key_id: String,
    pub types_json: String,
}

/// Generate & seal the webhook secret and encode `event_types` for `sql::WEBHOOKS_CREATE`.
pub fn prepare_create(
    codec: &SecretCodec,
    event_types: &[String],
) -> Result<PreparedCreate, Failure> {
    let Ok(secret) = generate_secret() else {
        return Err(Failure::Detail("secret generation failed"));
    };
    let Ok(sealed) = codec.seal(&secret) else {
        return Err(Failure::Detail("secret sealing failed"));
    };
    let types_json = format!(
        "[{}]",
        event_types
            .iter()
            .map(|t| gs(t))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(PreparedCreate {
        secret,
        sealed,
        key_id: codec.active_key_id().to_owned(),
        types_json,
    })
}

/// Decode the `RETURNING id` row of `sql::WEBHOOKS_CREATE`.
pub fn parse_created_id(rows: &[Row]) -> Result<i64, StatementFailure> {
    match rows {
        [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// Format the 201 JSON response for `POST /admin/webhooks`.
pub fn format_created(id: i64, scope_name: &str, secret: &str, url: &str) -> String {
    done(format!(
        "{{\"id\":{id},\"scope\":{},\"secret\":{},\"url\":{}}}",
        gs(scope_name),
        gs(secret),
        gs(url)
    ))
}

/// Stored secret cells read before CAS rotation (`sql::WEBHOOKS_ROTATE_READ`).
pub struct StoredSecret {
    pub legacy: Option<String>,
    pub stored: Option<Vec<u8>>,
    pub key: Option<String>,
}

/// Read the creator's own webhook secret cells via `AdminReadTx` (crosses `scope='self'` RLS
/// while preserving `WHERE id = $1 AND user_id = $2`).
pub async fn rotate_read(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    owner: i64,
) -> Result<Option<StoredSecret>, Failure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::WEBHOOKS_ROTATE_READ, &[&id, &owner])
        .await
        .map_err(|_| Failure::Database)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let (Ok(legacy), Ok(stored), Ok(key)) = (
        row.try_get::<_, Option<String>>(0),
        row.try_get::<_, Option<Vec<u8>>>(1),
        row.try_get::<_, Option<String>>(2),
    ) else {
        return Err(Failure::Database);
    };
    Ok(Some(StoredSecret {
        legacy,
        stored,
        key,
    }))
}

/// Generate and seal a new secret for rotation.
pub fn prepare_rotate_new(codec: &SecretCodec) -> Result<(String, Vec<u8>), Failure> {
    let Ok(secret) = generate_secret() else {
        return Err(Failure::Detail("secret generation failed"));
    };
    let Ok(sealed_new) = codec.seal(&secret) else {
        return Err(Failure::Detail("secret sealing failed"));
    };
    Ok((secret, sealed_new))
}

/// Re-seal the previous secret cell for `sql::WEBHOOKS_ROTATE_UPDATE`.
pub fn prepare_rotate_prev(
    codec: &SecretCodec,
    current: &StoredSecret,
) -> Result<Option<Vec<u8>>, Failure> {
    match (&current.stored, &current.key, &current.legacy) {
        (Some(envelope), Some(key), _) => {
            let Ok(prev) = codec.open(envelope, key) else {
                return Err(Failure::Stored("previous secret cannot be opened"));
            };
            match codec.seal(&prev) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(_) => Err(Failure::Detail("secret sealing failed")),
            }
        }
        (Some(_), None, _) => Err(Failure::Stored("stored secret has no key id")),
        (None, _, Some(plain)) => match codec.seal(plain) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Err(Failure::Detail("secret sealing failed")),
        },
        (None, _, None) => Ok(None),
    }
}

/// Format the 200 JSON response for `POST /admin/webhooks/{id}/rotate-secret`.
pub fn format_rotated(secret: &str) -> String {
    done(format!("{{\"secret\":{}}}", gs(secret)))
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
