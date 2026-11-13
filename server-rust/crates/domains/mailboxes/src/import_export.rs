//! `POST /admin/mailboxes/{id}/import` and `GET /admin/mailboxes/{id}/export`:
//! the database side. Everything runs on the worker credential (`setjoin_worker`,
//! BYPASSRLS), as Go's `ImportExportHandler` does, so the reach check and the
//! statement-level predicates carry the authority:
//!
//! * `reach` is Go's `canReachMailbox` fast path (owner arm `admin_can_reach`,
//!   owner-less arms `admin_effective_authority`).
//! * `import_message` is the existing reducer; the actor and the admin's domain
//!   scope ride into it (`p_actor_id`, `p_domain_scope`), so its INSERT predicate
//!   `admin_can_reach_mailbox` decides at execution time (R1-R3).
//! * `export_rows` filters through the same predicate in the SELECT.
//! * the audit row is one `audit_write` statement of its own, as in Go.
//!
//! Each reducer call is one receipted transaction, so a lost COMMIT answer is
//! reported rather than replayed.
use super::{deadline, envelope, invalid, scope, FAMILY};
use crate::mimeutil::ImportFields;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type};

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// Go's `canReachMailbox` result.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Reach {
    Allowed,
    OutOfScope,
    NotFound,
}

/// `canReachMailbox`: `actor` is the verified user, `scope` the admin's live
/// domain scope (0 = none). A database failure is `Err` (Go's 500).
pub async fn reach(
    worker: &ScopedExecutor,
    actor: i64,
    scope_id: i64,
    mailbox: i64,
) -> Result<Reach, StatementFailure> {
    let rows = worker
        .read(
            "SELECT mb.user_id, mb.domain_id FROM mailboxes mb WHERE mb.id = $1",
            &[(&mailbox, Type::INT8)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(Reach::NotFound);
    };
    let owner: Option<i64> = row.try_get(0).map_err(|_| invalid())?;
    let domain: Option<i64> = row.try_get(1).map_err(|_| invalid())?;
    let first_bool = |rows: &[setjoin_pg::Row]| -> Result<bool, StatementFailure> {
        // Go scans one row into a bool: no row or NULL is an error.
        rows.first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .ok_or_else(invalid)
    };
    if let Some(owner) = owner {
        let rows = worker
            .read(
                "SELECT admin_can_reach($1, $2)",
                &[(&actor, Type::INT8), (&owner, Type::INT8)],
            )
            .await?;
        return Ok(if first_bool(&rows)? {
            Reach::Allowed
        } else {
            Reach::OutOfScope
        });
    }
    if let Some(domain) = domain.filter(|d| *d > 0) {
        let rows = worker
            .read(
                "SELECT EXISTS (SELECT 1 FROM admin_effective_authority($1) a WHERE a.scope = $2)",
                &[(&actor, Type::INT8), (&domain, Type::INT8)],
            )
            .await?;
        if first_bool(&rows)? {
            return Ok(Reach::Allowed);
        }
    }
    if scope_id == 0 {
        let rows = worker
            .read(
                "SELECT a.scope IS NULL AND a.is_unconfined FROM admin_effective_authority($1) a",
                &[(&actor, Type::INT8)],
            )
            .await?;
        if first_bool(&rows)? {
            return Ok(Reach::Allowed);
        }
    }
    Ok(Reach::OutOfScope)
}

/// `folderToTag`: the tag that shares the folder's name in the same mailbox.
/// Go ignores every error and treats it as "no tag".
pub async fn folder_to_tag(worker: &ScopedExecutor, mailbox: i64, folder: i64) -> Option<i64> {
    let rows = worker
        .read(
            "SELECT t.id FROM tags t JOIN folders f ON f.mailbox_id = t.mailbox_id AND f.name = t.name \
             WHERE f.id = $1 AND f.mailbox_id = $2",
            &[(&folder, Type::INT8), (&mailbox, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first()?.try_get::<_, i64>(0).ok()
}

/// The text columns of a message that Postgres accepts: valid UTF-8 without a
/// NUL. `None` is the message Go's `import_message` call fails on.
pub struct Strings {
    pub message_id: String,
    pub subject: String,
    pub from_addr: String,
    pub from_name: String,
    pub in_reply_to: String,
    pub references: String,
    pub body_text: String,
    pub body_html: String,
}

fn text(b: &[u8]) -> Option<String> {
    let s = String::from_utf8(b.to_vec()).ok()?;
    (!s.contains('\0')).then_some(s)
}

impl Strings {
    pub fn of(fields: &ImportFields, message_id: &[u8]) -> Option<Self> {
        Some(Strings {
            message_id: text(message_id)?,
            subject: text(&fields.subject)?,
            from_addr: text(&fields.from_addr)?,
            from_name: text(&fields.from_name)?,
            in_reply_to: text(&fields.in_reply_to)?,
            references: text(&fields.references)?,
            body_text: text(&fields.body_text)?,
            body_html: text(&fields.body_html)?,
        })
    }
}

/// One `import_message` call. `Committed(None)` is Go's "authority was revoked"
/// (the reducer's predicate inserted nothing).
#[allow(clippy::too_many_arguments)]
pub async fn import_message(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    domain_scope: i64,
    mailbox: i64,
    tag: Option<i64>,
    strings: &Strings,
    fields: &ImportFields,
    size: i64,
    raw_ref: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<i64>, StatementFailure> {
    let auth = scope(actor);
    let actor_id = actor.user_id();
    let (secs, micros): (Option<i64>, Option<i32>) = match fields.date {
        Some((s, us)) => (Some(s), Some(us as i32)),
        None => (None, None),
    };
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.import_message"),
        &envelope(&auth, operation, &format!("{mailbox}:{raw_ref}")),
        &auth,
        deadline(),
        "SELECT import_message($4::bigint, $5::bigint, $6::text, $7::text, $8::text, $9::text, \
         $10::text::jsonb, $11::text::jsonb, $12::text::jsonb, $13::text, $14::text, $15::text, $16::text, \
         $17::bigint, FALSE, FALSE, $18::text, \
         (TIMESTAMPTZ 'epoch' + $19::bigint * INTERVAL '1 second' + $20::integer * INTERVAL '1 microsecond'), \
         p_actor_id => $21::bigint, p_domain_scope => $22::bigint) \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&mailbox, Type::INT8),
            (&tag, Type::INT8),
            (&strings.message_id, Type::TEXT),
            (&strings.subject, Type::TEXT),
            (&strings.from_addr, Type::TEXT),
            (&strings.from_name, Type::TEXT),
            (&fields.to_json, Type::TEXT),
            (&fields.cc_json, Type::TEXT),
            (&fields.bcc_json, Type::TEXT),
            (&strings.in_reply_to, Type::TEXT),
            (&strings.references, Type::TEXT),
            (&strings.body_text, Type::TEXT),
            (&strings.body_html, Type::TEXT),
            (&size, Type::INT8),
            (&raw_ref, Type::TEXT),
            (&secs, Type::INT8),
            (&micros, Type::INT4),
            (&actor_id, Type::INT8),
            (&domain_scope, Type::INT8),
        ],
        |rows| match rows {
            [row] => row.try_get::<_, Option<i64>>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// Go's best-effort `audit.Write` of `mailbox.import` (tier core).
pub async fn audit_import(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    mailbox: i64,
    after: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let actor_id = actor.user_id();
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.import_audit"),
        &envelope(&auth, operation, &format!("{mailbox}:{after}")),
        &auth,
        deadline(),
        "SELECT audit_write($4::bigint, 'mailbox.import', 'mailbox', $5::bigint, NULL, $6::text::jsonb, NULLIF($7::text, '')::inet, '', 'core') \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&actor_id, Type::INT8),
            (&mailbox, Type::INT8),
            (&after, Type::TEXT),
            (&ip, Type::TEXT),
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

/// One exported message: `(message_id, raw_ref)`, newest first.
pub async fn export_rows(
    worker: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
    mailbox: i64,
    tag: Option<i64>,
) -> Result<Vec<(String, String)>, StatementFailure> {
    let rows = worker
        .read(
            "SELECT m.id, m.message_id, m.raw_ref FROM messages m \
             WHERE m.mailbox_id = $1 AND admin_can_reach_mailbox($2, $3, $1) \
             AND ($4::BIGINT IS NULL OR EXISTS (SELECT 1 FROM message_tags mt \
                  WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = $4)) \
             ORDER BY m.received_at DESC",
            &[
                (&mailbox, Type::INT8),
                (&actor, Type::INT8),
                (&domain_scope, Type::INT8),
                (&tag, Type::INT8),
            ],
        )
        .await?;
    // Go skips a row it cannot scan.
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some((
                r.try_get::<_, String>(1).ok()?,
                r.try_get::<_, String>(2).ok()?,
            ))
        })
        .collect())
}
