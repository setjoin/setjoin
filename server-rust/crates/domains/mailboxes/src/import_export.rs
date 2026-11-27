//! `POST /admin/mailboxes/{id}/import` and `GET /admin/mailboxes/{id}/export`:
//! the database side. Reads execute through `TxFactory` (`AdminRead`,
//! `BYPASSRLS`) with verified `AdminPermissionProof`; per-message import uses
//! the `sql::IMPORT_MESSAGE` `WorkerBypass` contract with live statement-level
//! `admin_can_reach_mailbox` authority checks; the audit row is one
//! `audit_write` statement of its own, as in Go.
use super::{command, deadline, envelope, invalid, sql};
use crate::mimeutil::ImportFields;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// Go's `canReachMailbox` result.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Reach {
    Allowed,
    OutOfScope,
    NotFound,
}

/// `canReachMailbox`: `proof` carries the verified admin actor, `scope_id` the
/// admin's live domain scope (0 = none). A database failure is `Err` (Go's 500).
pub async fn reach(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    scope_id: i64,
    mailbox: i64,
) -> Result<Reach, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::IMPORT_REACH_MAILBOX, &[&mailbox])
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
        let rows = factory
            .run_admin_read_contract(proof, &sql::IMPORT_REACH_USER, &[&actor, &owner])
            .await?;
        return Ok(if first_bool(&rows)? {
            Reach::Allowed
        } else {
            Reach::OutOfScope
        });
    }
    if let Some(domain) = domain.filter(|d| *d > 0) {
        let rows = factory
            .run_admin_read_contract(proof, &sql::IMPORT_REACH_DOMAIN, &[&actor, &domain])
            .await?;
        if first_bool(&rows)? {
            return Ok(Reach::Allowed);
        }
    }
    if scope_id == 0 {
        let rows = factory
            .run_admin_read_contract(proof, &sql::IMPORT_REACH_GLOBAL, &[&actor])
            .await?;
        if first_bool(&rows)? {
            return Ok(Reach::Allowed);
        }
    }
    Ok(Reach::OutOfScope)
}

/// `folderToTag`: the tag that shares the folder's name in the same mailbox.
/// Go ignores every error and treats it as "no tag".
pub async fn folder_to_tag(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    mailbox: i64,
    folder: i64,
) -> Option<i64> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::FOLDER_TO_TAG, &[&folder, &mailbox])
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

/// Go's best-effort `audit.Write` of `mailbox.import` (tier core).
pub async fn audit_import(
    factory: &TxFactory,
    user: &UserPrincipal,
    mailbox: i64,
    after: &str,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{mailbox}:{after}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::AUDIT_IMPORT,
            &[&actor_id, &mailbox, &after, &ip],
            Some(command("mailbox.import_audit")),
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
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    domain_scope: i64,
    mailbox: i64,
    tag: Option<i64>,
) -> Result<Vec<(String, String)>, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(
            proof,
            &sql::EXPORT_ROWS,
            &[&mailbox, &actor, &domain_scope, &tag],
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
