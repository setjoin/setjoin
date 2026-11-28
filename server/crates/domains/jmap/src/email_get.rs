//! `Email/get` (JMAP1, #315, #328): the reducer read plus the `email_get`
//! audit row in one transaction.
//!
//! Calls `jmap_email_get(mailbox, ids, properties)` and commits one
//! `mailbox_audit_log` row (`email_get`, actor from the token, `message_id`
//! NULL) in one scoped transaction via [`TxFactory::run_mailbox_audited_read_contract`]
//! from a verified [`ReadCapability`].
use crate::failure::{classify, Failure};
use crate::sql;
use setjoin_authz::principals::{ReadCapability, TxFactory};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, Rejection, StatementFailure};
use std::time::Instant;

/// The command marker; the mailbox is the authenticated one.
#[derive(Clone, Copy, Debug)]
pub struct EmailGet;

#[derive(Debug, PartialEq, Eq)]
pub enum GetOutcome {
    /// The reducer's JSONB as text, audit row committed with it.
    Served(String),
    /// The database refused the read deterministically: Go's call fails the same way.
    Failed(Failure),
    /// Not served (rolled back, unknown commit, unreadable).
    Forward,
}

/// `$1` mailbox, `$2` actor, `$3` ids (NULL = Go's nil slice), `$4` properties.
pub const SQL: &str = sql::EMAIL_GET.sql;

pub async fn email_get(
    tx_factory: &TxFactory,
    envelope: &CommandEnvelope<EmailGet>,
    read: &ReadCapability,
    deadline: Instant,
    ids: Option<&[i64]>,
    properties: Option<&[String]>,
) -> GetOutcome {
    let mailbox = read.mailbox().get();
    let actor = read.actor().get();
    let ids: Option<Vec<i64>> = ids.map(<[i64]>::to_vec);
    let properties: Option<Vec<String>> = properties.map(<[String]>::to_vec);
    let outcome = tx_factory
        .run_mailbox_audited_read_contract(
            read,
            envelope,
            deadline,
            &sql::EMAIL_GET,
            &[&mailbox, &actor, &ids, &properties],
            None,
            |rows| {
                let row = rows.first().ok_or_else(|| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "reducer returned no row".into(),
                })?;
                let text: Option<String> = row.try_get(0).map_err(|_| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "invalid Email/get payload column".into(),
                })?;
                let audited: i32 = row.try_get(1).map_err(|_| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "invalid Email/get audit column".into(),
                })?;
                Ok((text, audited))
            },
        )
        .await;
    match outcome {
        CommandOutcome::Committed((Some(text), 1)) => GetOutcome::Served(text),
        CommandOutcome::RolledBack(Rejection::Statement(failure)) => match classify(&failure) {
            Failure::Forward => GetOutcome::Forward,
            other => GetOutcome::Failed(other),
        },
        _ => GetOutcome::Forward,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_is_one_admissible_statement_naming_no_partitioned_table() {
        assert_eq!(setjoin_pg::statement::admit(SQL), Ok(()));
        assert!(!SQL.contains("messages") && !SQL.contains("message_tags"));
    }
}
