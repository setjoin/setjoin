//! `Email/changes` read (JMAP1, #315): the per-account delta behind the
//! webmail and offline sync, read through the same reducer Go calls.
//!
//! The reducer `jmap_email_changes(p_mailbox_id, p_since_state, p_max_changes)`
//! (`mailserver/sql/reducers/jmap_email.sql`) is the single owner of the
//! journal collapse and soft cap; this crate never reimplements it (ARCH-028).
//! The call is one static `SELECT` in a `READ ONLY` transaction scoped to the
//! authenticated mailbox ([`TxFactory::run_mailbox_read_contract`]).
use setjoin_authz::principals::{ReadCapability, TxFactory};

use crate::sql;

/// Why no changes object came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangesError {
    /// SQLSTATE `BZ011`: the state is too old, too new or resync-marked.
    CannotCalculateChanges,
    /// SQLSTATE `BZ006`: the mailbox row does not exist.
    AccountNotFound,
    /// Anything else (timeouts, transport, other reducer codes).
    Other,
}

/// The reducer's JSONB as text. `since_state` is the client's decimal token
/// (Go checked it parses as a non-negative int64); `max_changes` is `None`
/// when the client omitted it or sent zero (Go's `nullIfZero`).
pub async fn email_changes(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    since_state: &str,
    max_changes: Option<i32>,
) -> Result<String, ChangesError> {
    let mailbox = read.mailbox().get();
    let rows = tx_factory
        .run_mailbox_read_contract(
            read,
            &sql::EMAIL_CHANGES,
            &[&mailbox, &since_state, &max_changes],
        )
        .await
        .map_err(|failure| match failure.sqlstate.as_deref() {
            Some("BZ011") => ChangesError::CannotCalculateChanges,
            Some("BZ006") => ChangesError::AccountNotFound,
            _ => ChangesError::Other,
        })?;
    rows.first()
        .and_then(|row| row.get::<_, Option<String>>(0))
        .ok_or(ChangesError::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_is_an_admissible_select() {
        assert_eq!(setjoin_pg::statement::admit(sql::EMAIL_CHANGES.sql), Ok(()));
        assert!(sql::EMAIL_CHANGES.sql.starts_with("SELECT "));
    }
}
