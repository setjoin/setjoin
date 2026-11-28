//! Email list read (RP07, #216): the mailbox-tag listing behind the webmail
//! inbox (`Email/query` with `inMailbox`), read in Rust via
//! [`TxFactory::run_mailbox_read_contract`] strictly from a [`ReadCapability`].
use setjoin_authz::principals::{ReadCapability, TxFactory};
use setjoin_pg::StatementFailure;

use crate::sql;

/// `focus` (the Focused/Other inbox split, V078).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// Hide messages tagged `Other`.
    Focused,
    /// Only messages tagged `Other`.
    Other,
}

/// One page request. Ranges are the gateway's to enforce (Go's handler
/// clamps `limit` to 1..=256 and passes `position` through).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmailListQuery {
    /// `inMailbox`: the tag id.
    pub tag: i64,
    pub focus: Option<Focus>,
    /// `hasKeyword`: `Some(true)` = `$seen`, `Some(false)` = `$unseen`.
    pub seen: Option<bool>,
    pub ascending: bool,
    pub position: i32,
    pub limit: i32,
}

/// What the reducer reports, minus the constant fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailListPage {
    pub email_state: i64,
    pub total: i64,
    pub ids: Vec<i64>,
}

/// Reads one page of `query` in `read`'s mailbox. `Err` means nothing was read.
pub async fn query_email_list(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    query: &EmailListQuery,
) -> Result<EmailListPage, StatementFailure> {
    let mailbox = read.mailbox().get();
    let focus = query.focus.map(|f| match f {
        Focus::Focused => "focused",
        Focus::Other => "other",
    });
    let (position, limit) = (i64::from(query.position), i64::from(query.limit));
    let contract = if query.ascending {
        &sql::EMAIL_LIST_OLDEST
    } else {
        &sql::EMAIL_LIST_NEWEST
    };
    let rows = tx_factory
        .run_mailbox_read_contract(
            read,
            contract,
            &[&mailbox, &query.tag, &focus, &query.seen, &position, &limit],
        )
        .await?;
    let row = rows.first().ok_or_else(|| StatementFailure {
        hint: None,
        sqlstate: None,
        message: "mailbox not found".into(),
    })?;
    Ok(EmailListPage {
        email_state: row.get(0),
        total: row.get(1),
        ids: row.get(2),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_are_admissible_selects() {
        for stmt in [sql::EMAIL_LIST_NEWEST.sql, sql::EMAIL_LIST_OLDEST.sql] {
            assert_eq!(setjoin_pg::statement::admit(stmt), Ok(()));
            assert!(stmt.starts_with("SELECT "));
        }
        assert!(sql::EMAIL_LIST_NEWEST
            .sql
            .contains("m.received_at DESC, m.id DESC LIMIT"));
        assert!(sql::EMAIL_LIST_OLDEST
            .sql
            .contains("m.received_at ASC, m.id ASC LIMIT"));
    }
}
