//! Email list read (RP07, #216): the mailbox-tag listing behind the webmail
//! inbox (`Email/query` with `inMailbox`), read in Rust.
//!
//! # Contract
//!
//! Parity with `jmap_email_query(p_mailbox_id, p_filter, p_sort, p_position,
//! p_limit)` (`mailserver/sql/reducers/jmap_email.sql`) for the filter
//! `{"inMailbox": "<tag>"}` plus optional `focus` and `hasKeyword`
//! `$seen`/`$unseen`, sorted by `receivedAt` either way:
//!
//! - rows: the mailbox's messages (`mailbox_id` = the authenticated mailbox,
//!   R1) that are not deleted and carry the tag; when the tag is a
//!   `location`-group tag of this mailbox, messages carrying any
//!   `snooze`-group tag are hidden (Snoozed/Scheduled list their own tag);
//!   `focus = other` keeps only messages tagged `Other`, `focused` drops
//!   them (a mailbox with no `Other` tag: `other` matches nothing, `focused`
//!   keeps everything); `seen` filters on `is_read`;
//! - order: pinned first, then `received_at`, then `id` in the same
//!   direction as `received_at` (the reducer's ORDER BY: a total order, so
//!   messages sharing a `received_at` page without repeats or gaps, #223);
//! - page: `OFFSET position LIMIT limit`; `total` counts every matching row;
//!   a position at or past `total` is an empty page, not an error;
//! - `email_state`: the mailbox's `jmap_email_state` (the reducer's `state`).
//!
//! A read writes nothing: no audit row (Go's `emailQuery` writes none), no
//! state bump, no journal row, no push, no mark-read. It runs as one
//! statement in a `READ ONLY` transaction scoped to the mailbox
//! ([`ScopedExecutor::read_scoped`]), so a write cannot happen even by
//! accident. The SQL is static and fully parameterised; the sort direction
//! picks one of two constant statements. The reducer is never called. No
//! column read here is encrypted or HMAC'd, so the pool needs no session GUCs.
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

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

macro_rules! list_sql {
    ($direction:literal) => {
        concat!(
            "SELECT s.state, \
               (SELECT count(*) FROM messages m WHERE ",
            list_sql!(@where),
            ")::int8, \
               ARRAY(SELECT m.id FROM messages m WHERE ",
            list_sql!(@where),
            " ORDER BY m.pinned_at IS NOT NULL DESC, m.received_at ",
            $direction,
            ", m.id ",
            $direction,
            " LIMIT $6 OFFSET $5) \
             FROM (SELECT jmap_email_state::int8 AS state FROM mailboxes WHERE id = $1) s"
        )
    };
    (@where) => {
        "m.mailbox_id = $1 AND NOT m.is_deleted \
         AND EXISTS (SELECT 1 FROM message_tags mt \
                      WHERE mt.message_id = m.id AND mt.received_at = m.received_at AND mt.tag_id = $2) \
         AND (NOT EXISTS (SELECT 1 FROM tags t \
                           WHERE t.id = $2 AND t.mailbox_id = $1 AND t.exclusive_group = 'location') \
              OR NOT EXISTS (SELECT 1 FROM message_tags ms JOIN tags ts ON ts.id = ms.tag_id \
                              WHERE ms.message_id = m.id AND ms.received_at = m.received_at \
                                AND ts.mailbox_id = $1 AND ts.exclusive_group = 'snooze')) \
         AND ($3::text IS NULL OR ($3 = 'other') = EXISTS ( \
               SELECT 1 FROM message_tags mo JOIN tags o ON o.id = mo.tag_id \
                WHERE mo.message_id = m.id AND mo.received_at = m.received_at \
                  AND o.mailbox_id = $1 AND o.name = 'Other')) \
         AND ($4::bool IS NULL OR m.is_read = $4)"
    };
}

const NEWEST_FIRST: &str = list_sql!("DESC");
const OLDEST_FIRST: &str = list_sql!("ASC");

/// Reads one page of `query` in `auth`'s mailbox. `Err` means nothing was
/// read (the caller forwards the request to Go); there is no partial page.
pub async fn query_email_list(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    query: &EmailListQuery,
) -> Result<EmailListPage, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let focus = query.focus.map(|f| match f {
        Focus::Focused => "focused",
        Focus::Other => "other",
    });
    let (position, limit) = (i64::from(query.position), i64::from(query.limit));
    let sql = if query.ascending {
        OLDEST_FIRST
    } else {
        NEWEST_FIRST
    };
    let rows = exec
        .read_scoped(
            auth,
            sql,
            &[
                (&mailbox, Type::INT8),
                (&query.tag, Type::INT8),
                (&focus, Type::TEXT),
                (&query.seen, Type::BOOL),
                (&position, Type::INT8),
                (&limit, Type::INT8),
            ],
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
        for sql in [NEWEST_FIRST, OLDEST_FIRST] {
            assert_eq!(setjoin_pg::statement::admit(sql), Ok(()));
            assert!(sql.starts_with("SELECT "));
        }
        assert!(NEWEST_FIRST.contains("m.received_at DESC, m.id DESC LIMIT"));
        assert!(OLDEST_FIRST.contains("m.received_at ASC, m.id ASC LIMIT"));
    }
}
