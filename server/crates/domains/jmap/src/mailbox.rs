//! Mailbox and thread reads use frozen Go's reducers in authenticated read-only scope.
use setjoin_authz::principals::{ReadCapability, TxFactory};
use setjoin_pg::StatementFailure;

use crate::sql;

pub enum Read {
    ThreadGet(Option<Vec<String>>),
    ThreadChanges(String),
    SearchSnippet {
        filter: Option<String>,
        ids: Option<Vec<i64>>,
    },
    Get {
        ids: Option<Vec<i64>>,
        properties: Option<Vec<String>>,
    },
    Query {
        filter: Option<String>,
        sort: Option<String>,
        position: i32,
        limit: Option<i32>,
    },
    Changes(String),
    QueryChanges {
        filter: Option<String>,
        sort: Option<String>,
        since: String,
    },
}

impl Read {
    pub fn since_state(&self) -> Option<&str> {
        match self {
            Self::Changes(s) | Self::ThreadChanges(s) | Self::QueryChanges { since: s, .. } => {
                Some(s)
            }
            _ => None,
        }
    }
}

pub async fn read(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    request: &Read,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let rows = match request {
        Read::ThreadGet(ids) => {
            tx_factory
                .run_mailbox_read_contract(read, &sql::MAILBOX_THREAD_GET, &[&mailbox, ids])
                .await?
        }
        Read::ThreadChanges(since) => {
            tx_factory
                .run_mailbox_read_contract(read, &sql::MAILBOX_THREAD_CHANGES, &[&mailbox, since])
                .await?
        }
        Read::SearchSnippet { filter, ids } => {
            tx_factory
                .run_mailbox_read_contract(
                    read,
                    &sql::MAILBOX_SEARCH_SNIPPET,
                    &[&mailbox, filter, ids],
                )
                .await?
        }
        Read::Get { ids, properties } => {
            tx_factory
                .run_mailbox_read_contract(read, &sql::MAILBOX_GET, &[&mailbox, ids, properties])
                .await?
        }
        Read::Query {
            filter,
            sort,
            position,
            limit,
        } => {
            tx_factory
                .run_mailbox_read_contract(
                    read,
                    &sql::MAILBOX_QUERY,
                    &[&mailbox, filter, sort, position, limit],
                )
                .await?
        }
        Read::Changes(since) => {
            tx_factory
                .run_mailbox_read_contract(read, &sql::MAILBOX_CHANGES, &[&mailbox, since])
                .await?
        }
        Read::QueryChanges {
            filter,
            sort,
            since,
        } => {
            tx_factory
                .run_mailbox_read_contract(
                    read,
                    &sql::MAILBOX_QUERY_CHANGES,
                    &[&mailbox, filter, sort, since],
                )
                .await?
        }
    };
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing mailbox result".into(),
        })
}
