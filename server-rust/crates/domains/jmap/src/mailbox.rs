//! Mailbox and thread reads use frozen Go's reducers in authenticated read-only scope.
use setjoin_pg::{MailboxAuthContext, Param, ScopedExecutor, StatementFailure, Type};

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
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    request: &Read,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let mut params: Vec<Param<'_>> = vec![(&mailbox, Type::INT8)];
    let sql = match request {
        Read::ThreadGet(ids) => {
            params.push((ids, Type::TEXT_ARRAY));
            "SELECT jmap_thread_get($1,$2)::text"
        }
        Read::ThreadChanges(since) => {
            params.push((since, Type::TEXT));
            "SELECT jmap_thread_changes($1,$2)::text"
        }
        Read::SearchSnippet { filter, ids } => {
            params.extend([(filter as _, Type::TEXT), (ids as _, Type::INT8_ARRAY)]);
            "SELECT jmap_search_snippet_get($1,$2::text::jsonb,$3)::text"
        }
        Read::Get { ids, properties } => {
            params.extend([
                (ids as _, Type::INT8_ARRAY),
                (properties as _, Type::TEXT_ARRAY),
            ]);
            "SELECT jmap_mailbox_get($1,$2,$3)::text"
        }
        Read::Query {
            filter,
            sort,
            position,
            limit,
        } => {
            params.extend([
                (filter as _, Type::TEXT),
                (sort as _, Type::TEXT),
                (position as _, Type::INT4),
                (limit as _, Type::INT4),
            ]);
            "SELECT jmap_mailbox_query($1,$2::text::jsonb,$3::text::jsonb,$4,$5)::text"
        }
        Read::Changes(since) => {
            params.push((since, Type::TEXT));
            "SELECT jmap_mailbox_changes($1,$2)::text"
        }
        Read::QueryChanges {
            filter,
            sort,
            since,
        } => {
            params.extend([
                (filter as _, Type::TEXT),
                (sort as _, Type::TEXT),
                (since as _, Type::TEXT),
            ]);
            "SELECT jmap_mailbox_query_changes($1,$2::text::jsonb,$3::text::jsonb,$4)::text"
        }
    };
    let rows = exec.read_scoped(auth, sql, &params).await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing mailbox result".into(),
        })
}
