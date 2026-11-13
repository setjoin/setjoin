//! General `Email/query` read (JMAP1, #315): `jmap_email_query` as Go calls it.
//!
//! One static `SELECT` in a `READ ONLY` transaction scoped to the authenticated
//! mailbox ([`ScopedExecutor::read_scoped`]); the reducer owns filtering and
//! sorting, this crate never reimplements it (ARCH-028). It writes nothing (Go's
//! `emailQuery` writes no audit row). `filter` and `sort` are the client's JSON
//! text (`None` = SQL NULL as Go's nil `RawMessage`; a JSON `null` literal stays
//! a JSON null). Any error (a reducer business code, a timeout) is `Err` and the
//! gateway forwards the request, so Go answers its own error mapping.
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

const SQL: &str = "SELECT jmap_email_query($1, $2::text::jsonb, $3::text::jsonb, $4, $5)::text";

pub async fn query_email(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    filter: Option<&str>,
    sort: Option<&str>,
    position: i32,
    limit: i32,
) -> Result<String, StatementFailure> {
    let mailbox = auth.mailbox().get();
    let rows = exec
        .read_scoped(
            auth,
            SQL,
            &[
                (&mailbox, Type::INT8),
                (&filter, Type::TEXT),
                (&sort, Type::TEXT),
                (&position, Type::INT4),
                (&limit, Type::INT4),
            ],
        )
        .await?;
    rows.first()
        .and_then(|row| row.get::<_, Option<String>>(0))
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "reducer returned no row".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_is_an_admissible_select() {
        assert_eq!(setjoin_pg::statement::admit(SQL), Ok(()));
    }
}
