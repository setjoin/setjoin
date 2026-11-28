//! General `Email/query` read (JMAP1, #315): `jmap_email_query` as Go calls it.
//!
//! One static `SELECT` in a `READ ONLY` transaction scoped to the authenticated
//! mailbox ([`TxFactory::run_mailbox_read_contract`]); the reducer owns
//! filtering and sorting, this crate never reimplements it (ARCH-028).
use setjoin_authz::principals::{ReadCapability, TxFactory};
use setjoin_pg::StatementFailure;

use crate::sql;

pub async fn query_email(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    filter: Option<&str>,
    sort: Option<&str>,
    position: i32,
    limit: i32,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let rows = tx_factory
        .run_mailbox_read_contract(
            read,
            &sql::EMAIL_QUERY,
            &[&mailbox, &filter, &sort, &position, &limit],
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
        assert_eq!(setjoin_pg::statement::admit(sql::EMAIL_QUERY.sql), Ok(()));
    }
}
