//! `Email/get` (JMAP1, #315): the reducer read plus Go's `email_get` audit row,
//! in one transaction, for every mailbox-scoped plaintext Email/get.
//!
//! Go's `emailGet` calls `jmap_email_get(mailbox, ids, properties)` through the
//! scoped caller, then writes one `mailbox_audit_log` row (`email_get`, actor
//! from the token, `message_id` NULL, `details` NULL) best-effort on the pool.
//! Here the reducer call and the audit row are one statement in one scoped
//! transaction, so the audit row is atomic with the read it records. The mailbox
//! and actor come from the authenticated context (R1/R2); the request's
//! `accountId` is never bound.
//!
//! S/MIME decrypt-on-read stays Go's: when any returned email has
//! `cryptoType = 'smime-encrypted'` the statement writes no audit row and the
//! outcome is [`GetOutcome::Encrypted`], so the gateway forwards the whole
//! request to Go (which reads, decrypts and audits as today). Owner of the
//! native decrypt: a later ticket that ports the keystore/CMS path.
use crate::failure::{classify, Failure};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, MailboxAuthContext, Rejection, ScopedExecutor, Type};
use std::time::Instant;

/// The command marker; the mailbox is the authenticated one.
#[derive(Clone, Copy, Debug)]
pub struct EmailGet;

#[derive(Debug, PartialEq, Eq)]
pub enum GetOutcome {
    /// The reducer's JSONB as text, audit row committed with it.
    Served(String),
    /// At least one email is stored encrypted: nothing written, Go decrypts.
    Encrypted,
    /// The database refused the read deterministically: Go's call fails the same way.
    Failed(Failure),
    /// Not served (rolled back, unknown commit, unreadable): forward to Go.
    /// The read has no effect to double beyond one more audit row.
    Forward,
}

/// `$1` mailbox, `$2` actor, `$3` ids (NULL = Go's nil slice), `$4` properties.
pub const SQL: &str = "WITH r AS MATERIALIZED (SELECT jmap_email_get($1, $3::bigint[], $4::text[]) AS res), \
     a AS (INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id) \
           SELECT $1, $2, 'email_get', NULL FROM r \
           WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements( \
                   CASE WHEN jsonb_typeof(r.res->'list') = 'array' THEN r.res->'list' ELSE '[]'::jsonb END) e \
                 WHERE e->>'cryptoType' = 'smime-encrypted') \
           RETURNING 1) \
     SELECT r.res::text, (SELECT count(*) FROM a)::int4 FROM r";

pub async fn email_get(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<EmailGet>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    ids: Option<&[i64]>,
    properties: Option<&[String]>,
) -> GetOutcome {
    let mailbox = auth.mailbox().get();
    let actor = auth.actor().get();
    let ids: Option<Vec<i64>> = ids.map(<[i64]>::to_vec);
    let properties: Option<Vec<String>> = properties.map(<[String]>::to_vec);
    let outcome = exec
        .run(envelope, auth, deadline, async |tx| {
            let rows = tx
                .query(
                    SQL,
                    &[
                        (&mailbox, Type::INT8),
                        (&actor, Type::INT8),
                        (&ids, Type::INT8_ARRAY),
                        (&properties, Type::TEXT_ARRAY),
                    ],
                )
                .await?;
            let row = rows.first().ok_or_else(|| setjoin_pg::StatementFailure {
                hint: None,
                sqlstate: None,
                message: "reducer returned no row".into(),
            })?;
            let text: Option<String> = row.get(0);
            let audited: i32 = row.get(1);
            Ok::<_, setjoin_pg::StatementFailure>((text, audited))
        })
        .await;
    match outcome {
        CommandOutcome::Committed((Some(text), 1)) => GetOutcome::Served(text),
        CommandOutcome::Committed((Some(_), 0)) => GetOutcome::Encrypted,
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
