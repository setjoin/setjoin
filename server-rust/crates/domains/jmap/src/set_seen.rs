//! `SetMessageSeen` (`mail.email.set-seen`, sheet [`MARK_SEEN`]): the Rust
//! command for the `$seen` keyword (RP07, #214; reducer call since #224).
//!
//! # Contract
//!
//! One transaction through [`run_command`] (mailbox scope from the
//! authenticated session) with exactly one body statement, [`SET_SEEN`],
//! doing two things:
//!
//! 1. `jmap_email_set_update(mailbox, {"<id>": {"keywords":
//!    {"$seen": b}}})` (`mailserver/sql/reducers/jmap_email.sql`), the
//!    existing authority, with `mailbox` bound from the auth context (R1/R3:
//!    the reducer locks and updates by `id` **and** `mailbox_id`) and the
//!    patch built server-side from typed parameters. Its effects are the
//!    reducer's: `is_read`, `unread_count`/`jmap_state` on every tag of the
//!    message, one `jmap_email_state` bump, one `email`/`updated` journal row
//!    and one push on `tag:<mailbox>` through `app_notify`;
//! 2. in a data-modifying CTE of the same statement, one `mailbox_audit_log`
//!    row (`email_set`, actor from the
//!    authenticated session, `message_id` NULL as Go writes it), always, with
//!    `details.operation` = the operation ID (Go writes `details` NULL), so
//!    [`lookup_set_seen`] answers committed / absent for an `Unknown` outcome.
//!
//! No-op rule (owner decision 2026-10-29, #219, implemented by the reducer):
//! when `is_read` already equals the request, nothing but the audit row is
//! written. The audit row is atomic with the data: if it fails, everything
//! rolls back (Go writes it best-effort after the reducer's commit). A
//! message outside the authenticated mailbox is [`SeenEffect::NotFound`].
//! A reducer item failure (`invalidArguments`: the reducer rolled its
//! per-item subtransaction back) is [`SeenEffect::NotUpdated`] carrying the
//! reducer's own `notUpdated` entry, and the command commits (audit row
//! included) exactly as Go's `emailSet` commits that reducer result and
//! answers it as a per-item `notUpdated` entry (review item 6).
//! The recognized empty-string `$seen` input uses the same statement with a
//! JSON string; the reducer decides whether the message exists and returns
//! its per-item error. Other unsupported value shapes still defer to Go.
//!
//! # Why the audit row rides in the reducer statement (review-fix c=8 finding)
//!
//! The reducer's state bump locks the mailbox row until COMMIT, so on one
//! mailbox concurrent commands serialise on that lock and throughput is
//! bounded by how long it is held. As a separate statement the audit
//! `INSERT` added one client round trip inside the lock (reducer → audit →
//! COMMIT); Go writes its audit row after COMMIT (best-effort), so Go held
//! it for reducer → COMMIT only. One statement restores Go's lock-hold time
//! and keeps the audit row atomic with the data.
//!
//! # Why one reducer call (#224)
//!
//! The hand-written per-statement version (14 client statements) spent
//! ~11–14 ms per command in the planner: every unnamed statement is planned
//! on every call, and the ones naming `messages`/`message_tags` (partitioned
//! by `received_at`, addressed by `id`, so no plan-time pruning; 23 indexes
//! per `messages` partition; `message_tags` RLS embeds a second `messages`
//! join) cost 1–4 ms each and grow with the partition count. The reducer
//! call plans in ~0.03 ms and its inner statements run on PL/pgSQL's
//! per-connection cached plans, which survive a PgBouncer transaction pool
//! (they belong to the server connection, not the client). The call is
//! still the unnamed statement; no named/protocol-level prepared statements
//! are needed. Regression guard: no body statement may name a partitioned
//! table (unit test below).
//!
//! Neither statement reads `app.encryption_key` or `app.audit_hmac_key`
//! (checked against the triggers on every table the reducer writes), so the
//! `setjoin-pg` pool needs no session GUCs for this command.
//!
//! [`MARK_SEEN`]: setjoin_contracts::command::MARK_SEEN
use setjoin_contracts::{
    authority::ResourceScope,
    command::{CommandEnvelope, OperationResult, SetMessageSeen},
    error::ContractError,
    ids::{MailboxId, MessageId, OperationId},
};
use setjoin_db::lifecycle::LifecycleError;
use setjoin_pg::{
    lookup_operation, run_command, CommandOutcome, MailboxAuthContext, Rejection, Row,
    ScopedExecutor, StatementFailure, Type,
};
pub use setjoin_pg::{operation_hex, OperationLookup};
use std::time::Instant;

/// What a committed set-seen did.
#[derive(Clone, Debug, PartialEq, Eq)]
///
/// Every variant carries the mailbox's `jmap_email_state` as read at the
/// start of the transaction (the reducer's `oldState`, read the same way, so
/// a JMAP `Email/set` answer can report `oldState`/`newState` as Go does).
pub enum SeenEffect {
    /// `is_read` changed; the state moved from `old_state` to `email_state`.
    Changed { old_state: i64, email_state: i64 },
    /// `is_read` already had the requested value: no state change emitted.
    Unchanged { email_state: i64 },
    /// No such message in the authenticated mailbox.
    NotFound { email_state: i64 },
    /// The reducer reported a per-item error for the message (its
    /// subtransaction rolled back; no state change). `set_error` is the
    /// reducer's `notUpdated` entry as PostgreSQL's JSONB text, verbatim.
    NotUpdated { email_state: i64, set_error: String },
}

/// The command's answer. `result` is `Accepted` only after a confirmed
/// COMMIT; `Unknown` (commit outcome not observed) is never success — look
/// the operation up under current authority with `operation`.
#[derive(Debug)]
pub struct SetSeenReply {
    pub operation: OperationId,
    pub result: OperationResult<SeenEffect>,
    /// Why the command is known not to have committed. Logs only; never sent
    /// to a client.
    pub rejection: Option<Rejection<StatementFailure>>,
}

/// Run `SetMessageSeen` for the authenticated mailbox in one transaction.
///
/// The command's `mailbox` must equal `auth`'s (the envelope authority is
/// checked by the executor); a mismatch is rejected before anything is sent.
pub async fn set_message_seen(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<SetMessageSeen>,
    auth: &MailboxAuthContext,
    deadline: Instant,
) -> SetSeenReply {
    let cmd = envelope.command;
    if let Err(e) = cmd.validate_scope(auth.authority()) {
        return reply(
            envelope.operation,
            CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e))),
        );
    }
    let message = cmd.message.get();
    let seen_json = if cmd.seen { "true" } else { "false" };
    let outcome = run_command(
        exec,
        envelope,
        auth,
        deadline,
        SET_SEEN,
        &[(&message, Type::INT8), (&seen_json, Type::TEXT)],
        decode_seen,
    )
    .await;
    reply(envelope.operation, outcome)
}

/// A recognized empty-string `$seen` value, passed to the same reducer so
/// its per-item error and ownership checks remain authoritative.
#[derive(Clone, Copy, Debug)]
pub struct EmptySeen {
    pub mailbox: MailboxId,
    pub message: MessageId,
}

pub async fn set_message_seen_empty(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<EmptySeen>,
    auth: &MailboxAuthContext,
    deadline: Instant,
) -> SetSeenReply {
    let cmd = envelope.command;
    if auth.authority().scope != ResourceScope::Mailbox(cmd.mailbox) {
        return reply(
            envelope.operation,
            CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(
                ContractError::ScopeMismatch,
            ))),
        );
    }
    let message = cmd.message.get();
    let seen_json = "\"\"";
    let outcome = run_command(
        exec,
        envelope,
        auth,
        deadline,
        SET_SEEN,
        &[(&message, Type::INT8), (&seen_json, Type::TEXT)],
        decode_seen,
    )
    .await;
    reply(envelope.operation, outcome)
}

/// Map the executor's terminal observation onto the operation result.
pub fn reply(
    operation: OperationId,
    outcome: CommandOutcome<SeenEffect, StatementFailure>,
) -> SetSeenReply {
    let (result, rejection) = match outcome {
        CommandOutcome::Committed(effect) => (OperationResult::Accepted(effect), None),
        CommandOutcome::RolledBack(r) => (OperationResult::Rejected, Some(r)),
        CommandOutcome::Unknown { .. } => (OperationResult::Unknown, None),
    };
    SetSeenReply {
        operation,
        result,
        rejection,
    }
}

/// The reducer call and the Go call site's actor audit row, one statement.
/// `$1` mailbox and `$2` actor (auth context), `$3` operation ID (32
/// lower-case hex, `details.operation`, so an
/// `Unknown` outcome can be looked up with [`lookup_set_seen`]; owner
/// decision 2026-10-29), `$4` message and `$5` seen. Go writes `details` NULL and nothing reads it for
/// `email_set`); `$5` is the JSON encoding of the seen value. Returns `oldState`, `newState`, whether the message is in
/// `updated`, its `notUpdated` type and its whole `notUpdated` entry (both
/// NULL when absent). The data-modifying CTE always runs; a reducer error
/// fails the whole statement, so the audit row commits exactly with the data.
pub const SET_SEEN: &str = "WITH audit AS ( \
       INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id, details) \
       VALUES ($1, $2, 'email_set', NULL, jsonb_build_object('operation', $3::text)) RETURNING 1) \
     SELECT (r->>'oldState')::bigint, (r->>'newState')::bigint, \
       r->'updated' @> jsonb_build_array($4::bigint), \
       r->'notUpdated'->($4::bigint::text)->>'type', \
       (r->'notUpdated'->($4::bigint::text))::text \
     FROM jmap_email_set_update($1, jsonb_build_object($4::bigint::text, \
       jsonb_build_object('keywords', jsonb_build_object('$seen', $5::text::jsonb)))) AS r, audit";

/// The lookup binds the authenticated mailbox and actor and the operation ID.
pub const LOOKUP: &str = "SELECT EXISTS (SELECT 1 FROM mailbox_audit_log \
     WHERE mailbox_id = $1 AND actor_user_id = $2 AND action = 'email_set' \
     AND details->>'operation' = $3)";

/// Look up an operation ID returned by an `Unknown` outcome, under the
/// caller's current authority (`recover(Unknown)` = look up under current
/// authority). One `READ ONLY` scoped read; an error means "still unknown".
pub async fn lookup_set_seen(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    operation: OperationId,
) -> Result<OperationLookup, StatementFailure> {
    lookup_operation(exec, auth, operation, LOOKUP, &[]).await
}

/// Every statement the command body sends, in order.
pub const BODY_STATEMENTS: [&str; 1] = [SET_SEEN];

fn decode_seen(rows: &[Row]) -> Result<SeenEffect, StatementFailure> {
    let row = rows
        .first()
        .ok_or_else(|| failure("reducer returned no row"))?;
    let old: Option<i64> = row.get(0);
    let new: Option<i64> = row.get(1);
    let updated: Option<bool> = row.get(2);
    let not_updated_type: Option<String> = row.get(3);
    let not_updated_entry: Option<String> = row.get(4);
    let (Some(old_state), Some(email_state)) = (old, new) else {
        return Err(failure("authenticated mailbox row missing"));
    };
    let not_updated = match (not_updated_type.as_deref(), not_updated_entry.as_deref()) {
        (Some(t), Some(raw)) => Some((t, raw)),
        (None, None) => None,
        _ => return Err(failure("reducer notUpdated entry without a type")),
    };
    classify(old_state, email_state, updated == Some(true), not_updated)
}

/// Map the reducer's per-id result onto [`SeenEffect`]. `not_updated` is the
/// message's `notUpdated` entry as (type, JSONB text). Anything but exactly
/// one of `updated` / `notUpdated` with a consistent state is a failure (the
/// command rolls back).
fn classify(
    old_state: i64,
    email_state: i64,
    updated: bool,
    not_updated: Option<(&str, &str)>,
) -> Result<SeenEffect, StatementFailure> {
    match (updated, not_updated) {
        (true, None) if email_state == old_state => Ok(SeenEffect::Unchanged { email_state }),
        (true, None) => Ok(SeenEffect::Changed {
            old_state,
            email_state,
        }),
        (false, Some(("notFound", _))) if email_state == old_state => {
            Ok(SeenEffect::NotFound { email_state })
        }
        (false, Some((_, raw))) if email_state == old_state => Ok(SeenEffect::NotUpdated {
            email_state,
            set_error: raw.to_owned(),
        }),
        (_, other) => Err(failure(&format!(
            "reducer result inconsistent (notUpdated type {:?})",
            other.map(|(t, _)| t)
        ))),
    }
}

fn failure(message: &str) -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: OperationId = OperationId([0x42; 16]);

    #[test]
    fn unknown_commit_returns_the_operation_for_lookup_never_success() {
        let r = reply(OP, CommandOutcome::Unknown { operation: OP });
        assert_eq!(r.operation, OP);
        assert_eq!(r.result, OperationResult::Unknown);
        assert!(r.rejection.is_none());
    }

    #[test]
    fn only_a_confirmed_commit_is_accepted() {
        let ok = reply(
            OP,
            CommandOutcome::Committed(SeenEffect::Unchanged { email_state: 3 }),
        );
        assert_eq!(
            ok.result,
            OperationResult::Accepted(SeenEffect::Unchanged { email_state: 3 })
        );
        let rolled = reply(OP, CommandOutcome::RolledBack(Rejection::Unavailable));
        assert_eq!(rolled.result, OperationResult::Rejected);
        assert!(matches!(rolled.rejection, Some(Rejection::Unavailable)));
        assert_eq!(rolled.operation, OP);
    }

    #[test]
    fn classifies_the_reducer_result() {
        assert_eq!(
            classify(4, 5, true, None).unwrap(),
            SeenEffect::Changed {
                old_state: 4,
                email_state: 5
            }
        );
        assert_eq!(
            classify(4, 4, true, None).unwrap(),
            SeenEffect::Unchanged { email_state: 4 }
        );
        let nf = r#"{"type": "notFound"}"#;
        assert_eq!(
            classify(4, 4, false, Some(("notFound", nf))).unwrap(),
            SeenEffect::NotFound { email_state: 4 }
        );
        assert!(classify(4, 4, false, None).is_err());
        assert!(classify(4, 5, false, Some(("notFound", nf))).is_err());
    }

    /// Review item 6 (+a): a per-item reducer error is Go's per-item
    /// `notUpdated` entry, committed like Go commits it — not a rollback.
    /// The entry is the reducer's own JSONB text, passed through.
    #[test]
    fn a_reducer_item_error_is_a_committed_not_updated_entry() {
        let raw = r#"{"type": "invalidArguments", "description": "Update failed"}"#;
        assert_eq!(
            classify(4, 4, false, Some(("invalidArguments", raw))).unwrap(),
            SeenEffect::NotUpdated {
                email_state: 4,
                set_error: raw.to_owned()
            }
        );
        // A state that moved while nothing was updated is not the reducer's
        // per-item error: fail closed.
        assert!(classify(4, 5, false, Some(("invalidArguments", raw))).is_err());
    }

    /// c=8 finding regression guard: the reducer's state bump holds the
    /// mailbox row lock until COMMIT, so nothing may add a client round trip
    /// between the reducer call and COMMIT: the body is one statement, and
    /// the audit row is written by it.
    #[test]
    fn the_audit_row_rides_in_the_reducer_statement() {
        assert_eq!(BODY_STATEMENTS.len(), 1);
        assert!(SET_SEEN.contains("INSERT INTO mailbox_audit_log"));
        assert!(SET_SEEN.contains("jmap_email_set_update("));
    }

    /// #224 regression guard: an unnamed statement is planned on every call,
    /// and a client-sent statement naming the `received_at`-partitioned
    /// tables cost 1-4 ms of planning each (growing with the partition
    /// count). Their access stays inside the reducer's cached plans.
    #[test]
    fn no_body_statement_names_a_partitioned_table() {
        for sql in BODY_STATEMENTS {
            let words: Vec<String> = sql
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(str::to_ascii_lowercase)
                .collect();
            for table in ["messages", "message_tags"] {
                assert!(!words.iter().any(|w| w == table), "{table} in {sql}");
            }
            assert!(setjoin_pg::statement::admit(sql).is_ok(), "{sql}");
        }
    }
}
