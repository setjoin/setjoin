//! Scoped PostgreSQL executor (RP07, ticket #213): one transaction per
//! command, scoped to the authenticated mailbox, over `tokio-postgres` +
//! `deadpool-postgres`, wired to the `setjoin-db` lifecycle model.
//!
//! # PgBouncer transaction pool (`DB_DSN`)
//!
//! No named prepared statement is ever created:
//! - command statements go through [`ScopedTx::query`] / [`ScopedTx::execute`],
//!   which use `tokio_postgres::Client::query_typed_raw`: Parse/Bind/Describe/
//!   Execute/Sync on the *unnamed* statement with explicitly typed parameters,
//!   one round trip, nothing left on the server connection afterwards;
//! - `BEGIN`, `COMMIT` and `ROLLBACK` use the simple-query protocol
//!   (`batch_execute`);
//! - deadpool's statement cache (`prepare_cached`) is never used.
//!
//! Keep result columns to built-in types (cast custom enums/domains to
//! `text`): the driver resolves an unknown result type OID with its own named
//! type-info statement.
//!
//! # Tenant scope
//!
//! Mirrors the Go seam `shared/dbscope.RunScoped` / `reducercall.CallScoped`:
//! `BEGIN` → `SELECT set_config('app.current_mailbox_id', $1, true)` (the
//! `setjoin-contracts` `InfrastructureStatement::MailboxScope` text; bound
//! parameter, transaction-local so it dies with the transaction and never
//! reaches the next pooled request) → command statements → `COMMIT`. The
//! mailbox comes only from [`MailboxAuthContext`], never from request-owned
//! fields (R2); the envelope's authority must equal it before anything is sent.
//! Statements still carry their own ownership predicates (R1/R3, bind
//! [`ScopedTx::mailbox`]); FORCE RLS on `messages`/`message_tags` is the
//! backstop when the pool's credential is the constrained `setjoin_app` role.
//!
//! # Privilege
//!
//! Privilege is the pool's credential. The executor never issues `SET ROLE`
//! and [`statement::admit`] refuses role/session/transaction-control
//! statements and `set_config` before they reach the server.
//!
//! # Outcomes
//!
//! [`CommandOutcome`] is the lifecycle's terminal observation: `Committed`,
//! `RolledBack` (known not committed) or `Unknown { operation }`, which is
//! never success and maps to `recover(Unknown) = LookupUnderCurrentAuthority`.
//! A connection whose outcome is unknown is discarded, never pooled again; a
//! dropped (cancelled) `run` future discards its connection too.
#![forbid(unsafe_code)]

pub mod auth;
pub mod cert_monitor;
pub mod command;
pub mod executor;
pub mod operator;
pub mod outcome;
pub mod statement;
pub mod ticket_keys;
pub mod workers;

pub use auth::MailboxAuthContext;
pub use command::{
    lookup_command, lookup_operation, operation_hex, run_command, run_receipted_command,
    run_receipted_command_capped,
    OperationLookup, ReceiptCommand,
};
pub use executor::{
    ConfigError, Param, ProvenStatement, ScopedExecutor, ScopedTx, Timeouts, DEADLINE_ENV,
};
pub use outcome::{
    commit_failure_observation, CommandOutcome, FailureCode, Rejection, StatementFailure,
};
pub use tokio_postgres::{types::Type, Row};

#[cfg(test)]
mod tests;
