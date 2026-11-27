//! Scoped PostgreSQL executor (RP07, ticket #213; Wave 1.2, ticket #540):
//! compile-time typed capability handles, `RecyclingMethod::Fast` (0-RTT
//! checkout), 1-RTT `tokio::join!(biased; ...)` pipelining, PgBouncer-safe
//! `CancelRequest` drop, and opt-in CVE-2026-14666-guarded prepared LRU.
//!
//! # PgBouncer transaction pool (`DB_DSN`)
//!
//! By default (`PreparedStatementMode::Unnamed`), no named prepared statement
//! is ever created:
//! - command statements use `tokio_postgres::Client::query_typed` /
//!   `query_typed_raw`: Parse/Bind/Describe/Execute/Sync on the *unnamed*
//!   statement with explicitly typed parameters, nothing left on the server
//!   connection afterwards;
//! - `BEGIN`, `COMMIT` and `ROLLBACK` use the simple-query protocol
//!   (`batch_execute`);
//! - deadpool's unbounded statement cache (`prepare_cached`) is never used.
//!
//! Keep result columns to built-in types (cast custom enums/domains to
//! `text`): the driver resolves an unknown result type OID with its own named
//! type-info statement (`TYPEINFO_QUERY` `s0`).
//!
//! # Capability Handles & Type-State
//!
//! New code uses [`AppPool`] and typed capability handles:
//! - [`MailboxTx<ReadOnly>`] / [`MailboxTx<ReadWrite>`]
//! - [`UserTx<ReadOnly>`] / [`UserTx<ReadWrite>`]
//! - [`AdminReadTx<Standard>`]
//! - [`AdminSensitiveRead`] (audit-before-read single-call API: Tx 1 commits
//!   `audit_write(..., 'core')`, Tx 2 runs under real `BEGIN READ ONLY`)
//! - [`AdminWriteTx<Unaudited>`] → [`AdminWriteTx<Audited>`] (and 1-RTT
//!   [`AppPool::run_admin_write_pipelined`])
//! - `WorkerTx` (constructible only from feature-gated `WorkerPool`)
//!
//! Principal minting (`mint`) and `WorkerPool` (`worker-pool`) are Cargo
//! feature-gated and statically isolated from `crates/domains/*` by
//! `scripts/check-rust-family-isolation.py`.
//!
//! # Outcomes
//!
//! [`CommandOutcome`] is the lifecycle's terminal observation: `Committed`,
//! `RolledBack` (known not committed) or `Unknown { operation }`, which is
//! never success and maps to `recover(Unknown) = LookupUnderCurrentAuthority`.
//! A connection whose outcome is unknown is quarantined with a PgBouncer-safe
//! bounded `CancelRequest`, never pooled again.
#![forbid(unsafe_code)]

pub mod auth;
mod capability;
pub mod cert_monitor;
pub mod command;
pub mod executor;
pub mod listen_hub;
pub mod operator;
pub mod outcome;
pub mod pipeline;
pub mod pool;
pub mod statement;
pub mod workers;

pub use auth::MailboxAuthContext;
#[cfg(feature = "mint")]
pub use capability::mint;
pub use capability::{
    AdminReadTx, AdminSensitiveRead, AdminWriteTx, AppPool, AuditEvent, AuditEventError, Audited,
    MailboxTx, ReadOnly, ReadWrite, Standard, Unaudited, UserTx, VerifiedAdmin, VerifiedMailbox,
    VerifiedUser,
};
#[cfg(feature = "worker-pool")]
pub use capability::{WorkerPool, WorkerTx};
pub use command::{
    lookup_command, lookup_operation, operation_hex, run_command, run_locked_tx,
    run_receipted_command, run_receipted_command_capped, run_receipted_effect, OperationLookup,
    ReceiptCommand,
};
pub use executor::{
    ConfigError, Param, ProvenStatement, ScopedExecutor, ScopedTx, Timeouts, DEADLINE_ENV,
};
pub use listen_hub::{
    ListenEvent, ListenHub, ListenHubError, ListenNotification, ListenSubscription,
    DEFAULT_SUBSCRIBER_CAPACITY,
};
pub use outcome::{
    commit_failure_observation, CommandOutcome, FailureCode, Rejection, StatementFailure,
};
pub use pool::{
    pg_version_allows_prepared_rls, PgBouncerAttestation, PlanCacheHint, PreparedStatementMode,
    CANCEL_SEMAPHORE_PERMITS, DEFAULT_PREPARED_CACHE_CAP, MIN_PGBOUNCER_MAX_PREPARED,
    PGBOUNCER_PREPARED_HEADROOM,
};
pub use tokio_postgres::{types::Type, Row};

#[cfg(test)]
mod tests;
