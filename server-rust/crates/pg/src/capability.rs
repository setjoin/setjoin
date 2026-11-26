//! Compile-time type-state capability handles for Setjoin PostgreSQL access.
//!
//! Every handle in this module enforces:
//! - private fields (cannot be constructed outside `setjoin-pg`);
//! - sealed marker traits (`mod sealed`);
//! - `#[must_use]` on every transaction handle;
//! - zero `Deref`, `DerefMut`, `AsRef`, or `Borrow` to any inner `Client`,
//!   `Object`, or `Transaction`;
//! - `#[cfg(feature = "mint")]` gating on principal minting (`setjoin_pg::mint`);
//! - `#[cfg(feature = "worker-pool")]` gating on cross-tenant `WorkerPool`.
//!
//! # Compile-fail proofs
//!
//! ## `MailboxTx<ReadOnly>` has no mutating methods
//! ```compile_fail
//! use setjoin_pg::{MailboxTx, ReadOnly};
//! async fn mutate(tx: &mut MailboxTx<ReadOnly>) {
//!     let _ = tx.execute("DELETE FROM messages", &[]).await;
//! }
//! ```
//!
//! ## `MailboxTx<ReadOnly>` has no `execute_contract`
//! ```compile_fail
//! use setjoin_pg::{MailboxTx, ReadOnly, SqlContract};
//! async fn mutate_contract(tx: &mut MailboxTx<ReadOnly>, c: &'static SqlContract) {
//!     let _ = tx.execute_contract(c, &[]).await;
//! }
//! ```
//!
//! ## `AdminReadTx<Standard>` has no mutating methods
//! ```compile_fail
//! use setjoin_pg::{AdminReadTx, Standard};
//! async fn mutate(tx: &mut AdminReadTx<Standard>) {
//!     let _ = tx.execute("UPDATE users SET is_active = false", &[]).await;
//! }
//! ```
//!
//! ## Unaudited `AdminWriteTx<Unaudited>` cannot commit
//! ```compile_fail
//! use setjoin_pg::{AdminWriteTx, Unaudited};
//! async fn skip_audit(tx: AdminWriteTx<Unaudited>) {
//!     let _ = tx.commit().await;
//! }
//! ```
//!
//! ## `AdminSensitiveRead` cannot be constructed directly to bypass audit-before-read
//! ```compile_fail
//! use setjoin_pg::AdminSensitiveRead;
//! fn forge() -> AdminSensitiveRead {
//!     AdminSensitiveRead { }
//! }
//! ```
//!
//! ## No `Deref` or `AsRef` to raw `tokio_postgres::Client`
//! ```compile_fail
//! use setjoin_pg::{MailboxTx, ReadOnly};
//! fn escape(tx: &MailboxTx<ReadOnly>) -> &tokio_postgres::Client {
//!     tx.as_ref()
//! }
//! ```
//!
//! ```compile_fail
//! use setjoin_pg::{MailboxTx, ReadWrite};
//! fn escape_deref(tx: &MailboxTx<ReadWrite>) {
//!     let _c: &tokio_postgres::Client = &*tx;
//! }
//! ```
//!
//! ## `AuditEvent` cannot accept caller-supplied `ActorId` or `'routine'` tier
//! ```compile_fail
//! use setjoin_pg::AuditEvent;
//! fn forge_audit() {
//!     let _ = AuditEvent::new("user.delete", "user").unwrap().with_tier("routine");
//! }
//! ```
//!
//! ```compile_fail
//! use setjoin_pg::AuditEvent;
//! use setjoin_contracts::ids::ActorId;
//! fn forge_actor() {
//!     let _ = AuditEvent::new("user.delete", "user").unwrap().with_actor(ActorId::new(1).unwrap());
//! }
//! ```
//!
//! ## Private handle construction fails outside `setjoin-pg`
//! ```compile_fail
//! use setjoin_pg::VerifiedMailbox;
//! use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
//! fn forge_principal() {
//!     let _ = VerifiedMailbox {
//!         actor: ActorId::new(1).unwrap(),
//!         mailbox: MailboxId::new(1).unwrap(),
//!         generation: Generation(1),
//!     };
//! }
//! ```
//!
//! ```compile_fail
//! use setjoin_pg::WorkerTx;
//! fn forge_worker_tx() -> WorkerTx {
//!     WorkerTx { }
//! }
//! ```
//!
//! ## `AdminRollbackOnlyTx` (`AdminReducerOutcome::NoOp`) cannot commit
//! ```compile_fail
//! use setjoin_pg::AdminRollbackOnlyTx;
//! async fn commit_noop(tx: AdminRollbackOnlyTx) {
//!     let _ = tx.commit().await;
//! }
//! ```
//!
//! ## Branch-only reducer returning `NoOp` cannot commit without setting `app.core_audit_written`
//! ```compile_fail
//! use setjoin_pg::{AdminReducerOutcome, AdminWriteTx, SqlContract, Unaudited};
//! async fn commit_branch_only(tx: AdminWriteTx<Unaudited>, c: &'static SqlContract) {
//!     if let Ok(AdminReducerOutcome::NoOp { tx, .. }) =
//!         tx.execute_audited_reducer_contract(c, &[]).await
//!     {
//!         let _ = tx.commit().await;
//!     }
//! }
//! ```
//!
//! ## `PreAuthReadTx` has no mutating methods
//! ```compile_fail
//! use setjoin_pg::PreAuthReadTx;
//! async fn mutate_pre_auth(tx: &mut PreAuthReadTx) {
//!     let _ = tx.execute("UPDATE users SET enabled = false", &[]).await;
//! }
//! ```

use crate::{
    auth::AuditKeys,
    command::{operation_hex, OperationLookup, ReceiptCommand},
    executor::{ConfigError, Param, Timeouts},
    outcome::{commit_failure_observation, CommandOutcome, Rejection, StatementFailure},
    pipeline::{
        build_begin_sql, build_begin_sql_with_idle_timeout, execute_read_pipeline,
        execute_write_pipeline, pre_encode_params, EncodedStep, Preamble,
    },
    pool::{ManagedLease, PlanCacheHint, PreparedStatementMode, SetjoinPool},
    statement::{admit, admit_select},
};
use futures_util::TryStreamExt;
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::{CommandEnvelope, CommitObservation},
    ids::{ActorId, Generation, MailboxId, OperationId},
};
use setjoin_db::lifecycle::{
    accepted_contract, ConnectionDisposition, LifecycleError, Phase, RollbackObservation,
    TransactionLifecycle,
};
use setjoin_sql_catalog::{SqlAuditPosture, SqlContract, SqlScope};
use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tokio_postgres::{
    types::{ToSql, Type},
    Row,
};

/// Server-side `SET LOCAL idle_in_transaction_session_timeout` (8000ms) enforced
/// on effect transactions (`run_*_effect_write`) so stalled peripheral I/O
/// never leaks pooled connections (#546a).
pub const EFFECT_IDLE_IN_TX_TIMEOUT_MS: u32 = 8_000;

/// Tight client-side peripheral body timeout (`<= 5s`) enforced on effect
/// transactions before `COMMIT` (#546a).
pub const EFFECT_BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// Default bounded concurrency limit on simultaneous in-flight effect
/// transactions so slow S3 promotions cannot exhaust `AppPool` (#546a).
pub const DEFAULT_EFFECT_CONCURRENCY: usize = 16;

// ---------------------------------------------------------------------------
// Sealed type-state markers
// ---------------------------------------------------------------------------

mod sealed {
    pub trait TxMode {}
    pub trait AdminReadClass {}
    pub trait AuditState {}
}

/// Type-state marker for `BEGIN READ ONLY` transactions (zero mutating methods).
#[derive(Debug)]
pub struct ReadOnly {
    _private: (),
}

/// Type-state marker for `BEGIN READ WRITE` transactions.
#[derive(Debug)]
pub struct ReadWrite {
    _private: (),
}

impl sealed::TxMode for ReadOnly {}
impl sealed::TxMode for ReadWrite {}

/// Type-state marker for standard (non-sensitive) admin reads.
#[derive(Debug)]
pub struct Standard {
    _private: (),
}

impl sealed::AdminReadClass for Standard {}

/// Type-state marker for an admin write transaction before its required `core`
/// `audit_write` row has been executed in the transaction.
#[derive(Debug)]
pub struct Unaudited {
    _private: (),
}

/// Type-state marker for an admin write transaction after its verified `core`
/// `audit_write` row has succeeded in the transaction.
#[derive(Debug)]
pub struct Audited {
    _private: (),
}

impl sealed::AuditState for Unaudited {}
impl sealed::AuditState for Audited {}

// ---------------------------------------------------------------------------
// Verified principal tokens (constructible ONLY via `setjoin_pg::mint`)
// ---------------------------------------------------------------------------

/// Verified mailbox authority minted by `setjoin-authz` / composition root.
///
/// Supports delegated mailboxes where `actor != mailbox_owner`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMailbox {
    actor: ActorId,
    mailbox: MailboxId,
    generation: Generation,
}

impl VerifiedMailbox {
    pub const fn actor(&self) -> ActorId {
        self.actor
    }

    pub const fn mailbox(&self) -> MailboxId {
        self.mailbox
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn authority(&self) -> AuthorityKey {
        AuthorityKey {
            actor: self.actor,
            scope: ResourceScope::Mailbox(self.mailbox),
            generation: self.generation,
        }
    }
}

/// Verified mailbox-less user authority minted by `setjoin-authz` / composition root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUser {
    actor: ActorId,
    generation: Generation,
}

impl VerifiedUser {
    pub const fn actor(&self) -> ActorId {
        self.actor
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn authority(&self) -> AuthorityKey {
        AuthorityKey {
            actor: self.actor,
            scope: ResourceScope::User(self.actor),
            generation: self.generation,
        }
    }
}

/// Verified admin authority minted by `setjoin-authz` / composition root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmin {
    actor: ActorId,
    generation: Generation,
}

impl VerifiedAdmin {
    pub const fn actor(&self) -> ActorId {
        self.actor
    }

    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn authority(&self) -> AuthorityKey {
        AuthorityKey {
            actor: self.actor,
            scope: ResourceScope::User(self.actor),
            generation: self.generation,
        }
    }
}

/// Principal minting boundary. Gated behind the `mint` Cargo feature, which is
/// enabled ONLY on `setjoin-authz` and composition-root binaries.
#[cfg(feature = "mint")]
pub mod mint {
    use super::{VerifiedAdmin, VerifiedMailbox, VerifiedUser};
    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};

    /// Mint a verified mailbox principal from authenticated session / grant state.
    pub const fn mailbox(
        actor: ActorId,
        mailbox: MailboxId,
        generation: Generation,
    ) -> VerifiedMailbox {
        VerifiedMailbox {
            actor,
            mailbox,
            generation,
        }
    }

    /// Mint a verified mailbox-less user principal from authenticated session state.
    pub const fn user(actor: ActorId, generation: Generation) -> VerifiedUser {
        VerifiedUser { actor, generation }
    }

    /// Mint a verified admin principal after role/permission verification.
    pub const fn admin(actor: ActorId, generation: Generation) -> VerifiedAdmin {
        VerifiedAdmin { actor, generation }
    }
}

// ---------------------------------------------------------------------------
// Verified AuditEvent (p_actor from handle, p_tier pinned to 'core')
// ---------------------------------------------------------------------------

/// Validation error constructing an [`AuditEvent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEventError(pub &'static str);

impl std::fmt::Display for AuditEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for AuditEventError {}

/// Canonical admin audit event passed to `AdminWriteTx::record_audit`,
/// `AppPool::run_admin_write_pipelined`, and `AppPool::run_admin_sensitive_read`.
///
/// Security invariants:
/// - `p_actor` is **never** accepted here; the executor populates it exclusively
///   from the verified [`VerifiedAdmin::actor`] handle (R2).
/// - `p_tier` is **never** configurable; the executor pins `'core'` in SQL so
///   `audit_write.sql` never suppresses rows at `audit_policy.level = 'lean'`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    action: String,
    target_type: String,
    target_id: Option<i64>,
    before_json: Option<String>,
    after_json: Option<String>,
    ip: Option<String>,
    notes: Option<String>,
}

const AUDIT_WRITE_CORE_SQL: &str =
    "SELECT audit_write($1, $2, $3, $4, $5::text::jsonb, $6::text::jsonb, $7::text::inet, $8, 'core')";

const RECEIPT_INSERT_SQL: &str =
    "INSERT INTO public.rust_operation_receipts (operation_id, family, command) \
     VALUES ($1::text::uuid, $2, $3)";

impl AuditEvent {
    /// Construct a validated audit event with non-empty `action` and `target_type`.
    pub fn new(
        action: impl Into<String>,
        target_type: impl Into<String>,
    ) -> Result<Self, AuditEventError> {
        let action = action.into();
        let target_type = target_type.into();
        if action.trim().is_empty() {
            return Err(AuditEventError("audit action must not be empty"));
        }
        if target_type.trim().is_empty() {
            return Err(AuditEventError("audit target_type must not be empty"));
        }
        Ok(Self {
            action,
            target_type,
            target_id: None,
            before_json: None,
            after_json: None,
            ip: None,
            notes: None,
        })
    }

    pub fn with_target_id(mut self, target_id: i64) -> Self {
        self.target_id = Some(target_id);
        self
    }

    pub fn with_before_json(mut self, before_json: impl Into<String>) -> Self {
        self.before_json = Some(before_json.into());
        self
    }

    pub fn with_after_json(mut self, after_json: impl Into<String>) -> Self {
        self.after_json = Some(after_json.into());
        self
    }

    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn target_type(&self) -> &str {
        &self.target_type
    }

    fn to_step(&self, actor: ActorId) -> Result<EncodedStep, StatementFailure> {
        let actor_id = actor.get();
        EncodedStep::new_infrastructure(
            AUDIT_WRITE_CORE_SQL,
            &[
                (&actor_id, Type::INT8),
                (&self.action, Type::TEXT),
                (&self.target_type, Type::TEXT),
                (&self.target_id, Type::INT8),
                (&self.before_json, Type::TEXT),
                (&self.after_json, Type::TEXT),
                (&self.ip, Type::TEXT),
                (&self.notes, Type::TEXT),
            ],
        )
    }
}

fn receipt_step(
    operation: OperationId,
    receipt: ReceiptCommand,
) -> Result<EncodedStep, StatementFailure> {
    let op_hex = operation_hex(operation);
    EncodedStep::new_infrastructure(
        RECEIPT_INSERT_SQL,
        &[
            (&op_hex, Type::TEXT),
            (&receipt.family, Type::TEXT),
            (&receipt.command, Type::TEXT),
        ],
    )
}

// ---------------------------------------------------------------------------
// Internal helpers for interactive transactions
// ---------------------------------------------------------------------------

enum InteractiveStmtError {
    /// Refused locally (`admit` / `pre_encode_params`) before sending any bytes
    /// on the wire: the underlying connection remains healthy and open.
    Local(StatementFailure),
    /// Server `ErrorResponse` or transport/driver error from `tokio-postgres`.
    Driver(tokio_postgres::Error),
}

impl InteractiveStmtError {
    fn into_failure(self) -> StatementFailure {
        match self {
            Self::Local(f) => f,
            Self::Driver(e) => StatementFailure::from_db(&e),
        }
    }

    fn is_transport_loss(&self) -> bool {
        matches!(self, Self::Driver(e) if e.as_db_error().is_none())
    }
}

pub(crate) fn zip_contract_params<'a>(
    contract: &'static SqlContract,
    values: &[&'a (dyn ToSql + Sync)],
) -> Result<Vec<Param<'a>>, StatementFailure> {
    if values.len() != contract.params.len() {
        return Err(StatementFailure::refused(
            "contract parameter count mismatch",
        ));
    }
    Ok(values
        .iter()
        .copied()
        .zip(contract.params.iter().cloned())
        .collect())
}

pub(crate) fn check_contract_scope(
    contract: &'static SqlContract,
    allowed: &[SqlScope],
    err_msg: &'static str,
) -> Result<(), StatementFailure> {
    if allowed.contains(&contract.scope) {
        Ok(())
    } else {
        Err(StatementFailure::refused(err_msg))
    }
}

async fn run_interactive_statement(
    lease: &ManagedLease,
    sql: &str,
    params: &[Param<'_>],
    select_only: bool,
) -> Result<(Vec<Row>, u64), InteractiveStmtError> {
    if select_only {
        admit_select(sql)
            .map_err(StatementFailure::refused)
            .map_err(InteractiveStmtError::Local)?;
    } else {
        admit(sql)
            .map_err(StatementFailure::refused)
            .map_err(InteractiveStmtError::Local)?;
    }
    let encoded = pre_encode_params(params).map_err(InteractiveStmtError::Local)?;
    let typed: Vec<Param<'_>> = encoded.iter().map(|p| p.as_param()).collect();
    let stream = lease
        .client()
        .query_typed_raw(sql, typed)
        .await
        .map_err(InteractiveStmtError::Driver)?;
    futures_util::pin_mut!(stream);
    let mut rows = Vec::new();
    while let Some(row) = stream
        .try_next()
        .await
        .map_err(InteractiveStmtError::Driver)?
    {
        rows.push(row);
    }
    Ok((rows, stream.rows_affected().unwrap_or(0)))
}

/// Frozen-Go row-iteration read compatibility seam inside an open `BEGIN READ ONLY`
/// capability transaction: a failure before `RowDescription` returns `Err`; a
/// stream error after `RowDescription` retains rows already delivered.
async fn run_interactive_iterated(
    lease: &ManagedLease,
    sql: &str,
    params: &[Param<'_>],
) -> Result<Vec<Row>, StatementFailure> {
    admit_select(sql).map_err(StatementFailure::refused)?;
    let encoded = pre_encode_params(params)?;
    let typed: Vec<Param<'_>> = encoded.iter().map(|p| p.as_param()).collect();
    let stream = lease
        .client()
        .query_typed_raw(sql, typed)
        .await
        .map_err(|e| StatementFailure::from_db(&e))?;
    futures_util::pin_mut!(stream);
    let mut rows = Vec::new();
    while let Ok(Some(row)) = stream.try_next().await {
        rows.push(row);
    }
    Ok(rows)
}

async fn begin_read_only_with_retry(
    pool: &SetjoinPool,
    preamble: &Preamble,
) -> Result<ManagedLease, StatementFailure> {
    let preamble_step = preamble.to_step()?;
    let begin_sql = build_begin_sql(
        "BEGIN READ ONLY",
        pool.timeouts.statement,
        pool.plan_cache_hint,
    );
    let deadline = Instant::now() + pool.timeouts.statement * 2;

    for attempt in 0..2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(StatementFailure::refused("read timed out"));
        }
        let lease = pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        let client = lease.client();
        let begun = tokio::time::timeout(remaining, async {
            tokio::join!(
                biased;
                client.batch_execute(&begin_sql),
                preamble_step.execute(client),
            )
        })
        .await;
        let Ok((begin_res, preamble_res)) = begun else {
            return Err(StatementFailure::refused("read timed out"));
        };
        if let Err(e) = begin_res {
            if attempt == 0 && e.as_db_error().is_none() {
                lease.quarantine();
                continue;
            }
            lease.quarantine();
            return Err(StatementFailure::from_db(&e));
        }
        if let Err(e) = preamble_res {
            lease.quarantine();
            return Err(StatementFailure::from_db(&e));
        }
        return Ok(lease);
    }
    Err(StatementFailure::refused("pool unavailable"))
}

/// Begin an interactive `BEGIN READ WRITE` + merged preamble (1 RTT via
/// `tokio::join!(biased; ...)`) with stale-socket 1-retry strictly BEFORE any
/// business SQL is sent (never returning spurious `CommandOutcome::Unknown` on
/// a dead idle socket).
async fn begin_write_with_retry(
    pool: &SetjoinPool,
    preamble: &Preamble,
    deadline: Instant,
) -> Result<ManagedLease, Rejection<StatementFailure>> {
    begin_write_with_retry_opts(pool, preamble, deadline, None).await
}

async fn begin_write_with_retry_opts(
    pool: &SetjoinPool,
    preamble: &Preamble,
    deadline: Instant,
    idle_in_tx_ms: Option<u32>,
) -> Result<ManagedLease, Rejection<StatementFailure>> {
    let preamble_step = preamble.to_step().map_err(Rejection::Statement)?;

    for attempt in 0..2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Rejection::Authority(LifecycleError::DeadlineElapsed));
        }
        let lease = pool.get().await.map_err(|_| Rejection::Unavailable)?;
        let begin_sql = build_begin_sql_with_idle_timeout(
            "BEGIN READ WRITE",
            remaining,
            idle_in_tx_ms,
            pool.plan_cache_hint,
        );
        let client = lease.client();
        let begun = tokio::time::timeout(remaining, async {
            tokio::join!(
                biased;
                client.batch_execute(&begin_sql),
                preamble_step.execute(client),
            )
        })
        .await;
        match begun {
            Ok((Ok(()), Ok(_))) => return Ok(lease),
            Ok((Err(e), _)) if attempt == 0 && e.as_db_error().is_none() => {
                lease.quarantine();
                continue;
            }
            Ok((Err(_), _)) | Err(_) => {
                lease.quarantine();
                return Err(Rejection::Unavailable);
            }
            Ok((Ok(()), Err(e))) => {
                let failure = StatementFailure::from_db(&e);
                if e.as_db_error().is_some()
                    && matches!(lease.client().batch_execute("ROLLBACK").await, Ok(()))
                    && !lease.is_closed()
                {
                    lease.keep();
                } else {
                    lease.quarantine();
                }
                return Err(Rejection::Statement(failure));
            }
        }
    }
    Err(Rejection::Unavailable)
}

// ---------------------------------------------------------------------------
// Capability Transaction Handles (private fields, #[must_use], zero Deref/AsRef)
// ---------------------------------------------------------------------------

/// Mailbox-scoped transaction handle (`ReadOnly` or `ReadWrite`).
///
/// - `MailboxTx<ReadOnly>`: `BEGIN READ ONLY`, zero mutating methods, PG
///   enforces SQLSTATE `25006`.
/// - `MailboxTx<ReadWrite>`: `BEGIN READ WRITE`, lifecycle-tracked commit and
///   rollback.
#[must_use = "transaction handles must be finished/committed or rolled back"]
pub struct MailboxTx<M: sealed::TxMode> {
    lease: ManagedLease,
    principal: VerifiedMailbox,
    lifecycle: Option<TransactionLifecycle>,
    failure: Option<TxFailure>,
    _mode: PhantomData<M>,
}

#[derive(Debug)]
enum TxFailure {
    Statement(StatementFailure),
    Authority(LifecycleError),
    CommitRefused(String),
}

impl<M: sealed::TxMode> MailboxTx<M> {
    pub const fn mailbox(&self) -> MailboxId {
        self.principal.mailbox
    }

    pub const fn actor(&self) -> ActorId {
        self.principal.actor
    }
}

impl MailboxTx<ReadOnly> {
    /// Execute one admitted `SELECT` inside the `BEGIN READ ONLY` transaction.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        run_interactive_statement(&self.lease, sql, params, true)
            .await
            .map(|(rows, _)| rows)
            .map_err(InteractiveStmtError::into_failure)
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::MailboxReadOnly`]
    /// via unnamed `query_typed_raw`.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::MailboxReadOnly],
            "contract scope mismatch for MailboxTx<ReadOnly>",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::MailboxReadOnly`]
    /// with frozen-Go `Rows.Err`-ignored row-iteration semantics.
    pub async fn query_iterated_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::MailboxReadOnly],
            "contract scope mismatch for MailboxTx<ReadOnly>::query_iterated_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        run_interactive_iterated(&self.lease, contract.sql, &params).await
    }

    /// Close the read-only transaction cleanly and return the connection to the pool.
    pub async fn finish(self) -> Result<(), StatementFailure> {
        match self.lease.client().batch_execute("COMMIT").await {
            Ok(()) => {
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }
}

impl MailboxTx<ReadWrite> {
    /// Execute one admitted statement and return its rows.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.run_rw_stmt(sql, params).await.map(|(rows, _)| rows)
    }

    /// Execute one admitted statement and return its affected-row count.
    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<u64, StatementFailure> {
        self.run_rw_stmt(sql, params).await.map(|(_, n)| n)
    }

    /// Execute a static [`SqlContract`] scoped to mailbox reads or writes and
    /// return its rows via unnamed `query_typed_raw`.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::MailboxReadOnly, SqlScope::MailboxReadWrite],
            "contract scope mismatch for MailboxTx<ReadWrite>",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::MailboxReadWrite`]
    /// and return its affected-row count via unnamed `query_typed_raw`.
    pub async fn execute_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::MailboxReadWrite],
            "contract scope mismatch for MailboxTx<ReadWrite>::execute_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.execute(contract.sql, &params).await
    }

    /// Acquire `#481` canonical parent row locks (`users FOR KEY SHARE` ->
    /// `mailboxes FOR UPDATE`) strictly after the transaction preamble's
    /// advisory lock (`setjoin-command:...`) and before locking child
    /// collections/items (`messages`, `calendars`, `tasks`, `rules`).
    pub async fn prelock_mailbox_hierarchy(&mut self) -> Result<(), StatementFailure> {
        let mailbox_id = self.principal.mailbox.get();
        let _ = self
            .run_rw_stmt(
                "SELECT u.id FROM public.users u \
                  JOIN public.mailboxes m ON m.user_id = u.id \
                 WHERE m.id = $1 FOR KEY SHARE OF u",
                &[(&mailbox_id, Type::INT8)],
            )
            .await?;
        let _ = self
            .run_rw_stmt(
                "SELECT id FROM public.mailboxes WHERE id = $1 FOR UPDATE",
                &[(&mailbox_id, Type::INT8)],
            )
            .await?;
        Ok(())
    }

    async fn run_rw_stmt(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<(Vec<Row>, u64), StatementFailure> {
        if let Some(prior) = &self.failure {
            return Err(match prior {
                TxFailure::Statement(f) => f.clone(),
                TxFailure::Authority(_) | TxFailure::CommitRefused(_) => {
                    StatementFailure::refused("authority check failed")
                }
            });
        }
        if let Some(lc) = self.lifecycle.as_mut() {
            if let Err(e) = lc.check_current_key(self.principal.authority(), Instant::now()) {
                self.failure = Some(TxFailure::Authority(e));
                return Err(StatementFailure::refused("authority check failed"));
            }
        }
        match run_interactive_statement(&self.lease, sql, params, false).await {
            Ok(v) => Ok(v),
            Err(err) => {
                if err.is_transport_loss() || self.lease.is_closed() {
                    if let Some(lc) = self.lifecycle.as_mut() {
                        lc.connection_lost();
                    }
                }
                let f = err.into_failure();
                if self.failure.is_none() {
                    self.failure = Some(TxFailure::Statement(f.clone()));
                }
                Err(f)
            }
        }
    }

    async fn finish_rw<T, E>(
        mut self,
        result: Option<Result<T, E>>,
        operation: OperationId,
    ) -> CommandOutcome<T, E> {
        let mut lc = self.lifecycle.take().expect("rw lifecycle present");
        let mut outcome_value = None;
        let mut body_error = None;
        match result {
            Some(Ok(v)) => outcome_value = Some(v),
            Some(Err(e)) => body_error = Some(e),
            None => {}
        }

        if matches!(lc.phase(), Phase::Active) && self.failure.is_none() && outcome_value.is_some()
        {
            match lc.request_commit(self.principal.authority(), Instant::now()) {
                Ok(()) => {
                    let obs = match self.lease.client().batch_execute("COMMIT").await {
                        Ok(()) => CommitObservation::Committed,
                        Err(e) => {
                            let code = e.code().map(|c| c.code().to_owned());
                            let obs = commit_failure_observation(code.as_deref());
                            if let (CommitObservation::RolledBack, Some(code)) = (obs, code) {
                                self.failure = Some(TxFailure::CommitRefused(code));
                            }
                            obs
                        }
                    };
                    let _ = lc.observe_commit(obs);
                }
                Err(e) => {
                    if self.failure.is_none() {
                        self.failure = Some(TxFailure::Authority(e));
                    }
                }
            }
        }

        if matches!(lc.phase(), Phase::Active | Phase::RollbackPending) {
            let _ = lc.request_rollback();
            let obs = match self.lease.client().batch_execute("ROLLBACK").await {
                Ok(()) => RollbackObservation::Acknowledged,
                Err(_) => RollbackObservation::Unknown,
            };
            let _ = lc.observe_rollback(obs);
        }

        let disp = lc.connection_disposition();
        if disp == ConnectionDisposition::VerifyDriverReset && !self.lease.is_closed() {
            self.lease.keep();
        } else {
            self.lease.quarantine();
        }

        match lc.phase() {
            Phase::Terminal(CommitObservation::Committed) => match outcome_value {
                Some(v) => CommandOutcome::Committed(v),
                None => CommandOutcome::Unknown { operation },
            },
            Phase::Terminal(CommitObservation::RolledBack) => {
                CommandOutcome::RolledBack(match (self.failure, body_error) {
                    (Some(TxFailure::Statement(f)), _) => Rejection::Statement(f),
                    (Some(TxFailure::CommitRefused(c)), _) => Rejection::CommitRefused(c),
                    (Some(TxFailure::Authority(e)), _) => Rejection::Authority(e),
                    (None, Some(e)) => Rejection::Body(e),
                    (None, None) => Rejection::Unavailable,
                })
            }
            _ => CommandOutcome::Unknown { operation },
        }
    }
}

/// Mailbox-less user-scoped transaction handle (`ReadOnly` or `ReadWrite`).
///
/// Installs `app.current_mailbox_id = ''` and `app.current_user_id = actor`.
#[must_use = "transaction handles must be finished/committed or rolled back"]
pub struct UserTx<M: sealed::TxMode> {
    lease: ManagedLease,
    principal: VerifiedUser,
    lifecycle: Option<TransactionLifecycle>,
    failure: Option<TxFailure>,
    _mode: PhantomData<M>,
}

impl<M: sealed::TxMode> UserTx<M> {
    pub const fn actor(&self) -> ActorId {
        self.principal.actor
    }
}

impl UserTx<ReadOnly> {
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        run_interactive_statement(&self.lease, sql, params, true)
            .await
            .map(|(rows, _)| rows)
            .map_err(InteractiveStmtError::into_failure)
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::UserScoped`]
    /// inside this `BEGIN READ ONLY` user transaction.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::UserScoped],
            "contract scope mismatch for UserTx<ReadOnly>",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::UserScoped`]
    /// with frozen-Go `Rows.Err`-ignored row-iteration semantics.
    pub async fn query_iterated_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::UserScoped],
            "contract scope mismatch for UserTx<ReadOnly>::query_iterated_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        run_interactive_iterated(&self.lease, contract.sql, &params).await
    }

    pub async fn finish(self) -> Result<(), StatementFailure> {
        match self.lease.client().batch_execute("COMMIT").await {
            Ok(()) => {
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }
}

impl UserTx<ReadWrite> {
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.run_rw_stmt(sql, params).await.map(|(rows, _)| rows)
    }

    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<u64, StatementFailure> {
        self.run_rw_stmt(sql, params).await.map(|(_, n)| n)
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::UserScoped`] and
    /// return its rows via unnamed `query_typed_raw`.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::UserScoped],
            "contract scope mismatch for UserTx<ReadWrite>",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::UserScoped`] and
    /// return its affected-row count via unnamed `query_typed_raw`.
    pub async fn execute_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::UserScoped],
            "contract scope mismatch for UserTx<ReadWrite>::execute_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.execute(contract.sql, &params).await
    }

    async fn run_rw_stmt(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<(Vec<Row>, u64), StatementFailure> {
        if let Some(prior) = &self.failure {
            return Err(match prior {
                TxFailure::Statement(f) => f.clone(),
                TxFailure::Authority(_) | TxFailure::CommitRefused(_) => {
                    StatementFailure::refused("authority check failed")
                }
            });
        }
        if let Some(lc) = self.lifecycle.as_mut() {
            if let Err(e) = lc.check_current_key(self.principal.authority(), Instant::now()) {
                self.failure = Some(TxFailure::Authority(e));
                return Err(StatementFailure::refused("authority check failed"));
            }
        }
        match run_interactive_statement(&self.lease, sql, params, false).await {
            Ok(v) => Ok(v),
            Err(err) => {
                if err.is_transport_loss() || self.lease.is_closed() {
                    if let Some(lc) = self.lifecycle.as_mut() {
                        lc.connection_lost();
                    }
                }
                let f = err.into_failure();
                if self.failure.is_none() {
                    self.failure = Some(TxFailure::Statement(f.clone()));
                }
                Err(f)
            }
        }
    }

    async fn finish_rw<T, E>(
        mut self,
        result: Option<Result<T, E>>,
        operation: OperationId,
    ) -> CommandOutcome<T, E> {
        let mut lc = self.lifecycle.take().expect("rw lifecycle present");
        let mut outcome_value = None;
        let mut body_error = None;
        match result {
            Some(Ok(v)) => outcome_value = Some(v),
            Some(Err(e)) => body_error = Some(e),
            None => {}
        }

        if matches!(lc.phase(), Phase::Active) && self.failure.is_none() && outcome_value.is_some()
        {
            match lc.request_commit(self.principal.authority(), Instant::now()) {
                Ok(()) => {
                    let obs = match self.lease.client().batch_execute("COMMIT").await {
                        Ok(()) => CommitObservation::Committed,
                        Err(e) => {
                            let code = e.code().map(|c| c.code().to_owned());
                            let obs = commit_failure_observation(code.as_deref());
                            if let (CommitObservation::RolledBack, Some(code)) = (obs, code) {
                                self.failure = Some(TxFailure::CommitRefused(code));
                            }
                            obs
                        }
                    };
                    let _ = lc.observe_commit(obs);
                }
                Err(e) => {
                    if self.failure.is_none() {
                        self.failure = Some(TxFailure::Authority(e));
                    }
                }
            }
        }

        if matches!(lc.phase(), Phase::Active | Phase::RollbackPending) {
            let _ = lc.request_rollback();
            let obs = match self.lease.client().batch_execute("ROLLBACK").await {
                Ok(()) => RollbackObservation::Acknowledged,
                Err(_) => RollbackObservation::Unknown,
            };
            let _ = lc.observe_rollback(obs);
        }

        let disp = lc.connection_disposition();
        if disp == ConnectionDisposition::VerifyDriverReset && !self.lease.is_closed() {
            self.lease.keep();
        } else {
            self.lease.quarantine();
        }

        match lc.phase() {
            Phase::Terminal(CommitObservation::Committed) => match outcome_value {
                Some(v) => CommandOutcome::Committed(v),
                None => CommandOutcome::Unknown { operation },
            },
            Phase::Terminal(CommitObservation::RolledBack) => {
                CommandOutcome::RolledBack(match (self.failure, body_error) {
                    (Some(TxFailure::Statement(f)), _) => Rejection::Statement(f),
                    (Some(TxFailure::CommitRefused(c)), _) => Rejection::CommitRefused(c),
                    (Some(TxFailure::Authority(e)), _) => Rejection::Authority(e),
                    (None, Some(e)) => Rejection::Body(e),
                    (None, None) => Rejection::Unavailable,
                })
            }
            _ => CommandOutcome::Unknown { operation },
        }
    }
}

/// Standard (non-sensitive) admin read transaction handle (`BEGIN READ ONLY`).
///
/// Zero mutating methods; PG enforces SQLSTATE `25006`.
#[must_use = "transaction handles must be finished"]
pub struct AdminReadTx<C: sealed::AdminReadClass> {
    lease: ManagedLease,
    principal: VerifiedAdmin,
    _class: PhantomData<C>,
}

impl<C: sealed::AdminReadClass> AdminReadTx<C> {
    pub const fn actor(&self) -> ActorId {
        self.principal.actor
    }
}

impl AdminReadTx<Standard> {
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        run_interactive_statement(&self.lease, sql, params, true)
            .await
            .map(|(rows, _)| rows)
            .map_err(InteractiveStmtError::into_failure)
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::AdminRead`]
    /// inside this `BEGIN READ ONLY` admin transaction.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AdminRead],
            "contract scope mismatch for AdminReadTx<Standard>",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::AdminRead`]
    /// with frozen-Go `Rows.Err`-ignored row-iteration semantics.
    pub async fn query_iterated_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AdminRead],
            "contract scope mismatch for AdminReadTx<Standard>::query_iterated_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        run_interactive_iterated(&self.lease, contract.sql, &params).await
    }

    pub async fn finish(self) -> Result<(), StatementFailure> {
        match self.lease.client().batch_execute("COMMIT").await {
            Ok(()) => {
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }
}

/// Sensitive admin read handle granted **only** after Tx 1 has durably
/// committed `audit_write(verified_actor, ..., 'core')`.
///
/// Runs inside Tx 2 under real PostgreSQL `BEGIN READ ONLY` (enforcing
/// `25006` defense-in-depth against `SELECT volatile_fn()`, `FOR UPDATE`, and
/// `nextval()`). Cannot be constructed directly outside `AppPool`.
#[must_use = "sensitive read handles execute inside an audited READ ONLY transaction"]
pub struct AdminSensitiveRead {
    lease: ManagedLease,
    principal: VerifiedAdmin,
}

impl AdminSensitiveRead {
    pub const fn actor(&self) -> ActorId {
        self.principal.actor
    }

    /// Execute one admitted `SELECT` inside the `BEGIN READ ONLY` transaction.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        run_interactive_statement(&self.lease, sql, params, true)
            .await
            .map(|(rows, _)| rows)
            .map_err(InteractiveStmtError::into_failure)
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::AdminRead`]
    /// inside this audited `BEGIN READ ONLY` transaction.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AdminRead],
            "contract scope mismatch for AdminSensitiveRead",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::AdminRead`]
    /// with frozen-Go `Rows.Err`-ignored row-iteration semantics.
    pub async fn query_iterated_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AdminRead],
            "contract scope mismatch for AdminSensitiveRead::query_iterated_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        run_interactive_iterated(&self.lease, contract.sql, &params).await
    }
}

/// Admin write transaction handle with compile-time audit enforcement:
/// `AdminWriteTx<Unaudited>` has **no** `.commit()` method and must call
/// [`AdminWriteTx::record_audit`] to transition to `AdminWriteTx<Audited>`.
#[must_use = "admin write transactions must be audited and committed or rolled back"]
pub struct AdminWriteTx<A: sealed::AuditState> {
    lease: ManagedLease,
    principal: VerifiedAdmin,
    lifecycle: TransactionLifecycle,
    operation: OperationId,
    failure: Option<TxFailure>,
    _audit: PhantomData<A>,
}

impl<A: sealed::AuditState> AdminWriteTx<A> {
    pub const fn actor(&self) -> ActorId {
        self.principal.actor
    }

    /// Execute one admitted statement and return its rows.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.run_stmt(sql, params).await.map(|(rows, _)| rows)
    }

    /// Execute one admitted statement and return its affected-row count.
    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<u64, StatementFailure> {
        self.run_stmt(sql, params).await.map(|(_, n)| n)
    }

    /// Execute a static [`SqlContract`] scoped to admin reads or writes and
    /// return its rows via unnamed `query_typed_raw`.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AdminRead, SqlScope::AdminWrite],
            "contract scope mismatch for AdminWriteTx",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::AdminWrite`] and
    /// return its affected-row count via unnamed `query_typed_raw`.
    pub async fn execute_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AdminWrite],
            "contract scope mismatch for AdminWriteTx::execute_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.execute(contract.sql, &params).await
    }

    async fn run_stmt(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<(Vec<Row>, u64), StatementFailure> {
        if let Some(prior) = &self.failure {
            return Err(match prior {
                TxFailure::Statement(f) => f.clone(),
                TxFailure::Authority(_) | TxFailure::CommitRefused(_) => {
                    StatementFailure::refused("authority check failed")
                }
            });
        }
        if let Err(e) = self
            .lifecycle
            .check_current_key(self.principal.authority(), Instant::now())
        {
            self.failure = Some(TxFailure::Authority(e));
            return Err(StatementFailure::refused("authority check failed"));
        }
        match run_interactive_statement(&self.lease, sql, params, false).await {
            Ok(v) => Ok(v),
            Err(err) => {
                if err.is_transport_loss() || self.lease.is_closed() {
                    self.lifecycle.connection_lost();
                }
                let f = err.into_failure();
                if self.failure.is_none() {
                    self.failure = Some(TxFailure::Statement(f.clone()));
                }
                Err(f)
            }
        }
    }

    /// Explicitly roll back this admin write transaction.
    pub async fn rollback(mut self) -> Result<(), StatementFailure> {
        let _ = self.lifecycle.request_rollback();
        match self.lease.client().batch_execute("ROLLBACK").await {
            Ok(()) => {
                let _ = self
                    .lifecycle
                    .observe_rollback(RollbackObservation::Acknowledged);
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                let _ = self
                    .lifecycle
                    .observe_rollback(RollbackObservation::Unknown);
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }
}

/// Rollback-only admin transaction returned when a
/// [`SqlAuditPosture::ReducerWritesCoreAudit`] reducer completed without
/// setting PostgreSQL's `app.core_audit_written = '1'` proof (for example, an
/// early `404`/`409` return).
///
/// Intentionally exposes **no** `.commit()` method and no query/execute
/// methods so unaudited branches can never commit (#546a).
#[must_use = "rollback-only admin transactions must be rolled back"]
pub struct AdminRollbackOnlyTx {
    lease: ManagedLease,
    principal: VerifiedAdmin,
    lifecycle: TransactionLifecycle,
}

impl AdminRollbackOnlyTx {
    pub const fn actor(&self) -> ActorId {
        self.principal.actor
    }

    /// Explicitly roll back this unaudited admin transaction.
    pub async fn rollback(mut self) -> Result<(), StatementFailure> {
        let _ = self.lifecycle.request_rollback();
        match self.lease.client().batch_execute("ROLLBACK").await {
            Ok(()) => {
                let _ = self
                    .lifecycle
                    .observe_rollback(RollbackObservation::Acknowledged);
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                let _ = self
                    .lifecycle
                    .observe_rollback(RollbackObservation::Unknown);
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }
}

/// Outcome of [`AdminWriteTx::execute_audited_reducer_contract`] (#546a).
#[must_use = "admin reducer outcomes must be committed or rolled back"]
pub enum AdminReducerOutcome {
    /// PostgreSQL's `audit_write(..., 'core')` succeeded in this exact
    /// transaction (`current_setting('app.core_audit_written', true) = '1'`),
    /// advancing the handle to `AdminWriteTx<Audited>` with zero double-audit.
    Audited {
        tx: AdminWriteTx<Audited>,
        rows: Vec<Row>,
    },
    /// The reducer returned without writing a `'core'` audit row (e.g. an early
    /// `404`/`409` no-op). The enclosed [`AdminRollbackOnlyTx`] cannot commit.
    NoOp {
        tx: AdminRollbackOnlyTx,
        rows: Vec<Row>,
    },
}

const RESET_CORE_AUDIT_WRITTEN_SQL: &str = "SELECT set_config('app.core_audit_written', '', true)";
const CHECK_CORE_AUDIT_WRITTEN_SQL: &str =
    "SELECT COALESCE(current_setting('app.core_audit_written', true), '') = '1'";

impl AdminWriteTx<Unaudited> {
    /// Execute `audit_write(verified_actor, ..., 'core')` in the same
    /// transaction and advance the type-state to `AdminWriteTx<Audited>`.
    pub async fn record_audit(
        mut self,
        event: &AuditEvent,
    ) -> Result<AdminWriteTx<Audited>, StatementFailure> {
        if let Some(prior) = &self.failure {
            let err = match prior {
                TxFailure::Statement(f) => f.clone(),
                TxFailure::Authority(_) | TxFailure::CommitRefused(_) => {
                    StatementFailure::refused("authority check failed")
                }
            };
            let _ = self.rollback().await;
            return Err(err);
        }
        if let Err(e) = self
            .lifecycle
            .check_current_key(self.principal.authority(), Instant::now())
        {
            self.failure = Some(TxFailure::Authority(e));
            let _ = self.rollback().await;
            return Err(StatementFailure::refused("authority check failed"));
        }
        let step = match event.to_step(self.principal.actor) {
            Ok(s) => s,
            Err(e) => {
                let _ = self.rollback().await;
                return Err(e);
            }
        };
        if let Err(e) = step.execute(self.lease.client()).await {
            let f = StatementFailure::from_db(&e);
            if e.as_db_error().is_none() || self.lease.is_closed() {
                self.lifecycle.connection_lost();
                self.lease.quarantine();
            } else {
                let _ = self.rollback().await;
            }
            return Err(f);
        }
        Ok(AdminWriteTx {
            lease: self.lease,
            principal: self.principal,
            lifecycle: self.lifecycle,
            operation: self.operation,
            failure: self.failure,
            _audit: PhantomData,
        })
    }

    /// Execute a [`SqlAuditPosture::ReducerWritesCoreAudit`] admin reducer
    /// contract inside this transaction without double-auditing (#546a):
    ///
    /// 1. Verifies `contract.scope == SqlScope::AdminWrite`,
    ///    `contract.audit == SqlAuditPosture::ReducerWritesCoreAudit`, and
    ///    `contract.params[0] == Type::INT8`.
    /// 2. Binds `$1` (`p_actor`) strictly from `self.principal.actor` (R2 —
    ///    callers pass only `$2..$N` in `rest_values`).
    /// 3. Resets `app.core_audit_written` to `''` before invocation, invokes
    ///    `contract.sql`, and verifies `current_setting('app.core_audit_written', true) = '1'`
    ///    in the same transaction:
    ///    - `'1'` -> returns [`AdminReducerOutcome::Audited`] (`AdminWriteTx<Audited>`).
    ///    - anything else -> returns rollback-only [`AdminReducerOutcome::NoOp`]
    ///      ([`AdminRollbackOnlyTx`], which exposes no `.commit()`).
    pub async fn execute_audited_reducer_contract(
        mut self,
        contract: &'static SqlContract,
        rest_values: &[&(dyn ToSql + Sync)],
    ) -> Result<AdminReducerOutcome, StatementFailure> {
        if contract.scope != SqlScope::AdminWrite {
            let _ = self.rollback().await;
            return Err(StatementFailure::refused(
                "contract scope mismatch for AdminWriteTx::execute_audited_reducer_contract",
            ));
        }
        if contract.audit != SqlAuditPosture::ReducerWritesCoreAudit {
            let _ = self.rollback().await;
            return Err(StatementFailure::refused(
                "contract must declare SqlAuditPosture::ReducerWritesCoreAudit",
            ));
        }
        if contract.params.first() != Some(&Type::INT8) {
            let _ = self.rollback().await;
            return Err(StatementFailure::refused(
                "audited reducer contract must bind INT8 p_actor as $1",
            ));
        }
        if rest_values.len() + 1 != contract.params.len() {
            let _ = self.rollback().await;
            return Err(StatementFailure::refused(
                "contract parameter count mismatch (p_actor is bound automatically as $1)",
            ));
        }
        if let Some(prior) = &self.failure {
            let err = match prior {
                TxFailure::Statement(f) => f.clone(),
                TxFailure::Authority(_) | TxFailure::CommitRefused(_) => {
                    StatementFailure::refused("authority check failed")
                }
            };
            let _ = self.rollback().await;
            return Err(err);
        }
        if let Err(e) = self
            .lifecycle
            .check_current_key(self.principal.authority(), Instant::now())
        {
            self.failure = Some(TxFailure::Authority(e));
            let _ = self.rollback().await;
            return Err(StatementFailure::refused("authority check failed"));
        }

        // Reset app.core_audit_written locally before running the reducer so
        // no prior statement in this tx can spoof core-audit completion.
        if let Err(e) = self
            .lease
            .client()
            .query_typed(RESET_CORE_AUDIT_WRITTEN_SQL, &[])
            .await
        {
            let f = StatementFailure::from_db(&e);
            if e.as_db_error().is_none() || self.lease.is_closed() {
                self.lifecycle.connection_lost();
                self.lease.quarantine();
            } else {
                let _ = self.rollback().await;
            }
            return Err(f);
        }

        // Bind p_actor ($1) exclusively from verified principal (R2).
        let actor_id = self.principal.actor.get();
        let mut params: Vec<Param<'_>> = Vec::with_capacity(contract.params.len());
        params.push((&actor_id, Type::INT8));
        for (val, ty) in rest_values.iter().copied().zip(contract.params[1..].iter()) {
            params.push((val, ty.clone()));
        }

        let rows = match run_interactive_statement(&self.lease, contract.sql, &params, false).await
        {
            Ok((rows, _)) => rows,
            Err(err) => {
                let transport_loss = err.is_transport_loss() || self.lease.is_closed();
                let f = err.into_failure();
                if transport_loss {
                    self.lifecycle.connection_lost();
                    self.lease.quarantine();
                } else {
                    let _ = self.rollback().await;
                }
                return Err(f);
            }
        };

        // Check PostgreSQL's unforgeable transaction-local core-audit flag.
        let check_rows = match self
            .lease
            .client()
            .query_typed(CHECK_CORE_AUDIT_WRITTEN_SQL, &[])
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let f = StatementFailure::from_db(&e);
                if e.as_db_error().is_none() || self.lease.is_closed() {
                    self.lifecycle.connection_lost();
                    self.lease.quarantine();
                } else {
                    let _ = self.rollback().await;
                }
                return Err(f);
            }
        };

        let core_audit_written = check_rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false);

        if core_audit_written {
            Ok(AdminReducerOutcome::Audited {
                tx: AdminWriteTx {
                    lease: self.lease,
                    principal: self.principal,
                    lifecycle: self.lifecycle,
                    operation: self.operation,
                    failure: self.failure,
                    _audit: PhantomData,
                },
                rows,
            })
        } else {
            Ok(AdminReducerOutcome::NoOp {
                tx: AdminRollbackOnlyTx {
                    lease: self.lease,
                    principal: self.principal,
                    lifecycle: self.lifecycle,
                },
                rows,
            })
        }
    }
}

impl AdminWriteTx<Audited> {
    /// Commit the audited admin write transaction.
    pub async fn commit(mut self) -> CommandOutcome<(), StatementFailure> {
        let operation = self.operation;
        if matches!(self.lifecycle.phase(), Phase::Active) && self.failure.is_none() {
            match self
                .lifecycle
                .request_commit(self.principal.authority(), Instant::now())
            {
                Ok(()) => {
                    let obs = match self.lease.client().batch_execute("COMMIT").await {
                        Ok(()) => CommitObservation::Committed,
                        Err(e) => {
                            let code = e.code().map(|c| c.code().to_owned());
                            let obs = commit_failure_observation(code.as_deref());
                            if let (CommitObservation::RolledBack, Some(code)) = (obs, code) {
                                self.failure = Some(TxFailure::CommitRefused(code));
                            }
                            obs
                        }
                    };
                    let _ = self.lifecycle.observe_commit(obs);
                }
                Err(e) => {
                    if self.failure.is_none() {
                        self.failure = Some(TxFailure::Authority(e));
                    }
                }
            }
        }

        if matches!(
            self.lifecycle.phase(),
            Phase::Active | Phase::RollbackPending
        ) {
            let _ = self.lifecycle.request_rollback();
            let obs = match self.lease.client().batch_execute("ROLLBACK").await {
                Ok(()) => RollbackObservation::Acknowledged,
                Err(_) => RollbackObservation::Unknown,
            };
            let _ = self.lifecycle.observe_rollback(obs);
        }

        let disp = self.lifecycle.connection_disposition();
        if disp == ConnectionDisposition::VerifyDriverReset && !self.lease.is_closed() {
            self.lease.keep();
        } else {
            self.lease.quarantine();
        }

        match self.lifecycle.phase() {
            Phase::Terminal(CommitObservation::Committed) => CommandOutcome::Committed(()),
            Phase::Terminal(CommitObservation::RolledBack) => {
                CommandOutcome::RolledBack(match self.failure {
                    Some(TxFailure::Statement(f)) => Rejection::Statement(f),
                    Some(TxFailure::CommitRefused(c)) => Rejection::CommitRefused(c),
                    Some(TxFailure::Authority(e)) => Rejection::Authority(e),
                    None => Rejection::Unavailable,
                })
            }
            _ => CommandOutcome::Unknown { operation },
        }
    }
}

/// Cross-tenant worker transaction (`DB_WORKER_DSN` / `setjoin_worker`,
/// `BYPASSRLS`), constructible **only** from [`WorkerPool`] (feature
/// `worker-pool`).
#[cfg(feature = "worker-pool")]
#[must_use = "worker transactions must be committed or rolled back"]
pub struct WorkerTx {
    lease: ManagedLease,
    read_only: bool,
}

#[cfg(feature = "worker-pool")]
impl WorkerTx {
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        run_interactive_statement(&self.lease, sql, params, self.read_only)
            .await
            .map(|(rows, _)| rows)
            .map_err(InteractiveStmtError::into_failure)
    }

    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<u64, StatementFailure> {
        if self.read_only {
            return Err(StatementFailure::refused(
                "worker read-only transaction refuses execute",
            ));
        }
        run_interactive_statement(&self.lease, sql, params, false)
            .await
            .map(|(_, n)| n)
            .map_err(InteractiveStmtError::into_failure)
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::WorkerBypass`]
    /// and return its rows via unnamed `query_typed_raw`.
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::WorkerBypass],
            "contract scope mismatch for WorkerTx",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Execute a static [`SqlContract`] scoped to [`SqlScope::WorkerBypass`]
    /// and return its affected-row count via unnamed `query_typed_raw`.
    pub async fn execute_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::WorkerBypass],
            "contract scope mismatch for WorkerTx::execute_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.execute(contract.sql, &params).await
    }

    pub async fn commit(self) -> Result<(), StatementFailure> {
        match self.lease.client().batch_execute("COMMIT").await {
            Ok(()) => {
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }

    pub async fn rollback(self) -> Result<(), StatementFailure> {
        match self.lease.client().batch_execute("ROLLBACK").await {
            Ok(()) => {
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AppPool (DB_DSN / setjoin_app, NOBYPASSRLS)
// ---------------------------------------------------------------------------

/// Composition-root application pool (`DB_DSN` / `setjoin_app`, `NOBYPASSRLS`)
/// configured with `RecyclingMethod::Fast`, TCP keepalives, and optional
/// opt-in guarded prepared-statement caching.
///
/// Banned in `crates/domains/*` by `scripts/check-rust-family-isolation.py`.
#[derive(Clone)]
pub struct AppPool {
    pool: SetjoinPool,
    audit_keys: Option<Arc<AuditKeys>>,
    effect_sem: Arc<Semaphore>,
}

impl AppPool {
    /// Build an `AppPool` with [`Timeouts::resolved`] and unnamed statements.
    pub fn from_dsn(dsn: &str, max_size: usize) -> Result<Self, ConfigError> {
        Self::from_dsn_with(dsn, max_size, Timeouts::resolved())
    }

    /// Build an `AppPool` with explicit [`Timeouts`] and unnamed statements.
    pub fn from_dsn_with(
        dsn: &str,
        max_size: usize,
        timeouts: Timeouts,
    ) -> Result<Self, ConfigError> {
        Self::from_dsn_configured(
            dsn,
            max_size,
            timeouts,
            PreparedStatementMode::Unnamed,
            PlanCacheHint::Auto,
        )
    }

    /// Build an `AppPool` with explicit prepared-statement mode and plan-cache hint.
    pub fn from_dsn_configured(
        dsn: &str,
        max_size: usize,
        timeouts: Timeouts,
        prepared_mode: PreparedStatementMode,
        plan_cache_hint: PlanCacheHint,
    ) -> Result<Self, ConfigError> {
        let pool =
            SetjoinPool::from_dsn_with(dsn, max_size, timeouts, prepared_mode, plan_cache_hint)?;
        Ok(Self {
            pool,
            audit_keys: None,
            effect_sem: Arc::new(Semaphore::new(DEFAULT_EFFECT_CONCURRENCY)),
        })
    }

    /// Override the bounded concurrency semaphore governing simultaneous
    /// effect transactions (`run_*_effect_write`) so slow peripheral I/O
    /// cannot exhaust `AppPool` (#546a).
    pub fn with_effect_concurrency(mut self, max_concurrent: usize) -> Self {
        self.effect_sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
        self
    }

    /// Attach trusted deployment encryption/audit GUC keys (`DB_ENCRYPTION_KEY`,
    /// `AUDIT_HMAC_KEY`).
    pub fn with_audit_keys(mut self, encryption_key: String, audit_hmac_key: String) -> Self {
        self.audit_keys = Some(Arc::new(AuditKeys {
            encryption: encryption_key,
            audit_hmac: audit_hmac_key,
        }));
        self
    }

    /// Return a clone with an updated [`PlanCacheHint`].
    pub fn with_plan_cache_hint(mut self, hint: PlanCacheHint) -> Self {
        self.pool.plan_cache_hint = hint;
        self
    }

    fn mailbox_preamble(
        &self,
        principal: &VerifiedMailbox,
        operation: Option<OperationId>,
        lock_key: Option<String>,
    ) -> Preamble {
        Preamble {
            mailbox: principal.mailbox.decimal(),
            actor: principal.actor.decimal(),
            operation_id: operation.map(operation_hex),
            audit_keys: self.audit_keys.clone(),
            lock_key,
        }
    }

    fn user_preamble(
        &self,
        actor: ActorId,
        operation: Option<OperationId>,
        lock_key: Option<String>,
    ) -> Preamble {
        Preamble {
            mailbox: String::new(),
            actor: actor.decimal(),
            operation_id: operation.map(operation_hex),
            audit_keys: self.audit_keys.clone(),
            lock_key,
        }
    }

    // ---- Mailbox transactions ----

    /// Begin an interactive `MailboxTx<ReadOnly>` (`BEGIN READ ONLY` + merged
    /// preamble, stale-socket 1-retry).
    pub async fn begin_mailbox_read(
        &self,
        principal: &VerifiedMailbox,
    ) -> Result<MailboxTx<ReadOnly>, StatementFailure> {
        let preamble = self.mailbox_preamble(principal, None, None);
        let lease = begin_read_only_with_retry(&self.pool, &preamble).await?;
        Ok(MailboxTx {
            lease,
            principal: principal.clone(),
            lifecycle: None,
            failure: None,
            _mode: PhantomData,
        })
    }

    /// Run a 1-RTT pipelined `BEGIN READ ONLY` mailbox query (`tokio::join!(biased; ...)`).
    pub async fn run_mailbox_read_pipelined(
        &self,
        principal: &VerifiedMailbox,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        let preamble = self.mailbox_preamble(principal, None, None);
        execute_read_pipeline(&self.pool, &preamble, sql, params, None).await
    }

    /// Run a 1-RTT SQL-validated pipelined mailbox write (`tokio::join!(biased; ...)`).
    ///
    /// Use ONLY when all rollback/validation checks happen in SQL (`RAISE
    /// EXCEPTION`, constraints, RLS). Commands requiring semantic Rust
    /// pre-commit decoding stay on [`Self::run_mailbox_write`].
    #[allow(clippy::too_many_arguments)]
    pub async fn run_mailbox_write_pipelined<C, T, P>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedMailbox,
        deadline: Instant,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        let business = match EncodedStep::new_admitted(sql, params, false) {
            Ok(s) => s,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let receipt_step = match receipt {
            Some(cmd) => match receipt_step(envelope.operation, cmd) {
                Ok(s) => Some(s),
                Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
            },
            None => None,
        };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!(
            "setjoin-command:{}:{}:{op_hex}",
            principal.mailbox.get(),
            principal.actor.get()
        );
        let preamble = self.mailbox_preamble(principal, Some(envelope.operation), Some(lock));
        execute_write_pipeline(
            &self.pool,
            envelope,
            principal.authority(),
            deadline,
            &preamble,
            business,
            None,
            receipt_step,
            project,
        )
        .await
    }

    /// Run a 2-RTT interactive `MailboxTx<ReadWrite>` transaction with
    /// pre-business-SQL stale-socket retry on `BEGIN`.
    pub async fn run_mailbox_write<C, T, E, F>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedMailbox,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, E>,
    {
        if let Err(e) = envelope.validate(principal.authority(), accepted_contract()) {
            return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e)));
        }
        let lifecycle = match TransactionLifecycle::new(envelope, deadline) {
            Ok(l) => l,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Authority(e)),
        };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!(
            "setjoin-command:{}:{}:{op_hex}",
            principal.mailbox.get(),
            principal.actor.get()
        );
        let preamble = self.mailbox_preamble(principal, Some(envelope.operation), Some(lock));
        let lease = match begin_write_with_retry(&self.pool, &preamble, deadline).await {
            Ok(l) => l,
            Err(Rejection::Unavailable) => {
                return CommandOutcome::RolledBack(Rejection::Unavailable)
            }
            Err(Rejection::Authority(e)) => {
                return CommandOutcome::RolledBack(Rejection::Authority(e))
            }
            Err(Rejection::Statement(f)) => {
                return CommandOutcome::RolledBack(Rejection::Statement(f))
            }
            Err(Rejection::CommitRefused(c)) => {
                return CommandOutcome::RolledBack(Rejection::CommitRefused(c))
            }
            Err(Rejection::Body(_)) => return CommandOutcome::RolledBack(Rejection::Unavailable),
        };
        let mut tx = MailboxTx {
            lease,
            principal: principal.clone(),
            lifecycle: Some(lifecycle),
            failure: None,
            _mode: PhantomData,
        };
        let result = body(&mut tx).await;
        tx.finish_rw(Some(result), envelope.operation).await
    }

    /// Run a receipted mailbox effect write transaction guarded by:
    /// - bounded concurrency semaphore (`effect_sem`) acquired before pool checkout;
    /// - `SET LOCAL idle_in_transaction_session_timeout = 8000` (8000ms);
    /// - preamble advisory lock (`setjoin-command:{mailbox}:{actor}:{op_hex}`)
    ///   strictly preceding any row locks (`#481`);
    /// - tight peripheral timeout (`<= EFFECT_BODY_TIMEOUT`, 5s) around `body`;
    /// - same-transaction durable `rust_operation_receipts` insert before `COMMIT`.
    pub async fn run_mailbox_effect_write<C, T, F>(
        &self,
        command: ReceiptCommand,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedMailbox,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut MailboxTx<ReadWrite>) -> Result<T, StatementFailure>,
    {
        if let Err(e) = envelope.validate(principal.authority(), accepted_contract()) {
            return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e)));
        }
        let lifecycle = match TransactionLifecycle::new(envelope, deadline) {
            Ok(l) => l,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Authority(e)),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return CommandOutcome::RolledBack(Rejection::Authority(
                LifecycleError::DeadlineElapsed,
            ));
        }
        let _permit =
            match tokio::time::timeout(remaining, Arc::clone(&self.effect_sem).acquire_owned())
                .await
            {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => return CommandOutcome::RolledBack(Rejection::Unavailable),
                Err(_) => {
                    return CommandOutcome::RolledBack(Rejection::Authority(
                        LifecycleError::DeadlineElapsed,
                    ))
                }
            };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!(
            "setjoin-command:{}:{}:{op_hex}",
            principal.mailbox.get(),
            principal.actor.get()
        );
        let preamble = self.mailbox_preamble(principal, Some(envelope.operation), Some(lock));
        let lease = match begin_write_with_retry_opts(
            &self.pool,
            &preamble,
            deadline,
            Some(EFFECT_IDLE_IN_TX_TIMEOUT_MS),
        )
        .await
        {
            Ok(l) => l,
            Err(Rejection::Unavailable) => {
                return CommandOutcome::RolledBack(Rejection::Unavailable)
            }
            Err(Rejection::Authority(e)) => {
                return CommandOutcome::RolledBack(Rejection::Authority(e))
            }
            Err(Rejection::Statement(f)) => {
                return CommandOutcome::RolledBack(Rejection::Statement(f))
            }
            Err(Rejection::CommitRefused(c)) => {
                return CommandOutcome::RolledBack(Rejection::CommitRefused(c))
            }
            Err(Rejection::Body(_)) => return CommandOutcome::RolledBack(Rejection::Unavailable),
        };
        let mut tx = MailboxTx {
            lease,
            principal: principal.clone(),
            lifecycle: Some(lifecycle),
            failure: None,
            _mode: PhantomData,
        };
        let body_budget = deadline
            .saturating_duration_since(Instant::now())
            .min(EFFECT_BODY_TIMEOUT);
        let result = match tokio::time::timeout(body_budget, body(&mut tx)).await {
            Ok(Ok(val)) => {
                let receipt_res = tx
                    .execute(
                        RECEIPT_INSERT_SQL,
                        &[
                            (&op_hex, Type::TEXT),
                            (&command.family, Type::TEXT),
                            (&command.command, Type::TEXT),
                        ],
                    )
                    .await;
                match receipt_res {
                    Ok(_) => Ok(val),
                    Err(e) => Err(e),
                }
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                let err = StatementFailure::refused("effect peripheral timed out");
                if tx.failure.is_none() {
                    tx.failure = Some(TxFailure::Statement(err.clone()));
                }
                Err(err)
            }
        };
        tx.finish_rw(Some(result), envelope.operation).await
    }

    /// Look up whether a receipted mailbox command committed under current
    /// authority, waiting on the same advisory operation lock before reading at
    /// `READ COMMITTED READ ONLY` (#546a).
    pub async fn lookup_mailbox_command(
        &self,
        principal: &VerifiedMailbox,
        operation: OperationId,
        command: ReceiptCommand,
    ) -> Result<OperationLookup, StatementFailure> {
        let op_hex = operation_hex(operation);
        let lock = format!(
            "setjoin-command:{}:{}:{op_hex}",
            principal.mailbox.get(),
            principal.actor.get()
        );
        let preamble = self.mailbox_preamble(principal, None, None);
        let mailbox_id = principal.mailbox.get();
        let actor_id = principal.actor.get();
        let rows = execute_read_pipeline(
            &self.pool,
            &preamble,
            "SELECT EXISTS(SELECT 1 FROM public.rust_operation_receipts \
              WHERE operation_id = $3::text::uuid AND family = $4 AND command = $5) \
              WHERE $1::bigint > 0 AND $2::bigint > 0",
            &[
                (&mailbox_id, Type::INT8),
                (&actor_id, Type::INT8),
                (&op_hex, Type::TEXT),
                (&command.family, Type::TEXT),
                (&command.command, Type::TEXT),
            ],
            Some(&lock),
        )
        .await?;
        parse_operation_lookup(&rows)
    }

    // ---- Mailbox-less User transactions ----

    /// Begin an interactive `UserTx<ReadOnly>` (`app.current_mailbox_id = ''`).
    pub async fn begin_user_read(
        &self,
        principal: &VerifiedUser,
    ) -> Result<UserTx<ReadOnly>, StatementFailure> {
        let preamble = self.user_preamble(principal.actor, None, None);
        let lease = begin_read_only_with_retry(&self.pool, &preamble).await?;
        Ok(UserTx {
            lease,
            principal: principal.clone(),
            lifecycle: None,
            failure: None,
            _mode: PhantomData,
        })
    }

    /// Run a 1-RTT pipelined `BEGIN READ ONLY` user-scoped query.
    pub async fn run_user_read_pipelined(
        &self,
        principal: &VerifiedUser,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        let preamble = self.user_preamble(principal.actor, None, None);
        execute_read_pipeline(&self.pool, &preamble, sql, params, None).await
    }

    /// Run a 1-RTT SQL-validated pipelined user write (`app.current_mailbox_id = ''`).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_write_pipelined<C, T, P>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedUser,
        deadline: Instant,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        let business = match EncodedStep::new_admitted(sql, params, false) {
            Ok(s) => s,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let receipt_step = match receipt {
            Some(cmd) => match receipt_step(envelope.operation, cmd) {
                Ok(s) => Some(s),
                Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
            },
            None => None,
        };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!("setjoin-command:0:{}:{op_hex}", principal.actor.get());
        let preamble = self.user_preamble(principal.actor, Some(envelope.operation), Some(lock));
        execute_write_pipeline(
            &self.pool,
            envelope,
            principal.authority(),
            deadline,
            &preamble,
            business,
            None,
            receipt_step,
            project,
        )
        .await
    }

    /// Run a 2-RTT interactive `UserTx<ReadWrite>` transaction.
    pub async fn run_user_write<C, T, E, F>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedUser,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut UserTx<ReadWrite>) -> Result<T, E>,
    {
        if let Err(e) = envelope.validate(principal.authority(), accepted_contract()) {
            return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e)));
        }
        let lifecycle = match TransactionLifecycle::new(envelope, deadline) {
            Ok(l) => l,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Authority(e)),
        };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!("setjoin-command:0:{}:{op_hex}", principal.actor.get());
        let preamble = self.user_preamble(principal.actor, Some(envelope.operation), Some(lock));
        let lease = match begin_write_with_retry(&self.pool, &preamble, deadline).await {
            Ok(l) => l,
            Err(Rejection::Unavailable) => {
                return CommandOutcome::RolledBack(Rejection::Unavailable)
            }
            Err(Rejection::Authority(e)) => {
                return CommandOutcome::RolledBack(Rejection::Authority(e))
            }
            Err(Rejection::Statement(f)) => {
                return CommandOutcome::RolledBack(Rejection::Statement(f))
            }
            Err(Rejection::CommitRefused(c)) => {
                return CommandOutcome::RolledBack(Rejection::CommitRefused(c))
            }
            Err(Rejection::Body(_)) => return CommandOutcome::RolledBack(Rejection::Unavailable),
        };
        let mut tx = UserTx {
            lease,
            principal: principal.clone(),
            lifecycle: Some(lifecycle),
            failure: None,
            _mode: PhantomData,
        };
        let result = body(&mut tx).await;
        tx.finish_rw(Some(result), envelope.operation).await
    }

    /// Run a receipted mailbox-less user effect write transaction guarded by
    /// `effect_sem`, `SET LOCAL idle_in_transaction_session_timeout = 8000`,
    /// `<= 5s` peripheral body timeout, preamble advisory lock, and same-tx
    /// `rust_operation_receipts` insert (#546a).
    pub async fn run_user_effect_write<C, T, F>(
        &self,
        command: ReceiptCommand,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedUser,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut UserTx<ReadWrite>) -> Result<T, StatementFailure>,
    {
        if let Err(e) = envelope.validate(principal.authority(), accepted_contract()) {
            return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e)));
        }
        let lifecycle = match TransactionLifecycle::new(envelope, deadline) {
            Ok(l) => l,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Authority(e)),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return CommandOutcome::RolledBack(Rejection::Authority(
                LifecycleError::DeadlineElapsed,
            ));
        }
        let _permit =
            match tokio::time::timeout(remaining, Arc::clone(&self.effect_sem).acquire_owned())
                .await
            {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => return CommandOutcome::RolledBack(Rejection::Unavailable),
                Err(_) => {
                    return CommandOutcome::RolledBack(Rejection::Authority(
                        LifecycleError::DeadlineElapsed,
                    ))
                }
            };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!("setjoin-command:0:{}:{op_hex}", principal.actor.get());
        let preamble = self.user_preamble(principal.actor, Some(envelope.operation), Some(lock));
        let lease = match begin_write_with_retry_opts(
            &self.pool,
            &preamble,
            deadline,
            Some(EFFECT_IDLE_IN_TX_TIMEOUT_MS),
        )
        .await
        {
            Ok(l) => l,
            Err(Rejection::Unavailable) => {
                return CommandOutcome::RolledBack(Rejection::Unavailable)
            }
            Err(Rejection::Authority(e)) => {
                return CommandOutcome::RolledBack(Rejection::Authority(e))
            }
            Err(Rejection::Statement(f)) => {
                return CommandOutcome::RolledBack(Rejection::Statement(f))
            }
            Err(Rejection::CommitRefused(c)) => {
                return CommandOutcome::RolledBack(Rejection::CommitRefused(c))
            }
            Err(Rejection::Body(_)) => return CommandOutcome::RolledBack(Rejection::Unavailable),
        };
        let mut tx = UserTx {
            lease,
            principal: principal.clone(),
            lifecycle: Some(lifecycle),
            failure: None,
            _mode: PhantomData,
        };
        let body_budget = deadline
            .saturating_duration_since(Instant::now())
            .min(EFFECT_BODY_TIMEOUT);
        let result = match tokio::time::timeout(body_budget, body(&mut tx)).await {
            Ok(Ok(val)) => {
                let receipt_res = tx
                    .execute(
                        RECEIPT_INSERT_SQL,
                        &[
                            (&op_hex, Type::TEXT),
                            (&command.family, Type::TEXT),
                            (&command.command, Type::TEXT),
                        ],
                    )
                    .await;
                match receipt_res {
                    Ok(_) => Ok(val),
                    Err(e) => Err(e),
                }
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                let err = StatementFailure::refused("effect peripheral timed out");
                if tx.failure.is_none() {
                    tx.failure = Some(TxFailure::Statement(err.clone()));
                }
                Err(err)
            }
        };
        tx.finish_rw(Some(result), envelope.operation).await
    }

    /// Look up whether a receipted mailbox-less user command committed under
    /// current authority, waiting on the same advisory operation lock before
    /// reading at `READ COMMITTED READ ONLY` (#546a).
    pub async fn lookup_user_command(
        &self,
        principal: &VerifiedUser,
        operation: OperationId,
        command: ReceiptCommand,
    ) -> Result<OperationLookup, StatementFailure> {
        let op_hex = operation_hex(operation);
        let lock = format!("setjoin-command:0:{}:{op_hex}", principal.actor.get());
        let preamble = self.user_preamble(principal.actor, None, None);
        let actor_id = principal.actor.get();
        let rows = execute_read_pipeline(
            &self.pool,
            &preamble,
            "SELECT EXISTS(SELECT 1 FROM public.rust_operation_receipts \
              WHERE operation_id = $2::text::uuid AND family = $3 AND command = $4) \
              WHERE $1::bigint > 0",
            &[
                (&actor_id, Type::INT8),
                (&op_hex, Type::TEXT),
                (&command.family, Type::TEXT),
                (&command.command, Type::TEXT),
            ],
            Some(&lock),
        )
        .await?;
        parse_operation_lookup(&rows)
    }

    // ---- Admin transactions ----

    /// Begin a standard (non-sensitive) admin read (`BEGIN READ ONLY`).
    pub async fn begin_admin_read(
        &self,
        principal: &VerifiedAdmin,
    ) -> Result<AdminReadTx<Standard>, StatementFailure> {
        let preamble = self.user_preamble(principal.actor, None, None);
        let lease = begin_read_only_with_retry(&self.pool, &preamble).await?;
        Ok(AdminReadTx {
            lease,
            principal: principal.clone(),
            _class: PhantomData,
        })
    }

    /// Run a 1-RTT pipelined standard admin read (`BEGIN READ ONLY`).
    pub async fn run_admin_read_pipelined(
        &self,
        principal: &VerifiedAdmin,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        let preamble = self.user_preamble(principal.actor, None, None);
        execute_read_pipeline(&self.pool, &preamble, sql, params, None).await
    }

    /// Audit-before-read single-call API for sensitive admin / eDiscovery reads:
    ///
    /// - **Tx 1 (`BEGIN READ WRITE`):** commits `audit_write(principal.actor, ..., 'core')`
    ///   (NO stale-socket retry; `'core'` tier is never suppressed at
    ///   `audit_policy.level = 'lean'`). If Tx 1 fails, Tx 2 NEVER runs.
    /// - **Tx 2 (`BEGIN READ ONLY`):** executes the sensitive `SELECT` under
    ///   real PostgreSQL `BEGIN READ ONLY` (`25006` blocks `SELECT volatile_fn()`,
    ///   `FOR UPDATE`, and `nextval()`).
    pub async fn run_admin_sensitive_read(
        &self,
        principal: &VerifiedAdmin,
        audit: &AuditEvent,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        // Pre-validate query & params before committing the audit row.
        admit_select(sql).map_err(StatementFailure::refused)?;
        let _ = pre_encode_params(params)?;

        self.commit_sensitive_read_audit(principal, audit).await?;

        // Tx 2: real BEGIN READ ONLY.
        let preamble = self.user_preamble(principal.actor, None, None);
        execute_read_pipeline(&self.pool, &preamble, sql, params, None).await
    }

    /// Closure form of audit-before-read for multi-query sensitive reads.
    ///
    /// Tx 1 durably commits `audit_write(..., 'core')` **before** `body` is
    /// invoked with an [`AdminSensitiveRead`] bound to a real `BEGIN READ ONLY`
    /// transaction.
    pub async fn run_admin_sensitive_read_with<T, F>(
        &self,
        principal: &VerifiedAdmin,
        audit: &AuditEvent,
        body: F,
    ) -> Result<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut AdminSensitiveRead) -> Result<T, StatementFailure>,
    {
        self.commit_sensitive_read_audit(principal, audit).await?;

        let preamble = self.user_preamble(principal.actor, None, None);
        let lease = begin_read_only_with_retry(&self.pool, &preamble).await?;
        let mut handle = AdminSensitiveRead {
            lease,
            principal: principal.clone(),
        };
        let value = body(&mut handle).await?;
        match handle.lease.client().batch_execute("COMMIT").await {
            Ok(()) => {
                if !handle.lease.is_closed() {
                    handle.lease.keep();
                } else {
                    handle.lease.quarantine();
                }
                Ok(value)
            }
            Err(e) => {
                handle.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }

    async fn commit_sensitive_read_audit(
        &self,
        principal: &VerifiedAdmin,
        audit: &AuditEvent,
    ) -> Result<(), StatementFailure> {
        commit_sensitive_read_audit_on(&self.pool, self.audit_keys.clone(), principal, audit).await
    }

    /// Begin an interactive audited admin write transaction.
    ///
    /// Returns `AdminWriteTx<Unaudited>`, which cannot `.commit()` until
    /// [`AdminWriteTx::record_audit`] succeeds in the same transaction.
    pub async fn begin_admin_write<C>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedAdmin,
        deadline: Instant,
    ) -> Result<AdminWriteTx<Unaudited>, Rejection<StatementFailure>> {
        if let Err(e) = envelope.validate(principal.authority(), accepted_contract()) {
            return Err(Rejection::Authority(LifecycleError::Contract(e)));
        }
        let lifecycle =
            TransactionLifecycle::new(envelope, deadline).map_err(Rejection::Authority)?;
        let op_hex = operation_hex(envelope.operation);
        let lock = format!("setjoin-admin-command:{}:{op_hex}", principal.actor.get());
        let preamble = self.user_preamble(principal.actor, Some(envelope.operation), Some(lock));
        let lease = begin_write_with_retry(&self.pool, &preamble, deadline).await?;
        Ok(AdminWriteTx {
            lease,
            principal: principal.clone(),
            lifecycle,
            operation: envelope.operation,
            failure: None,
            _audit: PhantomData,
        })
    }

    /// Run a 1-RTT SQL-validated pipelined admin write (`BEGIN READ WRITE` +
    /// merged preamble + business SQL + `audit_write(..., 'core')` + optional
    /// receipt + `COMMIT`) using `tokio::join!(biased; ...)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_admin_write_pipelined<C, T, P>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedAdmin,
        deadline: Instant,
        audit: &AuditEvent,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        let business = match EncodedStep::new_admitted(sql, params, false) {
            Ok(s) => s,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let audit_step = match audit.to_step(principal.actor) {
            Ok(s) => s,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let receipt_step = match receipt {
            Some(cmd) => match receipt_step(envelope.operation, cmd) {
                Ok(s) => Some(s),
                Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
            },
            None => None,
        };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!("setjoin-admin-command:{}:{op_hex}", principal.actor.get());
        let preamble = self.user_preamble(principal.actor, Some(envelope.operation), Some(lock));
        execute_write_pipeline(
            &self.pool,
            envelope,
            principal.authority(),
            deadline,
            &preamble,
            business,
            Some(audit_step),
            receipt_step,
            project,
        )
        .await
    }

    /// Inspect the per-connection prepared LRU size on a freshly checked-out
    /// connection (test helper for verifying bounded LRU eviction).
    #[doc(hidden)]
    pub async fn debug_prepared_cache_stats(&self) -> Result<(usize, usize), StatementFailure> {
        let mut lease = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        let stats = (
            lease.managed_mut().prepared.len(),
            lease.managed_mut().prepared.cap(),
        );
        lease.keep();
        Ok(stats)
    }

    /// Test helper: directly acquire a `ManagedLease` to exercise non-Tokio
    /// drop behavior without exposing any inner client.
    #[doc(hidden)]
    pub async fn debug_open_read_tx(
        &self,
        principal: &VerifiedMailbox,
    ) -> Result<MailboxTx<ReadOnly>, StatementFailure> {
        self.begin_mailbox_read(principal).await
    }
}

fn parse_operation_lookup(rows: &[Row]) -> Result<OperationLookup, StatementFailure> {
    match rows {
        [row] if row.len() == 1 => match row.try_get::<_, bool>(0) {
            Ok(true) => Ok(OperationLookup::Committed),
            Ok(false) => Ok(OperationLookup::Absent),
            Err(_) => Err(StatementFailure::refused(
                "operation lookup must return one boolean",
            )),
        },
        _ => Err(StatementFailure::refused(
            "operation lookup must return one boolean",
        )),
    }
}

async fn commit_sensitive_read_audit_on(
    pool: &SetjoinPool,
    audit_keys: Option<Arc<AuditKeys>>,
    principal: &VerifiedAdmin,
    audit: &AuditEvent,
) -> Result<(), StatementFailure> {
    let preamble = Preamble {
        mailbox: String::new(),
        actor: principal.actor.decimal(),
        operation_id: None,
        audit_keys,
        lock_key: None,
    };
    let preamble_step = preamble.to_step()?;
    let audit_step = audit.to_step(principal.actor)?;

    let lease = pool
        .get()
        .await
        .map_err(|_| StatementFailure::refused("pool unavailable"))?;
    let begin_sql = build_begin_sql(
        "BEGIN READ WRITE",
        pool.timeouts.statement,
        pool.plan_cache_hint,
    );
    let client = lease.client();
    // NO retry on sensitive-read audit tx (READ WRITE).
    let piped = tokio::time::timeout(pool.timeouts.statement * 2, async {
        tokio::join!(
            biased;
            client.batch_execute(&begin_sql),
            preamble_step.execute(client),
            audit_step.execute(client),
            client.batch_execute("COMMIT"),
        )
    })
    .await;

    let Ok((begin_res, preamble_res, audit_res, commit_res)) = piped else {
        lease.quarantine();
        return Err(StatementFailure::refused("sensitive read audit timed out"));
    };
    if let Err(e) = begin_res {
        lease.quarantine();
        return Err(StatementFailure::from_db(&e));
    }
    if let Err(e) = preamble_res {
        if e.as_db_error().is_some() && commit_res.is_ok() && !lease.is_closed() {
            lease.keep();
        } else {
            lease.quarantine();
        }
        return Err(StatementFailure::from_db(&e));
    }
    if let Err(e) = audit_res {
        if e.as_db_error().is_some() && commit_res.is_ok() && !lease.is_closed() {
            lease.keep();
        } else {
            lease.quarantine();
        }
        return Err(StatementFailure::from_db(&e));
    }
    match commit_res {
        Ok(()) => {
            if !lease.is_closed() {
                lease.keep();
            } else {
                lease.quarantine();
            }
            Ok(())
        }
        Err(e) => {
            lease.quarantine();
            Err(StatementFailure::from_db(&e))
        }
    }
}

// ---------------------------------------------------------------------------
// Encapsulated AdminWorkerPool & PreAuthReadTx (#546a, feature = "mint")
// ---------------------------------------------------------------------------

/// Pre-authentication `BEGIN READ ONLY` transaction handle minted strictly via
/// [`AdminWorkerPool`] for login/OIDC/SAML/Basic/Kerberos/WebAuthn credential
/// proofs without exposing a `users` password-hash dump helper to `setjoin_app`.
///
/// Zero mutating methods; PG enforces SQLSTATE `25006`.
#[cfg(feature = "mint")]
#[must_use = "pre-auth read transactions must be finished"]
pub struct PreAuthReadTx {
    lease: ManagedLease,
}

#[cfg(feature = "mint")]
impl PreAuthReadTx {
    /// Execute one admitted `SELECT` inside the `BEGIN READ ONLY` pre-auth tx.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        run_interactive_statement(&self.lease, sql, params, true)
            .await
            .map(|(rows, _)| rows)
            .map_err(InteractiveStmtError::into_failure)
    }

    /// Execute a static [`SqlContract`] scoped strictly to [`SqlScope::AuthPreScope`].
    pub async fn query_contract(
        &mut self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AuthPreScope],
            "contract scope mismatch for PreAuthReadTx",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.query(contract.sql, &params).await
    }

    /// Close the read-only transaction cleanly and return the connection to the pool.
    pub async fn finish(self) -> Result<(), StatementFailure> {
        match self.lease.client().batch_execute("COMMIT").await {
            Ok(()) => {
                if !self.lease.is_closed() {
                    self.lease.keep();
                } else {
                    self.lease.quarantine();
                }
                Ok(())
            }
            Err(e) => {
                self.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }
}

/// Encapsulated cross-tenant worker-credential pool (`DB_WORKER_DSN` /
/// `setjoin_worker`, `BYPASSRLS`) restricted strictly to:
/// - verified admin transactions (`AdminReadTx`, `AdminSensitiveRead`,
///   `AdminWriteTx<Unaudited->Audited>`) gated on [`VerifiedAdmin`], and
/// - read-only pre-authentication credential proofs ([`PreAuthReadTx`]).
///
/// Gated behind the `mint` Cargo feature (never exposed to `crates/domains/*`,
/// and never exposes `WorkerTx`), keeping `setjoin-authz` out of
/// `WORKER_POOL_FEATURE_ALLOWLIST` (#546a).
#[cfg(feature = "mint")]
#[derive(Clone)]
pub struct AdminWorkerPool {
    pool: SetjoinPool,
    audit_keys: Option<Arc<AuditKeys>>,
}

#[cfg(feature = "mint")]
impl AdminWorkerPool {
    /// Construct an `AdminWorkerPool` from `DB_WORKER_DSN` with default timeouts.
    pub fn from_dsn(dsn: &str, max_size: usize) -> Result<Self, ConfigError> {
        Self::from_dsn_with(dsn, max_size, Timeouts::resolved())
    }

    /// Construct an `AdminWorkerPool` from `DB_WORKER_DSN` with explicit timeouts.
    pub fn from_dsn_with(
        dsn: &str,
        max_size: usize,
        timeouts: Timeouts,
    ) -> Result<Self, ConfigError> {
        let pool = SetjoinPool::from_dsn_with(
            dsn,
            max_size,
            timeouts,
            PreparedStatementMode::Unnamed,
            PlanCacheHint::Auto,
        )?;
        Ok(Self {
            pool,
            audit_keys: None,
        })
    }

    /// Attach trusted deployment encryption/audit GUC keys (`DB_ENCRYPTION_KEY`,
    /// `AUDIT_HMAC_KEY`).
    pub fn with_audit_keys(mut self, encryption_key: String, audit_hmac_key: String) -> Self {
        self.audit_keys = Some(Arc::new(AuditKeys {
            encryption: encryption_key,
            audit_hmac: audit_hmac_key,
        }));
        self
    }

    fn admin_preamble(
        &self,
        actor: ActorId,
        operation: Option<OperationId>,
        lock_key: Option<String>,
    ) -> Preamble {
        Preamble {
            mailbox: String::new(),
            actor: actor.decimal(),
            operation_id: operation.map(operation_hex),
            audit_keys: self.audit_keys.clone(),
            lock_key,
        }
    }

    fn pre_auth_preamble(&self) -> Preamble {
        Preamble {
            mailbox: String::new(),
            actor: String::new(),
            operation_id: None,
            audit_keys: self.audit_keys.clone(),
            lock_key: None,
        }
    }

    /// Begin a cross-tenant standard (non-sensitive) admin read (`BEGIN READ ONLY`).
    pub async fn begin_admin_read(
        &self,
        principal: &VerifiedAdmin,
    ) -> Result<AdminReadTx<Standard>, StatementFailure> {
        let preamble = self.admin_preamble(principal.actor, None, None);
        let lease = begin_read_only_with_retry(&self.pool, &preamble).await?;
        Ok(AdminReadTx {
            lease,
            principal: principal.clone(),
            _class: PhantomData,
        })
    }

    /// Run a 1-RTT pipelined cross-tenant standard admin read (`BEGIN READ ONLY`).
    pub async fn run_admin_read_pipelined(
        &self,
        principal: &VerifiedAdmin,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        let preamble = self.admin_preamble(principal.actor, None, None);
        execute_read_pipeline(&self.pool, &preamble, sql, params, None).await
    }

    /// Cross-tenant audit-before-read single-call API for sensitive admin /
    /// eDiscovery reads (Tx 1 `audit_write(..., 'core')` -> Tx 2 `BEGIN READ ONLY`).
    pub async fn run_admin_sensitive_read(
        &self,
        principal: &VerifiedAdmin,
        audit: &AuditEvent,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        admit_select(sql).map_err(StatementFailure::refused)?;
        let _ = pre_encode_params(params)?;
        commit_sensitive_read_audit_on(&self.pool, self.audit_keys.clone(), principal, audit)
            .await?;
        let preamble = self.admin_preamble(principal.actor, None, None);
        execute_read_pipeline(&self.pool, &preamble, sql, params, None).await
    }

    /// Closure form of cross-tenant audit-before-read (Tx 1 `audit_write(..., 'core')`
    /// -> Tx 2 `BEGIN READ ONLY`).
    pub async fn run_admin_sensitive_read_with<T, F>(
        &self,
        principal: &VerifiedAdmin,
        audit: &AuditEvent,
        body: F,
    ) -> Result<T, StatementFailure>
    where
        F: AsyncFnOnce(&mut AdminSensitiveRead) -> Result<T, StatementFailure>,
    {
        commit_sensitive_read_audit_on(&self.pool, self.audit_keys.clone(), principal, audit)
            .await?;
        let preamble = self.admin_preamble(principal.actor, None, None);
        let lease = begin_read_only_with_retry(&self.pool, &preamble).await?;
        let mut handle = AdminSensitiveRead {
            lease,
            principal: principal.clone(),
        };
        let value = body(&mut handle).await?;
        match handle.lease.client().batch_execute("COMMIT").await {
            Ok(()) => {
                if !handle.lease.is_closed() {
                    handle.lease.keep();
                } else {
                    handle.lease.quarantine();
                }
                Ok(value)
            }
            Err(e) => {
                handle.lease.quarantine();
                Err(StatementFailure::from_db(&e))
            }
        }
    }

    /// Begin a cross-tenant audited admin write transaction (`AdminWriteTx<Unaudited>`).
    pub async fn begin_admin_write<C>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedAdmin,
        deadline: Instant,
    ) -> Result<AdminWriteTx<Unaudited>, Rejection<StatementFailure>> {
        if let Err(e) = envelope.validate(principal.authority(), accepted_contract()) {
            return Err(Rejection::Authority(LifecycleError::Contract(e)));
        }
        let lifecycle =
            TransactionLifecycle::new(envelope, deadline).map_err(Rejection::Authority)?;
        let op_hex = operation_hex(envelope.operation);
        let lock = format!("setjoin-admin-command:{}:{op_hex}", principal.actor.get());
        let preamble = self.admin_preamble(principal.actor, Some(envelope.operation), Some(lock));
        let lease = begin_write_with_retry(&self.pool, &preamble, deadline).await?;
        Ok(AdminWriteTx {
            lease,
            principal: principal.clone(),
            lifecycle,
            operation: envelope.operation,
            failure: None,
            _audit: PhantomData,
        })
    }

    /// Run a 1-RTT SQL-validated pipelined cross-tenant admin write.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_admin_write_pipelined<C, T, P>(
        &self,
        envelope: &CommandEnvelope<C>,
        principal: &VerifiedAdmin,
        deadline: Instant,
        audit: &AuditEvent,
        sql: &'static str,
        params: &[Param<'_>],
        receipt: Option<ReceiptCommand>,
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(Vec<Row>) -> Result<T, StatementFailure>,
    {
        let business = match EncodedStep::new_admitted(sql, params, false) {
            Ok(s) => s,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let audit_step = match audit.to_step(principal.actor) {
            Ok(s) => s,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let receipt_step = match receipt {
            Some(cmd) => match receipt_step(envelope.operation, cmd) {
                Ok(s) => Some(s),
                Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
            },
            None => None,
        };
        let op_hex = operation_hex(envelope.operation);
        let lock = format!("setjoin-admin-command:{}:{op_hex}", principal.actor.get());
        let preamble = self.admin_preamble(principal.actor, Some(envelope.operation), Some(lock));
        execute_write_pipeline(
            &self.pool,
            envelope,
            principal.authority(),
            deadline,
            &preamble,
            business,
            Some(audit_step),
            receipt_step,
            project,
        )
        .await
    }

    /// Begin a `BEGIN READ ONLY` pre-authentication credential-proof transaction.
    pub async fn begin_pre_auth_read(&self) -> Result<PreAuthReadTx, StatementFailure> {
        let preamble = self.pre_auth_preamble();
        let lease = begin_read_only_with_retry(&self.pool, &preamble).await?;
        Ok(PreAuthReadTx { lease })
    }

    /// Run a 1-RTT pipelined `BEGIN READ ONLY` pre-authentication query.
    pub async fn run_pre_auth_read_pipelined(
        &self,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        let preamble = self.pre_auth_preamble();
        execute_read_pipeline(&self.pool, &preamble, sql, params, None).await
    }

    /// Run a 1-RTT pipelined `BEGIN READ ONLY` pre-authentication [`SqlContract`]
    /// scoped strictly to [`SqlScope::AuthPreScope`].
    pub async fn run_pre_auth_read_contract(
        &self,
        contract: &'static SqlContract,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, StatementFailure> {
        check_contract_scope(
            contract,
            &[SqlScope::AuthPreScope],
            "contract scope mismatch for AdminWorkerPool::run_pre_auth_read_contract",
        )?;
        let params = zip_contract_params(contract, values)?;
        self.run_pre_auth_read_pipelined(contract.sql, &params)
            .await
    }
}

// ---------------------------------------------------------------------------
// WorkerPool (DB_WORKER_DSN / setjoin_worker, BYPASSRLS) — feature-gated
// ---------------------------------------------------------------------------

/// Cross-tenant background worker pool (`DB_WORKER_DSN` / `setjoin_worker`,
/// `BYPASSRLS`). Gated behind the `worker-pool` Cargo feature so domain crates
/// cannot construct or hold it.
#[cfg(feature = "worker-pool")]
#[derive(Clone)]
pub struct WorkerPool {
    pool: SetjoinPool,
    dsn: Arc<str>,
    audit_keys: Option<Arc<AuditKeys>>,
}

/// Maximum per-transaction `statement_timeout` allowed for
/// [`WorkerPool::begin_read_write_bounded`] (10 minutes, covering long periodic
/// maintenance tasks such as `chat-purge-expired`).
#[cfg(feature = "worker-pool")]
pub const MAX_BOUNDED_WORKER_TIMEOUT: Duration = Duration::from_secs(600);

#[cfg(feature = "worker-pool")]
impl WorkerPool {
    pub fn from_dsn(dsn: &str, max_size: usize) -> Result<Self, ConfigError> {
        Self::from_dsn_with(dsn, max_size, Timeouts::resolved())
    }

    pub fn from_dsn_with(
        dsn: &str,
        max_size: usize,
        timeouts: Timeouts,
    ) -> Result<Self, ConfigError> {
        let pool = SetjoinPool::from_dsn_with(
            dsn,
            max_size,
            timeouts,
            PreparedStatementMode::Unnamed,
            PlanCacheHint::Auto,
        )?;
        Ok(Self {
            pool,
            dsn: Arc::from(dsn),
            audit_keys: None,
        })
    }

    pub fn with_audit_keys(mut self, encryption_key: String, audit_hmac_key: String) -> Self {
        self.audit_keys = Some(Arc::new(AuditKeys {
            encryption: encryption_key,
            audit_hmac: audit_hmac_key,
        }));
        self
    }

    /// Derive a dedicated session-capable [`crate::workers::WorkerDatabase`]
    /// inheriting this boot-verified `WorkerPool`'s DSN and audit keys (#551).
    pub fn worker_database(&self) -> Result<crate::workers::WorkerDatabase, String> {
        let mut db = crate::workers::WorkerDatabase::new(&self.dsn).map_err(|e| e.to_string())?;
        if let Some(keys) = &self.audit_keys {
            db = db.with_audit_keys(keys.encryption.clone(), keys.audit_hmac.clone());
        }
        Ok(db)
    }

    /// Derive a narrow, capability-gated [`AdminWorkerPool`] sharing this
    /// `WorkerPool`'s underlying connection pool and audit keys for
    /// composition-root `TxFactory` wiring (#546a).
    #[cfg(feature = "mint")]
    pub fn admin_pool(&self) -> AdminWorkerPool {
        AdminWorkerPool {
            pool: self.pool.clone(),
            audit_keys: self.audit_keys.clone(),
        }
    }

    fn worker_preamble(&self) -> Preamble {
        Preamble {
            mailbox: String::new(),
            actor: String::new(),
            operation_id: None,
            audit_keys: self.audit_keys.clone(),
            lock_key: None,
        }
    }

    /// Fail-closed boot check verifying that this worker pool's PostgreSQL role
    /// holds `rolbypassrls OR rolsuper`.
    ///
    /// Returns the verified PostgreSQL role name on success, or refuses with an
    /// actionable `mailctl schema provision-roles --write-dsns` error when the
    /// role is constrained by RLS (e.g. `setjoin_app`).
    pub async fn verify_bypassrls(&self) -> Result<String, StatementFailure> {
        let mut tx = self.begin_repeatable_read_only().await?;
        let rows = match tx
            .query(
                "SELECT current_user::text, (rolbypassrls OR rolsuper) \
                 FROM pg_catalog.pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err);
            }
        };
        tx.commit().await?;
        let Some(row) = rows.first() else {
            return Err(StatementFailure::refused(
                "worker role verification returned no rows; run `mailctl schema provision-roles --write-dsns`",
            ));
        };
        let role: String = row
            .try_get(0)
            .map_err(|_| StatementFailure::refused("worker role verification: invalid role"))?;
        let ok: bool = row
            .try_get(1)
            .map_err(|_| StatementFailure::refused("worker role verification: invalid flag"))?;
        if !ok {
            return Err(StatementFailure::refused_owned(format!(
                "worker credential role {role:?} lacks BYPASSRLS or superuser; \
                 run `mailctl schema provision-roles --write-dsns`"
            )));
        }
        Ok(role)
    }

    /// Begin a `BEGIN READ WRITE` worker transaction with empty tenant GUCs
    /// and deployment audit keys.
    pub async fn begin_read_write(&self) -> Result<WorkerTx, StatementFailure> {
        let preamble = self.worker_preamble();
        let deadline = Instant::now() + self.pool.timeouts.statement * 2;
        let lease = begin_write_with_retry(&self.pool, &preamble, deadline)
            .await
            .map_err(|r| match r {
                Rejection::Statement(f) => f,
                _ => StatementFailure::refused("worker transaction unavailable"),
            })?;
        Ok(WorkerTx {
            lease,
            read_only: false,
        })
    }

    /// Begin a `BEGIN READ WRITE` worker transaction with an explicit per-transaction
    /// `SET LOCAL statement_timeout` clamped to `1ms..=600s` (bypassing the 2s
    /// interactive request statement timeout for long-running maintenance tasks).
    pub async fn begin_read_write_bounded(
        &self,
        timeout: Duration,
    ) -> Result<WorkerTx, StatementFailure> {
        let clamped = timeout.clamp(Duration::from_millis(1), MAX_BOUNDED_WORKER_TIMEOUT);
        let preamble = self.worker_preamble();
        let preamble_step = preamble.to_step()?;
        let begin_sql = build_begin_sql("BEGIN READ WRITE", clamped, self.pool.plan_cache_hint);
        let handshake_budget = (self.pool.timeouts.statement * 2).max(Duration::from_secs(5));
        let deadline = Instant::now() + handshake_budget;

        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StatementFailure::refused("worker transaction timed out"));
            }
            let lease = self
                .pool
                .get()
                .await
                .map_err(|_| StatementFailure::refused("worker pool unavailable"))?;
            let client = lease.client();
            let begun = tokio::time::timeout(remaining, async {
                tokio::join!(
                    biased;
                    client.batch_execute(&begin_sql),
                    preamble_step.execute(client),
                )
            })
            .await;
            match begun {
                Ok((Ok(()), Ok(_))) => {
                    return Ok(WorkerTx {
                        lease,
                        read_only: false,
                    });
                }
                Ok((Err(e), _)) if attempt == 0 && e.as_db_error().is_none() => {
                    lease.quarantine();
                    continue;
                }
                Ok((Err(e), _)) => {
                    lease.quarantine();
                    return Err(StatementFailure::from_db(&e));
                }
                Err(_) => {
                    lease.quarantine();
                    return Err(StatementFailure::refused("worker transaction timed out"));
                }
                Ok((Ok(()), Err(e))) => {
                    let failure = StatementFailure::from_db(&e);
                    if e.as_db_error().is_some()
                        && matches!(lease.client().batch_execute("ROLLBACK").await, Ok(()))
                        && !lease.is_closed()
                    {
                        lease.keep();
                    } else {
                        lease.quarantine();
                    }
                    return Err(failure);
                }
            }
        }
        Err(StatementFailure::refused("worker pool unavailable"))
    }

    /// Begin a `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY` worker
    /// snapshot transaction with empty tenant GUCs and deployment audit keys.
    pub async fn begin_repeatable_read_only(&self) -> Result<WorkerTx, StatementFailure> {
        let preamble = self.worker_preamble();
        let preamble_step = preamble.to_step()?;
        let begin_sql = build_begin_sql(
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
            self.pool.timeouts.statement,
            self.pool.plan_cache_hint,
        );
        let deadline = Instant::now() + self.pool.timeouts.statement * 2;
        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StatementFailure::refused("worker snapshot timed out"));
            }
            let lease = self
                .pool
                .get()
                .await
                .map_err(|_| StatementFailure::refused("worker pool unavailable"))?;
            let client = lease.client();
            let begun = tokio::time::timeout(remaining, async {
                tokio::join!(
                    biased;
                    client.batch_execute(&begin_sql),
                    preamble_step.execute(client),
                )
            })
            .await;
            let Ok((begin_res, preamble_res)) = begun else {
                return Err(StatementFailure::refused("worker snapshot timed out"));
            };
            if let Err(e) = begin_res {
                if attempt == 0 && e.as_db_error().is_none() {
                    lease.quarantine();
                    continue;
                }
                lease.quarantine();
                return Err(StatementFailure::from_db(&e));
            }
            if let Err(e) = preamble_res {
                lease.quarantine();
                return Err(StatementFailure::from_db(&e));
            }
            return Ok(WorkerTx {
                lease,
                read_only: true,
            });
        }
        Err(StatementFailure::refused("worker pool unavailable"))
    }
}
