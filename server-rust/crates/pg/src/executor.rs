//! One transaction per command, scoped to the authenticated mailbox.
//!
//! Upgraded internally in Wave 1.2 (#540) to use `RecyclingMethod::Fast` (via
//! [`SetjoinPool`]), merged single-statement preambles, 2-RTT `BEGIN`
//! stale-socket retry before business SQL, and PgBouncer-safe bounded
//! `CancelRequest` drop while keeping the legacy `ScopedExecutor`/`ScopedTx`
//! API compiling cleanly across the workspace during Wave 1 expand–contract.
use crate::{
    auth::{AuditKeys, MailboxAuthContext},
    outcome::{commit_failure_observation, CommandOutcome, Rejection, StatementFailure},
    pipeline::{build_begin_sql, pre_encode_params, PreEncodedParam, Preamble},
    pool::{
        quarantine_legacy_object, ManagedLease, PlanCacheHint, PreparedStatementMode, SetjoinPool,
        CANCEL_SEMAPHORE_PERMITS,
    },
    statement::{admit, admit_select},
};
use deadpool_postgres::{Object, Pool};
use futures_util::TryStreamExt;
use setjoin_contracts::{
    command::{CommandEnvelope, CommitObservation},
    ids::MailboxId,
};
use setjoin_db::lifecycle::{
    accepted_contract, ConnectionDisposition, LifecycleError, Phase, RollbackObservation,
    TransactionLifecycle,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tokio_postgres::{
    types::{ToSql, Type},
    Client, Row,
};

/// A typed statement parameter. The explicit type is what lets the driver
/// send Parse/Bind/Execute on the unnamed statement in one round trip.
pub type Param<'a> = (&'a (dyn ToSql + Sync), Type);

/// The one reducer statement selected after a credential read under its fence.
/// Values are server-derived proof results, never a new privilege context.
pub struct ProvenStatement {
    sql: &'static str,
    params: Vec<(Box<dyn ToSql + Sync + Send>, Type)>,
}
impl ProvenStatement {
    pub fn new(sql: &'static str) -> Self {
        Self {
            sql,
            params: Vec::new(),
        }
    }
    pub fn bind<T: ToSql + Sync + Send + 'static>(mut self, value: T, typ: Type) -> Self {
        self.params.push((Box::new(value), typ));
        self
    }
}

// Named infrastructure allowlist shared with `workers.rs`.
pub(crate) const AUDIT_SCOPE: &str = "SELECT set_config('app.encryption_key', $1, true), \
    set_config('app.audit_hmac_key', $2, true)";

const USER_SCOPE: &str = "SELECT set_config('app.current_user_id', $1, true)";

/// Error building a pool from a DSN.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// How long the executor waits on a stalled database (review item 1). Every
/// bound fails closed: the caller gets an error (a read) or a rejection (a
/// command before BEGIN), never a hang.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Waiting for a free pooled connection.
    pub pool_wait: Duration,
    /// Opening a new connection (TCP connect, startup and authentication)
    /// and the liveness check before a pooled one is reused.
    pub create: Duration,
    /// One read ([`ScopedExecutor::read`], [`ScopedExecutor::read_scoped`]):
    /// `SET LOCAL statement_timeout` inside the scoped read's transaction
    /// (sent by the executor itself, never caller SQL) plus a client-side
    /// deadline that cancels the statement and discards the connection.
    pub statement: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            pool_wait: Duration::from_secs(1),
            create: Duration::from_secs(2),
            statement: Duration::from_secs(2),
        }
    }
}

/// Environment override for [`Timeouts::resolved`], in milliseconds (1..=120000): every
/// bound becomes the larger of its default and this value. For test harnesses on a
/// CPU-starved host, where a 1 s pool wait would turn a scheduling stall into a request
/// forwarded to Go; unset, production keeps [`Timeouts::default`].
pub const DEADLINE_ENV: &str = "SETJOIN_PG_DEADLINE_MS";

impl Timeouts {
    /// [`Timeouts::default`] widened by [`DEADLINE_ENV`] when it holds a sane value.
    /// Read once per process. A longer bound only waits longer before failing closed.
    pub fn resolved() -> Self {
        static RESOLVED: std::sync::OnceLock<Timeouts> = std::sync::OnceLock::new();
        *RESOLVED.get_or_init(|| Self::widened(std::env::var(DEADLINE_ENV).ok().as_deref()))
    }

    fn widened(value: Option<&str>) -> Self {
        let base = Self::default();
        let Some(ms) = value
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|ms| (1..=120_000).contains(ms))
        else {
            return base;
        };
        let wide = Duration::from_millis(ms);
        Self {
            pool_wait: base.pool_wait.max(wide),
            create: base.create.max(wide),
            statement: base.statement.max(wide),
        }
    }
}

#[cfg(test)]
mod deadline_env_tests {
    use super::*;

    #[test]
    fn default_unless_a_sane_override_is_given() {
        let d = Timeouts::default();
        for v in [None, Some(""), Some("x"), Some("0"), Some("120001")] {
            assert_eq!(Timeouts::widened(v), d);
        }
        let w = Timeouts::widened(Some(" 30000 "));
        assert_eq!(w.pool_wait, Duration::from_secs(30));
        assert_eq!(w.create, Duration::from_secs(30));
        assert_eq!(w.statement, Duration::from_secs(30));
        // Never narrower than the default.
        assert_eq!(Timeouts::widened(Some("1")), d);
    }
}

/// `SET LOCAL statement_timeout` text for `d` (whole milliseconds, ≥ 1).
fn statement_timeout_sql(d: Duration) -> String {
    format!(
        "SET LOCAL statement_timeout = {}",
        d.as_millis().clamp(1, i32::MAX as u128)
    )
}

#[derive(Clone)]
enum PoolBackend {
    Fast(SetjoinPool),
    Legacy {
        pool: Pool,
        runtime_handle: Option<tokio::runtime::Handle>,
        cancel_sem: Arc<Semaphore>,
    },
}

impl PoolBackend {
    async fn get(&self) -> Result<PoolLease, ()> {
        match self {
            Self::Fast(pool) => pool
                .get()
                .await
                .map(|l| PoolLease::Fast(Some(l)))
                .map_err(|_| ()),
            Self::Legacy {
                pool,
                runtime_handle,
                cancel_sem,
            } => pool
                .get()
                .await
                .map(|obj| PoolLease::Legacy {
                    object: Some(obj),
                    runtime_handle: runtime_handle.clone(),
                    cancel_sem: Arc::clone(cancel_sem),
                })
                .map_err(|_| ()),
        }
    }
}

enum PoolLease {
    Fast(Option<ManagedLease>),
    Legacy {
        object: Option<Object>,
        runtime_handle: Option<tokio::runtime::Handle>,
        cancel_sem: Arc<Semaphore>,
    },
}

impl PoolLease {
    fn client(&self) -> &Client {
        match self {
            Self::Fast(l) => l.as_ref().expect("lease held").client(),
            Self::Legacy { object, .. } => object.as_ref().expect("lease held"),
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Self::Fast(l) => l.as_ref().is_none_or(|m| m.is_closed()),
            Self::Legacy { object, .. } => object.as_ref().is_none_or(|o| o.is_closed()),
        }
    }

    fn keep(mut self) {
        match &mut self {
            Self::Fast(l) => {
                if let Some(m) = l.take() {
                    m.keep();
                }
            }
            Self::Legacy { object, .. } => {
                drop(object.take());
            }
        }
    }

    fn quarantine(mut self) {
        match &mut self {
            Self::Fast(l) => {
                if let Some(m) = l.take() {
                    m.quarantine();
                }
            }
            Self::Legacy {
                object,
                runtime_handle,
                cancel_sem,
            } => {
                if let Some(obj) = object.take() {
                    quarantine_legacy_object(obj, runtime_handle.as_ref(), cancel_sem);
                }
            }
        }
    }
}

impl Drop for PoolLease {
    fn drop(&mut self) {
        if let Self::Legacy {
            object,
            runtime_handle,
            cancel_sem,
        } = self
        {
            if let Some(obj) = object.take() {
                quarantine_legacy_object(obj, runtime_handle.as_ref(), cancel_sem);
            }
        }
        // Self::Fast(ManagedLease) drops via ManagedLease::drop -> quarantine_managed_object.
    }
}

/// Runs each command in its own scoped transaction over one credential's pool.
///
/// The pool's credential is the privilege boundary: build the request
/// executor from `DB_DSN` (constrained `setjoin_app` role, RLS applies) and a
/// cross-tenant worker from `DB_WORKER_DSN`. The executor never issues
/// `SET ROLE` and refuses any statement that would.
#[derive(Clone)]
pub struct ScopedExecutor {
    pool: PoolBackend,
    timeouts: Timeouts,
    audit_keys: Option<Arc<AuditKeys>>,
    user_receipt: Option<crate::ReceiptCommand>,
    effect_sem: Arc<Semaphore>,
}

impl ScopedExecutor {
    /// Wrap an existing `deadpool_postgres::Pool`.
    pub fn new(pool: Pool) -> Self {
        Self {
            pool: PoolBackend::Legacy {
                pool,
                runtime_handle: tokio::runtime::Handle::try_current().ok(),
                cancel_sem: Arc::new(Semaphore::new(CANCEL_SEMAPHORE_PERMITS)),
            },
            timeouts: Timeouts::resolved(),
            audit_keys: None,
            user_receipt: None,
            effect_sem: Arc::new(Semaphore::new(crate::DEFAULT_EFFECT_CONCURRENCY)),
        }
    }

    /// Build a plaintext (`NoTls`) pool of `max_size` connections from a
    /// libpq-style DSN with [`Timeouts::resolved`], `RecyclingMethod::Fast`,
    /// and TCP keepalives.
    pub fn from_dsn(dsn: &str, max_size: usize) -> Result<Self, ConfigError> {
        Self::from_dsn_with(dsn, max_size, Timeouts::resolved())
    }

    /// [`ScopedExecutor::from_dsn`] with explicit [`Timeouts`].
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
            pool: PoolBackend::Fast(pool),
            timeouts,
            audit_keys: None,
            user_receipt: None,
            effect_sem: Arc::new(Semaphore::new(crate::DEFAULT_EFFECT_CONCURRENCY)),
        })
    }

    /// Attach code-owned commit metadata to authentication-time user commands.
    /// The stored key is SHA-256(operation UUID, authenticated actor), truncated
    /// to the UUID column. Lookup must derive the same actor-bound key; an opaque
    /// operation UUID alone is never permission to inspect another user's result.
    pub fn with_user_receipt(mut self, command: crate::ReceiptCommand) -> Self {
        self.user_receipt = Some(command);
        self
    }

    /// Configure Go's named encryption/audit GUCs from trusted deployment
    /// configuration only (`DB_ENCRYPTION_KEY`, `AUDIT_HMAC_KEY`). The executor
    /// attaches them to the verified mailbox context for each transaction.
    /// No request/claim may supply a key or a GUC name. Empty keys preserve
    /// Go's unkeyed audit fallback. Values never persist across a transaction.
    pub fn with_audit_keys(mut self, encryption_key: String, audit_hmac_key: String) -> Self {
        self.audit_keys = Some(Arc::new(AuditKeys {
            encryption: encryption_key,
            audit_hmac: audit_hmac_key,
        }));
        self
    }

    /// Derive a capability-gated [`crate::AppPool`] sharing this executor's
    /// underlying [`SetjoinPool`] and deployment audit keys (zero extra connections).
    pub fn try_app_pool(&self) -> Option<crate::AppPool> {
        match &self.pool {
            PoolBackend::Fast(pool) => Some(crate::AppPool::from_parts(
                pool.clone(),
                self.audit_keys.clone(),
                self.effect_sem.clone(),
            )),
            PoolBackend::Legacy { .. } => None,
        }
    }

    /// Derive a cross-tenant [`crate::WorkerPool`] sharing this executor's
    /// underlying [`SetjoinPool`] and deployment audit keys (composition-root only).
    #[cfg(feature = "worker-pool")]
    pub fn try_worker_pool(&self) -> Option<crate::WorkerPool> {
        match &self.pool {
            PoolBackend::Fast(pool) => Some(crate::WorkerPool::from_parts(
                pool.clone(),
                self.audit_keys.clone(),
            )),
            PoolBackend::Legacy { .. } => None,
        }
    }

    fn transaction_auth(&self, auth: &MailboxAuthContext) -> MailboxAuthContext {
        let mut auth = auth.clone();
        auth.audit_keys = self.audit_keys.clone();
        auth
    }

    /// Run one read-only `SELECT` outside any command transaction (autocommit,
    /// no tenant GUC) on the pool's credential, for the authentication-time
    /// lookups that precede a command. Retries once on a pre-response stale
    /// socket under `RecyclingMethod::Fast`.
    pub async fn read(
        &self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        admit_select(sql).map_err(StatementFailure::refused)?;
        let deadline = Instant::now() + self.timeouts.statement;
        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StatementFailure::refused("read timed out"));
            }
            let object = self
                .pool
                .get()
                .await
                .map_err(|_| StatementFailure::refused("pool unavailable"))?;
            let object = ReadLease(Some(object));
            let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
            let query = object.client().query_typed(sql, &typed);
            let result = match tokio::time::timeout(remaining, query).await {
                Ok(result) => result,
                Err(_) => {
                    return Err(StatementFailure::refused("read timed out"));
                }
            };
            match result {
                Ok(rows) => {
                    object.keep();
                    return Ok(rows);
                }
                Err(e) => {
                    if attempt == 0 && e.as_db_error().is_none() {
                        drop(object); // quarantines dead socket
                        continue;
                    }
                    if e.as_db_error().is_some() && !object.is_closed() {
                        object.keep();
                    }
                    return Err(StatementFailure::from_db(&e));
                }
            }
        }
        Err(StatementFailure::refused("pool unavailable"))
    }

    /// Authentication-time best-effort CAS, mirroring pwhash.CheckPassword.
    pub async fn upgrade_legacy_protocol_password(
        &self,
        user: i64,
        email: &str,
        old: &str,
        new: &str,
    ) -> Result<(), StatementFailure> {
        use tokio_postgres::types::Type;
        let object = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        let object = ReadLease(Some(object));
        let params: Vec<Param<'_>> = vec![
            (&user, Type::INT8),
            (&email, Type::TEXT),
            (&old, Type::TEXT),
            (&new, Type::TEXT),
        ];
        let query = object.client().query_typed(
            "UPDATE users SET password_hash=$4 WHERE id=$1 AND email=$2 AND password_hash=$3",
            &params,
        );
        match tokio::time::timeout(self.timeouts.statement, query).await {
            Ok(Ok(_)) => {
                object.keep();
                Ok(())
            }
            Ok(Err(error)) => {
                if error.as_db_error().is_some() && !object.is_closed() {
                    object.keep();
                }
                Err(StatementFailure::from_db(&error))
            }
            Err(_) => Err(StatementFailure::refused("credential upgrade timed out")),
        }
    }

    /// Pre-authentication protocol audit row (`pwhash.LogAuthEvent`).
    pub async fn record_protocol_auth_event(
        &self,
        user: Option<i64>,
        event: &str,
        provider: &str,
        email: Option<&str>,
        ip: Option<&str>,
    ) -> Result<(), StatementFailure> {
        self.record_protocol_auth_event_with_details(user, event, provider, email, ip, None)
            .await
    }

    /// Pre-authentication protocol audit row with optional JSONB `details`.
    pub async fn record_protocol_auth_event_with_details(
        &self,
        user: Option<i64>,
        event: &str,
        provider: &str,
        email: Option<&str>,
        ip: Option<&str>,
        details: Option<&str>,
    ) -> Result<(), StatementFailure> {
        self.protocol_write(
            "INSERT INTO auth_event_log (user_id, event, provider, email, ip_address, details) \
             VALUES ($1, $2, $3, $4, $5::text::inet, $6::text::jsonb)",
            &[
                (&user, Type::INT8),
                (&event, Type::TEXT),
                (&provider, Type::TEXT),
                (&email, Type::TEXT),
                (&ip, Type::TEXT),
                (&details, Type::TEXT),
            ],
        )
        .await
    }

    /// IMAP command audit row (`connState.auditLog`).
    pub async fn record_mailbox_audit(
        &self,
        mailbox: i64,
        actor: i64,
        action: &str,
    ) -> Result<(), StatementFailure> {
        let message: Option<i64> = None;
        self.protocol_write(
            "INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id) \
             VALUES ($1, $2, $3, $4)",
            &[
                (&mailbox, Type::INT8),
                (&actor, Type::INT8),
                (&action, Type::TEXT),
                (&message, Type::INT8),
            ],
        )
        .await
    }

    /// `pwhash.CheckAppPassword` success bookkeeping.
    pub async fn touch_app_password(
        &self,
        user: i64,
        token_hash: &str,
    ) -> Result<(), StatementFailure> {
        self.protocol_write(
            "UPDATE app_passwords SET last_used_at = now() \
             WHERE user_id = $1 AND token_hash = $2 AND revoked_at IS NULL",
            &[(&user, Type::INT8), (&token_hash, Type::TEXT)],
        )
        .await?;
        self.protocol_write(
            "UPDATE users SET last_login_at = now() WHERE id = $1",
            &[(&user, Type::INT8)],
        )
        .await
    }

    /// One autocommit statement of the IMAP mailbox-management commands.
    pub async fn protocol_statement(
        &self,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<(), StatementFailure> {
        self.protocol_write(sql, params).await
    }

    async fn protocol_write(
        &self,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<(), StatementFailure> {
        self.protocol_query(sql, params).await.map(|_| ())
    }

    /// Best-effort authentication-time statement with a returned decision.
    pub async fn protocol_query(
        &self,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        let object = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        let object = ReadLease(Some(object));
        let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
        match tokio::time::timeout(
            self.timeouts.statement,
            object.client().query_typed(sql, &typed),
        )
        .await
        {
            Ok(Ok(rows)) => {
                object.keep();
                Ok(rows)
            }
            Ok(Err(error)) => {
                if error.as_db_error().is_some() && !object.is_closed() {
                    object.keep();
                }
                Err(StatementFailure::from_db(&error))
            }
            Err(_) => Err(StatementFailure::refused("protocol write timed out")),
        }
    }

    /// Best-effort authentication-time statement; returns the rows affected.
    pub async fn protocol_statement_count(
        &self,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<u64, StatementFailure> {
        let object = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        let object = ReadLease(Some(object));
        let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
        match tokio::time::timeout(
            self.timeouts.statement,
            object.client().execute_typed(sql, &typed),
        )
        .await
        {
            Ok(Ok(count)) => {
                object.keep();
                Ok(count)
            }
            Ok(Err(error)) => {
                if error.as_db_error().is_some() && !object.is_closed() {
                    object.keep();
                }
                Err(StatementFailure::from_db(&error))
            }
            Err(_) => Err(StatementFailure::refused("protocol write timed out")),
        }
    }

    /// Frozen Go list handlers which ignore `Rows.Err` retain rows delivered
    /// before an iteration error.
    pub async fn read_iterated(
        &self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        admit_select(sql).map_err(StatementFailure::refused)?;
        let deadline = Instant::now() + self.timeouts.statement;
        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StatementFailure::refused("read timed out"));
            }
            let object = self
                .pool
                .get()
                .await
                .map_err(|_| StatementFailure::refused("pool unavailable"))?;
            let object = ReadLease(Some(object));
            let mut rows = Vec::new();
            let mut described = false;
            let result = tokio::time::timeout(remaining, async {
                let stream = object
                    .client()
                    .query_typed_raw(sql, params.iter().map(|(v, t)| (*v, t.clone())))
                    .await?;
                described = true;
                futures_util::pin_mut!(stream);
                while let Some(row) = stream.try_next().await? {
                    rows.push(row);
                }
                Ok::<_, tokio_postgres::Error>(())
            })
            .await;
            match result {
                Ok(Ok(())) => {
                    object.keep();
                    return Ok(rows);
                }
                Ok(Err(error)) => {
                    if attempt == 0 && !described && error.as_db_error().is_none() {
                        drop(object);
                        continue;
                    }
                    if error.as_db_error().is_some() && !object.is_closed() {
                        object.keep();
                    }
                    if described {
                        return Ok(rows);
                    } else {
                        return Err(StatementFailure::from_db(&error));
                    }
                }
                Err(_) => {
                    if described {
                        return Ok(rows);
                    } else {
                        return Err(StatementFailure::refused("read timed out"));
                    }
                }
            }
        }
        Err(StatementFailure::refused("pool unavailable"))
    }

    /// Run one read-only `SELECT` in its own `READ ONLY` transaction scoped
    /// to `auth`'s mailbox (#216).
    pub async fn read_scoped(
        &self,
        auth: &MailboxAuthContext,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.read_scoped_with_lock(auth, sql, params, None).await
    }

    /// A mailbox-less, verified actor's read-only user-domain query.
    pub async fn read_user_scoped(
        &self,
        actor: setjoin_contracts::ids::ActorId,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        admit_select(sql).map_err(StatementFailure::refused)?;
        let encoded = pre_encode_params(params)?;
        let deadline = Instant::now() + self.timeouts.statement * 2;
        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StatementFailure::refused("read timed out"));
            }
            let object = ReadLease(Some(
                self.pool
                    .get()
                    .await
                    .map_err(|_| StatementFailure::refused("pool unavailable"))?,
            ));
            let begin = build_begin_sql(
                "BEGIN READ ONLY",
                self.timeouts.statement,
                PlanCacheHint::Auto,
            );
            let actor_str = actor.decimal();
            let scope_params: [Param<'_>; 1] = [(&actor_str, Type::TEXT)];
            let typed: Vec<Param<'_>> = encoded.iter().map(PreEncodedParam::as_param).collect();
            let client = object.client();
            let work = tokio::time::timeout(remaining, async {
                tokio::join!(
                    biased;
                    client.batch_execute(&begin),
                    client.query_typed(USER_SCOPE, &scope_params),
                    client.query_typed(sql, &typed),
                    client.batch_execute("COMMIT"),
                )
            })
            .await;
            let Ok((begin_res, scope_res, query_res, commit_res)) = work else {
                return Err(StatementFailure::refused("read timed out"));
            };
            if let Err(e) = begin_res {
                if attempt == 0 && e.as_db_error().is_none() {
                    drop(object);
                    continue;
                }
                return Err(StatementFailure::from_db(&e));
            }
            if let Err(e) = scope_res {
                return Err(StatementFailure::from_db(&e));
            }
            if let Err(e) = query_res {
                return Err(StatementFailure::from_db(&e));
            }
            match commit_res {
                Ok(()) => {
                    let rows = query_res.expect("checked Ok");
                    if !object.is_closed() {
                        object.keep();
                    }
                    return Ok(rows);
                }
                Err(e) => return Err(StatementFailure::from_db(&e)),
            }
        }
        Err(StatementFailure::refused("pool unavailable"))
    }

    /// Go's independent console guard audit.
    pub async fn audit_console_denied(
        &self,
        actor: setjoin_contracts::ids::ActorId,
        before: &str,
        path: &str,
    ) -> Result<(), StatementFailure> {
        self.protocol_write(
            "SELECT audit_write(NULL,'console.denied','console',NULL,$2::text::jsonb,NULL,NULL,$3,'core') WHERE $1::bigint>0",
            &[(&actor.get(), Type::INT8), (&before, Type::TEXT), (&path, Type::TEXT)],
        )
        .await
    }

    /// Go's independent best-effort app-denial audit.
    pub async fn audit_app_blocked(
        &self,
        actor: setjoin_contracts::ids::ActorId,
        app: &str,
        ip: &str,
    ) -> Result<(), StatementFailure> {
        self.protocol_write(
            "SELECT audit_write($1,'app_blocked','app',NULL,NULL,NULL,$2::text::inet,$3,'routine')",
            &[
                (&actor.get(), Type::INT8),
                (&ip, Type::TEXT),
                (&app, Type::TEXT),
            ],
        )
        .await
    }

    /// Go's JMAP dispatch app-denial audit.
    pub async fn audit_app_blocked_without_ip(
        &self,
        actor: setjoin_contracts::ids::ActorId,
        app: &str,
    ) -> Result<(), StatementFailure> {
        self.protocol_write(
            "SELECT audit_write($1,'app_blocked','app',NULL,NULL,NULL,NULL::inet,$2,'routine')",
            &[(&actor.get(), Type::INT8), (&app, Type::TEXT)],
        )
        .await
    }

    pub(crate) async fn read_scoped_with_lock(
        &self,
        auth: &MailboxAuthContext,
        sql: &str,
        params: &[Param<'_>],
        operation_lock: Option<&str>,
    ) -> Result<Vec<Row>, StatementFailure> {
        admit_select(sql).map_err(StatementFailure::refused)?;
        let encoded = pre_encode_params(params)?;
        let auth = self.transaction_auth(auth);
        let preamble = Preamble {
            mailbox: auth
                .mailbox_optional()
                .map(|m| m.decimal())
                .unwrap_or_default(),
            actor: auth.actor().decimal(),
            operation_id: None,
            audit_keys: auth.audit_keys.clone(),
            lock_key: operation_lock.map(str::to_owned),
        };
        let preamble_step = preamble.to_step()?;
        let isolation = if operation_lock.is_some() {
            "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY"
        } else {
            "BEGIN READ ONLY"
        };
        let begin = build_begin_sql(isolation, self.timeouts.statement, PlanCacheHint::Auto);
        let deadline = Instant::now() + self.timeouts.statement * 2;

        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(StatementFailure::refused("read timed out"));
            }
            let object = self
                .pool
                .get()
                .await
                .map_err(|_| StatementFailure::refused("pool unavailable"))?;
            let object = ReadLease(Some(object));
            let typed: Vec<Param<'_>> = encoded.iter().map(PreEncodedParam::as_param).collect();
            let client = object.client();
            let result = tokio::time::timeout(remaining, async {
                tokio::join!(
                    biased;
                    client.batch_execute(&begin),
                    preamble_step.execute(client),
                    client.query_typed(sql, &typed),
                    client.batch_execute("COMMIT"),
                )
            })
            .await;
            let Ok((begin_res, preamble_res, query_res, commit_res)) = result else {
                return Err(StatementFailure::refused("read timed out"));
            };
            if let Err(e) = begin_res {
                if attempt == 0 && e.as_db_error().is_none() {
                    drop(object);
                    continue;
                }
                return Err(StatementFailure::from_db(&e));
            }
            if let Err(e) = preamble_res {
                return Err(StatementFailure::from_db(&e));
            }
            if let Err(e) = query_res {
                return Err(StatementFailure::from_db(&e));
            }
            match commit_res {
                Ok(()) => {
                    let rows = query_res.expect("checked Ok");
                    if !object.is_closed() {
                        object.keep();
                    }
                    return Ok(rows);
                }
                Err(e) => return Err(StatementFailure::from_db(&e)),
            }
        }
        Err(StatementFailure::refused("pool unavailable"))
    }

    /// Run `body` in one transaction scoped to `auth`'s mailbox.
    pub async fn run<C, T, E, F>(
        &self,
        envelope: &CommandEnvelope<C>,
        auth: &MailboxAuthContext,
        deadline: Instant,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut ScopedTx) -> Result<T, E>,
    {
        self.run_with_lock(envelope, auth, deadline, None, body)
            .await
    }

    pub(crate) async fn run_with_lock<C, T, E, F>(
        &self,
        envelope: &CommandEnvelope<C>,
        auth: &MailboxAuthContext,
        deadline: Instant,
        operation_lock: Option<&str>,
        body: F,
    ) -> CommandOutcome<T, E>
    where
        F: AsyncFnOnce(&mut ScopedTx) -> Result<T, E>,
    {
        let current = auth.authority();
        if let Err(e) = envelope.validate(current, accepted_contract()) {
            return CommandOutcome::RolledBack(Rejection::Authority(LifecycleError::Contract(e)));
        }
        let lifecycle = match TransactionLifecycle::new(envelope, deadline) {
            Ok(l) => l,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Authority(e)),
        };
        let tx_auth = self.transaction_auth(auth);
        let operation = envelope.operation;
        let preamble = Preamble {
            mailbox: tx_auth
                .mailbox_optional()
                .map(|m| m.decimal())
                .unwrap_or_default(),
            actor: tx_auth.actor().decimal(),
            operation_id: None,
            audit_keys: tx_auth.audit_keys.clone(),
            lock_key: operation_lock.map(str::to_owned),
        };
        let preamble_step = match preamble.to_step() {
            Ok(s) => s,
            Err(f) => return CommandOutcome::RolledBack(Rejection::Statement(f)),
        };

        // 2-RTT interactive BEGIN with stale-socket 1-retry strictly BEFORE any
        // business SQL is sent (never returning spurious CommandOutcome::Unknown
        // when RecyclingMethod::Fast hands out a dead idle socket).
        let mut lease_opt = None;
        for attempt in 0..2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return CommandOutcome::RolledBack(Rejection::Authority(
                    LifecycleError::DeadlineElapsed,
                ));
            }
            let Ok(object) = self.pool.get().await else {
                return CommandOutcome::RolledBack(Rejection::Unavailable);
            };
            let lease = Lease(Some(object));
            let begin = format!("BEGIN; {}", statement_timeout_sql(remaining));
            let client = lease.client();
            let begun = tokio::time::timeout(remaining, async {
                tokio::join!(
                    biased;
                    client.batch_execute(&begin),
                    preamble_step.execute(client),
                )
            })
            .await;
            match begun {
                Ok((Ok(()), Ok(_))) => {
                    lease_opt = Some(lease);
                    break;
                }
                Ok((Err(e), _)) if attempt == 0 && e.as_db_error().is_none() => {
                    // Dead idle socket before any business SQL: quarantine & retry once.
                    drop(lease);
                    continue;
                }
                Ok((Err(_), _)) | Err(_) => {
                    drop(lease);
                    return CommandOutcome::RolledBack(Rejection::Unavailable);
                }
                Ok((Ok(()), Err(e))) => {
                    let failure = StatementFailure::from_db(&e);
                    if e.as_db_error().is_some()
                        && matches!(lease.client().batch_execute("ROLLBACK").await, Ok(()))
                        && !lease.is_closed()
                    {
                        let mut l = lease;
                        l.release(ConnectionDisposition::VerifyDriverReset);
                    }
                    return CommandOutcome::RolledBack(Rejection::Statement(failure));
                }
            }
        }

        let Some(lease) = lease_opt else {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        };

        let mut tx = ScopedTx {
            lease,
            lifecycle,
            auth: tx_auth,
            failure: None,
        };

        let result = Some(body(&mut tx).await);
        tx.finish(result, operation).await
    }
}

/// A read's pooled connection: quarantined with a PgBouncer-safe bounded
/// `CancelRequest` on drop unless [`ReadLease::keep`] returns it after a clean
/// answer.
struct ReadLease(Option<PoolLease>);

impl ReadLease {
    fn keep(mut self) {
        if let Some(lease) = self.0.take() {
            lease.keep();
        }
    }

    fn client(&self) -> &Client {
        self.0.as_ref().expect("lease held").client()
    }

    fn is_closed(&self) -> bool {
        self.0.as_ref().is_none_or(|l| l.is_closed())
    }
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            lease.quarantine();
        }
    }
}

/// Why the transaction must not commit (first failure wins).
#[derive(Debug)]
enum Failure {
    Statement(StatementFailure),
    Authority(LifecycleError),
    CommitRefused(String),
}

/// Pooled connection that is quarantined with a PgBouncer-safe bounded
/// `CancelRequest` on drop unless marked reusable.
struct Lease(Option<PoolLease>);

impl Lease {
    fn client(&self) -> &Client {
        self.0.as_ref().expect("lease held until finish").client()
    }

    fn is_closed(&self) -> bool {
        self.0.as_ref().is_none_or(|l| l.is_closed())
    }

    fn release(&mut self, disposition: ConnectionDisposition) {
        if let Some(lease) = self.0.take() {
            if disposition == ConnectionDisposition::VerifyDriverReset && !lease.is_closed() {
                lease.keep();
            } else {
                lease.quarantine();
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.release(ConnectionDisposition::Quarantine);
    }
}

/// The open, mailbox-scoped transaction handed to a command body.
pub struct ScopedTx {
    lease: Lease,
    lifecycle: TransactionLifecycle,
    auth: MailboxAuthContext,
    failure: Option<Failure>,
}

impl ScopedTx {
    /// The authenticated mailbox; bind it as the ownership predicate (R1/R3).
    pub fn mailbox(&self) -> MailboxId {
        self.auth.mailbox()
    }

    /// Run one admitted statement and return its rows.
    pub async fn query(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.statement(sql, params).await.map(|(rows, _)| rows)
    }

    /// Run one admitted statement and return the affected-row count.
    pub async fn execute(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<u64, StatementFailure> {
        self.statement(sql, params).await.map(|(_, n)| n)
    }

    fn client(&self) -> &Client {
        self.lease.client()
    }

    async fn statement(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<(Vec<Row>, u64), StatementFailure> {
        if let Err(reason) = admit(sql) {
            let failure = StatementFailure::refused(reason);
            self.fail(Failure::Statement(failure.clone()));
            return Err(failure);
        }
        self.send(sql, params).await
    }

    async fn send(
        &mut self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<(Vec<Row>, u64), StatementFailure> {
        if let Some(prior) = &self.failure {
            return Err(match prior {
                Failure::Statement(f) => f.clone(),
                Failure::Authority(_) | Failure::CommitRefused(_) => {
                    StatementFailure::refused("authority check failed")
                }
            });
        }
        if let Err(e) = self
            .lifecycle
            .check_current_key(self.auth.authority(), Instant::now())
        {
            self.fail(Failure::Authority(e));
            return Err(StatementFailure::refused("authority check failed"));
        }
        let result = async {
            let stream = self
                .client()
                .query_typed_raw(sql, params.iter().map(|(v, t)| (*v, t.clone())))
                .await?;
            futures_util::pin_mut!(stream);
            let mut rows = Vec::new();
            while let Some(row) = stream.try_next().await? {
                rows.push(row);
            }
            Ok::<_, tokio_postgres::Error>((rows, stream.rows_affected().unwrap_or(0)))
        }
        .await;
        result.map_err(|e| {
            self.lost_if_disconnected(&e);
            let failure = StatementFailure::from_db(&e);
            self.fail(Failure::Statement(failure.clone()));
            failure
        })
    }

    fn fail(&mut self, failure: Failure) {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
    }

    fn lost_if_disconnected(&mut self, e: &tokio_postgres::Error) {
        if e.as_db_error().is_none() || self.client().is_closed() {
            self.lifecycle.connection_lost();
        }
    }

    async fn finish<T, E>(
        mut self,
        result: Option<Result<T, E>>,
        operation: setjoin_contracts::ids::OperationId,
    ) -> CommandOutcome<T, E> {
        let mut outcome_value = None;
        let mut body_error = None;
        match result {
            Some(Ok(v)) => outcome_value = Some(v),
            Some(Err(e)) => body_error = Some(e),
            None => {}
        }

        if matches!(self.lifecycle.phase(), Phase::Active)
            && self.failure.is_none()
            && outcome_value.is_some()
        {
            match self
                .lifecycle
                .request_commit(self.auth.authority(), Instant::now())
            {
                Ok(()) => {
                    let observation = match self.client().batch_execute("COMMIT").await {
                        Ok(()) => CommitObservation::Committed,
                        Err(e) => {
                            let code = e.code().map(|c| c.code().to_owned());
                            let observation = commit_failure_observation(code.as_deref());
                            if let (CommitObservation::RolledBack, Some(code)) = (observation, code)
                            {
                                self.failure = Some(Failure::CommitRefused(code));
                            }
                            observation
                        }
                    };
                    let _ = self.lifecycle.observe_commit(observation);
                }
                Err(e) => self.fail(Failure::Authority(e)),
            }
        }

        if matches!(
            self.lifecycle.phase(),
            Phase::Active | Phase::RollbackPending
        ) {
            let _ = self.lifecycle.request_rollback();
            let observation = match self.client().batch_execute("ROLLBACK").await {
                Ok(()) => RollbackObservation::Acknowledged,
                Err(_) => RollbackObservation::Unknown,
            };
            let _ = self.lifecycle.observe_rollback(observation);
        }

        let disposition = self.lifecycle.connection_disposition();
        self.lease.release(disposition);

        match self.lifecycle.phase() {
            Phase::Terminal(CommitObservation::Committed) => match outcome_value {
                Some(v) => CommandOutcome::Committed(v),
                None => CommandOutcome::Unknown { operation },
            },
            Phase::Terminal(CommitObservation::RolledBack) => {
                CommandOutcome::RolledBack(match (self.failure, body_error) {
                    (Some(Failure::Statement(f)), _) => Rejection::Statement(f),
                    (Some(Failure::CommitRefused(code)), _) => Rejection::CommitRefused(code),
                    (Some(Failure::Authority(e)), _) => Rejection::Authority(e),
                    (None, Some(e)) => Rejection::Body(e),
                    (None, None) => Rejection::Unavailable,
                })
            }
            _ => CommandOutcome::Unknown { operation },
        }
    }
}

impl StatementFailure {
    pub(crate) fn from_db(e: &tokio_postgres::Error) -> Self {
        Self {
            hint: e.as_db_error().and_then(|db| db.hint()).map(str::to_owned),
            sqlstate: e.code().map(|c| c.code().to_owned()),
            message: e
                .as_db_error()
                .map(|db| db.message().to_owned())
                .unwrap_or_else(|| e.to_string()),
        }
    }

    pub(crate) fn refused(reason: &'static str) -> Self {
        Self {
            hint: None,
            sqlstate: None,
            message: format!("refused by executor: {reason}"),
        }
    }

    pub(crate) fn refused_owned(reason: String) -> Self {
        Self {
            hint: None,
            sqlstate: None,
            message: format!("refused by executor: {reason}"),
        }
    }
}

impl ScopedExecutor {
    /// Authentication-time user command (#331).
    pub async fn run_user_command<T, D>(
        &self,
        user: setjoin_contracts::ids::ActorId,
        operation: setjoin_contracts::ids::OperationId,
        sql: &'static str,
        params: &[Param<'_>],
        decode: D,
    ) -> CommandOutcome<T, StatementFailure>
    where
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
    {
        self.run_user_command_with_tail(user, operation, sql, params, decode, |_| {
            std::future::ready(())
        })
        .await
    }

    /// Go-compatible independent best-effort effect after the reducer result,
    /// before COMMIT.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_command_with_tail<T, D, F, Fut>(
        &self,
        user: setjoin_contracts::ids::ActorId,
        operation: setjoin_contracts::ids::OperationId,
        sql: &'static str,
        params: &[Param<'_>],
        decode: D,
        tail: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
        F: FnOnce(&T) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        self.run_user_command_inner(
            user,
            operation,
            sql,
            params,
            |_| std::future::ready(Ok(None)),
            decode,
            tail,
        )
        .await
    }

    /// Hold credential/person/user fences through synchronous audited crypto
    /// validation and the one reducer write.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_proof_command<T, P, D>(
        &self,
        user: setjoin_contracts::ids::ActorId,
        operation: setjoin_contracts::ids::OperationId,
        proof_sql: &'static str,
        params: &[Param<'_>],
        prove: P,
        decode: D,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(&[Row]) -> Result<ProvenStatement, StatementFailure>,
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
    {
        self.run_user_command_inner(
            user,
            operation,
            proof_sql,
            params,
            |rows| std::future::ready(prove(rows).map(Some)),
            decode,
            |_| std::future::ready(()),
        )
        .await
    }

    /// Authentication completion may await independent admission reads/signing
    /// while its credential fence stays held.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_async_proof_command_with_tail<T, P, PF, D, F, Fut>(
        &self,
        user: setjoin_contracts::ids::ActorId,
        operation: setjoin_contracts::ids::OperationId,
        proof_sql: &'static str,
        params: &[Param<'_>],
        prove: P,
        decode: D,
        tail: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(&[Row]) -> PF,
        PF: std::future::Future<Output = Result<ProvenStatement, StatementFailure>>,
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
        F: FnOnce(&T) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        self.run_user_command_inner(
            user,
            operation,
            proof_sql,
            params,
            |rows| {
                let future = prove(rows);
                async move { future.await.map(Some) }
            },
            decode,
            tail,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_user_command_inner<T, P, PF, D, F, Fut>(
        &self,
        user: setjoin_contracts::ids::ActorId,
        operation: setjoin_contracts::ids::OperationId,
        sql: &'static str,
        params: &[Param<'_>],
        prepare: P,
        decode: D,
        tail: F,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(&[Row]) -> PF,
        PF: std::future::Future<Output = Result<Option<ProvenStatement>, StatementFailure>>,
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
        F: FnOnce(&T) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        if let Err(e) = admit(sql) {
            return CommandOutcome::RolledBack(Rejection::Statement(StatementFailure::refused(e)));
        }
        let mut lease_opt = None;
        for attempt in 0..2 {
            let object = match self.pool.get().await {
                Ok(o) => ReadLease(Some(o)),
                Err(_) => return CommandOutcome::RolledBack(Rejection::Unavailable),
            };
            match tokio::time::timeout(
                self.timeouts.statement,
                object.client().batch_execute("BEGIN"),
            )
            .await
            {
                Ok(Ok(())) => {
                    lease_opt = Some(object);
                    break;
                }
                Ok(Err(e)) if attempt == 0 && e.as_db_error().is_none() => {
                    drop(object);
                    continue;
                }
                _ => return CommandOutcome::RolledBack(Rejection::Unavailable),
            }
        }
        let Some(object) = lease_opt else {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        };
        let user = user.get().to_string();
        let op = crate::operation_hex(operation);
        let lock = format!("setjoin-auth-command:{user}:{op}");
        let result = async {
            if let Some(keys) = &self.audit_keys {
                object
                    .client()
                    .query_typed(
                        "SELECT set_config('app.current_user_id',$1,true),\
                         pg_advisory_xact_lock(hashtextextended($2,0)),\
                         set_config('app.rust_operation_id',$3,true),\
                         set_config('app.encryption_key',$4,true),\
                         set_config('app.audit_hmac_key',$5,true)",
                        &[
                            (&user, Type::TEXT),
                            (&lock, Type::TEXT),
                            (&op, Type::TEXT),
                            (&keys.encryption, Type::TEXT),
                            (&keys.audit_hmac, Type::TEXT),
                        ],
                    )
                    .await
                    .map_err(|e| StatementFailure::from_db(&e))?;
            } else {
                object
                    .client()
                    .query_typed(
                        "SELECT set_config('app.current_user_id',$1,true),\
                         pg_advisory_xact_lock(hashtextextended($2,0)),\
                         set_config('app.rust_operation_id',$3,true)",
                        &[(&user, Type::TEXT), (&lock, Type::TEXT), (&op, Type::TEXT)],
                    )
                    .await
                    .map_err(|e| StatementFailure::from_db(&e))?;
            }
            let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
            let rows = object
                .client()
                .query_typed(sql, &typed)
                .await
                .map_err(|e| StatementFailure::from_db(&e))?;
            let rows = if let Some(proven) = prepare(&rows).await? {
                admit(proven.sql).map_err(StatementFailure::refused)?;
                let typed: Vec<_> = proven
                    .params
                    .iter()
                    .map(|(v, t)| (v.as_ref() as &(dyn ToSql + Sync), t.clone()))
                    .collect();
                object
                    .client()
                    .query_typed(proven.sql, &typed)
                    .await
                    .map_err(|e| StatementFailure::from_db(&e))?
            } else {
                rows
            };
            let value = decode(&rows)?;
            if let Some(receipt) = self.user_receipt {
                object
                    .client()
                    .query_typed(
                        "INSERT INTO public.rust_operation_receipts(operation_id,family,command) \
                         VALUES(substr(encode(digest($1::text || ':' || $2::text,'sha256'),'hex'),1,32)::uuid,$3,$4)",
                        &[
                            (&op, Type::TEXT),
                            (&user, Type::TEXT),
                            (&receipt.family, Type::TEXT),
                            (&receipt.command, Type::TEXT),
                        ],
                    )
                    .await
                    .map_err(|e| StatementFailure::from_db(&e))?;
            }
            Ok(value)
        };
        let result = match tokio::time::timeout(self.timeouts.statement, result).await {
            Ok(r) => r,
            Err(_) => Err(StatementFailure::refused("user command timed out")),
        };
        let value = match result {
            Ok(v) => v,
            Err(e) => {
                if matches!(
                    tokio::time::timeout(
                        self.timeouts.statement,
                        object.client().batch_execute("ROLLBACK"),
                    )
                    .await,
                    Ok(Ok(()))
                ) && !object.is_closed()
                {
                    object.keep();
                }
                return CommandOutcome::RolledBack(Rejection::Statement(e));
            }
        };
        let _ = tokio::time::timeout(self.timeouts.statement, tail(&value)).await;
        match tokio::time::timeout(
            self.timeouts.statement,
            object.client().batch_execute("COMMIT"),
        )
        .await
        {
            Ok(Ok(())) => {
                if !object.is_closed() {
                    object.keep();
                }
                CommandOutcome::Committed(value)
            }
            Ok(Err(e)) => {
                let code = e.as_db_error().map(|d| d.code().code());
                if commit_failure_observation(code) == CommitObservation::RolledBack {
                    let code = code.unwrap_or("").to_owned();
                    if !object.is_closed() {
                        object.keep();
                    }
                    CommandOutcome::RolledBack(Rejection::CommitRefused(code))
                } else {
                    CommandOutcome::Unknown { operation }
                }
            }
            Err(_) => CommandOutcome::Unknown { operation },
        }
    }
}

impl ScopedExecutor {
    /// One acknowledged anonymous protocol command.
    pub async fn run_protocol_command<T, D>(
        &self,
        scope: &str,
        operation: setjoin_contracts::ids::OperationId,
        command: crate::ReceiptCommand,
        sql: &'static str,
        params: &[Param<'_>],
        decode: D,
    ) -> CommandOutcome<T, StatementFailure>
    where
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
    {
        if let Err(e) = admit(sql) {
            return CommandOutcome::RolledBack(Rejection::Statement(StatementFailure::refused(e)));
        }
        let mut lease_opt = None;
        for attempt in 0..2 {
            let object = match self.pool.get().await {
                Ok(o) => ReadLease(Some(o)),
                Err(_) => return CommandOutcome::RolledBack(Rejection::Unavailable),
            };
            match tokio::time::timeout(
                self.timeouts.statement,
                object.client().batch_execute("BEGIN"),
            )
            .await
            {
                Ok(Ok(())) => {
                    lease_opt = Some(object);
                    break;
                }
                Ok(Err(e)) if attempt == 0 && e.as_db_error().is_none() => {
                    drop(object);
                    continue;
                }
                _ => return CommandOutcome::RolledBack(Rejection::Unavailable),
            }
        }
        let Some(object) = lease_opt else {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        };
        let op = crate::operation_hex(operation);
        let lock = format!("setjoin-protocol-command:{scope}:{op}");
        let result = tokio::time::timeout(self.timeouts.statement, async {
            object
                .client()
                .query_typed(
                    "SELECT set_config('app.current_user_id','',true),\
                     set_config('app.current_mailbox_id','',true),\
                     pg_advisory_xact_lock(hashtextextended($1,0))",
                    &[(&lock, Type::TEXT)],
                )
                .await
                .map_err(|e| StatementFailure::from_db(&e))?;
            let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
            let rows = object
                .client()
                .query_typed(sql, &typed)
                .await
                .map_err(|e| StatementFailure::from_db(&e))?;
            let value = decode(&rows)?;
            object
                .client()
                .query_typed(
                    "INSERT INTO public.rust_operation_receipts(operation_id,family,command) \
                     VALUES(substr(encode(digest($1::text || ':' || $2::text,'sha256'),'hex'),1,32)::uuid,$3,$4)",
                    &[
                        (&op, Type::TEXT),
                        (&scope, Type::TEXT),
                        (&command.family, Type::TEXT),
                        (&command.command, Type::TEXT),
                    ],
                )
                .await
                .map_err(|e| StatementFailure::from_db(&e))?;
            Ok(value)
        })
        .await
        .unwrap_or_else(|_| Err(StatementFailure::refused("protocol command timed out")));
        let value = match result {
            Ok(v) => v,
            Err(e) => {
                if matches!(
                    tokio::time::timeout(
                        self.timeouts.statement,
                        object.client().batch_execute("ROLLBACK"),
                    )
                    .await,
                    Ok(Ok(()))
                ) && !object.is_closed()
                {
                    object.keep();
                }
                return CommandOutcome::RolledBack(Rejection::Statement(e));
            }
        };
        match tokio::time::timeout(
            self.timeouts.statement,
            object.client().batch_execute("COMMIT"),
        )
        .await
        {
            Ok(Ok(())) => {
                if !object.is_closed() {
                    object.keep();
                }
                CommandOutcome::Committed(value)
            }
            Ok(Err(e))
                if commit_failure_observation(e.as_db_error().map(|d| d.code().code()))
                    == CommitObservation::RolledBack =>
            {
                let code = e
                    .as_db_error()
                    .map(|d| d.code().code())
                    .unwrap_or("")
                    .to_owned();
                if !object.is_closed() {
                    object.keep();
                }
                CommandOutcome::RolledBack(Rejection::CommitRefused(code))
            }
            _ => CommandOutcome::Unknown { operation },
        }
    }

    /// Wait for the original anonymous operation lock before observing its
    /// receipt.
    pub async fn lookup_protocol_operation(
        &self,
        scope: &str,
        operation: setjoin_contracts::ids::OperationId,
        command: crate::ReceiptCommand,
    ) -> Result<bool, StatementFailure> {
        let op = crate::operation_hex(operation);
        let lock = format!("setjoin-protocol-command:{scope}:{op}");
        for attempt in 0..2 {
            let object = self
                .pool
                .get()
                .await
                .map_err(|_| StatementFailure::refused("pool unavailable"))?;
            let object = ReadLease(Some(object));
            let client = object.client();
            let lock_params: [Param<'_>; 1] = [(&lock, Type::TEXT)];
            let lookup_params: [Param<'_>; 4] = [
                (&op, Type::TEXT),
                (&scope, Type::TEXT),
                (&command.family, Type::TEXT),
                (&command.command, Type::TEXT),
            ];
            let result = tokio::time::timeout(self.timeouts.statement, async {
                tokio::join!(
                    biased;
                    client.batch_execute("BEGIN"),
                    client.query_typed(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                        &lock_params,
                    ),
                    client.query_typed(
                        "SELECT EXISTS(SELECT 1 FROM public.rust_operation_receipts \
                         WHERE operation_id=substr(encode(digest($1::text || ':' || $2::text,'sha256'),'hex'),1,32)::uuid \
                         AND family=$3 AND command=$4)",
                        &lookup_params,
                    ),
                    client.batch_execute("COMMIT"),
                )
            })
            .await
            .map_err(|_| StatementFailure::refused("protocol lookup timed out"))?;
            let (begin_res, lock_res, query_res, commit_res) = result;
            if let Err(e) = begin_res {
                if attempt == 0 && e.as_db_error().is_none() {
                    drop(object);
                    continue;
                }
                return Err(StatementFailure::from_db(&e));
            }
            if let Err(e) = lock_res {
                return Err(StatementFailure::from_db(&e));
            }
            let rows = query_res.map_err(|e| StatementFailure::from_db(&e))?;
            commit_res.map_err(|e| StatementFailure::from_db(&e))?;
            if !object.is_closed() {
                object.keep();
            }
            return Ok(rows[0].get(0));
        }
        Err(StatementFailure::refused("pool unavailable"))
    }
}
