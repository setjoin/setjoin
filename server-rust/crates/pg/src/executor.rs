//! One transaction per command, scoped to the authenticated mailbox.
use crate::{
    auth::{AuditKeys, MailboxAuthContext},
    outcome::{commit_failure_observation, CommandOutcome, Rejection, StatementFailure},
    statement::admit,
};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use futures_util::TryStreamExt;
use setjoin_contracts::{
    command::{CommandEnvelope, CommitObservation, InfrastructureStatement},
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
use tokio_postgres::{
    types::{ToSql, Type},
    NoTls, Row,
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

// Acquiring the operation lock in the same round trip as the trusted scope
// ensures a receipt lookup waits for the writer without extending the
// reducer-to-COMMIT lock hold by another client round trip.
// Named infrastructure allowlist: command SQL still cannot SET any GUC.
pub(crate) const AUDIT_SCOPE: &str = "SELECT set_config('app.encryption_key', $1, true), \
    set_config('app.audit_hmac_key', $2, true)";

// User-scoped FORCE RLS (approvals and later families) uses the same verified
// actor as the command envelope. This named infrastructure GUC dies at commit.
const USER_SCOPE: &str = "SELECT set_config('app.current_user_id', $1, true)";

const LOCKED_MAILBOX_SCOPE: &str = "SELECT set_config('app.current_mailbox_id', $1, true), \
    pg_advisory_xact_lock(hashtextextended($2::text, 0))";

/// Error building a pool from a DSN.
#[derive(Debug)]
pub struct ConfigError(pub String);

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

/// Runs each command in its own scoped transaction over one credential's pool.
///
/// The pool's credential is the privilege boundary: build the request
/// executor from `DB_DSN` (constrained `setjoin_app` role, RLS applies) and a
/// cross-tenant worker from `DB_WORKER_DSN`. The executor never issues
/// `SET ROLE` and refuses any statement that would.
#[derive(Clone)]
pub struct ScopedExecutor {
    pool: Pool,
    timeouts: Timeouts,
    audit_keys: Option<Arc<AuditKeys>>,
    user_receipt: Option<crate::ReceiptCommand>,
}

impl ScopedExecutor {
    /// Wrap an existing pool. Its recycling method must not be `Fast` (which
    /// skips the liveness round trip); [`ScopedExecutor::from_dsn`] uses `Verified`.
    /// The read deadline is [`Timeouts::resolved`]'s; the pool's own wait and
    /// create bounds are whatever `pool` was built with.
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            timeouts: Timeouts::resolved(),
            audit_keys: None,
            user_receipt: None,
        }
    }

    /// Build a plaintext (`NoTls`) pool of `max_size` connections from a
    /// libpq-style DSN with [`Timeouts::resolved`]. TLS connectors are a later
    /// wiring decision.
    pub fn from_dsn(dsn: &str, max_size: usize) -> Result<Self, ConfigError> {
        Self::from_dsn_with(dsn, max_size, Timeouts::resolved())
    }

    /// [`ScopedExecutor::from_dsn`] with explicit [`Timeouts`].
    pub fn from_dsn_with(
        dsn: &str,
        max_size: usize,
        timeouts: Timeouts,
    ) -> Result<Self, ConfigError> {
        let config: tokio_postgres::Config = dsn
            .parse()
            .map_err(|e: tokio_postgres::Error| ConfigError(e.to_string()))?;
        let manager = Manager::from_config(
            config,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(max_size)
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(timeouts.pool_wait))
            .create_timeout(Some(timeouts.create))
            .recycle_timeout(Some(timeouts.create))
            .build()
            .map_err(|e| ConfigError(e.to_string()))?;
        Ok(Self {
            pool,
            timeouts,
            audit_keys: None,
            user_receipt: None,
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

    fn transaction_auth(&self, auth: &MailboxAuthContext) -> MailboxAuthContext {
        let mut auth = auth.clone();
        auth.audit_keys = self.audit_keys.clone();
        auth
    }

    /// Run one read-only `SELECT` outside any command transaction (autocommit,
    /// no tenant GUC) on the pool's credential, for the authentication-time
    /// lookups that precede a command (session revocation, guest status, the
    /// caller's primary mailbox) — the reads Go's gateway issues on its own
    /// pool before a reducer runs. The statement must pass [`admit`] and begin
    /// with `SELECT`; it is sent on the unnamed statement. A connection whose
    /// read failed without a server response is discarded, never pooled.
    pub async fn read(
        &self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        admit(sql).map_err(StatementFailure::refused)?;
        let first = sql
            .trim_start()
            .split(|c: char| !c.is_ascii_alphabetic())
            .next()
            .unwrap_or("");
        if !first.eq_ignore_ascii_case("select") {
            return Err(StatementFailure::refused("read accepts only a SELECT"));
        }
        let object = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        // Discarded on every path but a clean answer, including a caller
        // dropping this future mid-statement (review item 1).
        let object = ReadLease(Some(object));
        let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
        let query = object.query_typed(sql, &typed);
        // Autocommit: no transaction to carry SET LOCAL, so the bound is the
        // client-side deadline plus a cancel request for the statement.
        let result = match tokio::time::timeout(self.timeouts.statement, query).await {
            Ok(result) => result,
            Err(_) => {
                return Err(StatementFailure::refused("read timed out"));
            }
        };
        match result {
            Ok(rows) => {
                object.keep();
                Ok(rows)
            }
            Err(e) => {
                // A server-reported error leaves an autocommit connection
                // clean; anything else is discarded with the lease.
                if e.as_db_error().is_some() && !object.is_closed() {
                    object.keep();
                }
                Err(StatementFailure::from_db(&e))
            }
        }
    }

    /// Authentication-time best-effort CAS, mirroring pwhash.CheckPassword.
    /// The caller already verified this exact hash. Both identity and the old
    /// hash stay in the same UPDATE predicate; concurrent rotation/rename wins.
    /// Failure does not assert that an upgrade committed.
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
        let query = object.query_typed(
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

    /// Pre-authentication protocol audit row (`pwhash.LogAuthEvent`): one
    /// autocommit INSERT on the pool credential, no tenant scope. Frozen Go
    /// passes the IP as text into an INET column, so a `host:port` value fails
    /// the insert and Go swallows that error; the cast reproduces it and the
    /// caller ignores the result the same way.
    pub async fn record_protocol_auth_event(
        &self,
        user: Option<i64>,
        event: &str,
        provider: &str,
        email: Option<&str>,
        ip: Option<&str>,
    ) -> Result<(), StatementFailure> {
        self.protocol_write(
            "INSERT INTO auth_event_log (user_id, event, provider, email, ip_address, details) \
             VALUES ($1, $2, $3, $4, $5::text::inet, NULL)",
            &[
                (&user, Type::INT8),
                (&event, Type::TEXT),
                (&provider, Type::TEXT),
                (&email, Type::TEXT),
                (&ip, Type::TEXT),
            ],
        )
        .await
    }

    /// IMAP command audit row (`connState.auditLog`): one autocommit INSERT on
    /// the pool credential after the reply, no tenant GUC, ownership taken from
    /// the authenticated session (R2). Frozen Go ignores the result.
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

    /// `pwhash.CheckAppPassword` success bookkeeping: both guarded by the
    /// verified user id (and, for the token, its hash). Best effort in Go.
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

    /// One autocommit statement of the IMAP mailbox-management commands
    /// (CREATE/DELETE/RENAME): static SQL only, so request text can only travel
    /// as a bound parameter, on the pool credential with no tenant GUC like Go's
    /// plain-pool `Exec`. Ownership (R2/R3) is in the statement's own WHERE.
    pub async fn protocol_statement(
        &self,
        sql: &'static str,
        params: &[Param<'_>],
    ) -> Result<(), StatementFailure> {
        self.protocol_write(sql, params).await
    }

    async fn protocol_write(&self, sql: &'static str, params: &[Param<'_>]) -> Result<(), StatementFailure> {
        self.protocol_query(sql, params).await.map(|_| ())
    }

    /// Best-effort authentication-time statement with a returned decision.
    /// Caller supplies fixed SQL and credential-verified identity only.
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
        match tokio::time::timeout(self.timeouts.statement, object.query_typed(sql, &typed)).await {
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

    /// Frozen Go list handlers which ignore `Rows.Err` retain rows delivered
    /// before an iteration error. Errors before RowDescription remain errors.
    /// This opt-in read must never be used for admission or command authority.
    /// It retains the normal SELECT guard, credential and bounded waits.
    pub async fn read_iterated(
        &self,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        admit(sql).map_err(StatementFailure::refused)?;
        if !sql
            .trim_start()
            .split(|c: char| !c.is_ascii_alphabetic())
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("select"))
        {
            return Err(StatementFailure::refused("read accepts only a SELECT"));
        }
        let object = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        let object = ReadLease(Some(object));
        let mut rows = Vec::new();
        let mut described = false;
        let result = tokio::time::timeout(self.timeouts.statement, async {
            let stream = object
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
                Ok(rows)
            }
            Ok(Err(error)) => {
                if error.as_db_error().is_some() && !object.is_closed() {
                    object.keep();
                }
                if described {
                    Ok(rows)
                } else {
                    Err(StatementFailure::from_db(&error))
                }
            }
            Err(_) => {
                if described {
                    Ok(rows)
                } else {
                    Err(StatementFailure::refused("read timed out"))
                }
            }
        }
    }

    /// Run one read-only `SELECT` in its own `READ ONLY` transaction scoped
    /// to `auth`'s mailbox (#216): the Go seam a read reducer runs under
    /// (`reducercall.CallScoped`), minus the ability to write. Sequence:
    /// `BEGIN READ ONLY` → `set_config('app.current_mailbox_id', $1, true)`
    /// from `auth` → the statement → `COMMIT`. A read has no effect to
    /// commit, so it carries no envelope or operation ID; any failure —
    /// including a write attempted from inside the SELECT (SQLSTATE 25006) —
    /// is an `Err` and the caller decides (the gateway forwards to Go). The
    /// statement must pass [`admit`] and begin with `SELECT`; bind
    /// `auth.mailbox()` as its ownership predicate (R1). Any failure discards
    /// the connection rather than pooling it.
    pub async fn read_scoped(
        &self,
        auth: &MailboxAuthContext,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        self.read_scoped_with_lock(auth, sql, params, None).await
    }

    /// A mailbox-less, verified actor's read-only user-domain query. The GUC
    /// is transaction-local; family SQL must also bind this actor in its WHERE.
    pub async fn read_user_scoped(
        &self,
        actor: setjoin_contracts::ids::ActorId,
        sql: &str,
        params: &[Param<'_>],
    ) -> Result<Vec<Row>, StatementFailure> {
        admit(sql).map_err(StatementFailure::refused)?;
        if !sql
            .trim_start()
            .split_whitespace()
            .next()
            .is_some_and(|s| s.eq_ignore_ascii_case("SELECT"))
        {
            return Err(StatementFailure::refused("read accepts only a SELECT"));
        }
        let object = ReadLease(Some(
            self.pool
                .get()
                .await
                .map_err(|_| StatementFailure::refused("pool unavailable"))?,
        ));
        let work = async {
            object
                .batch_execute(&format!(
                    "BEGIN READ ONLY; {}",
                    statement_timeout_sql(self.timeouts.statement)
                ))
                .await?;
            object
                .query_typed(USER_SCOPE, &[(&actor.decimal(), Type::TEXT)])
                .await?;
            let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
            let rows = object.query_typed(sql, &typed).await?;
            object.batch_execute("COMMIT").await?;
            Ok::<_, tokio_postgres::Error>(rows)
        };
        match tokio::time::timeout(self.timeouts.statement * 2, work).await {
            Ok(Ok(rows)) => {
                object.keep();
                Ok(rows)
            }
            Ok(Err(error)) => Err(StatementFailure::from_db(&error)),
            Err(_) => Err(StatementFailure::refused("read timed out")),
        }
    }

    /// Go's independent console guard audit. Its durable actor is NULL;
    /// verified display identity, target and missing permission are before_state.
    pub async fn audit_console_denied(&self, actor:setjoin_contracts::ids::ActorId,
        before:&str,path:&str)->Result<(),StatementFailure>{
        self.protocol_write("SELECT audit_write(NULL,'console.denied','console',NULL,$2::text::jsonb,NULL,NULL,$3,'core') WHERE $1::bigint>0",
            &[(&actor.get(),Type::INT8),(&before,Type::TEXT),(&path,Type::TEXT)]).await
    }

    /// Go's independent best-effort app-denial audit: one canonical reducer
    /// statement, actor from verified authentication, no request-owned identity.
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

    /// Go's JMAP dispatch app-denial audit (`audit.Entry` without IP, handler.go:1550).
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
        admit(sql).map_err(StatementFailure::refused)?;
        let first = sql
            .trim_start()
            .split(|c: char| !c.is_ascii_alphabetic())
            .next()
            .unwrap_or("");
        if !first.eq_ignore_ascii_case("select") {
            return Err(StatementFailure::refused("read accepts only a SELECT"));
        }
        let object = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        // Discarded on every path but a clean answer, including a caller
        // dropping this future mid-statement (review item 1).
        let object = ReadLease(Some(object));
        let auth = self.transaction_auth(auth);
        let mailbox = auth.mailbox_optional().map(|m| m.decimal()).unwrap_or_default();
        // One simple-query message: no extra round trip for the bound.
        let isolation = if operation_lock.is_some() {
            // A pool may default to REPEATABLE READ. Receipt visibility must
            // use a fresh snapshot after waiting for the operation lock.
            "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY"
        } else {
            "BEGIN READ ONLY"
        };
        let begin = format!(
            "{isolation}; {}",
            statement_timeout_sql(self.timeouts.statement)
        );
        let result = async {
            object.batch_execute(&begin).await?;
            if let Some(lock) = operation_lock {
                object
                    .query_typed(
                        LOCKED_MAILBOX_SCOPE,
                        &[(&mailbox, Type::TEXT), (&lock, Type::TEXT)],
                    )
                    .await?;
            } else {
                object
                    .query_typed(
                        InfrastructureStatement::MailboxScope.sql(),
                        &[(&mailbox, Type::TEXT)],
                    )
                    .await?;
            }
            object
                .query_typed(USER_SCOPE, &[(&auth.actor().get().to_string(), Type::TEXT)])
                .await?;
            if let Some(keys) = &auth.audit_keys {
                object
                    .query_typed(
                        AUDIT_SCOPE,
                        &[
                            (&keys.encryption, Type::TEXT),
                            (&keys.audit_hmac, Type::TEXT),
                        ],
                    )
                    .await?;
            }
            // Receipt SELECT gets a fresh READ COMMITTED snapshot *after*
            // the writer releases the operation lock.
            let rows = object
                .query_typed(
                    sql,
                    &params
                        .iter()
                        .map(|(v, t)| (*v, t.clone()))
                        .collect::<Vec<_>>(),
                )
                .await?;
            object.batch_execute("COMMIT").await?;
            Ok::<_, tokio_postgres::Error>(rows)
        };
        // The server-side statement_timeout fires first on a stalled
        // statement; the client deadline covers a stalled network.
        let result = match tokio::time::timeout(self.timeouts.statement * 2, result).await {
            Ok(result) => result,
            Err(_) => {
                return Err(StatementFailure::refused("read timed out"));
            }
        };
        match result {
            Ok(rows) => {
                object.keep();
                Ok(rows)
            }
            Err(e) => {
                // Never pool a connection that may still hold the scoped
                // transaction: the next lease would inherit its GUC. The
                // lease is discarded on drop.
                Err(StatementFailure::from_db(&e))
            }
        }
    }

    /// Run `body` in one transaction scoped to `auth`'s mailbox.
    ///
    /// Sequence: validate the envelope against `auth` (nothing sent on
    /// failure) → acquire → `BEGIN` → `set_config('app.current_mailbox_id',
    /// $1, true)` with `$1` taken from `auth` → body → `COMMIT`, or
    /// `ROLLBACK` when the body errs, any statement failed or the authority
    /// check before COMMIT refuses. Every phase goes through
    /// [`TransactionLifecycle`]; the returned outcome is its terminal
    /// observation. `Unknown` is never reported as success and the connection
    /// behind it is discarded, never returned to the pool.
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
        let Ok(object) = self.pool.get().await else {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        };
        let mut tx = ScopedTx {
            lease: Lease(Some(object)),
            lifecycle,
            auth: self.transaction_auth(auth),
            failure: None,
        };
        let operation = envelope.operation;

        // From BEGIN on, the lifecycle phase alone decides the outcome. The
        // command deadline also bounds every statement server-side (one
        // simple-query message with BEGIN; no extra round trip).
        let begin = format!(
            "BEGIN; {}",
            statement_timeout_sql(deadline.saturating_duration_since(Instant::now()))
        );
        if let Err(e) = tx.client().batch_execute(&begin).await {
            tx.lost_if_disconnected(&e);
            if tx.failure.is_none() {
                tx.failure = Some(Failure::Statement(StatementFailure::from_db(&e)));
            }
        } else {
            tx.set_scope(operation_lock).await;
        }

        let result = if tx.failure.is_none() {
            Some(body(&mut tx).await)
        } else {
            None
        };
        tx.finish(result, operation).await
    }
}

/// Ask the server to cancel whatever the connection is running (bounded, in
/// the background). The caller then drops the lease, which discards it.
fn cancel(object: &ReadLease) {
    if let Some(o) = &object.0 {
        let token = o.cancel_token();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), token.cancel_query(NoTls)).await;
        });
    }
}

/// A read's pooled connection: discarded on drop (error, timeout, or the
/// caller dropping the read future mid-flight, which may leave it inside the
/// scoped `READ ONLY` transaction with the mailbox GUC set) unless
/// [`ReadLease::keep`] returns it after a clean answer.
struct ReadLease(Option<Object>);

impl ReadLease {
    fn keep(mut self) {
        // Dropping the Object itself returns it to the pool.
        drop(self.0.take());
    }
}

impl std::ops::Deref for ReadLease {
    type Target = Object;
    fn deref(&self) -> &Object {
        // Some until keep() or drop consume it.
        self.0.as_ref().expect("lease held")
    }
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        // Dropping tokio-postgres's Client can queue Terminate behind the
        // running query. Send CancelRequest while its backend token is still
        // available, including when a caller drops the read future mid-flight.
        if tokio::runtime::Handle::try_current().is_ok() {
            cancel(self);
        }
        if let Some(object) = self.0.take() {
            drop(Object::take(object));
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

/// Pooled connection that is discarded on drop unless marked reusable, so a
/// cancelled `run` future can never return an open transaction to the pool.
struct Lease(Option<Object>);

impl Lease {
    fn release(&mut self, disposition: ConnectionDisposition) {
        if let Some(object) = self.0.take() {
            if disposition != ConnectionDisposition::VerifyDriverReset {
                drop(Object::take(object));
            }
            // VerifyDriverReset: dropping returns it; the pool's Verified
            // recycle checks liveness before the next lease.
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.release(ConnectionDisposition::Quarantine);
    }
}

/// The open, mailbox-scoped transaction handed to a command body.
///
/// Every statement uses the unnamed statement (`query_typed`): Parse/Bind/
/// Execute/Sync with no statement name, so nothing outlives the round trip
/// and PgBouncer's transaction pool can route it. Results should use built-in
/// types (cast custom enums/domains to `text`), since an unknown result OID
/// makes the driver look the type up with a named statement.
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

    fn client(&self) -> &tokio_postgres::Client {
        self.lease.0.as_ref().expect("lease held until finish")
    }

    async fn set_scope(&mut self, operation_lock: Option<&str>) {
        let mailbox = self.auth.mailbox_optional().map(|m| m.decimal()).unwrap_or_default();
        if let Some(lock) = operation_lock {
            let _ = self
                .send(
                    LOCKED_MAILBOX_SCOPE,
                    &[(&mailbox, Type::TEXT), (&lock, Type::TEXT)],
                )
                .await;
        } else {
            let _ = self
                .send(
                    InfrastructureStatement::MailboxScope.sql(),
                    &[(&mailbox, Type::TEXT)],
                )
                .await;
        }
        let actor = self.auth.actor().get().to_string();
        let _ = self.send(USER_SCOPE, &[(&actor, Type::TEXT)]).await;
        if let Some(keys) = self.auth.audit_keys.clone() {
            let _ = self
                .send(
                    AUDIT_SCOPE,
                    &[
                        (&keys.encryption, Type::TEXT),
                        (&keys.audit_hmac, Type::TEXT),
                    ],
                )
                .await;
        }
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
            // PostgreSQL would answer 25P02; do not even send it.
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

    /// No server response (I/O error, closed socket): the lifecycle refuses
    /// to infer the outcome and quarantines the connection.
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

    fn refused(reason: &'static str) -> Self {
        Self {
            hint: None,
            sqlstate: None,
            message: format!("refused by executor: {reason}"),
        }
    }
}

impl ScopedExecutor {
    /// Authentication-time user command (#331). The caller has already proved
    /// the user's credential. No mailbox is invented for mailbox-less people.
    /// Infrastructure owns scope, operation lock and explicit COMMIT; business
    /// logic is exactly one statement/reducer. Unknown discards the connection.
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
    /// before COMMIT. The caller's tail must use a separate pool lease and must
    /// never publish credentials; it is bounded and its failure cannot abort
    /// the main transaction (frozen refresh auth-event ordering, #332).
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
        self.run_user_command_inner(user, operation, sql, params, |_| std::future::ready(Ok(None)), decode, tail)
            .await
    }

    /// Hold credential/person/user fences through synchronous audited crypto
    /// validation and the one reducer write. No connection escapes the bound;
    /// a cancelled proof discards it. The callback cannot publish credentials.
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
    /// while its credential fence stays held. The bounded callback selects the
    /// one reducer write; the independent tail never publishes a response.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_user_async_proof_command_with_tail<T,P,PF,D,F,Fut>(
        &self,user:setjoin_contracts::ids::ActorId,operation:setjoin_contracts::ids::OperationId,
        proof_sql:&'static str,params:&[Param<'_>],prove:P,decode:D,tail:F,
    )->CommandOutcome<T,StatementFailure>
    where P:FnOnce(&[Row])->PF,
        PF:std::future::Future<Output=Result<ProvenStatement,StatementFailure>>,
        D:FnOnce(&[Row])->Result<T,StatementFailure>,
        F:FnOnce(&T)->Fut,Fut:std::future::Future<Output=()>,
    {
        self.run_user_command_inner(user,operation,proof_sql,params,
            |rows| {let future=prove(rows);async move {future.await.map(Some)}},decode,tail).await
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
        PF: std::future::Future<Output=Result<Option<ProvenStatement>,StatementFailure>>,
        D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
        F: FnOnce(&T) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        if let Err(e) = admit(sql) {
            return CommandOutcome::RolledBack(Rejection::Statement(StatementFailure::refused(e)));
        }
        let object = match self.pool.get().await {
            Ok(o) => ReadLease(Some(o)),
            Err(_) => return CommandOutcome::RolledBack(Rejection::Unavailable),
        };
        let begun =
            tokio::time::timeout(self.timeouts.statement, object.batch_execute("BEGIN")).await;
        if !matches!(begun, Ok(Ok(()))) {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        }
        let user = user.get().to_string();
        let op = crate::operation_hex(operation);
        let lock = format!("setjoin-auth-command:{user}:{op}");
        let result = async {
            object.query_typed("SELECT set_config('app.current_user_id',$1,true),pg_advisory_xact_lock(hashtextextended($2,0)),set_config('app.rust_operation_id',$3,true)",&[(&user,Type::TEXT),(&lock,Type::TEXT),(&op,Type::TEXT)]).await.map_err(|e|StatementFailure::from_db(&e))?;
            if let Some(keys) = &self.audit_keys {
                object
                    .query_typed(
                        AUDIT_SCOPE,
                        &[
                            (&keys.encryption, Type::TEXT),
                            (&keys.audit_hmac, Type::TEXT),
                        ],
                    )
                    .await
                    .map_err(|e| StatementFailure::from_db(&e))?;
            }
            let typed: Vec<_> = params.iter().map(|(v, t)| (*v, t.clone())).collect();
            let rows = object
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
                    .query_typed(proven.sql, &typed)
                    .await
                    .map_err(|e| StatementFailure::from_db(&e))?
            } else {
                rows
            };
            let value = decode(&rows)?;
            if let Some(receipt) = self.user_receipt {
                object.query_typed(
                    "INSERT INTO public.rust_operation_receipts(operation_id,family,command) VALUES(substr(encode(digest($1::text || ':' || $2::text,'sha256'),'hex'),1,32)::uuid,$3,$4)",
                    &[(&op,Type::TEXT),(&user,Type::TEXT),(&receipt.family,Type::TEXT),(&receipt.command,Type::TEXT)],
                ).await.map_err(|e|StatementFailure::from_db(&e))?;
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
                    tokio::time::timeout(self.timeouts.statement, object.batch_execute("ROLLBACK"))
                        .await,
                    Ok(Ok(()))
                ) {
                    object.keep();
                }
                return CommandOutcome::RolledBack(Rejection::Statement(e));
            }
        };
        let _ = tokio::time::timeout(self.timeouts.statement, tail(&value)).await;
        match tokio::time::timeout(self.timeouts.statement, object.batch_execute("COMMIT")).await {
            Ok(Ok(())) => {
                object.keep();
                CommandOutcome::Committed(value)
            }
            Ok(Err(e)) => {
                let code = e.as_db_error().map(|d| d.code().code());
                if commit_failure_observation(code) == CommitObservation::RolledBack {
                    let code = code.unwrap_or("").to_owned();
                    object.keep();
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
    /// One acknowledged anonymous protocol command. The scope is code-owned
    /// credential metadata, never a user or mailbox identity. A returned row
    /// alone does not prove publication; COMMIT loss returns the operation ID.
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
        let object = match self.pool.get().await {
            Ok(o) => ReadLease(Some(o)),
            Err(_) => return CommandOutcome::RolledBack(Rejection::Unavailable),
        };
        if !matches!(
            tokio::time::timeout(self.timeouts.statement, object.batch_execute("BEGIN")).await,
            Ok(Ok(()))
        ) {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        }
        let op = crate::operation_hex(operation);
        let lock = format!("setjoin-protocol-command:{scope}:{op}");
        let result=tokio::time::timeout(self.timeouts.statement,async{
            object.query_typed("SELECT set_config('app.current_user_id','',true),set_config('app.current_mailbox_id','',true),pg_advisory_xact_lock(hashtextextended($1,0))",&[(&lock,Type::TEXT)]).await.map_err(|e|StatementFailure::from_db(&e))?;
            let typed:Vec<_>=params.iter().map(|(v,t)|(*v,t.clone())).collect();let rows=object.query_typed(sql,&typed).await.map_err(|e|StatementFailure::from_db(&e))?;let value=decode(&rows)?;
            object.query_typed("INSERT INTO public.rust_operation_receipts(operation_id,family,command) VALUES(substr(encode(digest($1::text || ':' || $2::text,'sha256'),'hex'),1,32)::uuid,$3,$4)",&[(&op,Type::TEXT),(&scope,Type::TEXT),(&command.family,Type::TEXT),(&command.command,Type::TEXT)]).await.map_err(|e|StatementFailure::from_db(&e))?;Ok(value)
        }).await.unwrap_or_else(|_|Err(StatementFailure::refused("protocol command timed out")));
        let value = match result {
            Ok(v) => v,
            Err(e) => {
                if matches!(
                    tokio::time::timeout(self.timeouts.statement, object.batch_execute("ROLLBACK"))
                        .await,
                    Ok(Ok(()))
                ) {
                    object.keep();
                }
                return CommandOutcome::RolledBack(Rejection::Statement(e));
            }
        };
        match tokio::time::timeout(self.timeouts.statement, object.batch_execute("COMMIT")).await {
            Ok(Ok(())) => {
                object.keep();
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
                object.keep();
                CommandOutcome::RolledBack(Rejection::CommitRefused(code))
            }
            _ => CommandOutcome::Unknown { operation },
        }
    }
    /// Wait for the original anonymous operation lock before observing its
    /// receipt. Caller re-proves the same current protocol credential first.
    pub async fn lookup_protocol_operation(
        &self,
        scope: &str,
        operation: setjoin_contracts::ids::OperationId,
        command: crate::ReceiptCommand,
    ) -> Result<bool, StatementFailure> {
        let object = self
            .pool
            .get()
            .await
            .map_err(|_| StatementFailure::refused("pool unavailable"))?;
        let object = ReadLease(Some(object));
        let op = crate::operation_hex(operation);
        let lock = format!("setjoin-protocol-command:{scope}:{op}");
        let result=tokio::time::timeout(self.timeouts.statement,async{
            object.batch_execute("BEGIN").await.map_err(|e|StatementFailure::from_db(&e))?;
            object.query_typed("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",&[(&lock,Type::TEXT)]).await.map_err(|e|StatementFailure::from_db(&e))?;
            let rows=object.query_typed("SELECT EXISTS(SELECT 1 FROM public.rust_operation_receipts WHERE operation_id=substr(encode(digest($1::text || ':' || $2::text,'sha256'),'hex'),1,32)::uuid AND family=$3 AND command=$4)",&[(&op,Type::TEXT),(&scope,Type::TEXT),(&command.family,Type::TEXT),(&command.command,Type::TEXT)]).await.map_err(|e|StatementFailure::from_db(&e))?;
            object.batch_execute("COMMIT").await.map_err(|e|StatementFailure::from_db(&e))?;Ok(rows[0].get(0))
        }).await.map_err(|_|StatementFailure::refused("protocol lookup timed out"))?;
        if result.is_ok() {
            object.keep();
        }
        result
    }
}
