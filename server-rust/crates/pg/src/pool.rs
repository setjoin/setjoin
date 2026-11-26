//! Custom `deadpool::managed::Manager` with `RecyclingMethod::Fast` (0-RTT
//! checkout), TCP keepalives, opt-in CVE-2026-14666-guarded per-connection
//! bounded LRU prepared statement caching, and PgBouncer-safe `CancelRequest`
//! drop semantics.

use crate::executor::{ConfigError, Timeouts};
use deadpool::managed::{self, Metrics, Object, Pool, RecycleError, RecycleResult};
use std::{collections::HashMap, fmt, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tokio_postgres::{types::Type, Client, Config, NoTls, Statement};

/// Default per-connection prepared statement LRU capacity when `OptIn` mode is
/// enabled and `max_prepared_statements - 16 >= 128`.
pub const DEFAULT_PREPARED_CACHE_CAP: usize = 128;

/// Minimum PgBouncer `max_prepared_statements` required before opt-in prepared
/// statements may be enabled.
pub const MIN_PGBOUNCER_MAX_PREPARED: usize = 200;

/// Reserved PgBouncer prepared statement slots left unused for driver/admin
/// headroom (`effective_cap <= max_prepared_statements - 16`).
pub const PGBOUNCER_PREPARED_HEADROOM: usize = 16;

/// Maximum number of concurrent background `CancelRequest` handshakes spawned
/// on dirty lease quarantine/drop.
pub const CANCEL_SEMAPHORE_PERMITS: usize = 32;

/// Upper bound on each background `CancelRequest` handshake before dropping the
/// underlying connection wrapper.
pub const CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

/// Returns `true` iff `server_version_num` (from `SHOW server_version_num`)
/// includes the PostgreSQL fix for CVE-2026-14666 (RLS + prepared statements).
///
/// Explicitly rejects PG `< 17.11` (`< 170011`) **and** PG `18.0–18.5`
/// (`180000..=180005`), admitting `17.11+` (`170011..180000`) and `18.6+`
/// (`>= 180006`).
pub const fn pg_version_allows_prepared_rls(server_version_num: u32) -> bool {
    (server_version_num >= 170011 && server_version_num < 180000) || server_version_num >= 180006
}

/// Validated deployment attestation that PgBouncer is configured safely for
/// opt-in per-connection prepared statements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PgBouncerAttestation {
    max_prepared_statements: usize,
    server_reset_query_always: bool,
    effective_cap: usize,
}

impl PgBouncerAttestation {
    /// Validate PgBouncer configuration and compute the bounded per-connection
    /// LRU cap (`<= min(configured_cap, max_prepared_statements - 16)`).
    pub fn new(
        max_prepared_statements: usize,
        server_reset_query_always: bool,
        configured_cap: usize,
    ) -> Result<Self, ConfigError> {
        if max_prepared_statements < MIN_PGBOUNCER_MAX_PREPARED {
            return Err(ConfigError(format!(
                "PgBouncer max_prepared_statements ({max_prepared_statements}) must be >= {MIN_PGBOUNCER_MAX_PREPARED}"
            )));
        }
        if server_reset_query_always {
            return Err(ConfigError(
                "PgBouncer server_reset_query_always must be false for prepared statements".into(),
            ));
        }
        if configured_cap == 0 {
            return Err(ConfigError(
                "configured prepared statement LRU cap must be >= 1".into(),
            ));
        }
        let max_safe = max_prepared_statements.saturating_sub(PGBOUNCER_PREPARED_HEADROOM);
        let effective_cap = configured_cap.min(max_safe);
        if effective_cap == 0 {
            return Err(ConfigError(
                "effective prepared statement LRU cap must be >= 1".into(),
            ));
        }
        Ok(Self {
            max_prepared_statements,
            server_reset_query_always,
            effective_cap,
        })
    }

    /// Convenience constructor using [`DEFAULT_PREPARED_CACHE_CAP`] (128).
    pub fn with_default_cap(
        max_prepared_statements: usize,
        server_reset_query_always: bool,
    ) -> Result<Self, ConfigError> {
        Self::new(
            max_prepared_statements,
            server_reset_query_always,
            DEFAULT_PREPARED_CACHE_CAP,
        )
    }

    pub const fn max_prepared_statements(&self) -> usize {
        self.max_prepared_statements
    }

    pub const fn server_reset_query_always(&self) -> bool {
        self.server_reset_query_always
    }

    pub const fn effective_cap(&self) -> usize {
        self.effective_cap
    }
}

/// Prepared statement protocol mode for a pool.
///
/// Defaults to [`PreparedStatementMode::Unnamed`] (`query_typed`, zero named
/// server statements, zero `TYPEINFO_QUERY` `s0`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PreparedStatementMode {
    #[default]
    Unnamed,
    OptIn(PgBouncerAttestation),
}

/// Optional planner hint appended to step 1 (`BEGIN ...; SET LOCAL ...`) at
/// zero extra round trips.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PlanCacheHint {
    #[default]
    Auto,
    /// Appends `; SET LOCAL plan_cache_mode = force_custom_plan` to step 1's
    /// `batch_execute` to prevent 6th-call generic plan skew on skewed tenants.
    ForceCustomPlan,
}

/// Apply standard Setjoin TCP keepalive (and Linux `TCP_USER_TIMEOUT`) socket
/// defaults so dead TCP peers surface promptly under `RecyclingMethod::Fast`.
pub(crate) fn apply_pool_socket_defaults(config: &mut Config) {
    config.keepalives(true);
    config.keepalives_idle(Duration::from_secs(30));
    config.keepalives_interval(Duration::from_secs(10));
    config.keepalives_retries(3);
    #[cfg(target_os = "linux")]
    config.tcp_user_timeout(Duration::from_secs(30));
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PreparedKey {
    sql: &'static str,
    type_oids: Vec<u32>,
}

/// Bounded per-connection LRU cache of prepared statements.
///
/// Eviction and preparation MUST run strictly **before** `BEGIN` so
/// `StatementInner::drop` (`Close + Sync`) never executes inside an open
/// transaction.
#[derive(Debug)]
pub(crate) struct PreparedLru {
    cap: usize,
    tick: u64,
    entries: HashMap<PreparedKey, (Statement, u64)>,
}

impl PreparedLru {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            tick: 0,
            entries: HashMap::with_capacity(cap.min(16)),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn cap(&self) -> usize {
        self.cap
    }

    /// Look up or prepare `(sql, types)` on `client`, evicting the
    /// least-recently-used statement first if at capacity.
    ///
    /// Call ONLY while the connection is idle (before `BEGIN`).
    pub(crate) async fn get_or_prepare(
        &mut self,
        client: &Client,
        sql: &'static str,
        types: &[Type],
    ) -> Result<Statement, tokio_postgres::Error> {
        debug_assert!(
            self.cap > 0,
            "PreparedLru::get_or_prepare called with cap=0"
        );
        let key = PreparedKey {
            sql,
            type_oids: types.iter().map(Type::oid).collect(),
        };
        if let Some((stmt, last_used)) = self.entries.get_mut(&key) {
            self.tick = self.tick.wrapping_add(1);
            *last_used = self.tick;
            return Ok(stmt.clone());
        }
        // Evict LRU entries BEFORE preparing so the dropped Statement's
        // Close+Sync is queued ahead of prepare_typed and flushed before BEGIN.
        while self.entries.len() >= self.cap {
            if let Some(lru_key) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&lru_key);
            } else {
                break;
            }
        }
        let stmt = client.prepare_typed(sql, types).await?;
        self.tick = self.tick.wrapping_add(1);
        self.entries.insert(key, (stmt.clone(), self.tick));
        Ok(stmt)
    }
}

/// Error returned by [`SetjoinManager::create`].
#[derive(Debug)]
pub(crate) enum ManagerError {
    Postgres(tokio_postgres::Error),
    PreparedRlsVersionUnsupported { server_version_num: u32 },
    ServerVersionUnavailable(String),
}

impl fmt::Display for ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(e) => write!(f, "{e}"),
            Self::PreparedRlsVersionUnsupported { server_version_num } => write!(
                f,
                "PostgreSQL server_version_num {server_version_num} does not allow opt-in prepared statements with RLS (CVE-2026-14666 requires >= 17.11 or >= 18.6)"
            ),
            Self::ServerVersionUnavailable(msg) => {
                write!(f, "failed to verify PostgreSQL server_version_num: {msg}")
            }
        }
    }
}

impl std::error::Error for ManagerError {}

impl From<tokio_postgres::Error> for ManagerError {
    fn from(err: tokio_postgres::Error) -> Self {
        Self::Postgres(err)
    }
}

/// Owned connection inside our custom deadpool manager.
pub(crate) struct ManagedClient {
    pub(crate) client: Client,
    conn_task: tokio::task::JoinHandle<()>,
    pub(crate) prepared: PreparedLru,
    #[allow(dead_code)]
    pub(crate) server_version_num: Option<u32>,
}

impl ManagedClient {
    pub(crate) fn is_closed(&self) -> bool {
        self.client.is_closed()
    }
}

impl Drop for ManagedClient {
    fn drop(&mut self) {
        self.conn_task.abort();
    }
}

pub(crate) struct SetjoinManager {
    pg_config: Config,
    prepared_mode: PreparedStatementMode,
}

impl managed::Manager for SetjoinManager {
    type Type = ManagedClient;
    type Error = ManagerError;

    async fn create(&self) -> Result<ManagedClient, ManagerError> {
        let (client, connection) = self.pg_config.connect(NoTls).await?;
        let conn_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let (prepared_cap, server_version_num) = match self.prepared_mode {
            PreparedStatementMode::Unnamed => (0, None),
            PreparedStatementMode::OptIn(attestation) => {
                let rows = match client.query_typed("SHOW server_version_num", &[]).await {
                    Ok(rows) => rows,
                    Err(e) => {
                        conn_task.abort();
                        return Err(ManagerError::Postgres(e));
                    }
                };
                let raw = rows
                    .first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(|| {
                        conn_task.abort();
                        ManagerError::ServerVersionUnavailable(
                            "SHOW server_version_num returned no value".into(),
                        )
                    })?;
                let version_num = raw.trim().parse::<u32>().map_err(|_| {
                    conn_task.abort();
                    ManagerError::ServerVersionUnavailable(format!("unparseable version {raw:?}"))
                })?;
                if !pg_version_allows_prepared_rls(version_num) {
                    conn_task.abort();
                    return Err(ManagerError::PreparedRlsVersionUnsupported {
                        server_version_num: version_num,
                    });
                }
                (attestation.effective_cap(), Some(version_num))
            }
        };
        Ok(ManagedClient {
            client,
            conn_task,
            prepared: PreparedLru::new(prepared_cap),
            server_version_num,
        })
    }

    async fn recycle(
        &self,
        client: &mut ManagedClient,
        _: &Metrics,
    ) -> RecycleResult<ManagerError> {
        // RecyclingMethod::Fast: zero network RTT on checkout; reject only
        // connections whose driver task already observed EOF / closure.
        if client.is_closed() {
            return Err(RecycleError::message("Connection closed"));
        }
        Ok(())
    }
}

/// Internal managed pool shared by `AppPool`, `WorkerPool`, and `ScopedExecutor`.
#[derive(Clone)]
pub(crate) struct SetjoinPool {
    pool: Pool<SetjoinManager>,
    pub(crate) timeouts: Timeouts,
    pub(crate) prepared_mode: PreparedStatementMode,
    pub(crate) plan_cache_hint: PlanCacheHint,
    runtime_handle: Option<tokio::runtime::Handle>,
    cancel_sem: Arc<Semaphore>,
}

impl SetjoinPool {
    pub(crate) fn from_dsn_with(
        dsn: &str,
        max_size: usize,
        timeouts: Timeouts,
        prepared_mode: PreparedStatementMode,
        plan_cache_hint: PlanCacheHint,
    ) -> Result<Self, ConfigError> {
        let mut pg_config: Config = dsn
            .parse()
            .map_err(|e: tokio_postgres::Error| ConfigError(e.to_string()))?;
        apply_pool_socket_defaults(&mut pg_config);
        let manager = SetjoinManager {
            pg_config,
            prepared_mode,
        };
        let pool = Pool::builder(manager)
            .max_size(max_size)
            .runtime(deadpool::Runtime::Tokio1)
            .wait_timeout(Some(timeouts.pool_wait))
            .create_timeout(Some(timeouts.create))
            .recycle_timeout(Some(timeouts.create))
            .build()
            .map_err(|e| ConfigError(e.to_string()))?;
        Ok(Self {
            pool,
            timeouts,
            prepared_mode,
            plan_cache_hint,
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            cancel_sem: Arc::new(Semaphore::new(CANCEL_SEMAPHORE_PERMITS)),
        })
    }

    pub(crate) async fn get(&self) -> Result<ManagedLease, managed::PoolError<ManagerError>> {
        let object = self.pool.get().await?;
        Ok(ManagedLease {
            object: Some(object),
            runtime_handle: self.runtime_handle.clone(),
            cancel_sem: Arc::clone(&self.cancel_sem),
        })
    }
}

/// Checked-out pooled connection that quarantines with a PgBouncer-safe bounded
/// `CancelRequest` on drop unless explicitly returned via [`ManagedLease::keep`].
pub(crate) struct ManagedLease {
    object: Option<Object<SetjoinManager>>,
    runtime_handle: Option<tokio::runtime::Handle>,
    cancel_sem: Arc<Semaphore>,
}

impl ManagedLease {
    pub(crate) fn client(&self) -> &Client {
        &self.object.as_ref().expect("lease held").client
    }

    pub(crate) fn managed_mut(&mut self) -> &mut ManagedClient {
        self.object.as_mut().expect("lease held")
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.object.as_ref().is_none_or(|o| o.is_closed())
    }

    /// Return a clean, idle connection to the pool without cancellation.
    pub(crate) fn keep(mut self) {
        drop(self.object.take());
    }

    /// Synchronously free the pool slot and send a bounded `CancelRequest`
    /// while keeping the PgBouncer client TCP socket alive until cancellation
    /// finishes or times out.
    pub(crate) fn quarantine(mut self) {
        if let Some(object) = self.object.take() {
            quarantine_managed_object(object, self.runtime_handle.as_ref(), &self.cancel_sem);
        }
    }
}

impl Drop for ManagedLease {
    fn drop(&mut self) {
        if let Some(object) = self.object.take() {
            quarantine_managed_object(object, self.runtime_handle.as_ref(), &self.cancel_sem);
        }
    }
}

/// Shared PgBouncer-safe `CancelRequest` quarantine helper for `ManagedClient`.
///
/// 1. Calls `Object::take(object)` synchronously to free the pool slot while
///    retaining `wrapper` (its `conn_task` + client TCP socket).
/// 2. If `!wrapper.is_closed()`, a Tokio runtime `Handle` is available (current
///    or captured at pool creation), and the bounded `Semaphore` (32 permits)
///    grants a permit: spawns a task that awaits `timeout(2s, cancel_query)`
///    and drops `wrapper` **after** `cancel_query` finishes or times out.
/// 3. Otherwise (already closed, non-Tokio thread without runtime, or cancel
///    budget saturated): drops `wrapper` synchronously without panicking.
pub(crate) fn quarantine_managed_object(
    object: Object<SetjoinManager>,
    captured_handle: Option<&tokio::runtime::Handle>,
    cancel_sem: &Arc<Semaphore>,
) {
    let wrapper = Object::take(object);
    if wrapper.is_closed() {
        drop(wrapper);
        return;
    }
    let handle = tokio::runtime::Handle::try_current()
        .ok()
        .or_else(|| captured_handle.cloned());
    let Some(handle) = handle else {
        drop(wrapper);
        return;
    };
    let Ok(permit) = Arc::clone(cancel_sem).try_acquire_owned() else {
        drop(wrapper);
        return;
    };
    let cancel_token = wrapper.client.cancel_token();
    handle.spawn(async move {
        let _ = tokio::time::timeout(CANCEL_TIMEOUT, cancel_token.cancel_query(NoTls)).await;
        drop(wrapper);
        drop(permit);
    });
}

/// Same PgBouncer-safe `CancelRequest` quarantine helper for legacy
/// `deadpool_postgres::Object` pools wrapped via `ScopedExecutor::new`.
pub(crate) fn quarantine_legacy_object(
    object: deadpool_postgres::Object,
    captured_handle: Option<&tokio::runtime::Handle>,
    cancel_sem: &Arc<Semaphore>,
) {
    let wrapper = deadpool_postgres::Object::take(object);
    if wrapper.is_closed() {
        drop(wrapper);
        return;
    }
    let handle = tokio::runtime::Handle::try_current()
        .ok()
        .or_else(|| captured_handle.cloned());
    let Some(handle) = handle else {
        drop(wrapper);
        return;
    };
    let Ok(permit) = Arc::clone(cancel_sem).try_acquire_owned() else {
        drop(wrapper);
        return;
    };
    let cancel_token = wrapper.cancel_token();
    handle.spawn(async move {
        let _ = tokio::time::timeout(CANCEL_TIMEOUT, cancel_token.cancel_query(NoTls)).await;
        drop(wrapper);
        drop(permit);
    });
}
