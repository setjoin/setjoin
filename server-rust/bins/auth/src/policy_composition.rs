//! Wave 1.8 (`#546a`) composition-root builder for `setjoin-auth`.
//!
//! Wires `AppPool` (`DB_DSN` / `setjoin_app`), `WorkerPool` (`DB_WORKER_DSN` /
//! `setjoin_worker` -> encapsulated `AdminWorkerPool` for private pre-auth
//! credential proofs and cross-tenant admin paths), shared `GroupResolver`
//! subscribed via `#543a`'s `ListenHub` to `group_membership_changed`,
//! `TxFactory`, and `PolicyGate<K>` alongside the expand-phase `ScopedExecutor`.

use setjoin_authz::{
    groups::GroupResolver, policy_gate::PolicyGate, principals::TxFactory, token::KeySource,
};
use setjoin_pg::{AppPool, ListenHub, ScopedExecutor, WorkerPool};
use std::sync::Arc;
use tokio::{sync::watch, task::JoinHandle};

/// Configuration inputs for [`PolicyRuntime::build`] in `setjoin-auth`.
#[derive(Clone, Debug)]
pub struct PolicyRuntimeConfig {
    pub app_dsn: String,
    pub app_pool_size: usize,
    pub worker_dsn: String,
    pub worker_pool_size: usize,
    pub direct_dsn: Option<String>,
    pub encryption_key: Option<String>,
    pub audit_hmac_key: Option<String>,
    pub issuer: String,
}

impl PolicyRuntimeConfig {
    pub fn new(
        app_dsn: impl Into<String>,
        worker_dsn: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            app_dsn: app_dsn.into(),
            app_pool_size: 25,
            worker_dsn: worker_dsn.into(),
            worker_pool_size: 4,
            direct_dsn: None,
            encryption_key: None,
            audit_hmac_key: None,
            issuer: issuer.into(),
        }
    }

    pub fn with_direct_dsn(mut self, direct_dsn: impl Into<String>) -> Self {
        let dsn = direct_dsn.into();
        self.direct_dsn = (!dsn.trim().is_empty()).then_some(dsn);
        self
    }

    pub fn with_audit_keys(
        mut self,
        encryption_key: impl Into<String>,
        audit_hmac_key: impl Into<String>,
    ) -> Self {
        self.encryption_key = Some(encryption_key.into());
        self.audit_hmac_key = Some(audit_hmac_key.into());
        self
    }

    pub fn with_pool_sizes(mut self, app_size: usize, worker_size: usize) -> Self {
        self.app_pool_size = app_size.max(1);
        self.worker_pool_size = worker_size.max(1);
        self
    }
}

/// Composed Wave 1.8 policy, pre-auth, and capability-transaction runtime for
/// `setjoin-auth`.
pub struct PolicyRuntime<K: KeySource + 'static> {
    app_pool: AppPool,
    worker_pool: WorkerPool,
    groups: Arc<GroupResolver>,
    tx_factory: TxFactory,
    policy_gate: Arc<PolicyGate<K>>,
    legacy_executor: ScopedExecutor,
    listen_hub: Option<ListenHub>,
    group_listener: Option<JoinHandle<()>>,
}

impl<K: KeySource + 'static> PolicyRuntime<K> {
    /// Build and wire `AppPool`, `WorkerPool` (`AdminWorkerPool`), shared
    /// `GroupResolver` subscribed to `group_membership_changed` via `ListenHub`,
    /// `TxFactory`, `PolicyGate<K>`, and expand-phase `ScopedExecutor`.
    pub async fn build(
        config: PolicyRuntimeConfig,
        keys: Arc<K>,
        existing_hub: Option<ListenHub>,
        stop: watch::Receiver<bool>,
    ) -> Result<Self, String> {
        let mut app_pool = AppPool::from_dsn(&config.app_dsn, config.app_pool_size.max(1))
            .map_err(|e| format!("open auth AppPool: {e}"))?;
        let mut worker_pool =
            WorkerPool::from_dsn(&config.worker_dsn, config.worker_pool_size.max(1))
                .map_err(|e| format!("open auth WorkerPool: {e}"))?;
        let mut legacy_executor =
            ScopedExecutor::from_dsn(&config.app_dsn, config.app_pool_size.max(1))
                .map_err(|e| format!("open auth ScopedExecutor: {e}"))?;

        if let (Some(enc), Some(hmac)) = (&config.encryption_key, &config.audit_hmac_key) {
            app_pool = app_pool.with_audit_keys(enc.clone(), hmac.clone());
            worker_pool = worker_pool.with_audit_keys(enc.clone(), hmac.clone());
            legacy_executor = legacy_executor.with_audit_keys(enc.clone(), hmac.clone());
        }

        let admin_pool = worker_pool.admin_pool();
        let groups = Arc::new(GroupResolver::new(app_pool.clone()));

        let listen_hub = match existing_hub {
            Some(hub) => Some(hub),
            None => match config.direct_dsn.as_deref() {
                Some(dsn) => Some(
                    ListenHub::spawn_with_watch(dsn, stop.clone())
                        .map_err(|e| format!("spawn auth ListenHub: {e}"))?,
                ),
                None => None,
            },
        };

        let group_listener = if let Some(hub) = &listen_hub {
            Some(
                groups
                    .clone()
                    .subscribe_listen_hub(hub, stop)
                    .await
                    .map_err(|e| format!("subscribe auth GroupResolver to ListenHub: {e}"))?,
            )
        } else {
            None
        };

        let tx_factory = TxFactory::with_admin_pool(app_pool.clone(), admin_pool, groups.clone());
        let policy_gate = Arc::new(
            PolicyGate::new(legacy_executor.clone(), keys, config.issuer)
                .with_tx_factory(tx_factory.clone()),
        );

        Ok(Self {
            app_pool,
            worker_pool,
            groups,
            tx_factory,
            policy_gate,
            legacy_executor,
            listen_hub,
            group_listener,
        })
    }

    pub fn app_pool(&self) -> &AppPool {
        &self.app_pool
    }

    pub fn worker_pool(&self) -> &WorkerPool {
        &self.worker_pool
    }

    pub fn group_resolver(&self) -> &Arc<GroupResolver> {
        &self.groups
    }

    pub fn tx_factory(&self) -> &TxFactory {
        &self.tx_factory
    }

    pub fn policy_gate(&self) -> &Arc<PolicyGate<K>> {
        &self.policy_gate
    }

    pub fn legacy_executor(&self) -> &ScopedExecutor {
        &self.legacy_executor
    }

    pub fn listen_hub(&self) -> Option<&ListenHub> {
        self.listen_hub.as_ref()
    }

    /// Tear down the background `GroupResolver` listener task cleanly.
    pub async fn shutdown(mut self) {
        if let Some(handle) = self.group_listener.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

/// Run a 1-RTT `BEGIN READ ONLY` user-scoped query on `AppPool` (`setjoin_app`,
/// `NOBYPASSRLS`) via a minted [`setjoin_pg::VerifiedUser`].
pub(crate) async fn user_read(
    exec: &ScopedExecutor,
    actor: setjoin_contracts::ids::ActorId,
    sql: &'static str,
    params: &[setjoin_pg::Param<'_>],
) -> Result<Vec<setjoin_pg::Row>, setjoin_pg::StatementFailure> {
    let app_pool = exec
        .try_app_pool()
        .ok_or_else(|| setjoin_pg::StatementFailure {
            sqlstate: None,
            message: "AppPool unavailable".into(),
            hint: None,
        })?;
    let principal = setjoin_pg::mint::user(actor, setjoin_contracts::ids::Generation(1));
    app_pool
        .run_user_read_pipelined(&principal, sql, params)
        .await
}

/// Run a 1-RTT `BEGIN READ ONLY` pre-authentication / org-policy query via
/// `AdminWorkerPool::run_pre_auth_read_pipelined` (`DB_WORKER_DSN` / `setjoin_worker`).
pub(crate) async fn pre_auth_read(
    pool: Option<&setjoin_pg::AdminWorkerPool>,
    sql: &'static str,
    params: &[setjoin_pg::Param<'_>],
) -> Result<Vec<setjoin_pg::Row>, setjoin_pg::StatementFailure> {
    let admin_pool = pool.ok_or_else(|| setjoin_pg::StatementFailure {
        sqlstate: None,
        message: "AdminWorkerPool unavailable".into(),
        hint: None,
    })?;
    admin_pool.run_pre_auth_read_pipelined(sql, params).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_pg::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};

    struct EmptyKeys;

    impl KeySource for EmptyKeys {
        async fn key(&self, _kid: &str) -> Option<setjoin_authz::es256::VerifyingKey> {
            None
        }
    }

    static PRE_AUTH_CHECK: SqlContract = SqlContract {
        id: "auth_composition.pre_auth_check",
        domain: "auth",
        sql: "SELECT u.id, (r.rolbypassrls OR r.rolsuper), current_user::text \
                FROM users u JOIN pg_roles r ON r.rolname = current_user WHERE u.id = $1",
        params: &[Type::INT8],
        columns: &[
            ColumnSpec::named("id", Type::INT8),
            ColumnSpec::unnamed(Type::BOOL),
            ColumnSpec::unnamed(Type::TEXT),
        ],
        scope: SqlScope::AuthPreScope,
        rls_check: RlsCheck::PrepareAndExplain,
        audit: SqlAuditPosture::Standard,
    };

    #[tokio::test]
    async fn auth_policy_runtime_boots_and_runs_private_pre_auth_read() {
        let Some(db) = Db::for_case("auth_policy_runtime_546a") else {
            return;
        };
        let owner = db.connect().await.unwrap();
        let app_dsn = db.app.clone().unwrap_or_else(|| db.dsn.clone());
        let explicit_worker_dsn = std::env::var("DB_WORKER_DSN")
            .ok()
            .filter(|v| !v.is_empty());
        let has_explicit_worker = explicit_worker_dsn.is_some();
        let worker_dsn = explicit_worker_dsn.unwrap_or_else(|| db.dsn.clone());

        let (stop_tx, stop_rx) = watch::channel(false);
        let runtime = PolicyRuntime::build(
            PolicyRuntimeConfig::new(&app_dsn, &worker_dsn, "https://auth.546a.test")
                .with_direct_dsn(&db.direct)
                .with_pool_sizes(4, 2),
            Arc::new(EmptyKeys),
            None,
            stop_rx,
        )
        .await
        .expect("auth PolicyRuntime::build");

        runtime
            .listen_hub()
            .expect("ListenHub active")
            .wait_connected()
            .await
            .expect("ListenHub connected");

        let user = fixture::account(&owner, "auth546a-user").await.unwrap();
        let rows = runtime
            .policy_gate()
            .run_pre_auth_read_contract(&PRE_AUTH_CHECK, &[&user.user])
            .await
            .expect("private pre-auth read on AdminWorkerPool");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, i64>(0), user.user);
        assert!(rows[0].get::<_, bool>(1));
        if has_explicit_worker {
            assert_eq!(rows[0].get::<_, String>(2), "setjoin_worker");
        }

        let _ = stop_tx.send(true);
        runtime.shutdown().await;
        let _ = fixture::remove(&owner, &user).await;
    }
}
