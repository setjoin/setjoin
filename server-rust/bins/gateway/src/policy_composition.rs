//! Wave 1.8 (`#546a`) composition-root builder for `setjoin-gateway`.
//!
//! Self-contained module wiring:
//! - `AppPool` (`DB_DSN` / `setjoin_app`, `NOBYPASSRLS`)
//! - `WorkerPool` (`DB_WORKER_DSN` / `setjoin_worker`, `BYPASSRLS`) ->
//!   encapsulated `AdminWorkerPool`
//! - shared `GroupResolver` subscribed to `group_membership_changed` via
//!   `#543a`'s single-backend `ListenHub`
//! - capability-gated `TxFactory`
//! - unified `PolicyGate<K>` alongside legacy `ScopedExecutor` during the
//!   expand–contract cutover.

use setjoin_authz::{
    groups::GroupResolver, policy_gate::PolicyGate, principals::TxFactory, token::KeySource,
};
use setjoin_pg::{AppPool, ListenHub, ScopedExecutor, WorkerPool};
use std::sync::Arc;
use tokio::{sync::watch, task::JoinHandle};

/// Configuration inputs for [`PolicyRuntime::build`].
#[derive(Clone, Debug)]
pub struct PolicyRuntimeConfig {
    pub app_dsn: String,
    pub app_pool_size: usize,
    pub worker_dsn: String,
    pub worker_pool_size: usize,
    pub direct_dsn: Option<String>,
    pub encryption_key: Option<String>,
    pub audit_hmac_key: Option<String>,
    pub effect_concurrency: Option<usize>,
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
            app_pool_size: 8,
            worker_dsn: worker_dsn.into(),
            worker_pool_size: 4,
            direct_dsn: None,
            encryption_key: None,
            audit_hmac_key: None,
            effect_concurrency: None,
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

    pub fn with_effect_concurrency(mut self, max_concurrent: usize) -> Self {
        self.effect_concurrency = Some(max_concurrent.max(1));
        self
    }
}

/// Composed Wave 1.8 policy and capability-transaction runtime for
/// `setjoin-gateway` (keeping `ScopedExecutor` alongside during the expand
/// phase).
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
    /// `GroupResolver` (subscribed via `ListenHub` when available), `TxFactory`,
    /// `PolicyGate<K>`, and expand-phase `ScopedExecutor`.
    pub async fn build(
        config: PolicyRuntimeConfig,
        keys: Arc<K>,
        existing_hub: Option<ListenHub>,
        stop: watch::Receiver<bool>,
    ) -> Result<Self, String> {
        let mut app_pool = AppPool::from_dsn(&config.app_dsn, config.app_pool_size.max(1))
            .map_err(|e| format!("open gateway AppPool: {e}"))?;
        let mut worker_pool =
            WorkerPool::from_dsn(&config.worker_dsn, config.worker_pool_size.max(1))
                .map_err(|e| format!("open gateway WorkerPool: {e}"))?;
        let mut legacy_executor =
            ScopedExecutor::from_dsn(&config.app_dsn, config.app_pool_size.max(1))
                .map_err(|e| format!("open gateway ScopedExecutor: {e}"))?;

        if let (Some(enc), Some(hmac)) = (&config.encryption_key, &config.audit_hmac_key) {
            app_pool = app_pool.with_audit_keys(enc.clone(), hmac.clone());
            worker_pool = worker_pool.with_audit_keys(enc.clone(), hmac.clone());
            legacy_executor = legacy_executor.with_audit_keys(enc.clone(), hmac.clone());
        }
        if let Some(limit) = config.effect_concurrency {
            app_pool = app_pool.with_effect_concurrency(limit);
        }

        let admin_pool = worker_pool.admin_pool();
        let groups = Arc::new(GroupResolver::new(app_pool.clone()));

        let listen_hub = match existing_hub {
            Some(hub) => Some(hub),
            None => match config.direct_dsn.as_deref() {
                Some(dsn) => Some(
                    ListenHub::spawn_with_watch(dsn, stop.clone())
                        .map_err(|e| format!("spawn gateway ListenHub: {e}"))?,
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
                    .map_err(|e| format!("subscribe GroupResolver to ListenHub: {e}"))?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use hmac::{Hmac, Mac};
    use serde_json::json;
    use setjoin_authz::{
        groups::CaGroupId,
        policy_gate::{GateCredential, GateRequest, ProtocolSurface},
    };
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_contracts::{
        authority::{AuthorityKey, ResourceScope},
        command::CommandEnvelope,
        ids::{ActorId, Digest, Generation, MailboxId, OperationId},
    };
    use setjoin_pg::{AuditEvent, CommandOutcome};
    use sha2::Sha256;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const TEST_ISSUER: &str = "https://auth.gateway-546a.test";
    const TEST_SECRET: &[u8] = b"gateway-546a-composition-secret-key!";

    struct TestKeys(setjoin_authz::legacy_jwt::LegacyKeys);

    impl TestKeys {
        fn new() -> Self {
            Self(
                setjoin_authz::legacy_jwt::LegacyKeys::new(TEST_SECRET, &["hs256-546a"], None)
                    .unwrap(),
            )
        }
    }

    impl KeySource for TestKeys {
        async fn key(&self, _kid: &str) -> Option<setjoin_authz::es256::VerifyingKey> {
            None
        }
        fn legacy_keys(&self) -> Option<&setjoin_authz::legacy_jwt::LegacyKeys> {
            Some(&self.0)
        }
    }

    fn sign_jwt(uid: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT","kid":"hs256-546a"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            json!({
                "iss": TEST_ISSUER,
                "aud": "mailserver-gateway",
                "typ": "access",
                "uid": uid,
                "email": format!("u{uid}@546a.test"),
                "iat": now - 5,
                "exp": now + 300,
            })
            .to_string(),
        );
        let signing_input = format!("{header}.{payload}");
        let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{sig}")
    }

    #[tokio::test]
    async fn gateway_policy_runtime_boots_listens_and_mints_all_capability_txs() {
        let Some(db) = Db::for_case("gateway_policy_runtime_546a") else {
            return;
        };
        let owner = db.connect().await.unwrap();
        let has_explicit_app = db.app.is_some();
        let app_dsn = db.app.clone().unwrap_or_else(|| db.dsn.clone());
        let explicit_worker_dsn = std::env::var("DB_WORKER_DSN")
            .ok()
            .filter(|v| !v.is_empty());
        let has_explicit_worker = explicit_worker_dsn.is_some();
        let worker_dsn = explicit_worker_dsn.unwrap_or_else(|| db.dsn.clone());

        let (stop_tx, stop_rx) = watch::channel(false);
        let runtime = PolicyRuntime::build(
            PolicyRuntimeConfig::new(&app_dsn, &worker_dsn, TEST_ISSUER)
                .with_direct_dsn(&db.direct)
                .with_pool_sizes(4, 2),
            Arc::new(TestKeys::new()),
            None,
            stop_rx,
        )
        .await
        .expect("PolicyRuntime::build");

        runtime
            .listen_hub()
            .expect("ListenHub active")
            .wait_connected()
            .await
            .expect("ListenHub connected");

        let alice = fixture::account(&owner, "gw546a-alice").await.unwrap();
        let admin = fixture::account(&owner, "gw546a-admin").await.unwrap();

        // Grant admin role so AdminPrincipal minting + RBAC proof succeeds.
        let role_id: i64 = owner
            .query_one(
                "INSERT INTO admin_role_groups (name, permissions, sod_class) \
                 VALUES ($1, ARRAY['users.read','audit.read'], 'audit') RETURNING id",
                &[&format!("gw546a-role-{}", admin.user)],
            )
            .await
            .unwrap()
            .get(0);
        owner
            .execute(
                "INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, $2)",
                &[&admin.user, &role_id],
            )
            .await
            .unwrap();

        // 1. Verify GroupResolver invalidation over ListenHub (`group_membership_changed`).
        let group_id: i64 = 954601;
        let initial = runtime
            .group_resolver()
            .resolve(alice.user)
            .await
            .expect("initial resolve");
        assert!(!initial.has_ca_group(CaGroupId::new(group_id).unwrap()));
        assert!(runtime.group_resolver().cached_len() >= 1);

        owner
            .execute(
                "INSERT INTO user_group_members (group_id, user_id) VALUES ($1, $2)",
                &[&group_id, &alice.user],
            )
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut invalidated = false;
        while Instant::now() < deadline {
            if runtime.group_resolver().cached_len() == 0 {
                invalidated = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            invalidated,
            "GroupResolver must observe group_membership_changed via ListenHub"
        );
        let refreshed = runtime
            .group_resolver()
            .resolve(alice.user)
            .await
            .expect("refreshed resolve");
        assert!(refreshed.has_ca_group(CaGroupId::new(group_id).unwrap()));

        // 2. Admit via PolicyGate and mint MailboxTx + UserTx (running on setjoin_app).
        let alice_tok = sign_jwt(alice.user);
        let req = GateRequest {
            surface: ProtocolSurface::Http,
            credential: GateCredential::Jwt {
                token: &alice_tok,
                from_cookie: false,
            },
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: "gw546a-test",
            scheme: "https",
            method: "GET",
            path: "/api/v1/profile",
            headers: None,
            body: &[],
            tls_active: true,
            require_tls: false,
            production: true,
            allowed_origin_host: "",
            required_app: None,
            drive_path: false,
            now_secs: None,
        };
        let alice_adm = runtime
            .policy_gate()
            .admit(&req)
            .await
            .expect("admit alice");
        let mb_p = alice_adm
            .mint_mailbox(runtime.tx_factory(), MailboxId::new(alice.mailbox).unwrap())
            .await
            .expect("mint mailbox");
        let mut mb_tx = runtime
            .tx_factory()
            .begin_mailbox_read(&mb_p.require_read().unwrap())
            .await
            .expect("MailboxTx<ReadOnly>");
        let mb_rows = mb_tx
            .query(
                "SELECT (NOT r.rolsuper AND NOT r.rolbypassrls), current_user::text \
                   FROM pg_roles r WHERE r.rolname = current_user",
                &[],
            )
            .await
            .unwrap();
        if has_explicit_app {
            assert!(mb_rows[0].get::<_, bool>(0));
            assert_eq!(mb_rows[0].get::<_, String>(1), "setjoin_app");
        }
        mb_tx.finish().await.unwrap();

        let user_p = alice_adm
            .mint_user(runtime.tx_factory())
            .await
            .expect("mint user");
        let mut user_tx = runtime
            .tx_factory()
            .begin_user_read(&user_p)
            .await
            .expect("UserTx<ReadOnly>");
        let user_rows = user_tx
            .query(
                "SELECT (NOT r.rolsuper AND NOT r.rolbypassrls), current_user::text \
                   FROM pg_roles r WHERE r.rolname = current_user",
                &[],
            )
            .await
            .unwrap();
        if has_explicit_app {
            assert!(user_rows[0].get::<_, bool>(0));
            assert_eq!(user_rows[0].get::<_, String>(1), "setjoin_app");
        }
        user_tx.finish().await.unwrap();

        // 3. Mint AdminReadTx, AdminSensitiveRead, and AdminWriteTx (running on worker/owner).
        let admin_tok = sign_jwt(admin.user);
        let admin_req = GateRequest {
            credential: GateCredential::Jwt {
                token: &admin_tok,
                from_cookie: false,
            },
            ..req
        };
        let admin_adm = runtime
            .policy_gate()
            .admit(&admin_req)
            .await
            .expect("admit admin");
        let admin_p = admin_adm
            .mint_admin(runtime.tx_factory())
            .await
            .expect("mint admin");
        let read_proof = admin_p.require_permission("users.read").unwrap();
        let mut admin_ro = runtime
            .tx_factory()
            .begin_admin_read(&read_proof)
            .await
            .expect("AdminReadTx");
        let admin_rows = admin_ro
            .query(
                "SELECT (r.rolbypassrls OR r.rolsuper), current_user::text \
                   FROM pg_roles r WHERE r.rolname = current_user",
                &[],
            )
            .await
            .unwrap();
        assert!(admin_rows[0].get::<_, bool>(0));
        if has_explicit_worker {
            assert_eq!(admin_rows[0].get::<_, String>(1), "setjoin_worker");
        }
        admin_ro.finish().await.unwrap();

        let audit_proof = admin_p.require_permission("audit.read").unwrap();
        let sens_ev = AuditEvent::new("gw546a.sensitive_read", "user").unwrap();
        let sens_rows = runtime
            .tx_factory()
            .run_admin_sensitive_read(
                &audit_proof,
                &sens_ev,
                "SELECT (r.rolbypassrls OR r.rolsuper), current_user::text \
                   FROM pg_roles r WHERE r.rolname = current_user",
                &[],
            )
            .await
            .expect("AdminSensitiveRead");
        assert!(sens_rows[0].get::<_, bool>(0));
        if has_explicit_worker {
            assert_eq!(sens_rows[0].get::<_, String>(1), "setjoin_worker");
        }

        let op_id = OperationId([0x46; 16]);
        let env = CommandEnvelope {
            operation: op_id,
            authority: AuthorityKey {
                actor: ActorId::new(admin.user).unwrap(),
                scope: ResourceScope::User(ActorId::new(admin.user).unwrap()),
                generation: Generation(1),
            },
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest([0x11; 32]),
            command: (),
        };
        let admin_tx = runtime
            .tx_factory()
            .begin_admin_write(&read_proof, &env, Instant::now() + Duration::from_secs(5))
            .await
            .expect("AdminWriteTx<Unaudited>");
        let write_ev = AuditEvent::new("gw546a.admin_write", "user").unwrap();
        let audited = admin_tx
            .record_audit(&write_ev)
            .await
            .expect("record_audit");
        assert!(matches!(
            audited.commit().await,
            CommandOutcome::Committed(())
        ));

        let _ = stop_tx.send(true);
        runtime.shutdown().await;

        // Clean up fixture rows.
        let _ = owner
            .execute(
                "DELETE FROM admin_role_assignments WHERE role_group_id = $1",
                &[&role_id],
            )
            .await;
        let _ = owner
            .execute("DELETE FROM admin_role_groups WHERE id = $1", &[&role_id])
            .await;
        let _ = owner
            .execute(
                "DELETE FROM user_group_members WHERE group_id = $1 AND user_id = $2",
                &[&group_id, &alice.user],
            )
            .await;
        for acc in [&alice, &admin] {
            let _ = fixture::remove(&owner, acc).await;
        }
    }
}
