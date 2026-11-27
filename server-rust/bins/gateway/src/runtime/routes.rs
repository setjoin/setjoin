//! HTTP route table builder extracted from `bins/gateway/src/main.rs` (#543).

use std::sync::Arc;

use crate::jmap::{
    jwks::Jwks,
    limit::{EdgeLimit, Limiter},
    JmapCommands, JmapRoute,
};
use crate::workers::SessionDenylist;
use crate::RouteTable;
use setjoin_authz::auth_authority::{AuthAuthority, AuthKeySource};
use setjoin_authz::token::KeySource;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::{ListenHub, ScopedExecutor};

pub struct RouteDeps {
    pub configuration: Arc<crate::configuration::Runtime>,
    pub denylist: Option<Arc<SessionDenylist>>,
    pub chain: Option<Arc<setjoin_authz::auth_chain::Chain>>,
    pub threat: Option<Arc<setjoin_threat::Gate>>,
    pub lifecycle: Option<Arc<crate::guest_worker::GuestLifecycle>>,
    pub ldap: Option<Arc<crate::directory_sync_workers::LdapRuntime>>,
    pub ad: Option<Arc<crate::directory_sync_workers::AdRuntime>>,
    pub subscription_sync: Option<Arc<crate::subscription_sync::SubscriptionSync>>,
    pub migration_runner: Option<crate::migration::Runner>,
    pub webhook: Option<crate::webhook::Dispatcher>,
    pub federation: Option<Arc<setjoin_federation::service::Service>>,
    pub platform_storage: Option<Arc<crate::platform_storage::Runtime>>,
    pub auth_authority: Option<Arc<dyn AuthAuthority>>,
    pub listen_hub: Option<ListenHub>,
    /// Whether this process is permitted to load private signing keys
    /// (`JWT_SECRET`, `SM2_PRIVATE_KEY_FILE`). Must be `false` on non-`auth`
    /// `setjoind` nodes even when `AUTHSERVER_URL` is unset (#543).
    pub allow_private_keys: bool,
    pub boot_posture: Arc<setjoin_boot::BootPosture>,
    pub search_facade: Option<Arc<crate::search_facade::GatewaySearchFacade>>,
    pub search_work_queue: Option<setjoin_workqueue::WorkQueue>,
}

/// Build the HTTP route table and shared edge rate limiter.
///
/// When `deps.auth_authority` is `Some`, token verification uses
/// [`AuthKeySource`] directly (never loading `JWT_SECRET` or
/// `SM2_PRIVATE_KEY_FILE` on non-`auth` nodes). Otherwise falls back to legacy
/// `setjoin-server` `Jwks` + env key loading.
pub async fn build(
    settings: &crate::configuration::Settings,
    deps: RouteDeps,
) -> Result<(RouteTable, Option<EdgeLimit>), String> {
    let table = RouteTable::proxy_all().with(crate::oidc_namespace::Namespace);
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let limit = env("CORE_RATE_LIMIT")
        .and_then(|v| v.parse::<i64>().ok())
        .map_or(600, |n| n.max(0) as u64);
    let edge = EdgeLimit::for_front_door(Limiter::new(limit, 60));
    let website = env("WEBSITE_DIR")
        .map(|root| {
            setjoin_static::website::Website::load(std::path::Path::new(&root)).map(Arc::new)
        })
        .transpose()?;
    let Some(dsn) = env("DB_DSN") else {
        eprintln!(
            "setjoin-gateway: application routes not installed (needs DB_DSN); public catch-alls installed"
        );
        let mut catchall = crate::catchall::CatchallRoute::new();
        catchall.website = website;
        return Ok((table.with_catchall(catchall), Some(edge)));
    };
    let pool = env("GATEWAY_DB_POOL")
        .map_or(Ok(8), |v| v.parse::<usize>())
        .map_err(|e| format!("GATEWAY_DB_POOL: {e}"))?;
    let exec = ScopedExecutor::from_dsn(&dsn, pool)
        .map_err(|e| format!("DB_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        );
    if let Some(authority) = deps.auth_authority.clone() {
        let keys = Arc::new(AuthKeySource::new(authority));
        return build_with_keys(settings, deps, table, edge, website, dsn, pool, exec, keys).await;
    }
    let keys = build_legacy_jwks(&env, deps.allow_private_keys)?;
    build_with_keys(settings, deps, table, edge, website, dsn, pool, exec, keys).await
}

fn build_legacy_jwks(
    env: &impl Fn(&str) -> Option<String>,
    allow_private_keys: bool,
) -> Result<Arc<Jwks>, String> {
    let mut keys = match env("AUTHSERVER_JWKS_URL") {
        Some(jwks) => Jwks::new(
            jwks.parse()
                .map_err(|e| format!("AUTHSERVER_JWKS_URL: {e}"))?,
        )?,
        None => Jwks::with_fetch(Box::new(|| {
            Box::pin(async { Ok(br#"{"keys":[]}"#.to_vec()) })
        })),
    };
    let floor = if env("CRYPTO_ALGORITHM_PROFILE").as_deref() == Some("smx") {
        16
    } else {
        32
    };
    let drive_native_secret = env("DRIVE_NATIVE_TOKEN_SECRET");
    if let Some(drive_secret) = drive_native_secret.as_deref() {
        if drive_secret.len() < floor {
            return Err(format!(
                "DRIVE_NATIVE_TOKEN_SECRET must be at least {floor} characters"
            ));
        }
    }
    let jwt_secret = if allow_private_keys {
        env("JWT_SECRET")
    } else {
        None
    };
    if let Some(secret) = jwt_secret {
        if secret.len() < floor {
            return Err(format!("JWT_SECRET must be at least {floor} characters"));
        }
        let sm2_pem = if matches!(
            env("CRYPTO_ALGORITHM_PROFILE").as_deref(),
            Some("smx" | "hybrid")
        ) {
            env("SM2_PRIVATE_KEY_FILE")
                .map(std::fs::read_to_string)
                .transpose()
                .map_err(|_| "SM2_PRIVATE_KEY_FILE: unreadable key")?
        } else {
            None
        };
        if env("CRYPTO_ALGORITHM_PROFILE").as_deref() == Some("smx") && sm2_pem.is_none() {
            return Err("SM2_PRIVATE_KEY_FILE is required for smx".into());
        }
        let mut legacy = setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            secret.as_bytes(),
            &["authserver-hmac-1", "mailserver-drive-native-1"],
            sm2_pem.as_deref(),
        )?;
        if let Some(drive_secret) = drive_native_secret.as_deref() {
            legacy = legacy.with_hmac_kid("mailserver-drive-native-1", drive_secret.as_bytes());
        }
        keys = keys.with_legacy_keys(legacy);
    } else {
        let drive_secret = drive_native_secret.unwrap_or_default();
        let sm2_pub_pem = if matches!(
            env("CRYPTO_ALGORITHM_PROFILE").as_deref(),
            Some("smx" | "hybrid")
        ) {
            env("SM2_PUBLIC_KEY_FILE")
                .map(std::fs::read_to_string)
                .transpose()
                .map_err(|_| "SM2_PUBLIC_KEY_FILE: unreadable key")?
        } else {
            None
        };
        if !drive_secret.is_empty() || sm2_pub_pem.is_some() {
            let kids: &[&str] = if drive_secret.is_empty() {
                &[]
            } else {
                &["mailserver-drive-native-1"]
            };
            keys =
                keys.with_legacy_keys(setjoin_authz::legacy_jwt::LegacyKeys::from_sm2_public_pem(
                    drive_secret.as_bytes(),
                    kids,
                    sm2_pub_pem.as_deref(),
                )?);
        } else if allow_private_keys {
            eprintln!("setjoin-gateway: JWT_SECRET is unset; HS256/SM2 tokens will be refused (401). Set the authserver's JWT_SECRET in config.env.");
        }
    }
    Ok(Arc::new(keys))
}

#[allow(clippy::too_many_arguments)]
async fn build_with_keys<K: KeySource + 'static>(
    settings: &crate::configuration::Settings,
    deps: RouteDeps,
    table: RouteTable,
    edge: EdgeLimit,
    website: Option<Arc<setjoin_static::website::Website>>,
    dsn: String,
    pool: usize,
    exec: ScopedExecutor,
    keys: Arc<K>,
) -> Result<(RouteTable, Option<EdgeLimit>), String> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let RouteDeps {
        configuration,
        denylist,
        chain,
        threat,
        lifecycle,
        ldap,
        ad,
        subscription_sync,
        migration_runner,
        webhook,
        federation,
        platform_storage,
        auth_authority,
        listen_hub,
        allow_private_keys: _,
        boot_posture,
        search_facade,
        search_work_queue,
    } = deps;
    let issuer = env("JWT_ISSUER").unwrap_or_else(|| "mailserver".into());
    eprintln!(
        "setjoin-gateway: mark-read route installed (serves only while feature.rust_mark_read is ON)"
    );
    let family = crate::f16::F16Config::from_env(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
        denylist.clone(),
    )?;
    let compliance_worker_dsn = env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone());
    let worm = crate::compliance::WormConfig::from_settings(settings);
    let compliance = crate::compliance::ComplianceRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(&compliance_worker_dsn, pool)
            .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
            .with_audit_keys(
                env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                env("AUDIT_HMAC_KEY").unwrap_or_default(),
            ),
        jobs: {
            let jobs = crate::compliance::SearchJobs::new(
                setjoin_pg::workers::WorkerDatabase::new(&compliance_worker_dsn)
                    .map_err(|e| e.to_string())?,
                pool,
            );
            match search_work_queue {
                Some(q) => jobs.with_tier2_work_queue(q),
                None => jobs,
            }
        },
        store: Some(Arc::new(crate::recovery_worker::S3Store::from_env()?)),
        worm: Some(worm),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let surface_worker = compliance.worker.clone();
    let office = crate::f15::F15Config::from_env(
        exec.clone(),
        compliance.worker.clone(),
        keys.clone(),
        issuer.clone(),
    )?;
    let (attachment_secret, attachment_previous_secret) = crate::f16::attachment_secrets_from_env();
    let runtime =
        crate::runtime_access::RuntimeAccess::new(exec.clone(), keys.clone(), issuer.clone())
            .with_attachment_secrets(attachment_secret, attachment_previous_secret)
            .with_workers(
                compliance.worker.clone(),
                WorkerDatabase::from_dsns(&dsn, env("DB_WORKER_DSN").as_deref())
                    .map_err(|e| e.to_string())?,
            )
            .with_sessions(denylist.clone())
            .with_direct(
                env("DB_DIRECT_DSN")
                    .or_else(|| listen_hub.as_ref().map(|_| String::new()))
                    .ok_or("DB_DIRECT_DSN required for runtime gates")?,
            )
            .with_device_secret(
                crate::telemetry::device_hmac_key_from_env(),
                setjoin_config_secret::CryptoProfile::parse(
                    &env("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default(),
                ),
            );
    let runtime = match listen_hub.clone() {
        Some(hub) => runtime.with_listen_hub(hub),
        None => runtime,
    };
    let runtime = Arc::new(runtime);
    let denylist = runtime.session_cache();
    let kerberos: Option<Arc<dyn setjoin_authz::kerberos::KerberosValidator>> = if settings
        .boolean("kerberos.enabled")
    {
        let configured_keytab = settings.string("kerberos.keytab");
        let keytab = if !configured_keytab.is_empty() {
            std::path::PathBuf::from(configured_keytab)
        } else {
            let config_dir = env("CONFIG_DIR").unwrap_or_else(|| "/etc/mail".into());
            std::path::PathBuf::from(config_dir).join("mail.keytab")
        };
        let realm = settings.string("kerberos.realm");
        match setjoin_authz::kerberos::GssapiVerifier::new(
            setjoin_authz::kerberos::KerberosConfig { keytab, realm },
        ) {
            Ok(verifier) => Some(Arc::new(verifier)),
            Err(err) => {
                eprintln!("setjoin-gateway: kerberos enabled but unavailable (fail closed): {err}");
                None
            }
        }
    } else {
        None
    };
    let dav_basic = crate::dav_auth::DavBasicAuth {
        chain: chain.clone(),
        password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
        threat: threat.map(|gate| gate as Arc<dyn setjoin_threat::ThreatGate>),
        runtime: Some(runtime.clone() as Arc<dyn crate::runtime_access::RuntimeGate>),
        kerberos,
    };
    let chat_compliance = crate::chat_compliance::ChatComplianceRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        database: WorkerDatabase::new(&compliance_worker_dsn).map_err(|e| e.to_string())?,
        store: compliance.store.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let mail_security = crate::mail_security::MailSecurityRoute::new(
        exec.clone(),
        compliance.worker.clone(),
        keys.clone(),
        issuer.clone(),
    )
    .with_import_dir(Some(crate::mail_security_tls::import_dir_from_settings(
        settings,
    )))
    .with_trace(crate::mail_security_trace::TraceConfig::from_settings(
        settings,
    ));
    let rules = crate::rules::RulesRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let link_protect = crate::link_protect::LinkProtectRoute::from_env(compliance.worker.clone());
    let conditional_access = crate::conditional_access::ConditionalAccessRoute {
        exec: exec.clone(),
        worker: Some(
            ScopedExecutor::from_dsn(&env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()), pool)
                .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
                .with_audit_keys(
                    env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                    env("AUDIT_HMAC_KEY").unwrap_or_default(),
                ),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let retention_audit = crate::retention_audit::RetentionAuditRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let approval = crate::approvals::ApprovalsRoute {
        exec: exec.clone(),
        worker_exec: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        secret: crate::approvals::link_secret_from_env(),
    };
    let chat_store = Arc::new(crate::recovery_worker::S3Store::from_env()?);
    let channels = crate::chat_channels::ChannelRoute {
        unfurl: Some(Arc::new(crate::chat_unfurl::Unfurl::production(
            exec.clone(),
            chat_store.clone(),
        ))),
        federation_typing: federation
            .map(|service| Arc::new(crate::federation_typing::Typing::new(service))),
        federation_local_domain: std::env::var("FEDERATION_LOCAL_DOMAIN")
            .unwrap_or_default()
            .trim()
            .to_lowercase(),
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let chat_b = crate::chat_b::ChatBRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        store: Some(chat_store),
    };
    let chat = crate::chat::ChatRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let guests = crate::guests::GuestsRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        delivery: Some(Arc::new(crate::recovery_worker::S3Store::from_env()?)),
        lifecycle,
    };
    let calendar = crate::calendar::CalendarRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        queue: Some(
            WorkerDatabase::from_dsns(&dsn, env("DB_WORKER_DSN").as_deref())
                .map_err(|e| format!("DB_WORKER_DSN: {e}"))?,
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        store: Some(Arc::new(crate::recovery_worker::S3Store::from_env()?)),
        public_base: format!(
            "https://{}",
            env("HOSTNAME").unwrap_or_else(|| "localhost".into())
        ),
        // The detached first fetch of a new subscription is the
        // calendar-subscription-sync worker's; without it the route stays with Go.
        kick: subscription_sync.map(|sync| {
            Arc::new(crate::subscription_sync::SyncKick::new(sync))
                as Arc<dyn crate::calendar::SubscriptionKick>
        }),
    };
    // Go snapshots feature.caldav while mounting the listener. The process-local
    // timezone cache stays active in both processes until Go is deleted.
    let cal_tx = crate::policy_composition::tx_factory_from_executors(&exec, None)
        .ok_or_else(|| "CalDAV boot TxFactory unavailable".to_owned())?;
    let caldav = if setjoin_calendar::caldav_enabled(&cal_tx)
        .await
        .map_err(|_| "CalDAV boot feature unavailable".to_owned())?
    {
        let route = crate::caldav::CalDavRoute::new(exec.clone(), keys.clone(), issuer.clone())
            .await
            .with_basic_auth(dav_basic.clone());
        if let Some(hub) = listen_hub.clone() {
            route.start_timezone_hub(hub);
        } else if let Some(direct) = env("DB_DIRECT_DSN") {
            route.start_timezone_listener(direct);
        }
        Some(route)
    } else {
        None
    };
    // Like Go, snapshot the bridge registration flag at process startup.
    let carddav = if setjoin_calendar::flag(&cal_tx, "feature.carddav", true)
        .await
        .map_err(|_| "CardDAV boot feature unavailable".to_owned())?
    {
        Some(
            crate::carddav::CardDavRoute::new(exec.clone(), keys.clone(), issuer.clone())
                .with_basic_auth(dav_basic.clone()),
        )
    } else {
        None
    };
    let contacts = crate::contacts::ContactsRoute {
        exec: exec.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_identity = crate::admin_identity::AdminIdentityRoute {
        exec: exec.clone(),
        worker: Some(compliance.worker.clone()),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_access_reviews = crate::admin_access_reviews::AdminAccessReviewsRoute {
        exec: exec.clone(),
        worker: Some(compliance.worker.clone()),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_scope_sets = crate::admin_scope_sets::AdminScopeSetsRoute {
        exec: exec.clone(),
        worker: Some(compliance.worker.clone()),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_org_policies = crate::admin_org_policies::AdminOrgPoliciesRoute {
        exec: exec.clone(),
        worker: Some(compliance.worker.clone()),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let admin_sod = crate::admin_sod::AdminSodRoute {
        exec: exec.clone(),
        worker: Some(compliance.worker.clone()),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    // One ok-to-error tracker for both health verdicts (Go's single `health.Handler`).
    let health_alerts = webhook
        .clone()
        .map(|dispatcher| crate::health_alerts::HealthAlerts::new(dispatcher).observer());
    let mut platform =
        crate::platform::PlatformRoute::new(exec.clone(), keys.clone(), issuer.clone())
            .with_worker(compliance.worker.clone())
            .with_configuration(configuration.clone())
            .with_overrides(setjoin_platform::features::Overrides::from_env(&|name| {
                std::env::var(name).ok()
            }))
            .with_livekit(crate::meet_livekit::LiveKit::from_env())
            .with_boot_posture(boot_posture.clone());
    if let Some(alerts) = &health_alerts {
        platform = platform.with_health_alerts(alerts.clone());
    }
    let deploy_source = configuration.clone();
    let deploy_config = setjoin_platform::deploy::Config {
        host_key: env("DEPLOY_HOST_KEY").unwrap_or_default(),
        checksum: env("DEPLOY_SEAWEEDFS_SHA256").unwrap_or_default(),
        credentials: Arc::new(move || {
            deploy_source
                .source_settings()
                .map(|settings| {
                    (
                        settings.string("s3.access_key"),
                        settings.string("s3.secret_key"),
                    )
                })
                .unwrap_or_default()
        }),
    };
    let platform_updates = crate::platform_updates::PlatformUpdatesRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
    )
    .with_worker(compliance.worker.clone());
    let platform_updates = if let Some(hub) = listen_hub.clone() {
        platform_updates
            .with_recovery_hub(
                compliance.worker.clone(),
                family.as_ref().is_some_and(|f| f.continuity.is_some()),
                hub,
            )
            .await
    } else {
        platform_updates
            .with_recovery(
                compliance.worker.clone(),
                family.as_ref().is_some_and(|f| f.continuity.is_some()),
                env("DB_DIRECT_DSN"),
            )
            .await
    }
    .with_deploy(compliance.worker.clone(), deploy_config)
    .await
    .with_airgap(
        match setjoin_platform::airgap::Store::load(
            "/var/lib/setjoin/updates",
            env("OFFLINE_UPDATE_TRUST_ROOTS")
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/etc/setjoin/offline-update-roots.json".into()),
        ) {
            Ok(store) => Some(Arc::new(store)),
            Err(error) => {
                eprintln!("{error}");
                None
            }
        },
    );
    let platform_jobs = crate::platform_jobs::PlatformJobsRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        storage: platform_storage,
    };
    let platform_webhooks = crate::platform_webhooks::PlatformWebhooksRoute {
        exec: exec.clone(),
        worker: Some(compliance.worker.clone()),
        keys: keys.clone(),
        issuer: issuer.clone(),
        codec: super::workers::webhook_codec(),
    };
    let auth_admin =
        crate::auth_admin::AuthAdminRoute::new(exec.clone(), keys.clone(), issuer.clone());
    let platform_terms =
        crate::platform_terms::PlatformTermsRoute::new(exec.clone(), keys.clone(), issuer.clone())
            .with_worker(
                ScopedExecutor::from_dsn(
                    &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
                    pool,
                )
                .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
                .with_audit_keys(
                    env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                    env("AUDIT_HMAC_KEY").unwrap_or_default(),
                ),
            )
            .with_store(Arc::new(crate::recovery_worker::S3Store::from_env()?));
    let admin_identity_v2 = crate::admin_identity_v2::AdminIdentityV2Route {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        secrets: crate::admin_identity_v2::SourceSecrets::from_process_env().with_probe(Arc::new(
            crate::directory_sync::DirectoryProbe(
                WorkerDatabase::from_dsns(&dsn, env("DB_WORKER_DSN").as_deref())
                    .map_err(|e| format!("DB_WORKER_DSN: {e}"))?,
            ),
        )),
    };
    let admin_identity_v2_upgrade = crate::admin_identity_v2_upgrade::AdminIdentityV2UpgradeRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        secrets: crate::admin_identity_v2::SourceSecrets::from_process_env(),
        // Go's `IdentityRuntimeReadiness`: each DSN defaults to `DB_DSN`, the
        // authserver URL to a non-empty default.
        runtime: setjoin_admin_identity::idv2_upgrade::Runtime {
            expected_schema: setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0),
            worker_dsn: env("DB_WORKER_DSN").or_else(|| env("DB_DSN")).is_some(),
            owner_dsn: env("DB_OWNER_DSN").or_else(|| env("DB_DSN")).is_some(),
            direct_dsn: env("DB_DIRECT_DSN").or_else(|| env("DB_DSN")).is_some(),
            authserver: auth_authority.is_some()
                || std::env::var("AUTHSERVER_URL").map_or(true, |v| !v.is_empty()),
        },
    };
    let admin_users_lifecycle = crate::admin_users_lifecycle::AdminUsersLifecycleRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        authserver_url: env("SCIM_AUTHSERVER_URL")
            .unwrap_or_else(|| "http://localhost:8443".into()),
        internal_key: env("INTERNAL_API_KEY").unwrap_or_default(),
        authority: auth_authority.clone(),
        dispatcher: webhook.ok_or("DB_DSN is required for the webhook dispatcher")?,
    };
    let mailboxes = crate::mailboxes::MailboxesRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let mailbox_io = crate::mailbox_io::MailboxIoRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        store: Arc::new(crate::recovery_worker::S3Store::from_env()?),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let exchange = crate::exchange::ExchangeRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        artifacts: crate::exchange::Artifacts {
            signer: crate::exchange::signer_from_env()?,
            store: Some(Arc::new(crate::recovery_worker::S3Store::from_env()?)),
            master: env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            profile: setjoin_mailboxes::exchange_artifact::Profile::parse(
                &env("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default(),
            ),
        },
    };
    let migration = crate::migration::MigrationRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        encryption_key: env("DB_ENCRYPTION_KEY").unwrap_or_default(),
        runner: migration_runner.clone(),
        public_host: env("HOSTNAME").unwrap_or_default(),
    };
    let devices = crate::devices::DevicesRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let identity_self_service = crate::identity_self_service::IdentitySelfServiceRoute {
        exec: exec.clone(),
        worker: compliance.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        webhook_codec: super::workers::webhook_codec(),
        migration_runner,
        webhook_resolver: std::sync::Arc::new(crate::identity_self_service::SystemResolver),
    };
    let user_settings =
        crate::user_settings::UserSettingsRoute::new(exec.clone(), keys.clone(), issuer.clone());
    let offline = crate::offline::OfflineRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?,
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let dirsync = crate::directory_sync::DirectorySyncRoute {
        exec: exec.clone(),
        worker: Some(
            ScopedExecutor::from_dsn(&env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()), pool)
                .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
                .with_audit_keys(
                    env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                    env("AUDIT_HMAC_KEY").unwrap_or_default(),
                ),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        ldap,
        ad,
    };
    let scim = crate::scim::ScimRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        keys: keys.clone(),
        issuer: issuer.clone(),
        authserver_url: env("SCIM_AUTHSERVER_URL")
            .unwrap_or_else(|| "http://localhost:8443".into()),
        internal_key: env("INTERNAL_API_KEY").unwrap_or_default(),
        authority: auth_authority.clone(),
    };
    let mut drive_native = crate::drive_native::NativeTokenRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
        crate::drive_native::drive_native_secret_from_env().as_deref(),
    )
    .with_basic_auth(dav_basic)
    .with_chain(chain);
    if let Some(authority) = auth_authority.clone() {
        drive_native = drive_native.with_authority(authority);
    }
    let drive = crate::drive::DriveRoute {
        exec: exec.clone(),
        worker: ScopedExecutor::from_dsn(
            &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
            pool,
        )
        .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
        .with_audit_keys(
            env("DB_ENCRYPTION_KEY").unwrap_or_default(),
            env("AUDIT_HMAC_KEY").unwrap_or_default(),
        ),
        store: Some(Arc::new(crate::recovery_worker::S3Store::from_env()?)),
        keys: keys.clone(),
        issuer: issuer.clone(),
    };
    let drive_core = crate::drive::core::CoreRoute {
        exec: exec.clone(),
        worker: drive.worker.clone(),
        keys: keys.clone(),
        issuer: issuer.clone(),
        store: office.store.clone(),
    };
    let meet = crate::meet::MeetRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
        crate::meet_livekit::LiveKit::from_env(),
    )
    .with_worker(
        ScopedExecutor::from_dsn(&env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()), pool)
            .map_err(|e| format!("DB_WORKER_DSN: {}", e.0))?
            .with_audit_keys(
                env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                env("AUDIT_HMAC_KEY").unwrap_or_default(),
            ),
    );
    // Go registers /rtc only when the LiveKit sidecar is configured, at the
    // fixed loopback signal address.
    let rtc = crate::rtc::RtcRoute::new(
        exec.clone(),
        keys.clone(),
        issuer.clone(),
        crate::meet_livekit::LiveKit::from_env().configured(),
        crate::rtc::SFU_SIGNAL
            .parse()
            .expect("fixed SFU signal address"),
    )
    .without_guest_belt();
    let (assist_exec, assist_keys, assist_issuer) = (exec.clone(), keys.clone(), issuer.clone());
    let commands = Arc::new(JmapCommands {
        worker: Some(compliance.worker.clone()),
        services: Some(Arc::new({
            let svcs = crate::jmap::JmapServices::from_env(
                ScopedExecutor::from_dsn(
                    &env("DB_WORKER_DSN").unwrap_or_else(|| dsn.clone()),
                    pool,
                )
                .map_err(|e| e.0)?
                .with_audit_keys(
                    env("DB_ENCRYPTION_KEY").unwrap_or_default(),
                    env("AUDIT_HMAC_KEY").unwrap_or_default(),
                ),
            );
            match search_facade {
                Some(facade) => svcs.with_search_facade(facade),
                None => svcs,
            }
        })),
        exec,
        keys: keys.clone(),
        issuer: issuer.clone(),
        denylist: denylist.clone(),
    });
    let mut push = crate::jmap::push::WebSocketRoute::new(
        commands.clone(),
        env("DB_DIRECT_DSN").unwrap_or_default(),
    )
    .with_device_cache(runtime.device_cache());
    if let Some(hub) = listen_hub {
        push = push.with_listen_hub(hub);
    }
    push.worker = Some(
        WorkerDatabase::from_dsns(&dsn, env("DB_WORKER_DSN").as_deref())
            .map_err(|e| format!("push DB_WORKER_DSN: {e}"))?,
    );
    push.production = env("TLS_CERT_FILE").is_some()
        || env("TLS_CERT").is_some()
        || env("HTTP_MODE").as_deref() == Some("proxy");
    let hostname = env("HOSTNAME").unwrap_or_else(|| "localhost".into());
    if push.production && hostname != "localhost" {
        push.allowed_host = hostname;
    }
    let event_source = crate::jmap::sse::EventSourceRoute::new(&push);
    let presence = crate::jmap::presence::PresenceRoute {
        commands: commands.clone(),
        registry: push.registry.clone(),
    };
    let mut table = table
        .with_admission(
            compliance.worker.clone(),
            keys.clone(),
            issuer.clone(),
            denylist,
        )
        .with(event_source)
        .with(push)
        .with(presence)
        .with(JmapRoute(commands));
    table = table
        .with(compliance)
        .with(chat_compliance)
        .with(retention_audit)
        .with(mail_security)
        .with(rules)
        .with(link_protect)
        .with(conditional_access)
        .with(approval)
        .with(chat)
        .with(chat_b)
        .with(channels)
        .with(guests)
        .with(calendar)
        .with(contacts)
        .with(admin_identity)
        .with(admin_scope_sets)
        .with(admin_org_policies)
        .with(admin_access_reviews)
        .with(admin_sod)
        .with(platform)
        .with(platform_terms)
        .with(auth_admin)
        .with(platform_updates)
        .with(platform_webhooks)
        .with(platform_jobs)
        .with(admin_identity_v2)
        .with(admin_identity_v2_upgrade)
        .with(admin_users_lifecycle)
        .with(mailboxes)
        .with(mailbox_io)
        .with(migration)
        .with(devices)
        .with(user_settings)
        .with(identity_self_service)
        .with(offline)
        .with(exchange)
        .with(dirsync)
        .with(scim)
        .with(drive_native)
        .with(drive_core)
        .with(drive)
        .with(meet);
    if let Some(caldav) = caldav {
        table = table.with(caldav);
    }
    let mut catchall = crate::catchall::CatchallRoute::new().with_terminal_auth(
        assist_exec.clone(),
        assist_keys.clone(),
        assist_issuer.clone(),
    );
    catchall.meet_configured = crate::meet_livekit::LiveKit::from_env().configured();
    catchall.website = website;
    table = table.with(rtc.with_fallback(Arc::new(catchall.clone())));
    table = match carddav {
        Some(route) => table.with(route),
        None => table.with(crate::carddav::Unregistered {
            fallback: catchall.clone(),
        }),
    };
    let surface_config = Arc::new(crate::surface::SurfaceConfig::from_settings(settings));
    table = table
        .with(crate::surface::SurfaceRoute {
            discovery: None,
            fallback: Some(Arc::new(catchall.clone())),
            exec: assist_exec.clone(),
            worker: Some(surface_worker),
            keys: assist_keys.clone(),
            issuer: assist_issuer.clone(),
            health: Arc::new({
                let livekit = crate::meet_livekit::LiveKit::from_env();
                let gate =
                    setjoin_static::health::HealthGate::new(surface_config.probes_configured)
                        .with_boot_posture(boot_posture.clone())
                        .with_probes(Arc::new(move || {
                            let livekit = livekit.clone();
                            Box::pin(
                                async move { crate::platform::any_probe_failed(&livekit).await },
                            )
                        }));
                match &health_alerts {
                    Some(alerts) => gate.with_alerts(alerts.clone()),
                    None => gate,
                }
            }),
            config: surface_config,
        })
        .with(crate::assist::AssistRoute {
            exec: assist_exec,
            keys: assist_keys,
            issuer: assist_issuer,
        });
    if let Some(config) = family {
        table = table.with(crate::f16::F16Route::new(config));
    }
    table = table.with(crate::f15::F15Route::new(office));
    Ok((
        table.with_catchall(catchall).with_runtime(runtime),
        Some(edge),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use setjoin_authz::token::KeySource;
    use std::collections::HashMap;

    #[test]
    fn non_auth_node_never_loads_jwt_secret_or_sm2_private_key() {
        let vars = HashMap::from([
            ("JWT_SECRET", "0123456789abcdef0123456789abcdef"),
            ("CRYPTO_ALGORITHM_PROFILE", "smx"),
            ("SM2_PRIVATE_KEY_FILE", "/nonexistent/sm2-private.pem"),
        ]);
        let env = |k: &str| vars.get(k).map(|v| (*v).to_owned());

        // Non-auth node (`allow_private_keys = false`) MUST ignore JWT_SECRET and
        // SM2_PRIVATE_KEY_FILE even when AUTHSERVER_URL is unset and SM2 path is unreadable.
        let non_auth = build_legacy_jwks(&env, false)
            .expect("non-auth build_legacy_jwks must succeed without reading private keys");
        assert!(
            non_auth.legacy_keys().is_none(),
            "non-auth node must not load JWT_SECRET into legacy_keys"
        );

        // Legacy/auth node (`allow_private_keys = true`) reads JWT_SECRET + SM2_PRIVATE_KEY_FILE.
        let legacy_err = build_legacy_jwks(&env, true).err();
        assert_eq!(
            legacy_err.as_deref(),
            Some("SM2_PRIVATE_KEY_FILE: unreadable key"),
            "legacy mode must still read SM2_PRIVATE_KEY_FILE when allow_private_keys = true"
        );

        // With standard profile and allow_private_keys = true, JWT_SECRET IS loaded.
        let std_vars = HashMap::from([("JWT_SECRET", "0123456789abcdef0123456789abcdef")]);
        let std_env = |k: &str| std_vars.get(k).map(|v| (*v).to_owned());
        let legacy_ok = build_legacy_jwks(&std_env, true).expect("legacy standard jwks");
        assert!(
            legacy_ok.legacy_keys().is_some(),
            "legacy mode with allow_private_keys = true must load JWT_SECRET"
        );
    }
}
