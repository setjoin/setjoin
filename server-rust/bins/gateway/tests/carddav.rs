//! Frozen Go CardDAV oracle: real front door, assigned disposable DB, no Go in replay.
mod carddav_oracle;
mod common;
#[tokio::test]
async fn options_success() -> Result<(), common::BoxError> {
    carddav_oracle::run("options", "success", None).await
}

#[tokio::test]
async fn propfind_success() -> Result<(), common::BoxError> {
    carddav_oracle::run("propfind", "success", None).await
}

#[tokio::test]
async fn get_success() -> Result<(), common::BoxError> {
    carddav_oracle::run("get", "success", None).await
}

#[tokio::test]
async fn propfind_members() -> Result<(), common::BoxError> {
    carddav_oracle::run("propfind", "members", None).await
}

#[tokio::test]
async fn reports_success() -> Result<(), common::BoxError> {
    for kind in ["query", "multiget", "sync"] {
        carddav_oracle::run(kind, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn writes_success() -> Result<(), common::BoxError> {
    for kind in ["put", "put-update", "delete"] {
        carddav_oracle::run(kind, "success", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn gal_success() -> Result<(), common::BoxError> {
    for kind in [
        "gal-options",
        "gal-propfind",
        "gal-get",
        "gal-query",
        "gal-multiget",
        "gal-sync",
        "gal-put",
        "gal-delete",
    ] {
        carddav_oracle::run(kind, "success", None).await?;
    }
    Ok(())
}

macro_rules! case {
    ($name:ident,$route:literal,$label:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            carddav_oracle::run($route, $label, None).await
        }
    };
}
case!(
    qualification_options_cross_tenant,
    "options",
    "cross-tenant"
);
case!(
    qualification_options_invalid_input,
    "options",
    "invalid-input"
);
case!(
    qualification_propfind_cross_tenant,
    "propfind",
    "cross-tenant"
);
case!(
    qualification_propfind_invalid_input,
    "propfind",
    "invalid-input"
);
case!(qualification_get_cross_tenant, "get", "cross-tenant");
case!(qualification_get_invalid_input, "get", "invalid-input");
case!(qualification_query_cross_tenant, "query", "cross-tenant");
case!(qualification_query_invalid_input, "query", "invalid-input");
case!(
    qualification_multiget_cross_tenant,
    "multiget",
    "cross-tenant"
);
case!(
    qualification_multiget_invalid_input,
    "multiget",
    "invalid-input"
);
case!(qualification_sync_cross_tenant, "sync", "cross-tenant");
case!(qualification_sync_invalid_input, "sync", "invalid-input");
case!(qualification_put_cross_tenant, "put", "cross-tenant");
case!(qualification_put_invalid_input, "put", "invalid-input");
case!(
    qualification_put_update_cross_tenant,
    "put-update",
    "cross-tenant"
);
case!(
    qualification_put_update_invalid_input,
    "put-update",
    "invalid-input"
);
case!(qualification_delete_cross_tenant, "delete", "cross-tenant");
case!(
    qualification_delete_invalid_input,
    "delete",
    "invalid-input"
);
case!(
    qualification_unsupported_cross_tenant,
    "unsupported",
    "cross-tenant"
);
case!(
    qualification_unsupported_invalid_input,
    "unsupported",
    "invalid-input"
);
case!(qualification_unsupported_success, "unsupported", "success");
case!(
    qualification_gal_options_cross_tenant,
    "gal-options",
    "cross-tenant"
);
case!(
    qualification_gal_options_invalid_input,
    "gal-options",
    "invalid-input"
);
case!(
    qualification_gal_propfind_cross_tenant,
    "gal-propfind",
    "cross-tenant"
);
case!(
    qualification_gal_propfind_invalid_input,
    "gal-propfind",
    "invalid-input"
);
case!(
    qualification_gal_get_cross_tenant,
    "gal-get",
    "cross-tenant"
);
case!(
    qualification_gal_get_invalid_input,
    "gal-get",
    "invalid-input"
);
case!(
    qualification_gal_query_cross_tenant,
    "gal-query",
    "cross-tenant"
);
case!(
    qualification_gal_query_invalid_input,
    "gal-query",
    "invalid-input"
);
case!(
    qualification_gal_multiget_cross_tenant,
    "gal-multiget",
    "cross-tenant"
);
case!(
    qualification_gal_multiget_invalid_input,
    "gal-multiget",
    "invalid-input"
);
case!(
    qualification_gal_sync_cross_tenant,
    "gal-sync",
    "cross-tenant"
);
case!(
    qualification_gal_sync_invalid_input,
    "gal-sync",
    "invalid-input"
);
case!(
    qualification_gal_put_cross_tenant,
    "gal-put",
    "cross-tenant"
);
case!(
    qualification_gal_put_invalid_input,
    "gal-put",
    "invalid-input"
);
case!(
    qualification_gal_delete_cross_tenant,
    "gal-delete",
    "cross-tenant"
);
case!(
    qualification_gal_delete_invalid_input,
    "gal-delete",
    "invalid-input"
);
case!(
    qualification_entitlement_cross_tenant,
    "entitlement",
    "cross-tenant"
);
case!(
    qualification_entitlement_invalid_input,
    "entitlement",
    "invalid-input"
);
case!(qualification_entitlement_success, "entitlement", "success");
case!(edge_put_repeat, "put", "repeat");
case!(edge_put_update_repeat, "put-update", "repeat");
case!(edge_delete_repeat, "delete", "repeat");
case!(edge_gal_propfind_repeat, "gal-propfind", "repeat");
case!(edge_gal_get_repeat, "gal-get", "repeat");
case!(edge_gal_query_repeat, "gal-query", "repeat");
case!(edge_gal_multiget_repeat, "gal-multiget", "repeat");
case!(edge_gal_sync_repeat, "gal-sync", "repeat");
case!(edge_gal_put_repeat, "gal-put", "repeat");
case!(edge_gal_delete_repeat, "gal-delete", "repeat");
case!(edge_propfind_properties, "propfind", "properties");
case!(edge_propfind_resource, "propfind", "resource");
case!(edge_propfind_depth0, "propfind", "depth0");
case!(edge_propfind_limit, "propfind", "limit");
case!(edge_propfind_gal_off, "propfind", "gal-off");
case!(edge_get_fold, "get", "fold");
case!(edge_get_encoded, "get", "encoded");
case!(edge_query_filter, "query", "filter");
case!(edge_query_no_match, "query", "no-match");
case!(edge_query_unknown, "query", "unknown");
case!(edge_query_wrong_namespace, "query", "wrong-namespace");
case!(edge_query_limit, "query", "limit");
case!(edge_multiget_uid_collision, "multiget", "uid-collision");
case!(edge_sync_current, "sync", "current");
case!(edge_sync_removed, "sync", "removed");
case!(edge_sync_updated, "sync", "updated");
case!(edge_sync_pruned, "sync", "pruned");
case!(edge_sync_resync, "sync", "resync");
case!(edge_sync_future, "sync", "future");
case!(edge_put_if_none, "put", "if-none");
case!(edge_put_if_match_missing, "put", "if-match-missing");
case!(edge_put_bad_path, "put", "bad-path");
case!(edge_put_limit, "put", "limit");
case!(edge_put_vcard4, "put", "vcard4");
case!(edge_put_photo, "put", "photo");
case!(edge_put_update_if_match, "put-update", "if-match");
case!(edge_put_update_if_match_good, "put-update", "if-match-good");
case!(edge_delete_if_match, "delete", "if-match");
case!(edge_delete_if_match_good, "delete", "if-match-good");
case!(edge_delete_bad_path, "delete", "bad-path");
case!(edge_unsupported_head, "unsupported", "head");
case!(edge_unsupported_mkcol, "unsupported", "mkcol");
case!(edge_unsupported_proppatch, "unsupported", "proppatch");
case!(edge_unsupported_copy, "unsupported", "copy");
case!(edge_unsupported_move, "unsupported", "move");
case!(edge_unsupported_lock, "unsupported", "lock");
case!(edge_unsupported_unlock, "unsupported", "unlock");
case!(edge_gal_get_disabled, "gal-get", "disabled");
case!(edge_gal_get_hidden, "gal-get", "hidden");
case!(edge_gal_get_guest, "gal-get", "guest");
case!(edge_gal_get_gal_off, "gal-get", "gal-off");
case!(edge_gal_get_full_profile, "gal-get", "full-profile");
case!(edge_gal_propfind_properties, "gal-propfind", "properties");
case!(edge_gal_propfind_depth0, "gal-propfind", "depth0");
case!(edge_gal_propfind_gal_off, "gal-propfind", "gal-off");
case!(edge_gal_propfind_limit, "gal-propfind", "limit");
case!(edge_gal_query_alias_filter, "gal-query", "alias-filter");
case!(edge_gal_query_hidden_manager, "gal-query", "hidden-manager");
case!(edge_gal_query_guest, "gal-query", "guest");
case!(edge_gal_query_gal_off, "gal-query", "gal-off");
case!(edge_gal_multiget_gal_off, "gal-multiget", "gal-off");
case!(edge_gal_sync_current, "gal-sync", "current");
case!(edge_gal_sync_removed, "gal-sync", "removed");
case!(edge_gal_sync_never_visible, "gal-sync", "never-visible");
case!(edge_gal_sync_count_mismatch, "gal-sync", "count-mismatch");
case!(edge_gal_sync_future, "gal-sync", "future");
case!(edge_gal_sync_gal_off, "gal-sync", "gal-off");
case!(edge_gal_put_gal_off, "gal-put", "gal-off");
case!(edge_gal_delete_gal_off, "gal-delete", "gal-off");

#[tokio::test]
async fn scan_errors_preserve_contacts() -> Result<(), common::BoxError> {
    for route in ["get", "put-update", "delete"] {
        carddav_oracle::run(route, "bad-json", None).await?;
    }
    Ok(())
}

#[tokio::test]
async fn recovery_before_commit() -> Result<(), common::BoxError> {
    for route in ["put", "put-update", "delete", "gal-sync"] {
        carddav_oracle::run(route, "success", Some("commit-before")).await?;
    }
    Ok(())
}
#[tokio::test]
async fn recovery_after_commit() -> Result<(), common::BoxError> {
    for route in ["put", "put-update", "delete", "gal-sync"] {
        carddav_oracle::run(route, "success", Some("commit-after")).await?;
    }
    Ok(())
}
macro_rules! mutant_case {
    ($name:ident,$route:literal,$label:literal,$mutant:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            carddav_oracle::run($route, $label, Some($mutant)).await
        }
    };
}
mutant_case!(mutants_no_notify, "put", "success", "no-notify");
mutant_case!(mutants_no_audit, "entitlement", "success", "no-audit");
mutant_case!(
    mutants_no_tenant_filter,
    "get",
    "cross-tenant",
    "no-tenant-filter"
);
mutant_case!(mutants_double_bump, "put", "success", "double-bump");
mutant_case!(status_mutant_options, "options", "success", "status");
mutant_case!(status_mutant_propfind, "propfind", "success", "status");
mutant_case!(status_mutant_get, "get", "success", "status");
mutant_case!(status_mutant_query, "query", "success", "status");
mutant_case!(status_mutant_multiget, "multiget", "success", "status");
mutant_case!(status_mutant_sync, "sync", "success", "status");
mutant_case!(status_mutant_put, "put", "success", "status");
mutant_case!(status_mutant_put_update, "put-update", "success", "status");
mutant_case!(status_mutant_delete, "delete", "success", "status");
mutant_case!(
    status_mutant_unsupported,
    "unsupported",
    "success",
    "status"
);
mutant_case!(
    status_mutant_gal_options,
    "gal-options",
    "success",
    "status"
);
mutant_case!(
    status_mutant_gal_propfind,
    "gal-propfind",
    "success",
    "status"
);
mutant_case!(status_mutant_gal_get, "gal-get", "success", "status");
mutant_case!(status_mutant_gal_query, "gal-query", "success", "status");
mutant_case!(
    status_mutant_gal_multiget,
    "gal-multiget",
    "success",
    "status"
);
mutant_case!(status_mutant_gal_sync, "gal-sync", "success", "status");
mutant_case!(status_mutant_gal_put, "gal-put", "success", "status");
mutant_case!(status_mutant_gal_delete, "gal-delete", "success", "status");
mutant_case!(
    status_mutant_entitlement,
    "entitlement",
    "success",
    "status"
);

#[tokio::test]
async fn real_client_sessions() -> Result<(), common::BoxError> {
    carddav_oracle::run("client-session", "vdirsyncer", None).await
}
#[tokio::test]
async fn executable_client_sessions() -> Result<(), common::BoxError> {
    carddav_oracle::run("client-executable", "vdirsyncer", None).await
}
case!(fault_put_db_fault, "put", "db-fault");
case!(fault_put_unaccounted, "put", "unaccounted");
case!(fault_put_bad_accounting, "put", "bad-accounting");
case!(fault_put_update_db_fault, "put-update", "db-fault");
case!(fault_put_update_unaccounted, "put-update", "unaccounted");
case!(
    fault_put_update_bad_accounting,
    "put-update",
    "bad-accounting"
);
case!(fault_delete_db_fault, "delete", "db-fault");
case!(fault_delete_unaccounted, "delete", "unaccounted");
case!(fault_delete_bad_accounting, "delete", "bad-accounting");
case!(fault_sync_db_fault, "sync", "db-fault");
case!(fault_gal_sync_db_fault, "gal-sync", "db-fault");

#[tokio::test]
async fn stale_contacts_are_accounted() -> Result<(), common::BoxError> {
    carddav_oracle::accounting::stale().await
}

case!(
    disabled_bridge_is_native_not_found,
    "options",
    "bridge-disabled"
);

mod basic_tests {
    use super::carddav_oracle::SERIAL;
    use super::common::{self, BoxError};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use futures_util::FutureExt;
    use hyper::{Request, Response};
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{
        carddav::CardDavRoute, dav_auth::DavBasicAuth, Config, Gateway, Intercept, RouteTable,
        TrustedProxies,
    };
    use setjoin_threat::{ConnectionMeta, ThreatAction, ThreatGate};
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct MockThreat {
        action: ThreatAction,
        delay: std::time::Duration,
        intercepts: Mutex<Vec<ConnectionMeta>>,
        records: Mutex<Vec<(ConnectionMeta, bool, i64)>>,
    }

    impl MockThreat {
        fn new(action: ThreatAction, delay: std::time::Duration) -> Arc<Self> {
            Arc::new(Self {
                action,
                delay,
                intercepts: Mutex::new(Vec::new()),
                records: Mutex::new(Vec::new()),
            })
        }
    }

    impl ThreatGate for MockThreat {
        fn intercept<'a>(
            &'a self,
            meta: &'a ConnectionMeta,
        ) -> futures_util::future::BoxFuture<'a, (ThreatAction, std::time::Duration)> {
            Box::pin(async move {
                self.intercepts.lock().unwrap().push(meta.clone());
                (self.action, self.delay)
            })
        }
        fn record_result<'a>(
            &'a self,
            meta: &'a ConnectionMeta,
            success: bool,
            user_id: i64,
        ) -> futures_util::future::BoxFuture<'a, ()> {
            Box::pin(async move {
                self.records
                    .lock()
                    .unwrap()
                    .push((meta.clone(), success, user_id));
            })
        }
        fn evaluate_post_auth<'a>(
            &'a self,
            _meta: &'a mut ConnectionMeta,
        ) -> futures_util::future::BoxFuture<'a, (ThreatAction, String)> {
            Box::pin(async move { (ThreatAction::Allow, String::new()) })
        }
    }

    fn basic_header(email: &str, secret: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{email}:{secret}")))
    }

    fn token_hash(token: &str) -> String {
        Sha256::digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    async fn with_fixture<F, Fut>(f: F) -> Result<(), BoxError>
    where
        F: FnOnce(
            Arc<tokio_postgres::Client>,
            setjoin_pg::ScopedExecutor,
            Arc<setjoin_authz::jwks::Jwks>,
            fixture::Account,
            String,
        ) -> Fut,
        Fut: std::future::Future<Output = Result<(), BoxError>>,
    {
        let _serial = SERIAL.lock().await;
        let Some(db) = Db::for_case("carddav-basic-auth") else {
            return Ok(());
        };
        let owner = Arc::new(db.connect().await?);
        let a = fixture::account(&owner, "carddav-basic").await?;
        let email: String = owner
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await?
            .get(0);
        let saved_basic = owner
            .query_opt(
                "SELECT enabled FROM feature_toggles WHERE key='feature.disable_basic_auth'",
                &[],
            )
            .await?
            .map(|r| r.get::<_, bool>(0));
        owner
            .execute(
                "INSERT INTO feature_toggles(key,enabled) VALUES('feature.disable_basic_auth',false) ON CONFLICT(key) DO UPDATE SET enabled=false",
                &[],
            )
            .await?;
        let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?;
        let keys = Arc::new(common::recovery_keys());
        let res =
            std::panic::AssertUnwindSafe(f(owner.clone(), exec, keys, a.clone(), email.clone()))
                .catch_unwind()
                .await;
        if let Some(on) = saved_basic {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.disable_basic_auth'",
                    &[&on],
                )
                .await?;
        } else {
            owner
                .execute(
                    "DELETE FROM feature_toggles WHERE key='feature.disable_basic_auth'",
                    &[],
                )
                .await?;
        }
        owner
            .execute(
                "DELETE FROM auth_event_log WHERE user_id=$1 OR lower(email)=lower($2)",
                &[&a.user, &email],
            )
            .await?;
        owner
            .execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&a.user])
            .await?;
        owner
            .execute("DELETE FROM app_passwords WHERE user_id=$1", &[&a.user])
            .await?;
        owner
            .execute(
                "DELETE FROM session_revocations WHERE user_id=$1",
                &[&a.user],
            )
            .await?;
        fixture::remove(&owner, &a).await?;
        match res {
            Ok(inner) => inner,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    async fn spawn_gateway(
        upstream: Option<std::net::SocketAddr>,
        route: CardDavRoute<setjoin_authz::jwks::Jwks>,
    ) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), BoxError> {
        let table = RouteTable::proxy_all()
            .with(route)
            .with_catchall(setjoin_gateway::catchall::CatchallRoute::new());
        let gateway = Gateway::new(
            Config {
                upstream: upstream
                    .map(|a| format!("http://{a}").parse())
                    .transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            table,
        )?
        .with_inventory(setjoin_gateway::inventory::BUNDLED)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(gateway.serve(listener));
        Ok((addr, task))
    }

    async fn send_carddav(
        addr: std::net::SocketAddr,
        method: &str,
        auth: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<(u16, Option<String>, String), BoxError> {
        let mut req = Request::builder()
            .method(method)
            .uri("/carddav/")
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("depth", "0");
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        if let Some(cookie) = cookie {
            req = req.header("cookie", cookie);
        }
        let resp = common::send(addr, req.body(common::full(""))?).await;
        let status = resp.status().as_u16();
        let www = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = String::from_utf8(common::body_bytes(resp).await.to_vec())?;
        Ok((status, www, body))
    }

    #[tokio::test]
    async fn basic_app_password_succeeds_and_admits_member_skips_basic() -> Result<(), BoxError> {
        with_fixture(|owner, exec, keys, a, email| async move {
            let app_token = "carddav-basic-app-pw-1";
            owner
                .execute(
                    "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'carddav','carddav',$2)",
                    &[&a.user, &token_hash(app_token)],
                )
                .await?;
            let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
            chain.reload(&exec).await.unwrap();
            let threat = MockThreat::new(ThreatAction::Allow, std::time::Duration::ZERO);
            let route = CardDavRoute::new(exec, keys, "mailserver".into()).with_basic_auth(
                DavBasicAuth {
                    chain: Some(chain),
                    password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                    threat: Some(threat.clone()),
                    runtime: None,
                },
            );
            let mut basic_headers = hyper::HeaderMap::new();
            basic_headers.insert(
                hyper::header::AUTHORIZATION,
                basic_header(&email, app_token).parse()?,
            );
            assert!(
                !route.admits_member(basic_headers, "http").await,
                "admits_member must stay JWT/cookie only"
            );
            assert!(threat.intercepts.lock().unwrap().is_empty());
            assert!(threat.records.lock().unwrap().is_empty());

            let (addr, server) = spawn_gateway(None, route).await?;
            let (status, _, _) =
                send_carddav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
            assert_eq!(status, 200);
            let (status, _, body) = send_carddav(
                addr,
                "PROPFIND",
                Some(&basic_header(&email, app_token)),
                Some("access_token=invalid-jwt"),
            )
            .await?;
            assert_eq!(status, 207, "invalid cookie must not block Basic: {body}");
            assert!(body.contains("multistatus"));

            let intercepts = threat.intercepts.lock().unwrap().clone();
            assert_eq!(intercepts.len(), 2);
            assert!(intercepts.iter().all(|m| m.protocol == "http" && m.username == email));
            let records = threat.records.lock().unwrap().clone();
            assert_eq!(records.len(), 2);
            assert!(records.iter().all(|(m, ok, uid)| m.protocol == "http" && *ok && *uid == a.user));
            let metrics = String::from_utf8(
                common::body_bytes(
                    common::send(addr, Request::get("/_gateway/metrics").body(common::full(""))?).await,
                )
                .await
                .to_vec(),
            )?;
            assert!(metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_total 0"));
            server.abort();
            let _ = server.await;
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn basic_account_password_refused() -> Result<(), BoxError> {
        with_fixture(|owner, exec, keys, a, email| async move {
            let pw = "carddav-Account-Password1";
            let hash = bcrypt::hash_with_result(pw, 4)
                .unwrap()
                .format_for_version(bcrypt::Version::TwoA);
            owner
                .execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&hash, &a.user])
                .await?;
            let app_token = "carddav-basic-app-pw-guest";
            owner
                .execute(
                    "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'carddav','carddav',$2)",
                    &[&a.user, &token_hash(app_token)],
                )
                .await?;
            let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
            chain.reload(&exec).await.unwrap();
            let threat = MockThreat::new(ThreatAction::Allow, std::time::Duration::ZERO);
            let route =
                CardDavRoute::new(exec.clone(), keys.clone(), "mailserver".into()).with_basic_auth(
                    DavBasicAuth {
                        chain: Some(chain.clone()),
                        password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                        threat: Some(threat.clone()),
                        runtime: None,
                    },
                );
            let (addr, server) = spawn_gateway(None, route).await?;

            // Account password refused
            let (status, www, _) =
                send_carddav(addr, "OPTIONS", Some(&basic_header(&email, pw)), None).await?;
            assert_eq!(status, 401);
            assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));

            // TOTP account password refused
            owner
                .execute("UPDATE users SET totp_enabled=true WHERE id=$1", &[&a.user])
                .await?;
            let (status, www, _) =
                send_carddav(addr, "OPTIONS", Some(&basic_header(&email, pw)), None).await?;
            assert_eq!(status, 401);
            assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
            owner
                .execute("UPDATE users SET totp_enabled=false WHERE id=$1", &[&a.user])
                .await?;

            // Guest app password refused
            owner
                .execute(
                    "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,'guest@test','inviter@test',$2,'active')",
                    &[&a.user, &a.domain],
                )
                .await?;
            let (status, www, _) =
                send_carddav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
            assert_eq!(status, 401);
            assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
            owner
                .execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&a.user])
                .await?;

            // Missing / invalid Basic never touches ThreatGate or auth_event_log
            let intercepts_before = threat.intercepts.lock().unwrap().len();
            let events_before: i64 = owner
                .query_one(
                    "SELECT count(*) FROM auth_event_log WHERE user_id=$1 OR lower(email)=lower($2)",
                    &[&a.user, &email],
                )
                .await?
                .get(0);
            for bad in [None, Some("Basic !!!"), Some("Basic dXNlcg=="), Some("basic dXNlcjpwYXNz")] {
                let (status, www, _) = send_carddav(addr, "OPTIONS", bad, None).await?;
                assert_eq!(status, 401, "header {bad:?}");
                assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
            }
            assert_eq!(threat.intercepts.lock().unwrap().len(), intercepts_before);

            // basic_allowed=false -> 401 without ThreatGate or auth_event_log
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=true WHERE key='feature.disable_basic_auth'",
                    &[],
                )
                .await?;
            chain.reload(&exec).await.unwrap();
            let (status, www, _) =
                send_carddav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
            assert_eq!(status, 401);
            assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
            assert_eq!(threat.intercepts.lock().unwrap().len(), intercepts_before);
            let events_after: i64 = owner
                .query_one(
                    "SELECT count(*) FROM auth_event_log WHERE user_id=$1 OR lower(email)=lower($2)",
                    &[&a.user, &email],
                )
                .await?
                .get(0);
            assert_eq!(events_after, events_before);
            server.abort();
            let _ = server.await;
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn basic_threat_gate_actions_and_negotiate_forward() -> Result<(), BoxError> {
        with_fixture(|owner, exec, keys, a, email| async move {
            let app_token = "carddav-basic-app-pw-threat";
            owner
                .execute(
                    "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'carddav','carddav',$2)",
                    &[&a.user, &token_hash(app_token)],
                )
                .await?;
            let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
            chain.reload(&exec).await.unwrap();

            for (action, delay) in [
                (ThreatAction::Reject, std::time::Duration::ZERO),
                (ThreatAction::Tarpitted, std::time::Duration::from_millis(40)),
                (ThreatAction::RateLimited, std::time::Duration::ZERO),
            ] {
                let threat = MockThreat::new(action, delay);
                let route = CardDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
                    .with_basic_auth(DavBasicAuth {
                        chain: Some(chain.clone()),
                        password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                        threat: Some(threat.clone()),
                        runtime: None,
                    });
                let (addr, server) = spawn_gateway(None, route).await?;
                let started = std::time::Instant::now();
                let (status, www, _) =
                    send_carddav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
                assert_eq!(status, 401, "{action:?}");
                assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));
                if !delay.is_zero() {
                    assert!(started.elapsed() >= std::time::Duration::from_millis(30));
                }
                assert!(threat.records.lock().unwrap().is_empty());
                server.abort();
                let _ = server.await;
            }

            // Missing ThreatGate (None) -> fail closed 503
            let no_threat = CardDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
                .with_basic_auth(DavBasicAuth {
                    chain: Some(chain.clone()),
                    password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                    threat: None,
                    runtime: None,
                });
            let (addr, server) = spawn_gateway(None, no_threat).await?;
            let (status, _, _) =
                send_carddav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
            assert_eq!(status, 503);
            server.abort();
            let _ = server.await;

            // Negotiate forwards to Go
            let go_hits = Arc::new(AtomicUsize::new(0));
            let hits = go_hits.clone();
            let go = common::fake_upstream(move |_| {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .status(218)
                        .body(common::full("go-negotiate"))
                        .unwrap()
                }
            })
            .await;
            let threat = MockThreat::new(ThreatAction::Allow, std::time::Duration::ZERO);
            let route = CardDavRoute::new(exec, keys, "mailserver".into()).with_basic_auth(
                DavBasicAuth {
                    chain: Some(chain),
                    password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                    threat: Some(threat.clone()),
                    runtime: None,
                },
            );
            let (addr, server) = spawn_gateway(Some(go), route).await?;
            let (status, _, body) =
                send_carddav(addr, "OPTIONS", Some("Negotiate YII="), None).await?;
            assert_eq!(status, 218);
            assert_eq!(body, "go-negotiate");
            assert_eq!(go_hits.load(Ordering::SeqCst), 1);
            assert!(threat.intercepts.lock().unwrap().is_empty());
            server.abort();
            let _ = server.await;
            Ok(())
        })
        .await
    }
}
