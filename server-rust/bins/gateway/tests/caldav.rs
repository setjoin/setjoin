//! Frozen-Go CalDAV HTTP oracle (#426). No Go upstream during replay.
mod caldav_oracle;
mod common;

#[tokio::test]
async fn options_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "success", None).await
}

#[tokio::test]
async fn propfind_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "success", None).await
}

#[tokio::test]
async fn propfind_properties() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "properties", None).await
}

#[tokio::test]
async fn propfind_timezone_owned() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "timezone-owned", None).await
}

#[tokio::test]
async fn propfind_timezone_foreign() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "timezone-foreign", None).await
}

#[tokio::test]
async fn get_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "success", None).await
}

#[tokio::test]
async fn get_todo() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "todo", None).await
}

#[tokio::test]
async fn get_journal() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "journal", None).await
}

#[tokio::test]
async fn get_all_day() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "all-day", None).await
}

#[tokio::test]
async fn get_timezone() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "timezone", None).await
}

#[tokio::test]
async fn get_recurring() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "recurring", None).await
}

#[tokio::test]
async fn get_fold() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "fold", None).await
}

#[tokio::test]
async fn report_query_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "success", None).await
}

#[tokio::test]
async fn report_query_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "cross-tenant", None).await
}

#[tokio::test]
async fn report_query_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "invalid-input", None).await
}

#[tokio::test]
async fn report_multiget_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "success", None).await
}

#[tokio::test]
async fn report_multiget_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "cross-tenant", None).await
}

#[tokio::test]
async fn report_multiget_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "invalid-input", None).await
}

#[tokio::test]
async fn report_freebusy_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "success", None).await
}

#[tokio::test]
async fn report_freebusy_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "cross-tenant", None).await
}

#[tokio::test]
async fn report_freebusy_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "invalid-input", None).await
}

#[tokio::test]
async fn report_sync_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "success", None).await
}

#[tokio::test]
async fn report_sync_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "cross-tenant", None).await
}

#[tokio::test]
async fn report_sync_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "invalid-input", None).await
}

#[tokio::test]
async fn reads_get_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "cross-tenant", None).await
}

#[tokio::test]
async fn reads_get_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "invalid-input", None).await
}

#[tokio::test]
async fn reads_options_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "cross-tenant", None).await
}

#[tokio::test]
async fn reads_options_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "invalid-input", None).await
}

#[tokio::test]
async fn reads_propfind_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "cross-tenant", None).await
}

#[tokio::test]
async fn reads_propfind_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "invalid-input", None).await
}

#[tokio::test]
async fn reads_propfind_members() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "members", None).await
}

#[tokio::test]
async fn reads_propfind_event() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "event", None).await
}

#[tokio::test]
async fn reads_propfind_length() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "length", None).await
}

#[tokio::test]
async fn put_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", None).await
}

#[tokio::test]
async fn put_more_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "cross-tenant", None).await
}

#[tokio::test]
async fn put_more_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "invalid-input", None).await
}

#[tokio::test]
async fn put_more_update() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "update", None).await
}

#[tokio::test]
async fn put_more_repeat() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "repeat", None).await
}

#[tokio::test]
async fn put_more_if_none() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "if-none", None).await
}

#[tokio::test]
async fn put_more_if_match() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "if-match", None).await
}

#[tokio::test]
async fn put_more_if_match_create() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "if-match-create", None).await
}

#[tokio::test]
async fn put_more_uid_mismatch() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "uid-mismatch", None).await
}

#[tokio::test]
async fn put_more_bad_path() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "bad-path", None).await
}

#[tokio::test]
async fn put_more_todo() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "todo", None).await
}

#[tokio::test]
async fn put_more_journal() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "journal", None).await
}

#[tokio::test]
async fn put_more_attendees() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "attendees", None).await
}

#[tokio::test]
async fn put_more_recurring() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "recurring", None).await
}

#[tokio::test]
async fn writes_delete_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "success", None).await
}

#[tokio::test]
async fn writes_delete_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "cross-tenant", None).await
}

#[tokio::test]
async fn writes_delete_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "invalid-input", None).await
}

#[tokio::test]
async fn writes_delete_if_match() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "if-match", None).await
}

#[tokio::test]
async fn writes_delete_repeat() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "repeat", None).await
}

#[tokio::test]
async fn writes_mkcalendar_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "success", None).await
}

#[tokio::test]
async fn writes_mkcalendar_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "cross-tenant", None).await
}

#[tokio::test]
async fn writes_mkcalendar_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "invalid-input", None).await
}

#[tokio::test]
async fn writes_unsupported_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "success", None).await
}

#[tokio::test]
async fn writes_unsupported_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "cross-tenant", None).await
}

#[tokio::test]
async fn writes_unsupported_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "invalid-input", None).await
}

#[tokio::test]
async fn writes_head_success() -> Result<(), common::BoxError> {
    caldav_oracle::run("head", "success", None).await
}

#[tokio::test]
async fn hardening_get_encoded() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "encoded", None).await
}

#[tokio::test]
async fn hardening_put_todo_date() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "todo-date", None).await
}

#[tokio::test]
async fn hardening_put_recurrence_invalid() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "recurrence-invalid", None).await
}

#[tokio::test]
async fn hardening_put_recurrence_parameters() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "recurrence-parameters", None).await
}

#[tokio::test]
async fn hardening_propfind_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind-limit", "invalid-input", None).await
}

#[tokio::test]
async fn hardening_report_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("report-limit", "invalid-input", None).await
}

#[tokio::test]
async fn hardening_put_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("put-limit", "invalid-input", None).await
}

#[tokio::test]
async fn hardening_mkcalendar_limit_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar-limit", "invalid-input", None).await
}

#[tokio::test]
async fn calendar_entitlement_denied() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "denied", None).await
}

#[tokio::test]
async fn timezone_cache_lifecycle() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "timezone-cache", None).await
}

#[tokio::test]
async fn mutants_reject_no_audit() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "denied", Some("no-audit")).await
}

#[tokio::test]
async fn mutants_reject_no_notify() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("no-notify")).await
}

#[tokio::test]
async fn mutants_reject_no_tenant_filter() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "cross-tenant", Some("no-tenant-filter")).await
}

#[tokio::test]
async fn mutants_reject_double_bump() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("double-bump")).await
}

#[tokio::test]
async fn recovery_before_commit() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("commit-before")).await
}
#[tokio::test]
async fn recovery_after_commit() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("commit-after")).await
}

#[tokio::test]
async fn real_client_sessions() -> Result<(), common::BoxError> {
    caldav_oracle::run("session", "python-caldav", None).await
}

#[tokio::test]
async fn executable_client_sessions() -> Result<(), common::BoxError> {
    caldav_oracle::run("executable", "python-caldav", None).await
}

#[tokio::test]
async fn entitlement_cross_tenant() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "cross-tenant", None).await
}
#[tokio::test]
async fn entitlement_invalid_input() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "invalid-input", None).await
}

#[tokio::test]
async fn status_mutant_options() -> Result<(), common::BoxError> {
    caldav_oracle::run("options", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_propfind() -> Result<(), common::BoxError> {
    caldav_oracle::run("propfind", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_get() -> Result<(), common::BoxError> {
    caldav_oracle::run("get", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_query() -> Result<(), common::BoxError> {
    caldav_oracle::run("query", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_multiget() -> Result<(), common::BoxError> {
    caldav_oracle::run("multiget", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_freebusy() -> Result<(), common::BoxError> {
    caldav_oracle::run("freebusy", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_sync() -> Result<(), common::BoxError> {
    caldav_oracle::run("sync", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_put() -> Result<(), common::BoxError> {
    caldav_oracle::run("put", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_delete() -> Result<(), common::BoxError> {
    caldav_oracle::run("delete", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_mkcalendar() -> Result<(), common::BoxError> {
    caldav_oracle::run("mkcalendar", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_unsupported() -> Result<(), common::BoxError> {
    caldav_oracle::run("unsupported", "success", Some("status")).await
}

#[tokio::test]
async fn status_mutant_entitlement() -> Result<(), common::BoxError> {
    caldav_oracle::run("entitlement", "denied", Some("status")).await
}

mod basic_tests {
    use super::caldav_oracle::SERIAL;
    use super::common::{self, BoxError};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use futures_util::FutureExt;
    use hyper::{Request, Response};
    use setjoin_conformance::{fixture, harness::Db};
    use setjoin_gateway::{
        caldav::CalDavRoute, dav_auth::DavBasicAuth, BoxFuture, Config, Gateway, Intercept,
        RouteTable, TrustedProxies,
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
        let Some(db) = Db::for_case("caldav-basic-auth") else {
            return Ok(());
        };
        let owner = Arc::new(db.connect().await?);
        let a = fixture::account(&owner, "caldav-basic").await?;
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
        route: CalDavRoute<setjoin_authz::jwks::Jwks>,
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

    async fn send_caldav(
        addr: std::net::SocketAddr,
        method: &str,
        auth: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<(u16, Option<String>, String), BoxError> {
        let mut req = Request::builder()
            .method(method)
            .uri("/caldav/")
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
            let app_token = "caldav-basic-app-pw-1";
            owner
                .execute(
                    "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'caldav','caldav',$2)",
                    &[&a.user, &token_hash(app_token)],
                )
                .await?;
            let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
            chain.reload(&exec).await.unwrap();
            let threat = MockThreat::new(ThreatAction::Allow, std::time::Duration::ZERO);
            let route = CalDavRoute::new(exec, keys, "mailserver".into())
                .await
                .with_basic_auth(DavBasicAuth {
                    chain: Some(chain),
                    password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                    threat: Some(threat.clone()),
                    runtime: None,
                });
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
                send_caldav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
            assert_eq!(status, 200);
            let (status, _, body) = send_caldav(
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
            let pw = "caldav-Account-Password1";
            let hash = bcrypt::hash_with_result(pw, 4)
                .unwrap()
                .format_for_version(bcrypt::Version::TwoA);
            owner
                .execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&hash, &a.user])
                .await?;
            let app_token = "caldav-basic-app-pw-guest";
            owner
                .execute(
                    "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'caldav','caldav',$2)",
                    &[&a.user, &token_hash(app_token)],
                )
                .await?;
            let chain = Arc::new(setjoin_authz::auth_chain::Chain::default());
            chain.reload(&exec).await.unwrap();
            let threat = MockThreat::new(ThreatAction::Allow, std::time::Duration::ZERO);
            let route = CalDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
                .await
                .with_basic_auth(DavBasicAuth {
                    chain: Some(chain.clone()),
                    password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                    threat: Some(threat.clone()),
                    runtime: None,
                });
            let (addr, server) = spawn_gateway(None, route).await?;

            // Account password refused
            let (status, www, _) =
                send_caldav(addr, "OPTIONS", Some(&basic_header(&email, pw)), None).await?;
            assert_eq!(status, 401);
            assert_eq!(www.as_deref(), Some("Negotiate, Bearer realm=\"mailserver\""));

            // TOTP account password refused
            owner
                .execute("UPDATE users SET totp_enabled=true WHERE id=$1", &[&a.user])
                .await?;
            let (status, www, _) =
                send_caldav(addr, "OPTIONS", Some(&basic_header(&email, pw)), None).await?;
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
                send_caldav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
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
                let (status, www, _) = send_caldav(addr, "OPTIONS", bad, None).await?;
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
                send_caldav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
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
            let app_token = "caldav-basic-app-pw-threat";
            owner
                .execute(
                    "INSERT INTO app_passwords(user_id,name,label,token_hash) VALUES($1,'caldav','caldav',$2)",
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
                let route = CalDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
                    .await
                    .with_basic_auth(DavBasicAuth {
                        chain: Some(chain.clone()),
                        password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                        threat: Some(threat.clone()),
                        runtime: None,
                    });
                let (addr, server) = spawn_gateway(None, route).await?;
                let started = std::time::Instant::now();
                let (status, www, _) =
                    send_caldav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
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
            let no_threat = CalDavRoute::new(exec.clone(), keys.clone(), "mailserver".into())
                .await
                .with_basic_auth(DavBasicAuth {
                    chain: Some(chain.clone()),
                    password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                    threat: None,
                    runtime: None,
                });
            let (addr, server) = spawn_gateway(None, no_threat).await?;
            let (status, _, _) =
                send_caldav(addr, "OPTIONS", Some(&basic_header(&email, app_token)), None).await?;
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
            let route = CalDavRoute::new(exec, keys, "mailserver".into())
                .await
                .with_basic_auth(DavBasicAuth {
                    chain: Some(chain),
                    password_cache: Arc::new(setjoin_authz::basic::PasswordCache::new()),
                    threat: Some(threat.clone()),
                    runtime: None,
                });
            let (addr, server) = spawn_gateway(Some(go), route).await?;
            let (status, _, body) =
                send_caldav(addr, "OPTIONS", Some("Negotiate YII="), None).await?;
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
