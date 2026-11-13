//! #457: `system.health_alert` on the ok-to-error transition of a health check. Frozen Go's
//! real `health.Handler` and Dispatcher (overlay `tests/conformance/drain/health_alert_tick_test.go.txt`)
//! and the Rust public (`/health`) and admin (`/admin/health`) evaluations, sharing one
//! `HealthAlerts` tracker, run the same steps over the same seeded `health_history`; the
//! fake receiver must see the same alerts (exact signed bodies) and no repeat for a
//! persistent error. Record: `GOFREE_RECORD_DRAIN=all GOFREE_GO_SOURCE=<sha>`.
mod common;
mod drain_oracle;
use common::webhook_receiver::{self as hooks, Seen};
use drain_oracle::{settle, BoxError, GoTick};
use serde_json::json;
use setjoin_conformance::harness::Db;
use setjoin_gateway::health_alerts::HealthAlerts;
use setjoin_static::health::HealthGate;

fn insert(rows: &[(&str, &str)]) -> String {
    let values: Vec<String> = rows
        .iter()
        .map(|(c, s)| format!("('wh457_{c}','{s}','oracle')"))
        .collect();
    format!(
        "sql:INSERT INTO health_history(check_name,status,details) VALUES {}",
        values.join(",")
    )
}

/// Both cases rewrite the global `health_history` table: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_alerts_on_ok_to_error_transitions() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("health-alerts") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let recording = std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
    let seen: Seen = Seen::default();
    let hook = hooks::receiver(seen.clone()).await;
    let steps = [
        insert(&[
            ("disk", "ok"),
            ("queue", "error"),
            ("cert", "warn"),
            ("zeta", "error"),
        ]),
        "public".into(),
        "public".into(),
        "admin".into(),
        insert(&[("zeta", "ok"), ("disk", "error")]),
        "admin".into(),
        insert(&[("zeta", "error")]),
        "public".into(),
        insert(&[("queue", "warn")]),
        "public".into(),
        insert(&[("queue", "error")]),
        "admin".into(),
        "public".into(),
    ];
    let result = async {
        owner.batch_execute("DELETE FROM health_history").await?;
        hooks::clear(&owner).await?;
        let account = setjoin_conformance::fixture::account(&owner, "wh457-health").await?;
        for (path, scope, active, types) in [
            ("/alert", "organization", true, r#"["system.health_alert"]"#),
            ("/self", "self", true, r#"["system.health_alert"]"#),
            ("/other", "organization", true, r#"["user.updated"]"#),
            ("/inactive", "organization", false, r#"["system.health_alert"]"#),
        ] {
            hooks::subscribe(&owner, account.user, hook, path, types, scope, active).await?;
        }
        let outcome = async {
            if recording {
                GoTick {
                    package: "internal/health",
                    overlay: "health_alert_tick_test.go.txt",
                    test: "TestGoFreeHealthAlerts",
                    file: "gofree_health_alert_test.go",
                    env: vec![
                        ("GOFREE_DRAIN_DSN".into(), db.dsn.clone()),
                        ("GOFREE_WEBHOOK_MASTER".into(), hooks::MASTER.into()),
                        ("GOFREE_HEALTH_STEPS".into(), steps.join(";")),
                    ],
                    docker: vec![],
                }
                .run_with(&[("internal/webhook", "gofree_unguarded_export.go", "webhook_unguarded_export.go.txt")])?;
            } else {
                let dispatcher = hooks::unguarded(&db.dsn)?;
                let alerts = HealthAlerts::new(dispatcher.clone());
                let observer = alerts.observer();
                let exec = setjoin_pg::ScopedExecutor::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
                for step in &steps {
                    match step.as_str() {
                        "public" => {
                            // Seed-plus-one-request seam: the public route drives the real
                            // tracker and signed dispatcher with Go absent.
                            let table = setjoin_gateway::RouteTable::proxy_all().with(setjoin_gateway::surface::SurfaceRoute {
                                exec: exec.clone(), keys: std::sync::Arc::new(common::recovery_keys()),
                                issuer: "mailserver".into(), config: std::sync::Arc::new(setjoin_gateway::surface::SurfaceConfig::from_env()),
                                health: std::sync::Arc::new(HealthGate::new(false).with_alerts(observer.clone())),
                                fallback: None, discovery: None,
                            });
                            let gateway = setjoin_gateway::Gateway::new(setjoin_gateway::Config {
                                upstream: None, trusted_proxies: setjoin_gateway::TrustedProxies::parse("")?,
                                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT, edge_limit: None,
                            }, table)?;
                            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                            let address = listener.local_addr()?;
                            let task = tokio::spawn(gateway.serve(listener));
                            let response = common::send(address, hyper::Request::builder().uri("/health").body(common::full(""))?).await;
                            assert_eq!(response.status(), hyper::StatusCode::SERVICE_UNAVAILABLE);
                            assert_eq!(common::body_bytes(response).await.as_ref(), b"{\"status\":\"error\"}\n");
                            let metrics = common::send(address, hyper::Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;
                            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
                            task.abort(); let _ = task.await;
                            assert!(metrics.lines().any(|line| line == "setjoin_gateway_proxied_to_go_total 0"));
                        }
                        "admin" => {
                            setjoin_platform::health::evaluate(&exec, &[], "now", Some(&observer)).await;
                        }
                        sql => {
                            owner.batch_execute(sql.strip_prefix("sql:").ok_or("step")?).await?;
                        }
                    }
                    dispatcher.quiesce().await;
                }
                dispatcher.shutdown().await;
            }
            settle(
                "health-alerts",
                json!({"deliveries": hooks::deliveries(&owner).await?, "requests": hooks::requests(&seen)}),
                recording,
            )
        }
        .await;
        setjoin_conformance::fixture::remove(&owner, &account).await?;
        outcome
    }
    .await;
    let _ = hooks::clear(&owner).await;
    let _ = owner
        .batch_execute("DELETE FROM health_history WHERE check_name LIKE 'wh457_%'")
        .await;
    result
}

/// Go registers the live probes (`sfu`, `egress`, `asr`) on the handler: a failed probe makes
/// the public verdict `error` (503) but is never an alert, because only `health_history`
/// rows pass through the transition tracker. A gate with probes configured and no runner
/// still leaves the request to Go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_live_probe_is_an_error_verdict_but_not_an_alert() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use setjoin_static::health::Outcome;
    use std::sync::{Arc, Mutex};
    let Some(db) = Db::for_case("health-probes") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    owner.batch_execute("DELETE FROM health_history").await?;
    owner.batch_execute("INSERT INTO health_history(check_name,status,details) VALUES ('wh457_probe_base','ok','oracle')").await?;
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&db.dsn, 2).map_err(|e| e.0)?;
    let rows: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let observer: setjoin_static::health::Alerts = {
        let rows = rows.clone();
        Arc::new(move |checked| {
            rows.lock().unwrap().extend(checked);
            Box::pin(async {})
        })
    };
    let verdict = |failed: bool| {
        let probes: setjoin_static::health::Probes =
            Arc::new(move || Box::pin(async move { failed }));
        HealthGate::new(true)
            .with_alerts(observer.clone())
            .with_probes(probes)
    };
    let error = verdict(true).public(&exec).await;
    let ok = verdict(false).public(&exec).await;
    let deferred = HealthGate::new(true).public(&exec).await;
    owner
        .batch_execute("DELETE FROM health_history WHERE check_name LIKE 'wh457_%'")
        .await?;
    assert_eq!(
        error,
        Outcome::Json {
            status: 503,
            overall: "error"
        }
    );
    assert_eq!(
        ok,
        Outcome::Json {
            status: 200,
            overall: "ok"
        }
    );
    assert_eq!(deferred, Outcome::Defer);
    assert!(rows
        .lock()
        .unwrap()
        .iter()
        .all(|(check, status)| check == "wh457_probe_base" && status == "ok"));
    Ok(())
}
