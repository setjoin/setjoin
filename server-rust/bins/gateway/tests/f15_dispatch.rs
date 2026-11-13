//! Complete family registration, metrics and rollback at the HTTP boundary.
mod common;
#[path = "common/office_fixture.rs"]
mod office_fixture;
use hyper::{Request, Response};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[tokio::test]
async fn every_f15_registration_dispatches_without_go() -> Result<(), common::BoxError> {
    run(false, false).await
}
#[tokio::test]
async fn f15_kill_switch_forwards_the_identical_requests() -> Result<(), common::BoxError> {
    run(true, false).await
}
#[tokio::test]
async fn f15_inventory_rollback_forwards_the_identical_requests() -> Result<(), common::BoxError> {
    run(false, true).await
}
async fn run(kill: bool, rollback: bool) -> Result<(), common::BoxError> {
    let _serial = office_fixture::SERIAL.lock().await;
    let Some(db) = Db::for_case("f15-dispatch") else {
        return Ok(());
    };
    let (c, seed) = office_fixture::seed(&db).await?;
    let result = async {
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let go = common::fake_upstream(move |mut r| {
            let observed = observed.clone();
            async move {
                use http_body_util::BodyExt;
                let body = r.body_mut().collect().await.unwrap().to_bytes();
                assert!(body.is_empty() || body == "{");
                observed.fetch_add(1, Ordering::SeqCst);
                Response::builder()
                    .status(202)
                    .body(common::full("Go rollback"))
                    .unwrap()
            }
        })
        .await;
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let config = setjoin_gateway::f15::F15Config {
            exec: setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
                .map_err(|e| e.0)?,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            store: Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(
                &format!("http://{s3}"),
                "mailblobs",
                "test-access",
                "test-secret",
            )?)),
        };
        let table = RouteTable::proxy_all().with(setjoin_gateway::f15::F15Route::new(config));
        let gateway = Gateway::new(
            Config {
                upstream: if kill || rollback {
                    Some(format!("http://{go}").parse()?)
                } else {
                    None
                },
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            table,
        )?
        .with_enabled(!kill);
        let gateway = if rollback {
            let mut inventory: serde_json::Value =
                serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
            for r in inventory["routes"].as_array_mut().unwrap() {
                if r["family"] == "F15" {
                    r["state"] = "OFF".into();
                    r["upstream"] = "go-mail".into();
                }
            }
            gateway.with_inventory(&inventory.to_string())?
        } else {
            gateway
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(gateway.serve(listener));
        for (method, path, body, status) in [
            ("GET", "/api/office/wopi/files/invalid", "", 400),
            ("GET", "/api/office/wopi/files/invalid/contents", "", 400),
            ("POST", "/api/office/wopi/files/invalid", "", 400),
            ("POST", "/api/office/wopi/files/invalid/contents", "", 400),
            ("GET", "/api/admin/office", "", 200),
            ("PUT", "/api/admin/office/providers/office1", "{", 400),
            (
                "POST",
                "/api/admin/office/providers/office1/qualify",
                "{",
                400,
            ),
            (
                "POST",
                "/api/admin/office/providers/office1/activate",
                "{",
                400,
            ),
            ("DELETE", "/api/admin/office/providers/office1", "", 400),
        ] {
            let response = common::send(
                address,
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header(
                        "authorization",
                        format!("Bearer {}", office_fixture::token(seed.account.user, true)),
                    )
                    .header(
                        "x-audit-reason",
                        if method == "DELETE" {
                            ""
                        } else {
                            "Office1 parity"
                        },
                    )
                    .body(common::full(body))?,
            )
            .await;
            let actual = response.status().as_u16();
            let bytes = common::body_bytes(response).await;
            if actual != if kill || rollback { 202 } else { status } {
                task.abort();
                return Err(
                    format!("{method} {path}: expected {status}, got {actual} {bytes:?}").into(),
                );
            }
        }
        if !kill && !rollback {
            let response = common::send(
                address,
                Request::get("/_gateway/metrics").body(common::full(""))?,
            )
            .await;
            let text = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if !text.contains("setjoin_gateway_proxied_to_go_total 0") {
                return Err(format!("native family reached Go: {text}").into());
            }
        }
        task.abort();
        if hits.load(Ordering::SeqCst) != if kill || rollback { 9 } else { 0 } {
            return Err("wrong Go rollback count".into());
        }
        Ok::<_, common::BoxError>(())
    }
    .await;
    office_fixture::cleanup(&c, &seed).await?;
    result
}
