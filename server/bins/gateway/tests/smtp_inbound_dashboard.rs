//! The SMTP batch store's frozen-Go gauges reach the real authenticated dashboard.
mod common;
use futures_util::FutureExt;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_gateway::{
    mail_security::MailSecurityRoute, Config, Gateway, RouteTable, TrustedProxies,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

#[tokio::test]
async fn inbound_model_gauges_reach_the_admin_dashboard_and_release_on_quit() {
    let db = setjoin_conformance::harness::Db::for_case("smtp6-dashboard").unwrap();
    let owner = db.connect().await.unwrap();
    let cleanup = include_str!("../../../crates/protocols/smtp/oracle/cleanup.sql");
    owner.batch_execute(cleanup).await.unwrap();
    owner
        .batch_execute(include_str!(
            "../../../crates/protocols/smtp/oracle/seed.sql"
        ))
        .await
        .unwrap();
    let role = "gofree-smtp6-dashboard";
    owner
        .execute(
            "INSERT INTO admin_role_groups(name,permissions) VALUES($1,ARRAY['mail.pipeline'])",
            &[&role],
        )
        .await
        .unwrap();
    owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT 9348011,id,9348011,false FROM admin_role_groups WHERE name=$1", &[&role]).await.unwrap();
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../crates/protocols/smtp/oracle/security-ftrl-go.json"
    ))
    .unwrap();
    let case = corpus
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ftrl-batch-reuse")
        .unwrap();
    let worker = setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap();
    let stats = setjoin_spam::process_stats();
    let store = Arc::new(setjoin_spam::Store::new(worker.clone()).with_stats(stats));
    struct Flags;
    impl setjoin_smtp::submission::Flags for Flags {
        fn enabled(&self, key: &str) -> bool {
            matches!(key, "feature.ml_spam" | "feature.spam_model_batch_load")
        }
    }
    let smtp = Arc::new(
        setjoin_smtp::Server::new()
            .with_database(worker)
            .with_spam_store(store)
            .with_flags(Arc::new(Flags)),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let smtp_task = tokio::spawn(smtp.serve(listener, rx));
    let route = MailSecurityRoute::new(
        common::patient_exec(db.app.as_deref().unwrap(), 2).unwrap(),
        common::patient_exec(&db.dsn, 2).unwrap(),
        Arc::new(common::recovery_keys()),
        "mailserver".into(),
    );
    let gateway = Gateway::new(
        Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(route),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = listener.local_addr().unwrap();
    let gateway_task = tokio::spawn(gateway.serve(listener));
    let token = common::recovery_token_with(9348011, json!({"admin":true}));
    let check = |expected: Value| {
        let token = token.clone();
        async move {
            let response = common::send(
                http,
                Request::builder()
                    .uri("/api/admin/spam")
                    .header("host", "mail.test")
                    .header("authorization", format!("Bearer {token}"))
                    .body(common::full(""))
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), 200);
            let body: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            for (field, observed) in [
                ("batch_load_loads", "Loads"),
                ("batch_load_hits", "Hits"),
                ("batch_load_resident_models", "ResidentModels"),
                ("batch_load_resident_bytes", "ResidentBytes"),
            ] {
                assert_eq!(body[field], expected[observed], "SMTP store gauge {field}");
            }
        }
    };
    let result = std::panic::AssertUnwindSafe(async {
        let mut socket = TcpStream::connect(address).await.unwrap();
        for step in case["steps"].as_array().unwrap() {
            socket
                .write_all(step["send"].as_str().unwrap().as_bytes())
                .await
                .unwrap();
            let mut reply = Vec::new();
            for _ in 0..step["lines"].as_u64().unwrap() {
                loop {
                    let mut byte = [0];
                    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut byte))
                        .await
                        .unwrap()
                        .unwrap();
                    reply.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
            }
            assert_eq!(
                String::from_utf8(reply).unwrap(),
                step["reply"].as_str().unwrap()
            );
            if let Some(expected) = step.get("batch_stats") {
                check(expected.clone()).await;
            }
        }
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        // Wait for the closed session's monitoring row, after its batch was dropped.
        for _ in 0..100 {
            if owner
                .query_one(
                    "SELECT count(*) FROM smtp_sessions WHERE remote_ip='127.0.0.1'",
                    &[],
                )
                .await
                .unwrap()
                .get::<_, i64>(0)
                == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        check(case["batch_stats_after"].clone()).await;
    })
    .catch_unwind()
    .await;
    let _ = stop.send(true);
    smtp_task.await.unwrap().unwrap();
    gateway_task.abort();
    let _ = gateway_task.await;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=9348011",
            &[],
        )
        .await
        .unwrap();
    owner
        .execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role])
        .await
        .unwrap();
    owner.batch_execute(cleanup).await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
