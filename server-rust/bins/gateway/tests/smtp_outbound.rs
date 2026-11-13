//! Named worker handover checked through the actual gateway process.
use crate::common::boot::Child;
use crate::common::boot::CommandBootExt;
mod common;
use std::os::unix::process::CommandExt;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().expect("reap owned gofree-smtp4 gateway");
    }
}
#[test]
fn outbound_worker_refuses_shared_effects_until_go_is_off() {
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .arg0("gofree-smtp4-gateway-guard")
            .env_clear()
            .env("GATEWAY_LISTEN", "127.0.0.1:0")
            .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
            .env("RUST_WORKERS_ON", "outbound-mail")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn_boot()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.is_some_and(|s| !s.success()),
        "outbound-mail started while frozen Go still owns its effects"
    );
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.0.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    assert!(
        stderr.contains("outbound-mail requires GO_WORKERS_OFF=outbound-mail"),
        "{stderr}"
    );
}

#[path = "../../../crates/protocols/smtp/tests/support/outbound.rs"]
mod outbound_oracle;
#[tokio::test]
async fn stored_raw_blobs_match_frozen_go_through_native_s3() {
    outbound_oracle::replay(
        include_str!("../../../crates/protocols/smtp/oracle/outbound-go.json"),
        "all-delivered-repeat",
    )
    .await;
    for corpus in [
        include_str!("../../../crates/protocols/smtp/oracle/outbound-blobs-go.json"),
        include_str!("../../../crates/protocols/smtp/oracle/outbound-blobs-valid-go.json"),
    ] {
        let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
        let factory = |address| -> std::sync::Arc<dyn setjoin_smtp::outbound::RawSource> {
            std::sync::Arc::new(setjoin_gateway::smtp_outbound::BlobSource(
                setjoin_gateway::recovery_worker::S3Store::new(
                    &format!("http://{address}"),
                    "mail",
                    "smtp3-access",
                    "smtp3-secret",
                )
                .unwrap()
                .with_region("us-east-1".into()),
            ))
        };
        for case in cases.as_array().unwrap() {
            outbound_oracle::replay_with(
                corpus,
                case["case"]["name"].as_str().unwrap(),
                Some(&factory),
                &|worker, _| worker,
            )
            .await
        }
    }
}

#[tokio::test]
async fn all_transport_security_features_start_the_real_worker_on_its_worker_credential() {
    use futures_util::FutureExt;
    let _serial = outbound_oracle::SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp3-process") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/protocols/smtp/oracle");
    let cleanup = std::fs::read_to_string(root.join("outbound-cleanup.sql")).unwrap();
    owner.batch_execute(&cleanup).await.unwrap();
    owner
        .batch_execute(&std::fs::read_to_string(root.join("seed.sql")).unwrap())
        .await
        .unwrap();
    let cases: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("outbound-go.json")).unwrap())
            .unwrap();
    owner
        .batch_execute(cases[0]["case"]["sql"].as_str().unwrap())
        .await
        .unwrap();
    owner
        .batch_execute("UPDATE outbound_queue SET rcpt_addrs=ARRAY['invalid'] WHERE id=9350011;")
        .await
        .unwrap();
    let backlog: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/protocols/smtp/oracle/outbound-backlog-go.json"
    ))
    .unwrap();
    let sql = backlog[0]["case"]["sql"].as_str().unwrap();
    let future = sql.rfind("INSERT INTO outbound_queue(id,message_id,from_addr,rcpt_addrs,raw_ref,status,next_attempt_at)").unwrap();
    owner.batch_execute(&sql[future..]).await.unwrap();
    let names = vec![
        "feature.mta_sts",
        "feature.tls_rpt",
        "feature.dane",
        "feature.dnssec",
    ];
    let previous = owner
        .query(
            "SELECT row_to_json(t)::text FROM feature_toggles t WHERE key=ANY($1)",
            &[&names],
        )
        .await
        .unwrap();
    for name in &names {
        owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[name]).await.unwrap();
    }
    let request_role = format!("gofree_boot_smtp_request_{}", std::process::id());
    let mut role_created = false;
    let result = std::panic::AssertUnwindSafe(async {
        // Boot must lock/upgrade global secrets. Grant that narrow authority
        // while keeping the request role unable to mutate the worker queue.
        owner.batch_execute(&format!("BEGIN; CREATE ROLE {request_role} LOGIN PASSWORD 'gofree-boot-test'; GRANT USAGE ON SCHEMA public TO {request_role}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {request_role}; GRANT UPDATE ON system_config TO {request_role}; GRANT INSERT ON health_history TO {request_role}; GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {request_role}; GRANT EXECUTE ON FUNCTION boot_config_secret_apply(jsonb) TO {request_role}; COMMIT")).await.unwrap();
        role_created = true;
        let mut request_dsn = reqwest::Url::parse(&db.dsn).unwrap();
        request_dsn.set_username(&request_role).unwrap();
        request_dsn.set_password(Some("gofree-boot-test")).unwrap();
        let request_dsn = request_dsn.to_string();
        let request = setjoin_pg::workers::WorkerDatabase::new(&request_dsn)
            .unwrap().connect().await.unwrap();
        let denied = request.query_detailed(
            "UPDATE outbound_queue SET status='sending' WHERE id=9350011 AND mailbox_id=9348021 RETURNING id",
            &[],
        ).await.expect_err("request connection must not mutate the worker's queue item");
        assert_eq!(denied.sqlstate.as_deref(), Some("42501"));
        let addr = setjoin_conformance::ports::address();
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                .arg0("gofree-smtp4-gateway-worker")
                .env_clear()
                .env("GATEWAY_LISTEN", addr.to_string())
                .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
                .env("RUST_WORKERS_ON", "outbound-mail")
                .env("GO_WORKERS_OFF", "outbound-mail")
                .env("DB_DSN", &request_dsn)
                .env("DB_WORKER_DSN", &db.dsn)
                .env("DB_DIRECT_DSN", &db.dsn)
                .env("S3_ENDPOINT", "http://127.0.0.1:1")
                .env("S3_BUCKET", "mail")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn_boot()
                .unwrap(),
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if process.0.try_wait().unwrap().is_some() {
                let mut error = String::new();
                std::io::Read::read_to_string(process.0.stderr.as_mut().unwrap(), &mut error)
                    .unwrap();
                panic!("gateway startup failed: {error}")
            }
            let row = owner
                .query_one(
                    "SELECT status,attempt_count,last_error FROM outbound_queue WHERE id=9350011",
                    &[],
                )
                .await
                .unwrap();
            if row.get::<_, String>(0) == "deferred" {
                assert_eq!(row.get::<_, i32>(1), 1);
                assert_eq!(
                    row.get::<_, String>(2),
                    "all recipients failed: invalid recipient address: invalid"
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "selected executable never processed its outbound queue"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(Command::new("kill")
            .arg0("gofree-smtp4-worker-stop")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = process.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "gateway did not drain its outbound worker"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut stderr = String::new();
        std::io::Read::read_to_string(process.0.stderr.as_mut().unwrap(), &mut stderr).unwrap();
        let warning = &backlog[0]["backlog_warnings"][0];
        assert!(
            stderr.contains(warning["msg"].as_str().unwrap())
                && stderr.contains(&format!("depth={}", warning["depth"])),
            "missing recorded backlog warning: {stderr}"
        );
    })
    .catch_unwind()
    .await;
    if role_created {
        owner
            .batch_execute(&format!(
                "DROP OWNED BY {request_role}; DROP ROLE {request_role}"
            ))
            .await
            .unwrap();
    }
    owner
        .execute("DELETE FROM feature_toggles WHERE key=ANY($1)", &[&names])
        .await
        .unwrap();
    for row in previous {
        owner.execute("INSERT INTO feature_toggles SELECT * FROM json_populate_record(NULL::feature_toggles,$1::text::json)",&[&row.get::<_,String>(0)]).await.unwrap();
    }
    owner.batch_execute(&cleanup).await.unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error)
    }
}

async fn preparation(corpus: &str) {
    let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
    let factory = |address| -> std::sync::Arc<dyn setjoin_smtp::outbound::RawSource> {
        std::sync::Arc::new(setjoin_gateway::smtp_outbound::BlobSource(
            setjoin_gateway::recovery_worker::S3Store::new(
                &format!("http://{address}"),
                "mail",
                "smtp3-access",
                "smtp3-secret",
            )
            .unwrap()
            .with_region("us-east-1".into()),
        ))
    };
    for case in cases.as_array().unwrap() {
        outbound_oracle::replay_with(
            corpus,
            case["case"]["name"].as_str().unwrap(),
            Some(&factory),
            &|worker, case| {
                worker.with_forward_transform(std::sync::Arc::new(
                    setjoin_gateway::smtp_outbound::ForwardPreparation(
                        setjoin_gateway::link_protect::TokenKeys::new(
                            case["link_secret"].as_str().unwrap_or_default().as_bytes(),
                            case["link_previous"]
                                .as_str()
                                .unwrap_or_default()
                                .as_bytes(),
                            case["link_version"].as_i64().unwrap_or(1),
                        ),
                    ),
                ))
            },
        )
        .await
    }
}

#[tokio::test]
async fn forwarded_raw_preparation_matches_frozen_go_before_dkim() {
    preparation(include_str!(
        "../../../crates/protocols/smtp/oracle/outbound-preparation-go.json"
    ))
    .await
}
#[tokio::test]
async fn forwarded_byte_and_unknown_context_edges_match_go() {
    preparation(include_str!(
        "../../../crates/protocols/smtp/oracle/outbound-preparation-edge-go.json"
    ))
    .await
}
