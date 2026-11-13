//! #323: seed-plus-one-tick oracle for `tls-rpt-report`. Frozen Go's real
//! `TLSRPTWorker.sendReports` (overlays `tls_rpt_tick_test.go.txt` and `tls_rpt_source.go.txt`
//! in `tests/conformance/drain/`) runs one report pass over a seeded `tls_rpt_sessions`; the
//! Rust worker's `tick()` must leave the same rows and POST the same requests (method, path,
//! content type, exact body bytes) to a loopback TLS receiver.
//!
//! The current schema has no `tls_rpt_sessions` table (only the archived 035 migration), so the
//! oracle creates it from that DDL and drops it afterwards; `table-missing` runs without it.
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); replay needs no Go.
mod common;
mod drain_oracle;

use drain_oracle::{settle, BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::tls_rpt::TlsRptReport;
use setjoin_pg::workers::WorkerDatabase;
use std::sync::{Arc, Mutex};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const HOST: &str = "mx.oracle.test";
const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBvTCCAWOgAwIBAgIUeTsVydbKk2JhFxxWUH2SpAhMa9kwCgYIKoZIzj0EAwIw\nMzEXMBUGA1UECgwOU2V0am9pbiBPcmFjbGUxGDAWBgNVBAMMD3Rscy1vcmFjbGUu\ndGVzdDAgFw0yNjExMDMxMjU4MzBaGA8yMDk1MDQxNTEyNTgzMFowMzEXMBUGA1UE\nCgwOU2V0am9pbiBPcmFjbGUxGDAWBgNVBAMMD3Rscy1vcmFjbGUudGVzdDBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABFme8wfeFa3l6j63tPkbzV70HdtDxb1KVfhg\nQJYT8wRJB5xrpb8Gp9WJ3ivSJUKecfUrx/t5ABoLihU6g5a01xqjUzBRMB0GA1Ud\nDgQWBBRLDw9lvjbFwf8EVrrNPbuqx0F4hTAfBgNVHSMEGDAWgBRLDw9lvjbFwf8E\nVrrNPbuqx0F4hTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBGi\nSxI25ek6TMsn9qbHXjo6zsaEggo4Trl2UcNxx4obAiEA7D/adTkpQAambjZr/GEv\n3szZWVRFwOqP6f4Iq3S89i8=\n-----END CERTIFICATE-----";
const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgC2pGDY0ZIGMQWFHg\nLCe8vS59NebOjL0n69B7ThNghzuhRANCAARZnvMH3hWt5eo+t7T5G81e9B3bQ8W9\nSlX4YECWE/MESQeca6W/BqfVid4r0iVCnnH1K8f7eQAaC4oVOoOWtNca\n-----END PRIVATE KEY-----";
const DDL: &str = "CREATE TABLE tls_rpt_sessions (
    id BIGSERIAL PRIMARY KEY, policy_domain TEXT NOT NULL, policy_type TEXT NOT NULL DEFAULT 'sts',
    mx_host TEXT NOT NULL, mx_ip TEXT, result TEXT NOT NULL, failure_reason TEXT,
    session_count INT NOT NULL DEFAULT 1, report_uri TEXT, report_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now());
    CREATE INDEX tls_rpt_sessions_date_idx ON tls_rpt_sessions(report_date);
    CREATE INDEX tls_rpt_sessions_domain_idx ON tls_rpt_sessions(policy_domain, report_date);
    CREATE UNIQUE INDEX tls_rpt_sessions_uniq_idx ON tls_rpt_sessions(policy_domain, mx_host, mx_ip, result, report_date)";

#[derive(Clone, Copy)]
enum Uri {
    Null,
    Raw(&'static str),
    /// `https://127.0.0.1:<receiver port><path>`.
    Https(&'static str),
    /// Port 1: nothing listens.
    Refused,
}

#[derive(Clone, Copy)]
struct Row {
    domain: &'static str,
    mx: &'static str,
    ip: Option<&'static str>,
    result: &'static str,
    failure: Option<&'static str>,
    count: i32,
    uri: Uri,
    /// Days from today: -1 is the report date.
    day: i32,
}
const fn row(domain: &'static str, result: &'static str, count: i32, uri: Uri) -> Row {
    Row {
        domain,
        mx: "mx1.remote.test",
        ip: Some("192.0.2.1"),
        result,
        failure: None,
        count,
        uri,
        day: -1,
    }
}

struct Case {
    name: &'static str,
    guard: bool,
    table: bool,
    rows: Vec<Row>,
}
fn case(name: &'static str, rows: Vec<Row>) -> Case {
    Case {
        name,
        guard: false,
        table: true,
        rows,
    }
}

fn cases() -> Vec<Case> {
    let ok = Uri::Https("/ok");
    vec![
        case(
            "tls-rpt-post-success-deletes",
            vec![
                row("a.test", "success", 5, ok),
                Row {
                    mx: "mx2.remote.test",
                    ..row("a.test", "success", 2, ok)
                },
                row("other.test", "success", 1, Uri::Raw("mailto:x@other.test")),
            ],
        ),
        case(
            "tls-rpt-failures-and-escapes",
            vec![
                Row {
                    failure: Some("cert <bad> & \"worse\" \u{2028}"),
                    ip: None,
                    ..row("b.test", "certificate-expired", 3, ok)
                },
                row("b.test", "success", 7, ok),
                Row {
                    mx: "mx3.remote.test",
                    failure: None,
                    ..row("b.test", "starttls-not-supported", 1, ok)
                },
                Row {
                    mx: "mx\u{e9}.remote.test",
                    ..row("b.test", "validation-failure", 2, ok)
                },
            ],
        ),
        case(
            "tls-rpt-only-failures",
            vec![row("c.test", "validation-failure", 4, ok)],
        ),
        case(
            "tls-rpt-server-error-still-deletes",
            vec![row("d.test", "success", 1, Uri::Https("/five"))],
        ),
        case(
            "tls-rpt-client-error-still-deletes",
            vec![row("d.test", "success", 1, Uri::Https("/rejected"))],
        ),
        case(
            "tls-rpt-refused-keeps-rows",
            vec![row("e.test", "success", 1, Uri::Refused)],
        ),
        case(
            "tls-rpt-non-https-keeps-rows",
            vec![
                row(
                    "f1.test",
                    "success",
                    1,
                    Uri::Raw("http://127.0.0.1:1/plain"),
                ),
                row("f2.test", "success", 1, Uri::Raw("ftp://x.test/r")),
                row("f3.test", "success", 1, Uri::Raw("mailto:ops@f3.test!10m")),
                row(
                    "f4.test",
                    "success",
                    1,
                    Uri::Raw("https://x.test/a,mailto:ops@f4.test"),
                ),
                row("f5.test", "success", 1, Uri::Null),
                row("f6.test", "success", 1, Uri::Raw("")),
            ],
        ),
        case(
            "tls-rpt-other-dates-untouched",
            vec![
                row("g.test", "success", 1, ok),
                Row {
                    day: 0,
                    ..row("g.test", "success", 9, ok)
                },
                Row {
                    day: -2,
                    ..row("g.test", "success", 8, ok)
                },
                Row {
                    day: 0,
                    ..row("today-only.test", "success", 1, ok)
                },
                Row {
                    day: -2,
                    ..row("old-only.test", "success", 1, ok)
                },
            ],
        ),
        case(
            "tls-rpt-two-domains",
            vec![
                row("h1.test", "success", 1, Uri::Https("/one")),
                row("h2.test", "validation-failure", 2, Uri::Https("/two")),
                row("h3.test", "success", 1, Uri::Refused),
            ],
        ),
        case(
            "tls-rpt-two-uris-one-domain",
            vec![
                row("i.test", "success", 1, Uri::Https("/first")),
                Row {
                    mx: "mx2.remote.test",
                    ..row("i.test", "success", 1, Uri::Https("/second"))
                },
            ],
        ),
        case("tls-rpt-no-sessions", vec![]),
        Case {
            name: "tls-rpt-table-missing",
            guard: false,
            table: false,
            rows: vec![],
        },
        Case {
            guard: true,
            ..case(
                "tls-rpt-guarded-loopback-keeps-rows",
                vec![row("e.test", "success", 1, ok)],
            )
        },
    ]
}

/// A loopback TLS receiver: every request is recorded; the path picks the status.
struct Receiver {
    port: u16,
    seen: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn receiver() -> Result<Receiver, BoxError> {
    use base64::Engine;
    use http_body_util::BodyExt;
    use tokio_rustls::rustls::{pki_types::PrivateKeyDer, ServerConfig};
    let der = |pem: &str| {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD.decode(body)
    };
    let cert = tokio_rustls::rustls::pki_types::CertificateDer::from(der(CERT)?);
    let key = PrivateKeyDer::try_from(der(KEY)?).map_err(|e| e.to_string())?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let log = log.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let bytes = body
                                .collect()
                                .await
                                .map(|b| b.to_bytes())
                                .unwrap_or_default();
                            let path = parts.uri.path().to_owned();
                            log.lock().unwrap().push(json!({
                            "method": parts.method.as_str(),
                            "path": path,
                            "content_type": parts.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or(""),
                            "body": String::from_utf8_lossy(&bytes),
                        }));
                            let status = match path.as_str() {
                                "/five" => 500,
                                "/rejected" => 400,
                                _ => 200,
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                        b"answer",
                                    )))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Ok(Receiver { port, seen, task })
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_rpt_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("tls-rpt-tick") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let record = std::env::var("GOFREE_RECORD_DRAIN").ok();
    let only = std::env::var("GOFREE_DRAIN_ONLY").ok();
    let listed = |filter: &Option<String>, name: &str| {
        filter
            .as_deref()
            .is_none_or(|f| f == "all" || f.split(',').any(|t| t == name))
    };
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases() {
        let label = case.name.to_owned();
        let recording = record.is_some() && listed(&record, &label);
        if record.is_some() && !recording || !listed(&only, &label) {
            continue;
        }
        ran += 1;
        let result = run_case(&db, &owner, &case, &label, recording).await;
        let _ = owner
            .batch_execute("DROP TABLE IF EXISTS tls_rpt_sessions")
            .await;
        if let Err(error) = result {
            failures.push(format!("{label}: {error}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(ran > 0, "no case selected");
    Ok(())
}

async fn run_case(
    db: &Db,
    owner: &tokio_postgres::Client,
    case: &Case,
    label: &str,
    recording: bool,
) -> Result<(), BoxError> {
    owner
        .batch_execute("DROP TABLE IF EXISTS tls_rpt_sessions")
        .await?;
    if case.table {
        owner.batch_execute(DDL).await?;
    }
    let receiver = receiver().await?;
    let uri = |u: Uri| -> Option<String> {
        match u {
            Uri::Null => None,
            Uri::Raw(text) => Some(text.to_owned()),
            Uri::Https(path) => Some(format!("https://127.0.0.1:{}{path}", receiver.port)),
            Uri::Refused => Some("https://127.0.0.1:1/refused".into()),
        }
    };
    for r in &case.rows {
        owner
            .execute(
                "INSERT INTO tls_rpt_sessions (policy_domain, mx_host, mx_ip, result, failure_reason, session_count, report_uri, report_date) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,(now() AT TIME ZONE 'UTC')::date + $8::int)",
                &[&r.domain, &r.mx, &r.ip, &r.result, &r.failure, &r.count, &uri(r.uri), &r.day],
            )
            .await?;
    }
    if recording {
        let mut env = vec![
            ("GOFREE_DRAIN_DSN".to_string(), db.dsn.clone()),
            ("GOFREE_TLSRPT_HOSTNAME".into(), HOST.into()),
        ];
        if case.guard {
            env.push(("GOFREE_TLSRPT_GUARD".into(), "on".into()));
        }
        GoTick {
            package: "internal/smtp",
            overlay: "tls_rpt_tick_test.go.txt",
            test: "TestGoFreeTLSRPTTick",
            file: "gofree_tls_rpt_tick_test.go",
            env,
            docker: vec![],
        }
        .run_replacing(&[("tlsrpt.go", "tls_rpt_source.go.txt")])?;
    } else {
        let database = WorkerDatabase::new(&db.dsn)?;
        let worker = if case.guard {
            TlsRptReport::new(database, HOST.into())
        } else {
            TlsRptReport::unguarded_for_tests(database, HOST.into())
        };
        worker.tick().await;
    }
    let yesterday = chrono::Utc::now() - chrono::Duration::days(1);
    let today = chrono::Utc::now();
    let mask = |text: &str| {
        text.replace(&yesterday.format("%Y%m%d").to_string(), "<yesterday>")
            .replace(
                &yesterday.format("%Y-%m-%d").to_string(),
                "<yesterday-date>",
            )
            .replace(&today.format("%Y-%m-%d").to_string(), "<today-date>")
            .replace(&format!("127.0.0.1:{}", receiver.port), "127.0.0.1:<port>")
    };
    let mut requests: Vec<Value> = receiver.seen.lock().unwrap().clone();
    for request in &mut requests {
        request["body"] = json!(mask(request["body"].as_str().unwrap_or("")));
    }
    requests.sort_by_key(|r| (r["path"].to_string(), r["body"].to_string()));
    let mut rows = vec![];
    if case.table {
        for r in owner
            .query(
                "SELECT policy_domain, mx_host, COALESCE(mx_ip,'<null>'), result, COALESCE(failure_reason,'<null>'), session_count, \
                 COALESCE(report_uri,'<null>'), (report_date - (now() AT TIME ZONE 'UTC')::date)::int \
                 FROM tls_rpt_sessions ORDER BY id",
                &[],
            )
            .await?
        {
            rows.push(json!({
                "domain": r.get::<_, String>(0), "mx": r.get::<_, String>(1), "ip": r.get::<_, String>(2),
                "result": r.get::<_, String>(3), "failure": r.get::<_, String>(4), "count": r.get::<_, i32>(5),
                "uri": mask(&r.get::<_, String>(6)), "day": r.get::<_, i32>(7),
            }));
        }
    }
    settle(
        label,
        json!({"requests": requests, "rows": rows}),
        recording,
    )
}

/// `enabled` mirrors Go's toggle store: a stored row wins, the default is ON.
#[tokio::test]
async fn toggle_default_is_on_and_a_stored_row_wins() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("tls-rpt-toggle") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    owner
        .batch_execute("DELETE FROM feature_toggles WHERE key='feature.tls_rpt'")
        .await?;
    let database = WorkerDatabase::new(&db.dsn)?;
    let default = setjoin_gateway::tls_rpt::enabled(&database).await;
    owner
        .batch_execute(
            "INSERT INTO feature_toggles(key, enabled) VALUES ('feature.tls_rpt', false)",
        )
        .await?;
    let off = setjoin_gateway::tls_rpt::enabled(&database).await;
    owner
        .batch_execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.tls_rpt'")
        .await?;
    let on = setjoin_gateway::tls_rpt::enabled(&database).await;
    owner
        .batch_execute("DELETE FROM feature_toggles WHERE key='feature.tls_rpt'")
        .await?;
    assert!(default && !off && on, "default={default} off={off} on={on}");
    Ok(())
}

/// The overlay replaces only the report client of Go's `tlsrpt.go`.
#[test]
fn overlay_source_matches_frozen_go() {
    let root = drain_oracle::repo_root().unwrap();
    let go = std::fs::read_to_string(root.join("mailserver/internal/smtp/tlsrpt.go")).unwrap();
    let overlay = std::fs::read_to_string(
        root.join("server-rust/tests/conformance/drain/tls_rpt_source.go.txt"),
    )
    .unwrap();
    let body = overlay
        .split_once("package smtp")
        .map(|(_, rest)| format!("package smtp{rest}"))
        .unwrap();
    let rebuilt = body.replace("\nvar _ = ssrf.SafeHTTPClient\n", "").replace(
        "goFreeTLSRPTClient()",
        "ssrf.SafeHTTPClient(10 * time.Second)",
    );
    assert_eq!(
        rebuilt, go,
        "the overlay drifted from frozen Go's tlsrpt.go"
    );
}
