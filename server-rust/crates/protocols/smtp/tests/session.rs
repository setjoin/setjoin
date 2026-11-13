#[path = "support/auth_blobs.rs"]
mod auth_blobs;
#[path = "support/auth_dns.rs"]
mod auth_dns;
#[path = "support/pipeline.rs"]
mod pipeline;
use base64::Engine;
use futures_util::FutureExt;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

/// Case names whose recorded frozen-Go behaviour is a fixed security bug
/// (`oracle/divergences.json`); the secure behaviour is asserted in `secfix_*.rs`.
fn diverged(name: &str) -> bool {
    let records: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
    records
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["case"] == name && r["go_replay"] == "skipped")
}
async fn replay(corpus: &str) {
    let _guard = RegenGuard;
    replay_cases(corpus, None).await
}
/// `SECFIX12_WRITE_SECURITY=1` rewrites expectations instead of asserting them, so a test
/// run that did so must never pass: dropping the guard fails it ("review and rerun").
static REGENERATED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
struct RegenGuard;
impl Drop for RegenGuard {
    fn drop(&mut self) {
        if REGENERATED.load(std::sync::atomic::Ordering::SeqCst) && !std::thread::panicking() {
            panic!("expectations regenerated (SECFIX12_WRITE_SECURITY): review the diff and rerun without it");
        }
    }
}
const SECURITY_REASON: &str = "owner-approved security fix 2026-11-05";
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
/// A recorded golden replaced by a reviewed expectation (`go_replay: "pinned"` in
/// `oracle/divergences.json`, modeled on the gateway's `security_expected`): the entry
/// must be `reviewed`, carry the owner-approved reason and pin the sha256 of the frozen-Go
/// corpus file the case comes from, so editing the golden breaks the pin. Returns the
/// path of the expectation and, unless `SECFIX12_WRITE_SECURITY=1` (never CI) is
/// regenerating it for review against the baseline, the case it holds.
fn pinned_expectation(corpus: &str, name: &str) -> Option<(std::path::PathBuf, Option<serde_json::Value>)> {
    let records: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
    let sha = sha256_hex(corpus.as_bytes());
    let record = records.as_array().unwrap().iter().find(|r| {
        r["case"] == name && r["go_replay"] == "pinned" && r["sha256"] == sha.as_str()
    })?;
    assert_eq!(record["reviewed"], true, "{name}");
    assert!(record["reason"].as_str().unwrap().contains(SECURITY_REASON), "{name}");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("oracle")
        .join(record["expectation"].as_str().unwrap());
    if std::env::var_os("SECFIX12_WRITE_SECURITY").is_some() {
        return Some((path, None));
    }
    let case = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    Some((path, Some(case)))
}
/// Survey mode (`SECFIX_SURVEY=1`): replay every case of `corpus` alone and print
/// the ones that no longer match frozen Go instead of stopping at the first.
async fn survey(corpus: &str) {
    let parsed: serde_json::Value = serde_json::from_str(corpus).unwrap();
    for case in parsed.as_array().unwrap() {
        let name = case["name"].as_str().unwrap().to_owned();
        let outcome = std::panic::AssertUnwindSafe(replay_cases(corpus, Some(&name)))
            .catch_unwind()
            .await;
        if outcome.is_err() {
            println!("SURVEY-DIVERGES {name}");
        }
    }
}
async fn replay_cases(corpus: &str, only: Option<&str>) {
    let _serial = SERIAL.lock().await;
    replay_cases_locked(corpus, only).await
}
/// The caller holds `SERIAL` (the effect mutants keep it across the whole catalog swap).
async fn replay_cases_locked(corpus: &str, only: Option<&str>) {
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp1-session") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    let corpus_text = corpus;
    let corpus: serde_json::Value = serde_json::from_str(corpus).unwrap();
    let cases = corpus.as_array().unwrap();
    assert!(
        !cases.is_empty(),
        "SMTP corpus must contain recorded sessions"
    );
    for baseline in cases {
        let name = baseline["name"].as_str().unwrap_or_default();
        if only.is_some_and(|o| o != name) || (only.is_none() && diverged(name)) {
            continue;
        }
        let pin = pinned_expectation(corpus_text, name);
        // A secure-only case (not a Go recording) is regenerated the same way, into
        // `oracle/security/<name>.json` as a one-case corpus.
        let secure_only = baseline["secure_only"] == true;
        if secure_only && std::env::var_os("SECFIX12_WRITE_SECURITY").is_none() {
            // A secure-only case is reviewed expected behaviour, not a Go recording: it must
            // be pinned (reviewed, owner-approved reason, sha256 of its file) like a divergence.
            let records: serde_json::Value =
                serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
            let sha = sha256_hex(corpus_text.as_bytes());
            let record = records
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["case"] == name && r["go_replay"] == "secure-only" && r["sha256"] == sha.as_str())
                .unwrap_or_else(|| panic!("secure-only case {name} is not pinned in divergences.json"));
            assert_eq!(record["reviewed"], true, "{name}");
            assert!(record["reason"].as_str().unwrap().contains(SECURITY_REASON), "{name}");
        }
        let writing = pin.as_ref().is_some_and(|(_, case)| case.is_none())
            || (secure_only && std::env::var_os("SECFIX12_WRITE_SECURITY").is_some());
        let mut observed = baseline.clone();
        let case = pin.as_ref().and_then(|(_, case)| case.as_ref()).unwrap_or(baseline);
        owner
            .batch_execute(include_str!("../oracle/auth-cleanup.sql"))
            .await
            .unwrap();
        owner
            .batch_execute(include_str!("../oracle/cleanup.sql"))
            .await
            .unwrap();
        owner
            .batch_execute(include_str!("../oracle/seed.sql"))
            .await
            .unwrap();
        if let Some(sql) = case["setup_sql"].as_str() {
            owner.batch_execute(sql).await.unwrap();
        }
        if let Some(models) = case["models"].as_object() {
            use std::io::Read;
            for (user, packed) in models {
                let packed = base64::engine::general_purpose::STANDARD
                    .decode(packed.as_str().unwrap())
                    .unwrap();
                let mut bytes = Vec::new();
                flate2::read::GzDecoder::new(packed.as_slice())
                    .read_to_end(&mut bytes)
                    .unwrap();
                let user: i64 = user.parse().unwrap();
                owner.execute("INSERT INTO user_spam_model(user_id,model_bytes,sample_count) VALUES($1,$2,1) ON CONFLICT(user_id) DO UPDATE SET model_bytes=EXCLUDED.model_bytes", &[&user,&bytes]).await.unwrap();
            }
        }
        let mut notifications = if case["capture"] == true || case["imip_notify"] == true {
            let n = setjoin_pg::workers::DirectListener::connect(&db.dsn, if case["capture"]==true {"tag:9348021"} else {"calendar:9348021"})
                .await
                .unwrap();
            if case["capture"]==true {n.listen("tag:9348022").await.unwrap(); n.listen("tag:9348023").await.unwrap();}
            if case["imip_notify"] == true {
                n.listen("calendar:9348021").await.unwrap(); n.listen("calendar:9348022").await.unwrap(); n.listen("calendar:9348023").await.unwrap();
            }
            Some(n)
        } else {
            None
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let server = setjoin_smtp::Server::new()
            .with_database(setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap())
            .with_tls_enforce(case["enforce"] == true)
            .with_greylisting(case["greylist"] == true)
            .with_delivery_features(setjoin_smtp::DeliveryFeatures {
                audit: case["audit"] == true,
                ..Default::default()
            });
        let server = if !case["mail_auth"].is_null() {
            let flags = &case["mail_auth"];
            server.with_mail_auth(setjoin_smtp::mail_auth::MailAuth::new(
                setjoin_smtp::mail_auth::Features {
                    spf: flags["feature.spf"] == true,
                    dkim: flags["feature.dkim"] == true,
                    dmarc: flags["feature.dmarc"] == true,
                    arc: flags["feature.arc"] == true,
                },
                Arc::new(auth_dns::FixtureDns(case["dns"].clone())),
            ))
        } else {
            server
        };
        let server = if case.get("security_effects").is_some() {
            struct Flags(serde_json::Value);
            impl setjoin_smtp::submission::Flags for Flags {
                fn enabled(&self, key: &str) -> bool {
                    self.0[key] == true
                }
            }
            server.with_flags(Arc::new(Flags(case["mail_auth"].clone())))
        } else {
            server
        };
        let peers = pipeline::Peers::start(case).await;
        let server = server.with_inbound_config(peers.config.clone());
        let blobs = Arc::new(auth_blobs::Blobs::default());
        let server = if case["capture_blobs"] == true {
            server.with_blob_store(blobs.clone())
        } else {
            server
        };
        let server = if case["tls"] == true {
            server.with_tls(tls_server())
        } else {
            server
        };
        let server = if let Some(max) = case["max_conns"].as_u64() {
            server.with_max_connections(max as usize)
        } else {
            server
        };
        let server = Arc::new(server);
        let stats_server = server.clone();
        let task = tokio::spawn(server.serve(listener, rx));
        let outcome = std::panic::AssertUnwindSafe(async {
            let mut sockets = std::collections::HashMap::<u64, BoxStream>::new();
            let steps = case["steps"].as_array().unwrap();
            assert!(
                !steps.is_empty(),
                "SMTP session must contain recorded steps"
            );
            for (step_index, step) in steps.iter().enumerate() {
                if let Some(ms) = step["wait_ms"].as_u64() {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
                let index = step["conn"].as_u64().unwrap_or(0);
                let mut socket = if let Some(socket) = sockets.remove(&index) {
                    socket
                } else {
                    let mut socket: BoxStream = Box::new(TcpStream::connect(addr).await.unwrap());
                    if case["tls"] == true {
                        socket = upgrade(socket).await;
                    }
                    socket
                };
                socket
                    .write_all(step["send"].as_str().unwrap().as_bytes())
                    .await
                    .unwrap();
                if let Some(encoded) = step["send_base64"].as_str() {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .unwrap();
                    socket.write_all(&bytes).await.unwrap();
                }
                if let (Some(pattern), Some(count)) =
                    (step["repeat"].as_str(), step["count"].as_u64())
                {
                    let copies = (65536 / pattern.len()).max(1);
                    let chunk = pattern.repeat(copies);
                    let deadline = tokio::time::Instant::now()
                        + Duration::from_millis(step["timeout_ms"].as_u64().unwrap_or(5000));
                    let mut left = count as usize;
                    while left > 0 {
                        let n = left.min(copies);
                        tokio::time::timeout_at(
                            deadline,
                            socket.write_all(&chunk.as_bytes()[..n * pattern.len()]),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        left -= n;
                    }
                }
                if step["half_close"] == true {
                    socket.shutdown().await.unwrap();
                }
                if step["lines"] == 0 {
                    let mut byte = [0];
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(5), socket.read(&mut byte))
                            .await
                            .unwrap()
                            .unwrap(),
                        0,
                        "expected EOF"
                    );
                    continue;
                }
                let want = step["reply"].as_str().unwrap_or("").as_bytes();
                let got = tokio::time::timeout(
                    Duration::from_millis(step["timeout_ms"].as_u64().unwrap_or(5000)),
                    async {
                        let mut got = Vec::new();
                        for _ in 0..step["lines"].as_u64().unwrap() {
                            loop {
                                let mut byte = [0];
                                assert_eq!(
                                    socket.read(&mut byte).await.unwrap(),
                                    1,
                                    "premature SMTP EOF"
                                );
                                got.push(byte[0]);
                                assert!(got.len() < 65536, "unbounded SMTP reply");
                                if byte[0] == b'\n' {
                                    break;
                                }
                            }
                        }
                        got
                    },
                )
                .await
                .unwrap();
                if writing {
                    observed["steps"][step_index]["reply"] =
                        serde_json::json!(String::from_utf8_lossy(&got));
                } else {
                    assert_eq!(got, want, "{}", case["name"]);
                }
                if let Some(expected) = step.get("batch_stats") {
                    assert_eq!(
                        batch_stats_json(stats_server.spam_stats()),
                        *expected,
                        "batch gauges {}",
                        case["name"]
                    );
                }
                if let Some(expected) = step.get("monitor") {
                    let raw: String = owner
                        .query_one(include_str!("../oracle/monitor.sql"), &[])
                        .await
                        .unwrap()
                        .get(0);
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
                        *expected,
                        "session monitoring {}",
                        case["name"]
                    );
                }
                if step["upgrade"] == true {
                    socket = upgrade(socket).await;
                }
                sockets.insert(index, socket);
            }
            for socket in sockets.values_mut() {
                let mut byte = [0];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(5), socket.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0,
                    "unrecorded trailing bytes"
                );
            }
            if let Some(notifications) = &mut notifications {
                let mut got = Vec::new();
                while let Ok(Some(n)) =
                    tokio::time::timeout(Duration::from_millis(200), notifications.recv()).await
                {
                    let mut payload: serde_json::Value = serde_json::from_str(n.payload()).unwrap();
                    if let Some(id) = payload["tag_id"].as_i64() {
                        let tag: String = owner
                            .query_one("SELECT name FROM tags WHERE id=$1", &[&id])
                            .await
                            .unwrap()
                            .get(0);
                        payload["tag_id"] = serde_json::json!(tag);
                    }
                    if case["imip_notify"] == true {
                        for (field,query) in [("event_id",include_str!("../oracle/imip-event_id.sql")),("calendar_id",include_str!("../oracle/imip-calendar_id.sql"))] {
                            if let Some(id)=payload[field].as_i64() {
                                let raw:String=owner.query_one(query,&[&id]).await.unwrap().get(0);
                                payload[field]=serde_json::from_str(&raw).unwrap();
                            }
                        }
                    }
                    got.push(serde_json::json!({"channel":n.channel(),"payload":payload}));
                }
                got.sort_by_key(serde_json::Value::to_string);
                if writing {
                    observed["notifications"] = serde_json::json!(got);
                } else {
                    assert_eq!(
                        serde_json::json!(got),
                        case.get("notifications")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "committed notifications {}",
                        case["name"]
                    );
                }
            }
            if let Some(expected) = case.get("greylist_rows") {
                let raw: String = owner
                    .query_one(include_str!("../oracle/greylist-observe.sql"), &[])
                    .await
                    .unwrap()
                    .get(0);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
                    *expected,
                    "greylist rows"
                );
            }
            if let Some(expected) = case.get("blobs") {
                let got = serde_json::to_value(&*blobs.0.lock().unwrap()).unwrap();
                if writing {
                    observed["blobs"] = got;
                } else {
                    assert_eq!(got, *expected, "stored raw bytes {}", case["name"]);
                }
            }
            // Behaviour asserted independently of the recorded expectation: every needle
            // must occur in a stored message (`blob_contains`, base64 decoded).
            if let Some(needles) = case["blob_contains"].as_array() {
                let stored = serde_json::to_value(&*blobs.0.lock().unwrap()).unwrap();
                let stored: Vec<String> = stored
                    .as_object()
                    .unwrap()
                    .values()
                    .map(|v| {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(v.as_str().unwrap())
                            .unwrap();
                        String::from_utf8_lossy(&bytes).into_owned()
                    })
                    .collect();
                for needle in needles {
                    let needle = needle.as_str().unwrap();
                    assert!(
                        stored.iter().any(|m| m.contains(needle)),
                        "{}: stored message lacks {needle}",
                        case["name"]
                    );
                }
                for needle in case["blob_lacks"].as_array().into_iter().flatten() {
                    let needle = needle.as_str().unwrap();
                    assert!(
                        !stored.iter().any(|m| m.contains(needle)),
                        "{}: stored message still carries {needle}",
                        case["name"]
                    );
                }
            }
            if let Some(expected) = case.get("auth_reports") {
                let raw: String = owner
                    .query_one(include_str!("../oracle/auth-observe.sql"), &[])
                    .await
                    .unwrap()
                    .get(0);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
                    *expected,
                    "DMARC reporting {}",
                    case["name"]
                );
            }
            if case.get("pipeline").is_some() {
                assert_eq!(
                    peers.observed(),
                    case.get("pipeline_io")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([])),
                    "pipeline I/O {}",
                    case["name"]
                );
            }
            if let Some(expected) = case.get("imip_effects") {
                let raw: String=owner.query_one(include_str!("../oracle/imip-observe.sql"),&[]).await.unwrap().get(0);
                let got = serde_json::from_str::<serde_json::Value>(&raw).unwrap();
                if writing {
                    observed["imip_effects"] = got;
                } else {
                    assert_eq!(got, *expected, "iMIP effects {}", case["name"]);
                }
            }
            if let Some(expected) = case.get("pipeline_effects") {
                let raw: String = owner
                    .query_one(include_str!("../oracle/pipeline-observe.sql"), &[])
                    .await
                    .unwrap()
                    .get(0);
                let got = serde_json::from_str::<serde_json::Value>(&raw).unwrap();
                if writing {
                    observed["pipeline_effects"] = got;
                } else {
                    assert_eq!(got, *expected, "pipeline effects {}", case["name"]);
                }
            }
            if let Some(expected) = case.get("security_effects") {
                let raw: String = owner
                    .query_one(include_str!("../oracle/security-observe.sql"), &[])
                    .await
                    .unwrap()
                    .get(0);
                let got = serde_json::from_str::<serde_json::Value>(&raw).unwrap();
                if writing {
                    observed["security_effects"] = got;
                } else {
                    assert_eq!(got, *expected, "security effects {}", case["name"]);
                }
            }
            if case.get("effects").is_some() {
                let got: String = owner
                    .query_one(include_str!("../oracle/observe.sql"), &[])
                    .await
                    .unwrap()
                    .get(0);
                let mut got:serde_json::Value=serde_json::from_str(&got).unwrap();
                let mut expected=case["effects"].clone();
                if case.get("imip_effects").is_some() {
                    // The frozen observer orders by mailbox/state only. Calendar
                    // and email counters tie; SQL promises no order within a tie.
                    // Compare the full rows as a multiset, retaining every value.
                    for effects in [&mut got,&mut expected] {
                        effects["journal"].as_array_mut().unwrap().sort_by_key(serde_json::Value::to_string);
                    }
                }
                if writing {
                    observed["effects"] = got;
                } else {
                    assert_eq!(got, expected, "delivery effects");
                }
            }
        })
        .catch_unwind()
        .await;
        let _ = stop.send(true);
        let joined = task.await;
        peers.finish().await;
        if let Some(sql) = case["teardown_sql"].as_str() {
            owner.batch_execute(sql).await.unwrap();
        }
        owner
            .batch_execute(include_str!("../oracle/auth-cleanup.sql"))
            .await
            .unwrap();
        if case["restore_reducer"] == true {
            owner
                .batch_execute(include_str!(
                    "../../../../../mailserver/sql/reducers/smtp_inbound_deliver.sql"
                ))
                .await
                .unwrap();
        }
        if let Some(n) = notifications.take() {
            n.close().await.unwrap();
        }
        owner
            .batch_execute(include_str!("../oracle/cleanup.sql"))
            .await
            .unwrap();
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
        if writing {
            let (path, doc) = match &pin {
                Some((path, _)) => (path.clone(), observed.clone()),
                None => (
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("oracle/security")
                        .join(format!("{name}.json")),
                    serde_json::json!([observed.clone()]),
                ),
            };
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let text = format!("{}\n", serde_json::to_string_pretty(&doc).unwrap());
            std::fs::write(path, text).unwrap();
            REGENERATED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        joined.unwrap().unwrap();
        if let Some(expected) = case.get("batch_stats_after") {
            assert_eq!(
                batch_stats_json(stats_server.spam_stats()),
                *expected,
                "closed connection releases batch {}",
                case["name"]
            );
        }
    }
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
}

#[tokio::test]
async fn greeting_commands_match_frozen_go() {
    replay(include_str!("../oracle/session-go.json")).await;
}
#[tokio::test]
async fn command_bounds_and_sequence_match_frozen_go() {
    replay(include_str!("../oracle/commands-go.json")).await;
}

#[tokio::test]
async fn recipient_admission_matches_frozen_go() {
    replay(include_str!("../oracle/recipients-go.json")).await;
}

#[tokio::test]
async fn data_framing_matches_frozen_go() {
    replay(include_str!("../oracle/data-go.json")).await;
}

#[tokio::test]
async fn delivery_effects_match_frozen_go() {
    replay(include_str!("../oracle/delivery-go.json")).await;
}

trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}
type BoxStream = Box<dyn Stream>;
fn tls_server() -> Arc<tokio_rustls::rustls::ServerConfig> {
    use tokio_rustls::rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig,
    };
    let cert = CertificateDer::pem_slice_iter(include_bytes!(
        "../../../../tests/conformance/directory-sync/ldap-fixture/server.pem"
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../../../../tests/conformance/directory-sync/ldap-fixture/server.p8"
    ))
    .unwrap();
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .unwrap(),
    )
}
async fn upgrade(socket: BoxStream) -> BoxStream {
    use tokio_rustls::rustls::{
        pki_types::{pem::PemObject, CertificateDer, ServerName},
        ClientConfig, RootCertStore,
    };
    let ca = CertificateDer::from_pem_slice(include_bytes!(
        "../../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"
    ))
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Box::new(
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio_rustls::TlsConnector::from(Arc::new(cfg))
                .connect(ServerName::try_from("localhost").unwrap(), socket),
        )
        .await
        .unwrap()
        .unwrap(),
    )
}
#[tokio::test]
async fn tls_sessions_match_frozen_go() {
    replay(include_str!("../oracle/tls-go.json")).await;
}

#[tokio::test]
async fn admission_limits_match_frozen_go() {
    replay(include_str!("../oracle/admission-go.json")).await;
}

#[tokio::test]
async fn session_monitoring_matches_frozen_go() {
    replay(include_str!("../oracle/monitor-go.json")).await;
}

#[tokio::test]
async fn audit_and_notifications_match_frozen_go() {
    replay(include_str!("../oracle/effects-go.json")).await;
}

async fn effect_mutant(kind: &str) {
    // A broken baseline cannot masquerade as a successful mutant rejection.
    replay(include_str!("../oracle/effects-go.json")).await;
    let _serial = SERIAL.lock().await;
    let db = setjoin_conformance::harness::Db::for_case("smtp1-effect-mutant").unwrap();
    let owner = db.connect().await.unwrap();
    let (signature, name, alias, wrapper) = match kind {
        "no-notify" => (
            "app_notify(text,text)",
            "app_notify",
            "gofree_smtp1_notify_original",
            r#"
          CREATE OR REPLACE FUNCTION public.app_notify(p_channel text,p_payload text) RETURNS void
          LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$;"#,
        ),
        "double-bump" => (
            "notify_state_change(bigint,bigint,bigint,text)",
            "notify_state_change",
            "gofree_smtp1_state_original",
            r#"
          CREATE OR REPLACE FUNCTION public.notify_state_change(p_mailbox_id bigint,p_tag_id bigint,p_message_id bigint DEFAULT NULL,p_op text DEFAULT NULL) RETURNS bigint
          LANGUAGE plpgsql AS $$ DECLARE first_state bigint; BEGIN
           first_state:=gofree_smtp1_state_original(p_mailbox_id,p_tag_id,p_message_id,p_op);
           PERFORM gofree_smtp1_state_original(p_mailbox_id,p_tag_id,p_message_id,p_op);
           RETURN first_state; END $$;"#,
        ),
        "no-tenant-filter" => (
            "smtp_inbound_deliver(jsonb,text,text)",
            "smtp_inbound_deliver",
            "gofree_smtp1_delivery_original",
            r#"
          CREATE OR REPLACE FUNCTION public.smtp_inbound_deliver(p_params jsonb,p_envelope_from text,p_envelope_to text)
          RETURNS TABLE(message_id bigint,subject_user_id bigint,subject_mailbox_id bigint,publication_enrolled boolean)
          LANGUAGE plpgsql AS $$ BEGIN RETURN QUERY
           SELECT * FROM gofree_smtp1_delivery_original(jsonb_set(p_params,'{p_rcpt_addr}',to_jsonb('bob@smtp1-other.test'::text)),p_envelope_from,p_envelope_to);
          END $$;"#,
        ),
        _ => panic!("unknown mutant"),
    };
    let original: String = owner
        .query_one(
            "SELECT pg_get_functiondef($1::text::regprocedure)",
            &[&signature],
        )
        .await
        .unwrap()
        .get(0);
    let needle = format!("public.{name}(");
    let replacement = format!("public.{alias}(");
    assert!(original.contains(&needle));
    owner
        .batch_execute(&original.replacen(&needle, &replacement, 1))
        .await
        .unwrap();
    owner.batch_execute(wrapper).await.unwrap();
    let outcome = std::panic::AssertUnwindSafe(async {
        let _guard = RegenGuard;
        replay_cases_locked(include_str!("../oracle/effects-go.json"), None).await
    })
    .catch_unwind()
    .await;
    // Restore exact catalog definition before checking the rejection, even on failure.
    owner.batch_execute(&original).await.unwrap();
    let args = signature.split_once('(').unwrap().1;
    owner
        .batch_execute(&format!("DROP FUNCTION public.{alias}({args}"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    let panic = outcome.expect_err("planted effect mutant survived the frozen-Go oracle");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        message.contains("committed notifications") || message.contains("delivery effects"),
        "non-oracle failure is not mutant evidence: {message}"
    );
    eprintln!("MUTANT-REJECTED SMTP :: {kind}");
}
#[tokio::test]
async fn oracle_rejects_missing_notify() {
    effect_mutant("no-notify").await;
}
#[tokio::test]
async fn oracle_rejects_double_state_bump() {
    effect_mutant("double-bump").await;
}
#[tokio::test]
async fn oracle_rejects_cross_recipient_delivery() {
    effect_mutant("no-tenant-filter").await;
}

#[tokio::test]
async fn data_size_and_spilled_eof_match_frozen_go() {
    replay(include_str!("../oracle/size-go.json")).await;
}

#[tokio::test]
async fn byte_strings_match_frozen_go() {
    replay(include_str!("../oracle/bytes-go.json")).await;
}

#[tokio::test]
async fn greylisting_matches_frozen_go() {
    replay(include_str!("../oracle/greylist-go.json")).await;
}

#[tokio::test]
async fn recipient_resolution_effects_match_frozen_go() {
    replay(include_str!("../oracle/resolution-go.json")).await;
}

#[tokio::test]
async fn reducer_error_projection_matches_frozen_go() {
    replay(include_str!("../oracle/errors-go.json")).await;
}

#[tokio::test]
async fn bounded_recipient_fanout_matches_frozen_go() {
    replay(include_str!("../oracle/fanout-go.json")).await
}

#[tokio::test]
async fn spf_mail_identity_matches_frozen_go() {
    replay(include_str!("../oracle/spf-pass-go.json")).await;
}

#[tokio::test]
async fn spf_dns_mechanisms_match_frozen_go() {
    replay(include_str!("../oracle/spf-mechanisms-go.json")).await;
}

#[tokio::test]
async fn dkim_verification_matches_frozen_go() {
    replay(include_str!("../oracle/dkim-go.json")).await;
}

#[tokio::test]
async fn dmarc_policy_and_reports_match_frozen_go() {
    replay(include_str!("../oracle/dmarc-go.json")).await;
}

#[tokio::test]
async fn arc_sealing_and_key_loading_match_frozen_go() {
    replay(include_str!("../oracle/arc-go.json")).await;
}

#[tokio::test]
async fn arc_counter_bounds_match_frozen_go() {
    replay(include_str!("../oracle/arc-bounds-go.json")).await;
}

#[tokio::test]
async fn survey_recorded_corpora_for_secure_divergences() {
    if std::env::var("SECFIX_SURVEY").is_err() {
        return;
    }
    for corpus in [
        include_str!("../oracle/arc-bounds-go.json"),
        include_str!("../oracle/arc-go.json"),
        include_str!("../oracle/bytes-go.json"),
        include_str!("../oracle/data-go.json"),
        include_str!("../oracle/size-go.json"),
        include_str!("../oracle/dkim-go.json"),
        include_str!("../oracle/dmarc-go.json"),
        include_str!("../oracle/spf-mechanisms-go.json"),
        include_str!("../oracle/spf-pass-go.json"),
        include_str!("../oracle/recipients-go.json"),
        include_str!("../oracle/commands-go.json"),
        include_str!("../oracle/security-imip-requests-go.json"),
        include_str!("../oracle/security-imip-roles-go.json"),
        include_str!("../oracle/security-imip-smime-go.json"),
        include_str!("../oracle/security-imip-dkim-go.json"),
        include_str!("../oracle/security-imip-bytes-go.json"),
        include_str!("../oracle/security-phish-go.json"),
        include_str!("../oracle/security-smime-go.json"),
        include_str!("../oracle/security-smime-mutations-go.json"),
        include_str!("../oracle/security-smime-bounds-v2-go.json"),
        include_str!("../oracle/security-smime-framing-go.json"),
        include_str!("../oracle/security-joint-go.json"),
        include_str!("../oracle/security-joint-pipeline-go.json"),
        include_str!("../oracle/security-link-v2-go.json"),
        include_str!("../oracle/security-link-composition-go.json"),
        include_str!("../oracle/security-scoring-go.json"),
        include_str!("../oracle/security-group-go.json"),
        include_str!("../oracle/security-av-go.json"),
    ] {
        survey(corpus).await;
    }
}

#[tokio::test]
async fn data_framing_with_an_accepted_recipient_is_secure() {
    // Security fix 2026-11-05 (#488): the recorded framing cases refused every
    // recipient; these replay the same framing with one accepted recipient.
    replay(include_str!("../oracle/secfix-data.json")).await;
}

#[test]
fn divergence_records_name_recorded_cases_and_name_their_secure_test() {
    let records: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
    let corpora = [
        (
            "arc-bounds-go.json",
            include_str!("../oracle/arc-bounds-go.json"),
        ),
        ("arc-go.json", include_str!("../oracle/arc-go.json")),
        ("bytes-go.json", include_str!("../oracle/bytes-go.json")),
        ("data-go.json", include_str!("../oracle/data-go.json")),
        ("size-go.json", include_str!("../oracle/size-go.json")),
        ("dkim-go.json", include_str!("../oracle/dkim-go.json")),
        (
            "dkim-vectors-go.json",
            include_str!("../oracle/dkim-vectors-go.json"),
        ),
        ("dmarc-go.json", include_str!("../oracle/dmarc-go.json")),
        (
            "transport-dane-go.json",
            include_str!("../oracle/transport-dane-go.json"),
        ),
        (
            "spf-mechanisms-go.json",
            include_str!("../oracle/spf-mechanisms-go.json"),
        ),
        (
            "security-imip-requests-go.json",
            include_str!("../oracle/security-imip-requests-go.json"),
        ),
        (
            "security-imip-smime-go.json",
            include_str!("../oracle/security-imip-smime-go.json"),
        ),
        (
            "security-phish-go.json",
            include_str!("../oracle/security-phish-go.json"),
        ),
        (
            "security-smime-go.json",
            include_str!("../oracle/security-smime-go.json"),
        ),
    ];
    for record in records.as_array().unwrap() {
        assert_eq!(record["review"], "owner-approved security fix 2026-11-05");
        if record["go_replay"] == "secure-only" {
            assert_eq!(record["reviewed"], true, "{record}");
            assert!(record["reason"].as_str().unwrap().contains(SECURITY_REASON));
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("oracle")
                .join(record["baseline"].as_str().unwrap());
            assert_eq!(record["sha256"], sha256_hex(&std::fs::read(path).unwrap()), "{}", record["case"]);
            continue;
        }
        if record["go_replay"] == "pinned" {
            // Pinned: reviewed, owner-approved, pinned to the exact frozen-Go corpus bytes,
            // and the expectation is a different, still-complete case of the same name.
            assert_eq!(record["reviewed"], true, "{record}");
            assert!(record["reason"].as_str().unwrap().contains(SECURITY_REASON));
            let (_, text) = corpora
                .iter()
                .find(|(name, _)| record["baseline"] == *name)
                .unwrap_or_else(|| panic!("unknown baseline {}", record["baseline"]));
            assert_eq!(record["sha256"], sha256_hex(text.as_bytes()), "{}", record["case"]);
            let baseline: serde_json::Value = serde_json::from_str(text).unwrap();
            let baseline = baseline
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == record["case"])
                .unwrap();
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("oracle")
                .join(record["expectation"].as_str().unwrap());
            let expectation: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(expectation["name"], record["case"]);
            assert_ne!(&expectation, baseline, "{} must differ from the golden", record["case"]);
            assert_eq!(expectation["steps"].as_array().unwrap().len(), baseline["steps"].as_array().unwrap().len());
        }
        for field in ["issue", "reason", "secure_test", "mutant"] {
            assert!(
                record[field].as_str().is_some_and(|v| !v.is_empty()),
                "{record}"
            );
        }
        for file in record["corpus"].as_array().unwrap() {
            let (_, text) = corpora
                .iter()
                .find(|(name, _)| file == name)
                .unwrap_or_else(|| panic!("unknown corpus {file}"));
            let cases: serde_json::Value = serde_json::from_str(text).unwrap();
            assert!(
                cases.as_array().unwrap().iter().any(|c| {
                    c["name"] == record["case"] || c["case"]["name"] == record["case"]
                }),
                "{} is not in {file}",
                record["case"]
            );
        }
    }
}

#[tokio::test]
async fn enabled_sender_and_spam_pipeline_matches_frozen_go() {
    replay(include_str!("../oracle/security-scoring-go.json")).await;
}

#[tokio::test]
async fn enabled_ml_detectors_match_frozen_go() {
    replay(include_str!("../oracle/security-ml-go.json")).await;
}

#[tokio::test]
async fn enabled_rbl_matches_frozen_go() {
    replay(include_str!("../oracle/security-rbl-go.json")).await;
}

#[tokio::test]
async fn enabled_ftrl_matches_frozen_go() {
    replay(include_str!("../oracle/security-ftrl-go.json")).await;
}

fn batch_stats_json(s: setjoin_spam::BatchStats) -> serde_json::Value {
    serde_json::json!({"Loads":s.loads,"Hits":s.hits,"ResidentModels":s.resident_models,"ResidentBytes":s.resident_bytes})
}

#[tokio::test]
async fn enabled_anti_phish_matches_frozen_go() {
    replay(include_str!("../oracle/security-phish-go.json")).await;
}

#[tokio::test]
async fn enabled_av_and_atomic_condemnation_match_frozen_go() {
    replay(include_str!("../oracle/security-av-go.json")).await;
}

#[tokio::test]
async fn enabled_sandbox_matches_frozen_go() {
    replay(include_str!("../oracle/security-sandbox-go.json")).await;
}

#[tokio::test]
async fn enabled_group_moderation_matches_frozen_go() {
    replay(include_str!("../oracle/security-group-go.json")).await;
}

#[tokio::test]
async fn enabled_smime_matches_frozen_go() {
    replay(include_str!("../oracle/security-smime-go.json")).await;
}

#[tokio::test]
async fn enabled_smime_mutation_order_matches_frozen_go() {
    replay(include_str!("../oracle/security-smime-mutations-go.json")).await;
}

#[tokio::test]
async fn enabled_smime_trust_and_harvest_faults_match_frozen_go() {
    replay(include_str!("../oracle/security-smime-bounds-v2-go.json")).await;
}

#[tokio::test]
async fn enabled_smime_cms_framing_matches_frozen_go() {
    replay(include_str!("../oracle/security-smime-framing-go.json")).await;
}

#[tokio::test]
async fn enabled_link_protection_matches_frozen_go() {
    replay(include_str!("../oracle/security-link-v2-go.json")).await;
}

#[tokio::test]
async fn enabled_link_encoding_edges_match_frozen_go() {
    replay(include_str!("../oracle/security-link-encodings-go.json")).await;
}

#[tokio::test]
async fn enabled_link_pipeline_composition_matches_frozen_go() {
    replay(include_str!("../oracle/security-link-composition-go.json")).await;
}

#[tokio::test]
async fn enabled_link_qp_framing_matches_frozen_go() {
    replay(include_str!("../oracle/security-link-qp-framing-go.json")).await;
}

#[tokio::test]
async fn enabled_imip_requests_match_frozen_go() { replay(include_str!("../oracle/security-imip-requests-go.json")).await; }

#[tokio::test]
async fn enabled_imip_roles_match_frozen_go() { replay(include_str!("../oracle/security-imip-roles-go.json")).await; }

#[tokio::test]
async fn enabled_imip_smime_matches_frozen_go() { replay(include_str!("../oracle/security-imip-smime-go.json")).await; }

#[tokio::test]
async fn enabled_imip_dkim_matches_frozen_go() { replay(include_str!("../oracle/security-imip-dkim-go.json")).await; }

#[tokio::test]
async fn enabled_joint_pipeline_matches_frozen_go() { replay(include_str!("../oracle/security-joint-go.json")).await; }

#[tokio::test]
async fn enabled_joint_pipeline_effects_match_frozen_go() { replay(include_str!("../oracle/security-joint-pipeline-go.json")).await; }

#[tokio::test]
async fn enabled_imip_signed_bytes_match_frozen_go() { replay(include_str!("../oracle/security-imip-bytes-go.json")).await; }

// Owner-approved security fixes of 2026-11-05 (#544). The first four replay the recorded
// frozen-Go case through its reviewed expectation (`oracle/security/`, pinned in
// `oracle/divergences.json`); the secure-only cases were derived from recorded ones by
// `oracle/derive-secfix12.py`. `scripts/test-secfix12-mutants.py` restores each bug.
#[tokio::test]
async fn secfix12_imip_request_binds_attendee_to_envelope_recipient() {
    let _guard = RegenGuard;
    replay_cases(
        include_str!("../oracle/security-imip-requests-go.json"),
        Some("request-body-attendee-different-envelope"),
    )
    .await;
}

#[tokio::test]
async fn secfix12_imip_stops_for_a_revoked_signer() {
    let _guard = RegenGuard;
    replay_cases(
        include_str!("../oracle/security-imip-smime-go.json"),
        Some("smime-cancel-revoked-badge"),
    )
    .await;
}

#[tokio::test]
async fn secfix12_trailing_unsigned_part_is_not_fully_signed() {
    let _guard = RegenGuard;
    replay_cases(
        include_str!("../oracle/security-imip-smime-go.json"),
        Some("smime-cancel-trailing-unsigned-request"),
    )
    .await;
    replay(include_str!("../oracle/security/secfix12-trailing-part-links.json")).await;
}

#[tokio::test]
async fn secfix12_preamble_part_cannot_hide_behind_a_signed_message() {
    // A second, lowercase Content-Type frames an unsigned multipart/mixed part inside the
    // signed message's preamble. The signed message is not fully signed, so the part is
    // rewritten like any unsigned mail (its link never reaches the reader verbatim).
    let _guard = RegenGuard;
    replay(include_str!("../oracle/security/secfix12-preamble-part-links.json")).await;
}

#[tokio::test]
async fn secfix12_anti_phish_rejection_is_refused_not_silently_dropped() {
    let _guard = RegenGuard;
    for case in ["phish-exact-rejected", "phish-strict-upgrades-warn", "phish-homoglyph-reject"] {
        replay_cases(include_str!("../oracle/security-phish-go.json"), Some(case)).await;
    }
    replay_cases(
        include_str!("../oracle/security-smime-go.json"),
        Some("smime-valid-policy-reject-harvests"),
    )
    .await;
}

/// The cases share one database and fixed fixtures: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
