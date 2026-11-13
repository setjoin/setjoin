//! Immutable frozen-Go transcripts replayed at the listener's TCP boundary.
use setjoin_ldap::Server;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
/// Every DB-backed case seeds and cleans the same fixed `ldap1.test` identities, so
/// the cases of this file run one at a time under parallel libtest.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[tokio::test]
async fn recorded_unbound_sessions() {
    let corpus: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/oracle/go-sessions.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate))).serve(l, rx));
    for session in corpus
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["transport"] == "plain")
    {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        for step in session["steps"].as_array().unwrap() {
            socket
                .write_all(&unhex(step["request"].as_str().unwrap()))
                .await
                .unwrap();
            for response in step["responses"].as_array().unwrap() {
                let expected = unhex(response.as_str().unwrap());
                let mut actual = vec![0; expected.len()];
                tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut actual))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(actual, expected, "{}", session["name"]);
            }
        }
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn plaintext_bind_is_rejected() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate))).serve(l, rx));
    let mut socket = TcpStream::connect(addr).await.unwrap();
    // Frozen-Go anonymous bind rejection (LDAP inappropriateAuthentication).
    socket
        .write_all(&unhex("300c020101600702010304008000"))
        .await
        .unwrap();
    let mut actual = [0; 14];
    tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut actual))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(actual.as_slice(), unhex("300c02010161070a013004000400"));
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

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
async fn tls_client(addr: std::net::SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
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
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap()
}
#[tokio::test]
async fn recorded_tls_auth_failures() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate)).with_tls(tls_server())).serve(l, rx));
    for session in corpus
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| matches!(c["name"].as_str(), Some("bad-password" | "unknown-user")))
    {
        let mut socket = tls_client(addr).await;
        for step in session["steps"].as_array().unwrap() {
            socket
                .write_all(&unhex(step["request"].as_str().unwrap()))
                .await
                .unwrap();
            for response in step["responses"].as_array().unwrap() {
                let expected = unhex(response.as_str().unwrap());
                let mut actual = vec![0; expected.len()];
                tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut actual))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(actual, expected, "{}", session["name"]);
            }
        }
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn recorded_successful_bind() {
    use setjoin_conformance::harness::Db;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ldap-listener-bind") else {
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
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",
            &[&include_str!("../oracle/password-hash.txt")],
        )
        .await
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = fixture_server(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
        "ldap1.test",
    )
    .with_tls(tls_server());
    let task = tokio::spawn(Arc::new(server).serve(l, rx));
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
    let step = &corpus
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "people")
        .unwrap()["steps"][0];
    let mut socket = tls_client(addr).await;
    socket
        .write_all(&unhex(step["request"].as_str().unwrap()))
        .await
        .unwrap();
    let mut actual = [0; 14];
    socket.read_exact(&mut actual).await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    assert_eq!(
        actual.as_slice(),
        unhex(step["responses"][0].as_str().unwrap())
    );
}

async fn replay_cases(names: &[&str]) {
    use futures_util::FutureExt;
    use setjoin_conformance::harness::Db;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ldap-directory") else {
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
    let initial: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
    let extra = !initial
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == names[0]);
    if extra {
        owner
            .batch_execute(include_str!("../oracle/seed-extra.sql"))
            .await
            .unwrap();
    }
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",
            &[&include_str!("../oracle/password-hash.txt")],
        )
        .await
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = fixture_server(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
        "ldap1.test",
    )
    .with_tls(tls_server());
    let task = tokio::spawn(Arc::new(server).serve(l, rx));
    let outcome = std::panic::AssertUnwindSafe(async {
        let corpus:serde_json::Value=serde_json::from_str(if extra {
            let extended=include_str!("../oracle/extended-go-sessions.json");
            if serde_json::from_str::<serde_json::Value>(extended).unwrap().as_array().unwrap().iter().any(|c|c["name"]==names[0]){extended}else{include_str!("../oracle/edges-go-sessions.json")}
        }else{include_str!("../oracle/go-sessions.json")}).unwrap();
        for name in names {
            let session = corpus
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == *name)
                .expect("recorded case");
            let before_hash=session["password_hash"].as_str().unwrap_or(include_str!("../oracle/password-hash.txt"));
            if session.get("effects").is_some(){owner.execute("UPDATE users SET password_hash=$1 WHERE id=9342011",&[&before_hash]).await.unwrap();}
            let mut socket = tls_client(addr).await;
            let divergences:serde_json::Value=serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
            for (step_index,step) in session["steps"].as_array().unwrap().iter().enumerate() {
                socket
                    .write_all(&unhex(step["request"].as_str().unwrap()))
                    .await
                    .unwrap();
                let divergence=&divergences[name];
                let responses=if divergence["step"].as_u64()==Some(step_index as u64){&divergence["responses"]}else{&step["responses"]};
                for response in responses.as_array().unwrap() {
                    let expected = unhex(response.as_str().unwrap());
                    let mut actual = vec![0; expected.len()];
                    tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut actual))
                        .await
                        .expect(name)
                        .unwrap();
                    assert_eq!(actual, expected, "{name}");
                }
            }
            if let Some(effects)=session.get("effects") {
                let after:String=owner.query_one("SELECT password_hash FROM users WHERE id=9342011",&[]).await.unwrap().get(0);
                assert_eq!(after!=before_hash,effects["password_rehashed"].as_bool().unwrap(),"{name} password effects");
                let count:i64=owner.query_one("SELECT count(*) FROM auth_event_log WHERE user_id BETWEEN 9342011 AND 9342014 OR email LIKE '%@ldap1.test'",&[]).await.unwrap().get(0);
                assert_eq!(count,effects["auth_events"].as_i64().unwrap(),"{name} auth effects");
            }
        }
    })
    .catch_unwind()
    .await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}
#[tokio::test]
async fn recorded_people_search() {
    replay_cases(&["people"]).await
}
#[tokio::test]
async fn recorded_people_address_visibility() {
    replay_cases(&["hidden-denial", "alias", "upn"]).await
}
#[tokio::test]
async fn recorded_people_base_search() {
    replay_cases(&["base-person"]).await
}
#[tokio::test]
async fn recorded_root_and_unknown_base() {
    replay_cases(&[
        "root-empty",
        "root-children",
        "unknown-base",
        "base-domain-bug",
    ])
    .await
}
#[tokio::test]
async fn recorded_people_limits_types_and_rebind() {
    replay_cases(&[
        "types-only",
        "size-limit",
        "failed-rebind-retains-principal",
    ])
    .await
}
#[tokio::test]
async fn recorded_people_compare() {
    replay_cases(&[
        "compare-true",
        "compare-false",
        "compare-missing",
        "compare-no-cn",
    ])
    .await
}
#[tokio::test]
async fn oversized_declared_frame_is_closed_without_waiting_for_payload() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate))).serve(l, rx));
    let mut socket = TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(&[0x30, 0x84, 0, 0x20, 0, 0])
        .await
        .unwrap();
    let mut byte = [0; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte)).await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "oversized length must be refused before payload allocation: {closed:?}"
    );
}

#[tokio::test]
async fn recorded_groups_search() {
    replay_cases(&["groups-search"]).await
}
#[tokio::test]
async fn recorded_groups_base() {
    replay_cases(&["groups-base"]).await
}
#[tokio::test]
async fn recorded_resources_search() {
    replay_cases(&["resources-search", "resources-base", "resources-filter"]).await
}
#[tokio::test]
async fn recorded_contacts_search() {
    replay_cases(&["contacts-search", "contacts-base", "contact-private-denial"]).await
}
#[tokio::test]
async fn recorded_other_ou_compare() {
    replay_cases(&["groups-compare", "resources-compare", "contacts-compare"]).await
}
#[tokio::test]
async fn recorded_people_filter_tree() {
    replay_cases(&["people-cn-filter", "people-boolean-filter"]).await
}
#[tokio::test]
async fn recorded_department_subtrees() {
    replay_cases(&["people-department-subtree", "people-department-miss"]).await
}
#[tokio::test]
async fn recorded_paging_offset() {
    replay_cases(&["paged-offset"]).await
}
#[tokio::test]
async fn recorded_bind_dn() {
    replay_cases(&["bind-dn", "bind-mixed-cn-bug"]).await
}
#[tokio::test]
async fn recorded_configured_starttls() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/extended-go-sessions.json")).unwrap();
    let session = corpus
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "configured-starttls")
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate)).with_starttls(tls_server())).serve(l, rx));
    let mut socket = TcpStream::connect(addr).await.unwrap();
    let result = async {
        for step in session["steps"].as_array().unwrap() {
            socket
                .write_all(&unhex(step["request"].as_str().unwrap()))
                .await?;
            for response in step["responses"].as_array().unwrap() {
                let expected = unhex(response.as_str().unwrap());
                let mut actual = vec![0; expected.len()];
                tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut actual))
                    .await??;
                assert_eq!(actual, expected);
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    result.unwrap();
}
#[tokio::test]
async fn recorded_attribute_selection() {
    replay_cases(&["people-all-attrs", "people-star-attrs"]).await
}

#[tokio::test]
async fn recorded_other_ou_filter_denials() {
    replay_cases(&[
        "groups-missing-filter",
        "resources-missing-filter",
        "contacts-missing-filter",
    ])
    .await
}
#[tokio::test]
async fn recorded_read_only_operations() {
    replay_cases(&["add", "delete", "modify", "modifydn", "empty-extension"]).await
}
#[tokio::test]
async fn recorded_filter_compatibility() {
    replay_cases(&[
        "filter-not",
        "filter-substring",
        "filter-approx",
        "filter-unknown",
        "filter-greater-ignored",
        "filter-presence-ignored",
    ])
    .await
}
#[tokio::test]
async fn recorded_sm3_password() {
    replay_cases(&["sm3-bind"]).await
}
#[tokio::test]
async fn recorded_password_upgrade() {
    replay_cases(&["rehash-bcrypt", "rehash-sm3"]).await
}
#[tokio::test]
async fn connection_limit_backpressures_until_a_slot_is_released() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate)).with_max_connections(1)).serve(l, rx));
    let first = TcpStream::connect(addr).await.unwrap();
    // Give the first connection a complete operation, establishing its slot.
    let mut first = first;
    first
        .write_all(&unhex("300c020101600702010304008000"))
        .await
        .unwrap();
    let mut answer = [0; 14];
    first.read_exact(&mut answer).await.unwrap();
    let mut second = TcpStream::connect(addr).await.unwrap();
    second
        .write_all(&unhex("300c020101600702010304008000"))
        .await
        .unwrap();
    let held = tokio::time::timeout(Duration::from_millis(100), second.read_exact(&mut answer))
        .await
        .is_err();
    drop(first);
    let released =
        tokio::time::timeout(Duration::from_secs(3), second.read_exact(&mut answer)).await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(held, "second connection bypassed connection cap");
    released.unwrap().unwrap();
}

#[tokio::test]
async fn disconnect_cancels_a_blocked_directory_query() {
    use setjoin_conformance::harness::Db;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ldap-disconnect-cancel") else {
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
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",
            &[&include_str!("../oracle/password-hash.txt")],
        )
        .await
        .unwrap();
    let dsn = format!(
        "{}{}application_name=gofree-ldap1-cancel",
        db.app.as_deref().unwrap_or(&db.dsn),
        if db.app.as_deref().unwrap_or(&db.dsn).contains('?') {
            "&"
        } else {
            "?"
        }
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = fixture_server(
        setjoin_pg::ScopedExecutor::from_dsn(&dsn, 4).unwrap(),
        "ldap1.test",
    )
    .with_tls(tls_server());
    let task = tokio::spawn(Arc::new(server).serve(l, rx));
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
    let session = corpus
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "people")
        .unwrap();
    let mut socket = tls_client(address).await;
    socket
        .write_all(&unhex(session["steps"][0]["request"].as_str().unwrap()))
        .await
        .unwrap();
    let mut response = [0; 14];
    socket.read_exact(&mut response).await.unwrap();
    assert_eq!(response[9], 0);
    owner
        .batch_execute("BEGIN; LOCK TABLE users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    socket
        .write_all(&unhex(session["steps"][1]["request"].as_str().unwrap()))
        .await
        .unwrap();
    let mut observed = false;
    for _ in 0..100 {
        observed=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-ldap1-cancel' AND wait_event_type='Lock')",&[]).await.unwrap().get(0);
        if observed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(socket);
    let mut cancelled = false;
    for _ in 0..100 {
        let active:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-ldap1-cancel' AND wait_event_type='Lock')",&[]).await.unwrap().get(0);
        if !active {
            cancelled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    owner.batch_execute("ROLLBACK").await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    assert!(observed, "test did not reach the blocked real query");
    assert!(
        cancelled,
        "disconnect left the directory query waiting for its SQL deadline"
    );
}
#[tokio::test]
async fn recorded_abandon_admission_remains_responsive() {
    let observation: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-abandon-admission.json")).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate))).serve(l, rx));
    let mut socket = TcpStream::connect(addr).await.unwrap();
    for request in observation["requests"].as_array().unwrap() {
        socket
            .write_all(&unhex(request.as_str().unwrap()))
            .await
            .unwrap();
    }
    socket
        .write_all(&unhex(observation["final_request"].as_str().unwrap()))
        .await
        .unwrap();
    let divergences:serde_json::Value=serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
    let expected=unhex(divergences["abandon-admission"]["responses"][0].as_str().unwrap());
    let mut actual=vec![0;expected.len()];
    let result=tokio::time::timeout(Duration::from_secs(2),socket.read_exact(&mut actual)).await;
    stop.send(true).unwrap();task.await.unwrap().unwrap();
    assert!(result.is_ok_and(|r|r.is_ok()),"Abandon exhausted connection admission (restored Go bug)");
    assert_eq!(actual,expected);
}
#[tokio::test]
async fn global_operation_budget_sheds_before_authentication() {
    use setjoin_conformance::harness::Db;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ldap-operation-budget") else {
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
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",
            &[&include_str!("../oracle/password-hash.txt")],
        )
        .await
        .unwrap();
    let dsn = format!(
        "{}{}application_name=gofree-ldap1-budget",
        db.app.as_deref().unwrap_or(&db.dsn),
        if db.app.as_deref().unwrap_or(&db.dsn).contains('?') {
            "&"
        } else {
            "?"
        }
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = fixture_server(
        setjoin_pg::ScopedExecutor::from_dsn(&dsn, 4).unwrap(),
        "ldap1.test",
    )
    .with_tls(tls_server())
    .with_max_inflight(1);
    let task = tokio::spawn(Arc::new(server).serve(l, rx));
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
    let session = corpus
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "people")
        .unwrap();
    let mut first = tls_client(address).await;
    first
        .write_all(&unhex(session["steps"][0]["request"].as_str().unwrap()))
        .await
        .unwrap();
    let mut response = [0; 14];
    first.read_exact(&mut response).await.unwrap();
    assert_eq!(response[9], 0);
    owner
        .batch_execute("BEGIN; LOCK TABLE users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    first
        .write_all(&unhex(session["steps"][1]["request"].as_str().unwrap()))
        .await
        .unwrap();
    let mut observed = false;
    for _ in 0..100 {
        observed=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-ldap1-budget' AND wait_event_type='Lock')",&[]).await.unwrap().get(0);
        if observed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut second = tls_client(address).await;
    second
        .write_all(&unhex("300c020101600702010304008000"))
        .await
        .unwrap();
    second.read_exact(&mut response).await.unwrap();
    owner.batch_execute("ROLLBACK").await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    assert!(observed, "test did not reach blocked work");
    assert_eq!(
        response[9], 51,
        "pool-wide saturation must reject before the anonymous-bind handler"
    );
}
#[tokio::test]
async fn recorded_cancel_fallback() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/cancel-go-sessions.json")).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(Server::default().with_threat_gate(Arc::new(FixtureGate))).serve(l, rx));
    for session in corpus.as_array().unwrap() {
        let mut socket = TcpStream::connect(address).await.unwrap();
        for step in session["steps"].as_array().unwrap() {
            socket
                .write_all(&unhex(step["request"].as_str().unwrap()))
                .await
                .unwrap();
            for response in step["responses"].as_array().unwrap() {
                let expected = unhex(response.as_str().unwrap());
                let mut actual = vec![0; expected.len()];
                tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut actual))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(actual, expected, "{}", session["name"]);
            }
        }
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn cancel_stops_an_active_directory_query() {
    use setjoin_conformance::harness::Db;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("ldap-active-cancel") else {
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
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",
            &[&include_str!("../oracle/password-hash.txt")],
        )
        .await
        .unwrap();
    let dsn = format!(
        "{}{}application_name=gofree-ldap1-active-cancel",
        db.app.as_deref().unwrap_or(&db.dsn),
        if db.app.as_deref().unwrap_or(&db.dsn).contains('?') {
            "&"
        } else {
            "?"
        }
    );
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = fixture_server(
        setjoin_pg::ScopedExecutor::from_dsn(&dsn, 4).unwrap(),
        "ldap1.test",
    )
    .with_tls(tls_server());
    let task = tokio::spawn(Arc::new(server).serve(l, rx));
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
    let session = corpus
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "people")
        .unwrap();
    let mut socket = tls_client(address).await;
    socket
        .write_all(&unhex(session["steps"][0]["request"].as_str().unwrap()))
        .await
        .unwrap();
    let mut response = [0; 14];
    socket.read_exact(&mut response).await.unwrap();
    assert_eq!(response[9], 0);
    owner
        .batch_execute("BEGIN; LOCK TABLE users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    socket
        .write_all(&unhex(session["steps"][1]["request"].as_str().unwrap()))
        .await
        .unwrap();
    let mut observed = false;
    for _ in 0..100 {
        observed=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-ldap1-active-cancel' AND wait_event_type='Lock')",&[]).await.unwrap().get(0);
        if observed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    use tokio_util::codec::Encoder;
    let request = ldap3_proto::proto::LdapMsg {
        msgid: 2,
        op: ldap3_proto::proto::LdapOp::ExtendedRequest(ldap3_proto::proto::LdapExtendedRequest {
            name: "1.3.6.1.1.8".into(),
            value: Some(vec![0x30, 3, 2, 1, 1]),
        }),
        ctrl: vec![],
    };
    let mut bytes = bytes::BytesMut::new();
    ldap3_proto::LdapCodec::default()
        .encode(request, &mut bytes)
        .unwrap();
    socket.write_all(&bytes).await.unwrap();
    let mut cancel_code = None;
    for _ in 0..2 {
        socket.read_exact(&mut response).await.unwrap();
        if response[5] == 0x78 {
            cancel_code = Some(response[9]);
            break;
        }
    }

    let mut cancelled = false;
    for _ in 0..100 {
        let active:bool=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-ldap1-active-cancel' AND wait_event_type='Lock')",&[]).await.unwrap().get(0);
        if !active {
            cancelled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    owner.batch_execute("ROLLBACK").await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    assert_eq!(
        cancel_code,
        Some(118),
        "Cancel must find the in-flight directory operation"
    );
    assert!(observed, "test did not reach the blocked real query");
    assert!(
        cancelled,
        "Cancel left the directory query waiting for its SQL deadline"
    );
}
#[tokio::test]
async fn recorded_empty_directory_ous() {
    replay_cases(&["groups-empty", "resources-empty", "contacts-empty"]).await
}
#[tokio::test]
async fn recorded_other_ou_matching_filters() {
    replay_cases(&["groups-filter", "contacts-filter"]).await
}
#[tokio::test]
async fn recorded_failed_authentication_with_database() {
    replay_cases(&["bad-password", "unknown-user"]).await
}

#[tokio::test]
async fn recorded_shared_threat_policy_at_ldap_bind_socket(){
 use setjoin_conformance::harness::Db;
 use setjoin_threat::{Config,Gate};
 let _serial=SERIAL.lock().await;let db=Db::for_case("AUTHRT-LDAP").unwrap();let owner=db.connect().await.unwrap();
 owner.batch_execute(include_str!("../oracle/cleanup.sql")).await.unwrap();owner.batch_execute(include_str!("../oracle/seed.sql")).await.unwrap();owner.execute("UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",&[&include_str!("../oracle/password-hash.txt")]).await.unwrap();
 let corpus:serde_json::Value=serde_json::from_str(include_str!("../oracle/threat-policy-go-sessions.json")).unwrap();
 for case in corpus.as_array().unwrap(){
  owner.batch_execute(include_str!("../oracle/threat/reset.sql")).await.unwrap();
  let sql=match case["name"].as_str().unwrap(){"feed"=>"INSERT INTO threat_feed_blocks(cidr,source) VALUES('127.0.0.1/32','authrt-ldap')","ip"=>"INSERT INTO ip_rules(cidr,action,description) VALUES('127.0.0.1/32','block','authrt-ldap')","lockout"=>"INSERT INTO auth_lockouts(lockout_key,locked_until) VALUES('user:alice@ldap1.test',now()+interval '800 milliseconds')","policy"=>r#"INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9420422,'authrt-ldap',9422,'on','user','9342011','{}','{"action":"block"}')"#,_=>"SELECT 1"};owner.batch_execute(sql).await.unwrap();
  let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).unwrap();let mut config=Config::default();for key in ["geo_block","spray_detect","captcha","tarpit","rate_limit","conditional_access"]{config.overrides.insert(format!("feature.{key}"),false);}config.overrides.insert("feature.threat_feed".into(),true);config.overrides.insert("feature.conditional_access".into(),case["name"]=="policy");
  let gate=Gate::load(exec.clone(),setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap(),config,None).await.unwrap();
  let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();let(stop,rx)=watch::channel(false);
  let server=fixture_server(exec,"ldap1.test").with_tls(tls_server()).with_threat_gate(gate);let task=tokio::spawn(Arc::new(server).serve(listener,rx));
  let mut socket=tls_client(addr).await;let step=&case["steps"][0];socket.write_all(&unhex(step["request"].as_str().unwrap())).await.unwrap();let divergence:serde_json::Value=serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
  let expected=unhex(if case["name"]=="policy"{divergence["ldap-user-policy"]["responses"][0].as_str().unwrap()}else{step["responses"][0].as_str().unwrap()});let mut actual=vec![0;expected.len()];tokio::time::timeout(Duration::from_secs(3),socket.read_exact(&mut actual)).await.unwrap().unwrap();drop(socket);stop.send(true).unwrap();task.await.unwrap().unwrap();assert_eq!(actual,expected,"{}",case["name"]);
 }
 owner.batch_execute(include_str!("../oracle/threat/reset.sql")).await.unwrap();owner.batch_execute(include_str!("../oracle/cleanup.sql")).await.unwrap();
}

/// Hold the first credential exchange while a pipelined failing Bind arrives.
struct InterleavedBinds {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    failed: tokio::sync::Notify,
}
impl setjoin_threat::ThreatGate for InterleavedBinds {
    fn intercept<'a>(
        &'a self,
        meta: &'a setjoin_threat::ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (setjoin_threat::ThreatAction, Duration)> {
        Box::pin(async move {
            if meta.username == "alice@ldap1.test" {
                self.entered.notify_one();
                self.release.notified().await;
                (setjoin_threat::ThreatAction::Allow, Duration::ZERO)
            } else {
                self.failed.notify_one();
                (setjoin_threat::ThreatAction::Reject, Duration::ZERO)
            }
        })
    }
    fn record_result<'a>(
        &'a self,
        _: &'a setjoin_threat::ConnectionMeta,
        _: bool,
        _: i64,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async {})
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        _: &'a mut setjoin_threat::ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (setjoin_threat::ThreatAction, String)> {
        Box::pin(async { (setjoin_threat::ThreatAction::Allow, String::new()) })
    }
}

#[tokio::test]
async fn interleaved_valid_then_failed_binds_leave_connection_anonymous() {
    use futures_util::{FutureExt, SinkExt, StreamExt};
    use ldap3_proto::{proto::*, LdapCodec};
    let _serial = SERIAL.lock().await;
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-LDAP-bind-race").unwrap();
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",
            &[&include_str!("../oracle/password-hash.txt")],
        )
        .await
        .unwrap();
    let gate = Arc::new(InterleavedBinds {
        entered: Default::default(),
        release: Default::default(),
        failed: Default::default(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = fixture_server(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
        "ldap1.test",
    )
    .with_tls(tls_server())
    .with_threat_gate(gate.clone());
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    let outcome = std::panic::AssertUnwindSafe(async {
        let mut socket =
            tokio_util::codec::Framed::new(tls_client(addr).await, LdapCodec::default());
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
        let people = corpus
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "people")
            .unwrap();
        let mut decoder = LdapCodec::default();
        use tokio_util::codec::Decoder;
        let bind = decoder
            .decode(
                &mut unhex(people["steps"][0]["request"].as_str().unwrap())
                    .as_slice()
                    .into(),
            )
            .unwrap()
            .unwrap();
        socket.send(bind).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), gate.entered.notified())
            .await
            .unwrap();
        socket
            .send(LdapMsg {
                msgid: 2,
                op: LdapOp::BindRequest(LdapBindRequest {
                    version: 3,
                    dn: "denied@ldap1.test".into(),
                    cred: LdapBindCred::Simple("wrong".into()),
                }),
                ctrl: vec![],
            })
            .await
            .unwrap();
        // Concurrent implementations enter the failing Bind before releasing A.
        // Serialized implementations defer B until A completes.
        let _ = tokio::time::timeout(Duration::from_millis(200), gate.failed.notified()).await;
        gate.release.notify_one();
        let mut codes = vec![];
        for _ in 0..2 {
            let reply = tokio::time::timeout(Duration::from_secs(5), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let LdapOp::BindResponse(response) = reply.op else {
                panic!("expected Bind response")
            };
            codes.push((reply.msgid, response.res.code));
        }
        codes.sort_by_key(|r| r.0);
        assert_eq!(
            codes,
            vec![
                (1, LdapResultCode::Success),
                (2, LdapResultCode::InvalidCredentials)
            ]
        );
        let search = decoder
            .decode(
                &mut unhex(people["steps"][1]["request"].as_str().unwrap())
                    .as_slice()
                    .into(),
            )
            .unwrap()
            .unwrap();
        socket.send(search).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            matches!(
                reply.op,
                LdapOp::SearchResultDone(LdapResult {
                    code: LdapResultCode::InsufficentAccessRights,
                    ..
                })
            ),
            "failed pipelined Bind left an authenticated principal: {:?}",
            reply.op
        );
    })
    .catch_unwind()
    .await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn listener_refuses_missing_threat_policy() {
    for server in [
        Server::default(),
        Server::default().with_threat_policy(setjoin_ldap::ThreatPolicy::Disabled),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_stop, rx) = watch::channel(false);
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            Arc::new(server).serve(listener, rx),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(ref error)) if error.kind() == std::io::ErrorKind::PermissionDenied),
            "LDAP accepted sessions without an enforced threat policy: {result:?}"
        );
    }
}

// Only the legacy protocol oracle uses an allow-all policy. Production serve
// still requires explicit Enforced wiring, including for anonymous operations.
struct FixtureGate;
impl setjoin_threat::ThreatGate for FixtureGate {
    fn intercept<'a>(
        &'a self,
        _: &'a setjoin_threat::ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (setjoin_threat::ThreatAction, std::time::Duration)>
    {
        Box::pin(async {
            (
                setjoin_threat::ThreatAction::Allow,
                std::time::Duration::ZERO,
            )
        })
    }
    fn record_result<'a>(
        &'a self,
        _: &'a setjoin_threat::ConnectionMeta,
        _: bool,
        _: i64,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async {})
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        _: &'a mut setjoin_threat::ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (setjoin_threat::ThreatAction, String)> {
        Box::pin(async { (setjoin_threat::ThreatAction::Allow, String::new()) })
    }
}
fn fixture_server(db: setjoin_pg::ScopedExecutor, domain: impl Into<String>) -> Server {
    Server::new(db, domain).with_threat_gate(Arc::new(FixtureGate))
}

#[tokio::test]
async fn disconnect_during_bind_releases_connection_admission() {
    use futures_util::SinkExt;
    use ldap3_proto::{proto::*, LdapCodec};
    let gate = Arc::new(InterleavedBinds {
        entered: Default::default(),
        release: Default::default(),
        failed: Default::default(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = Server::default()
        .with_tls(tls_server())
        .with_threat_gate(gate.clone())
        .with_max_connections(1);
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    let mut first = tokio_util::codec::Framed::new(tls_client(addr).await, LdapCodec::default());
    first
        .send(LdapMsg {
            msgid: 1,
            op: LdapOp::BindRequest(LdapBindRequest {
                version: 3,
                dn: "alice@ldap1.test".into(),
                cred: LdapBindCred::Simple("irrelevant".into()),
            }),
            ctrl: vec![],
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), gate.entered.notified())
        .await
        .unwrap();
    drop(first);
    let second = tokio::time::timeout(Duration::from_secs(1), tls_client(addr)).await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(
        second.is_ok(),
        "disconnected Bind retained the sole connection permit"
    );
}
