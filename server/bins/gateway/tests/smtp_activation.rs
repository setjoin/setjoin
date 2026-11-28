//! The SMTP swap's activation contract (#501): sockets handed over by systemd are
//! served by the gateway's wiring (real shared gate and flags on the database),
//! inbound without STARTTLS as in Go, submission with STARTTLS-only AUTH.

use setjoin_gateway::smtp_runtime;
use std::{collections::HashMap, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};

fn hooks() -> Option<setjoin_gateway::webhook::Dispatcher> {
    Some(setjoin_gateway::webhook::Dispatcher::new(
        setjoin_pg::workers::WorkerDatabase::new("postgres://nobody@127.0.0.1:9/none").unwrap(),
        None,
    ))
}

async fn read_reply(peer: &mut BufReader<TcpStream>) -> String {
    let mut reply = String::new();
    loop {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), peer.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(!line.is_empty(), "premature EOF after {reply:?}");
        reply.push_str(&line);
        if line.as_bytes().get(3) == Some(&b' ') {
            return reply;
        }
    }
}

/// One case disables the SMTP toggles the other needs enabled: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn activated_sockets_are_served_by_the_runtime_on_the_shared_gate() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp5-activation") else {
        return;
    };
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    let gate = setjoin_threat::Gate::load(
        exec,
        setjoin_threat::WorkerPools::from_dsn(&db.dsn).unwrap(),
        setjoin_threat::Config::default(),
        None,
    )
    .await
    .unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/directory-sync/ldap-fixture");
    let map: HashMap<String, String> = [
        ("GO_LISTENERS_OFF", "smtp,submission"),
        ("DB_DSN", db.dsn.as_str()),
        ("S3_ACCESS_KEY", "fixture"),
        ("S3_SECRET_KEY", "fixture"),
        ("TLS_CERT", fixture.join("server.pem").to_str().unwrap()),
        ("TLS_KEY", fixture.join("server.p8").to_str().unwrap()),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let get = move |name: &str| map.get(name).cloned();
    let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let submission = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (inbound_addr, submission_addr) =
        (inbound.local_addr().unwrap(), submission.local_addr().unwrap());
    let runtime = smtp_runtime::start(
        Some(inbound),
        None,
        Some(submission),
        &get,
        Some(gate),
        hooks(),
    )
    .unwrap()
    .expect("sockets were activated");
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(runtime.run(rx));

    let mut mta = BufReader::new(TcpStream::connect(inbound_addr).await.unwrap());
    assert_eq!(read_reply(&mut mta).await, "220 mailserver ESMTP\r\n");
    mta.get_mut().write_all(b"EHLO peer\r\n").await.unwrap();
    let ehlo = read_reply(&mut mta).await;
    // Go's :25 listener has no STARTTLS and never offers AUTH.
    assert!(!ehlo.contains("STARTTLS") && !ehlo.contains("AUTH"), "{ehlo}");

    let mut msa = BufReader::new(TcpStream::connect(submission_addr).await.unwrap());
    assert_eq!(
        read_reply(&mut msa).await,
        "220 mailserver ESMTP submission ready\r\n"
    );
    msa.get_mut().write_all(b"EHLO client\r\n").await.unwrap();
    let ehlo = read_reply(&mut msa).await;
    assert!(ehlo.contains("250-STARTTLS") && !ehlo.contains("AUTH"), "{ehlo}");
    msa.get_mut()
        .write_all(b"AUTH PLAIN AGE=\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut msa).await,
        "530 Must issue STARTTLS first\r\n"
    );
    drop((mta, msa));
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
}

/// Go reads `feature.smtp_inbound` / `feature.smtp_submission` at startup and does
/// not bind a disabled listener: here the socket stays but every connection is
/// closed unanswered.
#[tokio::test]
async fn disabled_admin_toggles_close_the_listeners() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp5-toggles") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute("UPDATE feature_toggles SET enabled=false WHERE key IN ('feature.smtp_inbound','feature.smtp_submission')")
        .await
        .unwrap();
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    let gate = setjoin_threat::Gate::load(
        exec,
        setjoin_threat::WorkerPools::from_dsn(&db.dsn).unwrap(),
        setjoin_threat::Config::default(),
        None,
    )
    .await;
    owner
        .batch_execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.smtp_inbound','feature.smtp_submission')")
        .await
        .unwrap();
    let gate = gate.unwrap();
    let map: HashMap<String, String> = [
        ("GO_LISTENERS_OFF", "smtp,submission"),
        ("DB_DSN", db.dsn.as_str()),
        ("S3_ACCESS_KEY", "fixture"),
        ("S3_SECRET_KEY", "fixture"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let get = move |name: &str| map.get(name).cloned();
    let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let submission = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a, b) = (inbound.local_addr().unwrap(), submission.local_addr().unwrap());
    let runtime = smtp_runtime::start(Some(inbound), None, Some(submission), &get, Some(gate), hooks())
        .unwrap()
        .expect("sockets were activated");
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(runtime.run(rx));
    for addr in [a, b] {
        let mut peer = BufReader::new(TcpStream::connect(addr).await.unwrap());
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(5), peer.read_line(&mut line))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(read, 0, "a disabled listener must not greet: {line:?}");
    }
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap();
}
