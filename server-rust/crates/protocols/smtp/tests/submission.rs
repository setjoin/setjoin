//! #501: replays every frozen-Go submission session (AUTH, threat gate, envelope
//! ownership, reducer failures, per-user limit) over real TCP + STARTTLS.
#[path = "support/auth_blobs.rs"]
mod auth_blobs;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}
type BoxStream = Box<dyn Stream>;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/conformance/directory-sync/ldap-fixture")
        .join(name)
}
async fn upgrade(socket: BoxStream) -> BoxStream {
    use tokio_rustls::rustls::{
        pki_types::{pem::PemObject, CertificateDer, ServerName},
        ClientConfig, RootCertStore,
    };
    let ca = CertificateDer::from_pem_slice(&std::fs::read(fixture("ca.pem")).unwrap()).unwrap();
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

async fn gate(
    db: &setjoin_conformance::harness::Db,
    name: &str,
) -> Arc<dyn setjoin_threat::ThreatGate> {
    let mut config = setjoin_threat::Config::default();
    for k in [
        "geo_block",
        "spray_detect",
        "captcha",
        "tarpit",
        "rate_limit",
        "conditional_access",
    ] {
        config.overrides.insert(format!("feature.{k}"), false);
    }
    config.overrides.insert("feature.threat_feed".into(), true);
    config
        .overrides
        .insert("feature.rate_limit".into(), name == "rate");
    config
        .overrides
        .insert("feature.conditional_access".into(), name == "policy");
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    setjoin_threat::Gate::load(
        exec,
        setjoin_threat::WorkerPools::from_dsn(&db.dsn).unwrap(),
        config,
        None,
    )
    .await
    .unwrap()
}

async fn replay(corpus: &str) {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp5-submission") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let cases: serde_json::Value = serde_json::from_str(corpus).unwrap();
    let cleanup = include_str!("../oracle/submission-cleanup.sql");
    let seed = include_str!("../oracle/submission-seed.sql");
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        // The rate counters live in per-minute windows: a case that straddles a minute boundary
        // splits its counts. Start each case early in a wall-clock minute (as the drive oracles do).
        let second = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 60;
        if second >= 45 {
            tokio::time::sleep(Duration::from_secs(61 - second)).await;
        }
        if std::env::var("SMTP5_ONLY").is_ok_and(|only| only != name) {
            continue;
        }
        owner.batch_execute(cleanup).await.unwrap();
        owner.batch_execute(seed).await.unwrap();
        if let Some(sql) = case["setup_sql"].as_str() {
            owner.batch_execute(sql).await.unwrap();
        }
        if let Some(kind) = case["threat"].as_str() {
            let sql = match kind {
                "feed" => "INSERT INTO threat_feed_blocks(cidr,source) VALUES('127.0.0.1/32','smtp5')",
                "ip" => "INSERT INTO ip_rules(cidr,action,description) VALUES('127.0.0.1/32','block','smtp5')",
                "lockout" => "INSERT INTO auth_lockouts(lockout_key,locked_until) VALUES('user:alice@smtp5.test',now()+interval '800 milliseconds')",
                "device_country_null" => "INSERT INTO device_registry(user_id,device_hash,user_agent,ip_prefix,country,auth_count) VALUES(9501011,encode(sha256('|127.0.0.0'::bytea),'hex'),'','127.0.0.0',NULL,1)",
                "rate" => "INSERT INTO rate_limit_counters(key,count,window_start) VALUES('auth:smtp:127.0.0.1',20,now())",
                "policy" => r#"INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9501900,'smtp5',9501,'on','user','9501011','{}','{"action":"block"}')"#,
                _ => "SELECT 1",
            };
            owner.batch_execute(sql).await.unwrap();
        }
        let blobs = Arc::new(auth_blobs::Blobs::default());
        let mut server = setjoin_smtp::Submission::new(
            setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap(),
        );
        if case["cert"] == true {
            server = server
                .with_starttls_files(fixture("server.pem"), fixture("server.p8"))
                .unwrap();
        }
        if let Some(kind) = case["threat"].as_str() {
            server = server.with_threat_gate(gate(&db, kind).await);
        }
        if let Some(max) = case["per_user_max"].as_i64() {
            server = server.with_per_user_max(max);
        }
        if case["capture_blobs"] == true {
            server = server.with_blob_store(blobs.clone());
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(Arc::new(server).serve(listener, rx));
        let mut sockets = std::collections::HashMap::<u64, BoxStream>::new();
        for (index, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let conn = step["conn"].as_u64().unwrap_or(0);
            let mut socket = match sockets.remove(&conn) {
                Some(s) => s,
                None => Box::new(TcpStream::connect(addr).await.unwrap()),
            };
            socket
                .write_all(step["send"].as_str().unwrap_or("").as_bytes())
                .await
                .unwrap();
            if let (Some(pattern), Some(count)) = (step["repeat"].as_str(), step["count"].as_u64())
            {
                let copies = (65536 / pattern.len()).max(1);
                let chunk = pattern.repeat(copies);
                let mut left = count as usize;
                while left > 0 {
                    let n = left.min(copies);
                    socket
                        .write_all(&chunk.as_bytes()[..n * pattern.len()])
                        .await
                        .unwrap();
                    left -= n;
                }
            }
            socket.flush().await.unwrap();
            if step["half_close"] == true {
                socket.shutdown().await.unwrap();
            }
            let want = step["reply"].as_str().unwrap_or("").as_bytes();
            if step["lines"] == 0 {
                let mut got = Vec::new();
                tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut got))
                    .await
                    .unwrap_or(Ok(0))
                    .unwrap_or(0);
                assert_eq!(
                    String::from_utf8_lossy(&got),
                    String::from_utf8_lossy(want),
                    "{name} step {index}"
                );
                continue;
            }
            let mut got = Vec::new();
            for _ in 0..step["lines"].as_u64().unwrap() {
                loop {
                    let mut byte = [0];
                    let n = tokio::time::timeout(Duration::from_secs(8), socket.read(&mut byte))
                        .await
                        .unwrap_or_else(|_| panic!("{name} step {index}: read timed out after {} bytes", got.len()))
                        .unwrap_or(0);
                    assert_eq!(n, 1, "{name} step {index}: premature EOF");
                    got.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
            }
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(want),
                "{name} step {index}"
            );
            if step["upgrade"] == true {
                socket = upgrade(socket).await;
            }
            sockets.insert(conn, socket);
        }
        drop(sockets);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let got: String = owner
            .query_one(include_str!("../oracle/submission-observe.sql"), &[])
            .await
            .unwrap()
            .get(0);
        let got = serde_json::from_str::<serde_json::Value>(&got).unwrap();
        for (key, want) in case["effects"].as_object().unwrap() {
            assert_eq!(&got[key], want, "effects.{key} of {name}");
        }
        if let Some(expected) = case.get("blobs") {
            assert_eq!(
                serde_json::to_value(&*blobs.0.lock().unwrap()).unwrap(),
                *expected,
                "stored raw bytes {name}"
            );
        }
        let _ = stop.send(true);
        task.await.unwrap().unwrap();
        if let Some(sql) = case["teardown_sql"].as_str() {
            owner.batch_execute(sql).await.unwrap();
        }
    }
    owner.batch_execute(cleanup).await.unwrap();
}

#[tokio::test]
async fn submission_sessions_match_frozen_go() {
    replay(include_str!("../oracle/submission-go.json")).await;
}

/// Security fix (#501, SECFIX3 pattern): AUTH for an unknown, disabled or
/// hash-less account costs one password hash, like a real failed login. Mutant
/// `smtp-no-dummy-hash` (feature oracle-mutants) restores frozen Go's early return.
#[tokio::test]
async fn unknown_and_disabled_accounts_spend_a_password_hash() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp5-submission") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/submission-cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/submission-seed.sql"))
        .await
        .unwrap();
    owner
        .batch_execute("UPDATE users SET password_hash='' WHERE id=9501015")
        .await
        .unwrap();
    let server = Arc::new(
        setjoin_smtp::Submission::new(setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap())
            .with_starttls_files(fixture("server.pem"), fixture("server.p8"))
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.clone().serve(listener, rx));
    let mut socket: BoxStream = Box::new(TcpStream::connect(addr).await.unwrap());
    async fn line(socket: &mut BoxStream) -> String {
        let mut got = Vec::new();
        loop {
            let mut byte = [0];
            socket.read_exact(&mut byte).await.unwrap();
            got.push(byte[0]);
            if byte[0] == b'\n' {
                return String::from_utf8(got).unwrap();
            }
        }
    }
    line(&mut socket).await;
    socket.write_all(b"EHLO c\r\n").await.unwrap();
    for _ in 0..6 {
        line(&mut socket).await;
    }
    socket.write_all(b"STARTTLS\r\n").await.unwrap();
    line(&mut socket).await;
    let mut socket = upgrade(socket).await;
    socket.write_all(b"EHLO c\r\n").await.unwrap();
    for _ in 0..6 {
        line(&mut socket).await;
    }
    use base64::Engine;
    let auth = |user: &str, pw: &str| {
        let b = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pw}"));
        format!("AUTH PLAIN {b}\r\n")
    };
    for (user, pw, spent) in [
        ("nobody@smtp5.test", "x", 1),
        ("off@smtp5.test", "x", 2),
        ("nomb@smtp5.test", "x", 3),
        ("alice@smtp5.test", "wrong", 3),
        ("alice@smtp5.test", "IMAP1-correct-password!", 3),
    ] {
        socket.write_all(auth(user, pw).as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        let reply = line(&mut socket).await;
        assert_eq!(
            server.dummy_verifications(),
            spent,
            "{user}: unknown/disabled/hash-less accounts must each cost one hash ({reply})"
        );
    }
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/submission-cleanup.sql"))
        .await
        .unwrap();
}

/// The cases share one database and fixed fixtures: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
