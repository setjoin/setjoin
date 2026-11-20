use setjoin_threat::RuntimeTasks;
/// The cases share one database and fixed fixtures: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn cleanup_tick_replays_frozen_go_survivors() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN (REQUIRE_DB lane)");
    let (db, driver) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    db.batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    db.batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    RuntimeTasks::new(&dsn, None)
        .unwrap()
        .cleanup_tick()
        .await
        .unwrap();
    let actual:Vec<String>=db.query("SELECT 'oauth:'||encode(token_hash,'hex') AS k FROM oauth_tokens WHERE user_id=9420011 UNION ALL SELECT id FROM oidc_tokens WHERE user_id=9420011 ORDER BY k",&[]).await.unwrap().iter().map(|r|r.get(0)).collect();
    let expected: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/oracle/cleanup-go.json"
        ))
        .unwrap(),
    )
    .unwrap();
    db.batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    assert_eq!(actual, expected);
    drop(db);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn feed_tick_replays_fake_endpoint_and_keeps_last_snapshot_on_empty() {
    let _serial = SERIAL.lock().await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dsn = std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN");
    let (db, driver) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/drop/drop.txt", listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        let mut requests = vec![];
        for response in ["; comment\n198.51.100.0/24 ; SBL1\n2001:db8::/32 other\n198.51.100.0/24 ; duplicate\nnot-a-cidr\n", "; empty feed leaves previous snapshot\n"] {
   let(mut socket,_)=listener.accept().await.unwrap();let mut bytes=vec![];
   while !bytes.ends_with(b"\r\n\r\n") {let mut b=[0;1];assert_eq!(socket.read(&mut b).await.unwrap(),1);bytes.extend_from_slice(&b)}
   let req=String::from_utf8(bytes).unwrap();let path=req.split_whitespace().nth(1).unwrap();requests.push(format!("GET https://www.spamhaus.org{path}"));
   socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).as_bytes()).await.unwrap();
  }
        requests
    });
    db.batch_execute("DELETE FROM threat_feed_blocks")
        .await
        .unwrap();
    let runtime = RuntimeTasks::new(&dsn, None).unwrap();
    let mut snapshots = vec![];
    for _ in 0..2 {
        runtime.feed_tick(&url).await.unwrap();
        snapshots.push(
            db.query(
                "SELECT cidr::text||'|'||source FROM threat_feed_blocks ORDER BY cidr::text",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>(),
        );
    }
    let actual = serde_json::json!({"requests":peer.await.unwrap(),"snapshots":snapshots});
    db.batch_execute("DELETE FROM threat_feed_blocks")
        .await
        .unwrap();
    assert_eq!(
        actual,
        serde_json::from_str::<serde_json::Value>(include_str!("../oracle/feed-go.json")).unwrap()
    );
    drop(db);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn listeners_replay_go_notifications_and_reconcile_after_disconnect() {
    let _serial = SERIAL.lock().await;
    use setjoin_threat::{Config, ConnectionMeta, Gate, Watchers};
    let dsn = std::env::var("TEST_DB_DSN").unwrap();
    let (db, driver) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let old: bool = db
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.threat_feed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    db.batch_execute("DELETE FROM threat_feed_blocks WHERE source='authrt-listeners'; DELETE FROM conditional_access_policies WHERE id=9420421; INSERT INTO threat_feed_blocks(cidr,source) VALUES('192.0.2.42/32','authrt-listeners'); UPDATE feature_toggles SET enabled=false WHERE key='feature.threat_feed'").await.unwrap();
    let mut config = Config::default();
    for k in [
        "geo_block",
        "spray_detect",
        "captcha",
        "tarpit",
        "rate_limit",
    ] {
        config.overrides.insert(format!("feature.{k}"), false);
    }
    config
        .overrides
        .insert("feature.conditional_access".into(), true);
    let gate = Gate::load(
        setjoin_pg::ScopedExecutor::from_dsn(&dsn, 4).unwrap(),
        setjoin_threat::WorkerPools::from_dsn(&dsn).unwrap(),
        config,
        None,
    )
    .await
    .unwrap();
    let watchers = Watchers::start(gate.clone(), &dsn, "gofree-authrt-rust")
        .await
        .unwrap();
    let meta = ConnectionMeta {
        source_ip: "192.0.2.42".into(),
        username: "authrt-listener".into(),
        protocol: "imap".into(),
        ..Default::default()
    };
    let pre = |d: setjoin_threat::Decision| {
        format!(
            "{}|{}",
            if d.action == setjoin_threat::ThreatAction::Allow {
                "proceed"
            } else {
                "reject"
            },
            d.reason
        )
    };
    let mut observations = vec![pre(gate.decide(&meta, true).await)];
    db.batch_execute(r#"UPDATE feature_toggles SET enabled=true WHERE key='feature.threat_feed'; SELECT pg_notify('config_changed','{"key":"feature.threat_feed","enabled":false}')"#).await.unwrap();
    for expected in ["reject|threat_blocked", "proceed|"] {
        if expected == "proceed|" {
            db.batch_execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-authrt-rust-flags'; UPDATE feature_toggles SET enabled=false WHERE key='feature.threat_feed'").await.unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(12), async {
            loop {
                if pre(gate.decide(&meta, true).await) == expected {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await
            }
        })
        .await
        .unwrap();
        observations.push(pre(gate.decide(&meta, true).await));
    }
    let meta = ConnectionMeta {
        source_ip: "192.0.2.43".into(),
        user_id: 9420011,
        protocol: "imap".into(),
        ..Default::default()
    };
    let post = |(a, r): (setjoin_threat::ThreatAction, String)| {
        format!(
            "{}|{r}",
            if a == setjoin_threat::ThreatAction::Allow {
                "proceed"
            } else {
                "reject"
            }
        )
    };
    observations.push(post(gate.post_auth(&meta).await));
    db.batch_execute(r#"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-authrt-rust-policy'; INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9420421,'authrt-listeners',9421,'on','user','9420011','{}','{"action":"block"}')"#).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(12), async {
        loop {
            if post(gate.post_auth(&meta).await) == "reject|conditional_access_blocked" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await
        }
    })
    .await
    .unwrap();
    observations.push(post(gate.post_auth(&meta).await));
    drop(watchers);
    db.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.threat_feed'",
        &[&old],
    )
    .await
    .unwrap();
    db.batch_execute("DELETE FROM threat_feed_blocks WHERE source='authrt-listeners'; DELETE FROM conditional_access_policies WHERE id=9420421").await.unwrap();
    let expected: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/oracle/listeners-go.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(observations, expected);
    drop(db);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn denylist_tick_replays_go_positive_matches_and_failure_retention() {
    let _serial = SERIAL.lock().await;
    use setjoin_threat::AuthDenylist;
    let dsn = std::env::var("TEST_DB_DSN").unwrap();
    let (db, driver) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    db.batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    db.batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    db.batch_execute(include_str!("../oracle/revocations.sql"))
        .await
        .unwrap();
    let cache = AuthDenylist::default();
    let worker = setjoin_pg::workers::WorkerDatabase::new(&dsn).unwrap();
    cache.refresh(&worker).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i128;
    let probe = || {
        vec![
            cache.contains(9420011, now, "authrt-jti", ""),
            cache.contains(9420011, now, "", "authrt-family"),
            cache.contains(9420011, now - 7200_000_000_000, "", ""),
            cache.contains(9420011, now, "other", "other"),
            cache.contains(9420099, now, "authrt-jti", "authrt-family"),
        ]
    };
    let mut actual = vec![probe()];
    let unavailable =
        setjoin_pg::workers::WorkerDatabase::new("host=127.0.0.1 port=1 connect_timeout=1")
            .unwrap();
    assert!(cache.refresh(&unavailable).await.is_err());
    actual.push(probe());
    db.execute("DELETE FROM session_revocations WHERE user_id=9420011", &[])
        .await
        .unwrap();
    cache.refresh(&worker).await.unwrap();
    actual.push(probe());
    db.batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    let expected: Vec<Vec<bool>> = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/oracle/denylist-go.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(actual, expected);
    drop(db);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn feed_transport_replays_go_gzip_and_request_headers() {
    let _serial = SERIAL.lock().await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dsn = std::env::var("TEST_DB_DSN").unwrap();
    let (db, driver) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/drop/drop.txt", listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![];
        while !request.ends_with(b"\r\n\r\n") {
            let mut b = [0; 1];
            assert_eq!(socket.read(&mut b).await.unwrap(), 1);
            request.extend_from_slice(&b);
        }
        let compressed: &[u8] = &[
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 51, 180, 180, 208, 51, 53, 212, 51, 52, 48, 208, 51,
            208, 55, 50, 81, 176, 86, 8, 118, 242, 49, 228, 2, 0, 216, 114, 246, 77, 23, 0, 0, 0,
        ];
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",compressed.len()).as_bytes()).await.unwrap();
        socket.write_all(compressed).await.unwrap();
        String::from_utf8(request).unwrap()
    });
    db.execute("DELETE FROM threat_feed_blocks", &[])
        .await
        .unwrap();
    let result = RuntimeTasks::new(&dsn, None)
        .unwrap()
        .feed_tick(&endpoint)
        .await;
    let blocks: Vec<String> = db
        .query(
            "SELECT cidr::text||'|'||source FROM threat_feed_blocks ORDER BY cidr::text",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let request = peer.await.unwrap();
    let header = |name: &str| {
        request
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.trim().to_string())
            })
            .unwrap_or_default()
    };
    let actual = serde_json::json!({"request_line":request.lines().next().unwrap().trim_end_matches(" HTTP/1.1"),"user_agent":header("user-agent"),"accept_encoding":header("accept-encoding"),"blocks":blocks});
    db.execute("DELETE FROM threat_feed_blocks", &[])
        .await
        .unwrap();
    drop(db);
    driver.await.unwrap().unwrap();
    assert!(result.is_ok(), "gzip feed failed: {result:?}");
    assert_eq!(
        actual,
        serde_json::from_str::<serde_json::Value>(include_str!("../oracle/feed-transport-go.json"))
            .unwrap()
    );
}

#[tokio::test]
async fn ip_rule_lookup_uses_go_three_second_query_budget() {
    let _serial = SERIAL.lock().await;
    use setjoin_threat::{Config, ConnectionMeta, Gate, ThreatAction};
    use std::time::{Duration, Instant};
    let dsn = std::env::var("TEST_DB_DSN").unwrap();
    let (owner, driver) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let mut config = Config::default();
    for key in [
        "threat_feed",
        "geo_block",
        "spray_detect",
        "captcha",
        "tarpit",
        "rate_limit",
        "conditional_access",
    ] {
        config.overrides.insert(format!("feature.{key}"), false);
    }
    let gate = Gate::load(
        setjoin_pg::ScopedExecutor::from_dsn_with(
            &dsn,
            1,
            setjoin_pg::Timeouts {
                statement: Duration::from_secs(10),
                ..Default::default()
            },
        )
        .unwrap(),
        setjoin_threat::WorkerPools::from_dsn(&dsn).unwrap(),
        config,
        None,
    )
    .await
    .unwrap();
    let meta = ConnectionMeta {
        source_ip: "198.18.42.99".into(),
        protocol: "ldap".into(),
        ..Default::default()
    };
    assert_eq!(gate.decide(&meta, true).await.action, ThreatAction::Allow);
    owner
        .batch_execute("BEGIN; LOCK TABLE ip_rules IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let started = Instant::now();
    let decision = tokio::time::timeout(Duration::from_secs(4), gate.decide(&meta, true)).await;
    let elapsed = started.elapsed();
    owner.batch_execute("ROLLBACK").await.unwrap();
    drop(owner);
    driver.await.unwrap().unwrap();
    assert!(
        decision.is_ok(),
        "IP rule lookup exceeded Go's three-second budget"
    );
    assert!(
        elapsed >= Duration::from_secs(2),
        "test did not exercise a stalled query"
    );
    let decision = decision.unwrap();
    assert_eq!(decision.action, ThreatAction::Reject);
    assert_eq!(
        decision.reason, "ip_rules_unavailable",
        "#367: an unanswered ip_rules lookup fails closed"
    );
    assert_eq!(
        gate.decide(&meta, true).await.action,
        ThreatAction::Allow,
        "cancelled read poisoned the request pool"
    );
}
