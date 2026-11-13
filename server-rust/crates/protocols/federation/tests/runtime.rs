//! Production composition seam: complete static config + inherited socket + Go off.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
use setjoin_federation::runtime::{reaper_from_env, Runtime};
use std::collections::HashMap;
use tokio::net::TcpListener;
fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| map.get(k).cloned()
}
#[tokio::test]
async fn federation_activation_requires_sole_ownership_and_complete_static_config() {
    let certs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("oracle/certs");
    let cert = certs.join("zulu.crt");
    let key = certs.join("zulu.key");
    let base = [
        ("FEDERATION_LOCAL_DOMAIN", " ZULU.TEST "),
        ("FEDERATION_CERT", cert.to_str().unwrap()),
        ("FEDERATION_KEY", key.to_str().unwrap()),
        ("DB_DSN", "postgres://nobody@127.0.0.1:9/none"),
        ("DB_DIRECT_DSN", "postgres://nobody@127.0.0.1:9/none"),
    ];
    assert!(Runtime::prepare(None, &env(&[])).unwrap().is_none());
    assert!(Runtime::prepare(None, &env(&base)).unwrap().is_none());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(Runtime::prepare(Some(listener), &env(&base))
        .err()
        .unwrap()
        .contains("GO_WORKERS_OFF"));
    let mut configured = base.to_vec();
    configured.push(("GO_WORKERS_OFF", "federation-service"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(Runtime::prepare(Some(listener), &env(&configured))
        .unwrap()
        .is_some());
}
#[test]
fn reaper_requires_both_worker_switches_even_without_a_listener() {
    assert!(reaper_from_env(&env(&[])).unwrap().is_none());
    let mut pairs = vec![("RUST_WORKERS_ON", "federation-residue-reap")];
    assert!(reaper_from_env(&env(&pairs))
        .err()
        .unwrap()
        .contains("GO_WORKERS_OFF"));
    pairs.push(("GO_WORKERS_OFF", "federation-residue-reap"));
    assert!(reaper_from_env(&env(&pairs))
        .err()
        .unwrap()
        .contains("DB_DSN"));
    pairs.push(("DB_DSN", "postgres://nobody@127.0.0.1:9/none"));
    assert!(reaper_from_env(&env(&pairs)).unwrap().is_some());
}

mod common;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_cache_reloads_authoritatively_and_revokes_live_delivery() {
    let _serial = SERIAL.lock().await;
    use setjoin_federation::{
        stream::{dial, PeerEndpoint},
        trust::Anchor,
        wire::Hello,
    };
    use std::{sync::atomic::AtomicBool, time::Duration};
    use tokio_util::sync::CancellationToken;
    let Some(db) = setjoin_conformance::harness::Db::for_case("federation-runtime") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    let prior: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap();
    owner.execute("INSERT INTO federation_allowlist(peer_domain,peer_anchor,enabled) VALUES('alpha.test',$1,true)",&[&common::ca_pem("alpha")]).await.unwrap();
    let certs = common::oracle_dir().join("certs");
    let cert = certs.join("zulu.crt");
    let key = certs.join("zulu.key");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let runtime = Runtime::prepare(
        Some(listener),
        &env(&[
            ("FEDERATION_LOCAL_DOMAIN", "zulu.test"),
            ("FEDERATION_CERT", cert.to_str().unwrap()),
            ("FEDERATION_KEY", key.to_str().unwrap()),
            ("DB_DSN", &db.dsn),
            ("DB_DIRECT_DSN", &db.direct),
            ("GO_WORKERS_OFF", "federation-service"),
        ]),
    )
    .unwrap()
    .unwrap();
    let ctx = CancellationToken::new();
    let task = tokio::spawn(runtime.run(ctx.clone()));
    let result = std::panic::AssertUnwindSafe(async {
        let endpoint = PeerEndpoint {
            domain: "zulu.test".into(),
            target: "127.0.0.1".into(),
            port: address.port(),
        };
        let peer = tokio::time::timeout(
            Duration::from_secs(10),
            dial(
                &ctx,
                &AtomicBool::new(true),
                &endpoint,
                &common::identity("alpha"),
                Anchor::from_pem(&common::ca_pem("zulu")).unwrap(),
                &Hello::new("alpha.test"),
                Duration::from_secs(5),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        // A forged notification payload cannot override the authoritative DB row.
        owner.execute("SELECT pg_notify('config_changed','{\"key\":\"feature.federation\",\"enabled\":false}')",&[]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(150), peer.read_frame())
                .await
                .is_err()
        );
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=false WHERE key='feature.federation'",
                &[],
            )
            .await
            .unwrap();
        owner
            .execute(
                "SELECT pg_notify('config_changed','malformed reload hint')",
                &[],
            )
            .await
            .unwrap();
        // Go's config observer updates the cache but does not wake federation:
        // live eviction converges on its existing 20-second reconcile ticker.
        assert!(
            tokio::time::timeout(Duration::from_millis(250), peer.read_frame())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(25), peer.read_frame())
                .await
                .unwrap()
                .is_err()
        );
    });
    use futures_util::FutureExt;
    let outcome = result.catch_unwind().await;
    ctx.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.federation'",
            &[&prior],
        )
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}

#[tokio::test]
async fn invalid_leaf_material_leaves_only_federation_inert_like_go() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(Runtime::prepare(
        Some(listener),
        &env(&[
            ("FEDERATION_LOCAL_DOMAIN", "zulu.test"),
            ("FEDERATION_CERT", "/no/fed2.crt"),
            ("FEDERATION_KEY", "/no/fed2.key"),
            ("GO_WORKERS_OFF", "federation-service"),
            ("DB_DSN", "postgres://nobody@127.0.0.1:9/none"),
            ("DB_DIRECT_DSN", "postgres://nobody@127.0.0.1:9/none")
        ])
    )
    .unwrap()
    .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn losing_only_notify_connection_preserves_the_last_go_feature_snapshot() {
    use setjoin_federation::{
        service::TypingChannel,
        stream::{dial, PeerEndpoint},
        trust::Anchor,
        wire::Hello,
    };
    use std::{sync::atomic::AtomicBool, time::Duration};
    use tokio_util::sync::CancellationToken;
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("fed2-cache-disconnect") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    let prior: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.federation'",
            &[],
        )
        .await
        .unwrap();
    owner.execute("INSERT INTO federation_allowlist(peer_domain,peer_anchor,enabled) VALUES('alpha.test',$1,true)",&[&common::ca_pem("alpha")]).await.unwrap();
    let mut direct = url::Url::parse(&db.direct).unwrap();
    let target = format!(
        "{}:{}",
        direct.host_str().unwrap(),
        direct.port().unwrap_or(5432)
    );
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    direct.set_host(Some("127.0.0.1")).unwrap();
    direct.set_port(Some(port)).unwrap();
    let cut = CancellationToken::new();
    let stop = CancellationToken::new();
    let proxy_task = {
        let cut = cut.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=stop.cancelled()=>break,
                    connection=proxy.accept()=>{let (mut inbound,_)=connection.unwrap();let target=target.clone();let cut=cut.clone();tasks.spawn(async move {
                        tokio::select! { _=cut.cancelled()=>{}, _=async {if let Ok(mut outbound)=tokio::net::TcpStream::connect(target).await {let _=tokio::io::copy_bidirectional(&mut inbound,&mut outbound).await;}}=>{} }
                    });},
                    Some(_)=tasks.join_next()=>{},
                }
            }
            tasks.shutdown().await;
        })
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let certs = common::oracle_dir().join("certs");
    let cert = certs.join("zulu.crt");
    let key = certs.join("zulu.key");
    let runtime = Runtime::prepare(
        Some(listener),
        &env(&[
            ("FEDERATION_LOCAL_DOMAIN", "zulu.test"),
            ("FEDERATION_CERT", cert.to_str().unwrap()),
            ("FEDERATION_KEY", key.to_str().unwrap()),
            ("DB_DSN", &db.dsn),
            ("DB_DIRECT_DSN", direct.as_str()),
            ("GO_WORKERS_OFF", "federation-service"),
        ]),
    )
    .unwrap()
    .unwrap();
    let service = runtime.service.clone();
    let ctx = CancellationToken::new();
    let task = tokio::spawn(runtime.run(ctx.clone()));
    use futures_util::FutureExt;
    let outcome = std::panic::AssertUnwindSafe(async {
        let endpoint = PeerEndpoint {
            domain: "zulu.test".into(),
            target: "127.0.0.1".into(),
            port: address.port(),
        };
        let peer = tokio::time::timeout(
            Duration::from_secs(10),
            dial(
                &ctx,
                &AtomicBool::new(true),
                &endpoint,
                &common::identity("alpha"),
                Anchor::from_pem(&common::ca_pem("zulu")).unwrap(),
                &Hello::new("alpha.test"),
                Duration::from_secs(5),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        cut.cancel();
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Go's pgnotify.Listener refreshes only after reconnect; losing the
        // direct connection does not invalidate a still-usable DB snapshot.
        service
            .send_typing(
                &ctx,
                &TypingChannel {
                    channel_id: 1,
                    peer_domain: "alpha.test".into(),
                    room_id: String::new(),
                    remote_id: "bob@alpha.test".into(),
                    local_user_email: "alice@zulu.test".into(),
                },
            )
            .await;
        let frame = tokio::time::timeout(Duration::from_secs(2), peer.read_frame())
            .await
            .unwrap()
            .unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../oracle/typing-go.json")).unwrap();
        assert_eq!(
            String::from_utf8(frame.encode()).unwrap(),
            expected["frames"]["dm"].as_str().unwrap()
        );
    })
    .catch_unwind()
    .await;
    ctx.cancel();
    task.await.unwrap();
    stop.cancel();
    proxy_task.await.unwrap();
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.federation'",
            &[&prior],
        )
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}
