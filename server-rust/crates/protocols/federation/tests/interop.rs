//! Pure-Rust federation peer interop: both connection roles (dialer and
//! acceptor), >256-frame bidirectional delivery, durable cursors, and
//! ephemeral typing over mutual TLS on loopback.
mod common;
use common::*;
use futures_util::FutureExt;
use serde_json::Value;
use setjoin_federation::{
    db::WorkerPool,
    discover::{Srv, StaticResolver},
    log::Logger,
    service::{Config, Service, TypingChannel},
};
use setjoin_pg::workers::WorkerDatabase;
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_postgres::Client;
use tokio_util::sync::CancellationToken;

fn make_service(
    domain: &str,
    direct_dsn: &str,
    db_dsn: &str,
    resolver: Arc<StaticResolver>,
) -> Arc<Service> {
    let mut cfg = Config::new(domain);
    cfg.direct_dsn = Some(direct_dsn.to_string());
    cfg.resolver = Some(resolver);
    Service::new(
        cfg,
        Arc::new(WorkerPool::new(WorkerDatabase::new(db_dsn).unwrap())),
        Arc::new(AtomicBool::new(true)),
        identity(domain.strip_suffix(".test").unwrap()),
        Logger::stderr(),
    )
    .unwrap()
}

async fn wait_cursors(owner: &Client, peer: &str, n: i64) {
    let mut last = (0_i64, 0_i64, 0_i64);
    for _ in 0..200 {
        let row = owner
            .query_one(
                "SELECT
                   COALESCE((SELECT last_seq         FROM federation_peers        WHERE peer_domain = $1), 0),
                   COALESCE((SELECT last_acked_seq   FROM federation_peers        WHERE peer_domain = $1), 0),
                   COALESCE((SELECT last_applied_seq FROM federation_inbox_cursor WHERE peer_domain = $1), 0)",
                &[&peer],
            )
            .await
            .unwrap();
        let seq: i64 = row.get(0);
        let acked: i64 = row.get(1);
        let applied: i64 = row.get(2);
        if seq == n && acked == n && applied == n {
            return;
        }
        last = (seq, acked, applied);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "peer {peer} cursors must be durably acked and applied at {n}: \
         last_seq={}, last_acked_seq={}, last_applied_seq={}",
        last.0, last.1, last.2
    );
}

async fn assert_inbox_gap_free(owner: &Client, peer: &str, expected: i64) {
    let rows = owner
        .query(
            "SELECT peer_seq FROM federation_inbox WHERE peer_domain = $1 ORDER BY peer_seq",
            &[&peer],
        )
        .await
        .unwrap();
    let seqs: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
    assert_eq!(seqs.len() as i64, expected, "inbox count for {peer}");
    assert_eq!(seqs.first().copied(), Some(1), "inbox min_seq for {peer}");
    assert_eq!(
        seqs.last().copied(),
        Some(expected),
        "inbox max_seq for {peer}"
    );
    let gaps: Vec<i64> = (1..=expected)
        .zip(seqs.iter().copied())
        .filter_map(|(want, got)| (want != got).then_some(want))
        .collect();
    assert!(gaps.is_empty(), "inbox gaps for {peer}: {gaps:?}");
}

async fn enqueue(owner: &Client, peer: &str, from: i64, to: i64) -> i64 {
    let pad = "x".repeat(160);
    let payload = format!(r#"{{"body":"Rust to Rust <&>","pad":"{pad}"}}"#);
    let rows = owner
        .query(
            "SELECT federation_enqueue($1,'interop-'||$1||'-'||g,'application/json',$4::text::jsonb) \
             FROM generate_series($2::bigint,$3::bigint) g",
            &[&peer, &from, &to, &payload],
        )
        .await
        .unwrap();
    rows.last().unwrap().get(0)
}

async fn scenario(
    db: &setjoin_conformance::harness::Db,
    owner: &Client,
    local_domain: &str,
    peer_domain: &str,
) {
    let cleanup = std::fs::read_to_string(oracle_dir().join("cleanup.sql")).unwrap();
    owner.batch_execute(&cleanup).await.unwrap();
    owner
        .batch_execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.federation'")
        .await
        .unwrap();
    for domain in [local_domain, peer_domain] {
        let ca = ca_pem(domain.strip_suffix(".test").unwrap());
        owner
            .execute(
                "INSERT INTO federation_allowlist(peer_domain,peer_anchor,scope,enabled) VALUES($1,$2,'room',true)",
                &[&domain, &ca],
            )
            .await
            .unwrap();
    }

    let local_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = local_ln.local_addr().unwrap().port();
    let peer_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_port = peer_ln.local_addr().unwrap().port();

    let resolver = Arc::new(StaticResolver(vec![
        (
            local_domain.to_string(),
            Srv {
                target: "127.0.0.1".into(),
                port: local_port,
                priority: 0,
                weight: 0,
            },
        ),
        (
            peer_domain.to_string(),
            Srv {
                target: "127.0.0.1".into(),
                port: peer_port,
                priority: 0,
                weight: 0,
            },
        ),
    ]));

    let local_service = make_service(local_domain, &db.direct, &db.dsn, resolver.clone());
    let peer_service = make_service(peer_domain, &db.direct, &db.dsn, resolver);

    let ctx = CancellationToken::new();
    let local_run = tokio::spawn(local_service.clone().run_with_listener(ctx.clone(), local_ln));
    let peer_run = tokio::spawn(peer_service.clone().run_with_listener(ctx.clone(), peer_ln));

    let mut typing_fixture = None;
    let outcome = std::panic::AssertUnwindSafe(async {
        // More than the 256-frame window; each side must drain using real acks.
        assert_eq!(enqueue(owner, local_domain, 1, 300).await, 300);
        assert_eq!(enqueue(owner, peer_domain, 1, 300).await, 300);

        wait_cursors(owner, local_domain, 300).await;
        wait_cursors(owner, peer_domain, 300).await;
        assert_inbox_gap_free(owner, local_domain, 300).await;
        assert_inbox_gap_free(owner, peer_domain, 300).await;

        // #418: native typing works across both TLS roles (dialer and acceptor).
        // The receiving peer's canonical reducer must emit the same ephemeral
        // notification as the immutable Go HTTP typing recording, without
        // adding durable messages.
        typing_fixture = Some(
            setjoin_conformance::fixture::account(owner, "chat4-fed-typing")
                .await
                .unwrap(),
        );
        let recipient = typing_fixture.as_ref().unwrap();
        let to: String = owner
            .query_one("SELECT email FROM users WHERE id=$1", &[&recipient.user])
            .await
            .unwrap()
            .get(0);
        let from = format!("alice@{local_domain}");
        let channel: i64 = owner
            .query_one(
                "INSERT INTO chat_channels(kind,visibility,created_by,federated_peer_domain,federated_remote_id,federated_local_key) \
                 VALUES('dm','private',$1,$2,$3,encode(digest(least($3::text,$4::text)||':'||greatest($3::text,$4::text),'sha256'),'hex')) \
                 RETURNING id",
                &[&recipient.user, &local_domain, &from, &to],
            )
            .await
            .unwrap()
            .get(0);
        owner
            .execute(
                "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'owner')",
                &[&channel, &recipient.user],
            )
            .await
            .unwrap();
        let mut notifications = db.listen(&format!("chat:{}", recipient.user)).await.unwrap();
        local_service
            .send_typing(
                &ctx,
                &TypingChannel {
                    peer_domain: peer_domain.into(),
                    local_user_email: from,
                    remote_id: to,
                    ..Default::default()
                },
            )
            .await;
        let mut seen = Vec::new();
        for _ in 0..100 {
            seen.extend(notifications.drain(owner).await.unwrap());
            if !seen.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut actual: Vec<Value> = seen
            .iter()
            .map(|v| serde_json::from_str(v).unwrap())
            .collect();
        for event in &mut actual {
            assert_eq!(event["channelId"], channel);
            event["channelId"] = "<channel>".into();
        }
        let recorded: Value = serde_json::from_str(include_str!(
            "../../../../tests/conformance/chat/goldens/channels-typing-success.json"
        ))
        .unwrap();
        assert_eq!(
            actual,
            vec![recorded["observation"]["notify"][0]["payload"].clone()]
        );
        for domain in [local_domain, peer_domain] {
            let inbox_count: i64 = owner
                .query_one(
                    "SELECT count(*) FROM federation_inbox WHERE peer_domain=$1",
                    &[&domain],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(
                inbox_count, 300,
                "typing must not persist a stanza for {domain}"
            );
            let outbox_count: i64 = owner
                .query_one(
                    "SELECT count(*) FROM federation_outbox WHERE peer_domain=$1",
                    &[&domain],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(
                outbox_count, 300,
                "typing must not create an outbox row for {domain}"
            );
        }
        owner
            .execute(
                "DELETE FROM chat_channels WHERE id=$1 AND created_by=$2",
                &[&channel, &recipient.user],
            )
            .await
            .unwrap();
        if let Some(recipient) = typing_fixture.take() {
            setjoin_conformance::fixture::remove(owner, &recipient)
                .await
                .unwrap();
        }
    })
    .catch_unwind()
    .await;

    ctx.cancel();
    tokio::time::timeout(Duration::from_secs(10), local_run)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), peer_run)
        .await
        .unwrap()
        .unwrap();
    owner.batch_execute(&cleanup).await.unwrap();
    if let Some(recipient) = typing_fixture {
        setjoin_conformance::fixture::remove(owner, &recipient)
            .await
            .unwrap();
    }
    if let Err(p) = outcome {
        std::panic::resume_unwind(p);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_peers_interoperate_as_dialer_and_acceptor() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("federation_peer_interop") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    // One assigned disposable database suffices: peer-domain keys keep the
    // opposite directions separate. No second DB or shared cluster mutation.
    scenario(&db, &owner, "zulu.test", "alpha.test").await;
    scenario(&db, &owner, "alpha.test", "zulu.test").await;
}
