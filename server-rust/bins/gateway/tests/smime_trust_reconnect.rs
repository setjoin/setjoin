//! #465 (owner-approved security fix 2026-11-05): a removed S/MIME trust anchor must stop
//! being trusted across a LISTEN reconnect. Frozen Go never repaired a `smime_trust_changed`
//! notification lost while its subscription was down. The cache serves no pool while the
//! listener is disconnected and is cleared when the subscription is back.
//! Mutant: `scripts/test-smtp-secfix-mutants.py` (feature `oracle-mutants`,
//! `SETJOIN_MAILSEC_MUTANT=smime-no-reconnect-reload|smime-cache-while-deaf`).
use setjoin_conformance::harness::Db;
use setjoin_gateway::smime_trust::SmimeTrustListener;
use setjoin_mail_security::smime::{parse_chain, trust::TrustCache};
use setjoin_pg::ScopedExecutor;
use std::{sync::Arc, time::Duration};

const A: &str = include_str!("../../../tests/conformance/mail-security/smime-certs/a.pem");
const X: i64 = 910_001;

async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_anchor_stops_being_trusted_after_listen_reconnect() {
    let Some(db) = Db::for_case("smime-trust-reconnect") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let fingerprint = parse_chain(A.as_bytes()).unwrap().remove(0).fingerprint;
    let stash: Vec<String> = owner
        .query("SELECT to_jsonb(s)::text FROM smime_trust_anchors s", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .batch_execute("DELETE FROM smime_trust_anchors")
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO smime_trust_anchors (label, cert_pem, fingerprint, domain_id) VALUES ('reconnect', $1, $2, NULL)",
            &[&A, &fingerprint],
        )
        .await
        .unwrap();
    let worker = ScopedExecutor::from_dsn(&db.dsn, 4).unwrap();
    let cache = Arc::new(TrustCache::new());
    let listener = Arc::new(SmimeTrustListener::new(cache.clone(), db.dsn.clone()));
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(listener.clone().run_until(async move {
        let _ = stopped.await;
    }));
    until("listener connects", || listener.listening()).await;

    assert!(cache.pool_for(&worker, X).await.trusts(&fingerprint));
    assert_eq!(
        cache.cached_domains(),
        1,
        "a pool is cached while listening"
    );

    // Drop the LISTEN connection from the server side.
    owner
        .execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname=current_database() AND pid<>pg_backend_pid() \
             AND query ILIKE '%LISTEN%smime_trust_changed%'",
            &[],
        )
        .await
        .unwrap();
    until("listener notices the loss", || !listener.listening()).await;
    // A lookup while deaf must not leave a cached pool behind.
    assert!(cache.pool_for(&worker, X).await.trusts(&fingerprint));
    // Removed while the subscription is down: no notification can announce it.
    owner
        .batch_execute("DELETE FROM smime_trust_anchors")
        .await
        .unwrap();
    assert!(
        !cache.pool_for(&worker, X).await.trusts(&fingerprint),
        "a removed anchor stayed trusted while the listener was disconnected"
    );
    until("listener reconnects", || listener.listening()).await;
    assert!(
        !cache.pool_for(&worker, X).await.trusts(&fingerprint),
        "a removed anchor stayed trusted after the reconnect"
    );
    let _ = stop.send(());
    task.await.unwrap();

    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM smime_trust_anchors;",
        )
        .await
        .unwrap();
    for row in &stash {
        owner
            .execute("INSERT INTO smime_trust_anchors SELECT * FROM jsonb_populate_record(NULL::smime_trust_anchors, $1::text::jsonb)", &[row])
            .await
            .unwrap();
    }
    owner.batch_execute("COMMIT;").await.unwrap();
}
