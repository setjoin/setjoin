//! #302: dispatcher behaviour the one-tick oracle cannot show. The oracle's receivers sit on
//! loopback, so here the production (guarded) client is exercised against them: it must
//! refuse loopback, private and metadata addresses at dial time without sending a byte,
//! and log the failure like Go's legacy path. Also `enqueue_durable`, the circuit breaker
//! through the executor, mailbox-scoped fail-closed matching and graceful shutdown.
mod common;
use common::BoxError;
use hyper::Response;
use setjoin_config_secret::CryptoProfile;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::webhook::{CloudEvent, Dispatcher};
use setjoin_pg::workers::WorkerDatabase;
use setjoin_platform::webhook_secret::SecretCodec;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

const SECRET: &str = "4444444444444444444444444444444444444444444444444444444444444444";
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn codec() -> Option<SecretCodec> {
    Some(SecretCodec::new(b"gofree-dispatch-master", CryptoProfile::Standard))
}

async fn subscribe(owner: &tokio_postgres::Client, url: &str, scope: &str, user: Option<i64>) -> Result<i64, BoxError> {
    Ok(owner
        .query_one(
            "INSERT INTO webhook_subscriptions(url,secret,event_types,scope,user_id) VALUES($1,$2,'[\"user.updated\",\"mail.received\"]'::jsonb,$3,$4) RETURNING id",
            &[&url, &SECRET, &scope, &user],
        )
        .await?
        .get(0))
}

async fn rows(owner: &tokio_postgres::Client, sub: i64) -> Result<Vec<(String, i32, i32, String)>, BoxError> {
    Ok(owner
        .query("SELECT status,attempt,COALESCE(response_code,-1),COALESCE(error_message,'') FROM webhook_deliveries WHERE subscription_id=$1 ORDER BY id", &[&sub])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guarded_client_refuses_internal_addresses_without_sending() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("webhook-dispatch-guard") else { return Ok(()) };
    let owner = db.connect().await?;
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let hook = common::fake_upstream(move |_| {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Response::builder().status(200).body(common::full("ok")).unwrap()
        }
    })
    .await;
    let mut subs = Vec::new();
    for url in [format!("http://{hook}/x"), "http://10.0.0.1/x".into(), "http://169.254.169.254/latest".into(), "http://[::1]:9/x".into(), "http://localhost:9/x".into()] {
        subs.push(subscribe(&owner, &url, "organization", None).await?);
    }
    let dispatcher = Dispatcher::new(WorkerDatabase::new(&db.dsn)?, codec());
    dispatcher.dispatch(&CloudEvent::new("mailserver/test", "user.updated", serde_json::json!({"user_id": 1}))).await;
    dispatcher.quiesce().await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reached the loopback receiver");
    for sub in &subs {
        let log = rows(&owner, *sub).await?;
        assert_eq!(log.len(), 1, "{sub}: {log:?}");
        assert_eq!((log[0].0.as_str(), log[0].1, log[0].2), ("failed", 1, 0), "{log:?}");
        assert!(log[0].3.contains("URL is not allowed (must be http/https to a public host)"), "{log:?}");
        assert!(log[0].3.starts_with("Post \""), "{log:?}");
    }
    dispatcher.shutdown().await;
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_dispatch_and_durable_enqueue_follow_the_matching_rules() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("webhook-dispatch-scope") else { return Ok(()) };
    let owner = db.connect().await?;
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    let a = fixture::account(&owner, "plat4d-a").await?;
    let b = fixture::account(&owner, "plat4d-b").await?;
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = seen.clone();
    let hook = common::fake_upstream(move |request| {
        let log = log.clone();
        async move {
            log.lock().unwrap().push(request.uri().path().to_owned());
            Response::builder().status(200).body(common::full("ok")).unwrap()
        }
    })
    .await;
    let org = subscribe(&owner, &format!("http://{hook}/org"), "organization", None).await?;
    let self_a = subscribe(&owner, &format!("http://{hook}/self-a"), "self", Some(a.user)).await?;
    let self_b = subscribe(&owner, &format!("http://{hook}/self-b"), "self", Some(b.user)).await?;
    let dispatcher = Dispatcher::unguarded_for_tests(WorkerDatabase::new(&db.dsn)?, codec());
    let taken = |seen: &Arc<std::sync::Mutex<Vec<String>>>| {
        let mut paths = std::mem::take(&mut *seen.lock().unwrap());
        paths.sort();
        paths
    };
    // A generic event: organization subscriptions only (default-self rows fail closed).
    dispatcher.dispatch(&CloudEvent::new("t", "user.updated", serde_json::json!({}))).await;
    dispatcher.quiesce().await;
    assert_eq!(taken(&seen), ["/org"]);
    // A user event: organization plus the subject's own.
    dispatcher.dispatch_for_user(a.user, &CloudEvent::new("t", "user.updated", serde_json::json!({}))).await;
    dispatcher.quiesce().await;
    assert_eq!(taken(&seen), ["/org", "/self-a"]);
    // A mailbox event proves the pair in SQL: the right pair reaches the owner, a mismatched
    // pair reaches nobody.
    dispatcher.dispatch_for_mailbox(a.user, a.mailbox, &CloudEvent::new("t", "mail.received", serde_json::json!({}))).await;
    dispatcher.quiesce().await;
    assert_eq!(taken(&seen), ["/org", "/self-a"]);
    dispatcher.dispatch_for_mailbox(a.user, b.mailbox, &CloudEvent::new("t", "mail.received", serde_json::json!({}))).await;
    dispatcher.quiesce().await;
    assert!(taken(&seen).is_empty(), "a mailbox that is not the subject's fails closed");
    // Durable enqueue: organization subscriptions only, one pending row each, delivered
    // at once; the same event id again changes nothing at the subscriber.
    let event = CloudEvent::new("t", "user.updated", serde_json::json!({"n": 1}));
    let before = rows(&owner, org).await?.len();
    dispatcher.enqueue_durable(&event).await?;
    dispatcher.quiesce().await;
    assert_eq!(taken(&seen), ["/org"]);
    let durable = rows(&owner, org).await?;
    assert_eq!(durable.len(), before + 1, "one pending row, delivered at once");
    assert_eq!(durable.last().map(|r| (r.0.as_str(), r.1)), Some(("success", 1)));
    dispatcher.enqueue_durable(&event).await?;
    dispatcher.quiesce().await;
    assert!(taken(&seen).is_empty(), "a replayed event id is a no-op");
    assert_eq!(rows(&owner, org).await?.len(), before + 1);
    assert!(rows(&owner, self_a).await?.iter().all(|r| r.0 == "success"));
    assert_eq!(rows(&owner, self_b).await?.len(), 0);
    dispatcher.shutdown().await;
    // After shutdown nothing is accepted.
    dispatcher.dispatch(&CloudEvent::new("t", "user.updated", serde_json::json!({}))).await;
    assert!(taken(&seen).is_empty());
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_whose_secret_cannot_be_opened_is_skipped() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("webhook-dispatch-secret") else { return Ok(()) };
    let owner = db.connect().await?;
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let hook = common::fake_upstream(move |_| {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Response::builder().status(200).body(common::full("ok")).unwrap()
        }
    })
    .await;
    let sub = subscribe(&owner, &format!("http://{hook}/x"), "organization", None).await?;
    owner.execute("UPDATE webhook_subscriptions SET secret=NULL,secret_enc='\\x00'::bytea,secret_key_id='v2' WHERE id=$1", &[&sub]).await?;
    for with_codec in [codec(), None] {
        let dispatcher = Dispatcher::unguarded_for_tests(WorkerDatabase::new(&db.dsn)?, with_codec);
        dispatcher.dispatch(&CloudEvent::new("t", "user.updated", serde_json::json!({}))).await;
        dispatcher.quiesce().await;
        dispatcher.shutdown().await;
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0, "fail closed: nothing was sent");
    assert!(rows(&owner, sub).await?.is_empty(), "the legacy path logs nothing for a skipped subscription");
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    Ok(())
}

/// A claim the client gave up on must not commit (#472 review). The claim reducer is held on a
/// table lock past the 5 s claim timeout; once the lock is released the abandoned statement
/// finishes server-side. Its lease and attempt must roll back: with retry disabled, a committed
/// lease would expire into `exhausted` ("delivery lease expired") and the event would never be
/// sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_claim_rolls_back_instead_of_leasing_the_row() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("webhook-dispatch-claim-timeout") else { return Ok(()) };
    let owner = db.connect().await?;
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let hook = common::fake_upstream(move |_| {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Response::builder().status(200).body(common::full("ok")).unwrap()
        }
    })
    .await;
    let sub = subscribe(&owner, &format!("http://{hook}/x"), "organization", None).await?;
    owner.execute("UPDATE webhook_subscriptions SET retry_enabled=false WHERE id=$1", &[&sub]).await?;
    let delivery: i64 = owner
        .query_one(
            "INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status) \
             VALUES($1,'claim-timeout-event','user.updated','{}'::jsonb,0,'pending') RETURNING id",
            &[&sub],
        )
        .await?
        .get(0);
    // Hold the table so the claim reducer's first UPDATE waits past the claim timeout.
    let locker = db.connect().await?;
    locker.batch_execute("BEGIN; LOCK TABLE webhook_deliveries IN SHARE MODE").await?;
    let dispatcher = Dispatcher::unguarded_for_tests(WorkerDatabase::new(&db.dsn)?, codec());
    let started = std::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(15), dispatcher.retry_pending())
        .await
        .map_err(|_| "retry_pending did not return within 15 s: the 5 s claim timeout is missing (stale setjoin-gateway build?)")?;
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(4),
        "the claim waited on the lock until its timeout: {:?}",
        started.elapsed()
    );
    locker.batch_execute("COMMIT").await?;
    // Let the abandoned backend run the claim to its end (commit or rollback) and exit.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let left: i64 = owner
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND state<>'idle' \
                 AND datname=current_database() AND position('webhook_delivery_claim(' in query)>0",
                &[],
            )
            .await?
            .get(0);
        if left == 0 {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err("the abandoned claim backend did not finish".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let row = owner
        .query_one("SELECT status,attempt,lease_owner IS NULL FROM webhook_deliveries WHERE id=$1", &[&delivery])
        .await?;
    let state: (String, i32, bool) = (row.get(0), row.get(1), row.get(2));
    assert_eq!(
        state,
        ("pending".to_owned(), 0, true),
        "a claim the client gave up on rolled back: no lease, no attempt spent"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing was sent while the claim was abandoned");
    // The next claim takes the row and delivers it once.
    dispatcher.retry_pending().await;
    dispatcher.quiesce().await;
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the delivery was sent");
    let row = owner
        .query_one("SELECT status,attempt FROM webhook_deliveries WHERE id=$1", &[&delivery])
        .await?;
    assert_eq!((row.get::<_, String>(0), row.get::<_, i32>(1)), ("success".to_owned(), 1));
    dispatcher.shutdown().await;
    owner.batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions").await?;
    Ok(())
}
