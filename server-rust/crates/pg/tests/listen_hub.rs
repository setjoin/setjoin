//! Live PostgreSQL integration tests for [`ListenHub`] (#543).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use setjoin_pg::{ListenEvent, ListenHub};
use tokio_util::sync::CancellationToken;

fn direct_dsn_with_app(app_name: &str) -> String {
    let base = std::env::var("DB_DIRECT_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("TEST_DB_DSN").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()))
        .expect("listen_hub integration tests require TEST_DB_DSN / DB_DIRECT_DSN");
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}application_name={app_name}")
}

fn unique_tag(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{prefix}_{}_{nanos}", std::process::id())
}

async fn connect_control() -> (
    tokio_postgres::Client,
    tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
) {
    let dsn = std::env::var("TEST_DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()))
        .expect("TEST_DB_DSN required");
    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .expect("control PG connect");
    let driver = tokio::spawn(conn);
    (client, driver)
}

#[tokio::test]
async fn single_backend_multiplexes_many_subscribers_and_refcounts_listen_unlisten() {
    let app = unique_tag("lh_single");
    let dsn = direct_dsn_with_app(&app);
    let shutdown = CancellationToken::new();
    let hub = ListenHub::spawn_connected(dsn, shutdown.clone())
        .await
        .expect("spawn connected hub");

    let ch_a = unique_tag("lh_ch_a");
    let ch_b = unique_tag("lh_ch_b");
    let mut sub_a1 = hub.subscribe(&ch_a).await.unwrap();
    let mut sub_a2 = hub.subscribe(&ch_a).await.unwrap();
    let mut sub_b1 = hub.subscribe(&ch_b).await.unwrap();
    let mut sub_b2 = hub.subscribe(&ch_b).await.unwrap();
    let mut sub_b3 = hub.subscribe(&ch_b).await.unwrap();

    let (ctrl, driver) = connect_control().await;

    // Prove exactly ONE PG backend exists for all 5 subscribers across 2 channels.
    let backend_count: i64 = ctrl
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        backend_count, 1,
        "ListenHub must maintain exactly 1 direct LISTEN backend"
    );

    // Fan-out delivery on channel A reaches both subscribers.
    ctrl.query_one("SELECT pg_notify($1, $2)", &[&ch_a, &"payload_a"])
        .await
        .unwrap();
    for sub in [&mut sub_a1, &mut sub_a2] {
        let ev = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("ch_a notify timeout")
            .expect("ch_a event");
        match ev {
            ListenEvent::Notification(n) => {
                assert_eq!(n.channel, ch_a);
                assert_eq!(n.payload, "payload_a");
            }
            other => panic!("expected Notification on ch_a, got {other:?}"),
        }
    }

    // Dropping 1 of 2 subscribers on ch_a keeps LISTEN active (2->1 does NOT UNLISTEN).
    drop(sub_a1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.query_one("SELECT pg_notify($1, $2)", &[&ch_a, &"still_alive"])
        .await
        .unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(3), sub_a2.recv())
        .await
        .expect("ch_a still_alive timeout")
        .expect("event");
    match ev {
        ListenEvent::Notification(n) => assert_eq!(n.payload, "still_alive"),
        other => panic!("expected still_alive Notification, got {other:?}"),
    }

    // Channel B reaches all 3 subscribers.
    ctrl.query_one("SELECT pg_notify($1, $2)", &[&ch_b, &"payload_b"])
        .await
        .unwrap();
    for sub in [&mut sub_b1, &mut sub_b2, &mut sub_b3] {
        let ev = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("ch_b timeout")
            .expect("event");
        match ev {
            ListenEvent::Notification(n) => assert_eq!(n.payload, "payload_b"),
            other => panic!("expected payload_b Notification, got {other:?}"),
        }
    }

    // Clean shutdown closes subscriptions and releases backend.
    hub.shutdown().await;
    assert!(tokio::time::timeout(Duration::from_secs(3), sub_a2.recv())
        .await
        .expect("shutdown close timeout")
        .is_none());
    drop(ctrl);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn pg_terminate_backend_reconnects_relistens_emits_resync_and_delivers_subsequent_notify() {
    let app = unique_tag("lh_reconn");
    let dsn = direct_dsn_with_app(&app);
    let shutdown = CancellationToken::new();
    let hub = ListenHub::spawn_connected(dsn, shutdown.clone())
        .await
        .expect("spawn connected hub");

    let ch = unique_tag("lh_ch_reconn");
    let mut sub = hub.subscribe(&ch).await.unwrap();
    let initial_epoch = hub.epoch();
    assert!(initial_epoch >= 1);

    let (ctrl, driver) = connect_control().await;

    // Locate and terminate the ListenHub backend.
    let pid: i32 = ctrl
        .query_one(
            "SELECT pid FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .await
        .unwrap()
        .get(0);
    let terminated: bool = ctrl
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(
        terminated,
        "expected pg_terminate_backend to kill hub backend"
    );

    // Subscriber MUST receive ResyncRequired with a bumped epoch AFTER re-LISTEN completes.
    let ev = tokio::time::timeout(Duration::from_secs(5), sub.recv())
        .await
        .expect("resync timeout after backend termination")
        .expect("resync event");
    let resync_epoch = match ev {
        ListenEvent::ResyncRequired { epoch } => epoch,
        other => panic!("expected ResyncRequired after pg_terminate_backend, got {other:?}"),
    };
    assert!(
        resync_epoch > initial_epoch,
        "resync epoch ({resync_epoch}) must exceed initial epoch ({initial_epoch})"
    );

    // Immediately after ResyncRequired is delivered, LISTEN is ALREADY active again:
    // sending NOTIFY right now must be delivered with zero extra delay.
    ctrl.query_one("SELECT pg_notify($1, $2)", &[&ch, &"after_reconnect"])
        .await
        .unwrap();
    let ev2 = tokio::time::timeout(Duration::from_secs(3), sub.recv())
        .await
        .expect("post-reconnect notify timeout")
        .expect("post-reconnect event");
    match ev2 {
        ListenEvent::Notification(n) => {
            assert_eq!(n.channel, ch);
            assert_eq!(n.payload, "after_reconnect");
        }
        other => panic!("expected Notification after reconnect, got {other:?}"),
    }

    // Still exactly 1 backend with a new PID.
    let rows = ctrl
        .query(
            "SELECT pid FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_ne!(rows[0].get::<_, i32>(0), pid);

    hub.shutdown().await;
    drop(ctrl);
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn slow_subscriber_overflow_never_blocks_session_revoke_and_delivers_resync() {
    let app = unique_tag("lh_slow");
    let dsn = direct_dsn_with_app(&app);
    let shutdown = CancellationToken::new();
    let hub = ListenHub::spawn_connected(dsn, shutdown.clone())
        .await
        .expect("spawn connected hub");

    let slow_ch = unique_tag("lh_slow_ch");
    let fast_ch = unique_tag("lh_session_revoke");

    // Tiny capacity=2 for slow subscriber; never polled while flooded.
    let mut slow_sub = hub.subscribe_with_capacity(&slow_ch, 2).await.unwrap();
    let mut fast_sub = hub.subscribe(&fast_ch).await.unwrap();

    let (ctrl, driver) = connect_control().await;

    // Flood slow_ch with 20 notifications without reading slow_sub.
    for i in 0..20 {
        let payload = format!("flood_{i}");
        ctrl.query_one("SELECT pg_notify($1, $2)", &[&slow_ch, &payload])
            .await
            .unwrap();
    }

    // Immediately notify fast_ch (session_revoke) — must arrive promptly without stalling!
    ctrl.query_one("SELECT pg_notify($1, $2)", &[&fast_ch, &"revoke_user_42"])
        .await
        .unwrap();
    let fast_ev = tokio::time::timeout(Duration::from_secs(2), fast_sub.recv())
        .await
        .expect("fast subscriber was stalled by slow subscriber!")
        .expect("fast event");
    match fast_ev {
        ListenEvent::Notification(n) => {
            assert_eq!(n.channel, fast_ch);
            assert_eq!(n.payload, "revoke_user_42");
        }
        other => panic!("expected Notification on fast_ch, got {other:?}"),
    }

    // Now wake slow_sub: it MUST receive ResyncRequired (coalesced, never lost!).
    let slow_ev = tokio::time::timeout(Duration::from_secs(2), slow_sub.recv())
        .await
        .expect("slow subscriber resync timeout")
        .expect("slow event");
    assert!(
        matches!(slow_ev, ListenEvent::ResyncRequired { .. }),
        "expected ResyncRequired for overflowed slow subscriber, got {slow_ev:?}"
    );

    // After resync, fresh notifications on slow_ch flow cleanly again.
    ctrl.query_one(
        "SELECT pg_notify($1, $2)",
        &[&slow_ch, &"fresh_after_resync"],
    )
    .await
    .unwrap();
    let fresh_ev = tokio::time::timeout(Duration::from_secs(2), slow_sub.recv())
        .await
        .expect("fresh notification after resync timeout")
        .expect("fresh event");
    match fresh_ev {
        ListenEvent::Notification(n) => assert_eq!(n.payload, "fresh_after_resync"),
        other => panic!("expected fresh Notification after resync, got {other:?}"),
    }

    hub.shutdown().await;
    drop(ctrl);
    driver.await.unwrap().unwrap();
}
