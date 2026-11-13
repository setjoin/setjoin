use chrono::{TimeZone, Timelike};
use setjoin_gateway::workers::{CronScheduler, SessionDenylist};
use setjoin_pg::workers::WorkerDatabase;
use std::sync::Arc;
use std::time::Duration;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn revocation_snapshot(owner: &tokio_postgres::Client, users: &[i64]) -> String {
    owner.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id),'[]')::text FROM session_revocations r WHERE user_id=ANY($1::bigint[])", &[&users]).await.unwrap().get(0)
}

#[tokio::test]
async fn cron_runs_go_interval_at_start_and_after_the_next_due_tick() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let db = WorkerDatabase::new(&dsn).unwrap();
    let mut scheduler = CronScheduler::acquire(db)
        .await
        .unwrap()
        .expect("scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    scheduler
        .register(
            "drain-outbound-hot",
            Arc::new(move || {
                let send = send.clone();
                Box::pin(async move {
                    send.send("tick").unwrap();
                    Ok(())
                })
            }),
        )
        .unwrap();

    let now = chrono::Local::now();
    scheduler.tick(now).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await
            .unwrap(),
        Some("tick")
    );
    scheduler.wait_idle().await;
    scheduler
        .tick(now + chrono::Duration::seconds(1))
        .await
        .unwrap();
    assert!(receive.try_recv().is_err());
    scheduler
        .tick(now + chrono::Duration::seconds(2))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await
            .unwrap(),
        Some("tick")
    );
    scheduler.wait_idle().await;
    scheduler.shutdown().await.unwrap();
}

#[tokio::test]
async fn cron_runs_go_hourly_schedule_and_catches_up_after_a_missed_minute() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let db = WorkerDatabase::new(&dsn).unwrap();
    let mut scheduler = CronScheduler::acquire(db)
        .await
        .unwrap()
        .expect("scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    scheduler
        .register(
            "reset-sending-quotas",
            Arc::new(move || {
                let send = send.clone();
                Box::pin(async move {
                    send.send("tick").unwrap();
                    Ok(())
                })
            }),
        )
        .unwrap();
    let now = chrono::Local::now()
        .with_minute(58)
        .unwrap()
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap();
    scheduler.tick(now).await.unwrap();
    assert!(receive.try_recv().is_err());
    scheduler
        .tick(now + chrono::Duration::minutes(2))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await
            .unwrap(),
        Some("tick")
    );
    scheduler.wait_idle().await;
    // Skip the next hour's matching minute, then check catch-up on minute 1.
    scheduler
        .tick(now + chrono::Duration::minutes(63))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await
            .unwrap(),
        Some("tick")
    );
    scheduler.shutdown().await.unwrap();
}

#[tokio::test]
async fn cron_registers_the_frozen_go_tasks_and_runs_only_those_due() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let mut scheduler = CronScheduler::acquire(WorkerDatabase::new(&dsn).unwrap())
        .await
        .unwrap()
        .expect("scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let names = [
        "drain-outbound-hot",
        "dispatch-scheduled-actions",
        "scan-due-reminders",
        "retry-outbound-queue",
        "drain-journal-queue",
        "retry-journal-queue",
        "prune-ws-subscriptions",
        "prune-used-password-reset-tokens",
        "approval-expire-due",
        "health-check",
        "refresh-antiphish-contact-graph",
        "reset-sending-quotas",
        "prune-auth-lockouts",
        "enforce-retention",
        "purge-deleted-messages",
        "chat-chain-anchor",
        "chat-purge-expired",
        "prune-dmarc-reports",
        "prune-spam",
        "prune-log-tables",
        "prune-ca-signin-log",
        "prune-login-events",
        "prune-session-runtime",
        "prune-changes-journal",
        "prune-bulk-role-jobs",
        "prune-greylist",
        "prune-health-history",
        "prune-vacation-replies",
        "purge-expired-tokens",
        "purge-saml-assertions",
        "create-monthly-partitions",
    ];
    for name in names {
        let send = send.clone();
        scheduler
            .register(
                name,
                Arc::new(move || {
                    let send = send.clone();
                    Box::pin(async move {
                        send.send(name).unwrap();
                        Ok(())
                    })
                }),
            )
            .unwrap_or_else(|err| panic!("{name}: {err}"));
    }
    // Sunday at 04:00: Go starts interval jobs immediately, plus these
    // matching hourly, daily, and weekly jobs. No other job is due.
    let now = chrono::Local
        .with_ymd_and_hms(2026, 10, 25, 4, 0, 0)
        .single()
        .expect("valid local time");
    scheduler.tick(now).await.unwrap();
    scheduler.wait_idle().await;
    let mut got = Vec::new();
    while let Ok(name) = receive.try_recv() {
        got.push(name);
    }
    got.sort_unstable();
    let mut want = vec![
        "drain-outbound-hot",
        "dispatch-scheduled-actions",
        "scan-due-reminders",
        "retry-outbound-queue",
        "drain-journal-queue",
        "retry-journal-queue",
        "prune-ws-subscriptions",
        "prune-used-password-reset-tokens",
        "approval-expire-due",
        "health-check",
        "refresh-antiphish-contact-graph",
        "prune-auth-lockouts",
        "reset-sending-quotas",
        "prune-login-events",
        "prune-vacation-replies",
        "purge-expired-tokens",
    ];
    want.sort_unstable();
    assert_eq!(got, want);
    scheduler.shutdown().await.unwrap();
}

#[tokio::test]
async fn cron_stops_inflight_work_if_its_lock_connection_is_lost() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let separator = if dsn.contains('?') { '&' } else { '?' };
    let worker_dsn = format!("{dsn}{separator}application_name=gofree-t9-cron-lock-test");
    let db = WorkerDatabase::new(&worker_dsn).unwrap();
    let mut scheduler = CronScheduler::acquire(db.clone())
        .await
        .unwrap()
        .expect("scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    scheduler
        .register(
            "drain-outbound-hot",
            Arc::new(move || {
                let send = send.clone();
                Box::pin(async move {
                    send.send("started").unwrap();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    send.send("finished").unwrap();
                    Ok(())
                })
            }),
        )
        .unwrap();
    let running = tokio::spawn(scheduler.run_until(std::future::pending()));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), receive.recv())
            .await
            .unwrap(),
        Some("started")
    );
    let (admin, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let rows = admin.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", &[&"gofree-t9-cron-lock-test"]).await.unwrap();
    assert_eq!(rows.len(), 1);
    let pid: i32 = rows[0].get(0);
    let terminated: bool = admin
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(terminated);
    assert!(tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    assert_ne!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await
            .ok()
            .flatten(),
        Some("finished")
    );
    let next = db
        .try_cron_singleton()
        .await
        .unwrap()
        .expect("lock freed after connection loss");
    next.release().await.unwrap();
    drop(admin);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn cancelling_scheduler_cancels_its_jobs_before_another_can_run() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let db = WorkerDatabase::new(&dsn).unwrap();
    let mut scheduler = CronScheduler::acquire(db.clone())
        .await
        .unwrap()
        .expect("scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    scheduler
        .register(
            "drain-outbound-hot",
            Arc::new(move || {
                let send = send.clone();
                Box::pin(async move {
                    send.send("started").unwrap();
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    send.send("finished").unwrap();
                    Ok(())
                })
            }),
        )
        .unwrap();
    let running = tokio::spawn(scheduler.run_until(std::future::pending()));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), receive.recv())
            .await
            .unwrap(),
        Some("started")
    );
    running.abort();
    assert!(running.await.is_err());
    let next = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(lease) = db.try_cron_singleton().await.unwrap() {
                break lease;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("lock released");
    assert_ne!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await
            .ok()
            .flatten(),
        Some("finished")
    );
    next.release().await.unwrap();
}

#[tokio::test]
async fn shutdown_cancels_pending_work_before_releasing_the_singleton() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let db = WorkerDatabase::new(&dsn).unwrap();
    let mut scheduler = CronScheduler::acquire(db.clone())
        .await
        .unwrap()
        .expect("scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let finish = Arc::new(tokio::sync::Notify::new());
    let finish_action = finish.clone();
    scheduler
        .register(
            "drain-outbound-hot",
            Arc::new(move || {
                let send = send.clone();
                let finish = finish_action.clone();
                Box::pin(async move {
                    send.send("started").unwrap();
                    finish.notified().await;
                    send.send("finished").unwrap();
                    Ok(())
                })
            }),
        )
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut running = tokio::spawn(scheduler.run_until(async {
        stopped.await.unwrap();
    }));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), receive.recv())
            .await
            .unwrap(),
        Some("started")
    );
    assert!(db.try_cron_singleton().await.unwrap().is_none());
    stop.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), &mut running).await;
    let cancelled = result.is_ok();
    // Clean up even on the red path, without leaking the callback or its lock.
    match result {
        Ok(result) => result.unwrap().unwrap(),
        Err(_) => {
            finish.notify_one();
            running.await.unwrap().unwrap();
        }
    }
    let next = db
        .try_cron_singleton()
        .await
        .unwrap()
        .expect("shutdown released the singleton");
    next.release().await.unwrap();
    assert!(cancelled, "shutdown waited for uncancelled outbound work");
    finish.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receive.recv())
            .await
            .expect("shutdown left a callback running"),
        None,
        "cancelled work completed after singleton handover"
    );
}

#[tokio::test]
async fn a_tick_cannot_start_work_after_the_singleton_connection_dies() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let separator = if dsn.contains('?') { '&' } else { '?' };
    let worker_dsn = format!("{dsn}{separator}application_name=gofree-t9-manual-tick");
    let mut scheduler = CronScheduler::acquire(WorkerDatabase::new(&worker_dsn).unwrap())
        .await
        .unwrap()
        .expect("scheduler lock");
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    scheduler
        .register(
            "drain-outbound-hot",
            Arc::new(move || {
                let send = send.clone();
                Box::pin(async move {
                    let _ = send.send(());
                    Ok(())
                })
            }),
        )
        .unwrap();
    let (owner, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let rows = owner.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", &[&"gofree-t9-manual-tick"]).await.unwrap();
    assert_eq!(rows.len(), 1);
    let pid: i32 = rows[0].get(0);
    assert!(owner
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap()
        .get::<_, bool>(0));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(scheduler.tick(chrono::Local::now()).await.is_err());
    let admitted = tokio::time::timeout(Duration::from_millis(300), receive.recv()).await;
    drop(scheduler);
    drop(owner);
    connection.await.unwrap().unwrap();
    assert!(
        admitted.is_err(),
        "a tick ran after losing the singleton lock"
    );
}

#[tokio::test]
async fn session_refresh_replays_the_frozen_go_worker_oracle() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let (owner, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let mailbox_a: i64 = owner
        .query_one("SELECT mk_account('t9-rust-worker-a')", &[])
        .await
        .unwrap()
        .get(0);
    let mailbox_b: i64 = owner
        .query_one("SELECT mk_account('t9-rust-worker-b')", &[])
        .await
        .unwrap()
        .get(0);
    let user_a: i64 = owner
        .query_one("SELECT user_id FROM mailboxes WHERE id=$1", &[&mailbox_a])
        .await
        .unwrap()
        .get(0);
    let user_b: i64 = owner
        .query_one("SELECT user_id FROM mailboxes WHERE id=$1", &[&mailbox_b])
        .await
        .unwrap()
        .get(0);
    owner.execute("INSERT INTO session_revocations(user_id,scope,jti,family_id,reason,not_before,expires_at) VALUES \
        ($1,'jti','revoked-jti',NULL,'worker oracle',now()-interval '1 hour',now()+interval '1 hour'), \
        ($1,'family',NULL,'revoked-family','worker oracle',now()-interval '1 hour',now()+interval '1 hour'), \
        ($2,'all',NULL,NULL,'worker oracle',now()-interval '30 minutes',now()+interval '1 hour'), \
        ($1,'jti','expired-jti',NULL,'worker oracle',now()-interval '2 hours',now()-interval '1 hour')", &[&user_a, &user_b]).await.unwrap();
    let users = [user_a, user_b];
    let before = revocation_snapshot(&owner, &users).await;
    let bad_request = "postgres://postgres:gofree@127.0.0.1:1/gofree_t9?connect_timeout=1";
    let denylist =
        SessionDenylist::new(WorkerDatabase::from_dsns(bad_request, Some(&dsn)).unwrap());
    let closed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let now = chrono::Utc::now();
    let mut handles = Vec::new();
    for (name, user, issued, jti, family) in [
        ("jti", user_a, now, "revoked-jti", ""),
        ("family", user_a, now, "", "revoked-family"),
        ("expired", user_a, now, "expired-jti", ""),
        ("old", user_b, now - chrono::Duration::hours(1), "", ""),
        ("new", user_b, now, "", ""),
    ] {
        let closed = closed.clone();
        handles.push(denylist.register_session(
            user,
            issued,
            jti,
            family,
            Arc::new(move || closed.lock().unwrap().push(name.to_owned())),
        ));
    }
    denylist.refresh_once().await.unwrap();
    let mut closes = closed.lock().unwrap().clone();
    closes.sort();
    let got = serde_json::json!({
        "loaded": denylist.loaded(),
        "database_unchanged": before == revocation_snapshot(&owner, &users).await,
        "closed_sessions": closes,
        "revoked": {
            "jti": denylist.is_revoked(user_a, "revoked-jti", "", now),
            "family": denylist.is_revoked(user_a, "", "revoked-family", now),
            "expired": denylist.is_revoked(user_a, "expired-jti", "", now),
            "old": denylist.is_revoked(user_b, "", "", now - chrono::Duration::hours(1)),
            "new": denylist.is_revoked(user_b, "", "", now),
            "other_user": denylist.is_revoked(user_b, "revoked-jti", "revoked-family", now),
        }
    });
    drop(handles);
    owner.batch_execute(&format!("BEGIN; DELETE FROM session_revocations WHERE user_id IN ({user_a},{user_b}); DELETE FROM mailboxes WHERE id IN ({mailbox_a},{mailbox_b}); DELETE FROM users WHERE id IN ({user_a},{user_b}); COMMIT;")).await.unwrap();
    drop(owner);
    connection.await.unwrap().unwrap();
    let golden = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/go-session-refresh.json"
    ))
    .expect("frozen Go worker golden");
    let want: serde_json::Value = serde_json::from_str(&golden).unwrap();
    assert_eq!(got, want);
}

#[tokio::test]
async fn protocol_registry_remembers_revocations_after_snapshot_removal() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let (owner, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let mailbox: i64 = owner
        .query_one("SELECT mk_account('t9-protocol-memory')", &[])
        .await
        .unwrap()
        .get(0);
    let user: i64 = owner
        .query_one("SELECT user_id FROM mailboxes WHERE id=$1", &[&mailbox])
        .await
        .unwrap()
        .get(0);
    owner.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES ($1,'jti','previously-revoked','worker test',now(),now()+interval '1 hour')", &[&user]).await.unwrap();
    let denylist = SessionDenylist::new(WorkerDatabase::new(&dsn).unwrap());
    denylist.refresh_once().await.unwrap();
    owner
        .execute(
            "DELETE FROM session_revocations WHERE user_id=$1 AND jti='previously-revoked'",
            &[&user],
        )
        .await
        .unwrap();
    denylist.refresh_once().await.unwrap();
    let no_longer_in_denylist =
        !denylist.is_revoked(user, "previously-revoked", "", chrono::Utc::now());
    let (closed, mut events) = tokio::sync::mpsc::unbounded_channel();
    let _session = denylist.register_session(
        user,
        chrono::Utc::now(),
        "previously-revoked",
        "",
        Arc::new(move || {
            let _ = closed.send(());
        }),
    );
    let closed_by_registry = events.try_recv().is_ok();
    owner.batch_execute(&format!("BEGIN; DELETE FROM mailboxes WHERE id={mailbox}; DELETE FROM users WHERE id={user}; COMMIT;")).await.unwrap();
    drop(owner);
    connection.await.unwrap().unwrap();
    assert!(
        no_longer_in_denylist,
        "successful refresh replaces the denylist snapshot"
    );
    assert!(
        closed_by_registry,
        "Go's protocol registry retains the revocation until expiry"
    );
}

#[tokio::test]
async fn session_worker_applies_direct_notifications_to_open_sessions() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let direct = std::env::var("DB_DIRECT_DSN").expect("direct LISTEN connection");
    let denylist = Arc::new(SessionDenylist::new(WorkerDatabase::new(&dsn).unwrap()));
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let worker = tokio::spawn(denylist.clone().run(direct, async move {
        let _ = stopped.await;
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !denylist.loaded() || !denylist.listening() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker did not load");
    let (closed, mut events) = tokio::sync::mpsc::unbounded_channel();
    let issued = chrono::Utc::now() - chrono::Duration::hours(1);
    let _session = denylist.register_session(
        9_000_000_001,
        issued,
        "live-jti",
        "",
        Arc::new(move || {
            closed.send("closed").unwrap();
        }),
    );
    let now = chrono::Utc::now();
    let payload = serde_json::json!({"user_id": 9_000_000_001_i64, "scope":"jti", "jti":"live-jti", "not_before":now.to_rfc3339(), "expires_at":(now + chrono::Duration::hours(1)).to_rfc3339()}).to_string();
    let (sender, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    sender
        .query_one("SELECT pg_notify('session_revoke',$1)", &[&payload])
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap(),
        Some("closed")
    );
    assert!(denylist.is_revoked(9_000_000_001, "live-jti", "", issued));
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(sender);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn unavailable_direct_listener_never_falls_back_to_worker_connection() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let bad_direct = "postgres://postgres:gofree@127.0.0.1:1/gofree_t9?connect_timeout=1";
    let denylist = Arc::new(SessionDenylist::new(WorkerDatabase::new(&dsn).unwrap()));
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let worker = tokio::spawn(denylist.clone().run(bad_direct.to_owned(), async move {
        let _ = stopped.await;
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !denylist.loaded() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("worker refresh must continue even while direct LISTEN is down");
    let (closed, mut events) = tokio::sync::mpsc::unbounded_channel();
    let issued = chrono::Utc::now() - chrono::Duration::hours(1);
    let _session = denylist.register_session(
        9_000_000_002,
        issued,
        "direct-only",
        "",
        Arc::new(move || {
            let _ = closed.send(());
        }),
    );
    let now = chrono::Utc::now();
    let payload = serde_json::json!({"user_id": 9_000_000_002_i64, "scope":"jti", "jti":"direct-only", "not_before":now.to_rfc3339(), "expires_at":(now + chrono::Duration::hours(1)).to_rfc3339()}).to_string();
    let (sender, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    sender
        .query_one("SELECT pg_notify('session_revoke',$1)", &[&payload])
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(400), events.recv())
            .await
            .is_err()
    );
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(sender);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn listener_reconnect_repairs_revocations_missed_during_disconnect() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let direct = std::env::var("DB_DIRECT_DSN").expect("direct connection");
    let separator = if direct.contains('?') { '&' } else { '?' };
    let direct = format!("{direct}{separator}application_name=gofree-t9-reconnect-test");
    let (owner, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let mailbox: i64 = owner
        .query_one("SELECT mk_account('t9-reconnect')", &[])
        .await
        .unwrap()
        .get(0);
    let user: i64 = owner
        .query_one("SELECT user_id FROM mailboxes WHERE id=$1", &[&mailbox])
        .await
        .unwrap()
        .get(0);
    let denylist = Arc::new(SessionDenylist::new(WorkerDatabase::new(&dsn).unwrap()));
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let worker = tokio::spawn(denylist.clone().run(direct, async move {
        let _ = stopped.await;
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !denylist.loaded() || !denylist.listening() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("listener did not start");
    let (closed, mut events) = tokio::sync::mpsc::unbounded_channel();
    let _session = denylist.register_session(
        user,
        chrono::Utc::now(),
        "missed",
        "",
        Arc::new(move || {
            let _ = closed.send(());
        }),
    );
    let rows = owner.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", &[&"gofree-t9-reconnect-test"]).await.unwrap();
    assert_eq!(rows.len(), 1);
    let pid: i32 = rows[0].get(0);
    let terminated: bool = owner
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(terminated);
    tokio::time::timeout(Duration::from_secs(3), async {
        while denylist.listening() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("listener did not notice disconnect");
    owner.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES ($1,'jti','missed','reconnect test',now(),now()+interval '1 hour')", &[&user]).await.unwrap();
    let early = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .ok()
        .flatten();
    let _ = shutdown.send(());
    worker.await.unwrap().unwrap();
    owner.batch_execute(&format!("BEGIN; DELETE FROM session_revocations WHERE user_id={user}; DELETE FROM mailboxes WHERE id={mailbox}; DELETE FROM users WHERE id={user}; COMMIT;")).await.unwrap();
    drop(owner);
    connection.await.unwrap().unwrap();
    assert_eq!(early, Some(()), "reconnect must immediately repair missed revocations");

}

#[tokio::test]
async fn notification_watermarks_keep_go_nanosecond_precision() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let direct = std::env::var("DB_DIRECT_DSN").expect("direct connection");
    let denylist = Arc::new(SessionDenylist::new(WorkerDatabase::new(&dsn).unwrap()));
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let worker = tokio::spawn(denylist.clone().run(direct, async move {
        let _ = stopped.await;
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !denylist.loaded() || !denylist.listening() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (closed, mut events) = tokio::sync::mpsc::unbounded_channel();
    let base = chrono::Utc::now().with_nanosecond(0).unwrap();
    let issued = base + chrono::Duration::nanoseconds(123_456_900);
    let watermark = base + chrono::Duration::nanoseconds(123_456_700);
    let user = 9_000_000_003_i64;
    let _session = denylist.register_session(
        user,
        issued,
        "",
        "",
        Arc::new(move || {
            let _ = closed.send(());
        }),
    );
    let payload = |scope: &str, jti: &str, before: chrono::DateTime<chrono::Utc>| {
        serde_json::json!({"user_id":user,"scope":scope,"jti":jti,"not_before":before.to_rfc3339(),"expires_at":(base + chrono::Duration::hours(1)).to_rfc3339()}).to_string()
    };
    let (sender, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    sender
        .query_one(
            "SELECT pg_notify('session_revoke',$1)",
            &[&payload("all", "", watermark)],
        )
        .await
        .unwrap();
    sender
        .query_one(
            "SELECT pg_notify('session_revoke',$1)",
            &[&payload("jti", "marker", watermark)],
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !denylist.is_revoked(user, "marker", "", issued) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("notification marker");
    assert!(events.try_recv().is_err(), "newer session must stay open");
    assert!(!denylist.is_revoked(user, "", "", issued));
    sender
        .query_one(
            "SELECT pg_notify('session_revoke',$1)",
            &[&payload(
                "all",
                "",
                base + chrono::Duration::nanoseconds(123_457_000),
            )],
        )
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap(),
        Some(())
    );
    shutdown.send(()).unwrap();
    worker.await.unwrap().unwrap();
    drop(sender);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn failed_refresh_keeps_the_last_successful_revocation_snapshot() {
    let _serial = SERIAL.lock().await;
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let separator = if dsn.contains('?') { '&' } else { '?' };
    let worker_dsn = format!("{dsn}{separator}application_name=gofree-t9-refresh-failure");
    let (owner, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let mailbox: i64 = owner
        .query_one("SELECT mk_account('t9-refresh-failure')", &[])
        .await
        .unwrap()
        .get(0);
    let user: i64 = owner
        .query_one("SELECT user_id FROM mailboxes WHERE id=$1", &[&mailbox])
        .await
        .unwrap()
        .get(0);
    owner.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES ($1,'jti','retained','worker test',now(),now()+interval '1 hour')", &[&user]).await.unwrap();
    let denylist = Arc::new(SessionDenylist::new(
        WorkerDatabase::new(&worker_dsn).unwrap(),
    ));
    denylist.refresh_once().await.unwrap();
    assert!(denylist.is_revoked(user, "retained", "", chrono::Utc::now()));

    owner
        .batch_execute("BEGIN; LOCK TABLE session_revocations IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let refresh = tokio::spawn({
        let denylist = denylist.clone();
        async move { denylist.refresh_once().await }
    });
    let pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            owner.query_one("SELECT pg_stat_clear_snapshot()", &[]).await.unwrap();
            let rows = owner.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock'", &[&"gofree-t9-refresh-failure"]).await.unwrap();
            if let Some(row) = rows.first() { break row.get::<_, i32>(0); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("refresh did not block on the test lock");
    let terminated: bool = owner
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(terminated);
    owner.batch_execute("ROLLBACK").await.unwrap();
    assert!(refresh.await.unwrap().is_err());
    let retained =
        denylist.loaded() && denylist.is_revoked(user, "retained", "", chrono::Utc::now());
    owner.batch_execute(&format!("BEGIN; DELETE FROM session_revocations WHERE user_id={user}; DELETE FROM mailboxes WHERE id={mailbox}; DELETE FROM users WHERE id={user}; COMMIT;")).await.unwrap();
    drop(owner);
    connection.await.unwrap().unwrap();
    assert!(
        retained,
        "a failed refresh must not resurrect a revoked token"
    );
}
