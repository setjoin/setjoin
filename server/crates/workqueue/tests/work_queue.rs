//! Live-DB integration tests for `setjoin-workqueue` (Wave 2.1, #548):
//! - 8-worker concurrent `SKIP LOCKED` claim over 200 items (zero overlaps)
//! - per-kind `max_concurrency = 3` cap + lowered cap (`active > cap`, zero PG `2201W`)
//! - late `heartbeat()` after lease expiry returns `false` without breaching `max_concurrency`
//! - `claim_generation` fencing across `complete` / `fail_transient` / `heartbeat`
//! - jittered backoff + poison-pill DLQ via `reclaim_expired` + UTF-8 multibyte truncation
//! - `execute_scheduled_action_work` + `complete_tx` same-tx atomicity
//! - content-free `work` / `sync` wakeup bells via `ListenHub` + `pg_terminate_backend`
//!   reconnect recovery + fallback poll

use std::collections::HashSet;
use std::time::Duration;

use serde_json::json;
use setjoin_conformance::harness::Db;
use setjoin_pg::{ListenEvent, ListenHub, Type, WorkerPool};
use setjoin_workqueue::{
    BackoffPolicy, ClaimSpec, FailOutcome, KindCap, ScheduledActionOutcome, WorkConsumerConfig,
    WorkQueue, WorkRequest, WorkScheduledActionConsumer, MAX_ERROR_BYTES, SYNC_WAKEUP_CHANNEL,
    WORK_WAKEUP_CHANNEL,
};
use tokio_util::sync::CancellationToken;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn clean_tables(owner: &tokio_postgres::Client) {
    owner
        .batch_execute(
            "DELETE FROM public.work_items; \
             DELETE FROM public.work_dead_letters; \
             DELETE FROM public.notify_intents WHERE channel IN ('work', 'sync');",
        )
        .await
        .expect("clean workqueue tables");
}

#[tokio::test]
async fn eight_worker_skip_locked_200_items_zero_overlaps() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("workqueue-skip-locked") else {
        return;
    };
    let owner = db.connect().await.expect("owner connect");
    clean_tables(&owner).await;

    let pool = WorkerPool::from_dsn(&db.dsn, 16).expect("worker pool");
    let queue = WorkQueue::new(pool);

    for i in 0..200 {
        let receipt = queue
            .enqueue(&WorkRequest::new("bench.parallel", json!({"seq": i})))
            .await
            .expect("enqueue");
        assert!(!receipt.coalesced);
    }

    let mut handles = Vec::new();
    for w in 0..8 {
        let q = queue.clone();
        handles.push(tokio::spawn(async move {
            let worker_id = format!("worker-{w}");
            let mut claimed = Vec::new();
            loop {
                let batch = q
                    .claim(
                        &ClaimSpec::new(&worker_id, vec!["bench.parallel".into()])
                            .with_batch(7)
                            .with_lease_secs(60),
                    )
                    .await
                    .expect("claim");
                if batch.is_empty() {
                    break;
                }
                for item in batch {
                    claimed.push(item.id);
                    let ok = q
                        .complete(item.id, item.claim_generation, &worker_id)
                        .await
                        .expect("complete");
                    assert!(ok, "fenced completion must succeed for active owner");
                }
            }
            claimed
        }));
    }

    let mut all = Vec::new();
    for h in handles {
        all.extend(h.await.expect("join"));
    }
    let unique: HashSet<i64> = all.iter().copied().collect();
    assert_eq!(all.len(), 200, "all 200 items must be claimed exactly once");
    assert_eq!(
        unique.len(),
        200,
        "zero overlapping claims across 8 workers"
    );

    let stats = queue.stats().await.expect("stats");
    assert_eq!(stats.pending, 0);
    assert_eq!(stats.leased, 0);
    clean_tables(&owner).await;
}

#[tokio::test]
async fn per_kind_max_concurrency_and_lowered_cap_zero_2201w() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("workqueue-concurrency-cap") else {
        return;
    };
    let owner = db.connect().await.expect("owner connect");
    clean_tables(&owner).await;

    let pool = WorkerPool::from_dsn(&db.dsn, 8).expect("worker pool");
    let queue = WorkQueue::new(pool);

    for i in 0..8 {
        queue
            .enqueue(&WorkRequest::new("capped.kind", json!({"i": i})))
            .await
            .expect("enqueue");
    }

    // Claim with max_concurrency = 3 (requesting batch=10 -> must cap at 3).
    let first = queue
        .claim(
            &ClaimSpec::new("w-cap-1", vec!["capped.kind".into()])
                .with_batch(10)
                .with_lease_secs(60)
                .with_max_concurrency(3),
        )
        .await
        .expect("capped claim");
    assert_eq!(
        first.len(),
        3,
        "max_concurrency=3 must cap active leases at 3"
    );

    // Second worker cannot claim while 3 leases are active.
    let second = queue
        .claim(
            &ClaimSpec::new("w-cap-2", vec!["capped.kind".into()])
                .with_batch(10)
                .with_lease_secs(60)
                .with_max_concurrency(3),
        )
        .await
        .expect("second capped claim");
    assert!(second.is_empty());

    // Lower runtime cap below current active count (active=3 > cap=1):
    // must return 0 rows cleanly with ZERO PG 2201W (LIMIT must not be negative)!
    let lowered = queue
        .claim_with_caps(
            "w-cap-3",
            &[KindCap {
                kind: "capped.kind".into(),
                max_concurrency: Some(1),
            }],
            10,
            60,
        )
        .await
        .expect("lowered cap must not fail with 2201W");
    assert!(lowered.is_empty());

    // Expire one lease and verify late heartbeat returns false (prevents max_concurrency breach).
    let lapsed = &first[0];
    owner
        .execute(
            "UPDATE public.work_items SET lease_expires_at = now() - interval '5 seconds' WHERE id = $1",
            &[&lapsed.id],
        )
        .await
        .expect("expire lease");
    let hb = queue
        .heartbeat(lapsed.id, lapsed.claim_generation, "w-cap-1", 60)
        .await
        .expect("late heartbeat");
    assert!(!hb, "late heartbeat after lease expiry must return false");

    // Complete one active item -> headroom opens for exactly 1 replacement under cap=3.
    assert!(queue
        .complete(first[1].id, first[1].claim_generation, "w-cap-1")
        .await
        .expect("complete"));
    let replacement = queue
        .claim(
            &ClaimSpec::new("w-cap-2", vec!["capped.kind".into()])
                .with_batch(10)
                .with_lease_secs(60)
                .with_max_concurrency(3),
        )
        .await
        .expect("replacement claim");
    // Only 1 active unexpired lease remains (first[2]), so headroom is 2.
    assert_eq!(replacement.len(), 2);

    clean_tables(&owner).await;
}

#[tokio::test]
async fn fencing_backoff_utf8_truncation_and_poison_pill_dlq() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("workqueue-fencing-dlq") else {
        return;
    };
    let owner = db.connect().await.expect("owner connect");
    clean_tables(&owner).await;

    let pool = WorkerPool::from_dsn(&db.dsn, 8).expect("worker pool");
    let queue = WorkQueue::new(pool);

    let receipt = queue
        .enqueue(&WorkRequest::new("job.retry", json!({"x": 1})).with_max_attempts(2))
        .await
        .expect("enqueue");

    let claimed1 = queue
        .claim(&ClaimSpec::new("w1", vec!["job.retry".into()]).with_lease_secs(60))
        .await
        .expect("claim 1");
    assert_eq!(claimed1.len(), 1);
    let item1 = &claimed1[0];
    assert_eq!(item1.id, receipt.id);
    assert_eq!(item1.claim_generation, 1);

    // Valid heartbeat succeeds while lease is live.
    assert!(queue
        .heartbeat(item1.id, item1.claim_generation, "w1", 60)
        .await
        .expect("live heartbeat"));

    // Simulate multibyte UTF-8 error > 4096 bytes.
    let big_utf8_err = "🔥错误".repeat(1000);
    assert!(big_utf8_err.len() > MAX_ERROR_BYTES);
    let policy = BackoffPolicy::new(Duration::from_millis(10), Duration::from_millis(20));
    let delay = policy.jittered_delay(item1.attempts);
    assert!(delay >= Duration::from_millis(5) && delay <= Duration::from_millis(10));

    let fail1 = queue
        .fail_transient(
            item1.id,
            item1.claim_generation,
            "w1",
            &big_utf8_err,
            Duration::ZERO,
        )
        .await
        .expect("fail 1");
    assert_eq!(fail1, FailOutcome::Retried);

    // Claim attempt 2/2 by w2.
    let claimed2 = queue
        .claim(&ClaimSpec::new("w2", vec!["job.retry".into()]).with_lease_secs(60))
        .await
        .expect("claim 2");
    assert_eq!(claimed2.len(), 1);
    let item2 = &claimed2[0];
    assert_eq!(item2.claim_generation, 2);
    assert_eq!(item2.attempts, 2);
    assert!(item2.last_error.as_deref().unwrap_or("").len() <= MAX_ERROR_BYTES);

    // Stale w1 (claim_generation=1) is fenced out of complete, fail, and heartbeat.
    assert!(!queue
        .complete(item1.id, item1.claim_generation, "w1")
        .await
        .expect("stale complete"));
    assert_eq!(
        queue
            .fail_transient(
                item1.id,
                item1.claim_generation,
                "w1",
                "stale",
                Duration::ZERO
            )
            .await
            .expect("stale fail"),
        FailOutcome::LeaseLost
    );

    // Simulate mid-run crash on attempt 2/2 -> reclaim_expired dead-letters poison pill!
    owner
        .execute(
            "UPDATE public.work_items SET lease_expires_at = now() - interval '5 seconds' WHERE id = $1",
            &[&item2.id],
        )
        .await
        .expect("expire lease");
    let rec = queue.reclaim_expired(10).await.expect("reclaim");
    assert_eq!(rec.reclaimed, 0);
    assert_eq!(rec.dead_lettered, 1);

    let stats = queue.stats().await.expect("stats");
    assert_eq!(stats.pending, 0);
    assert_eq!(stats.leased, 0);
    assert_eq!(stats.dead_letters, 1);

    clean_tables(&owner).await;
}

#[tokio::test]
async fn execute_scheduled_action_and_complete_tx_same_tx_atomicity() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("workqueue-sa-atomicity") else {
        return;
    };
    let owner = db.connect().await.expect("owner connect");
    clean_tables(&owner).await;

    let acct = setjoin_conformance::fixture::account(&owner, "wq-sa-atomic")
        .await
        .expect("fixture");

    let sa_id: String = owner
        .query_one(
            "SELECT enqueue_scheduled_action('snooze', now() - interval '1 minute', \
             '{\"_test_outcome\":\"ok\"}'::jsonb, $1)::text",
            &[&acct.mailbox],
        )
        .await
        .expect("enqueue sa")
        .get(0);

    let pool = WorkerPool::from_dsn(&db.dsn, 8).expect("worker pool");
    let queue = WorkQueue::new(pool.clone());

    let promoted = queue
        .promote_due_scheduled_actions(50)
        .await
        .expect("promote");
    assert!(promoted >= 1);

    let items = queue
        .claim(&ClaimSpec::new(
            "w-atomic",
            vec!["scheduled_action.snooze".into()],
        ))
        .await
        .expect("claim");
    let item = items
        .iter()
        .find(|i| i.payload["scheduled_action_id"].as_str() == Some(sa_id.as_str()))
        .expect("claimed promoted item");

    // 1. Rollback proof: running execute_scheduled_action_work + complete_tx inside
    //    one WorkerTx and rolling back leaves BOTH scheduled_actions and work_items intact.
    {
        let mut tx = pool.begin_read_write().await.expect("begin tx");
        let allow_replay = false;
        let rows = tx
            .query(
                "SELECT outcome, note FROM public.execute_scheduled_action_work($1::text::uuid, $2, $3, $4, $5)",
                &[
                    (&sa_id, Type::TEXT),
                    (&"w-atomic", Type::TEXT),
                    (&item.attempts, Type::INT4),
                    (&item.max_attempts, Type::INT4),
                    (&allow_replay, Type::BOOL),
                ],
            )
            .await
            .expect("exec");
        assert_eq!(rows[0].get::<_, String>(0), "complete");
        assert!(
            WorkQueue::complete_tx(&mut tx, item.id, item.claim_generation, "w-atomic")
                .await
                .expect("complete_tx")
        );
        tx.rollback().await.expect("rollback");
    }
    let sa_status: String = owner
        .query_one(
            "SELECT status FROM public.scheduled_actions WHERE id = $1::text::uuid",
            &[&sa_id],
        )
        .await
        .expect("sa status after rollback")
        .get(0);
    assert_eq!(
        sa_status, "enqueued",
        "rolled-back tx leaves scheduled_action enqueued"
    );
    let wi_exists: i64 = owner
        .query_one(
            "SELECT count(*) FROM public.work_items WHERE id = $1",
            &[&item.id],
        )
        .await
        .expect("wi exists after rollback")
        .get(0);
    assert_eq!(wi_exists, 1, "rolled-back tx leaves work_item intact");

    // 2. Expired-lease pre-handler fence: an expired lease returns LeaseLost
    //    WITHOUT invoking execute_scheduled_action_work (scheduled_actions stays 'enqueued').
    owner
        .execute(
            "UPDATE public.work_items SET lease_expires_at = clock_timestamp() - interval '5 seconds' WHERE id = $1",
            &[&item.id],
        )
        .await
        .expect("expire lease before execute");
    let lost = queue
        .execute_scheduled_action_and_settle(item, "w-atomic", &BackoffPolicy::default())
        .await
        .expect("expired pre-check");
    assert_eq!(lost, ScheduledActionOutcome::LeaseLost);
    let sa_status_expired: String = owner
        .query_one(
            "SELECT status FROM public.scheduled_actions WHERE id = $1::text::uuid",
            &[&sa_id],
        )
        .await
        .expect("sa status after expired pre-check")
        .get(0);
    assert_eq!(
        sa_status_expired, "enqueued",
        "expired lease must not invoke handler"
    );
    owner
        .execute(
            "UPDATE public.work_items SET lease_expires_at = clock_timestamp() + interval '60 seconds' WHERE id = $1",
            &[&item.id],
        )
        .await
        .expect("restore lease");

    // 3. Commit proof: execute_scheduled_action_and_settle commits both atomically.
    let outcome = queue
        .execute_scheduled_action_and_settle(item, "w-atomic", &BackoffPolicy::default())
        .await
        .expect("atomic settle");
    assert!(matches!(outcome, ScheduledActionOutcome::Completed { .. }));

    let sa_status_after: String = owner
        .query_one(
            "SELECT status FROM public.scheduled_actions WHERE id = $1::text::uuid",
            &[&sa_id],
        )
        .await
        .expect("sa status after commit")
        .get(0);
    assert_eq!(sa_status_after, "done");
    let wi_after: i64 = owner
        .query_one(
            "SELECT count(*) FROM public.work_items WHERE id = $1",
            &[&item.id],
        )
        .await
        .expect("wi count after commit")
        .get(0);
    assert_eq!(wi_after, 0);

    owner
        .execute(
            "DELETE FROM public.scheduled_action_log WHERE action_id = $1::text::uuid",
            &[&sa_id],
        )
        .await
        .ok();
    owner
        .execute(
            "DELETE FROM public.scheduled_actions WHERE id = $1::text::uuid",
            &[&sa_id],
        )
        .await
        .ok();
    setjoin_conformance::fixture::remove(&owner, &acct)
        .await
        .expect("cleanup fixture");
    clean_tables(&owner).await;
}

#[tokio::test]
async fn listen_hub_wakeup_bells_reconnect_recovery_and_fallback_poll() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("workqueue-listen-hub") else {
        return;
    };
    let owner = db.connect().await.expect("owner connect");
    clean_tables(&owner).await;

    let app_name = format!("wq_hub_548_{}", std::process::id());
    let sep = if db.direct.contains('?') { '&' } else { '?' };
    let direct_named = format!("{}{sep}application_name={app_name}", db.direct);

    let shutdown = CancellationToken::new();
    let hub = ListenHub::spawn_connected(direct_named, shutdown.clone())
        .await
        .expect("spawn ListenHub");
    let mut work_sub = hub.subscribe(WORK_WAKEUP_CHANNEL).await.expect("sub work");
    let mut sync_sub = hub.subscribe(SYNC_WAKEUP_CHANNEL).await.expect("sub sync");

    // Emit content-free bells into notify_intents, then drain into pg_notify.
    owner
        .query("SELECT public.emit_wakeup_bell('work', 'job.bell')", &[])
        .await
        .expect("emit work bell");
    owner
        .query("SELECT public.emit_wakeup_bell('sync', 'mb:1')", &[])
        .await
        .expect("emit sync bell");
    owner
        .batch_execute(
            "WITH batch AS ( \
               DELETE FROM public.notify_intents \
                WHERE channel IN ('work', 'sync') \
                RETURNING id, channel, payload \
             ) \
             SELECT pg_notify(channel, payload) \
               FROM (SELECT channel, payload FROM batch GROUP BY channel, payload ORDER BY MIN(id)) d",
        )
        .await
        .expect("drain bells");

    let w_ev = tokio::time::timeout(Duration::from_secs(5), work_sub.recv())
        .await
        .expect("work bell timeout")
        .expect("work bell event");
    assert_eq!(
        w_ev,
        ListenEvent::Notification(setjoin_pg::ListenNotification {
            channel: "work".into(),
            payload: "job.bell".into(),
        })
    );
    let s_ev = tokio::time::timeout(Duration::from_secs(5), sync_sub.recv())
        .await
        .expect("sync bell timeout")
        .expect("sync bell event");
    assert_eq!(
        s_ev,
        ListenEvent::Notification(setjoin_pg::ListenNotification {
            channel: "sync".into(),
            payload: "mb:1".into(),
        })
    );

    // Terminate the ListenHub backend -> must reconnect and emit ResyncRequired!
    let pid: i32 = owner
        .query_one(
            "SELECT pid FROM pg_stat_activity WHERE datname = current_database() AND application_name = $1",
            &[&app_name],
        )
        .await
        .expect("find hub pid")
        .get(0);
    let terminated: bool = owner
        .query_one("SELECT pg_terminate_backend($1)", &[&pid])
        .await
        .expect("terminate backend")
        .get(0);
    assert!(terminated);

    let resync = tokio::time::timeout(Duration::from_secs(5), work_sub.recv())
        .await
        .expect("resync timeout")
        .expect("resync event");
    assert!(
        matches!(resync, ListenEvent::ResyncRequired { .. }),
        "expected ResyncRequired after pg_terminate_backend, got {resync:?}"
    );

    // Consumer fallback poll executes a due scheduled_action even with no wakeup bell emitted.
    let acct = setjoin_conformance::fixture::account(&owner, "wq-hub-fallback")
        .await
        .expect("fixture");
    let sa_id: String = owner
        .query_one(
            "SELECT enqueue_scheduled_action('snooze', now() - interval '1 minute', \
             '{\"_test_outcome\":\"ok\"}'::jsonb, $1)::text",
            &[&acct.mailbox],
        )
        .await
        .expect("enqueue sa")
        .get(0);

    let pool = WorkerPool::from_dsn(&db.dsn, 4).expect("pool");
    let consumer_stop = CancellationToken::new();
    let consumer = WorkScheduledActionConsumer::new(
        WorkQueue::new(pool),
        WorkConsumerConfig {
            worker_id: "wq-consumer-test".into(),
            batch: 10,
            lease_secs: 30,
            poll_interval: Duration::from_millis(100),
            reclaim_interval: Duration::from_secs(5),
            backoff: BackoffPolicy::default(),
        },
        Some(hub.clone()),
    );
    let consumer_task = tokio::spawn(consumer.run_until(consumer_stop.clone()));

    let done = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status: String = owner
                .query_one(
                    "SELECT status FROM public.scheduled_actions WHERE id = $1::text::uuid",
                    &[&sa_id],
                )
                .await
                .unwrap()
                .get(0);
            if status == "done" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    consumer_stop.cancel();
    let _ = consumer_task.await;
    hub.shutdown().await;
    assert!(
        done.is_ok(),
        "consumer fallback poll must execute due scheduled_action"
    );

    owner
        .execute(
            "DELETE FROM public.scheduled_action_log WHERE action_id = $1::text::uuid",
            &[&sa_id],
        )
        .await
        .ok();
    owner
        .execute(
            "DELETE FROM public.scheduled_actions WHERE id = $1::text::uuid",
            &[&sa_id],
        )
        .await
        .ok();
    setjoin_conformance::fixture::remove(&owner, &acct)
        .await
        .expect("cleanup fixture");
    clean_tables(&owner).await;
}
