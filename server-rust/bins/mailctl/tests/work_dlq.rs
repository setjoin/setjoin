//! Live-DB integration tests for `mailctl work` / `mailctl workq` DLQ CLI
//! commands (Wave 2.1, #548):
//! - `workq stats --json`
//! - `workq dlq list`, `inspect`, `replay` (single, batch, active idempotency
//!   conflict refusal, `--reset-idempotency`, concurrent `FOR UPDATE` double-replay
//!   safety, `--force` refusal on `'done'` scheduled action), `purge`.

use std::process::Command;
use std::sync::Arc;

use serde_json::Value;

fn dsn() -> Option<String> {
    if let Ok(v) = std::env::var("TEST_DB_DSN").or_else(|_| std::env::var("DB_DSN")) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    if std::env::var("REQUIRE_DB").as_deref() == Ok("1") {
        panic!("REQUIRE_DB=1 but TEST_DB_DSN / DB_DSN is unset");
    }
    eprintln!("MAILCTL-WORK-DLQ-SKIP (reason=no-dsn)");
    None
}

fn mailctl(dsn: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mailctl"))
        .env_clear()
        .env("DB_DSN", dsn)
        .args(args)
        .output()
        .expect("run mailctl")
}

#[test]
fn mailctl_workq_dlq_list_inspect_replay_conflicts_and_purge() {
    let Some(dsn) = dsn() else {
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let conn = setjoin_pg::operator::OperatorConnection::connect(&dsn)
            .await
            .expect("connect");
        conn.batch("DELETE FROM public.work_items; DELETE FROM public.work_dead_letters;")
            .await
            .expect("clean");

        // Enqueue, claim, and permanently dead-letter an item with idempotency_key.
        let rows = conn
            .query(
                "SELECT work_item_id FROM public.work_enqueue('cli.test', '{\"hello\":\"world\"}'::jsonb, 'cli-idem-1', now(), 0::smallint, 3)",
                &[],
            )
            .await
            .expect("enqueue");
        let wi_id: i64 = rows[0].get(0);
        let claimed = conn
            .query(
                "SELECT id, claim_generation FROM public.work_queue_claim('cli-w', ARRAY['cli.test'], 1, 60, NULL)",
                &[],
            )
            .await
            .expect("claim");
        assert_eq!(claimed[0].get::<_, i64>(0), wi_id);
        let gen: i32 = claimed[0].get(1);
        let failed = conn
            .query(
                "SELECT dead_letter_id FROM public.work_queue_fail($1, $2, 'cli-w', 'boom-cli', NULL, TRUE)",
                &[(&wi_id, setjoin_pg::Type::INT8), (&gen, setjoin_pg::Type::INT4)],
            )
            .await
            .expect("fail");
        let dlq_id: i64 = failed[0].get(0);

        // 1. stats --json
        let out = mailctl(&dsn, &["workq", "stats", "--json"]);
        assert!(out.status.success(), "stats stderr: {}", String::from_utf8_lossy(&out.stderr));
        let stats: Value = serde_json::from_slice(&out.stdout).expect("stats json");
        assert_eq!(stats["dead_letters"], 1);

        // 2. dlq list --json
        let out = mailctl(&dsn, &["workq", "dlq", "list", "--kind", "cli.test", "--json"]);
        assert!(out.status.success(), "list stderr: {}", String::from_utf8_lossy(&out.stderr));
        let listed: Value = serde_json::from_slice(&out.stdout).expect("list json");
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["id"], dlq_id);

        // 3. dlq inspect <id> --json
        let id_arg = dlq_id.to_string();
        let out = mailctl(&dsn, &["workq", "dlq", "inspect", &id_arg, "--json"]);
        assert!(out.status.success(), "inspect stderr: {}", String::from_utf8_lossy(&out.stderr));
        let inspected: Value = serde_json::from_slice(&out.stdout).expect("inspect json");
        assert_eq!(inspected["last_error"], "boom-cli");
        assert_eq!(inspected["payload"]["hello"], "world");

        // 4. Active idempotency_key conflict refusal (must NOT silently mark replayed_at).
        conn.query(
            "SELECT work_item_id FROM public.work_enqueue('cli.test', '{\"active\":true}'::jsonb, 'cli-idem-1', now(), 0::smallint, 3)",
            &[],
        )
        .await
        .expect("seed active conflict");
        let conflict = mailctl(&dsn, &["workq", "dlq", "replay", &id_arg]);
        assert!(!conflict.status.success(), "active idempotency_key conflict must abort");
        assert!(
            String::from_utf8_lossy(&conflict.stderr).contains("--reset-idempotency"),
            "stderr: {}",
            String::from_utf8_lossy(&conflict.stderr)
        );
        // Verify replayed_at is still NULL.
        let check = mailctl(&dsn, &["workq", "dlq", "inspect", &id_arg, "--json"]);
        let inspected2: Value = serde_json::from_slice(&check.stdout).unwrap();
        assert!(inspected2["replayed_at"].is_null());

        // 5. Concurrent replay with --reset-idempotency: exactly ONE wins (FOR UPDATE).
        let dsn_arc = Arc::new(dsn.clone());
        let id_arc = Arc::new(id_arg.clone());
        let mut threads = Vec::new();
        for _ in 0..4 {
            let d = dsn_arc.clone();
            let id = id_arc.clone();
            threads.push(std::thread::spawn(move || {
                mailctl(&d, &["workq", "dlq", "replay", "--reset-idempotency", "--json", &id])
            }));
        }
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let successes = results.iter().filter(|o| o.status.success()).count();
        assert_eq!(
            successes, 1,
            "concurrent FOR UPDATE replay must allow exactly one winner, got {successes}"
        );

        // 6. Reject combining positional <id> with --kind on purge, then purge replayed item.
        let bad_purge = mailctl(
            &dsn,
            &["workq", "dlq", "purge", "--yes", "--kind", "cli.test", &id_arg],
        );
        assert!(
            !bad_purge.status.success(),
            "combining <id> with --kind on purge must fail"
        );
        for bad_args in [
            vec!["workq", "dlq", "purge", "--yes", "--kind", ""],
            vec!["workq", "dlq", "purge", "--yes", "--kind="],
            vec!["workq", "dlq", "purge", "--yes", "--older-than-days", ""],
            vec!["workq", "dlq", "purge", "--yes", "--older-than-days="],
        ] {
            let empty_flag = mailctl(&dsn, &bad_args);
            assert!(
                !empty_flag.status.success(),
                "empty flag value must fail for {bad_args:?}"
            );
        }
        // Also verify concurrent --force --reset-idempotency while prior replay item is still active fails.
        let force_dup = mailctl(
            &dsn,
            &["workq", "dlq", "replay", "--force", "--reset-idempotency", &id_arg],
        );
        assert!(
            !force_dup.status.success(),
            "--force --reset-idempotency must refuse while previous replay work item is still active"
        );

        let purge = mailctl(&dsn, &["workq", "dlq", "purge", "--yes", "--json", &id_arg]);
        assert!(purge.status.success(), "purge stderr: {}", String::from_utf8_lossy(&purge.stderr));
        let purged: Value = serde_json::from_slice(&purge.stdout).expect("purge json");
        assert_eq!(purged["purged"], 1);

        // 7. Scheduled action 'done' refusal even with --force.
        let mb: i64 = conn
            .query("SELECT mk_account('mailctl-workq-done')", &[])
            .await
            .expect("mk_account")[0]
            .get(0);
        let sa_id: String = conn
            .query(
                "SELECT enqueue_scheduled_action('snooze', now() - interval '1 minute', '{\"_test_outcome\":\"ok\"}'::jsonb, $1)::text",
                &[(&mb, setjoin_pg::Type::INT8)],
            )
            .await
            .expect("enqueue sa")[0]
            .get(0);
        conn.query(
            "UPDATE public.scheduled_actions SET status = 'done' WHERE id = $1::text::uuid",
            &[(&sa_id, setjoin_pg::Type::TEXT)],
        )
        .await
        .expect("mark done");
        let dlq_done: i64 = conn
            .query(
                "INSERT INTO public.work_dead_letters (work_item_id, kind, payload, idempotency_key, attempts, max_attempts, last_error, enqueued_at) \
                 VALUES (999999, 'scheduled_action.snooze', jsonb_build_object('scheduled_action_id', $1::text), 'sa-done-idem', 5, 5, 'old err', now()) \
                 RETURNING id",
                &[(&sa_id, setjoin_pg::Type::TEXT)],
            )
            .await
            .expect("insert done dlq")[0]
            .get(0);
        let done_id_arg = dlq_done.to_string();
        let refused = mailctl(
            &dsn,
            &["work", "dlq", "replay", "--force", "--reset-idempotency", &done_id_arg],
        );
        assert!(
            !refused.status.success(),
            "--force must refuse replay of already-done scheduled_action"
        );
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("refusing to replay"),
            "stderr: {}",
            String::from_utf8_lossy(&refused.stderr)
        );

        // 8. Poison-pill scheduled_action expiry reclaim -> DLQ -> mailctl work dlq replay succeeds!
        let sa_pp: String = conn
            .query(
                "SELECT enqueue_scheduled_action('snooze', now() - interval '1 minute', '{\"_test_outcome\":\"ok\"}'::jsonb, $1)::text",
                &[(&mb, setjoin_pg::Type::INT8)],
            )
            .await
            .expect("enqueue poison-pill sa")[0]
            .get(0);
        conn.query("SELECT public.promote_due_scheduled_actions(50)", &[])
            .await
            .expect("promote");
        let claimed_pp = conn
            .query(
                "SELECT id FROM public.work_queue_claim('cli-pp', ARRAY['scheduled_action.snooze'], 10, 60, NULL) \
                 WHERE payload->>'scheduled_action_id' = $1",
                &[(&sa_pp, setjoin_pg::Type::TEXT)],
            )
            .await
            .expect("claim pp");
        let wi_pp: i64 = claimed_pp[0].get(0);
        conn.query(
            "UPDATE public.work_items SET attempts = max_attempts, lease_expires_at = now() - interval '5 seconds' WHERE id = $1",
            &[(&wi_pp, setjoin_pg::Type::INT8)],
        )
        .await
        .expect("expire pp");
        conn.query("SELECT * FROM public.work_queue_reclaim_expired(10)", &[])
            .await
            .expect("reclaim pp");
        let dlq_pp: i64 = conn
            .query(
                "SELECT id FROM public.work_dead_letters WHERE work_item_id = $1",
                &[(&wi_pp, setjoin_pg::Type::INT8)],
            )
            .await
            .expect("find pp dlq")[0]
            .get(0);
        let pp_id_arg = dlq_pp.to_string();
        let pp_replay = mailctl(&dsn, &["work", "dlq", "replay", "--json", &pp_id_arg]);
        assert!(
            pp_replay.status.success(),
            "poison-pill scheduled_action replay must succeed, stderr: {}",
            String::from_utf8_lossy(&pp_replay.stderr)
        );
        let sa_pp_status: String = conn
            .query(
                "SELECT status FROM public.scheduled_actions WHERE id = $1::text::uuid",
                &[(&sa_pp, setjoin_pg::Type::TEXT)],
            )
            .await
            .expect("sa pp status")[0]
            .get(0);
        assert_eq!(sa_pp_status, "enqueued");

        // Clean up.
        conn.query(
            "DELETE FROM public.scheduled_action_log WHERE action_id IN ($1::text::uuid, $2::text::uuid)",
            &[(&sa_id, setjoin_pg::Type::TEXT), (&sa_pp, setjoin_pg::Type::TEXT)],
        )
        .await
        .ok();
        conn.query(
            "DELETE FROM public.scheduled_actions WHERE id IN ($1::text::uuid, $2::text::uuid)",
            &[(&sa_id, setjoin_pg::Type::TEXT), (&sa_pp, setjoin_pg::Type::TEXT)],
        )
        .await
        .ok();
        conn.batch("DELETE FROM public.work_items; DELETE FROM public.work_dead_letters;")
            .await
            .ok();
    });
}
