//! #407: the Rust cron catalog equals frozen Go's `AllTasks()`, every task is
//! guarded by `GO_WORKERS_OFF`, and credentials split per task.
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use setjoin_gateway::cron_catalog::{
    credential, cron_action, drain_rust_operation_receipts, register_cron_tasks, Credential,
    CronDatabases, CATALOG, PRUNE_RECEIPTS_TASK,
};
use setjoin_gateway::workers::{go_task_spec, CronScheduler};
use setjoin_pg::workers::WorkerDatabase;
use std::time::Duration;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct GoTask {
    name: String,
    schedule: String,
    sql: String,
    seconds: u64,
}

/// Parse Go's registry literal lines straight from the frozen source, so any
/// change to `AllTasks()` (add, remove, edit) fails this test until Rust follows.
fn go_tasks() -> Vec<GoTask> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../mailserver/internal/cron/tasks.go");
    let source = std::fs::read_to_string(path).expect("tasks.go");
    let field = |line: &str, key: &str| -> String {
        let start = line.find(key).unwrap_or_else(|| panic!("{key} in {line}")) + key.len();
        let rest = &line[start..];
        let quote = rest.chars().next().unwrap();
        assert!(quote == '"' || quote == '`', "{line}");
        let body = &rest[1..];
        body[..body.find(quote).unwrap()].to_string()
    };
    source
        .lines()
        .filter(|l| l.trim_start().starts_with("{Name: \""))
        .map(|line| {
            assert!(line.contains("enabled: true}"), "disabled task: {line}");
            let timeout = line
                .split("Timeout: ")
                .nth(1)
                .unwrap()
                .split(" * time.Second")
                .next()
                .unwrap();
            GoTask {
                name: field(line, "Name: "),
                schedule: field(line, "Schedule: "),
                sql: field(line, "SQL: "),
                seconds: timeout.parse().unwrap(),
            }
        })
        .collect()
}

#[test]
fn catalog_equals_gos_all_tasks_name_sql_schedule_and_timeout() {
    let go = go_tasks();
    assert_eq!(go.len(), 31, "Go has 31 cron tasks");
    assert_eq!(
        CATALOG.len(),
        32,
        "Rust catalog has 31 Go-ported tasks + 1 Rust-only task"
    );
    let rust_go: Vec<_> = CATALOG[..go.len()].iter().map(|(n, ..)| *n).collect();
    let names: Vec<_> = go.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(rust_go, names, "Rust Go-ported catalog and Go AllTasks() differ");
    for (task, (name, sql, _)) in go.iter().zip(&CATALOG[..go.len()]) {
        assert_eq!(task.sql, *sql, "{name}: statement");
        let (schedule, seconds) = go_task_spec(name).unwrap_or_else(|| panic!("{name}: no spec"));
        assert_eq!(task.schedule, schedule, "{name}: schedule");
        assert_eq!(task.seconds, seconds, "{name}: timeout");
    }
    let rust_only = &CATALOG[go.len()..];
    assert_eq!(
        rust_only,
        &[(
            PRUNE_RECEIPTS_TASK,
            "SELECT prune_rust_operation_receipts(5000)",
            Credential::Worker
        )]
    );
    assert_eq!(
        go_task_spec(PRUNE_RECEIPTS_TASK),
        Some(("@every 1h".to_string(), 30))
    );
    assert!(go_task_spec("not-a-task").is_none());
}

#[test]
fn only_the_two_schema_owner_statements_use_the_owner_credential() {
    let owner: Vec<_> = CATALOG
        .iter()
        .filter(|(.., c)| *c == Credential::Owner)
        .map(|(n, ..)| *n)
        .collect();
    assert_eq!(
        owner,
        [
            "refresh-antiphish-contact-graph",
            "create-monthly-partitions"
        ]
    );
    assert_eq!(credential("prune-greylist"), Some(Credential::Worker));
    assert_eq!(credential(PRUNE_RECEIPTS_TASK), Some(Credential::Worker));
    assert_eq!(credential("not-a-task"), None);
}

#[tokio::test]
async fn every_task_registers_without_go_workers_off() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-catalog-guard") else {
        return Ok(());
    };
    let worker = WorkerDatabase::new(&db.dsn)?;
    let dbs = CronDatabases {
        worker: worker.clone(),
        owner: worker.clone(),
    };
    for (name, ..) in CATALOG {
        let action = || cron_action(name, &dbs).expect("action for every Go task");
        let mut admitted = CronScheduler::per_task(worker.clone());
        admitted
            .register_transferred(name, action(), "")
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        admitted.shutdown().await?;
    }
    assert!(cron_action("not-a-task", &dbs).is_none());
    Ok(())
}

#[tokio::test]
async fn owner_statements_run_on_the_owner_dsn_and_the_rest_on_the_worker_dsn(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-catalog-credentials") else {
        return Ok(());
    };
    let good = WorkerDatabase::new(&db.dsn)?;
    // Nothing listens on port 1: any statement sent there fails to connect.
    let dead = WorkerDatabase::new("postgres://nobody@127.0.0.1:1/none?connect_timeout=1")?;
    let split = CronDatabases {
        worker: dead.clone(),
        owner: good.clone(),
    };
    let swapped = CronDatabases {
        worker: good,
        owner: dead,
    };
    for (name, _, credential) in CATALOG.iter().filter(|(n, ..)| !n.starts_with("chat-")) {
        let (on_owner, on_worker) = match credential {
            Credential::Owner => (&split, &swapped),
            Credential::Worker => (&swapped, &split),
        };
        // Reached only by the credential the task is meant to use.
        let ran = cron_action(name, on_owner).unwrap()().await;
        let refused = cron_action(name, on_worker).unwrap()().await;
        let _ = &ran;
        assert!(
            refused.is_err(),
            "{name} must not run on the other credential"
        );
        if let Err(error) = ran {
            // The reducer itself may reject an unseeded database; a connect error never.
            assert!(
                !error.to_string().contains("error connecting"),
                "{name} did not reach the database on its credential: {error}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn prune_rust_operation_receipts_drains_multiple_batches_and_propagates_errors(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-prune-receipts-drain") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let worker_env = std::env::var("DB_WORKER_DSN").ok();
    let worker = WorkerDatabase::from_dsns(&db.dsn, worker_env.as_deref())?;
    let dbs = CronDatabases {
        worker: worker.clone(),
        owner: worker.clone(),
    };
    let saved_cfg: Option<String> = owner
        .query_opt(
            "SELECT value::text FROM public.system_config WHERE key = 'rust_operation_receipts_retain_days'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    owner
        .execute(
            "DELETE FROM public.system_config WHERE key = 'rust_operation_receipts_retain_days'",
            &[],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM public.rust_operation_receipts WHERE command LIKE 'cron473.%'",
            &[],
        )
        .await?;

    let test_result: Result<(), BoxError> = async {
        // Seed 10,005 expired rows (spans 3 batches of 5,000: 5000 + 5000 + 5)
        // plus 3 in-window rows that must survive.
        owner
            .execute(
                "INSERT INTO public.rust_operation_receipts (operation_id, family, command, committed_at)
                 SELECT ('47300000-0000-0000-0000-' || lpad(to_hex(g), 12, '0'))::uuid,
                        CASE g % 3 WHEN 0 THEN 'F01' WHEN 1 THEN 'F12' ELSE 'F21' END,
                        'cron473.stale',
                        now() - interval '45 days' - (g * interval '1 second')
                   FROM generate_series(1, 10005) AS g",
                &[],
            )
            .await?;
        owner
            .execute(
                "INSERT INTO public.rust_operation_receipts (operation_id, family, command, committed_at)
                 SELECT ('47310000-0000-0000-0000-' || lpad(to_hex(g), 12, '0'))::uuid,
                        'F21',
                        'cron473.fresh',
                        now() - interval '1 day'
                   FROM generate_series(1, 3) AS g",
                &[],
            )
            .await?;

        cron_action(PRUNE_RECEIPTS_TASK, &dbs)
            .expect("prune-rust-operation-receipts action")()
        .await?;

        let stale_left: i64 = owner
            .query_one(
                "SELECT count(*) FROM public.rust_operation_receipts WHERE command = 'cron473.stale'",
                &[],
            )
            .await?
            .get(0);
        let fresh_left: i64 = owner
            .query_one(
                "SELECT count(*) FROM public.rust_operation_receipts WHERE command = 'cron473.fresh'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(stale_left, 0, "multi-batch drain must delete all 10,005 stale rows");
        assert_eq!(fresh_left, 3, "in-window rows must survive");

        // Verify max_batches bound stops after the requested number of batches.
        owner
            .execute(
                "INSERT INTO public.rust_operation_receipts (operation_id, family, command, committed_at)
                 SELECT ('47320000-0000-0000-0000-' || lpad(to_hex(g), 12, '0'))::uuid,
                        'F01',
                        'cron473.capped',
                        now() - interval '45 days' - (g * interval '1 second')
                   FROM generate_series(1, 5) AS g",
                &[],
            )
            .await?;
        let deleted = drain_rust_operation_receipts(&worker, 2, 1, Duration::from_secs(20)).await?;
        assert_eq!(deleted, 2, "max_batches=1 with batch_size=2 must stop at 2 rows");
        let capped_left: i64 = owner
            .query_one(
                "SELECT count(*) FROM public.rust_operation_receipts WHERE command = 'cron473.capped'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(capped_left, 3, "3 remaining capped rows wait for next tick");

        // Verify BZ040 config error propagates out of the cron action.
        owner
            .execute(
                "INSERT INTO public.system_config (key, value, encrypted, updated_at)
                 VALUES ('rust_operation_receipts_retain_days', '0', false, now())
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[],
            )
            .await?;
        let err = cron_action(PRUNE_RECEIPTS_TASK, &dbs)
            .unwrap()()
            .await
            .expect_err("invalid retention config must propagate BZ040");
        assert!(
            err.to_string().contains("BZ040"),
            "expected BZ040 error, got: {err}"
        );
        Ok(())
    }
    .await;

    let _ = owner
        .execute(
            "DELETE FROM public.rust_operation_receipts WHERE command LIKE 'cron473.%'",
            &[],
        )
        .await;
    match saved_cfg {
        Some(val) => {
            let _ = owner
                .execute(
                    "INSERT INTO public.system_config (key, value, encrypted, updated_at)
                     VALUES ('rust_operation_receipts_retain_days', $1::text::jsonb, false, now())
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    &[&val],
                )
                .await;
        }
        None => {
            let _ = owner
                .execute(
                    "DELETE FROM public.system_config WHERE key = 'rust_operation_receipts_retain_days'",
                    &[],
                )
                .await;
        }
    }
    test_result
}

#[tokio::test]
async fn auto_registration_skips_prune_receipts_on_lock_contention_while_explicit_fails_fast(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cron-prune-receipts-autoreg") else {
        return Ok(());
    };
    let worker = WorkerDatabase::new(&db.dsn)?;
    let dbs = CronDatabases {
        worker: worker.clone(),
        owner: worker.clone(),
    };

    // Another Rust scheduler already holds cron-task:prune-rust-operation-receipts.
    let held_lease = worker
        .try_cron_task_lock(PRUNE_RECEIPTS_TASK)
        .await?
        .expect("acquire prune-rust-operation-receipts lock");

    // 1. Implicit auto-registration skips non-fatally when lock is contended.
    let mut auto_sched = CronScheduler::per_task(worker.clone());
    let auto_res = register_cron_tasks(&mut auto_sched, &["prune-greylist"], &dbs, "").await;
    assert!(
        auto_res.is_ok(),
        "auto-registration must skip non-fatally on lock contention: {auto_res:?}"
    );
    auto_sched.shutdown().await?;

    // 2. Explicit listing in RUST_WORKERS_ON still fails fast on lock contention.
    let mut explicit_sched = CronScheduler::per_task(worker.clone());
    let explicit_err =
        register_cron_tasks(&mut explicit_sched, &[PRUNE_RECEIPTS_TASK], &dbs, "")
            .await
            .expect_err("explicit prune-rust-operation-receipts must fail fast on lock contention");
    assert!(
        explicit_err.contains("already held"),
        "expected already-held error, got: {explicit_err}"
    );
    explicit_sched.shutdown().await?;

    // Release the competing lock, then verify auto-registration acquires it.
    held_lease.release().await?;
    let mut fresh_sched = CronScheduler::per_task(worker.clone());
    register_cron_tasks(&mut fresh_sched, &["prune-greylist"], &dbs, "").await?;
    assert!(
        worker
            .try_cron_task_lock(PRUNE_RECEIPTS_TASK)
            .await?
            .is_none(),
        "auto-registration must hold cron-task:prune-rust-operation-receipts when uncontended"
    );
    fresh_sched.shutdown().await?;
    Ok(())
}
