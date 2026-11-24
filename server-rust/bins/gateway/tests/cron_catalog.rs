//! #407: the Rust cron catalog equals frozen Go's `AllTasks()`, every task is
//! guarded by `GO_WORKERS_OFF`, and credentials split per task.
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use setjoin_gateway::cron_catalog::{credential, cron_action, Credential, CronDatabases, CATALOG};
use setjoin_gateway::workers::{go_task_spec, CronScheduler};
use setjoin_pg::workers::WorkerDatabase;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[test]
fn catalog_tasks_have_unique_names_non_empty_sql_and_valid_specs() {
    use std::collections::BTreeSet;
    assert_eq!(CATALOG.len(), 31, "cron catalog must retain all 31 tasks");
    let mut names = BTreeSet::new();
    for (name, sql, _) in CATALOG {
        assert!(!name.is_empty(), "cron task name must not be empty");
        assert!(names.insert(*name), "duplicate cron task name: {name}");
        assert!(!sql.trim().is_empty(), "{name}: SQL statement must not be empty");
        let (schedule, seconds) =
            go_task_spec(name).unwrap_or_else(|| panic!("{name}: missing cron task spec"));
        assert!(!schedule.trim().is_empty(), "{name}: empty schedule");
        assert!(seconds > 0, "{name}: timeout must be positive");
    }
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
