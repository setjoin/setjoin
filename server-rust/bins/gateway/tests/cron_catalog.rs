//! #407: the Rust cron catalog equals frozen Go's `AllTasks()`, every task is
//! guarded by `GO_WORKERS_OFF`, and credentials split per task.
mod common;
use common::BoxError;
use setjoin_conformance::harness::Db;
use setjoin_gateway::cron_catalog::{credential, cron_action, Credential, CronDatabases, CATALOG};
use setjoin_gateway::workers::{go_task_spec, CronScheduler};
use setjoin_pg::workers::WorkerDatabase;

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
    let rust: Vec<_> = CATALOG.iter().map(|(n, ..)| *n).collect();
    let names: Vec<_> = go.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(rust, names, "Rust catalog and Go AllTasks() differ");
    for (task, (name, sql, _)) in go.iter().zip(CATALOG) {
        assert_eq!(task.sql, *sql, "{name}: statement");
        let (schedule, seconds) = go_task_spec(name).unwrap_or_else(|| panic!("{name}: no spec"));
        assert_eq!(task.schedule, schedule, "{name}: schedule");
        assert_eq!(task.seconds, seconds, "{name}: timeout");
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
async fn every_task_refuses_to_start_unless_go_lists_it_off() -> Result<(), BoxError> {
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
        let mut refused = CronScheduler::per_task(worker.clone());
        for go_off in ["", "cron:other-task", name, &format!("cron:{name}x")] {
            let error = refused
                .register_transferred(name, action(), go_off)
                .await
                .expect_err("Go copy still on");
            assert!(
                error
                    .to_string()
                    .contains(&format!("GO_WORKERS_OFF=cron:{name}")),
                "{name}: {error}"
            );
        }
        refused.shutdown().await?;
        for go_off in [format!("cron:{name}"), "cron".to_string()] {
            let mut admitted = CronScheduler::per_task(worker.clone());
            admitted
                .register_transferred(name, action(), &go_off)
                .await
                .unwrap_or_else(|e| panic!("{name} with {go_off}: {e}"));
            admitted.shutdown().await?;
        }
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
