//! #457: terminal `migration.completed` / `migration.failed` webhook events from the Rust
//! migration runner. Frozen Go's real Orchestrator (overlay
//! `tests/conformance/drain/migration_terminal_tick_test.go.txt`) runs the same steps over
//! the same seed against a fake receiver; the Rust orchestrator must deliver the same
//! requests (path, signature, exact body) and leave the same job, delivery and publication
//! rows. Record: `GOFREE_RECORD_DRAIN=all GOFREE_GO_SOURCE=<sha>`; replay needs no Go.
mod common;
mod drain_oracle;
use common::webhook_receiver::{self as hooks, Seen};
use drain_oracle::{settle, BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::migration_runner::{Config, Dialer, Orchestrator};
use setjoin_pg::workers::WorkerDatabase;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const ROOT: &str = "gofree-migration-root";

async fn run(name: &str, outbox: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("migration-terminal") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let accounts = [
        fixture::account(&owner, "wh457-a").await?,
        fixture::account(&owner, "wh457-b").await?,
        fixture::account(&owner, "wh457-c").await?,
        fixture::account(&owner, "wh457-d").await?,
        fixture::account(&owner, "wh457-e").await?,
    ];
    let seen: Seen = Seen::default();
    let hook = hooks::receiver(seen.clone()).await;
    // The toggle's stored state before the case (`None`: no row, as in a fresh schema).
    let mut prior: Option<bool> = None;
    let result = async {
        hooks::clear(&owner).await?;
        owner.execute("DELETE FROM migration_jobs WHERE user_id=ANY($1)", &[&accounts.iter().map(|a| a.user).collect::<Vec<_>>()]).await?;
        let both = r#"["migration.completed","migration.failed"]"#;
        let [a, b, c, d, e] = &accounts;
        for (path, user, scope, active, types) in [
            ("/org", a.user, "organization", true, both),
            ("/self-a", a.user, "self", true, both),
            ("/self-b", b.user, "self", true, r#"["migration.failed"]"#),
            ("/self-c", c.user, "self", true, both),
            ("/self-d", d.user, "self", true, both),
            ("/self-e", e.user, "self", true, both),
            ("/other", a.user, "organization", true, r#"["user.updated"]"#),
            ("/inactive", a.user, "organization", false, both),
        ] {
            hooks::subscribe(&owner, user, hook, path, types, scope, active).await?;
        }
        if outbox {
            prior = owner.query_opt("SELECT enabled FROM feature_toggles WHERE key='feature.webhook_publication_outbox'", &[]).await?.map(|r| r.get(0));
            owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.webhook_publication_outbox',true) ON CONFLICT(key) DO UPDATE SET enabled=true", &[]).await?;
        }
        // One live job per user: a (mailbox) completes, b (no mailbox) fails, c (paused,
        // mailbox) and d (no mailbox) are failed by startup recovery; a's earlier
        // cancelled job meets a second terminal transition and is refused; e's job targets
        // a's mailbox, which is not e's: the mailbox fan-out fails closed.
        let mut ids = Vec::new();
        for (account, mailbox, status) in [
            (a, Some(a.mailbox), "fetching"),
            (b, None, "importing"),
            (c, Some(c.mailbox), "paused"),
            (d, None, "fetching"),
            (a, Some(a.mailbox), "cancelled"),
            (e, Some(a.mailbox), "fetching"),
        ] {
            let id: i64 = owner.query_one(
                "INSERT INTO migration_jobs(user_id,source_type,status,progress,error_log,target_mailbox_id,started_at) VALUES($1,'imap',$2,'{}','[]',$3,now()) RETURNING id",
                &[&account.user, &status, &mailbox],
            ).await?.get(0);
            ids.push(id);
        }
        let steps = format!("complete:{},fail:{},cancel:{},complete:{},complete:{},recover", ids[0], ids[1], ids[4], ids[4], ids[5]);
        if std::env::var_os("GOFREE_RECORD_DRAIN").is_some() {
            GoTick {
                package: "internal/migration",
                overlay: "migration_terminal_tick_test.go.txt",
                test: "TestGoFreeMigrationTerminal",
                file: "gofree_migration_terminal_test.go",
                env: vec![
                    ("GOFREE_DRAIN_DSN".into(), db.dsn.clone()),
                    ("GOFREE_WEBHOOK_MASTER".into(), hooks::MASTER.into()),
                    ("GOFREE_MIGRATION_STEPS".into(), steps.clone()),
                ],
                docker: vec![],
            }
            .run_with(&[("internal/webhook", "gofree_unguarded_export.go", "webhook_unguarded_export.go.txt")])?;
        } else {
            let dispatcher = hooks::unguarded(&db.dsn)?;
            let orchestrator = Orchestrator::new(Config {
                db: WorkerDatabase::new(&db.dsn)?,
                store: Arc::new(NoStore),
                root: ROOT.into(),
                dialer: Dialer::system(),
                dispatcher: Some(dispatcher.clone()),
            });
            for step in steps.split(',') {
                if step == "recover" {
                    orchestrator.recover_stuck().await?;
                } else {
                    let (phase, id) = step.split_once(':').unwrap();
                    let _ = orchestrator.orchestrate(id.parse()?, phase, None).await;
                }
            }
            dispatcher.shutdown().await;
        }
        // Job ids are run-specific: name each by its seed position in every body.
        let label = |text: String| {
            let mut text = text;
            for (i, id) in ids.iter().enumerate() {
                for form in [format!("\\\"job_id\\\":{id}}}"), format!("\\\"job_id\\\": {id}}}")] {
                    text = text.replace(&form, &format!("\\\"job_id\\\":\\\"<job{i}>\\\"}}"));
                }
            }
            text
        };
        let mut jobs = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let row = owner.query_one("SELECT status,error_log::text,source_config_enc IS NOT NULL FROM migration_jobs WHERE id=$1", &[id]).await?;
            jobs.push(json!([i, row.get::<_, String>(0), row.get::<_, String>(1), row.get::<_, bool>(2)]));
        }
        let publications: Vec<Value> = owner
            .query("SELECT event_type,audience,state,subject_user_id=ANY($1),subject_mailbox_id IS NOT NULL FROM webhook_publications ORDER BY event_type,audience,subject_user_id", &[&accounts.iter().map(|a| a.user).collect::<Vec<_>>()])
            .await?
            .iter()
            .map(|r| json!([r.get::<_, String>(0), r.get::<_, String>(1), r.get::<_, String>(2), r.get::<_, bool>(3), r.get::<_, bool>(4)]))
            .collect();
        let relabel = |value: Value| serde_json::from_str::<Value>(&label(value.to_string())).unwrap();
        settle(
            name,
            json!({
                "jobs": jobs, "publications": publications,
                "deliveries": relabel(hooks::deliveries(&owner).await?),
                "requests": relabel(hooks::requests(&seen)),
            }),
            std::env::var_os("GOFREE_RECORD_DRAIN").is_some(),
        )
    }
    .await;
    let _ = hooks::clear(&owner).await;
    let _ = owner.execute("DELETE FROM webhook_publications WHERE subject_user_id=ANY($1)", &[&accounts.iter().map(|a| a.user).collect::<Vec<_>>()]).await;
    let _ = owner.execute("DELETE FROM migration_jobs WHERE user_id=ANY($1)", &[&accounts.iter().map(|a| a.user).collect::<Vec<_>>()]).await;
    if outbox {
        let _ = match prior {
            None => owner.execute("DELETE FROM feature_toggles WHERE key='feature.webhook_publication_outbox'", &[]).await,
            Some(enabled) => owner.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.webhook_publication_outbox'", &[&enabled]).await,
        };
    }
    for account in &accounts {
        fixture::remove(&owner, account).await?;
    }
    result
}

/// The terminal-event steps never touch the object store (every method refuses).
struct NoStore;
impl setjoin_gateway::recovery_worker::ObjectStore for NoStore {
    fn remove<'a>(
        &'a self,
        _key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("no object store".into()) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migration_terminal_events_direct_dispatch() -> Result<(), BoxError> {
    run("migration-terminal-events", false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migration_terminal_events_enrolled_in_publication_outbox() -> Result<(), BoxError> {
    run("migration-terminal-events-outbox", true).await
}
